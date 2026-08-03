// fips-shield guard: tc clsact ingress classifier.
//
// Drops or throttles inbound IPv6 traffic by source address, before the
// kernel delivers it to any local socket. On a FIPS mesh the source
// /128 is the peer's node identity, so a ban here silences that node
// against every service on the host — not only the shield-fronted one.
//
// tc rather than XDP: fips0 is a TUN device, which only supports
// generic-mode XDP (no better than tc, less predictable).
//
// Compiled by build.rs with clang -target bpf and loaded by the
// fips-guard binary (aya). Deliberately depends on nothing but
// linux/bpf.h: the few libbpf conveniences used are defined below, so
// the build needs no libbpf headers.
//
// SPDX-License-Identifier: GPL-2.0
// (The BPF object declares GPL to keep every helper available; the
// rest of fips-shield is not affected.)

#include <linux/bpf.h>

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

// Maps pin themselves by name under the loader's pin directory, so the
// CLI can reach them with no daemon running and a reload reuses the
// existing bans instead of starting from an empty map.
#define LIBBPF_PIN_BY_NAME 1

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key,
                                   const void *value, __u64 flags) = (void *)2;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static long (*bpf_skb_load_bytes_relative)(const void *skb, __u32 offset,
                                           void *to, __u32 len,
                                           __u32 start_header) = (void *)68;

#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

#define ETH_P_IPV6 0x86DD
// Source-address offset within the IPv6 header.
#define IP6_SADDR_OFF 8
// Mode for bpf_skb_load_bytes_relative: offsets are relative to the
// network header, so the ethernet header (if any) is already skipped.
#define BPF_HDR_START_NET 1

#define MAX_TRACKED 65536

// Stats slots (see StatSlot in src/main.rs — keep in sync).
#define ST_PASSED 0
#define ST_DROPPED_BAN 1
#define ST_DROPPED_THROTTLE 2
#define ST_NOT_IPV6 3
#define ST_PARSE_FAILED 4
#define ST_COUNT 5

struct addr6 {
    __u8 b[16];
};

struct ban_val {
    // Monotonic deadline the kernel compares against; 0 = permanent.
    __u64 expires_mono_ns;
    // Wall-clock deadline, for userspace reporting only.
    __u64 expires_epoch_s;
};

struct bucket {
    // Milli-packets: 1000 == one packet's worth of credit.
    __u64 tokens_milli;
    __u64 last_ns;
};

struct config {
    // 0 disables throttling entirely.
    __u64 rate_pps;
    __u64 burst_pkts;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct addr6);
    __type(value, struct ban_val);
    __uint(max_entries, MAX_TRACKED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} shield_bans SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct addr6);
    __type(value, struct bucket);
    __uint(max_entries, MAX_TRACKED);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} shield_throttle SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct config);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} shield_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, ST_COUNT);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} shield_stats SEC(".maps");

/* Liveness heartbeat: epoch seconds, written by "fips-guard watchdog"
 * on the host each time it confirms the classifier is still attached.
 *
 * The classifier never touches this map. It exists because attachment
 * cannot be checked from where it needs to be acted on: the detection
 * sidecar runs with network_mode "none", so it has no view of the mesh
 * interface and cannot ask whether a tc filter is attached. The pinned
 * maps are the one channel that does reach it, so the host publishes
 * the answer here and "fips-guard health" reads it. A stale value means
 * enforcement is not known to be running.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 1);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} shield_health SEC(".maps");

static __always_inline void bump(__u32 slot)
{
    __u64 *v = bpf_map_lookup_elem(&shield_stats, &slot);
    if (v)
        *v += 1;
}

// Copies the IPv6 source address out of the packet.
//
// The offset is taken relative to the network header, which the kernel
// already knows, so this is correct on both L3 devices (TUN: fips0
// delivers packets with no ethernet header) and L2 devices, with no
// guessing. An earlier version inferred the layout from the first
// byte's version nibble; that misread any ethernet frame whose
// destination MAC happened to start with nibble 6 (~6% of random MACs)
// as an L3 packet, silently reading the wrong 16 bytes as the source
// address and letting banned traffic through.
//
// Using the helper rather than direct data access also removes the
// dependence on those bytes being in the skb's linear area.
static __always_inline int load_saddr(struct __sk_buff *skb, struct addr6 *out)
{
    if (bpf_skb_load_bytes_relative(skb, IP6_SADDR_OFF, out->b, 16,
                                    BPF_HDR_START_NET) < 0)
        return -1;
    return 0;
}

SEC("classifier")
int shield_guard(struct __sk_buff *skb)
{
    // bpf_htons on a constant; skb->protocol is network byte order.
    if (skb->protocol != __builtin_bswap16(ETH_P_IPV6)) {
        bump(ST_NOT_IPV6);
        return TC_ACT_OK;
    }

    struct addr6 src;
    if (load_saddr(skb, &src) < 0) {
        // Counted separately from ordinary non-IPv6 traffic: a rising
        // parse-failure count means enforcement is silently degraded,
        // which must not hide inside a counter that normally moves.
        bump(ST_PARSE_FAILED);
        return TC_ACT_OK;
    }

    __u64 now = bpf_ktime_get_ns();

    struct ban_val *ban = bpf_map_lookup_elem(&shield_bans, &src);
    if (ban) {
        // Expiry is enforced here, not by a userspace sweeper: a ban
        // lapses on time even if nothing ever prunes the map.
        if (ban->expires_mono_ns == 0 || ban->expires_mono_ns > now) {
            bump(ST_DROPPED_BAN);
            return TC_ACT_SHOT;
        }
    }

    __u32 zero = 0;
    struct config *cfg = bpf_map_lookup_elem(&shield_config, &zero);
    if (cfg && cfg->rate_pps) {
        __u64 cap = cfg->burst_pkts * 1000;
        struct bucket *b = bpf_map_lookup_elem(&shield_throttle, &src);
        if (!b) {
            struct bucket fresh = {
                .tokens_milli = cap > 1000 ? cap - 1000 : 0,
                .last_ns = now,
            };
            bpf_map_update_elem(&shield_throttle, &src, &fresh, BPF_ANY);
        } else {
            // Refill: rate_pps milli-tokens per elapsed millisecond.
            // Sub-millisecond time is left on the clock rather than
            // rounded away, so slow rates stay accurate.
            __u64 elapsed_ms = (now - b->last_ns) / 1000000;
            if (elapsed_ms) {
                __u64 tokens = b->tokens_milli + elapsed_ms * cfg->rate_pps;
                b->tokens_milli = tokens > cap ? cap : tokens;
                b->last_ns = now;
            }
            if (b->tokens_milli < 1000) {
                bump(ST_DROPPED_THROTTLE);
                return TC_ACT_SHOT;
            }
            b->tokens_milli -= 1000;
        }
    }

    bump(ST_PASSED);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
