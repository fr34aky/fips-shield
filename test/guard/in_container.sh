#!/usr/bin/env bash
# Runs inside the privileged test container (see guard_smoke.sh).
#
# Two complementary tests:
#   * veth + ping   — real end-to-end traffic over an L2 device, proving
#                     the drop is a real drop (not just a counter).
#   * tun_test.py   — the L3 device shape production actually uses
#                     (fips0 is a TUN), plus expiry and throttling.
set -euo pipefail

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

echo "=== veth end-to-end (L2 device) ==="

ip link add veth-host type veth peer name veth-peer
ip netns add client
ip link set veth-peer netns client
ip -6 addr add fd97:e2e::1/64 dev veth-host nodad
ip link set veth-host up
ip netns exec client ip -6 addr add fd97:e2e::2/64 dev veth-peer nodad
ip netns exec client ip link set veth-peer up
ip netns exec client ip link set lo up

ping6() { ip netns exec client ping -6 -c 2 -W 2 -q "$@" >/dev/null 2>&1; }

# Warm the neighbour caches before the guard is attached, so neighbour
# discovery (which uses link-local addresses, not the banned global
# one) never lands inside a measured window.
ping6 fd97:e2e::1 || true

fips-guard load --iface veth-host

if ! ping6 fd97:e2e::1; then
    echo "FAIL baseline ping should succeed" >&2
    exit 1
fi
echo "PASS baseline ping succeeds through the guard"

fips-guard ban fd97:e2e::2 60 >/dev/null
if ping6 fd97:e2e::1; then
    echo "FAIL banned peer should not reach the host" >&2
    tc filter show dev veth-host ingress >&2
    fips-guard list >&2
    fips-guard stats >&2
    ip netns exec client ip -6 addr show veth-peer >&2
    exit 1
fi
echo "PASS banned peer's traffic is dropped end-to-end"

stats="$(fips-guard stats)"
if ! grep -q "^dropped (ban) *[1-9]" <<<"$stats"; then
    echo "FAIL drop counter did not move" >&2
    echo "$stats" >&2
    exit 1
fi
echo "PASS drop counter reflects the dropped packets"

fips-guard unban fd97:e2e::2 >/dev/null
if ! ping6 fd97:e2e::1; then
    echo "FAIL unban should restore reachability" >&2
    exit 1
fi
echo "PASS unban restores reachability"

# Bans must survive a reload of the program (pinned maps are reused).
fips-guard ban fd97:e2e::2 60 >/dev/null
fips-guard load --iface veth-host >/dev/null
if ! fips-guard check fd97:e2e::2 >/dev/null; then
    echo "FAIL ban did not survive reload" >&2
    exit 1
fi
if ping6 fd97:e2e::1; then
    echo "FAIL still-banned peer reachable after reload" >&2
    exit 1
fi
echo "PASS bans survive a guard reload"

# --- attachment visibility and self-repair -----------------------------
#
# The failure this covers is silent: the pinned maps outlive the tc
# filter, so after a detach `check` still answers "banned" and `list`
# still lists, while nothing is dropped at all. Nothing in the guard
# used to be able to tell the difference, and the loader unit is
# Type=oneshot + RemainAfterExit, so its Restart=on-failure can never
# fire to repair it.
if ! fips-guard status --iface veth-host >/dev/null; then
    echo "FAIL status should report the classifier attached" >&2
    exit 1
fi
echo "PASS status reports the classifier attached"

fips-guard watchdog --iface veth-host >/dev/null
if ! fips-guard health --max-age 60 >/dev/null; then
    echo "FAIL health should be fresh right after the watchdog ran" >&2
    exit 1
fi
echo "PASS watchdog publishes a heartbeat health can read"

# Detach behind the guard's back, exactly as an interface recreation or
# a stray `tc filter del` would.
fips-guard ban fd97:e2e::2 60 >/dev/null
tc filter del dev veth-host ingress 2>/dev/null || true
if fips-guard status --iface veth-host >/dev/null; then
    echo "FAIL status did not notice the filter was removed" >&2
    exit 1
fi
echo "PASS status notices the filter was removed"

# The point of the whole exercise: everything else still claims the
# node is banned while its traffic now flows.
if ! fips-guard check fd97:e2e::2 >/dev/null; then
    echo "FAIL check should still report the ban (maps outlive the filter)" >&2
    exit 1
fi
if ! ping6 fd97:e2e::1; then
    echo "FAIL a detached filter should not be dropping anything" >&2
    exit 1
fi
echo "PASS a detached classifier enforces nothing while check still says 'banned'"

fips-guard watchdog --iface veth-host >/dev/null
if ! fips-guard status --iface veth-host >/dev/null; then
    echo "FAIL watchdog did not re-attach the classifier" >&2
    exit 1
fi
if ping6 fd97:e2e::1; then
    echo "FAIL banned peer reachable after the watchdog repaired the attachment" >&2
    exit 1
fi
echo "PASS watchdog re-attaches and enforcement resumes"

# The throttle config must survive the repair: a naive re-attach resets
# it to the CLI defaults, silently disabling a configured throttle.
fips-guard throttle 500 100 >/dev/null
tc filter del dev veth-host ingress 2>/dev/null || true
fips-guard watchdog --iface veth-host >/dev/null
# Capture rather than pipe into `grep -q`: the guard restores default
# SIGPIPE handling on purpose (so `list | head` ends quietly instead of
# panicking), and `grep -q` closes the pipe on its first match — under
# `set -o pipefail` that turns a *passing* check into a failed pipeline.
throttle_now="$(fips-guard stats)"
case "$throttle_now" in
*"500 pkt/s"*) ;;
*)
    echo "FAIL watchdog reset the throttle configuration" >&2
    echo "$throttle_now" >&2
    exit 1
    ;;
esac
echo "PASS watchdog preserves the throttle across a repair"
fips-guard throttle 0 0 >/dev/null
fips-guard unban fd97:e2e::2 >/dev/null

fips-guard unload --iface veth-host >/dev/null
if ! ping6 fd97:e2e::1; then
    echo "FAIL unload should leave traffic unfiltered" >&2
    exit 1
fi
echo "PASS unload leaves the interface unfiltered"

# health must fail closed once the heartbeat goes stale, since that is
# what tells fail2ban to re-apply its tickets.
if fips-guard health --max-age 0 >/dev/null; then
    echo "FAIL health should report a stale heartbeat as unhealthy" >&2
    exit 1
fi
echo "PASS health reports a stale heartbeat as unhealthy"

ip netns del client
ip link del veth-host

echo
echo "=== TUN injection (L3 device — the fips0 shape) ==="
python3 /test/guard/tun_test.py
