# fips-guard — eBPF enforcement backend

Drops or throttles inbound IPv6 traffic **by source node** at the mesh
interface, before the kernel delivers it to any socket. A tc clsact
ingress classifier does the filtering; the `fips-guard` CLI loads it
and manages its maps.

Compared with the Phase 3 banlist backend (nginx rejects banned nodes
at accept), this backend:

- covers **every** listener on `fips0`, not just shield-fronted ones
  (SSH, databases, anything else bound to the mesh address);
- costs nothing per rejected packet — no TCP handshake, socket, or
  nginx worker is involved;
- can **throttle** a source at packet rate, which no userspace proxy
  can do as cheaply.

What it does **not** do: it sits on `fips0`, which the fips daemon
feeds *after* transport reception and Noise decryption. A banned node
can still make your daemon spend CPU decrypting its packets, and its
peer link, routing role, and transit forwarding are untouched — this is
a host-service filter, not a mesh-level control. See "Where this sits"
in the repository README.

## Requirements

Linux only. Kernel 5.4+ (developed against 6.8), `CAP_BPF` +
`CAP_NET_ADMIN` (in practice: root), and bpffs mounted at
`/sys/fs/bpf`:

```sh
mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf
```

Build needs a Rust toolchain and `clang` (compiles the BPF object;
`build.rs` embeds it in the binary). To build where clang is
unavailable, point `SHIELD_GUARD_BPF_OBJ` at a prebuilt object.

```sh
cargo build --release          # -> target/release/fips-guard
```

## Use

```sh
# attach to the mesh interface (idempotent; reuses existing bans)
fips-guard load --iface fips0

# optional per-source packet throttle
fips-guard load --iface fips0 --rate 2000 --burst 4000
fips-guard throttle 2000 4000          # change it at runtime
fips-guard throttle 0 0                # disable

# the shield-ban contract (what fail2ban calls)
fips-guard ban fd97::1234 3600         # 0 seconds = until unbanned
fips-guard unban fd97::1234
fips-guard check fd97::1234            # exit 0 if banned, 1 if not
fips-guard list                        # "<ip> <until-epoch-seconds>"

fips-guard stats                       # counters + current config
fips-guard unload --iface fips0        # detach and unpin
```

There is no daemon. The maps are pinned under `/sys/fs/bpf/fips-shield`
(override with `--pin-dir` / `SHIELD_GUARD_PIN_DIR`) and the tc filter
owns the program, so both survive the CLI exiting. Ban expiry is
enforced in-kernel against the monotonic clock: a lapsed ban stops
dropping even if nothing ever prunes the map, and `list`/`check` clean
up stale entries as they encounter them.

Attachment uses a classic netlink tc filter rather than TCX
deliberately: a TCX link is owned by the process that created it and
would disappear the moment the CLI exits.

## Wiring it to the detection engine

Install the wrapper as the backend fail2ban invokes:

```sh
install -m 755 target/release/fips-guard /usr/local/bin/fips-guard
install -m 755 shield-ban /usr/local/bin/shield-ban
```

The Phase 3 jails and action need no changes — they call
`shield-ban ban|unban`, which now enforces in the kernel. To also keep
the banlist file in sync (so nginx's view agrees, and bans still apply
while the guard is unloaded), install the file backend alongside it and
set `SHIELD_BAN_ALSO_FILE=true`:

```sh
install -m 755 ../core/actions/shield-ban \
    /usr/local/lib/fips-shield/shield-ban-file
```

Run `fips-guard load` at boot before the services it protects — a
systemd unit example is in [../deploy/host/README.md](../deploy/host/README.md).

## Tests

`../test/guard_smoke.sh` builds the binary and exercises it in a
privileged container against the host kernel: real end-to-end traffic
over a veth pair (L2) and a TUN device (L3 — the shape `fips0` has),
covering drop, unban, reload persistence, in-kernel expiry, and
per-source throttling.
