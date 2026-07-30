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
`build.rs` embeds it in the binary).

```sh
cargo build --release          # -> target/release/fips-guard
# or, from the repository root:
make guard
```

On Debian/Ubuntu/Mint the two packages are `clang` and `linux-libc-dev`
(the latter provides `asm/types.h`, which `linux/bpf.h` includes).

The LLVM apt repository installs versioned binaries (`clang-19`,
`clang-18`, …) with no unversioned `clang` symlink unless the `clang`
meta package or an `update-alternatives` entry is also installed.
`build.rs` handles that: it tries `clang` first, then the
highest-numbered `clang-<N>` on `PATH`. Override the choice with
`CLANG`, which is used verbatim:

```sh
CLANG=clang-19 cargo build --release
```

With no usable compiler the build script stops with the list of what it
tried:

```text
no working clang found (tried: clang, clang-19). Install it
(Debian/Ubuntu: apt install clang linux-libc-dev), or set CLANG to a
versioned binary such as clang-19, or point SHIELD_GUARD_BPF_OBJ at a
prebuilt object
```

### Building for a host without clang

You do not need clang on the node you deploy to — only on whatever
machine compiles the object. Build it once where clang exists:

```sh
clang -O2 -g -target bpf -Wall -Werror \
    -I/usr/include/$(uname -m)-linux-gnu \
    -c bpf/shield_guard.bpf.c -o shield_guard.bpf.o
```

(`clang-19` or whichever version you have — this one is invoked by hand,
so it is not subject to the detection above.)

Copy `shield_guard.bpf.o` to the target host and point the build at it,
which skips the clang step entirely:

```sh
SHIELD_GUARD_BPF_OBJ=/path/to/shield_guard.bpf.o cargo build --release
```

The object is architecture-independent BPF bytecode, but it is
generated from the headers of the machine that compiled it — build it
on the same distribution family as the target. Simpler still: build the
whole `fips-guard` binary on the build host and copy that single file
over; it embeds the object and needs no runtime assets.

### Installing

Build as your normal user, install as root — `make install-guard` does
not rebuild, precisely so it can be run under `sudo` when the Rust
toolchain lives in your `~/.cargo/bin` (outside sudo's `secure_path`):

```sh
make guard                     # as you
sudo make install-guard        # as root
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

`ban`/`unban` here write only the kernel maps. Once fail2ban is driving
the guard, unban through `fail2ban-client unban <ip>` instead — a
hand-unbanned node is not re-banned while fail2ban still holds its
ticket ([guide](../docs/guide.md#managing-bans-by-hand)). `check`,
`list` and `stats` are always safe.

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

Or `make install-guard` from the repository root, which does both plus
the systemd unit.

The Phase 3 jails and action need no changes — they call
`shield-ban ban|unban`, which now enforces in the kernel. To also keep
the banlist file in sync (so nginx's view agrees, and bans still apply
while the guard is unloaded), install the file backend alongside it and
set `SHIELD_BAN_ALSO_FILE=true`:

```sh
install -m 755 ../core/actions/shield-ban \
    /usr/local/lib/fips-shield/shield-ban-file
```

**This requires fail2ban on the host.** The container-mode sidecar bakes
its own copy of the banlist-file backend into the image and has no
access to the host's bpffs, so it cannot invoke the guard: bans land in
the shared banlist (where nginx enforces them) and `fips-guard stats`
stays at zero. Run detection on the host — `deploy/host/install-fail2ban.sh`
— if you want kernel enforcement. Details and the log-path wrinkle:
[../docs/guide.md § 7](../docs/guide.md#7-optional-kernel-level-enforcement).

`install-fail2ban.sh` and `make install` deliberately do not replace an
already-installed guard wrapper; they put the file backend in
`/usr/local/lib/fips-shield/shield-ban-file` instead. Check which
backend is live with `head -3 /usr/local/bin/shield-ban`.

Run `fips-guard load` at boot before the services it protects — a
systemd unit example is in [../deploy/host/README.md](../deploy/host/README.md).

## Tests

`../test/guard_smoke.sh` builds the binary and exercises it in a
privileged container against the host kernel: real end-to-end traffic
over a veth pair (L2) and a TUN device (L3 — the shape `fips0` has),
covering drop, unban, reload persistence, in-kernel expiry, and
per-source throttling.
