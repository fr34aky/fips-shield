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

`install-fail2ban.sh` and `make install` deliberately do not replace an
already-installed guard wrapper; they put the file backend in
`/usr/local/lib/fips-shield/shield-ban-file` instead. Check which
backend is live with `head -3 /usr/local/bin/shield-ban`.

### From the containerized fail2ban

The detection sidecar can drive the guard too, so a container deployment
gets kernel-level bans without moving fail2ban to the host.

The state the guard enforces lives in **BPF maps pinned to bpffs**. Pins
are filesystem objects, so any process that can open them may add or
remove ban entries; the tc classifier on `fips0` reads those same maps on
every packet. That is all the sidecar needs — it never loads a program
and never touches the interface.

```sh
sudo make install-guard                       # host side, once
sudo systemctl enable --now fips-guard
cd deploy/container
docker compose -f compose.yaml -f compose.guard.yaml up -d
```

The overlay adds three things to the sidecar, and nothing else changes —
same jails, same filters, same action:

- **`CAP_BPF`.** Map access needs it. `CAP_NET_ADMIN` is *not* required:
  attaching the classifier (`fips-guard load`) stays on the host under
  systemd, where `PartOf=fips.service` re-attaches it across daemon
  restarts. The container keeps `network_mode: none`.
- **The host's `fips-guard` and `shield-ban`, bind-mounted read-only.**
  Mounting rather than baking them in means the container always runs
  exactly the guard the host runs — no version skew between the process
  writing the maps and the classifier reading them. It also means
  removing the overlay silently reverts to the image's file backend.
- **bpffs mounted at `/mnt/bpf`, not `/sys/fs/bpf`.** AppArmor's
  `docker-default` profile denies writes under `/sys/**`, so pinning
  through a `/sys` path fails with `EACCES`. The profile matches the
  path *inside* the container, so mounting bpffs elsewhere works with
  default AppArmor and default seccomp — no `--privileged`, no
  `security-opt`. `SHIELD_GUARD_PIN_DIR` points the CLI at it.

Because the image executes the host's binary, the sidecar is
Debian-based: `fips-guard` links against glibc and cannot run on musl.

`test/guard_sidecar_smoke.sh` covers this end to end — a privileged
container stands in for the host and pins the maps, the real sidecar
image bans and unbans through them, and the host's view is checked after
each step. It also asserts the negative case: with `CAP_BPF` dropped the
ban must fail, which is what proves the privilege is the thing doing the
work.

#### Choosing what enforces

| | Enforced by | `shield-ban list` reads |
|---|---|---|
| sidecar alone | nginx, from the banlist file | the file |
| **+ `compose.guard.yaml`** | the kernel, on `fips0` | the BPF maps |
| + `SHIELD_BAN_ALSO_FILE=true` | both | the maps (the file is kept in step) |

With the guard alone, banned traffic never reaches nginx, so the banlist
file stays empty — that is expected, not a fault. Set
`SHIELD_BAN_ALSO_FILE=true` if you want nginx to keep its own view as a
fallback for when the guard is unloaded.

Run `fips-guard load` at boot before the services it protects — a
systemd unit example is in [../deploy/host/README.md](../deploy/host/README.md).

## Tests

`../test/guard_smoke.sh` builds the binary and exercises it in a
privileged container against the host kernel: real end-to-end traffic
over a veth pair (L2) and a TUN device (L3 — the shape `fips0` has),
covering drop, unban, reload persistence, in-kernel expiry, and
per-source throttling.
