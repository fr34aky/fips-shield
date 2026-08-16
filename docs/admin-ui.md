# The status dashboard

`shield-ui` answers "what is this node protecting, what is it
enforcing, and who is banned" in a browser, instead of an ssh session
and four tools.

It is **read-only**. There is no ban, unban, config edit, or reload path
in it. That is a deliberate boundary, not a missing feature — see
[Why read-only](#why-read-only).

## Running it

**Which one you use is decided by how the shield itself runs**, not by
preference. In container mode the logs and the banlist are Docker named
volumes, not `/var/log/nginx` and `/var/lib/fips-shield`, so a
host-installed dashboard resolves configuration correctly and then finds
no logs and no bans — it is looking at paths nothing writes to.

### Container mode

```sh
cd deploy/container
docker compose -f compose.yaml -f compose.ui.yaml up -d --build
```

That is all. The image builds `shield-ui` itself, so the host needs no
Rust toolchain, and it mounts the same `shield-logs` and `shield-bans`
volumes the shield and fail2ban use, read-only, plus your `shield.env`.

The port is published on `127.0.0.1:8088` only. Publishing it as
`8088:8088` instead would expose it on every interface including
`fips0`, which hands a mesh peer the shield's own view of itself.

### Host mode

```sh
rustup target add "$(uname -m)"-unknown-linux-musl   # once, same target as the guard
make ui                       # as your normal user
sudo make install-ui ENV=/etc/fips-shield/shield.env
sudo systemctl daemon-reload && sudo systemctl enable --now shield-ui
```

`install-ui` records the env path in `/etc/default/shield-ui`, because
the service starts in `/` and would otherwise find no configuration. It
also installs `shield-config` and `presets/`, which the dashboard runs
to resolve configuration. It does **not** install `shield-ban`; that
comes from `sudo make install` or `sudo make install-guard`. Without it
the Bans panel says so.

**Keep `shield.env` outside a home directory.** The unit runs as root
with an empty `CapabilityBoundingSet`, so it has no
`CAP_DAC_READ_SEARCH` and cannot traverse a `0750` home directory —
Ubuntu's default. A `shield.env` in `~/fips-shield/` is unreadable, and
the dashboard starts cleanly and reports `no such env file` on every
panel. `install-ui` checks for this and warns. `/etc/fips-shield/` is
the right home for it.

Then, from your workstation:

```sh
ssh -N -L 8088:127.0.0.1:8088 <node>
```

and open <http://localhost:8088>.

Build as your normal user and install as root, for the same reason the
guard does: a rustup toolchain lives outside sudo's `secure_path`.

## What it shows

| Panel | Source |
|---|---|
| Services — profile, port, upstream, preset level, every limit in force with `preset` / `custom` provenance | `shield-config show --porcelain` |
| Bans — node identity and time remaining, permanent marked as such | `shield-ban list` |
| Kernel guard — packet counters, throttle setting, map occupancy | `fips-guard stats` |
| Logs — the last 200 lines of any service's stream or access log | the files themselves |

Everything refreshes every five seconds.

It resolves configuration by calling `shield-config`, not by reading
`shield.env` itself, so what the dashboard shows and what the shield
enforces cannot drift apart. A service whose limits you have pinned
shows `custom` against those keys and reports its preset as `custom`
rather than naming a preset it no longer follows.

Panels degrade independently. The eBPF guard is optional, so an absent
`fips-guard` renders "not in use" rather than an error, and the rest of
the page still works.

## When a panel says a tool did not run

Each panel reports the command it ran, the error, and the path it tried,
because the causes need different fixes:

| Message | Cause | Fix |
|---|---|---|
| `No such file or directory` | the tool is not installed on this host | `sudo make install`, `sudo make install-guard`, or point the matching `--shield-*` flag at it |
| `no such env file: /home/...` | the path exists but the service cannot traverse a `0750` home directory | move `shield.env` to `/etc/fips-shield/`, or use container mode |
| `no shield.env found` | started in `/` with nothing to read | set `SHIELD_UI_ENV_FILE` in `/etc/default/shield-ui` |
| a permission error from `fips-guard` | the unit has no `CAP_BPF`, so the pinned maps cannot be opened | see below |
| everything resolves, but Logs and Bans are empty | host mode against a container deployment | use the compose overlay instead |

To reproduce what the service sees, drop the capabilities the way the
unit does:

```sh
sudo setpriv --bounding-set=-all --inh-caps=-all cat /path/to/shield.env >/dev/null \
    && echo readable || echo blocked
```

### The eBPF panels and CAP_BPF

With the eBPF backend, `shield-ban list` and `fips-guard stats` open
pinned BPF maps, which needs `CAP_BPF`. The unit ships with an empty
capability bounding set, so those two panels report a permission error
by default. That is deliberate: **`CAP_BPF` is host-wide**, permitting
any BPF map on the machine to be opened, not just the shield's.

To accept that trade:

```sh
sudo systemctl edit shield-ui
```

```ini
[Service]
CapabilityBoundingSet=CAP_BPF
```

On the file backend nothing is needed — `shield-ban` just reads the
banlist.

## Security

**It has no authentication.** It is bound to loopback and meant to be
reached through an ssh tunnel. The binary **refuses to bind a
non-loopback address** unless you pass `--insecure-bind`:

```
Error: refusing to bind 0.0.0.0:8088 — it is not a loopback address and
this page has no authentication. It lists banned node identities and
serves log contents, so exposing it on the mesh hands an attacker the
shield's own view.
```

That refusal is deliberate. On a FIPS mesh every peer is authenticated
but not necessarily trusted, and this page tells a reader exactly which
identities are banned, for how long, and what every limit is set to —
which is most of what you would want before probing a node. Put real
authentication in front of it before you widen the bind.

The systemd unit adds `IPAddressAllow=localhost` / `IPAddressDeny=any`
on top, so even a misconfigured bind cannot be reached off-box.

`ProtectHome=read-only` rather than `yes`, because `shield.env` commonly
lives in a checkout under a home directory and `yes` would make it
unreadable — the dashboard would start cleanly and report "no shield.env
found" on every panel. Writes are still blocked. If you keep
`shield.env` outside `/home`, tighten it back to `yes`.

What the process can do is bounded by construction:

- **GET only.** Every other method is 405 before routing.
- **A fixed route table.** Paths are matched, never mapped onto the
  filesystem.
- **Log lookups are whitelisted**, not sanitised. The service name is
  interpolated into a filename, so it is checked against the configured
  services first — `?service=../../etc/passwd` is a 404, not a file
  read.
- **Bounded reads.** Caps on the request line, header count and size,
  the tail window (2 MB), and the line count (1000, clamped not
  rejected).
- **No writes.** It opens files for reading and runs only the query
  verbs of tools that already exist.
- The unit runs with `ProtectSystem=strict`, an empty capability
  bounding set, a syscall filter, and `ReadOnlyPaths` for the log and
  bpf directories.

`test/ui_smoke.sh` asserts the refusals — traversal, write methods,
absurd line counts, routable bind — alongside the reporting.

## Why read-only

Everything the dashboard does today needs no privilege beyond reading.
Adding ban/unban or config editing changes that: applying config means
writing `/etc/nginx/conf.d` and reloading nginx, which is root, and a
bad config applied through a web form can take down the shield **and**
the form.

The shape that work needs is an unprivileged web process plus a small
privileged helper with a fixed verb set over a unix socket — plus
authentication, an audit log, and validate-before-apply with rollback.
That is a different security review from this one, so it is a different
phase.

One trap already known for whoever builds it: **ban actions must go
through `fail2ban-client`, not `shield-ban`.** Calling the backend
directly leaves fail2ban's ticket state and the backend disagreeing,
which is the class of bug that produced two separate unban failures in
this project already.

## Options

All also settable in `/etc/default/shield-ui`.

| Flag | Env | Default |
|---|---|---|
| `--bind` | `SHIELD_UI_BIND` | `127.0.0.1:8088` |
| `--insecure-bind` | `SHIELD_UI_INSECURE_BIND` | off |
| `--env-file` | `SHIELD_UI_ENV_FILE` | whatever `shield-config` finds |
| `--log-dir` | `SHIELD_UI_LOG_DIR` | `/var/log/nginx` |
| `--shield-config` | `SHIELD_UI_CONFIG_BIN` | `/usr/local/bin/shield-config` |
| `--shield-ban` | `SHIELD_UI_BAN_BIN` | `/usr/local/bin/shield-ban` |
| `--fips-guard` | `SHIELD_UI_GUARD_BIN` | `/usr/local/bin/fips-guard` |

## API

The page is a client of these; they are stable enough to script against.

```sh
curl -s localhost:8088/api/status                       # services, bans, guard
curl -s localhost:8088/api/bans                         # the full ban list
curl -s 'localhost:8088/api/logs?service=web&kind=access&n=50'
```

`kind` is `stream` or `access`. `service` must be one of the configured
service names.
