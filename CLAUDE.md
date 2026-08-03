# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Layer-7 protection for services exposed over a FIPS mesh (an IPv6 overlay where every source address is a stable /128 tied to a node identity — no NAT, no spoofing, so every per-address limit is a per-node limit and a ban is an identity ban). nginx is the enforcement proxy, fail2ban the detection engine, eBPF the kernel-level ban layer.

Data flow: mesh peers → `fips0` TUN → eBPF tc ingress (kernel drops/throttle) → nginx stream stage + njs (WebSocket inspection) → nginx http stage (request limits) → protected service on loopback. fail2ban tails the shield logs and calls `shield-ban`, which writes the banlist file and/or the eBPF maps.

## Commands

```sh
make help                # list all targets
make test                # full suite (needs Docker; guard tests need Linux + privileges)
make validate            # static: render every profile, nginx -t, fail2ban -t (test/validate.sh)
make test-filters        # fail2ban filters match real log lines
make test-ws             # WebSocket message policy (strfry profile)
make test-ban            # detection -> enforcement loop
make test-tcp            # generic TCP profile
make test-http           # generic HTTP profile
make test-guard          # eBPF guard (privileged, Linux)
make test-guard-sidecar  # containerized fail2ban banning via guard maps
make lint                # shellcheck + rustfmt + clippy (clippy runs with -D warnings)
make guard               # build the eBPF guard (needs clang; build.rs compiles + embeds the BPF object)
```

Each `test-*` target is one script in `test/` — run the script directly to run a single test. The smoke tests build and run Docker containers; there is no unit-test framework. CI (`.github/workflows/ci.yml`) runs lint + validate + all smoke tests on every push.

- shellcheck runs with `--exclude=SC2016` deliberately: the literal `${VAR}` lists handed to envsubst must not expand. Keep that exclusion.
- Build the guard as your normal user, install as root (`make guard`, then `sudo make install-guard`) — rustup lives outside sudo's secure_path; the Makefile enforces this split on purpose.

## Architecture

### Core vs. profiles

Everything service-agnostic lives in `core/` and is shared: ban enforcement, per-node connection-rate limiting, verdict logging (`core/njs/shield_core.js`), shared nginx config and limit zones (`core/nginx/`), fail2ban jails/filters/banaction (`core/fail2ban/`), the banlist-file backend CLI (`core/actions/shield-ban`).

A profile (`profiles/<service>/`) makes one service protected and is usually **one `*.stream.template` file** (plus an optional `*.conf.template` http stage and, only for protocol-aware filtering, an njs module in `core/njs/` that imports `shield_core.js`). Three exist and bracket the range: `tcp` (no inspection), `http` (request-level limits), `strfry` (Nostr/WebSocket, protocol-aware via `core/njs/shield_ws.js`). See `docs/writing-a-profile.md` before adding one.

- Templates are rendered with envsubst; only `${SHIELD_*}` placeholders are substituted, nginx's own `$vars` are left alone.
- File-name numeric prefixes set nginx include order: `00`/`05` are core, profiles start at `10`. Pick a range that won't collide with other profiles enabled simultaneously.
- New tunables go in `shield.env.example` with a comment; profiles are enabled via `SHIELD_PROFILES` (comma-separated).
- `test/validate.sh` auto-discovers profiles and renders each one alone *and* all together — a profile that depends on another or collides with one fails CI.

### Frozen contracts (the plugin seams)

Both are frozen as of Phase 3 — extend by appending fields/adding rules, never by renaming or reordering (`docs/verdict-schema.md`):

1. **Verdict lines** — every detection layer emits one JSON line per violation to the shield error log, grep anchor `shield-verdict`. Field **order is fixed** (fail2ban filters are regex-based); new fields append at the end. Rule `banned` is an enforcement echo — detection filters must ignore it or a banned client knocking would extend its own ban forever.
2. **`shield-ban` CLI** — `ban <ip> <seconds> | unban <ip> | check <ip> | list`. Two backends implement it: the banlist file (`core/actions/shield-ban`, enforced by nginx at accept and mid-session) and the eBPF guard (`guard/shield-ban` → `fips-guard` → tc classifier maps). Idempotent; `<ip>` is lowercase compressed IPv6 as nginx prints it.

### Enforcement layers

- **nginx + njs**: `shield_core.js` re-reads the banlist only on mtime/size change, does fixed-window connection-rate limiting in a shared dict (stream module has no `limit_req`), and logs verdicts. `shield_ws.js` inspects WebSocket/Nostr messages; violations close with a NOTICE + 1008.
- **eBPF guard** (`guard/`): Rust/aya loader (`guard/src/main.rs`) + tc clsact ingress classifier in C (`guard/bpf/shield_guard.bpf.c`) on `fips0`. Covers every listener on the interface, not just shield-fronted ones, and can throttle by packet rate.
- **fail2ban**: three jails (handshake floods/429s, `shield-verdict` lines, surface probing 444/405). Manual ban control must go through `fail2ban-client`, not `shield-ban` directly, or fail2ban's ticket state and the backend diverge.

### Deployment modes

Two, kept equivalent: **container** (`deploy/container/` — shield + fail2ban sidecar sharing log/banlist volumes, host networking to bind fips0) and **host** (`deploy/host/render.sh` + `install-fail2ban.sh`). `render.sh` parses shield.env exactly as `docker --env-file` does (literal KEY=VALUE, no shell evaluation) — keep the two modes in agreement when touching env handling.

## Docs

`docs/README.md` is the index. Key ones when changing behavior: `guide.md` (user-facing operation), `verdict-schema.md` (frozen contracts), `writing-a-profile.md`, `plan.md` (roadmap, complete — see its Future section), `review-2026-07.md` (adversarial review; remaining medium/low findings listed there).
