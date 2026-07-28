# fips-shield

Layer-7 protection for services exposed over a FIPS mesh — defended
against application-level abuse the mesh's own crypto cannot see:
connection floods, handshake churn, slow clients, and protocol-level
floods inside established connections. nginx is the enforcement proxy,
fail2ban the detection engine, and eBPF the kernel-level ban layer.

Ships with two profiles: **strfry** (Nostr relays, with WebSocket
message-aware filtering) and **tcp** (any plain TCP service — SSH,
databases, APIs). Adding another service is usually one template file.

> **📖 New here? Read the [user guide](docs/guide.md).** It covers
> installation, configuration, and operation from scratch. To protect
> something other than a Nostr relay, go straight to
> [protecting your own service](docs/protecting-your-service.md).

## Threat model

The protected service listens only on the node's `fips0` mesh address.
Every client is an authenticated mesh node: its source address is a
stable `/128` derived from its Nostr keypair, arrives via the local TUN
after Noise decryption, and cannot be spoofed. There is no NAT and no
shared addresses, so **every per-address limit is a per-node limit, and
a ban is a node-identity ban**. The attacker is an authenticated but
abusive peer — the mesh's transport crypto does nothing against L7
misbehavior; that gap is what fips-shield fills.

## Architecture

```text
mesh peers ──▶ fips0 (TUN, owned by the fips daemon)
                 │
                 ▼
  [eBPF tc ingress]                kernel drop/throttle per node
                 │
                 ▼
  [nginx stream stage + njs]       WebSocket message inspection
                 │
                 ▼
  [nginx http stage]               handshake limits, request filtering
                 │
                 ▼
  protected service (loopback)     e.g. strfry on 127.0.0.1:7777

  fail2ban (detection) ◀── JSON logs + shield-verdict lines
        └── shield-ban ──▶ banlist file ──▶ nginx (reject/cut)
                       └──▶ eBPF maps  ──▶ kernel (drop)
```

### Where this sits

Everything above runs on `fips0`, which the fips daemon feeds *after*
transport reception and Noise decryption. That is the right place for
application-level abuse — the mesh's transport crypto authenticates a
peer but says nothing about how it behaves — but it has a ceiling: a
banned node's packets are still decrypted before they are dropped, and
its peer link, routing role, and transit forwarding are untouched.
fips-shield protects the services on this host; it is not a mesh-level
control. Pushing enforcement below the TUN (per-source refusal in the
daemon, driven by the same ban list) is future work.

Three modular seams keep it extensible beyond HTTP and beyond today's
mechanisms:

- **Profiles** (`profiles/<service>/`) — per-service nginx config +
  rules + docs. Adding a service is usually **one template file**;
  everything else is inherited from the core. Two ship today: `strfry`
  (Nostr over WebSocket, protocol-aware) and `tcp` (any plain TCP
  service). See [docs/writing-a-profile.md](docs/writing-a-profile.md).
- **Detection modules** — anything emitting a verdict in the frozen
  schema ([docs/verdict-schema.md](docs/verdict-schema.md)) into the
  log stream the engine consumes.
- **Enforcement backends** — implementations of the frozen `shield-ban`
  CLI: the banlist file (Phase 3, enforced by nginx at accept and
  mid-session), eBPF ban/throttle maps (Phase 4), potentially the fips
  daemon itself (peer-level refusal).

## Layout

```text
core/nginx/        nginx.conf (module loading, http+stream contexts) and
                   shared http-context config: log format, limit zones,
                   WebSocket plumbing (*.conf.template, envsubst)
core/njs/          shield_core.js — bans, connection-rate limiting,
                   verdict logging (shared by every profile);
                   shield_ws.js — WebSocket/Nostr inspection
core/fail2ban/     jails, filters, banaction for the detection engine
core/actions/      shield-ban — enforcement backend CLI (frozen contract)
guard/             fips-guard — eBPF enforcement backend (Rust/aya + a
                   tc classifier in C), same CLI, kernel-level drops
profiles/strfry/   strfry relay: http vhost + stream stage, WS-aware
profiles/tcp/      any plain TCP service: one stream server block
deploy/container/  Dockerfiles (shield, fail2ban sidecar) + compose
deploy/host/       render.sh, install-fail2ban.sh + README for running
                   directly on the fips node
test/              validate.sh (static), ws_smoke.sh (WS policy),
                   ban_smoke.sh (detection→enforcement loop),
                   tcp_smoke.sh (generic profile), guard_smoke.sh (eBPF)
Makefile           build / test / install targets (make help)
docs/               guide.md (start here), protecting-your-service.md
                    (cookbook), writing-a-profile.md, verdict-schema.md,
                    plan.md — index in docs/README.md
shield.env.example all tunables, documented
```

## Quick start — container mode

The shield runs as a container with host networking (it must bind the
host's fips0 address) in front of a loopback-bound service:

```sh
cd deploy/container
cp ../../shield.env.example shield.env
$EDITOR shield.env          # at minimum: SHIELD_BIND_ADDR (ip -6 addr show fips0)
docker compose up -d
```

## Quick start — host mode

For a node already running nginx (or preferring no containers) —
prerequisites (njs stream module, `stream{}` include) in
[deploy/host/README.md](deploy/host/README.md):

```sh
cp shield.env.example shield.env
$EDITOR shield.env
sudo deploy/host/render.sh shield.env /etc/nginx/conf.d
sudo nginx -t && sudo systemctl reload nginx
```

Then configure the protected service per its profile README
([strfry](profiles/strfry/README.md)) and, if the FIPS mesh firewall is
active, open the shield's port on fips0 (also in the profile README).

Verify from another mesh node:

```sh
curl -6 -H 'Accept: application/nostr+json' "http://<npub>.fips/"   # NIP-11
```

## Tuning

All knobs live in `shield.env` (see `shield.env.example` for the full
annotated list): which profiles to run, bind address/port, upstreams,
per-node connection rate and concurrency caps, and — for the strfry
profile — the WebSocket message policy (message/EVENT/REQ token
buckets, subscription and filter-complexity caps, message size, type
allowlist, kind denylist).

Connection-level violations return 429 (HTTP) or refuse the connection
(stream) and are marked in the JSON logs; message-level violations
close the WebSocket with a NOTICE and a 1008 Close. Both write
`shield-verdict` lines, which is what the detection engine consumes.

## Validation

```sh
make test            # everything below
make validate        # static: render every profile, nginx -t, fail2ban -t
make test-ws         # behavioral: WS clients vs. the message policy
make test-ban        # behavioral: detection -> enforcement loop
make test-tcp        # behavioral: generic TCP profile
make test-guard      # behavioral: eBPF drops/throttle (privileged, Linux)
```

CI runs all of them on every push
([.github/workflows/ci.yml](.github/workflows/ci.yml)), plus
shellcheck, rustfmt, and clippy.

`ws_smoke.sh` runs a mock relay upstream plus raw-socket WebSocket
clients inside the container's network namespace and asserts both
halves of the enforcement contract per rule: the client is cut off,
and the offending message never reached the upstream.

## Automated bans

Repeat offenders are banned automatically: fail2ban (container mode: a
sidecar sharing the log volume; host mode:
`deploy/host/install-fail2ban.sh`) tails the shield logs with three
jails — handshake floods (429s), message-level `shield-verdict` lines,
and surface probing (444/405) — and calls the `shield-ban` backend,
which maintains the banlist file. nginx rejects banned nodes at
connection accept and cuts their live sessions within
`SHIELD_BAN_RECHECK` seconds. Ban times escalate (doubling up to a
week) for nodes that keep coming back; expiry and unban restore
service automatically. Manual control uses the same tool:

```sh
shield-ban ban fd97::x 3600 | unban fd97::x | check fd97::x | list
```

Two enforcement backends implement that CLI, and the jails are
identical for both:

- **banlist file** (default, portable) — nginx rejects banned nodes at
  connection accept and cuts their live sessions. Protects the
  shield-fronted service.
- **eBPF guard** (Linux, `guard/`) — a tc classifier on `fips0` drops
  banned nodes' packets in the kernel and can throttle a source by
  packet rate. Protects *every* listener on the mesh interface at no
  per-packet cost. Install per [guard/README.md](guard/README.md) and
  the same fail2ban jails enforce in-kernel.

## Status / roadmap

Phase 1 — HTTP-level hardening and per-node rate limiting. ✅
Phase 2 — WebSocket message-aware filtering (njs stream stage). ✅
Phase 3 — Detection & response: fail2ban → shield-ban → nginx. ✅
Phase 4 — eBPF guard: kernel-level drops and per-source throttle. ✅
Phase 5 — Modular profiles (second profile), Makefile, CI. ✅
The roadmap in [docs/plan.md](docs/plan.md) is complete; see its
"Future" section for what could come next.
