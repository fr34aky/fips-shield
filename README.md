# fips-shield

Layer-7 protection for services exposed over a [FIPS](https://github.com/)
mesh. First target: Nostr relays (strfry) reachable via authenticated
FIPS IPv6, defended against application-level abuse — connection floods,
handshake churn, slow clients, and (in later phases) WebSocket message
floods — with nginx as the enforcement proxy and eBPF as the kernel-level
ban layer.

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
  [eBPF tc ingress]                Phase 4 — kernel drop/throttle maps
                 │
                 ▼
  [nginx stream stage + njs]       Phase 2 — WS frame inspection
                 │
                 ▼
  [nginx http stage]               Phase 1 — handshake limits, filtering
                 │
                 ▼
  protected service (loopback)     e.g. strfry on 127.0.0.1:7777

  fail2ban (detection) ◀── JSON logs + shield-verdict lines
        └── shield-ban ──▶ banlist file ──▶ nginx (reject/cut)
                └── Phase 4: same CLI ──▶ eBPF maps
```

Three modular seams keep it extensible beyond HTTP and beyond today's
mechanisms:

- **Profiles** (`profiles/<service>/`) — per-service nginx config +
  rules + docs. Adding a service = adding a profile; the core is shared.
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
core/njs/          shield_ws.js — WebSocket/Nostr inspection engine +
                   banlist enforcement (njs)
core/fail2ban/     jails, filters, banaction for the detection engine
core/actions/      shield-ban — enforcement backend CLI (frozen contract)
profiles/strfry/   strfry relay profile: http vhost + stream stage
                   templates, operator notes
deploy/container/  Dockerfiles (shield, fail2ban sidecar) + compose
deploy/host/       render.sh, install-fail2ban.sh + README for running
                   directly on the fips node
test/              validate.sh (static), ws_smoke.sh (WS policy),
                   ban_smoke.sh (detection→enforcement loop)
docs/plan.md       full implementation plan and phase status
docs/verdict-schema.md  frozen verdict schema + backend CLI contract
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
annotated list): bind address/port, upstream, per-node handshake rate
and connection cap, and the WebSocket message policy — message/EVENT/
REQ token buckets, subscription and filter-complexity caps, message
size, type allowlist, kind denylist. Connection-level violations
return 429 and are marked in the JSON access log (`"limited"`);
message-level violations close the WebSocket (NOTICE + 1008) and log a
`shield-verdict` JSON line. Both streams are the detection-engine
input in Phase 3.

## Validation

```sh
test/validate.sh    # static: render, build images, nginx -t, fail2ban -t
test/ws_smoke.sh    # behavioral: WS clients vs. the message policy
test/ban_smoke.sh   # behavioral: detection -> enforcement loop
```

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

## Status / roadmap

Phase 1 — HTTP-level hardening and per-node rate limiting. ✅
Phase 2 — WebSocket message-aware filtering (njs stream stage). ✅
Phase 3 — Detection & response: fail2ban → shield-ban → nginx. ✅
See [docs/plan.md](docs/plan.md) for what's next: eBPF enforcement
(4), second profile + CI (5).
