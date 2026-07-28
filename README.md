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

  detection engine (Phase 3) ◀── JSON logs/verdicts from the nginx stages
        └── actions ──▶ nginx denylist, eBPF maps
```

Three modular seams keep it extensible beyond HTTP and beyond today's
mechanisms:

- **Profiles** (`profiles/<service>/`) — per-service nginx config +
  rules + docs. Adding a service = adding a profile; the core is shared.
- **Detection modules** — anything emitting a verdict in one common
  schema (Phase 3) into the log stream the engine consumes.
- **Enforcement backends** — verdict consumers: nginx denylist, eBPF
  ban/throttle maps, potentially the fips daemon itself (peer-level
  refusal).

## Layout

```text
core/nginx/        shared http-context config: log format, limit zones,
                   WebSocket plumbing (*.conf.template, envsubst)
profiles/strfry/   strfry relay profile: vhost template + operator notes
deploy/container/  Dockerfile + compose for the shield-as-container mode
deploy/host/       render.sh for nginx running directly on the fips node
test/              validate.sh — render + nginx -t in Docker
docs/plan.md       full implementation plan and phase status
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

For a node already running nginx (or preferring no containers):

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
and burst, per-node connection cap, WebSocket idle timeout, limit-zone
sizing. Limit violations return 429 and are marked in the JSON access
log (`"limited"`), which doubles as the detection-engine input in
Phase 3.

## Validation

```sh
test/validate.sh    # renders the example env, runs nginx -t (Docker)
```

## Status / roadmap

Phase 1 (this) — HTTP-level hardening and per-node rate limiting.
See [docs/plan.md](docs/plan.md) for the full plan: WS message-aware
filtering (2), detection & response engine (3), eBPF enforcement (4),
second profile + CI (5).
