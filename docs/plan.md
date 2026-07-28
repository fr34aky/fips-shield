# fips-shield implementation plan

Standalone project (separate from the fips repository). Two deployment
modes throughout: **host mode** (nginx + tooling installed directly on
the fips node) and **container mode** (a shield container with host
networking in front of the protected service). eBPF phases are
Linux-only; the nginx layers work anywhere nginx runs.

Design invariant: on a FIPS-only service, source IPv6 = authenticated
node identity (stable /128 per keypair, no NAT, no spoofing). All
limits, detections, and bans key on the source /128.

## Modular seams

1. **Profiles** — `profiles/<service>/`: everything service-specific
   (vhost/stream config, filter rules, jails, docs). Core stays
   service-agnostic.
2. **Detection modules** — emit verdicts in one JSON schema
   (`{src_ip, rule, severity, ttl, evidence}`) into logs/spool.
3. **Enforcement backends** — consume verdicts: nginx denylist, eBPF
   maps, future fips-daemon peer actions. Each backend is one action
   script implementing the same interface.

## Phase 1 — Baseline reverse proxy + HTTP-level hardening ✅

- Core nginx layer (`core/nginx/`): JSON log format with limiter
  status, per-node limit_req/limit_conn zones, WS upgrade map.
- strfry profile: fips0-bound vhost, surface reduction to `GET /`,
  handshake rate limit, per-node connection cap, slow-client
  containment, idle-WS reaping, 444 on unknown paths.
- envsubst templating shared by both deploy modes; `shield.env` as the
  single tuning surface.
- Container mode (Dockerfile + compose, host networking) and host mode
  (`render.sh`).
- `test/validate.sh`: render + `nginx -t` in Docker.

## Phase 2 — WebSocket message-aware filtering

- nginx `stream` stage in front of the http stage; njs `js_filter`
  passes the WS handshake through, then parses client→server frames
  (unmasking included) and the Nostr JSON inside.
- Per-connection token buckets for `REQ`/`EVENT`/`COUNT`; caps on
  subscription count, filter complexity, frame size; kind allow/deny
  lists per profile.
- Violations: close the connection + emit a verdict log line.
- Risk: njs frame parsing is the hardest deliverable. Fallbacks:
  OpenResty/`lua-resty-websocket`, or relay-native policy (strfry
  `writePolicy`) for the message layer while nginx keeps the
  connection layer.

## Phase 3 — Detection & response engine

- fail2ban with custom filters over the Phase 1/2 JSON logs; jails per
  attack class (handshake flood, REQ flood, EVENT spam, repeated
  malformed frames) with escalating ban TTLs.
- Freeze the verdict schema and the action-script contract — this is
  the plugin interface every later mechanism targets.
- First enforcement backend: nginx denylist include (deny + reload, or
  njs shared dict).
- Container mode: fail2ban sidecar sharing the log volume.

## Phase 4 — eBPF enforcement (`guard/`)

- Rust/aya workspace in this repo: tc clsact ingress program on fips0
  (tc rather than XDP — TUN only does generic XDP; tc is predictable
  there).
- Maps: banned-/128 hash with TTL; per-source token-bucket throttle.
- `guardctl ban|unban|throttle|list` over a unix socket; a fail2ban
  action calls it. Bans drop in-kernel before the socket exists.
- Drop counters exported Prometheus-style.
- No-compiled-code fallback: nftables sets driven by the same action
  script (no per-source throttling, zero code to own).

## Phase 5 — Modularization proof, packaging, CI

- Extract a profile template; prove the seams with a second profile
  (generic TCP service via the stream stage only).
- Integration test harness (Docker): attacker + relay nodes running
  the full stack; assert floods get 429/closed, banned node's traffic
  drops at the eBPF layer, a well-behaved node is unaffected.
- CI: shellcheck, validate.sh, guard build + clippy, integration
  suite. Release packaging (image publish, host-mode tarball).

## Future (out of scope, design toward)

- Enforcement backend talking to `fipsctl`: a banned /128 is a node
  identity, so the fips daemon could refuse/deprioritize the peer
  below the TUN.
- Per-node reputation with decay instead of binary bans.
