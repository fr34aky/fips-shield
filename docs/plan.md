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

## Phase 2 — WebSocket message-aware filtering ✅

- nginx `stream` stage owns the fips0 listener; njs engine
  (`core/njs/shield_ws.js`) sniffs the handshake (non-WS sessions pass
  through, pinned to one response by `keepalive_timeout 0`), then
  parses client→server WS frames (unmasking, fragmentation, 16/64-bit
  lengths) and the Nostr JSON inside. Messages are held until
  inspected — a rejected message never reaches the relay. http stage
  moved to loopback behind PROXY protocol + realip, so per-node limits
  still key on the mesh /128.
- Enforced: protocol strictness (mask/RSV/opcodes), whole-message size
  cap, per-connection token buckets (all messages / EVENT / REQ+COUNT),
  subscription cap, filter count + complexity caps, message-type
  allowlist, kind denylist.
- Violations: NOTICE + 1008 Close to the client, Close to the upstream
  (njs cannot hard-kill from a filter callback; the upstream closing
  tears the session down, proxy_timeout as backstop), structured
  `shield-verdict` line in the error log + `verdict` field in the
  stream session log.
- `Sec-WebSocket-Extensions` is stripped in the handshake so
  permessage-deflate is never negotiated (frames must stay
  inspectable).
- Covered by `test/ws_smoke.sh`: mock relay + raw-socket WS clients
  assert per rule that the client is cut and the message never reached
  the upstream (incl. fragmentation reassembly and flood-tail cases).

## Phase 3 — Detection & response engine ✅

- fail2ban with three jails over the shield logs: handshake floods
  (429s in the access log), message-level violations (`shield-verdict`
  lines in the shield error log), surface probing (444/405). Escalating
  ban times (`bantime.increment`, doubling, capped at a week).
- Frozen contracts in `docs/verdict-schema.md`: the verdict JSON line
  (grep anchor `shield-verdict`, fixed field order) and the
  `shield-ban ban|unban|check|list` backend CLI. The `banned` rule is
  excluded from detection filters so enforcement can't feed back into
  detection.
- Enforcement backend: banlist file on a shared volume (atomic replace
  under flock, expired entries pruned on write, expiry honored
  reader-side). No nginx reloads, no docker socket: the njs engine
  re-reads the file on mtime change, rejects banned sources at accept
  (`js_access`) and cuts live sessions within `SHIELD_BAN_RECHECK`
  seconds.
- Container mode: fail2ban sidecar (`Dockerfile.fail2ban`,
  `network_mode: none`) sharing log + banlist volumes; host mode:
  `deploy/host/install-fail2ban.sh` for native fail2ban.
- Covered by `test/ban_smoke.sh`: manual ban (reject at accept),
  unban restore, established-session cut, and the full automatic loop
  (2 violations → fail2ban → banlist → rejected).

## Phase 4 — eBPF enforcement (`guard/`) ✅

- `guard/`: a tc clsact ingress classifier in C (clang -target bpf,
  compiled by build.rs and embedded) loaded by a stable-Rust aya CLI —
  no nightly, no bpf-linker, no libbpf headers. tc rather than XDP
  because fips0 is a TUN (generic XDP only).
- Maps: `shield_bans` (/128 → monotonic + wall-clock expiry),
  `shield_throttle` (LRU token buckets), `shield_config`,
  `shield_stats` (per-CPU counters).
- Deviation from the sketch: **no daemon and no unix socket**. Maps are
  pinned to bpffs and the tc filter owns the program, so the CLI is
  fire-and-forget and both survive its exit. Attachment is a classic
  netlink filter, not TCX — a TCX link dies with the process that
  created it.
- Ban expiry is enforced in-kernel against the monotonic clock, so a
  lapsed ban stops dropping with no sweeper; `list`/`check` prune
  stale entries opportunistically.
- Implements the frozen `shield-ban` CLI (`guard/shield-ban` wrapper),
  so the Phase 3 jails switch to kernel enforcement unchanged;
  `SHIELD_BAN_ALSO_FILE=true` keeps the file backend in sync.
- Packet parsing handles both L3 (TUN — what fips0 delivers) and L2
  devices; `fips-guard stats` reports counters and configuration.
- Covered by `test/guard_smoke.sh` (privileged container, host
  kernel): veth end-to-end drop/unban/reload-persistence plus a TUN
  device exercising the production L3 path, in-kernel expiry, and
  per-source throttling.

Scope, deliberately: this filters on fips0, i.e. after the daemon has
decrypted the traffic. It protects every service on the host but does
not reduce decrypt cost or touch peering/routing — see "Where this
sits" in README.md.

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
