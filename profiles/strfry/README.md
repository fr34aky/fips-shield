# Profile: strfry Nostr relay

Protects a [strfry](https://github.com/hoytech/strfry) relay exposed to
FIPS mesh peers. The shield owns the fips0-facing listener; strfry must
be reachable only through it.

## strfry configuration requirements

In `strfry.conf`:

```
relay {
    bind = "127.0.0.1"      # loopback only — never fips0, never ::
    port = 7777             # must match SHIELD_UPSTREAM

    realIpHeader = "x-forwarded-for"
}
```

- `bind = "127.0.0.1"` is load-bearing. If strfry listens on a wildcard
  or the fips0 address, mesh peers bypass the shield entirely. Verify
  with `ss -tulnp`: the only fips0-bound listener on the relay's port
  range should be nginx.
- `realIpHeader` makes strfry attribute connections to the mesh source
  address the shield forwards, so strfry's own per-IP connection
  accounting stays per-node instead of seeing everything as 127.0.0.1.

## Mesh firewall interplay

If the node runs the FIPS mesh firewall baseline (`fips-firewall.service`,
default-deny on fips0), open only the shield's port with a drop-in:

```sh
sudo tee /etc/fips/fips.d/shield-strfry.nft >/dev/null <<'EOF'
tcp dport 80 accept
EOF
sudo systemctl reload-or-restart fips-firewall.service
```

Do **not** add a drop-in for strfry's own port (7777) — nothing on the
mesh should reach it.

## What this profile enforces (Phase 1)

- Surface reduction: strfry's HTTP surface is exactly `GET /`
  (WebSocket upgrade, or NIP-11 with `Accept: application/nostr+json`).
  Any other path or method is rejected; unknown paths get connection
  close (444) with no response to fingerprint.
- Handshake rate limiting per mesh node (`SHIELD_HANDSHAKE_RATE`,
  `SHIELD_HANDSHAKE_BURST`) — prices connection churn/reconnect floods.
- Concurrent connection cap per mesh node (`SHIELD_MAX_CONNS_PER_NODE`).
- Slow-client containment: header/body timeouts, small header buffers,
  4k body cap (Nostr carries no HTTP bodies).
- Idle WebSocket reaping after `SHIELD_WS_IDLE_TIMEOUT`.
- Structured JSON access log (`shield-strfry.access.log`) with the
  source node address and limiter status on every line — the input for
  the Phase 3 detection engine.

Not yet enforced (later phases): anything inside the WebSocket after
the upgrade — REQ floods, EVENT spam, oversized filters. Until Phase 2
lands, pair this profile with strfry's own `writePolicy` plugin and
`maxWebsocketPayloadSize` for message-level control.
