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

## What this profile enforces

Connection level (Phase 1, http stage):

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

Message level (Phase 2, stream stage — every Nostr message is
inspected before strfry sees it; a rejected message never reaches the
relay):

- WebSocket protocol strictness: masked client frames only, no RSV
  bits, no binary frames, sane fragmentation, whole-message size cap
  (`SHIELD_WS_MAX_MSG`).
- Per-connection token buckets: all messages (`SHIELD_WS_MSG_RATE`),
  EVENT publishes (`SHIELD_WS_EVENT_RATE`), REQ/COUNT queries
  (`SHIELD_WS_REQ_RATE`), each with a burst knob.
- REQ policy: subscription cap (`SHIELD_WS_MAX_SUBS`), filters per
  query (`SHIELD_WS_MAX_FILTERS`), total filter complexity
  (`SHIELD_WS_MAX_FILTER_ITEMS`).
- Message-type allowlist (`SHIELD_NOSTR_TYPES`) and event-kind
  denylist (`SHIELD_NOSTR_KIND_DENY`).
- On violation: the client gets a `NOTICE` and a 1008 Close, both
  sides are torn down, and a `shield-verdict` JSON line lands in the
  error log (plus the session log's `verdict` field) for the Phase 3
  detection engine.

Note: the shield strips `Sec-WebSocket-Extensions` from handshakes, so
permessage-deflate is never negotiated — frames must stay uncompressed
to be inspectable. strfry's own `writePolicy` remains useful for
content-level decisions (spam scoring, pubkey reputation); the shield
handles the transport- and rate-level abuse in front of it.

Detection & response (Phase 3, fail2ban): repeated violations —
handshake floods, message-level verdicts, surface probing — ban the
node via the `shield-ban` backend (see the README's "Automated bans"
and [../../docs/verdict-schema.md](../../docs/verdict-schema.md));
banned nodes are rejected at connection accept and live sessions are
cut. Still later: kernel-level enforcement (Phase 4 eBPF).
