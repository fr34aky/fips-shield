# Writing a profile

A profile is what makes one service protected. Everything not specific
to a service — ban enforcement, connection-rate limiting, verdict
logging, session logs, limit zones, the njs engine loader — lives in
`core/` and is shared. In the common case a profile is **one template
file**.

Three exist today and bracket the range:

- `profiles/tcp/` — a plain TCP service, no payload inspection. One
  30-line stream server block.
- `profiles/http/` — any HTTP app: a stream stage plus an http stage
  adding request-level limits, without knowing the application.
- `profiles/strfry/` — Nostr over WebSocket, with a protocol-aware
  inspection module on top of both.

## The moving parts

| Piece | Lives in | Notes |
|---|---|---|
| `*.stream.template` | your profile | the fips0-facing listener; rendered into the `stream{}` context |
| `*.conf.template` | your profile (optional) | an http stage, if the service is HTTP; keep it on loopback behind the stream stage |
| njs module (optional) | `core/njs/` | only for protocol-aware filtering |
| everything else | `core/` | inherited, nothing to write |

File-name prefixes set the include order: `00`/`05` are the core, so
profiles start at `10` and up. Pick a range that will not collide with
other profiles a deployment might enable at the same time.

## Minimal profile

`profiles/myservice/40-myservice.stream.template`:

```nginx
# Your own limit zone, declared outside the server block. Never share a
# zone with another profile — see "Nothing may be shared by name" below.
limit_conn_zone $binary_remote_addr zone=shield_myservice_stream_conn:${SHIELD_CONN_ZONE_SIZE};

server {
    listen [${SHIELD_BIND_ADDR}]:${SHIELD_MYSERVICE_PORT};

    access_log /var/log/nginx/shield-myservice.stream.log shield_stream_json;
    error_log /var/log/nginx/shield-error.log warn;

    # One policy string, in a js_var named after the listening port.
    js_var $shield_cfg_${SHIELD_MYSERVICE_PORT} 'service=myservice;ban_file=${SHIELD_BAN_FILE};conn_rate=${SHIELD_MYSERVICE_CONN_RATE};conn_window=${SHIELD_CONN_WINDOW}';
    js_access shield_core.access;

    limit_conn shield_myservice_stream_conn ${SHIELD_MYSERVICE_MAX_CONNS};

    proxy_pass ${SHIELD_MYSERVICE_UPSTREAM};
    proxy_timeout ${SHIELD_MYSERVICE_IDLE_TIMEOUT};
}
```

That block alone gets you ban enforcement (shared with every other
profile and with the eBPF guard), per-node connection rate and
concurrency limits, idle reaping, and structured logs the detection
engine already knows how to read.

## Nothing may be shared by name

nginx has one global namespace for variables and one for limit zones,
and a profile is not the unit of scoping in either. Two profiles that
pick the same name do not get two of something — they get one, silently.
Both mistakes have shipped here, and both were invisible until two
profiles ran at once:

| Thing | Shared-name failure | Rule |
|---|---|---|
| `js_var` | A plain `$shield_conn_rate` in two profiles resolves to whichever nginx parsed last, applying one profile's policy to both. | Name it `$shield_cfg_${...PORT}` and put the whole policy in that one string. |
| `limit_conn_zone` / `limit_req_zone` | nginx counts per (zone, key). Sharing a zone shares the count, so a node's connections to one profile exhaust another's cap and the tightest limit governs everything. | Declare your own zone, named for the profile. |
| njs shared dict | One dict serves the whole shield, so an address-only key merges every profile's counters. | Include `s.variables.server_port` in any key you add. |

The port is the safe discriminator throughout: two servers cannot listen
on the same address and port, so it is unique per listener by
construction. A service name is not — it comes from `SHIELD_*_SERVICE`
and two profiles can be configured with the same string.

`test/multiprofile_smoke.sh` is the regression test for this; it enables
two profiles with mismatched limits and asserts neither spends the
other's budget.

Then:

1. Ship presets: `presets/myservice/{strict,default,loose}.env`, each
   defining **every** `SHIELD_MYSERVICE_*` key the templates reference.
   This is not optional — `shield.env` no longer carries per-profile
   defaults, so a profile without presets fails to resolve. Add to
   `shield.env.example` only the one or two keys an operator must
   choose (typically the upstream), commented out.
   See [presets/README.md](../presets/README.md).
2. Write `profiles/myservice/README.md`: what it enforces, how the
   protected service must be configured (loopback bind!), and the mesh
   firewall drop-in.
3. Enable it with `SHIELD_PROFILES=myservice` (comma-separate for
   several).

`test/validate.sh` picks the profile up automatically — it renders
every profile alone and all of them together, so a profile that
depends on another being enabled, or that collides with one, fails CI.
It also renders every preset level, and rejects a preset key that no
template uses, so a stale or misspelled key fails there rather than
silently doing nothing on an operator's node.

## Protocol-aware filtering

If the shield should look inside the connection, add an njs module
next to `core/njs/shield_ws.js` and point `js_filter` at it. The
contract:

- `import core from 'shield_core.js';` and use `core.verdict(...)` so
  violations reach the detection engine in the frozen schema
  (`docs/verdict-schema.md`), and `core.isBanned(...)` if you want
  established sessions cut mid-flight rather than only refused at
  accept.
- Hold data until it has passed inspection, then forward it. Never
  forward first and judge after — the upstream would already have seen
  it.
- njs cannot hard-terminate a session from a filter callback. Close the
  connection the way the protocol expects (a Close frame, an error
  response) and swallow everything afterwards; let `proxy_timeout` be
  the backstop.
- Fail closed: wrap the callback so an engine bug ends the session
  instead of becoming a bypass.

Add a behavioral test modelled on `test/tcp_smoke.sh` (or
`test/ws_smoke.sh` for a protocol module) that asserts both halves of
the contract: the client is refused *and* the upstream never saw the
offending traffic. Wire it into `.github/workflows/ci.yml` and the
`Makefile`.

## Adding a protection mechanism instead

Mechanisms that apply to every service belong in `core/`, not in a
profile — connection-rate limiting landed that way in Phase 5. Emit a
verdict with a new `rule` value, and it flows into the existing jails
with no changes; a genuinely new enforcement point implements the
`shield-ban` CLI (`docs/verdict-schema.md`) and slots in beside the
banlist file and the eBPF guard.
