# Profile: generic HTTP service

Protects any HTTP application exposed to mesh peers — an API, a
dashboard, a static site, an internal tool — with request-level limits
on top of the connection-level ones.

Use this instead of the [`tcp`](../tcp/README.md) profile whenever the
service speaks HTTP. The `tcp` profile can only see connections, so one
connection carrying ten thousand expensive requests looks the same to
it as one carrying a single request. This profile parses HTTP and can
therefore price requests, restrict methods and paths, and cap bodies.

## What it enforces

Connection level (shared with every profile):

- **Ban enforcement** — banned nodes refused at accept, from the same
  banlist the other profiles and the eBPF guard use.
- **Connection rate** per node (`SHIELD_HTTP_CONN_RATE`).
- **Concurrency cap** per node (`SHIELD_HTTP_MAX_CONNS_PER_NODE`).
- **Idle reaping** (`SHIELD_HTTP_IDLE_TIMEOUT`).

Request level (this profile):

- **Request rate** per node (`SHIELD_HTTP_REQ_RATE` /
  `SHIELD_HTTP_REQ_BURST`) — excess gets 429.
- **Method allowlist** (`SHIELD_HTTP_METHODS`, space-separated) —
  anything else gets 403, never reaching the app. Enforced with
  `limit_except` so refused requests still count against the request
  rate; an `if`-based rejection would run before the rate limiter and
  cost an attacker nothing.
- **Path allowlist** (`SHIELD_HTTP_PATH_REGEX`) — matched against the
  normalised, decoded URI, so `../` and `%2e` traversal cannot slip
  past it. Unlisted paths are closed silently (444) so scanners learn
  nothing.
- **Body size cap** (`SHIELD_HTTP_MAX_BODY`) — oversized uploads get
  413 before the app allocates anything.
- **Slow-client containment** — header/body timeouts and header buffer
  caps (slowloris).

All rejections land in `shield-<service>.access.log`, which the
detection jails already read, so repeat offenders are banned with no
extra configuration.

## Configure

```sh
SHIELD_PROFILES=http
SHIELD_BIND_ADDR=fd97:...            # your fips0 address
SHIELD_HTTP_SERVICE=web              # names the log files
SHIELD_HTTP_LISTEN_PORT=8080         # port on the mesh address
SHIELD_HTTP_UPSTREAM=127.0.0.1:3000  # your app — loopback only!
SHIELD_SOCKET_DIR=/run/fips-shield   # private dir for the internal socket

SHIELD_HTTP_REQ_RATE=20r/s
SHIELD_HTTP_REQ_BURST=40
SHIELD_HTTP_METHODS=GET HEAD POST
SHIELD_HTTP_PATH_REGEX=.*
SHIELD_HTTP_MAX_BODY=1m
```

Two worth thinking about rather than leaving at the default:

- **`SHIELD_HTTP_METHODS`** — drop `POST` for a read-only site; the
  default already excludes `PUT`, `DELETE`, and `PATCH`.
- **`SHIELD_HTTP_PATH_REGEX`** — the default (`.*`) exposes the whole
  app. Narrowing it is the cheapest real security win here, e.g.
  `/api/.*|/health` to expose an API while hiding an admin panel that
  lives on the same server.

As always, the app must bind loopback only — if it also listens on
`fips0`, peers reach it without passing the shield (`ss -tulnp`).

## Notes

**WebSockets** are forwarded (the `Upgrade` headers pass through), and
the connection-level protections apply to them, but their **payloads
are not inspected**. Message-level rules need a protocol-aware profile
— see [../strfry/](../strfry/README.md) for a worked example and
[../../docs/writing-a-profile.md](../../docs/writing-a-profile.md) for
how to write one.

**Your app sees the peer's mesh address** in `X-Real-IP` and
`X-Forwarded-For`. Because that address is a node identity rather than
a rotating client IP, it is worth logging and can be used for the app's
own per-user accounting.

**HTTPS**: the mesh path is already encrypted and authenticated end to
end, so TLS on top buys little here and would prevent request-level
filtering entirely (the shield would see ciphertext). This profile is
plain HTTP by design.

**Several HTTP services** need one copy of the profile each — see
[../../docs/protecting-your-service.md](../../docs/protecting-your-service.md#several-services-at-once).
