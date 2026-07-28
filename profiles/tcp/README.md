# Profile: generic TCP service

Protects any plain TCP service reachable over the mesh — SSH, a
database, an internal API — where the shield should not (or cannot)
understand the payload.

This profile exists as much to prove the architecture as to be used:
it is a single server block plus environment knobs, with every
mechanism inherited from the shared core. Adding a service is adding
one file.

## What it enforces

- **Ban enforcement** — banned nodes are refused at connection accept,
  from the same banlist the strfry profile and the eBPF guard use.
- **Connection-rate limiting** — new connections per node per window
  (`SHIELD_TCP_CONN_RATE` / `SHIELD_CONN_WINDOW`), counted in a shared
  dict so all workers agree. nginx's stream module has no `limit_req`,
  so this lives in the njs engine.
- **Concurrency cap** — `SHIELD_TCP_MAX_CONNS_PER_NODE` simultaneous
  connections per node.
- **Idle reaping** — `SHIELD_TCP_IDLE_TIMEOUT`.
- **Structured session logs** with the source node and any verdict,
  feeding the same detection engine.

What it does *not* do: inspect or filter the payload. Protocol-aware
rules need a profile that knows the protocol (as the strfry profile
does for Nostr-over-WebSocket).

## Configure

```sh
SHIELD_PROFILES=tcp                    # or strfry,tcp for both
SHIELD_TCP_SERVICE=ssh                 # names the log file and log field
SHIELD_TCP_LISTEN_PORT=2222            # port on the mesh address
SHIELD_TCP_UPSTREAM=127.0.0.1:22       # the protected service (loopback!)
SHIELD_TCP_CONN_RATE=10                # connections per node per window
SHIELD_TCP_MAX_CONNS_PER_NODE=4
SHIELD_TCP_IDLE_TIMEOUT=1h             # long for SSH; shorten for RPC
```

As always, the protected service must bind loopback only — if it also
listens on `fips0`, peers reach it without passing the shield. Check
with `ss -tulnp`.

## Mesh firewall

With the FIPS firewall baseline active, open the shield's port and not
the service's:

```sh
sudo tee /etc/fips/fips.d/shield-tcp.nft >/dev/null <<'EOF'
tcp dport 2222 accept
EOF
sudo systemctl reload-or-restart fips-firewall.service
```

## Running several services

The profile renders one server block per shield instance. For several
TCP services, either run one shield per service (separate config
directories and `shield.env` files) or copy this profile to
`profiles/<name>/` with its own variables and add it to
`SHIELD_PROFILES`.
