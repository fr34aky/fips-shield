# Protecting your own service

fips-shield is not Nostr-specific. The Nostr relay profile is just the
one that also understands the *protocol*; the protections that matter
most — bans, connection-rate limits, concurrency caps, idle reaping —
work for any TCP service without the shield knowing anything about it.

This page is a cookbook. Start with [Which approach do I need?](#which-approach-do-i-need),
then jump to the recipe that matches your service.

- [SSH](#ssh)
- [A database (PostgreSQL, Redis, …)](#a-database-postgresql-redis-)
- [An internal HTTP API](#an-internal-http-api)
- [A Git server](#a-git-server)
- [Several services at once](#several-services-at-once)
- [Choosing sensible limits](#choosing-sensible-limits)
- [Things that will not work](#things-that-will-not-work)

---

## Which approach do I need?

| Your situation | Use |
|---|---|
| Any TCP service; you want bans, rate limits, connection caps | the **`tcp` profile** — 5 minutes, no code |
| Several TCP services on one node | **copy the `tcp` profile** once per service |
| You need rules based on the *contents* of the traffic | **write a profile** ([writing-a-profile.md](writing-a-profile.md)) |
| UDP service | not supported today (see [below](#things-that-will-not-work)) |

Most people need the first row.

## The pattern behind every recipe

Three steps, always the same:

1. **Move the service to loopback** so it is unreachable from the mesh
   directly.
2. **Point the shield at it** — the shield takes over the mesh-facing
   port.
3. **Set the limits** for how that service is normally used.

Peers keep connecting to your node the same way as before; the shield
is transparent to them.

---

## SSH

Protects against connection floods and brute-force reconnect loops, and
means an abusive node can be cut off from SSH by identity.

**1. Bind sshd to loopback.** In `/etc/ssh/sshd_config`:

```
ListenAddress 127.0.0.1
```

```sh
sudo systemctl restart ssh
ss -tulnp | grep :22        # should show 127.0.0.1:22 only
```

**2. Configure the shield** in `shield.env`:

```sh
SHIELD_PROFILES=tcp
SHIELD_BIND_ADDR=fd97:...          # your fips0 address
SHIELD_TCP_SERVICE=ssh             # names the log file
SHIELD_TCP_LISTEN_PORT=22          # peers still use port 22
SHIELD_TCP_UPSTREAM=127.0.0.1:22
SHIELD_TCP_CONN_RATE=6             # 6 new SSH sessions per node per minute
SHIELD_TCP_MAX_CONNS_PER_NODE=3    # 3 concurrent sessions per node
SHIELD_TCP_IDLE_TIMEOUT=12h        # interactive sessions idle a lot
```

**3. Apply**, and open port 22 in the mesh firewall if you run it.

Peers connect exactly as before:

```sh
ssh user@<npub>.fips
```

> **Watch the idle timeout.** A shell left open overnight is normal;
> `12h` (or `1d`) avoids killing it. If you use SSH keepalives, they
> reset the timer anyway.

---

## A database (PostgreSQL, Redis, …)

Databases are the case where an exposure mistake hurts most, and where
connection caps genuinely protect the server: connection storms are a
classic way to knock a database over.

**1. Bind to loopback.** PostgreSQL (`postgresql.conf`):

```
listen_addresses = '127.0.0.1'
```

Redis (`redis.conf`): `bind 127.0.0.1`.

**2. Configure the shield:**

```sh
SHIELD_PROFILES=tcp
SHIELD_TCP_SERVICE=postgres
SHIELD_TCP_LISTEN_PORT=5432
SHIELD_TCP_UPSTREAM=127.0.0.1:5432
SHIELD_TCP_CONN_RATE=30            # apps with connection pools reconnect in bursts
SHIELD_TCP_MAX_CONNS_PER_NODE=20   # keep below your server's max_connections
SHIELD_TCP_IDLE_TIMEOUT=1h
```

> **Size the cap against the server.** If PostgreSQL allows 100
> connections and five peer nodes use it, a per-node cap of 20 means no
> single node can starve the others.

The shield does not authenticate anyone — the database still does its
own authentication. What the shield adds is that only mesh peers can
reach it at all, and no single peer can exhaust it.

---

## An internal HTTP API

The `tcp` profile protects HTTP services at the connection level:
bans, connection rate, concurrency, idle reaping. That covers the
common abuse patterns and needs no HTTP-specific setup.

```sh
SHIELD_PROFILES=tcp
SHIELD_TCP_SERVICE=api
SHIELD_TCP_LISTEN_PORT=8080
SHIELD_TCP_UPSTREAM=127.0.0.1:3000
SHIELD_TCP_CONN_RATE=120           # HTTP clients open connections readily
SHIELD_TCP_MAX_CONNS_PER_NODE=30
SHIELD_TCP_IDLE_TIMEOUT=75s        # keep-alive idle, then reap
```

**When you need more.** Per-*request* rate limiting, path and method
allowlists, and header/body size caps need an HTTP-aware profile —
nginx sees requests only when it proxies in HTTP mode. The `strfry`
profile is a working example of that shape (an HTTP stage behind the
stream stage); copy its `10-strfry.conf.template` and strip the
Nostr-specific parts. See [writing-a-profile.md](writing-a-profile.md).

Rule of thumb: if a single connection can carry unlimited expensive
requests, you eventually want an HTTP-aware profile. If clients open a
connection per request or two, connection-level limits already do most
of the work.

---

## A Git server

Same shape as SSH — Git over SSH is just SSH. For a `git daemon`
(port 9418):

```sh
SHIELD_PROFILES=tcp
SHIELD_TCP_SERVICE=git
SHIELD_TCP_LISTEN_PORT=9418
SHIELD_TCP_UPSTREAM=127.0.0.1:9418
SHIELD_TCP_CONN_RATE=20
SHIELD_TCP_MAX_CONNS_PER_NODE=5
SHIELD_TCP_IDLE_TIMEOUT=10m        # clones can be slow; don't be aggressive
```

> **Long transfers are not idle.** The idle timeout measures silence,
> not duration, so a long clone that keeps sending data is safe. Set it
> generously anyway if your repositories are large.

---

## Several services at once

The `tcp` profile describes *one* service. For several, copy it once
per service — each copy gets its own port, limits, and log file. This
recipe is verified to work with all profiles enabled simultaneously.

```sh
cd fips-shield

# one copy per service, with a distinct file-name prefix (31, 32, …)
cp -r profiles/tcp profiles/ssh
mv profiles/ssh/30-tcp.stream.template profiles/ssh/31-ssh.stream.template
sed -i 's/SHIELD_TCP_/SHIELD_SSH_/g' profiles/ssh/31-ssh.stream.template

cp -r profiles/tcp profiles/postgres
mv profiles/postgres/30-tcp.stream.template profiles/postgres/32-postgres.stream.template
sed -i 's/SHIELD_TCP_/SHIELD_PG_/g' profiles/postgres/32-postgres.stream.template
```

Two things matter: give each copy a **different file-name prefix**
(they would otherwise overwrite each other), and a **different variable
prefix** (so they have independent settings).

Then add each one's variables to `shield.env` and enable them together:

```sh
SHIELD_PROFILES=ssh,postgres

SHIELD_SSH_SERVICE=ssh
SHIELD_SSH_LISTEN_PORT=22
SHIELD_SSH_UPSTREAM=127.0.0.1:22
SHIELD_SSH_CONN_RATE=6
SHIELD_SSH_MAX_CONNS_PER_NODE=3
SHIELD_SSH_IDLE_TIMEOUT=12h

SHIELD_PG_SERVICE=postgres
SHIELD_PG_LISTEN_PORT=5432
SHIELD_PG_UPSTREAM=127.0.0.1:5432
SHIELD_PG_CONN_RATE=30
SHIELD_PG_MAX_CONNS_PER_NODE=20
SHIELD_PG_IDLE_TIMEOUT=1h
```

Verify before deploying — this renders every profile and runs nginx's
own config check:

```sh
make validate
```

Each service gets its own log (`shield-ssh.stream.log`,
`shield-postgres.stream.log`), and the detection engine picks them up
with no extra configuration. Bans are global: a node banned for abusing
one service is refused by all of them.

Remember that the concurrency caps share one table, so a node's
connections across profiles add up.

---

## Choosing sensible limits

Ask three questions about normal use:

1. **How often does one node connect?** → `CONN_RATE` (per
   `SHIELD_CONN_WINDOW`, default 60s). Interactive tools: single
   digits. Connection-pooling apps: tens. HTTP clients: a hundred or
   more.
2. **How many connections does one node hold at once?** →
   `MAX_CONNS_PER_NODE`. Set it above your busiest legitimate peer, and
   well below what your service can survive from a single client.
3. **How long is a connection legitimately silent?** →
   `IDLE_TIMEOUT`. Interactive sessions: hours. Request/response
   traffic: seconds to minutes.

Start generous. Watch `shield-error.log` for a week; the `rule` field
names exactly which limit fired, so tightening is an informed decision
rather than a guess. Legitimate clients tripping a limit is the signal
to raise it — a shield that blocks your own users is worse than none.

---

## Things that will not work

**UDP services.** The shield is TCP-only today. The eBPF guard's bans
*do* cover UDP (it filters packets, not connections), so a banned node
loses UDP access too — but there are no UDP-specific limits.

**Services that need the client's address.** The shield replaces the
peer's address with its own for the upstream connection. The `strfry`
profile solves this with the PROXY protocol; if your service supports
PROXY protocol, add `proxy_protocol on;` to your profile and enable it
on the service side. Otherwise the service sees `127.0.0.1`.

**Encrypted payload inspection.** Message-level filtering needs the
shield to see the traffic. That is fine on a FIPS mesh, where the
transport is already encrypted and decrypted before `fips0` — but if
your service adds its own TLS on top, the shield sees ciphertext and
only connection-level protections apply.

**Protecting the mesh itself.** Bans stop a node from reaching your
*services*. They do not drop its peer link, stop it routing through
you, or save the CPU your daemon spends decrypting its traffic. See
"Where this sits" in the [README](../README.md).
