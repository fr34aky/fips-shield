# fips-shield user guide

Everything you need to run fips-shield in front of a service on your
FIPS mesh node — what it protects against, how to install it, how to
configure it, and how to operate it day to day.

To protect a service that is *not* a Nostr relay, you can read this
guide first for background, or jump straight to
[protecting-your-service.md](protecting-your-service.md), which is a
cookbook of worked examples (SSH, databases, HTTP APIs, anything TCP).

**Contents**

1. [What problem this solves](#1-what-problem-this-solves)
2. [How it works](#2-how-it-works)
3. [Installing and running](#3-installing-and-running)
4. [Configuration](#4-configuration)
5. [Feature reference](#5-feature-reference)
6. [Operating it](#6-operating-it)
7. [Optional: kernel-level enforcement](#7-optional-kernel-level-enforcement)
8. [Troubleshooting](#8-troubleshooting)

---

## 1. What problem this solves

When you expose a service on your FIPS mesh interface (`fips0`), every
peer that can route to you can talk to it. FIPS itself guarantees a
lot: traffic is encrypted, peers are cryptographically authenticated,
and addresses cannot be spoofed. What it does **not** tell you is
whether an authenticated peer is behaving reasonably once connected.

Nothing in the mesh stops a peer from:

- opening thousands of connections,
- reconnecting in a tight loop,
- holding connections open and sending nothing,
- flooding your service with expensive requests inside one connection,
- probing for endpoints your service does not intend to expose.

fips-shield sits between the mesh and your service and applies limits,
filters, and bans to exactly that class of abuse.

### The property that makes this work well

On a FIPS mesh, a source address is a `/128` derived from the peer's
keypair. There is no NAT, no shared addresses, and no spoofing.

That means **every per-address limit is a per-node limit, and every ban
is a node-identity ban**. On the public internet, IP-based blocking is
crude: you punish whole networks and attackers rotate addresses. Here,
an address *is* an identity, so limits and bans are precise and hard to
evade.

### What it does not do

It runs on `fips0`, which the FIPS daemon feeds *after* it has received
and decrypted the traffic. So a banned peer's packets still cost your
daemon the decryption work, and its peer link, routing role, and
transit forwarding are untouched. fips-shield protects the *services on
your host*; it is not a mesh-level control and not a defense against
raw bandwidth floods.

---

## 2. How it works

Traffic passes through up to four layers on its way in. Which ones
apply depends on the profile you choose:

```text
peer ──▶ fips0
          │
          ▼
   1. eBPF (optional)      banned peers dropped in the kernel
          │
          ▼
   2. connection layer     is this peer banned? too many connections?
          │                connecting too often?
          ▼
   3. request layer        (http/strfry profiles) too many requests?
          │                a method or path you don't expose?
          ▼
   4. message layer        (protocol-aware profiles) is what they're
          │                sending inside the connection acceptable?
          ▼
   5. your service         only clean traffic arrives
```

Alongside them, a **detection engine** (fail2ban) reads the shield's
logs and bans peers that keep misbehaving:

```text
   shield logs ──▶ fail2ban ──▶ shield-ban ──▶ banlist ──▶ layers 1 & 2
```

### Three concepts worth knowing

**Profiles** decide *what* is protected. A profile is a small config
file describing one service: which port to listen on, where the real
service is, and its limits. Three ship with the project:

| Profile | For | Protection depth |
|---|---|---|
| `tcp` | any plain TCP service — SSH, databases, game servers | connection layer |
| `http` | any HTTP app — APIs, dashboards, websites | connection **and** request layer |
| `strfry` | Nostr relays over WebSocket | connection, request **and** message layer |

You can enable several at once, and writing your own is usually one
file ([writing-a-profile.md](writing-a-profile.md)).

**Verdicts** are how the layers report abuse: one structured log line
per violation, in a fixed format. Anything that emits verdicts feeds
the detection engine automatically.

**Enforcement backends** are how bans are applied. Two exist, they use
the identical command (`shield-ban`), and you can run either or both:

| Backend | Enforces | Covers |
|---|---|---|
| banlist file (default) | nginx refuses the connection | services behind the shield |
| eBPF guard (Linux) | kernel drops the packets | *every* service on `fips0` |

---

## 3. Installing and running

You need a FIPS node with the daemon running, and a service you want to
protect. Two ways to run the shield — pick one.

### Before you start: bind your service to loopback

**This is the most important step.** The shield only helps if your
service cannot be reached directly. Configure the service to listen on
`127.0.0.1` (loopback) rather than `0.0.0.0`, `[::]`, or the mesh
address.

Check what is currently exposed:

```sh
ss -tulnp
```

Anything bound to `*`, `0.0.0.0`, or `[::]` is reachable from the mesh
today, shield or not.

### Find your mesh address

```sh
ip -6 addr show fips0        # the fd97:... address
# or
sudo fipsctl show status     # the "ipv6_addr" field
```

### Option A — container mode (recommended to start)

Nothing to install but Docker; the shield and its detection engine run
as two containers.

```sh
git clone https://github.com/fr34aky/fips-shield.git
cd fips-shield/deploy/container
cp ../../shield.env.example shield.env
$EDITOR shield.env            # see section 4
docker compose up -d
```

The shield container uses host networking — it has to, because it binds
your node's mesh address, which lives on the host. The fail2ban
sidecar has no network at all; it only reads logs and writes bans
through shared volumes.

Check it came up:

```sh
docker compose ps
docker compose logs shield
```

### Option B — host mode

nginx runs directly on the node. Requires the **njs stream module**:

```sh
# Debian/Ubuntu (distro nginx)
sudo apt install nginx libnginx-mod-stream-js

# or nginx.org packages
sudo apt install nginx nginx-module-njs
# then add to the top of /etc/nginx/nginx.conf:
#   load_module modules/ngx_stream_js_module.so;
```

Your `nginx.conf` also needs a `stream {}` block that picks up the
shield's config (the `http {}` include is already standard):

```nginx
stream {
    include /etc/nginx/conf.d/*.stream;
}
```

`core/nginx/nginx.conf` in the repository is a complete working
example. Then:

```sh
cp shield.env.example shield.env
$EDITOR shield.env
sudo deploy/host/render.sh shield.env      # renders config + installs the engine
sudo nginx -t && sudo systemctl reload nginx

sudo apt install fail2ban                  # detection engine
sudo deploy/host/install-fail2ban.sh shield.env
sudo fail2ban-client -t && sudo systemctl reload fail2ban
```

Or simply `sudo make install`, which runs both steps.

### Open the port on the mesh firewall

If you run the FIPS firewall baseline (`fips-firewall.service`), open
the port the *shield* listens on — never the service's own port:

```sh
sudo tee /etc/fips/fips.d/shield.nft >/dev/null <<'EOF'
tcp dport 80 accept
EOF
sudo systemctl reload-or-restart fips-firewall.service
```

### Verify

From another mesh node, connect to the shield's port on your node's
address (`<npub>.fips` or the `fd97:...` address). Then, on your node:

```sh
# container mode
docker compose logs shield
docker exec <shield-container> cat /var/log/nginx/shield-*.stream.log

# host mode
sudo tail /var/log/nginx/shield-*.stream.log
```

You should see one JSON line per session.

---

## 4. Configuration

Everything lives in one file, `shield.env`. Copy
`shield.env.example` — every option is documented inline — and edit.
Both deploy modes read the same file.

### The three settings you must set

```sh
# 1. Which profile(s) to run (comma-separated for several)
SHIELD_PROFILES=tcp

# 2. Your node's mesh address (ip -6 addr show fips0)
SHIELD_BIND_ADDR=fd97:1234:5678:9abc:def0:1234:5678:9abc

# 3. Where your real service listens — must be loopback
SHIELD_TCP_UPSTREAM=127.0.0.1:22
```

### Everything else has a working default

Grouped by what they do:

| Group | Variables | Meaning |
|---|---|---|
| Listener | `SHIELD_*_LISTEN_PORT` | port on the mesh address |
| Limits | `SHIELD_*_CONN_RATE`, `SHIELD_CONN_WINDOW` | new connections per node per window |
| Limits | `SHIELD_*_MAX_CONNS_PER_NODE` | simultaneous connections per node |
| Limits | `SHIELD_*_IDLE_TIMEOUT` | reap silent connections |
| Bans | `SHIELD_BAN_FILE`, `SHIELD_BAN_RECHECK` | where bans live; how fast live sessions notice |
| Detection | `SHIELD_F2B_*` | how many violations before a ban, and for how long |
| strfry only | `SHIELD_WS_*`, `SHIELD_NOSTR_*` | WebSocket/Nostr message policy |

After changing anything:

```sh
# container mode
docker compose up -d --force-recreate

# host mode
sudo deploy/host/render.sh shield.env && sudo nginx -t && sudo systemctl reload nginx
```

### A note on shared limits

The per-node concurrency cap is counted in one shared table across all
enabled profiles. If a peer holds 3 connections to one profile and 2 to
another, it has 5 in the table. Size the caps with that in mind when
you run several profiles.

---

## 5. Feature reference

Everything the shield can do, and where each thing is configured.

### Connection layer (every profile)

| Feature | What it stops | Setting |
|---|---|---|
| Ban enforcement | banned nodes, refused at accept | `SHIELD_BAN_FILE` |
| Live-session cutting | a node banned while connected | `SHIELD_BAN_RECHECK` |
| Connection-rate limit | reconnect loops, connection floods | `SHIELD_*_CONN_RATE`, `SHIELD_CONN_WINDOW` |
| Concurrency cap | one node hogging all your capacity | `SHIELD_*_MAX_CONNS_PER_NODE` |
| Idle reaping | connections held open doing nothing | `SHIELD_*_IDLE_TIMEOUT` |
| Session logging | (feeds detection) | always on |

### Request layer (`http` and `strfry` profiles)

| Feature | What it stops | Setting (`http` profile) |
|---|---|---|
| Request-rate limit | request floods on one connection | `SHIELD_HTTP_REQ_RATE`, `_BURST` |
| Method allowlist | writes to a read-only service | `SHIELD_HTTP_METHODS` (space-separated) |
| Path allowlist | probing routes you don't expose | `SHIELD_HTTP_PATH_REGEX` |
| Body size cap | memory-exhausting uploads | `SHIELD_HTTP_MAX_BODY` |
| Slow-client timeouts | slowloris | built in |
| Silent close (444) | gives scanners nothing to fingerprint | built in |

The `strfry` profile has the same layer with its own knobs
(`SHIELD_HANDSHAKE_RATE`, `_BURST`), tuned for relay handshakes.

### Message layer (protocol-aware profiles, today: `strfry`)

| Feature | What it stops | Setting |
|---|---|---|
| Protocol strictness | malformed/abusive frames | built in |
| Message size cap | memory-exhaustion messages | `SHIELD_WS_MAX_MSG` |
| Per-message-type rate limits | EVENT spam, REQ floods | `SHIELD_WS_MSG_RATE`, `_EVENT_`, `_REQ_` |
| Subscription cap | subscription exhaustion | `SHIELD_WS_MAX_SUBS` |
| Query-complexity cap | expensive database queries | `SHIELD_WS_MAX_FILTERS`, `_FILTER_ITEMS` |
| Type allowlist / kind denylist | unwanted message types or content kinds | `SHIELD_NOSTR_TYPES`, `_KIND_DENY` |

A rejected message is **never forwarded** — your service never sees it.

### Detection and response

| Feature | Detail | Setting |
|---|---|---|
| Handshake-flood jail | repeated rate-limit rejections | `SHIELD_F2B_HANDSHAKE_MAXRETRY` |
| Verdict jail | repeated protocol/limit violations | `SHIELD_F2B_VERDICT_MAXRETRY` |
| Scan jail | repeated probing of unknown paths | `SHIELD_F2B_SCAN_MAXRETRY` |
| Escalating bans | each re-offense doubles the ban, up to a week | `SHIELD_F2B_BANTIME` |
| Allowlist | never ban these sources | `SHIELD_F2B_IGNOREIP` |

### Kernel enforcement (optional, Linux)

| Feature | Detail |
|---|---|
| In-kernel drops | banned peers dropped before any socket work |
| Host-wide coverage | protects every listener on `fips0`, not just proxied ones |
| Packet-rate throttling | per-source packet limit, cheaper than any userspace limit |
| In-kernel expiry | bans lapse on time with nothing running |

---

## 6. Operating it

### Managing bans by hand

There are two ban registries, and they must agree:

- **fail2ban** holds a ticket per banned node (in memory, plus its
  SQLite database). This is what decides whether a *new* offence leads
  to a ban.
- **the enforcement backend** holds the banlist that nginx and the eBPF
  guard actually read (`SHIELD_BAN_FILE`, or the pinned BPF maps).
  `shield-ban` is its CLI.

fail2ban drives the backend, never the reverse. **So while the
detection engine is running, ban and unban through `fail2ban-client`**
— it updates its own ticket *and* calls `shield-ban` for you. Use
`shield-ban` directly for reading (`check`, `list`), and for writing
only on a deployment with no fail2ban.

```sh
# unban (all jails + fail2ban's database, and calls shield-ban unban)
sudo fail2ban-client unban fd97:...:1234

# ban for an hour, attributed to a specific jail
sudo fail2ban-client set fips-shield-handshake banip fd97:...:1234 3600

# read the enforcement backend
shield-ban check fd97:...:1234       # exit 0 if banned
shield-ban list                      # active bans and their expiry
```

Jail names are `fips-shield-handshake`, `fips-shield-verdict` and
`fips-shield-scan`.

> ⚠️ **Do not unban with `shield-ban unban` while fail2ban is
> running.** It removes the entry nginx reads but leaves fail2ban's
> ticket in place, and fail2ban will not re-ban a node it believes is
> already banned — it logs `<ip> already banned` and skips the action.
> The node then misbehaves freely until fail2ban's own ban time
> expires, which with escalation (`bantime.increment`) can be days.
> The symptom is a node that still trips the rate limits (429s in the
> access log) but never reappears in `shield-ban list`. Fix it by
> running `fail2ban-client unban <ip>`, which clears the stale ticket
> even when the file entry is already gone.
>
> The same caveat applies to `shield-ban ban`: the ban is enforced, but
> fail2ban knows nothing about it and will not extend or escalate it.

In container mode, run all of these inside the fail2ban container:

```sh
docker compose exec fail2ban fail2ban-client unban fd97:...:1234
docker compose exec fail2ban shield-ban list
```

### Checking every jail at once

```sh
sudo fail2ban-client banned          # every jail's banned IPs, as a dict
sudo fail2ban-client status          # which jails exist
```

`banned` is the quickest way to see the whole picture, and the one to
compare against the backend. The two lists should match:

```sh
sudo fail2ban-client banned          # what detection thinks is banned
shield-ban list                      # what is actually enforced
```

An address in the first but not the second is the desync described
above. An address in the second but not the first is a manual or
expired-in-fail2ban ban that is still being enforced — harmless, and
it lapses at its own expiry.

Per-jail detail, including the match counter and the current ban list:

```sh
sudo fail2ban-client status fips-shield-verdict
```

If a counter stays at zero the jail is not reading its log; if it
climbs without banning, look for `already banned` in fail2ban's log
(`/var/log/fail2ban.log` — inside the sidecar in container mode, not
in the shared log volume).

### Reading the logs

Two files matter:

- `shield-<service>.stream.log` — one JSON line per session. A
  non-empty `verdict` field means the shield refused or cut it.
- `shield-error.log` — one `shield-verdict` line per violation, with
  the rule that fired and the offending node.

```sh
# who is getting refused, and why
grep shield-verdict /var/log/nginx/shield-error.log | tail -20

# busiest peers today
awk -F'"' '/"src"/ {print $8}' /var/log/nginx/shield-*.stream.log \
    | sort | uniq -c | sort -rn | head
```

### Tuning limits

Start with the defaults, then watch `shield-error.log` for a week:

- **Legitimate clients tripping limits?** Your limits are too tight —
  raise the specific one named in the `rule` field.
- **Abuse getting through?** Tighten that limit, or lower the matching
  `SHIELD_F2B_*_MAXRETRY` so offenders get banned sooner.
- **Never any verdicts?** That is fine. It means nobody is misbehaving.

Set `SHIELD_F2B_IGNOREIP` to your own monitoring nodes so they are
never banned.

---

## 7. Optional: kernel-level enforcement

The eBPF guard makes bans cost nothing and extends them to every
service on the mesh interface — including ones not behind the shield,
like SSH on its own port. Linux only; needs root.

```sh
make guard                             # as you, not under sudo
sudo make install-guard
sudo systemctl daemon-reload
sudo systemctl enable --now fips-guard
```

That installs `shield-ban` as the guard's wrapper, so a **host-mode**
detection engine starts enforcing in the kernel with no other changes.

In container mode, add the overlay that shares the guard's pinned maps
with the detection sidecar, so fail2ban bans in the kernel instead of
writing a banlist file:

```sh
docker compose -f compose.yaml -f compose.guard.yaml up -d --build
```

`--build` is required the first time: `compose up` reuses an existing
image when the Dockerfile changes, and the sidecar has to be rebuilt to
run the host's binary. It verifies this at startup and refuses to start
if the wiring is wrong, so check `docker compose logs fail2ban`.

The sidecar gets `CAP_BPF` and the host's `fips-guard` bind-mounted; it
keeps `network_mode: none` and needs no `CAP_NET_ADMIN`, because loading
the classifier stays on the host. Full explanation in
[../guard/README.md](../guard/README.md#from-the-containerized-fail2ban).

Without that overlay the sidecar uses the banlist-file backend: bans are
enforced by nginx at accept and mid-session, and `fips-guard stats` stays
at zero because nothing calls the guard. That is working enforcement, not
a fault — just not in the kernel.

Verify the guard enforces at all, independently of detection:

```sh
sudo fips-guard ban <a-test-node-address> 60
sudo fips-guard list                  # the entry, with its expiry
sudo fips-guard stats                 # "bans 1"; drops climb as it retries
sudo fips-guard unban <address>
```

Optional per-source packet throttle:

```sh
sudo fips-guard throttle 2000 4000    # 2000 pkt/s per node, burst 4000
sudo fips-guard stats                 # counters and current settings
```

Full details: [../guard/README.md](../guard/README.md).

---

## 8. Troubleshooting

**Clients cannot reach the service at all.**
Check, in order: the shield is running (`docker compose ps` /
`systemctl status nginx`); the mesh firewall allows the shield's port;
`SHIELD_BIND_ADDR` matches `ip -6 addr show fips0`; and your service is
actually listening on the loopback address in `SHIELD_*_UPSTREAM`
(`ss -tulnp`).

**Everything works, but the shield is not involved.**
Your service is probably still bound to all interfaces, so peers reach
it directly. Confirm with `ss -tulnp` that it listens only on
`127.0.0.1`.

**A legitimate client keeps getting refused.**
Check whether it is banned (`shield-ban check <addr>`) and why
(`grep <addr> /var/log/nginx/shield-error.log`). Unban it with
`fail2ban-client unban <addr>`, raise the limit that fired, and
consider adding it to `SHIELD_F2B_IGNOREIP`.

**fail2ban reports the node banned, but `fips-guard stats` shows no
drops.**
Detection is not reaching the guard; the ban is being enforced by nginx
instead. Two causes. In container mode, the sidecar uses the
banlist-file backend unless you started it with `compose.guard.yaml` —
see [§ 7](#7-optional-kernel-level-enforcement). In host mode, check
which backend is installed:

```sh
head -3 /usr/local/bin/shield-ban     # "eBPF edition" = the guard
```

If it is the file backend, `install-fail2ban.sh` or `make install` was
run after `make install-guard` and replaced it. Current versions detect
and keep the wrapper; older ones overwrote it. Reinstall with
`sudo make install-guard`.

**A node keeps misbehaving but is never banned again.**
Almost always a previous unban that bypassed fail2ban. Compare
`fail2ban-client banned` with `shield-ban list`: if the address is in
the first and not the second, fail2ban still holds a ticket and is
skipping the ban action (`grep "already banned" /var/log/fail2ban.log`).
`fail2ban-client unban <addr>` clears it. See
[managing bans by hand](#managing-bans-by-hand).

**nginx will not start after a config change.**
Run `sudo nginx -t` — it names the file and line. In host mode, a
missing `stream {}` block or the njs module not being loaded are the
two usual causes.

**Bans have no effect.**
Both the shield and the detection engine must see the *same* banlist
file: same `SHIELD_BAN_FILE`, and in container mode the same volume
mounted in both containers. `shield-ban list` shows what is actually
recorded.

**fail2ban is not banning anything.**
`fail2ban-client status <jail>` shows what it has matched. If the
counter stays at zero, it is not reading the log — check the paths in
its jail config and that the shield is actually writing verdicts.

---

## Where to go next

- [protecting-your-service.md](protecting-your-service.md) — worked
  examples for SSH, databases, HTTP APIs, and other services.
- [writing-a-profile.md](writing-a-profile.md) — protecting a service
  with protocol-aware rules of its own.
- [verdict-schema.md](verdict-schema.md) — the log format and ban CLI,
  for integrating your own tooling.
- [../guard/README.md](../guard/README.md) — the eBPF backend in depth.
