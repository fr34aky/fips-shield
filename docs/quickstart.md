# Quick start

One page, from nothing to a protected service. If you want to
understand *why* any of it works, read the [user guide](guide.md) —
this page is only the shortest path that works.

`shield.env` is short: you set the few things specific to your node and
a **preset** supplies the rest. Three enforcement levels ship —
`strict`, `default`, `loose` — and you can override any individual value
without giving up the preset for everything else.

---

## 1. Find your mesh address

```sh
ip -6 addr show fips0          # the fd97:... address
```

Everything the shield binds is on that address. If you have no `fips0`,
the fips daemon is not running and nothing below will work.

## 2. Copy the config

```sh
cp shield.env.example shield.env
```

Then edit the lines for your case. `SHIELD_BIND_ADDR` is the one edit
every deployment needs.

### A Nostr relay (strfry)

`SHIELD_PROFILES=strfry` is already the default, so this is one line:

```sh
SHIELD_BIND_ADDR=fd97:...
```

Then make strfry listen on loopback only, in `strfry.conf`:

```
relay {
    bind = "127.0.0.1"      # never fips0, never "::"
    port = 7777             # must match SHIELD_UPSTREAM
}
```

### An HTTP app

```sh
SHIELD_PROFILES=http
SHIELD_BIND_ADDR=fd97:...
SHIELD_HTTP_UPSTREAM=127.0.0.1:3000    # your app
```

### A plain TCP service (SSH, a database, …)

```sh
SHIELD_PROFILES=tcp
SHIELD_BIND_ADDR=fd97:...
SHIELD_TCP_UPSTREAM=127.0.0.1:22       # default: SSH
```

### Two or more at once

List them. One profile = one service, and the default ports do not
collide (strfry 80, http 8080, tcp 2222):

```sh
SHIELD_PROFILES=strfry,http,tcp
SHIELD_BIND_ADDR=fd97:...
```

Each service's limits are its own, so a busy relay cannot use up the
budget that lets the same node reach SSH.

**In every case the protected service must bind loopback only.** If it
also listens on `fips0`, mesh peers reach it directly and the shield
protects nothing.

## 3. Pick an enforcement level

```sh
shield-config levels
```

```
strict   Tightest limits and fastest banning. For a node whose clients you
         know, or one under active abuse.
default  Balanced. What the project ships and what the smoke tests exercise.
loose    Generous limits and slow banning. For a busy public service where a
         false positive costs more than an abusive peer.
```

Set one for everything, and optionally a different one per service:

```sh
SHIELD_PRESET=default
SHIELD_STRFRY_PRESET=strict     # relay tight, everything else balanced
```

Then check what that actually means before you start anything:

```sh
shield-config show strfry
```

```
service strfry   preset strict

  KEY                                VALUE            SOURCE
  SHIELD_MAX_CONNS_PER_NODE          4                preset:strfry/strict
  SHIELD_STRFRY_CONN_RATE            30               preset:strfry/strict
  SHIELD_WS_MAX_LIMIT                1000             preset:strfry/strict
  SHIELD_UPSTREAM                    127.0.0.1:7777   preset:strfry/strict
  ...
```

To change one value, set it in `shield.env` — the rest of the preset
still applies:

```sh
SHIELD_WS_MAX_LIMIT=5000        # clients page larger result sets
```

```
  SHIELD_WS_MAX_LIMIT                5000             custom
```

`shield-config diff` lists only what you have overridden, which is the
short answer to "what did I change on this node".

## 4. Start it

### Container mode — easiest, nothing to install but Docker

```sh
cd deploy/container
cp ../../shield.env.example shield.env && $EDITOR shield.env
docker compose up -d
```

The shield uses host networking (it must bind the host's fips0
address), and the fail2ban sidecar shares its log and banlist volumes.

### Host mode — if you already run nginx

Two prerequisites first. The njs **stream** module:

```sh
sudo apt install libnginx-mod-stream-js        # Debian/Ubuntu distro nginx
# nginx.org packages: apt install nginx-module-njs, then add
#   load_module modules/ngx_stream_js_module.so;
# at the top of /etc/nginx/nginx.conf
```

and a `stream{}` block in `/etc/nginx/nginx.conf` that picks up the
rendered stream configs:

```nginx
stream {
    include /etc/nginx/conf.d/*.stream;
}
```

Then:

```sh
sudo make install        # renders configs, installs the fail2ban jails
sudo install -m 644 deploy/host/fips-shield-tmpfiles.conf \
    /etc/tmpfiles.d/fips-shield.conf
sudo nginx -t && sudo systemctl reload nginx
sudo fail2ban-client -t && sudo systemctl reload fail2ban
```

The tmpfiles snippet recreates `SHIELD_SOCKET_DIR` at boot — `/run` is
a tmpfs, and those 0700 permissions are what stop another local process
from spoofing a client address past the shield.

## 5. Open the port on the mesh firewall

Only if the node runs the FIPS firewall baseline (default-deny on
fips0). Open the **shield's** port, never the protected service's:

```sh
sudo tee /etc/fips/fips.d/shield.nft >/dev/null <<'EOF'
tcp dport 80 accept
EOF
sudo systemctl reload-or-restart fips-firewall.service
```

Use the port you configured: 80 for strfry, 8080 for http, 2222 for
tcp — one `accept` line each if you run several.

## 6. Check it works

From **another mesh node**:

```sh
# strfry: NIP-11 relay info
curl -6 -H 'Accept: application/nostr+json' "http://<npub>.fips/"

# http profile
curl -6 "http://<npub>.fips:8080/"

# tcp profile
ssh -p 2222 user@<npub>.fips
```

On the shield host:

```sh
sudo fail2ban-client status            # which jails are running
sudo fail2ban-client banned            # who is banned, per jail
tail -f /var/log/nginx/shield-*.log    # container: docker compose logs -f
```

---

## Optional: kernel-level enforcement (eBPF guard)

Moves bans into the kernel, so they cover **every** listener on `fips0`
rather than only what the shield fronts, and cost nothing per packet.
Entirely optional — the default banlist backend works, and the fail2ban
jails are identical either way.

On Debian:

```sh
sudo apt install clang linux-libc-dev
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add "$(uname -m)"-unknown-linux-musl
make guard                    # as your normal user
sudo make install-guard
mountpoint -q /sys/fs/bpf || sudo mount -t bpf bpf /sys/fs/bpf
sudo systemctl daemon-reload && sudo systemctl enable --now fips-guard
sudo systemctl enable --now fips-guard-watchdog.timer
fips-guard stats              # counters + "bans 0/65536 active"
```

Use rustup rather than `apt install cargo`: Debian's packaged rustc is
generally too old for the aya version used here. Build as your normal
user and install as root — the Makefile enforces that split on purpose,
because a rustup toolchain lives outside sudo's `secure_path`.

The musl target is what makes the build static, and that matters in
container mode: the sidecar bind-mounts this exact binary, and a glibc
build would carry *your build host's* glibc version into an older image
and fail to exec there. `file /usr/local/bin/fips-guard` should say
`static-pie linked`.

Enable the watchdog timer as well as the guard itself. `fips-guard` is
`Type=oneshot`, so nothing notices if its tc filter later disappears —
the pinned maps outlive it and every CLI keeps reporting bans that are
no longer enforced. The timer re-attaches it once a minute.

In container mode, add the overlay so the sidecar bans in the kernel:

```sh
docker compose -f compose.yaml -f compose.guard.yaml up -d
```

> **Read [guard/README.md](../guard/README.md) before enabling the
> overlay.** `CAP_BPF` is host-wide, not shield-scoped: it lets the
> sidecar open every BPF map on the machine. That is a real trade, and
> the file backend is a perfectly good alternative.

Two known rough edges, both open findings:

- **Host mode: keep the default pin directory.**
  `SHIELD_GUARD_PIN_DIR` never reaches the fail2ban action there, so a
  custom path makes every ban fail.
- **`fips-guard check` is not a health check.** It reads the pinned
  maps, which outlive the classifier, so it reports "banned" even if the
  tc filter has been detached and nothing is being enforced. Rising
  counters in `fips-guard stats` are the better signal.

---

## Upgrading an existing install

Nothing to do. A `shield.env` written before presets existed sets every
key explicitly, and an explicit value always wins, so behaviour is
unchanged. `shield-config diff` will list every one of them as `custom`.

To adopt a preset, delete the lines you have no opinion about and add
`SHIELD_PRESET=default`. `shield-config show` before and after tells you
exactly what changed.

## The knobs worth a decision

The presets handle the rest, but these three change behaviour your
clients will notice, so they are worth an explicit choice:

| Knob | Change it when |
|---|---|
| `SHIELD_WS_REQUIRE_NARROWING` | Your clients open genuinely unconstrained subscriptions (`["REQ","s",{}]`). Normal filters like `{"kinds":[1]}` are unaffected. |
| `SHIELD_WS_MAX_LIMIT` | Clients legitimately page larger result sets. |
| `SHIELD_HTTP_METHODS` / `SHIELD_HTTP_MAX_BODY` | Serving uploads — Blossom and NIP-96 need `PUT`/`DELETE` and a much larger body cap. |

Run `shield-config show` to see every value you could pin, with its
current source.
