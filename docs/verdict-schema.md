# Verdict schema and enforcement-backend contract

These two interfaces are the plugin seams of fips-shield: detection
modules emit verdicts, enforcement backends consume ban commands.
Both are **frozen** as of Phase 3 — extend by adding fields/rules,
never by renaming or reordering what exists.

## Verdict lines

Emitted by any detection layer to the shield error log
(`/var/log/nginx/shield-error.log`), one line per violation, grep
anchor `shield-verdict`:

```text
... js: shield-verdict {"ts":"2026-07-28T20:50:19.159Z","src":"fd97::1","service":"strfry","layer":"ws","rule":"event-rate","detail":""}
```

| Field | Meaning |
|---|---|
| `ts` | ISO 8601 UTC timestamp of the violation |
| `src` | source address, as nginx prints `$remote_addr` (on a FIPS mesh: the node's /128, i.e. its identity) |
| `service` | profile name (`strfry`, …) |
| `layer` | detection layer: `ws` (message engine), `ban` (enforcement echo) |
| `rule` | machine-readable rule id, see below |
| `detail` | free-form context, may be empty |

Field **order is fixed** (detection filters are regex-based). New
fields append at the end.

Rules emitted by the `ws` layer: `protocol`, `binary-frame`,
`oversized-handshake`, `oversized-message`, `malformed`,
`type-not-allowed`, `kind-denied`, `msg-rate`, `event-rate`,
`req-rate`, `filter-complexity`, `too-many-subs`, `engine-error`.

Rule `banned` (layers `ws`/`ban`) is an **enforcement echo** — an
already-banned source getting rejected or cut. Detection filters must
ignore it, or a banned client that keeps knocking would extend its own
ban forever.

The http stage contributes connection-level signals through its JSON
access log instead (`status` 429 = rate/conn limit, 444/405 =
surface probing; `"limited":"REJECTED"` marks limit_req rejections).

## Enforcement backend CLI

The detection engine invokes exactly this CLI (fail2ban `banaction`
`fips-shield` calls `/usr/local/bin/shield-ban`); any enforcement
backend implements it:

```text
shield-ban ban <ip> <seconds>    # add or extend a ban
shield-ban unban <ip>            # remove a ban
shield-ban check <ip>            # exit 0 (+expiry on stdout) | exit 1
shield-ban list                  # active bans: "<ip> <until-epoch-s>"
```

`<ip>` is the address as nginx/fail2ban print it (lowercase,
compressed IPv6). Idempotent: banning a banned IP replaces the expiry,
unbanning an unknown IP succeeds.

Backends:

- **banlist file** (Phase 3, `core/actions/shield-ban`): maintains
  `SHIELD_BAN_FILE` (default `/var/lib/fips-shield/banlist`), one
  `<ip> <until-epoch-seconds>` per line, atomic replace under flock,
  expired entries pruned on write. nginx's njs engine re-reads the
  file on mtime change: banned sources are rejected at accept
  (`js_access`) and live sessions are cut within
  `SHIELD_BAN_RECHECK` seconds. Readers honor `until` themselves, so
  a stale file cannot outlive its expiries.
- **eBPF guard** (Phase 4, `guard/`): same CLI, enforced in-kernel by a
  tc classifier on fips0 — covers every listener on the mesh
  interface, drops before any socket work, and adds per-source packet
  throttling. Bans live in pinned BPF maps with in-kernel expiry;
  `guard/shield-ban` is the wrapper fail2ban calls. Installing it
  replaces the file backend without touching the jails
  (`SHIELD_BAN_ALSO_FILE=true` runs both).
