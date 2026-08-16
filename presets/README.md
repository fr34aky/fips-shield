# Presets

A preset is a complete set of values for one scope at one enforcement
level. They exist so that a working deployment is a handful of lines in
`shield.env` rather than 60 knobs you have to have an opinion about.

```
presets/core/{strict,default,loose}.env      shared limits, ban policy, fail2ban jails
presets/strfry/{strict,default,loose}.env    the Nostr/WebSocket profile
presets/http/{strict,default,loose}.env      the generic HTTP profile
presets/tcp/{strict,default,loose}.env       the generic TCP profile
```

`core` always applies. Each profile named in `SHIELD_PROFILES` adds its
own. One profile = one service.

## Two layers, and only two

| Layer | Where | Wins? |
|---|---|---|
| **custom** | `shield.env` | always |
| **preset** | `presets/<scope>/<level>.env` | only where you set nothing |

There is no third layer and no partial preset. A preset defines every
key its scope needs, so `shield.env` never has to be complete — which is
the whole point.

```sh
shield-config levels        # what the three levels mean
shield-config show          # every effective value, and where it came from
shield-config show http     # one service
shield-config diff          # only what you have overridden
```

`show` labels each value `custom` or `preset:<scope>/<level>`, so
"what is this node actually enforcing" has one answer you can read.

## Choosing a level

`SHIELD_PRESET` sets the level for everything.
`SHIELD_<PROFILE>_PRESET` overrides it for one service — a strict relay
next to a loose internal dashboard is a two-line config.

| Level | For |
|---|---|
| `strict` | Clients you control, or a node under active abuse. Tight limits, fast banning, long bans. |
| `default` | Balanced. What the smoke tests exercise and what the docs assume. |
| `loose` | A busy public service where a false positive costs more than an abusive peer does. |

The levels differ only in degree. None of them changes *which*
protections run — every layer is active at every level.

## Overriding

Set the key in `shield.env`. That is the entire mechanism:

```sh
SHIELD_PRESET=strict
SHIELD_WS_MAX_LIMIT=5000      # but let clients page normally
```

```
$ shield-config show strfry | grep MAX_LIMIT
  SHIELD_WS_MAX_LIMIT          5000    custom
```

A key repeated in `shield.env` takes its **last** occurrence, matching
`docker --env-file`, so appending an override to the bottom of the file
works and reads in the order you made the decisions.

## Upgrading an existing install

Nothing to do. A `shield.env` written before presets existed sets every
key explicitly, so every key is `custom` and behaviour is unchanged —
`shield-config diff` will simply list all of them. Adopt a preset by
deleting the lines you do not actually care about and setting
`SHIELD_PRESET`.

## Editing a preset

Prefer overriding in `shield.env`; presets are project defaults, and a
local edit is lost on upgrade. If you do change one, `test/validate.sh`
renders every level with every profile and runs `nginx -t` and
`fail2ban-client -t`, and checks that each preset key is one the
templates actually use — so a typo or a dead key fails CI rather than
your node.
