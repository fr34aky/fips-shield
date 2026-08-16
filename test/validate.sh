#!/usr/bin/env bash
# Static validation: build the container image and run nginx -t inside
# it with the example environment (bind address swapped for ::1, since
# nginx -t binds the listen sockets). Catches template syntax errors,
# bad include ordering, njs parse errors (js_import loads the engine at
# config time), and envsubst placeholders that leaked through
# unrendered. Every profile is validated alone and all of them
# together. Also exercises host-mode render.sh and the fail2ban config.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

PROFILES=$(cd "$REPO_ROOT/profiles" && echo *)

LEVELS=$(cd "$REPO_ROOT/presets/core" && for f in *.env; do echo "${f%.env}"; done)

# Overrides are APPENDED, never sed-substituted: the example carries only
# the few keys an operator must choose, and presets supply the rest, so a
# sed that matched nothing would silently validate a config this script
# never specified. Appending relies on last-occurrence-wins, which is
# what docker --env-file and shield-config both do.
cp "$REPO_ROOT"/shield.env.example "$WORK_DIR/shield.env"
echo 'SHIELD_BIND_ADDR=::1' >> "$WORK_DIR/shield.env"

docker build -q -f "$REPO_ROOT"/deploy/container/Dockerfile -t fips-shield:test "$REPO_ROOT"
docker build -q -f "$REPO_ROOT"/deploy/container/Dockerfile.fail2ban \
    -t fips-shield-f2b:test "$REPO_ROOT"

# Each profile on its own, then all at once: a profile must not depend
# on another being enabled, and they must not collide.
ALL=$(echo "$PROFILES" | tr ' ' ',')
for set in $PROFILES "$ALL"; do
    echo "--- profiles: $set"
    cp "$WORK_DIR/shield.env" "$WORK_DIR/env.current"
    echo "SHIELD_PROFILES=$set" >> "$WORK_DIR/env.current"

    # Host-mode render path: must succeed and leave no placeholders.
    # The socket directory is redirected into the work dir because
    # rendering runs unprivileged and must not touch /run.
    rm -rf "$WORK_DIR/conf" "$WORK_DIR/njs"
    cp "$WORK_DIR/env.current" "$WORK_DIR/env.render"
    echo "SHIELD_SOCKET_DIR=$WORK_DIR/sock" >> "$WORK_DIR/env.render"
    "$REPO_ROOT"/deploy/host/render.sh "$WORK_DIR/env.render" \
        "$WORK_DIR/conf" "$WORK_DIR/njs" >/dev/null
    if grep -rnE '\$\{SHIELD_[A-Z0-9_]+\}' "$WORK_DIR/conf"; then
        echo "error: unrendered \${SHIELD_*} placeholders in output" >&2
        exit 1
    fi

    # Container path: the real image, real entrypoint templating, nginx -t.
    docker run --rm --env-file "$WORK_DIR/env.current" fips-shield:test nginx -t
done

# Every preset level, with every profile enabled. A preset is config the
# operator never sees rendered, so a typo or a value nginx rejects would
# otherwise surface as a failed start on their node rather than here.
for level in $LEVELS; do
    echo "--- preset level: $level (all profiles)"
    cp "$WORK_DIR/shield.env" "$WORK_DIR/env.preset"
    {
        echo "SHIELD_PROFILES=$ALL"
        echo "SHIELD_PRESET=$level"
    } >> "$WORK_DIR/env.preset"
    docker run --rm --env-file "$WORK_DIR/env.preset" fips-shield:test nginx -t
    docker run --rm --env-file "$WORK_DIR/env.preset" fips-shield-f2b:test \
        fail2ban-client -t >/dev/null
done

# Every key a preset defines must actually be consumed somewhere — a
# stale preset key is a value the operator sets that does nothing.
#
# Two consumers, not one: a ${SHIELD_*} placeholder in a template, or a
# key shield-config hands to the enforcement backend (SHIELD_BAN_FILE,
# SHIELD_BAN_ALSO_FILE, SHIELD_GUARD_PIN_DIR go through `action-env`
# rather than through envsubst, precisely because that list has to be
# conditional).
KNOWN=$(
    grep -rhoE '\$\{SHIELD_[A-Z0-9_]+\}' \
        "$REPO_ROOT"/core "$REPO_ROOT"/profiles | tr -d '${}'
    grep -hoE 'SHIELD_[A-Z0-9_]+' "$REPO_ROOT"/bin/shield-config
)
KNOWN=$(printf '%s\n' "$KNOWN" | sort -u)
for f in "$REPO_ROOT"/presets/*/*.env; do
    while IFS= read -r key; do
        case "
$KNOWN
" in *"
$key
"*) continue ;; esac
        echo "error: $f defines $key, which no template uses" >&2
        exit 1
    done < <(grep -oE '^SHIELD_[A-Z0-9_]+' "$f")
done
echo "--- preset keys all map to real template placeholders"

# Resolver invariants. An empty preset value (SHIELD_F2B_IGNOREIP,
# SHIELD_NOSTR_KIND_DENY, SHIELD_WS_MAX_MSG_READS) must survive as
# empty. It once did not: the resolver split its KEY/VALUE/SOURCE stream
# with `IFS=<tab> read`, tab counts as IFS whitespace, so an empty value
# collapsed and the SOURCE label was written into the config —
# `ignoreip = preset:core/default` made fail2ban exit 255 at startup.
for level in $LEVELS; do
    cp "$WORK_DIR/shield.env" "$WORK_DIR/env.resolve"
    {
        echo "SHIELD_PROFILES=$ALL"
        echo "SHIELD_PRESET=$level"
    } >> "$WORK_DIR/env.resolve"
    out=$("$REPO_ROOT"/bin/shield-config resolve -f "$WORK_DIR/env.resolve")

    if echo "$out" | grep -n 'preset:'; then
        echo "error: a resolved value leaked its source label ($level)" >&2
        exit 1
    fi
    # Every key any enabled scope's preset defines must appear exactly
    # once (all profiles are enabled here, so this covers all of them).
    for f in "$REPO_ROOT"/presets/*/"$level".env; do
        while IFS= read -r key; do
            n=$(echo "$out" | grep -c "^$key=") || true
            [ "$n" -eq 1 ] || {
                echo "error: $key resolved $n times at level $level" >&2
                exit 1
            }
        done < <(grep -oE '^SHIELD_[A-Z0-9_]+' "$f")
    done
done
echo "--- resolver keeps empty values empty and emits each key once"

# The banaction must carry SHIELD_GUARD_PIN_DIR when it is set, and must
# omit it entirely when it is not. Both halves matter: without the first
# a custom pin directory made every ban target maps that do not exist
# (fail2ban logged success, the kernel enforced nothing); with an empty
# `SHIELD_GUARD_PIN_DIR=` instead of an omission, clap would take the
# empty string as the value and break the default case too.
ACT="$REPO_ROOT/core/fail2ban/action.d/fips-shield.conf.template"

cp "$WORK_DIR/shield.env" "$WORK_DIR/env.pin"
echo "SHIELD_GUARD_PIN_DIR=/sys/fs/bpf/custom-test" >> "$WORK_DIR/env.pin"
rendered=$(SHIELD_ACTION_ENV="$("$REPO_ROOT"/bin/shield-config action-env -f "$WORK_DIR/env.pin")"     envsubst '${SHIELD_ACTION_ENV}' < "$ACT")
for verb in actioncheck actionban actionunban; do
    echo "$rendered" | grep -q "^$verb = .*SHIELD_GUARD_PIN_DIR='/sys/fs/bpf/custom-test'" || {
        echo "error: $verb does not carry a custom SHIELD_GUARD_PIN_DIR" >&2
        echo "$rendered" >&2
        exit 1
    }
done

rendered=$(SHIELD_ACTION_ENV="$("$REPO_ROOT"/bin/shield-config action-env -f "$WORK_DIR/shield.env")"     envsubst '${SHIELD_ACTION_ENV}' < "$ACT")
# Only the action lines — the template's own comments name the
# variable, and matching those would fail for the wrong reason.
if echo "$rendered" | grep -E '^action(check|ban|unban) = ' |
        grep -q 'SHIELD_GUARD_PIN_DIR'; then
    echo "error: SHIELD_GUARD_PIN_DIR is unset but still reached the action" >&2
    echo "$rendered" >&2
    exit 1
fi
echo "--- banaction carries a custom guard pin dir, and omits an unset one"

# Detection sidecar: render the jails and let fail2ban verify the full
# configuration (filters, action, jail wiring).
docker run --rm --env-file "$WORK_DIR/shield.env" fips-shield-f2b:test \
    fail2ban-client -t

echo "OK"
