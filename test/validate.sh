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

sed 's/^SHIELD_BIND_ADDR=.*/SHIELD_BIND_ADDR=::1/' \
    "$REPO_ROOT"/shield.env.example > "$WORK_DIR/shield.env"

docker build -q -f "$REPO_ROOT"/deploy/container/Dockerfile -t fips-shield:test "$REPO_ROOT"

# Each profile on its own, then all at once: a profile must not depend
# on another being enabled, and they must not collide.
ALL=$(echo "$PROFILES" | tr ' ' ',')
for set in $PROFILES "$ALL"; do
    echo "--- profiles: $set"
    sed "s/^SHIELD_PROFILES=.*/SHIELD_PROFILES=$set/" \
        "$WORK_DIR/shield.env" > "$WORK_DIR/env.current"

    # Host-mode render path: must succeed and leave no placeholders.
    # The socket directory is redirected into the work dir because
    # rendering runs unprivileged and must not touch /run.
    rm -rf "$WORK_DIR/conf" "$WORK_DIR/njs"
    sed "s|^SHIELD_SOCKET_DIR=.*|SHIELD_SOCKET_DIR=$WORK_DIR/sock|" \
        "$WORK_DIR/env.current" > "$WORK_DIR/env.render"
    "$REPO_ROOT"/deploy/host/render.sh "$WORK_DIR/env.render" \
        "$WORK_DIR/conf" "$WORK_DIR/njs" >/dev/null
    if grep -rnE '\$\{SHIELD_[A-Z0-9_]+\}' "$WORK_DIR/conf"; then
        echo "error: unrendered \${SHIELD_*} placeholders in output" >&2
        exit 1
    fi

    # Container path: the real image, real entrypoint templating, nginx -t.
    docker run --rm --env-file "$WORK_DIR/env.current" fips-shield:test nginx -t
done

# Detection sidecar: render the jails and let fail2ban verify the full
# configuration (filters, action, jail wiring).
docker build -q -f "$REPO_ROOT"/deploy/container/Dockerfile.fail2ban \
    -t fips-shield-f2b:test "$REPO_ROOT"
docker run --rm --env-file "$WORK_DIR/shield.env" fips-shield-f2b:test \
    fail2ban-client -t

echo "OK"
