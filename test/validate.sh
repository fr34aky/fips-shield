#!/usr/bin/env bash
# Static validation: build the container image and run nginx -t inside
# it with the example environment (bind address swapped for ::1, since
# nginx -t binds the listen sockets). Catches template syntax errors,
# bad include ordering, njs parse errors (js_import loads the engine at
# config time), and envsubst placeholders that leaked through
# unrendered. Also exercises host-mode render.sh.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

sed 's/^SHIELD_BIND_ADDR=.*/SHIELD_BIND_ADDR=::1/' \
    "$REPO_ROOT"/shield.env.example > "$WORK_DIR/shield.env"

# Host-mode render path: must succeed and leave no placeholders behind.
"$REPO_ROOT"/deploy/host/render.sh "$WORK_DIR/shield.env" "$WORK_DIR/conf" "$WORK_DIR/njs"
if grep -rnE '\$\{SHIELD_[A-Z0-9_]+\}' "$WORK_DIR/conf"; then
    echo "error: unrendered \${SHIELD_*} placeholders in output" >&2
    exit 1
fi

# Container path: the real image, real entrypoint templating, nginx -t.
docker build -q -f "$REPO_ROOT"/deploy/container/Dockerfile -t fips-shield:test "$REPO_ROOT"
docker run --rm --env-file "$WORK_DIR/shield.env" fips-shield:test nginx -t

echo "OK"
