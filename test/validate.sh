#!/usr/bin/env bash
# Render all templates with the example environment and run nginx -t on
# the result inside the official nginx image. Catches template syntax
# errors, bad include ordering (zones referenced before definition),
# and envsubst placeholders that leaked through unrendered.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# nginx -t binds the listen sockets, so the example's placeholder mesh
# address must be swapped for one that exists inside the test container.
sed 's/^SHIELD_BIND_ADDR=.*/SHIELD_BIND_ADDR=::1/' \
    "$REPO_ROOT"/shield.env.example > "$WORK_DIR/shield.env"

"$REPO_ROOT"/deploy/host/render.sh "$WORK_DIR/shield.env" "$WORK_DIR/conf"

# Unrendered placeholders mean render.sh's variable list and the
# templates drifted apart.
if grep -rnE '\$\{SHIELD_[A-Z0-9_]+\}' "$WORK_DIR/conf"; then
    echo "error: unrendered \${SHIELD_*} placeholders in output" >&2
    exit 1
fi

docker run --rm -v "$WORK_DIR/conf":/etc/nginx/conf.d:ro nginx:1.29-alpine nginx -t

echo "OK"
