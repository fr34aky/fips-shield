#!/usr/bin/env bash
# End-to-end behavioral test of the shield container: builds the image,
# starts it with a test policy (tight limits so violations are cheap to
# trigger), and runs test/ws_test.py — mock relay upstream plus raw-
# socket WebSocket clients — inside the container's network namespace.
# Finally asserts the expected shield-verdict lines reached the logs.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
CONTAINER="fips-shield-wstest"

cleanup() {
    docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

# Test policy: example env with a loopback bind and limits small enough
# to trip deterministically (ws_test.py encodes these expectations).
sed -e 's/^SHIELD_BIND_ADDR=.*/SHIELD_BIND_ADDR=::1/' \
    -e 's/^SHIELD_HANDSHAKE_BURST=.*/SHIELD_HANDSHAKE_BURST=20/' \
    -e 's/^SHIELD_WS_MAX_MSG=.*/SHIELD_WS_MAX_MSG=1000/' \
    -e 's/^SHIELD_WS_MAX_SUBS=.*/SHIELD_WS_MAX_SUBS=2/' \
    -e 's/^SHIELD_WS_EVENT_RATE=.*/SHIELD_WS_EVENT_RATE=1/' \
    -e 's/^SHIELD_WS_EVENT_BURST=.*/SHIELD_WS_EVENT_BURST=3/' \
    -e 's/^SHIELD_NOSTR_KIND_DENY=.*/SHIELD_NOSTR_KIND_DENY=4/' \
    "$REPO_ROOT"/shield.env.example > "$WORK_DIR/shield.env"

docker build -q -f "$REPO_ROOT"/deploy/container/Dockerfile \
    -t fips-shield:test "$REPO_ROOT"

docker run -d --name "$CONTAINER" --env-file "$WORK_DIR/shield.env" \
    fips-shield:test >/dev/null

run_probe() {
    docker run --rm --network "container:$CONTAINER" \
        -v "$REPO_ROOT/test":/test:ro python:3-alpine python3 "/test/$1"
}

if ! docker run --rm --network "container:$CONTAINER" \
    -v "$REPO_ROOT/test":/test:ro \
    python:3-alpine python3 /test/ws_test.py; then
    echo "--- shield logs ---" >&2
    docker logs "$CONTAINER" >&2 || true
    docker exec "$CONTAINER" cat /var/log/nginx/shield-error.log >&2 || true
    exit 1
fi

# The engine must have logged a structured verdict for each rule the
# tests tripped (shield-error.log is the file the detection engine
# tails).
for rule in unmasked-client-frame oversized-message kind-denied \
            type-not-allowed event-rate too-many-subs; do
    if ! docker exec "$CONTAINER" cat /var/log/nginx/shield-error.log \
        | grep shield-verdict | grep -q "$rule"; then
        echo "error: no shield-verdict line for rule '$rule'" >&2
        docker exec "$CONTAINER" cat /var/log/nginx/shield-error.log >&2 || true
        exit 1
    fi
done

# Regression tests for fixed inspection bypasses. Both were live:
# a bare-LF handshake desynchronised this engine from nginx's HTTP
# parser, and JavaScript prototype keys defeated the subscription cap
# and the message-type allowlist.
echo "--- handshake desync (bare LF) must not bypass inspection"
run_probe bypass_probe.py
echo "--- prototype keys must not defeat the caps"
run_probe proto_probe.py

echo "OK"
