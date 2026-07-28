#!/usr/bin/env bash
# Behavioral test of the generic TCP profile — the modularity proof.
# The shield knows nothing about the protocol here, yet the shared
# mechanisms (ban enforcement, connection rate, concurrency cap, verdict
# logging) must all work, driven by the same banlist and detection
# engine as the strfry profile.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
SHIELD_C="fips-shield-tcptest"

cleanup() {
    docker rm -f "$SHIELD_C" >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

py() {
    docker run --rm --network "container:$SHIELD_C" \
        -v "$REPO_ROOT/test":/test:ro python:3-alpine \
        python3 /test/tcp_test.py "$@"
}

mkdir -p "$WORK_DIR/logs" "$WORK_DIR/bans"
chmod 777 "$WORK_DIR/logs" "$WORK_DIR/bans"

sed -e 's/^SHIELD_PROFILES=.*/SHIELD_PROFILES=tcp/' \
    -e 's/^SHIELD_BIND_ADDR=.*/SHIELD_BIND_ADDR=::1/' \
    -e 's/^SHIELD_TCP_SERVICE=.*/SHIELD_TCP_SERVICE=echo/' \
    -e 's/^SHIELD_TCP_UPSTREAM=.*/SHIELD_TCP_UPSTREAM=127.0.0.1:9001/' \
    -e 's/^SHIELD_TCP_MAX_CONNS_PER_NODE=.*/SHIELD_TCP_MAX_CONNS_PER_NODE=2/' \
    -e 's/^SHIELD_TCP_CONN_RATE=.*/SHIELD_TCP_CONN_RATE=5/' \
    -e 's/^SHIELD_CONN_WINDOW=.*/SHIELD_CONN_WINDOW=5/' \
    "$REPO_ROOT"/shield.env.example > "$WORK_DIR/shield.env"

docker build -q -f "$REPO_ROOT"/deploy/container/Dockerfile \
    -t fips-shield:test "$REPO_ROOT"

docker run -d --name "$SHIELD_C" --env-file "$WORK_DIR/shield.env" \
    -v "$WORK_DIR/logs":/var/log/nginx \
    -v "$WORK_DIR/bans":/var/lib/fips-shield \
    fips-shield:test >/dev/null

echo "--- limits and passthrough"
py

# Let the connection-rate window roll over so the next steps measure
# what they mean to measure, not the leftover budget.
sleep 6

echo "--- ban enforcement (same banlist as every other profile)"
printf '::1 %s\n' "$(( $(date +%s) + 120 ))" > "$WORK_DIR/bans/banlist"
chmod 644 "$WORK_DIR/bans/banlist"
py expect-reject

echo "--- unban restores service"
: > "$WORK_DIR/bans/banlist"
sleep 6
py benign

# The engine must have logged verdicts the detection jails can match.
for rule in conn-rate banned; do
    if ! grep shield-verdict "$WORK_DIR/logs/shield-error.log" | grep -q "$rule"; then
        echo "error: no shield-verdict line for rule '$rule'" >&2
        cat "$WORK_DIR/logs/shield-error.log" >&2 || true
        exit 1
    fi
done
echo "--- verdict lines present for: conn-rate, banned"

# Sessions land in the profile's own log, named after the service.
if [ ! -s "$WORK_DIR/logs/shield-echo.stream.log" ]; then
    echo "error: profile session log missing or empty" >&2
    ls -la "$WORK_DIR/logs" >&2
    exit 1
fi
echo "--- session log shield-echo.stream.log written"

echo "OK"
