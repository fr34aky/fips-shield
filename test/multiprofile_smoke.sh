#!/usr/bin/env bash
# Cross-profile isolation of the per-node limits.
#
# Every other smoke test runs one profile alone, which is exactly the
# configuration in which shared limit state cannot be observed. This one
# enables two profiles with mismatched limits and proves traffic to one
# does not consume the other's budget — the regression test for the
# shared connection-rate counter and the shared limit_conn zone.
#
# Covers the stream-stage limits (the njs conn-rate dict and
# shield_*_stream_conn), which is where the reported lockout came from.
# The http-stage zones were split by the same change; that split is
# covered structurally by test/validate.sh, which renders strfry and
# http together and would fail on a duplicate or missing zone name.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
SHIELD_C="fips-shield-multitest"

cleanup() {
    docker rm -f "$SHIELD_C" >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

mkdir -p "$WORK_DIR/logs" "$WORK_DIR/bans"
chmod 777 "$WORK_DIR/logs" "$WORK_DIR/bans"

# tcp deliberately much tighter than http, and a window long enough that
# it cannot roll over mid-test and hand the tcp profile a fresh budget —
# that would make the isolation checks pass for the wrong reason.
# Test policy is appended rather than sed-substituted into the example:
# the example no longer carries every key (presets supply the rest), so a
# sed that matched nothing would silently leave the preset value in place
# and the test would pass against a policy it never set. Appending is
# also exactly how an operator pins a value, so this exercises the
# override path.
cp "$REPO_ROOT"/shield.env.example "$WORK_DIR/shield.env"
cat >> "$WORK_DIR/shield.env" <<'EOF'
SHIELD_PROFILES=tcp,http
SHIELD_BIND_ADDR=::1
SHIELD_CONN_WINDOW=60
SHIELD_TCP_SERVICE=echo
SHIELD_TCP_UPSTREAM=127.0.0.1:9001
SHIELD_TCP_CONN_RATE=5
SHIELD_TCP_MAX_CONNS_PER_NODE=2
SHIELD_HTTP_SERVICE=web
SHIELD_HTTP_UPSTREAM=127.0.0.1:3000
SHIELD_HTTP_CONN_RATE=50
SHIELD_HTTP_MAX_CONNS_PER_NODE=20
SHIELD_HTTP_REQ_RATE=100r/s
SHIELD_HTTP_REQ_BURST=100
EOF

docker build -q -f "$REPO_ROOT"/deploy/container/Dockerfile \
    -t fips-shield:test "$REPO_ROOT"

docker run -d --name "$SHIELD_C" --env-file "$WORK_DIR/shield.env" \
    -v "$WORK_DIR/logs":/var/log/nginx \
    -v "$WORK_DIR/bans":/var/lib/fips-shield \
    fips-shield:test >/dev/null

# nginx must be listening before the checks run, or a connection refused
# for being early reads as a limit refusal.
#
# Probe ONLY the loose profile's port. Every probe is a real connection
# that spends that profile's rate budget, and the tcp profile's budget
# is deliberately tiny — probing 2222 here left the isolation checks
# with almost nothing to spend and made them flake. The master binds
# every listen socket before forking workers, so 8080 accepting means
# 2222 is bound too.
for _ in $(seq 1 30); do
    if docker exec "$SHIELD_C" nc -z ::1 8080 >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

echo "--- cross-profile limit isolation"
docker run --rm --network "container:$SHIELD_C" \
    -v "$REPO_ROOT/test":/test:ro python:3-alpine \
    python3 /test/multiprofile_test.py

# The tcp refusals in the positive control must still reach the
# detection engine, and must be attributed to the tcp profile rather
# than whichever profile happened to be parsed last.
if ! grep shield-verdict "$WORK_DIR/logs/shield-error.log" 2>/dev/null |
        grep -q '"service":"echo","layer":"access","rule":"conn-rate"'; then
    echo "error: no conn-rate verdict attributed to the tcp profile" >&2
    grep shield-verdict "$WORK_DIR/logs/shield-error.log" >&2 || true
    exit 1
fi
echo "--- conn-rate verdicts attributed to the right profile"

# The http profile must not have been refused at all; a conn-rate
# verdict against it would mean the counters are still entangled.
if grep shield-verdict "$WORK_DIR/logs/shield-error.log" 2>/dev/null |
        grep -q '"service":"web","layer":"access","rule":"conn-rate"'; then
    echo "error: the http profile hit a conn-rate limit it never exceeded" >&2
    grep shield-verdict "$WORK_DIR/logs/shield-error.log" >&2 || true
    exit 1
fi
echo "--- no spurious conn-rate verdict against the http profile"

echo "OK"
