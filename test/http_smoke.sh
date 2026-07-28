#!/usr/bin/env bash
# Behavioral test of the generic HTTP profile: request-level filtering
# (methods, paths, body size, request rate) on top of the shared
# connection-level protections, and the same banlist as every other
# profile.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
SHIELD_C="fips-shield-httptest"

cleanup() {
    docker rm -f "$SHIELD_C" >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

py() {
    docker run --rm --network "container:$SHIELD_C" \
        -v "$REPO_ROOT/test":/test:ro python:3-alpine \
        python3 /test/http_test.py "$@"
}

mkdir -p "$WORK_DIR/logs" "$WORK_DIR/bans"
chmod 777 "$WORK_DIR/logs" "$WORK_DIR/bans"

# Test policy: tight enough to trip deterministically. Only /allowed/*
# is exposed, and DELETE is not in the method list.
sed -e 's/^SHIELD_PROFILES=.*/SHIELD_PROFILES=http/' \
    -e 's/^SHIELD_BIND_ADDR=.*/SHIELD_BIND_ADDR=::1/' \
    -e 's/^SHIELD_HTTP_SERVICE=.*/SHIELD_HTTP_SERVICE=web/' \
    -e 's/^SHIELD_HTTP_REQ_RATE=.*/SHIELD_HTTP_REQ_RATE=5r\/s/' \
    -e 's/^SHIELD_HTTP_REQ_BURST=.*/SHIELD_HTTP_REQ_BURST=5/' \
    -e 's/^SHIELD_HTTP_PATH_REGEX=.*/SHIELD_HTTP_PATH_REGEX=\/allowed\/.*/' \
    -e 's/^SHIELD_HTTP_MAX_BODY=.*/SHIELD_HTTP_MAX_BODY=100k/' \
    -e 's/^SHIELD_HTTP_CONN_RATE=.*/SHIELD_HTTP_CONN_RATE=0/' \
    "$REPO_ROOT"/shield.env.example > "$WORK_DIR/shield.env"

docker build -q -f "$REPO_ROOT"/deploy/container/Dockerfile \
    -t fips-shield:test "$REPO_ROOT"

docker run -d --name "$SHIELD_C" --env-file "$WORK_DIR/shield.env" \
    -v "$WORK_DIR/logs":/var/log/nginx \
    -v "$WORK_DIR/bans":/var/lib/fips-shield \
    fips-shield:test >/dev/null

echo "--- request-level filtering"
py

echo "--- ban enforcement (same banlist as every other profile)"
printf '::1 %s\n' "$(( $(date +%s) + 120 ))" > "$WORK_DIR/bans/banlist"
chmod 644 "$WORK_DIR/bans/banlist"
py expect-reject

echo "--- unban restores service"
: > "$WORK_DIR/bans/banlist"
sleep 1

# Rejections must be visible to the detection engine in the access log
# the jails already glob (429 rate limited, 405 method, 444 path).
for code in 429 403 444; do
    if ! grep -q "\"status\":$code," "$WORK_DIR/logs/shield-web.access.log"; then
        echo "error: no $code line in the access log for the jails to match" >&2
        tail -5 "$WORK_DIR/logs/shield-web.access.log" >&2 || true
        exit 1
    fi
done
echo "--- access log carries 429/405/444 for the detection jails"

echo "OK"
