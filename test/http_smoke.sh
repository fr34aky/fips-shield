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
# Test policy is appended rather than sed-substituted into the example:
# the example no longer carries every key (presets supply the rest), so a
# sed that matched nothing would silently leave the preset value in place
# and the test would pass against a policy it never set. Appending is
# also exactly how an operator pins a value, so this exercises the
# override path.
cp "$REPO_ROOT"/shield.env.example "$WORK_DIR/shield.env"
cat >> "$WORK_DIR/shield.env" <<'EOF'
SHIELD_PROFILES=http
SHIELD_BIND_ADDR=::1
SHIELD_HTTP_SERVICE=web
SHIELD_HTTP_REQ_RATE=5r/s
SHIELD_HTTP_REQ_BURST=5
SHIELD_HTTP_PATH_REGEX=/allowed/.*
SHIELD_HTTP_MAX_BODY=100k
SHIELD_HTTP_CONN_RATE=0
EOF

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
