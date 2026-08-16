#!/usr/bin/env bash
# End-to-end test of the Phase 3 detection & response loop: shield
# container + fail2ban sidecar wired exactly like compose (shared log
# and banlist directories), clients driven by ban_test.py.
#
# Covers: manual ban via the shield-ban backend (reject at accept,
# established-session cut, unban), and the full automatic loop
# (violations -> verdict log -> fail2ban -> banlist -> nginx rejects).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
SHIELD_C="fips-shield-bantest"
F2B_C="fips-shield-bantest-f2b"

cleanup() {
    docker rm -f "$SHIELD_C" "$F2B_C" >/dev/null 2>&1 || true
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

py() {
    docker run --rm --network "container:$SHIELD_C" \
        -v "$REPO_ROOT/test":/test:ro python:3-alpine \
        python3 "/test/ban_test.py" "$@"
}

fban() {
    docker exec "$F2B_C" shield-ban "$@"
}

mkdir -p "$WORK_DIR/logs" "$WORK_DIR/bans"
chmod 777 "$WORK_DIR/logs" "$WORK_DIR/bans"

# Test policy: loopback bind, kind 4 denied, 1s ban recheck, and a
# 2-violation trigger so the automatic loop fires fast.
sed -e 's/^SHIELD_BIND_ADDR=.*/SHIELD_BIND_ADDR=::1/' \
    -e 's/^SHIELD_NOSTR_KIND_DENY=.*/SHIELD_NOSTR_KIND_DENY=4/' \
    -e 's/^SHIELD_BAN_RECHECK=.*/SHIELD_BAN_RECHECK=1/' \
    -e 's/^SHIELD_F2B_VERDICT_MAXRETRY=.*/SHIELD_F2B_VERDICT_MAXRETRY=2/' \
    -e 's/^SHIELD_F2B_FINDTIME=.*/SHIELD_F2B_FINDTIME=120/' \
    -e 's/^SHIELD_F2B_BANTIME=.*/SHIELD_F2B_BANTIME=120/' \
    -e 's/^SHIELD_F2B_IGNORESELF=.*/SHIELD_F2B_IGNORESELF=false/' \
    "$REPO_ROOT"/shield.env.example > "$WORK_DIR/shield.env"

docker build -q -f "$REPO_ROOT"/deploy/container/Dockerfile \
    -t fips-shield:test "$REPO_ROOT"
docker build -q -f "$REPO_ROOT"/deploy/container/Dockerfile.fail2ban \
    -t fips-shield-f2b:test "$REPO_ROOT"

docker run -d --name "$SHIELD_C" --env-file "$WORK_DIR/shield.env" \
    -v "$WORK_DIR/logs":/var/log/nginx \
    -v "$WORK_DIR/bans":/var/lib/fips-shield \
    fips-shield:test >/dev/null
docker run -d --name "$F2B_C" --env-file "$WORK_DIR/shield.env" \
    --network none \
    -v "$WORK_DIR/logs":/var/log/nginx \
    -v "$WORK_DIR/bans":/var/lib/fips-shield \
    fips-shield-f2b:test >/dev/null

echo "--- baseline"
py benign

echo "--- manual ban: reject at accept"
fban ban ::1 120 >/dev/null
fban check ::1 >/dev/null
py expect-reject

echo "--- manual unban: service restored"
fban unban ::1 >/dev/null
py benign

echo "--- established session cut after mid-session ban"
py session-cut &
SESSION_PID=$!
sleep 1.5
fban ban ::1 120 >/dev/null
wait "$SESSION_PID"
fban unban ::1 >/dev/null

echo "--- automatic loop: violations -> fail2ban -> ban"
py violate
py violate
banned=0
for _ in $(seq 30); do
    if fban check ::1 >/dev/null 2>&1; then
        banned=1
        break
    fi
    sleep 1
done
if [ "$banned" -ne 1 ]; then
    echo "error: fail2ban never banned ::1" >&2
    echo "--- fail2ban logs ---" >&2
    docker logs "$F2B_C" >&2 || true
    echo "--- shield error log ---" >&2
    cat "$WORK_DIR/logs/shield-error.log" >&2 || true
    exit 1
fi
py expect-reject
fban unban ::1 >/dev/null

# Regression: fail2ban's permanent ban is bantime = -1, which reaches
# the backend as "ban <ip> -1". That used to compute an expiry one
# second in the PAST, report success, and enforce nothing — while the
# eBPF backend treated the same input as permanent. Both backends now
# store 0 and never expire it.
echo "--- permanent ban (bantime = -1) is actually enforced"
fban ban ::1 -1 >/dev/null
if ! fban check ::1 | grep -q permanently; then
    echo "error: permanent ban not reported as banned" >&2
    fban check ::1 >&2 || true
    exit 1
fi
if ! fban list | grep -q '^::1 0$'; then
    echo "error: permanent ban not stored as 0 in the banlist" >&2
    fban list >&2 || true
    exit 1
fi
py expect-reject
fban unban ::1 >/dev/null
py benign

# Regression: expiry itself was untested — deleting the reader-side
# comparison used to leave every test passing.
echo "--- a ban expires on its own and service returns"
fban ban ::1 2 >/dev/null
py expect-reject
sleep 3
if fban check ::1 >/dev/null 2>&1; then
    echo "error: ban did not expire" >&2
    exit 1
fi
py benign

echo "--- a non-integer ttl is refused, not evaluated"
if fban ban ::1 'PATH[$(id)]' >/dev/null 2>&1; then
    echo "error: backend accepted a non-integer ttl" >&2
    exit 1
fi

echo "OK"
