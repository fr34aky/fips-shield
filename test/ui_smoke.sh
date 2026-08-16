#!/usr/bin/env bash
# Behavioral test of the read-only status dashboard.
#
# Two halves, and the second matters more. The first is that it reports
# what it should: services resolved through the same preset machinery
# everything else uses, bans with their expiry, a graceful "not in use"
# when the optional eBPF guard is absent.
#
# The second is that it refuses what it should. This process reads the
# shield's own view — which node identities are banned, and the contents
# of the access logs — so the interesting assertions are the negative
# ones: no path traversal into the log directory, no method but GET, no
# routable bind without an explicit override, and no write verbs at all.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
PORT=18099
UI_PID=""

cleanup() {
    [ -n "$UI_PID" ] && kill "$UI_PID" 2>/dev/null
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT

fail() { echo "FAIL $*" >&2; exit 1; }

BIN="$REPO_ROOT/ui/target/$(uname -m)-unknown-linux-musl/release/shield-ui"
[ -x "$BIN" ] || BIN="$REPO_ROOT/ui/target/release/shield-ui"
if [ ! -x "$BIN" ]; then
    cargo build --release --manifest-path "$REPO_ROOT/ui/Cargo.toml" >/dev/null
    BIN="$REPO_ROOT/ui/target/release/shield-ui"
fi

mkdir -p "$WORK_DIR/logs"
cat > "$WORK_DIR/shield.env" <<'EOF'
SHIELD_PROFILES=strfry,tcp
SHIELD_BIND_ADDR=fd97:abcd::1
SHIELD_PRESET=strict
SHIELD_TCP_SERVICE=ssh
SHIELD_TCP_CONN_RATE=7
EOF
printf 'fd97:aaaa::1 %s\nfd97:bbbb::2 0\n' "$(( $(date +%s) + 3600 ))" \
    > "$WORK_DIR/banlist"
# A log line carrying a quote and a backslash, which is what an attacker
# controls via User-Agent. It must come back as one JSON string.
cat > "$WORK_DIR/logs/shield-ssh.stream.log" <<'EOF'
{"ts":"2026-08-16T15:00:00+00:00","src":"fd97:aaaa::1","service":"ssh","status":200}
{"ts":"2026-08-16T15:00:01+00:00","src":"fd97:cccc::9","ua":"evil\" ,\"admin\":true"}
EOF
# A file the dashboard must never serve, sitting where a traversal would
# land if the service name were interpolated unchecked.
echo "SECRET-CANARY" > "$WORK_DIR/secret.log"

SHIELD_BAN_FILE="$WORK_DIR/banlist" "$BIN" \
    --bind "127.0.0.1:$PORT" \
    --env-file "$WORK_DIR/shield.env" \
    --log-dir "$WORK_DIR/logs" \
    --shield-config "$REPO_ROOT/bin/shield-config" \
    --shield-ban "$REPO_ROOT/core/actions/shield-ban" \
    --fips-guard /nonexistent/fips-guard >/dev/null 2>&1 &
UI_PID=$!

for _ in $(seq 1 40); do
    curl -sf "http://127.0.0.1:$PORT/api/status" >/dev/null 2>&1 && break
    sleep 0.25
done

get()  { curl -s "http://127.0.0.1:$PORT$1"; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "=== reports what it should ==="

STATUS=$(get /api/status)

python3 - "$STATUS" <<'PY' || exit 1
import json, sys
d = json.loads(sys.argv[1])

assert d["config_ok"] is True, "config should have resolved"
names = [s["name"] for s in d["services"]]
assert names == ["strfry", "ssh"], names

svc = {s["name"]: s for s in d["services"]}
# strfry uses unprefixed keys; a derived name would leave these empty.
assert svc["strfry"]["port"] == "80", svc["strfry"]
assert svc["strfry"]["upstream"] == "127.0.0.1:7777", svc["strfry"]
assert svc["strfry"]["preset"] == "strict", svc["strfry"]
# The tcp service pinned its conn rate, so it reports as custom rather
# than claiming a preset it no longer follows.
assert svc["ssh"]["preset"] == "custom", svc["ssh"]
# Limits must not leak across services.
assert all(k["key"].startswith("SHIELD_TCP_") for k in svc["ssh"]["limits"]), \
    svc["ssh"]["limits"]

assert d["bans_ok"] is True
assert d["ban_count"] == 2, d["ban_count"]
bans = {b["addr"]: b for b in d["bans"]}
assert bans["fd97:bbbb::2"]["permanent"] is True
assert bans["fd97:aaaa::1"]["permanent"] is False
assert 3000 < bans["fd97:aaaa::1"]["remaining"] <= 3600

# The eBPF guard is optional; absent must read as "not in use", not as
# an error that hides the rest of the page.
assert d["guard_ok"] is False, d
print("  ok   services, presets, bans, and an absent guard")
PY

LOGS=$(get "/api/logs?service=ssh&kind=stream&n=10")
python3 - "$LOGS" <<'PY' || exit 1
import json, sys
d = json.loads(sys.argv[1])
assert len(d["lines"]) == 2, d
# The quote-carrying line survived as exactly one string: if escaping
# were wrong this would have failed to parse at all, above.
assert 'admin' in d["lines"][1]
assert d["lines"][1].count('"') >= 6
print("  ok   log tail, including a line with embedded quotes")
PY

echo "=== refuses what it should ==="

# Traversal, raw and percent-encoded. The canary must never appear.
for probe in \
    '../secret' \
    '%2e%2e%2fsecret' \
    '../../../../etc/passwd' \
    'ssh/../../secret'
do
    body=$(get "/api/logs?service=$probe&kind=stream")
    case "$body" in
        *SECRET-CANARY*|*root:*) fail "traversal served a file: $probe" ;;
    esac
    case "$body" in
        *'unknown service'*) ;;
        *) fail "traversal not rejected cleanly: $probe -> $body" ;;
    esac
done
echo "  ok   path traversal into the log directory is refused"

[ "$(code "http://127.0.0.1:$PORT/api/logs?service=ssh&kind=evil")" = 400 ] ||
    fail "an unknown log kind should be 400"
[ "$(code "http://127.0.0.1:$PORT/api/logs")" = 400 ] ||
    fail "a missing service should be 400"
[ "$(code "http://127.0.0.1:$PORT/nope")" = 404 ] ||
    fail "an unknown route should be 404"
echo "  ok   bad parameters and unknown routes are rejected"

# Read-only means read-only: no write verb may be accepted on any route,
# including ones that exist.
for m in POST PUT DELETE PATCH; do
    for path in / /api/status /api/bans; do
        c=$(code -X "$m" "http://127.0.0.1:$PORT$path")
        [ "$c" = 405 ] || fail "$m $path returned $c, expected 405"
    done
done
echo "  ok   every write method is refused on every route"

# A huge n must be clamped, not honoured, or a dashboard poll could be
# turned into an unbounded read.
n=$(get "/api/logs?service=ssh&kind=stream&n=999999999" |
    python3 -c 'import json,sys; print(len(json.load(sys.stdin)["lines"]))')
[ "$n" -le 1000 ] || fail "n was not clamped: got $n lines"
echo "  ok   an absurd line count is clamped"

echo "=== will not expose itself by accident ==="

if "$BIN" --bind 0.0.0.0:18098 >/dev/null 2>&1; then
    fail "a routable bind was accepted without --insecure-bind"
fi
# Captured rather than piped: the binary exits non-zero here (that is
# the point), and under `set -o pipefail` that would fail the pipeline
# even when grep matched.
refusal=$("$BIN" --bind 0.0.0.0:18098 2>&1 || true)
case "$refusal" in
    *'refusing to bind'*) ;;
    *) fail "the refusal should say why, got: $refusal" ;;
esac
case "$refusal" in
    *'ssh -N -L'*) ;;
    *) fail "the refusal should say what to do instead" ;;
esac
echo "  ok   a routable bind is refused unless explicitly overridden"

echo OK
