#!/usr/bin/env bash
# Verifies that each fail2ban filter actually MATCHES the log lines the
# shield produces. `fail2ban-client -t` only proves the config parses —
# a filter that compiles but matches nothing looks identical to a
# working one, which is exactly how two jails shipped dead.
#
# The sample lines below are copied verbatim from real shield output.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

ACCESS_LOG="$WORK_DIR/access.log"
ERROR_LOG="$WORK_DIR/error.log"
STREAM_LOG="$WORK_DIR/stream.log"

cat > "$ACCESS_LOG" <<'EOF'
{"ts":"2026-07-28T20:13:35+00:00","src":"fd97:dead:beef::1","status":429,"request":"GET / HTTP/1.1","host":"[::1]","upgrade":"","bytes_in":84,"bytes_out":327,"duration":0.000,"conn":43,"conn_reqs":1,"limited":"REJECTED","ua":"Wget"}
{"ts":"2026-07-28T20:13:36+00:00","src":"fd97:dead:beef::2","status":444,"request":"GET /admin HTTP/1.1","host":"[::1]","upgrade":"","bytes_in":84,"bytes_out":0,"duration":0.000,"conn":44,"conn_reqs":1,"limited":"","ua":"curl/8"}
{"ts":"2026-07-28T20:13:37+00:00","src":"fd97:dead:beef::3","status":405,"request":"DELETE / HTTP/1.1","host":"[::1]","upgrade":"","bytes_in":84,"bytes_out":150,"duration":0.000,"conn":45,"conn_reqs":1,"limited":"","ua":"curl/8"}
{"ts":"2026-07-28T20:13:38+00:00","src":"fd97:dead:beef::4","status":200,"request":"GET / HTTP/1.1","host":"[::1]","upgrade":"websocket","bytes_in":84,"bytes_out":150,"duration":0.000,"conn":46,"conn_reqs":1,"limited":"","ua":"nostr-client"}
EOF

cat > "$ERROR_LOG" <<'EOF'
2026/07/28 20:50:19 [warn] 32#32: *32 js: shield-verdict {"ts":"2026-07-28T20:50:19.159Z","src":"fd97:dead:beef::5","service":"strfry","layer":"ws","rule":"event-rate","detail":""}
2026/07/28 20:50:20 [warn] 32#32: *36 js: shield-verdict {"ts":"2026-07-28T20:50:20.664Z","src":"fd97:dead:beef::6","service":"strfry","layer":"ws","rule":"too-many-subs","detail":"max=2"}
2026/07/28 20:50:21 [warn] 32#32: *38 js: shield-verdict {"ts":"2026-07-28T20:50:21.100Z","src":"fd97:dead:beef::7","service":"strfry","layer":"ban","rule":"banned","detail":"rejected-at-accept"}
2026/07/28 20:50:22 [warn] 32#32: *40 js: shield-verdict {"ts":"2026-07-28T20:50:22.310Z","src":"fd97:dead:beef::8","service":"tcp","layer":"access","rule":"conn-rate","detail":"max=10"}
2026/07/28 20:50:23 [warn] 32#32: *42 js: shield-verdict {"ts":"2026-07-28T20:50:23.900Z","src":"fd97:dead:beef::9","service":"strfry","layer":"ws","rule":"handshake-drip","detail":""}
EOF

# Stream-stage sessions. Nothing read this file before: a per-node
# concurrency rejection (503) was logged and ignored, and on the tcp
# profile — which has no http stage, so no access log at all — it was
# the only connection-level signal there was.
cat > "$STREAM_LOG" <<'EOF'
{"ts":"2026-07-28T20:51:01+00:00","src":"fd97:dead:beef::a","service":"tcp","status":503,"bytes_in":0,"bytes_out":0,"duration":0.000,"verdict":""}
{"ts":"2026-07-28T20:51:02+00:00","src":"fd97:dead:beef::b","service":"strfry","status":200,"bytes_in":420,"bytes_out":880,"duration":12.500,"verdict":""}
{"ts":"2026-07-28T20:51:03+00:00","src":"fd97:dead:beef::c","service":"tcp","status":403,"bytes_in":0,"bytes_out":0,"duration":0.000,"verdict":"banned"}
EOF

docker build -q -f "$REPO_ROOT"/deploy/container/Dockerfile.fail2ban \
    -t fips-shield-f2b:test "$REPO_ROOT" >/dev/null

# $1 log file, $2 filter name, $3 expected match count
expect_matches() {
    local out count
    out=$(docker run --rm -v "$WORK_DIR":/w:ro -v \
        "$REPO_ROOT/core/fail2ban/filter.d":/etc/fail2ban/filter.d:ro \
        fips-shield-f2b:test fail2ban-regex "/w/$(basename "$1")" \
        "/etc/fail2ban/filter.d/$2.conf")
    count=$(sed -n 's/^Lines: .* \([0-9]*\) matched.*/\1/p' <<<"$out")
    [ -z "$count" ] && count=$(grep -oE '[0-9]+ matched' <<<"$out" | grep -oE '^[0-9]+')
    if [ "${count:-0}" != "$3" ]; then
        echo "FAIL $2: expected $3 matches, got ${count:-0}" >&2
        echo "$out" | tail -25 >&2
        return 1
    fi
    echo "PASS $2 matched $3 line(s)"
}

expect_matches "$ACCESS_LOG" fips-shield-handshake 1
expect_matches "$ACCESS_LOG" fips-shield-scan 2
# 5 verdict lines: two layer "ws" violations plus the new
# handshake-drip, minus the "banned" echo (enforcement must never feed
# back into detection) and minus the layer "access" conn-rate line,
# which now belongs to its own jail with its own threshold.
expect_matches "$ERROR_LOG" fips-shield-verdict 3
# ...and that conn-rate line is matched there, and only there.
expect_matches "$ERROR_LOG" fips-shield-connrate 1
# 503 only. The 403 line is an already-banned source being refused;
# counting it would let a banned node extend its own ban by knocking.
expect_matches "$STREAM_LOG" fips-shield-conn 1

echo "OK"
