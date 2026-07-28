#!/usr/bin/env bash
# Render the fips-shield nginx configs for host mode (nginx running
# directly on the fips node, next to the daemon).
#
#   ./render.sh <shield.env> [output-dir] [njs-dir]
#
# Renders the shared core plus every profile named in SHIELD_PROFILES.
# Output defaults to /etc/nginx/conf.d; the njs engine is copied to
# njs-dir (default /etc/nginx/njs). Only ${SHIELD_*} placeholders are
# substituted; nginx's own $variables are left alone.
#
# Host prerequisites (see deploy/host/README.md):
#   - the njs stream module (Debian/Ubuntu: libnginx-mod-stream-js;
#     nginx.org packages: nginx-module-njs) loaded via load_module
#   - a stream{} block including /etc/nginx/conf.d/*.stream
#     (core/nginx/nginx.conf shows the reference layout)
#
# After rendering: nginx -t && systemctl reload nginx.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

ENV_FILE="${1:?usage: render.sh <shield.env> [output-dir] [njs-dir]}"
OUT_DIR="${2:-/etc/nginx/conf.d}"
NJS_DIR="${3:-/etc/nginx/njs}"

# Read KEY=VALUE literally, exactly as docker --env-file does. Sourcing
# the file with "." would run it through the shell, so a value like
# GET|HEAD|POST would be parsed as a pipeline, and quotes would be
# stripped here but taken literally by docker — the two deploy modes
# must agree.
while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    case "$line" in *=*) ;; *) continue ;; esac
    key=${line%%=*}
    case "$key" in [A-Za-z_]*) export "$key=${line#*=}" ;; esac
done < "$ENV_FILE"

TEMPLATES=("$REPO_ROOT"/core/nginx/*.template)
for profile in $(echo "${SHIELD_PROFILES:-strfry}" | tr ',' ' '); do
    dir="$REPO_ROOT/profiles/$profile"
    [ -d "$dir" ] || { echo "error: no such profile: $profile" >&2; exit 1; }
    TEMPLATES+=("$dir"/*.template)
done

# Every placeholder used by the selected templates must be set (empty
# is fine — some knobs, like the kind deny list, are legitimately so).
mapfile -t vars < <(grep -hoE '\$\{SHIELD_[A-Z0-9_]+\}' "${TEMPLATES[@]}" | tr -d '${}' | sort -u)
missing=0
for v in "${vars[@]}"; do
    if [ -z "${!v+x}" ]; then
        echo "error: $v is not set in $ENV_FILE" >&2
        missing=1
    fi
done
[ "$missing" -eq 0 ] || exit 1

subst_list="$(printf '${%s} ' "${vars[@]}")"

mkdir -p "$OUT_DIR" "$NJS_DIR"
for t in "${TEMPLATES[@]}"; do
    out="$OUT_DIR/$(basename "$t" .template)"
    envsubst "$subst_list" < "$t" > "$out"
    echo "rendered $out"
done

# Socket directory for the stream->http hop. nginx chmods unix listen
# sockets to 0666, so these directory permissions are the access
# control: anything that can connect could spoof a client address past
# the shield.
# Provisioning it is best-effort: rendering configs must work as an
# unprivileged user (that is how CI validates every profile), while the
# directory itself needs root.
SOCKET_DIR="${SHIELD_SOCKET_DIR:-/run/fips-shield}"
if mkdir -p "$SOCKET_DIR" 2>/dev/null && chmod 700 "$SOCKET_DIR" 2>/dev/null; then
    # Guarded: with `set -o pipefail`, a missing nginx binary would
    # abort the whole render — and rendering must work on hosts (and
    # CI runners) where nginx is not installed.
    worker_user=""
    if command -v nginx >/dev/null 2>&1; then
        worker_user="$(nginx -T 2>/dev/null \
            | awk '/^[[:space:]]*user[[:space:]]/ {print $2; exit}' \
            | tr -d ';' || true)"
    fi
    if [ -n "$worker_user" ] && id "$worker_user" >/dev/null 2>&1; then
        chown "$worker_user" "$SOCKET_DIR" 2>/dev/null \
            && echo "socket dir $SOCKET_DIR (0700, owned by $worker_user)"
    else
        echo "warning: could not determine the nginx worker user; chown" \
             "$SOCKET_DIR to it by hand or nginx workers cannot connect" >&2
    fi
else
    echo "note: create $SOCKET_DIR yourself (0700, owned by the nginx" \
         "worker user) — nginx cannot connect the stages without it" >&2
fi
# /run is usually a tmpfs, so the directory needs recreating at boot.
echo "tip: install deploy/host/fips-shield-tmpfiles.conf into" \
     "/etc/tmpfiles.d/ so $SOCKET_DIR survives a reboot"

cp "$REPO_ROOT"/core/njs/*.js "$NJS_DIR"/
echo "installed $NJS_DIR/{$(cd "$REPO_ROOT"/core/njs && echo *.js | tr ' ' ',')}"

echo "Now run: nginx -t && systemctl reload nginx"
echo "(nginx must load ngx_stream_js_module and include conf.d/*.stream" \
     "in a stream{} block — see deploy/host/README.md)"
