#!/usr/bin/env bash
# Render the fips-shield nginx configs for host mode (nginx running
# directly on the fips node, next to the daemon).
#
#   ./render.sh <shield.env> [output-dir] [njs-dir]
#
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

TEMPLATES=(
    "$REPO_ROOT"/core/nginx/*.template
    "$REPO_ROOT"/profiles/strfry/*.template
)

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

# Every placeholder used by the templates must be set (empty is fine —
# some knobs, like the kind deny list, are legitimately empty).
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

cp "$REPO_ROOT"/core/njs/shield_ws.js "$NJS_DIR"/
echo "installed $NJS_DIR/shield_ws.js"

echo "Now run: nginx -t && systemctl reload nginx"
echo "(nginx must load ngx_stream_js_module and include conf.d/*.stream" \
     "in a stream{} block — see deploy/host/README.md)"
