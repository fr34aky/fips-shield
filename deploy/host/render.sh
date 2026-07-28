#!/usr/bin/env bash
# Render the fips-shield nginx configs for host mode (nginx running
# directly on the fips node, next to the daemon).
#
#   ./render.sh <shield.env> [output-dir]
#
# Output defaults to /etc/nginx/conf.d (included by stock nginx.conf on
# Debian/Ubuntu and nginx.org packages). Only ${SHIELD_*} placeholders
# are substituted; nginx's own $variables are left alone. After
# rendering: nginx -t && systemctl reload nginx.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

ENV_FILE="${1:?usage: render.sh <shield.env> [output-dir]}"
OUT_DIR="${2:-/etc/nginx/conf.d}"

TEMPLATES=(
    "$REPO_ROOT"/core/nginx/*.conf.template
    "$REPO_ROOT"/profiles/strfry/*.conf.template
)

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

# Every placeholder used by the templates must be set — an empty value
# would render broken nginx config silently.
mapfile -t vars < <(grep -hoE '\$\{SHIELD_[A-Z0-9_]+\}' "${TEMPLATES[@]}" | tr -d '${}' | sort -u)
missing=0
for v in "${vars[@]}"; do
    if [ -z "${!v:-}" ]; then
        echo "error: $v is not set in $ENV_FILE" >&2
        missing=1
    fi
done
[ "$missing" -eq 0 ] || exit 1

subst_list="$(printf '${%s} ' "${vars[@]}")"

mkdir -p "$OUT_DIR"
for t in "${TEMPLATES[@]}"; do
    out="$OUT_DIR/$(basename "$t" .template)"
    envsubst "$subst_list" < "$t" > "$out"
    echo "rendered $out"
done

echo "Now run: nginx -t && systemctl reload nginx"
