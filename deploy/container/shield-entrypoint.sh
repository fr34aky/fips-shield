#!/bin/sh
# Selects the profiles named in SHIELD_PROFILES (default: strfry),
# stages their templates next to the shared core ones, then hands over
# to the stock nginx entrypoint, which runs envsubst over
# /etc/nginx/templates/*.template into /etc/nginx/conf.d/.
set -eu

for profile in $(echo "${SHIELD_PROFILES:-strfry}" | tr ',' ' '); do
    dir="/etc/nginx/profiles/$profile"
    if [ ! -d "$dir" ]; then
        echo "error: no such profile: $profile" >&2
        echo "available: $(ls /etc/nginx/profiles)" >&2
        exit 1
    fi
    cp "$dir"/*.template /etc/nginx/templates/
    echo "shield: profile $profile staged"
done

exec /docker-entrypoint.sh "$@"
