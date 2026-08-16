#!/bin/sh
# Selects the profiles named in SHIELD_PROFILES (default: strfry),
# stages their templates next to the shared core ones, then hands over
# to the stock nginx entrypoint, which runs envsubst over
# /etc/nginx/templates/*.template into /etc/nginx/conf.d/.
set -eu

# Fill in preset values for every key the operator did not set. docker
# --env-file has already put shield.env into the environment, so
# "already set" means "the operator chose it" and the preset leaves it
# alone. Same script host mode runs, so the two cannot drift.
eval "$(/usr/local/bin/shield-config resolve --from-env --shell)"

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
