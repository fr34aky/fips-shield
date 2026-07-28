#!/bin/sh
# Renders the jail template from the SHIELD_F2B_* environment and preps
# the shared files fail2ban expects, then execs the given command
# (default: fail2ban-server in the foreground; pass `fail2ban-client -t`
# to only validate the configuration).
set -eu

envsubst '${SHIELD_F2B_FINDTIME} ${SHIELD_F2B_BANTIME} ${SHIELD_F2B_IGNOREIP}
          ${SHIELD_F2B_IGNORESELF} ${SHIELD_F2B_HANDSHAKE_MAXRETRY}
          ${SHIELD_F2B_VERDICT_MAXRETRY} ${SHIELD_F2B_SCAN_MAXRETRY}' \
    < /etc/fail2ban/fips-shield.local.template \
    > /etc/fail2ban/jail.d/fips-shield.local

# The jails refuse to start on missing logpaths, and nginx creates its
# logs on its own schedule. The access-log jails use a glob over all
# profiles, so seed one file to make sure the glob always resolves —
# a tcp-only deployment has no http stage and thus no access log.
mkdir -p /var/log/nginx
touch /var/log/nginx/shield-init.access.log /var/log/nginx/shield-error.log

mkdir -p "$(dirname "${SHIELD_BAN_FILE:-/var/lib/fips-shield/banlist}")"

exec "$@"
