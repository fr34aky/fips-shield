#!/usr/bin/env bash
# Install the fips-shield detection engine on a host that runs fail2ban
# natively (apt install fail2ban / apk add fail2ban):
#
#   sudo deploy/host/install-fail2ban.sh <shield.env>
#
# Copies the filters and banaction, renders the jails from shield.env,
# installs the shield-ban backend, and prepares the banlist directory.
# Reload with: systemctl reload fail2ban (or fail2ban-client reload).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ENV_FILE="${1:?usage: install-fail2ban.sh <shield.env>}"
F2B_DIR="${2:-/etc/fail2ban}"
PREFIX="${PREFIX:-/usr/local}"

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

install -m 644 "$REPO_ROOT"/core/fail2ban/filter.d/*.conf "$F2B_DIR/filter.d/"

# The banlist backend always lands in the library directory, where the
# eBPF wrapper expects to find it (SHIELD_BAN_ALSO_FILE).
install -d "$PREFIX/lib/fips-shield"
install -m 755 "$REPO_ROOT"/core/actions/shield-ban \
    "$PREFIX/lib/fips-shield/shield-ban-file"

# Installing it as *the* backend would silently undo `make install-guard`
# on a host using kernel enforcement: fail2ban would keep banning, the
# banlist file would keep growing, and `fips-guard stats` would sit at
# zero drops. Leave an existing eBPF wrapper alone.
BAN_BIN="$PREFIX/bin/shield-ban"
if [ -e "$BAN_BIN" ] && grep -q 'enforcement backend: eBPF edition' "$BAN_BIN"; then
    echo "note: $BAN_BIN is the eBPF guard wrapper — keeping it."
    echo "      The file backend is installed as" \
        "$PREFIX/lib/fips-shield/shield-ban-file."
else
    install -m 755 "$REPO_ROOT"/core/actions/shield-ban "$BAN_BIN"
fi

envsubst '${SHIELD_BAN_FILE} ${SHIELD_BAN_ALSO_FILE}' \
    < "$REPO_ROOT"/core/fail2ban/action.d/fips-shield.conf.template \
    > "$F2B_DIR/action.d/fips-shield.conf"

# The jails refuse to start when a logpath glob matches nothing, and
# nginx creates its logs on its own schedule — seed one so a fresh host
# can load the configuration before the first request arrives.
mkdir -p /var/log/nginx
touch /var/log/nginx/shield-init.access.log /var/log/nginx/shield-error.log

envsubst '${SHIELD_F2B_FINDTIME} ${SHIELD_F2B_BANTIME} ${SHIELD_F2B_IGNOREIP}
          ${SHIELD_F2B_IGNORESELF} ${SHIELD_F2B_HANDSHAKE_MAXRETRY}
          ${SHIELD_F2B_VERDICT_MAXRETRY} ${SHIELD_F2B_SCAN_MAXRETRY}
          ${SHIELD_F2B_CONNRATE_MAXRETRY} ${SHIELD_F2B_CONN_MAXRETRY}' \
    < "$REPO_ROOT"/core/fail2ban/jail.d/fips-shield.local.template \
    > "$F2B_DIR/jail.d/fips-shield.local"

mkdir -p "$(dirname "${SHIELD_BAN_FILE:-/var/lib/fips-shield/banlist}")"

# Jails refuse to start on a logpath glob that resolves to nothing, and
# nginx writes these on its own schedule. Seed one file per glob so a
# fresh install can start before any traffic has arrived.
mkdir -p /var/log/nginx
touch /var/log/nginx/shield-init.access.log \
      /var/log/nginx/shield-init.stream.log \
      /var/log/nginx/shield-error.log

echo "installed. Now run: fail2ban-client -t && systemctl reload fail2ban"
