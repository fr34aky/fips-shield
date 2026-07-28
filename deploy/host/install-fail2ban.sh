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

set -a
# shellcheck disable=SC1090
. "$ENV_FILE"
set +a

install -m 644 "$REPO_ROOT"/core/fail2ban/filter.d/*.conf "$F2B_DIR/filter.d/"
install -m 644 "$REPO_ROOT"/core/fail2ban/action.d/*.conf "$F2B_DIR/action.d/"
install -m 755 "$REPO_ROOT"/core/actions/shield-ban /usr/local/bin/shield-ban

envsubst '${SHIELD_F2B_FINDTIME} ${SHIELD_F2B_BANTIME} ${SHIELD_F2B_IGNOREIP}
          ${SHIELD_F2B_IGNORESELF} ${SHIELD_F2B_HANDSHAKE_MAXRETRY}
          ${SHIELD_F2B_VERDICT_MAXRETRY} ${SHIELD_F2B_SCAN_MAXRETRY}' \
    < "$REPO_ROOT"/core/fail2ban/jail.d/fips-shield.local.template \
    > "$F2B_DIR/jail.d/fips-shield.local"

mkdir -p "$(dirname "${SHIELD_BAN_FILE:-/var/lib/fips-shield/banlist}")"

echo "installed. Now run: fail2ban-client -t && systemctl reload fail2ban"
