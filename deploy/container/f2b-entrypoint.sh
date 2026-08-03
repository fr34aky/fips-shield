#!/bin/sh
# Renders the jail template from the SHIELD_F2B_* environment and preps
# the shared files fail2ban expects, then execs the given command
# (default: fail2ban-server in the foreground; pass `fail2ban-client -t`
# to only validate the configuration).
set -eu

envsubst '${SHIELD_BAN_FILE} ${SHIELD_BAN_ALSO_FILE}' \
    < /etc/fail2ban/fips-shield-action.conf.template \
    > /etc/fail2ban/action.d/fips-shield.conf

envsubst '${SHIELD_F2B_FINDTIME} ${SHIELD_F2B_BANTIME} ${SHIELD_F2B_IGNOREIP}
          ${SHIELD_F2B_IGNORESELF} ${SHIELD_F2B_HANDSHAKE_MAXRETRY}
          ${SHIELD_F2B_VERDICT_MAXRETRY} ${SHIELD_F2B_SCAN_MAXRETRY}
          ${SHIELD_F2B_CONNRATE_MAXRETRY} ${SHIELD_F2B_CONN_MAXRETRY}' \
    < /etc/fail2ban/fips-shield.local.template \
    > /etc/fail2ban/jail.d/fips-shield.local

# The jails refuse to start on missing logpaths, and nginx creates its
# logs on its own schedule. The access-log and stream-log jails use a
# glob over all profiles, so seed one file of each to make sure the
# globs always resolve — a tcp-only deployment has no http stage and
# thus no access log.
mkdir -p /var/log/nginx
touch /var/log/nginx/shield-init.access.log \
      /var/log/nginx/shield-init.stream.log \
      /var/log/nginx/shield-error.log

mkdir -p "$(dirname "${SHIELD_BAN_FILE:-/var/lib/fips-shield/banlist}")"

# --- eBPF backend wiring check (compose.guard.yaml) ---------------------
#
# SHIELD_GUARD_PIN_DIR is only set by that overlay, so its presence means
# the operator expects kernel enforcement. Verify it now: otherwise the
# first sign of trouble is a node that fail2ban reports as banned while
# `fips-guard stats` shows zero drops, hours later.
#
# The two failure modes need different treatment. A binary that cannot
# execute is a deployment error that will never fix itself — usually a
# stale image, since `docker compose up` reuses an existing one when the
# Dockerfile changes; refuse to start. Maps that are not reachable yet
# may simply mean the host has not run `fips-guard load`, which can
# resolve on its own; warn and carry on, because losing detection
# entirely is worse than enforcing in the wrong layer.
if [ -n "${SHIELD_GUARD_PIN_DIR:-}" ]; then
    if ! /usr/local/bin/fips-guard --help >/dev/null 2>&1; then
        echo "fips-shield: FATAL - /usr/local/bin/fips-guard cannot be executed." >&2
        echo "  SHIELD_GUARD_PIN_DIR is set, so this container is expected to ban" >&2
        echo "  in the kernel, but the guard binary does not run here." >&2
        echo "  Most likely a stale image: 'docker compose up' does not rebuild" >&2
        echo "  when the Dockerfile changes. Rebuild with:" >&2
        echo "      docker compose -f compose.yaml -f compose.guard.yaml up -d --build" >&2
        echo "  (an Alpine-based image cannot exec the host's glibc binary; the" >&2
        echo "   error reads 'cannot execute: required file not found')" >&2
        echo "  Also check that /usr/local/bin/fips-guard exists on the host --" >&2
        echo "  if it does not, Docker creates a directory in its place." >&2
        exit 1
    fi

    if ! /usr/local/bin/fips-guard list >/dev/null 2>&1; then
        echo "fips-shield: WARNING - cannot read the guard's maps at" \
            "$SHIELD_GUARD_PIN_DIR." >&2
        echo "  Bans will be recorded by fail2ban but not enforced in the kernel." >&2
        echo "  On the host: systemctl status fips-guard, and check that its pin" >&2
        echo "  directory matches (host /sys/fs/bpf/... == container $SHIELD_GUARD_PIN_DIR)." >&2
    else
        echo "fips-shield: eBPF backend reachable at $SHIELD_GUARD_PIN_DIR"
    fi
fi

exec "$@"
