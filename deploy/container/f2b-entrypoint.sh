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
    if ! err="$(/usr/local/bin/fips-guard --help 2>&1)"; then
        echo "fips-shield: FATAL - /usr/local/bin/fips-guard cannot be executed." >&2
        echo "  SHIELD_GUARD_PIN_DIR is set, so this container is expected to ban" >&2
        echo "  in the kernel, but the guard binary does not run here." >&2
        echo "  The error was:" >&2
        echo "      ${err:-(no output)}" >&2
        if [ ! -e /usr/local/bin/fips-guard ]; then
            echo "  The path does not exist in this container. Check that" >&2
            echo "  /usr/local/bin/fips-guard exists ON THE HOST -- if it does not," >&2
            echo "  Docker creates a directory in its place at the bind mount." >&2
        elif [ -d /usr/local/bin/fips-guard ]; then
            echo "  The path is a DIRECTORY, which is Docker's way of saying the" >&2
            echo "  host file was missing when the container started. Build and" >&2
            echo "  install the guard on the host first (make guard && sudo make" >&2
            echo "  install-guard), then recreate this container." >&2
        else
            # The common one, and the least obvious: glibc is backward
            # compatible, never forward. A binary built against the host's
            # glibc needs at least that version wherever it runs, and this
            # image's is usually older than a current distro's. The symptom
            # is a version-specific loader error, not a missing file.
            echo "  The binary exists but this image cannot run it. Almost always" >&2
            echo "  a glibc mismatch: it was built against a NEWER glibc than the" >&2
            echo "  one here (glibc is backward compatible, never forward), so the" >&2
            echo "  error names a GLIBC_x.yz version. Rebuild it static, which is" >&2
            echo "  what 'make guard' now produces, and reinstall on the host:" >&2
            echo "      make guard && sudo make install-guard" >&2
            echo "  Verify with: file /usr/local/bin/fips-guard  (want 'static')" >&2
            echo "  If instead the error mentions exec format, the binary is for" >&2
            echo "  a different architecture than this container." >&2
        fi
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
