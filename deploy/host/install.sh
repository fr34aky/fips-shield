#!/usr/bin/env bash
# One-step host-side install of fips-shield.
#
#   sudo deploy/host/install.sh <shield.env> [options]
#
#     --with-guard      install the eBPF guard as the enforcement backend
#     --without-guard   skip it (use the portable banlist file)
#     --no-nginx        skip rendering nginx configs (nginx runs in a
#                       container; only detection + enforcement here)
#     --guard-iface IF  interface for the guard (default: fips0)
#
# With neither --with-guard nor --without-guard, the guard is offered
# when this host can actually run it, and skipped with an explanation
# when it cannot. On a terminal you are asked; non-interactively the
# answer defaults to no, so automation never gains a kernel component
# by surprise.
#
# What it does, in order:
#   1. nginx configs for every profile in SHIELD_PROFILES  (render.sh)
#   2. the detection engine: filters, jails, banaction      (install-fail2ban.sh)
#   3. optionally the eBPF enforcement backend              (make install-guard)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PREFIX="${PREFIX:-/usr/local}"

ENV_FILE=""
WANT_GUARD="ask"
RENDER_NGINX=true
GUARD_IFACE="fips0"

while [ $# -gt 0 ]; do
    case "$1" in
    --with-guard) WANT_GUARD=yes ;;
    --without-guard) WANT_GUARD=no ;;
    --no-nginx) RENDER_NGINX=false ;;
    --guard-iface)
        GUARD_IFACE="${2:?--guard-iface needs an interface}"
        shift
        ;;
    -h | --help)
        sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
        exit 0
        ;;
    -*)
        echo "unknown option: $1" >&2
        exit 2
        ;;
    *) ENV_FILE="$1" ;;
    esac
    shift
done

[ -n "$ENV_FILE" ] || {
    echo "usage: install.sh <shield.env> [--with-guard|--without-guard]" >&2
    exit 2
}
[ -f "$ENV_FILE" ] || {
    echo "no such file: $ENV_FILE" >&2
    exit 2
}

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
note() { printf '    %s\n' "$*"; }

# --------------------------------------------------------- prerequisites
# Checked up front and reported together: failing halfway through leaves
# a host with configs rendered but no detection engine, and the raw
# error from a missing directory ("install: cannot stat ...") says
# nothing about what to install.

pkg_hint() {
    if command -v apt-get >/dev/null 2>&1; then
        echo "apt install $1"
    elif command -v dnf >/dev/null 2>&1; then
        echo "dnf install $1"
    elif command -v pkg >/dev/null 2>&1; then
        echo "pkg install $1"
    elif command -v apk >/dev/null 2>&1; then
        echo "apk add $1"
    else
        echo "install the $1 package"
    fi
}

check_prereqs() {
    local missing=()

    command -v envsubst >/dev/null 2>&1 ||
        missing+=("envsubst — $(pkg_hint gettext-base)")

    # The jails, filters and banaction are installed into fail2ban's
    # configuration tree; without fail2ban there is nothing to configure.
    if ! command -v fail2ban-client >/dev/null 2>&1 &&
        [ ! -d "${F2B_DIR:-/etc/fail2ban}" ]; then
        missing+=("fail2ban — $(pkg_hint fail2ban)")
    elif [ ! -d "${F2B_DIR:-/etc/fail2ban}" ]; then
        missing+=("fail2ban's config directory ${F2B_DIR:-/etc/fail2ban} \
(installed elsewhere? set F2B_DIR)")
    fi

    if [ "$RENDER_NGINX" = true ] && ! command -v nginx >/dev/null 2>&1; then
        missing+=("nginx — $(pkg_hint nginx), plus the njs stream module
      (see deploy/host/README.md); or use --no-nginx if it runs in a container")
    fi

    [ ${#missing[@]} -eq 0 ] && return 0

    echo "error: missing prerequisites on this host:" >&2
    printf '  - %s\n' "${missing[@]}" >&2
    echo >&2
    echo "Install them and re-run. Nothing has been changed." >&2
    exit 1
}

check_prereqs

# ---------------------------------------------------------------- guard
# Decided before anything is installed, so a "no" needs no rollback and
# the reasons appear before the noise of the install itself.

guard_blockers() {
    # Prints one line per reason the guard cannot be used here; silence
    # means it can.
    [ "$(uname -s)" = "Linux" ] || echo "not Linux (eBPF is Linux-only)"
    if [ ! -x "$REPO_ROOT/guard/target/release/fips-guard" ] &&
        ! command -v fips-guard >/dev/null 2>&1; then
        echo "fips-guard is not built — run 'make guard' as your normal user first"
        echo "  (it needs clang, and must NOT run under sudo: a rustup cargo lives"
        echo "   in your ~/.cargo/bin, which sudo's secure_path excludes)"
    fi
    # bpffs is where the maps are pinned; without it the guard cannot
    # keep state across invocations.
    if ! grep -q ' /sys/fs/bpf ' /proc/mounts 2>/dev/null; then
        echo "bpffs is not mounted — mount -t bpf bpf /sys/fs/bpf"
    fi
}

decide_guard() {
    local blockers
    blockers="$(guard_blockers)"

    if [ -n "$blockers" ]; then
        if [ "$WANT_GUARD" = yes ]; then
            echo "error: --with-guard requested but this host cannot run it:" >&2
            printf '  - %s\n' "$blockers" >&2
            exit 1
        fi
        WANT_GUARD=no
        GUARD_SKIP_REASON="$blockers"
        return
    fi

    case "$WANT_GUARD" in
    yes | no) return ;;
    esac

    # Offer it. A tty means a person is watching; anything else takes the
    # conservative answer.
    if [ -t 0 ]; then
        say "Optional: eBPF kernel enforcement"
        note "Bans are enforced by the kernel on ${GUARD_IFACE}, covering every"
        note "listener on the mesh interface at no per-packet cost — not just"
        note "the services behind this shield. Linux only; can be added later"
        note "with 'sudo make install-guard'."
        printf '    Install the eBPF guard? [y/N] '
        read -r reply </dev/tty || reply=""
        case "$reply" in
        [Yy]*) WANT_GUARD=yes ;;
        *) WANT_GUARD=no ;;
        esac
    else
        WANT_GUARD=no
        GUARD_SKIP_REASON="not a terminal; pass --with-guard to enable"
    fi
}

GUARD_SKIP_REASON=""
decide_guard

# --------------------------------------------------------------- nginx
if [ "$RENDER_NGINX" = true ]; then
    say "nginx configs"
    "$REPO_ROOT/deploy/host/render.sh" "$ENV_FILE"
else
    say "nginx configs — skipped (--no-nginx)"
    note "nginx presumably runs in a container; see deploy/container/compose.split.yaml"
fi

# ----------------------------------------------------------- detection
say "detection engine (fail2ban)"
# F2B_DIR is inherited, so a FreeBSD host can point both scripts at
# /usr/local/etc/fail2ban without editing either.
PREFIX="$PREFIX" "$REPO_ROOT/deploy/host/install-fail2ban.sh" "$ENV_FILE"

# --------------------------------------------------------- enforcement
if [ "$WANT_GUARD" = yes ]; then
    say "eBPF enforcement backend"
    # Reuses the Makefile target so there is one definition of what
    # installing the guard means. It does not rebuild.
    make -C "$REPO_ROOT" install-guard PREFIX="$PREFIX"
    printf 'SHIELD_GUARD_IFACE=%s\n' "$GUARD_IFACE" >/etc/default/fips-guard
    note "wrote /etc/default/fips-guard (interface: $GUARD_IFACE)"
else
    say "eBPF enforcement backend — skipped"
    if [ -n "$GUARD_SKIP_REASON" ]; then
        printf '    %s\n' "$GUARD_SKIP_REASON"
    fi
    # Skipping the install is not the same as removing an existing one:
    # install-fail2ban.sh deliberately leaves a guard wrapper in place, so
    # claiming file enforcement here would be false on a host that already
    # had the guard.
    if [ -e "$PREFIX/bin/shield-ban" ] &&
        grep -q 'enforcement backend: eBPF edition' "$PREFIX/bin/shield-ban"; then
        note "Note: $PREFIX/bin/shield-ban is already the eBPF wrapper, so bans"
        note "still enforce in the kernel. To switch to the banlist file:"
        note "    install -m 755 $PREFIX/lib/fips-shield/shield-ban-file \\"
        note "        $PREFIX/bin/shield-ban"
        note "    systemctl disable --now fips-guard"
    else
        note "Bans are enforced by nginx from the banlist file, which is portable"
        note "and needs nothing further."
    fi
fi

# -------------------------------------------------------------- finish
say "done — next steps"
if [ "$RENDER_NGINX" = true ]; then
    note "nginx:    nginx -t && systemctl reload nginx"
else
    note "nginx:    docker compose -f deploy/container/compose.split.yaml up -d"
    note "rotation: install -m 644 deploy/host/fips-shield.logrotate \\"
    note "              /etc/logrotate.d/fips-shield"
fi
note "fail2ban: fail2ban-client -t && systemctl reload fail2ban"
if [ "$WANT_GUARD" = yes ]; then
    note "guard:    systemctl daemon-reload && systemctl enable --now fips-guard"
fi
note "verify:   fail2ban-client banned; shield-ban list"
