#!/usr/bin/env bash
# Proves the compose.guard.yaml contract: the detection sidecar, with no
# network and only CAP_BPF, can ban and unban in the kernel by writing to
# the maps the host's fips-guard pinned.
#
# Two containers on purpose. Isolating them is the whole point — one
# stands in for the host (privileged, loads the classifier and pins the
# maps), the other for the sidecar (the real fail2ban image, unprivileged,
# network none). If the sidecar could only do this because of some
# ambient privilege, the negative case below would not fail.
#
# Uses the host's bpffs, because that is what production shares. State
# lives in a test-specific pin directory, removed on exit.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GUARD_IMAGE="fips-shield-guard:test"
F2B_IMAGE="fips-shield-f2b:test"
PIN_NAME="fips-shield-sidecar-test"
HOST_PIN="/sys/fs/bpf/$PIN_NAME"
BIN="$REPO_ROOT/guard/target/release/fips-guard"
WRAPPER="$REPO_ROOT/guard/shield-ban"

if [ "$(uname -s)" != "Linux" ]; then
    echo "SKIP: Linux only" >&2
    exit 0
fi

if ! mountpoint -q /sys/fs/bpf; then
    echo "bpffs is not mounted; trying to mount it" >&2
    sudo mount -t bpf bpf /sys/fs/bpf || {
        echo "SKIP: no bpffs at /sys/fs/bpf" >&2
        exit 0
    }
fi

cargo build --release --manifest-path "$REPO_ROOT/guard/Cargo.toml"

docker build -q -f "$REPO_ROOT"/test/guard/Dockerfile.test -t "$GUARD_IMAGE" \
    "$REPO_ROOT"/test/guard >/dev/null
docker build -q -f "$REPO_ROOT"/deploy/container/Dockerfile.fail2ban \
    -t "$F2B_IMAGE" "$REPO_ROOT" >/dev/null

cleanup() {
    # The pins are root-owned on the host's bpffs; drop them from a
    # privileged container so the test needs no sudo of its own.
    docker run --rm --privileged -v /sys/fs/bpf:/mnt/bpf "$GUARD_IMAGE" \
        rm -rf "/mnt/bpf/$PIN_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

fail() {
    echo "FAIL $*" >&2
    exit 1
}

# The sidecar, exactly as compose.guard.yaml configures it: no network,
# CAP_BPF and nothing else, host binaries mounted read-only, bpffs at
# /mnt/bpf rather than /sys/fs/bpf (AppArmor denies writes under /sys).
sidecar() {
    docker run --rm --network none --cap-add BPF \
        -v "$BIN":/usr/local/bin/fips-guard:ro \
        -v "$WRAPPER":/usr/local/bin/shield-ban:ro \
        -v /sys/fs/bpf:/mnt/bpf \
        -e SHIELD_GUARD_PIN_DIR="/mnt/bpf/$PIN_NAME" \
        "$F2B_IMAGE" "$@"
}

echo "=== host side: load the classifier and pin the maps ==="
docker run --rm --privileged --network none \
    -v "$BIN":/usr/local/bin/fips-guard:ro \
    -v /sys/fs/bpf:/sys/fs/bpf "$GUARD_IMAGE" bash -c "
        set -e
        ip link add dummy0 type dummy
        ip link set dummy0 up
        fips-guard load --iface dummy0 --pin-dir '$HOST_PIN' >/dev/null
        fips-guard ban fd97:c0de::1 300 --pin-dir '$HOST_PIN' >/dev/null
    "
echo "PASS host loaded the guard"

echo "=== the image can execute the host's binary (glibc, not musl) ==="
sidecar fips-guard --version >/dev/null 2>&1 ||
    sidecar fips-guard --help >/dev/null ||
    fail "the sidecar image cannot exec the host-built fips-guard"
echo "PASS sidecar can run the host binary"

echo "=== sidecar sees the host's ban ==="
sidecar shield-ban list | grep -q '^fd97:c0de::1 ' ||
    fail "sidecar cannot read the host's pinned bans"
echo "PASS sidecar reads host-created bans"

echo "=== sidecar bans in the kernel ==="
sidecar shield-ban ban fd97:c0de::2 300 >/dev/null
sidecar shield-ban check fd97:c0de::2 >/dev/null ||
    fail "ban written by the sidecar does not read back"

# The authority is the host's view of the maps, not the sidecar's.
docker run --rm --privileged -v "$BIN":/usr/local/bin/fips-guard:ro \
    -v /sys/fs/bpf:/sys/fs/bpf "$GUARD_IMAGE" \
    fips-guard list --pin-dir "$HOST_PIN" | grep -q '^fd97:c0de::2 ' ||
    fail "the host does not see the ban the sidecar wrote"
echo "PASS sidecar ban is visible to the host kernel maps"

echo "=== sidecar unbans in the kernel ==="
sidecar shield-ban unban fd97:c0de::2 >/dev/null
if sidecar shield-ban check fd97:c0de::2 >/dev/null 2>&1; then
    fail "unban written by the sidecar had no effect"
fi
docker run --rm --privileged -v "$BIN":/usr/local/bin/fips-guard:ro \
    -v /sys/fs/bpf:/sys/fs/bpf "$GUARD_IMAGE" \
    fips-guard list --pin-dir "$HOST_PIN" | grep -q '^fd97:c0de::2 ' &&
    fail "the host still sees a ban the sidecar removed"
echo "PASS sidecar unban is visible to the host kernel maps"

echo "=== the capability is genuinely required ==="
# Without CAP_BPF the same command must fail. This is what proves the
# test is measuring container privilege and not something ambient.
if docker run --rm --network none \
    -v "$BIN":/usr/local/bin/fips-guard:ro \
    -v "$WRAPPER":/usr/local/bin/shield-ban:ro \
    -v /sys/fs/bpf:/mnt/bpf \
    -e SHIELD_GUARD_PIN_DIR="/mnt/bpf/$PIN_NAME" \
    "$F2B_IMAGE" shield-ban ban fd97:c0de::3 60 >/dev/null 2>&1; then
    fail "banning succeeded without CAP_BPF — the container has more privilege than intended"
fi
echo "PASS CAP_BPF is required (dropping it denies the ban)"

echo OK
