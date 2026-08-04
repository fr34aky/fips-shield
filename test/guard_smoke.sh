#!/usr/bin/env bash
# End-to-end test of the Phase 4 eBPF guard. Builds the binary on the
# host (needs cargo + clang) and exercises it inside a privileged
# container against the host kernel: real veth traffic and a TUN device
# in the production L3 shape.
#
# Privileged is unavoidable — loading BPF and attaching tc needs
# CAP_BPF/CAP_NET_ADMIN and a writable bpffs. The container gets no
# network of its own; everything happens on interfaces it creates.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="fips-shield-guard:test"

# Prefer the static build, which is what `make guard` produces and what
# deployments actually run; fall back to a native one so the suite still
# works on a checkout built with `make guard-native`.
GUARD_TARGET="$(uname -m)-unknown-linux-musl"
if rustup target list --installed 2>/dev/null | grep -qx "$GUARD_TARGET"; then
    cargo build --release --target "$GUARD_TARGET" \
        --manifest-path "$REPO_ROOT/guard/Cargo.toml"
    BIN="$REPO_ROOT/guard/target/$GUARD_TARGET/release/fips-guard"
else
    cargo build --release --manifest-path "$REPO_ROOT/guard/Cargo.toml"
    BIN="$REPO_ROOT/guard/target/release/fips-guard"
fi

docker build -q -f "$REPO_ROOT"/test/guard/Dockerfile.test -t "$IMAGE" \
    "$REPO_ROOT"/test/guard

docker run --rm --privileged --network none \
    -v "$BIN":/usr/local/bin/fips-guard:ro \
    -v "$REPO_ROOT/test":/test:ro \
    "$IMAGE" bash /test/guard/in_container.sh

echo "OK"
