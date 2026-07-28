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

cargo build --release --manifest-path "$REPO_ROOT/guard/Cargo.toml"

docker build -q -f "$REPO_ROOT"/test/guard/Dockerfile.test -t "$IMAGE" \
    "$REPO_ROOT"/test/guard

docker run --rm --privileged --network none \
    -v "$REPO_ROOT/guard/target/release/fips-guard":/usr/local/bin/fips-guard:ro \
    -v "$REPO_ROOT/test":/test:ro \
    "$IMAGE" bash /test/guard/in_container.sh

echo "OK"
