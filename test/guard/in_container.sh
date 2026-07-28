#!/usr/bin/env bash
# Runs inside the privileged test container (see guard_smoke.sh).
#
# Two complementary tests:
#   * veth + ping   — real end-to-end traffic over an L2 device, proving
#                     the drop is a real drop (not just a counter).
#   * tun_test.py   — the L3 device shape production actually uses
#                     (fips0 is a TUN), plus expiry and throttling.
set -euo pipefail

mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

echo "=== veth end-to-end (L2 device) ==="

ip link add veth-host type veth peer name veth-peer
ip netns add client
ip link set veth-peer netns client
ip -6 addr add fd97:e2e::1/64 dev veth-host nodad
ip link set veth-host up
ip netns exec client ip -6 addr add fd97:e2e::2/64 dev veth-peer nodad
ip netns exec client ip link set veth-peer up
ip netns exec client ip link set lo up

ping6() { ip netns exec client ping -6 -c 2 -W 2 -q "$@" >/dev/null 2>&1; }

# Warm the neighbour caches before the guard is attached, so neighbour
# discovery (which uses link-local addresses, not the banned global
# one) never lands inside a measured window.
ping6 fd97:e2e::1 || true

fips-guard load --iface veth-host

if ! ping6 fd97:e2e::1; then
    echo "FAIL baseline ping should succeed" >&2
    exit 1
fi
echo "PASS baseline ping succeeds through the guard"

fips-guard ban fd97:e2e::2 60 >/dev/null
if ping6 fd97:e2e::1; then
    echo "FAIL banned peer should not reach the host" >&2
    tc filter show dev veth-host ingress >&2
    fips-guard list >&2
    fips-guard stats >&2
    ip netns exec client ip -6 addr show veth-peer >&2
    exit 1
fi
echo "PASS banned peer's traffic is dropped end-to-end"

stats="$(fips-guard stats)"
if ! grep -q "^dropped (ban) *[1-9]" <<<"$stats"; then
    echo "FAIL drop counter did not move" >&2
    echo "$stats" >&2
    exit 1
fi
echo "PASS drop counter reflects the dropped packets"

fips-guard unban fd97:e2e::2 >/dev/null
if ! ping6 fd97:e2e::1; then
    echo "FAIL unban should restore reachability" >&2
    exit 1
fi
echo "PASS unban restores reachability"

# Bans must survive a reload of the program (pinned maps are reused).
fips-guard ban fd97:e2e::2 60 >/dev/null
fips-guard load --iface veth-host >/dev/null
if ! fips-guard check fd97:e2e::2 >/dev/null; then
    echo "FAIL ban did not survive reload" >&2
    exit 1
fi
if ping6 fd97:e2e::1; then
    echo "FAIL still-banned peer reachable after reload" >&2
    exit 1
fi
echo "PASS bans survive a guard reload"

fips-guard unload --iface veth-host >/dev/null
if ! ping6 fd97:e2e::1; then
    echo "FAIL unload should leave traffic unfiltered" >&2
    exit 1
fi
echo "PASS unload leaves the interface unfiltered"

ip netns del client
ip link del veth-host

echo
echo "=== TUN injection (L3 device — the fips0 shape) ==="
python3 /test/guard/tun_test.py
