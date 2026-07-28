#!/usr/bin/env python3
"""L3 path test for the eBPF guard — the production shape.

fips0 is a TUN device: packets arrive at tc ingress with no ethernet
header, starting straight at the IPv6 header. This test reproduces that
exactly by creating a TUN device and writing packets into its fd, which
is precisely how a packet "arrives from the network" on such a device.

Asserts, against the guard's own counters: unbanned traffic passes,
banned traffic is dropped, a ban expires in-kernel with no userspace
involvement, and the per-source throttle drops a burst while leaving a
well-behaved source alone.
"""

import fcntl
import os
import struct
import subprocess
import sys
import time

TUNSETIFF = 0x400454CA
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
DEV = "guard0"
LOCAL = "fd97::1"

failures = []


def sh(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True)


def guard(*args, check=True):
    return sh("fips-guard", *args, check=check)


def stats():
    out = {}
    for line in guard("stats").stdout.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].isdigit():
            out[" ".join(parts[:-1])] = int(parts[-1])
    return out


def addr(a):
    """Text IPv6 -> 16 bytes, without pulling in socket.inet_pton edge cases."""
    import socket
    return socket.inet_pton(socket.AF_INET6, a)


def packet(src, dst=LOCAL, payload=b"fips-shield-guard-test"):
    """Minimal IPv6/UDP packet. The UDP checksum is left zero: tc
    ingress counts the packet long before the stack validates it."""
    udp = struct.pack("!HHHH", 4444, 4445, 8 + len(payload), 0) + payload
    ip6 = struct.pack("!IHBB", (6 << 28), len(udp), 17, 64) + addr(src) + addr(dst)
    return ip6 + udp


def check(name, cond, detail=""):
    if cond:
        print(f"PASS {name}")
    else:
        failures.append(name)
        print(f"FAIL {name} {detail}")


def main():
    tun = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(tun, TUNSETIFF, struct.pack("16sH", DEV.encode(), IFF_TUN | IFF_NO_PI))
    sh("ip", "link", "set", DEV, "up")
    sh("ip", "-6", "addr", "add", f"{LOCAL}/64", "dev", DEV)

    guard("load", "--iface", DEV)

    def inject(src, n=1):
        for _ in range(n):
            os.write(tun, packet(src))
        time.sleep(0.2)

    # --- baseline: L3 packets are parsed and passed
    before = stats()
    inject("fd97::99")
    after = stats()
    check("L3 (TUN) packet passes and is counted",
          after["passed"] == before["passed"] + 1,
          f"{before['passed']} -> {after['passed']}")

    # --- ban drops
    guard("ban", "fd97::99", "60")
    before = stats()
    inject("fd97::99", 3)
    after = stats()
    check("banned source is dropped in-kernel",
          after["dropped (ban)"] == before["dropped (ban)"] + 3
          and after["passed"] == before["passed"],
          f"ban {before['dropped (ban)']}->{after['dropped (ban)']} "
          f"pass {before['passed']}->{after['passed']}")

    # --- other sources unaffected
    before = stats()
    inject("fd97::a")
    after = stats()
    check("unbanned source still passes",
          after["passed"] == before["passed"] + 1)

    # --- check/list reflect the ban
    check("check reports banned", guard("check", "fd97::99", check=False).returncode == 0)
    check("list contains the ban",
          any(l.startswith("fd97::99 ") for l in guard("list").stdout.splitlines()),
          guard("list").stdout)

    # --- unban restores
    guard("unban", "fd97::99")
    before = stats()
    inject("fd97::99")
    after = stats()
    check("unban restores traffic", after["passed"] == before["passed"] + 1)
    check("check reports not banned",
          guard("check", "fd97::99", check=False).returncode == 1)

    # --- expiry is enforced by the kernel, not a userspace sweeper
    guard("ban", "fd97::b", "2")
    before = stats()
    inject("fd97::b")
    mid = stats()
    check("short ban drops while active",
          mid["dropped (ban)"] == before["dropped (ban)"] + 1)
    time.sleep(3)
    inject("fd97::b")
    after = stats()
    check("ban expires in-kernel without intervention",
          after["passed"] == mid["passed"] + 1,
          f"{mid['passed']} -> {after['passed']}")

    # --- throttle: burst allowed, excess dropped, other sources spared
    guard("throttle", "5", "5")
    before = stats()
    inject("fd97::c", 30)
    after = stats()
    dropped = after["dropped (throttle)"] - before["dropped (throttle)"]
    passed = after["passed"] - before["passed"]
    check("throttle drops the flood tail", dropped > 0, f"dropped={dropped}")
    check("throttle lets the burst through", 0 < passed <= 12,
          f"passed={passed} (burst 5 + refill)")

    before = stats()
    inject("fd97::d")
    after = stats()
    check("throttle is per-source, not global",
          after["passed"] == before["passed"] + 1)

    guard("throttle", "0", "0")
    guard("unload", "--iface", DEV)
    os.close(tun)

    if failures:
        print(f"\n{len(failures)} FAILED: {failures}")
        sys.exit(1)
    print("\nL3/TUN guard tests passed")


if __name__ == "__main__":
    main()
