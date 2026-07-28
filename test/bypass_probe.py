#!/usr/bin/env python3
"""Probe: does a bare-LF handshake bypass WebSocket inspection?

The engine's handshake sniffer looks for CRLF header framing. nginx's
HTTP parser also accepts a bare LF. If the two disagree, a client can
complete a WebSocket upgrade that the engine did not classify as one —
and then speak WebSocket with no inspection at all.

Sends a message the policy must reject (denied kind 4) and asks the
mock relay whether it arrived. Upstream sight == bypass.
"""

import base64
import os
import socket
import sys
import time

from wslib import (SHIELD, event, make_frame, read_frame, received,
                   recv_until, start_upstream, wait_for_shield)

KEY = base64.b64encode(b"0123456789abcdef").decode()


def handshake(raw: bytes, label: str):
    sock = socket.create_connection(SHIELD, timeout=5)
    sock.sendall(raw)
    try:
        head = recv_until(sock, b"\r\n\r\n")
    except (ConnectionError, socket.timeout):
        print(f"  {label}: no response (refused)")
        sock.close()
        return None
    status = head.split(b"\r\n")[0]
    print(f"  {label}: {status.decode(errors='replace')}")
    if b" 101 " not in status:
        sock.close()
        return None
    return sock


def try_bypass(label, raw, marker):
    print(f"\n--- {label}")
    sock = handshake(raw, "handshake")
    if sock is None:
        print(f"  RESULT: no upgrade -> no bypass via this variant")
        return False
    # Policy says kind 4 is denied; if inspection is active this frame
    # is dropped and the connection cut.
    sock.sendall(make_frame(event(marker, kind=4).encode()))
    time.sleep(1.0)
    got = any(marker in m for m in received)
    print(f"  denied-kind message reached upstream: {got}")
    sock.close()
    return got


def main():
    start_upstream()
    wait_for_shield()

    normal = (
        f"GET / HTTP/1.1\r\nHost: relay.test\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {KEY}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\r\n"
    ).encode()

    # Variant A: bare LF ends the header line *before* Upgrade, so the
    # engine's "\r\nupgrade:" regex misses it.
    variant_a = (
        f"GET / HTTP/1.1\r\nHost: relay.test\r\nX-Pad: 1\n"
        f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {KEY}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ).encode()

    # Variant B: header block terminated by "\r\n\n", so the engine
    # never finds "\r\n\r\n" and stays in handshake mode.
    variant_b = (
        f"GET / HTTP/1.1\r\nHost: relay.test\r\nUpgrade: websocket\r\n"
        f"Connection: Upgrade\r\nSec-WebSocket-Key: {KEY}\r\n"
        f"Sec-WebSocket-Version: 13\r\n\n"
    ).encode()

    baseline = try_bypass("baseline (well-formed CRLF, inspection expected)",
                          normal, "probe-baseline")
    a = try_bypass("variant A: bare LF before Upgrade header", variant_a,
                   "probe-variant-a")
    b = try_bypass("variant B: header block ends with CRLF+LF", variant_b,
                   "probe-variant-b")

    print("\n=== SUMMARY")
    print(f"baseline blocked (expected True): {not baseline}")
    print(f"variant A bypass: {a}")
    print(f"variant B bypass: {b}")
    sys.exit(1 if (a or b) else 0)


if __name__ == "__main__":
    main()
