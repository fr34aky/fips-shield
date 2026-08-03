#!/usr/bin/env python3
"""Regression: slow-drip inspection cost.

What this engine costs is per read callback, and the client chooses the
segment size. A byte-at-a-time handshake stayed under every
byte-denominated cap (MAX_HANDSHAKE, ws_max_msg) while costing ~300x
the worker CPU of the same bytes delivered normally -- measured at 4.75
seconds of nginx CPU for 16 KB, against 10 ms through a profile with no
js_filter. Nothing logged a verdict, so the detection engine never saw
it and the source was never banned.

Both phases now cap reads and emit a verdict. The third test is the
other half of the contract: the caps must not cut a legitimate client
whose message merely happens to arrive across several segments.
"""

import json
import socket
import struct
import sys
import time

sys.path.insert(0, "/test")
from wslib import (check, connect, drain, failures,  # noqa: E402
                   read_frame, start_upstream, upstream_saw,
                   wait_for_shield, ws_connect)


def drip(sock, payload, per_read=1, pace=0.0002):
    """Send payload in `per_read`-byte segments, paced so each lands as
    its own read event rather than being coalesced by TCP."""
    for i in range(0, len(payload), per_read):
        sock.sendall(payload[i:i + per_read])
        time.sleep(pace)


def test_handshake_drip():
    """A handshake delivered one byte per read is cut, not absorbed."""
    sock = connect()
    sock.settimeout(10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.sendall(b"GET / HTTP/1.1\r\n")
    cut = False
    try:
        # Well under MAX_HANDSHAKE (16384): the byte cap is not what
        # should stop this.
        drip(sock, b"X-Pad: " + b"a" * 4000 + b"\r\n")
        drip(sock, b"Host: r\r\nUpgrade: websocket\r\n\r\n")
        sock.settimeout(3)
        cut = sock.recv(64) == b""
    except (ConnectionError, socket.timeout, OSError):
        cut = True
    check("dripped handshake is cut before completing", cut)
    sock.close()


def test_message_drip():
    """A frame payload delivered one byte per read is cut."""
    sock = ws_connect()
    sock.settimeout(10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    marker = "drip-marker-never-forwarded"
    payload = json.dumps(
        ["EVENT", {"kind": 1, "tags": [], "created_at": 0,
                   "content": marker + "x" * 6000}]).encode()
    # Declared length is legal and under ws_max_msg; only the delivery
    # pattern is abusive.
    sock.sendall(struct.pack("!BBH", 0x81, 0x80 | 126, len(payload))
                 + b"\x00\x00\x00\x00")
    cut = False
    try:
        drip(sock, payload)
        sock.settimeout(3)
        texts, saw_close = drain(sock)
        cut = saw_close or any("fips-shield" in t for t in texts)
    except (ConnectionError, socket.timeout, OSError):
        cut = True
    check("dripped message is cut", cut)
    check("dripped message never reached upstream", not upstream_saw(marker))
    sock.close()


def test_moderate_segmentation_still_works():
    """The caps must not punish a legitimate client whose message
    happens to arrive in several segments.

    Sized against ws_smoke.sh's test policy, which tightens
    SHIELD_WS_MAX_MSG to 1000 -- so this stays well under that while
    still spanning many more reads than a single send would.
    """
    sock = ws_connect()
    sock.settimeout(10)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    marker = "legit-segmented-message"
    payload = json.dumps(
        ["EVENT", {"kind": 1, "tags": [], "created_at": 0,
                   "content": marker + "y" * 600}]).encode()
    sock.sendall(struct.pack("!BBH", 0x81, 0x80 | 126, len(payload))
                 + b"\x00\x00\x00\x00")
    # ~40 reads: far more than one send, far below the read cap.
    drip(sock, payload, per_read=16, pace=0.001)
    echoed = False
    try:
        frame = read_frame(sock)
        echoed = frame is not None and marker in frame[2].decode(
            "utf-8", "replace")
    except (ConnectionError, socket.timeout, OSError):
        pass
    check("message split across ~40 normal reads is still forwarded",
          echoed)
    sock.close()


def main():
    start_upstream()
    wait_for_shield()
    test_handshake_drip()
    test_message_drip()
    test_moderate_segmentation_still_works()
    if failures:
        print("FAILURES:", failures)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
