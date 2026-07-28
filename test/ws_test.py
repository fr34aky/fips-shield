#!/usr/bin/env python3
"""Behavioral test for the fips-shield WebSocket inspection engine.

Runs inside the shield container's network namespace (see ws_smoke.sh).
Uses wslib's mock relay upstream and raw-socket WebSocket clients.

Asserts both halves of the enforcement contract: the client is cut off
(NOTICE + Close 1008 / EOF), and the offending message never reached
the upstream.
"""

import json
import socket
import sys
import time

from wslib import (check, connect, drain, event, failures, make_frame,
                   read_frame, start_upstream, upstream_saw,
                   wait_for_shield, ws_connect)


def expect_cut(sock, name, marker):
    """Bad message already sent: expect NOTICE/close and no upstream sight."""
    sock.settimeout(5)
    texts, saw_close = drain(sock)
    echoed = any(marker in t for t in texts if "NOTICE" not in t)
    noticed = any("fips-shield" in t for t in texts)
    check(name + ": connection cut", (saw_close or noticed) and not echoed,
          f"texts={texts} close={saw_close}")
    check(name + ": never reached upstream", not upstream_saw(marker))
    sock.close()


def test_nip11():
    sock = connect()
    sock.sendall(b"GET / HTTP/1.1\r\nHost: relay.test\r\n"
                 b"Accept: application/nostr+json\r\n\r\n")
    sock.settimeout(5)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    check("nip11 passthrough", b" 200 " in data and b"test-relay" in data,
          data[:200])
    sock.close()


def test_benign():
    sock = ws_connect()
    sock.settimeout(5)
    msg = event("hello-mesh")
    sock.sendall(make_frame(msg.encode()))
    op, _, payload = read_frame(sock)
    check("benign EVENT forwarded", op == 1 and payload.decode() == msg)
    req = json.dumps(["REQ", "sub1", {"kinds": [1], "limit": 10}])
    sock.sendall(make_frame(req.encode()))
    op, _, payload = read_frame(sock)
    check("benign REQ forwarded", op == 1 and payload.decode() == req)
    sock.sendall(make_frame(json.dumps(["CLOSE", "sub1"]).encode()))
    op, _, payload = read_frame(sock)
    check("benign CLOSE forwarded", op == 1 and b"CLOSE" in payload)
    sock.sendall(make_frame(b"", opcode=8))
    sock.close()


def test_fragmented():
    sock = ws_connect()
    sock.settimeout(5)
    msg = event("fragmented-msg").encode()
    half = len(msg) // 2
    sock.sendall(make_frame(msg[:half], opcode=1, fin=False))
    sock.sendall(make_frame(msg[half:], opcode=0, fin=True))
    op, _, payload = read_frame(sock)
    check("fragmented EVENT reassembled+forwarded",
          op == 1 and payload == msg)
    sock.sendall(make_frame(b"", opcode=8))
    sock.close()


def test_unmasked():
    sock = ws_connect()
    sock.sendall(make_frame(event("unmasked-attack").encode(), masked=False))
    expect_cut(sock, "unmasked frame", "unmasked-attack")


def test_oversized():
    sock = ws_connect()                       # test env: max 1000 bytes
    sock.sendall(make_frame(event("big " + "x" * 2000).encode()))
    expect_cut(sock, "oversized message", "big x")


def test_kind_denied():
    sock = ws_connect()                       # test env: kind 4 denied
    sock.sendall(make_frame(event("secret-dm", kind=4).encode()))
    expect_cut(sock, "denied kind", "secret-dm")


def test_bad_type():
    sock = ws_connect()
    sock.sendall(make_frame(json.dumps(["SPAM", "flood-me"]).encode()))
    expect_cut(sock, "disallowed type", "flood-me")


def test_event_flood():
    sock = ws_connect()                       # test env: rate 1, burst 3
    for i in range(5):
        sock.sendall(make_frame(event(f"flood-{i}").encode()))
    sock.settimeout(5)
    texts, saw_close = drain(sock)
    check("event flood: cut after burst", saw_close or
          any("fips-shield" in t for t in texts), f"texts={texts}")
    # The client is closed the moment the bucket runs dry, so in-flight
    # echoes may not make it back; the invariant is what the upstream
    # saw: the burst-allowed prefix and nothing after.
    time.sleep(0.5)
    got = [i for i in range(5) if upstream_saw(f"flood-{i}")]
    check("event flood: burst respected, tail dropped", got == [0, 1, 2],
          f"upstream got {got}")
    sock.close()


def test_sub_cap():
    sock = ws_connect()                       # test env: max 2 subs
    for sid in ("a", "b", "c"):
        sock.sendall(make_frame(
            json.dumps(["REQ", "sub-" + sid, {"kinds": [1]}]).encode()))
    sock.settimeout(5)
    texts, saw_close = drain(sock)
    check("sub cap: cut on third REQ", saw_close or
          any("fips-shield" in t for t in texts), f"texts={texts}")
    check("sub cap: third REQ never reached upstream",
          not upstream_saw("sub-c"))
    sock.close()


def main():
    start_upstream()
    wait_for_shield()

    test_nip11()
    test_benign()
    test_fragmented()
    test_unmasked()
    test_oversized()
    test_kind_denied()
    test_bad_type()
    test_event_flood()
    test_sub_cap()

    if failures:
        print(f"\n{len(failures)} FAILED: {failures}")
        sys.exit(1)
    print("\nall tests passed")


if __name__ == "__main__":
    main()
