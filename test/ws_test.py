#!/usr/bin/env python3
"""Behavioral test for the fips-shield WebSocket inspection engine.

Runs inside the shield container's network namespace. Plays both roles
with raw sockets (no dependencies): a mock relay upstream on
127.0.0.1:7777 that records and echoes every Nostr message it receives,
and mesh clients connecting to the shield on [::1]:80.

Asserts both halves of the enforcement contract: the client is cut off
(NOTICE + Close 1008 / EOF), and the offending message never reached
the upstream.
"""

import base64
import hashlib
import json
import os
import socket
import struct
import sys
import threading
import time

SHIELD = ("::1", 80)
UPSTREAM = ("127.0.0.1", 7777)
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

received = []          # messages the upstream saw, across all conns
received_lock = threading.Lock()
failures = []


# --- WebSocket plumbing -------------------------------------------------

def recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("EOF")
        buf += chunk
    return buf


def recv_until(sock, marker):
    buf = b""
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("EOF")
        buf += chunk
    return buf


def make_frame(payload, opcode=1, fin=True, masked=True, mask_key=None):
    b0 = (0x80 if fin else 0) | opcode
    length = len(payload)
    if length < 126:
        header = struct.pack("!BB", b0, (0x80 if masked else 0) | length)
    elif length < 65536:
        header = struct.pack("!BBH", b0, (0x80 if masked else 0) | 126, length)
    else:
        header = struct.pack("!BBQ", b0, (0x80 if masked else 0) | 127, length)
    if masked:
        key = mask_key if mask_key is not None else os.urandom(4)
        body = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
        return header + key + body
    return header + payload


def read_frame(sock):
    """Returns (opcode, fin, payload) or None on EOF."""
    try:
        head = recv_exact(sock, 2)
    except ConnectionError:
        return None
    b0, b1 = head
    fin, opcode = bool(b0 & 0x80), b0 & 0x0F
    masked, length = bool(b1 & 0x80), b1 & 0x7F
    if length == 126:
        length = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", recv_exact(sock, 8))[0]
    key = recv_exact(sock, 4) if masked else None
    payload = recv_exact(sock, length)
    if masked:
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
    return opcode, fin, payload


# --- Mock relay upstream ------------------------------------------------

def upstream_conn(conn):
    try:
        head = recv_until(conn, b"\r\n\r\n")
        headers = head.decode("latin-1").lower()
        if "upgrade: websocket" not in headers:
            body = b'{"name":"test-relay"}'
            conn.sendall(
                b"HTTP/1.1 200 OK\r\ncontent-type: application/nostr+json\r\n"
                b"content-length: " + str(len(body)).encode() +
                b"\r\nconnection: close\r\n\r\n" + body)
            return
        key = next(l.split(":", 1)[1].strip()
                   for l in head.decode("latin-1").split("\r\n")
                   if l.lower().startswith("sec-websocket-key:"))
        accept = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        conn.sendall(("HTTP/1.1 101 Switching Protocols\r\n"
                      "upgrade: websocket\r\nconnection: upgrade\r\n"
                      f"sec-websocket-accept: {accept}\r\n\r\n").encode())
        parts = []
        while True:
            frame = read_frame(conn)
            if frame is None:
                return
            opcode, fin, payload = frame
            if opcode == 8:                      # close
                conn.sendall(make_frame(payload, opcode=8, masked=False))
                return
            if opcode in (1, 0):                 # text/continuation
                parts.append(payload)
                if fin:
                    msg = b"".join(parts)
                    parts = []
                    with received_lock:
                        received.append(msg.decode())
                    conn.sendall(make_frame(msg, masked=False))
    except (ConnectionError, OSError):
        pass
    finally:
        conn.close()


def upstream_server(sock):
    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        threading.Thread(target=upstream_conn, args=(conn,), daemon=True).start()


# --- Client helpers -----------------------------------------------------

def connect():
    sock = socket.create_connection(SHIELD, timeout=5)
    return sock


def ws_connect():
    sock = connect()
    key = base64.b64encode(os.urandom(16)).decode()
    sock.sendall((f"GET / HTTP/1.1\r\nHost: relay.test\r\n"
                  f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
                  f"Sec-WebSocket-Key: {key}\r\n"
                  f"Sec-WebSocket-Version: 13\r\n\r\n").encode())
    head = recv_until(sock, b"\r\n\r\n")
    assert b" 101 " in head.split(b"\r\n")[0], head
    return sock


def drain(sock):
    """Read frames until EOF (or timeout); returns (texts, saw_close).

    Deliberately keeps reading past a Close frame like a polite client:
    hanging up instantly RSTs the proxied session and can discard
    in-flight data nginx has not yet relayed.
    """
    texts, saw_close = [], False
    try:
        while True:
            frame = read_frame(sock)
            if frame is None:
                break
            opcode, _, payload = frame
            if opcode == 8:
                saw_close = True
            elif opcode == 1:
                texts.append(payload.decode())
    except (ConnectionError, socket.timeout, OSError):
        pass
    return texts, saw_close


def upstream_saw(needle):
    with received_lock:
        return any(needle in m for m in received)


def check(name, cond, detail=""):
    if cond:
        print(f"PASS {name}")
    else:
        failures.append(name)
        print(f"FAIL {name} {detail}")


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


def event(content, kind=1):
    return json.dumps(["EVENT", {"kind": kind, "content": content,
                                 "tags": [], "created_at": int(time.time())}])


# --- Tests --------------------------------------------------------------

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
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(UPSTREAM)
    srv.listen(16)
    threading.Thread(target=upstream_server, args=(srv,), daemon=True).start()

    # Shield may still be starting up.
    for _ in range(50):
        try:
            socket.create_connection(SHIELD, timeout=1).close()
            break
        except OSError:
            time.sleep(0.2)

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
