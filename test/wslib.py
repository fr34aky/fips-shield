"""Shared plumbing for fips-shield behavioral tests: a raw-socket
WebSocket client, a mock relay upstream that records and echoes every
Nostr message it receives, and small assertion helpers. No external
dependencies."""

import base64
import hashlib
import json
import os
import socket
import struct
import threading
import time

SHIELD = ("::1", 80)
UPSTREAM = ("127.0.0.1", 7777)
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

received = []          # messages the upstream saw, across all conns
received_lock = threading.Lock()
failures = []


# --- byte-level helpers -------------------------------------------------

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


# --- mock relay upstream ------------------------------------------------

def _upstream_conn(conn):
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


def _upstream_server(sock):
    while True:
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        threading.Thread(target=_upstream_conn, args=(conn,), daemon=True).start()


def start_upstream():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(UPSTREAM)
    srv.listen(16)
    threading.Thread(target=_upstream_server, args=(srv,), daemon=True).start()
    return srv


def wait_for_shield(timeout=10):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            socket.create_connection(SHIELD, timeout=1).close()
            return
        except OSError:
            time.sleep(0.2)


# --- client helpers -----------------------------------------------------

def connect():
    return socket.create_connection(SHIELD, timeout=5)


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


def event(content, kind=1):
    return json.dumps(["EVENT", {"kind": kind, "content": content,
                                 "tags": [], "created_at": int(time.time())}])
