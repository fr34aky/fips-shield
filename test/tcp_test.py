#!/usr/bin/env python3
"""Behavioral test for the generic TCP profile.

Runs inside the shield container's network namespace (see tcp_smoke.sh)
with a trivial echo server standing in for the protected service. The
point is that the shield knows nothing about the protocol: it must
still enforce bans, connection rate, and concurrency caps, and pass
payload through untouched.
"""

import socket
import subprocess
import sys
import threading
import time

SHIELD = ("::1", 2222)
UPSTREAM = ("127.0.0.1", 9001)

failures = []


def check(name, cond, detail=""):
    if cond:
        print(f"PASS {name}")
    else:
        failures.append(name)
        print(f"FAIL {name} {detail}")


def echo_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(UPSTREAM)
    srv.listen(32)

    def serve(conn):
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=serve, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


def connect(timeout=5):
    return socket.create_connection(SHIELD, timeout=timeout)


def roundtrip(sock, payload=b"hello-mesh"):
    sock.sendall(payload)
    return sock.recv(len(payload))


def refused():
    """True if the shield refuses the connection (js_access deny closes
    it immediately, so either connect() fails or the first read hits
    EOF)."""
    try:
        sock = connect(timeout=3)
    except OSError:
        return True
    try:
        sock.sendall(b"probe")
        return sock.recv(16) == b""
    except OSError:
        return True
    finally:
        sock.close()


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    echo_server()
    time.sleep(0.3)

    if mode == "expect-reject":
        check("banned node is refused", refused())
    elif mode == "benign":
        sock = connect()
        check("service reachable", roundtrip(sock) == b"hello-mesh")
        sock.close()
    else:
        sock = connect()
        check("payload passes through untouched",
              roundtrip(sock) == b"hello-mesh")
        sock.close()

        # Concurrency cap (test env: 2 per node).
        socks = []
        try:
            for _ in range(2):
                s = connect()
                roundtrip(s, b"x")
                socks.append(s)
            check("connections up to the cap work", len(socks) == 2)
            check("connection over the cap is refused", refused())
        finally:
            for s in socks:
                s.close()

        # Connection rate (test env: 5 per window). The cap above
        # already consumed part of the budget, so open until refused.
        time.sleep(0.3)
        accepted = 0
        for _ in range(10):
            if refused():
                break
            accepted += 1
        check("connection rate limit eventually refuses",
              accepted < 10, f"accepted={accepted}")

    if failures:
        print(f"\n{len(failures)} FAILED: {failures}")
        sys.exit(1)
    print("\nall tests passed")


if __name__ == "__main__":
    main()
