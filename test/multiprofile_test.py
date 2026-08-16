#!/usr/bin/env python3
"""Cross-profile isolation of the per-node limits.

Two profiles are enabled at once with deliberately mismatched limits:
tcp is tight (3 connections per window, 2 concurrent), http is loose
(50 per window, 20 concurrent). Traffic to the loose profile must not
consume the tight profile's budget.

That used to fail. Both limits kept one counter per source address for
the whole shield — the njs connection-rate dict keyed on the address
alone, and every profile shared the core `shield_stream_conn` zone — so
each profile tested a common count against its own limit and the
tightest limit governed all of them. A node using the relay normally
locked itself out of SSH it had never connected to.

Runs inside the shield container's network namespace, with its own
upstreams standing in for the protected services.
"""
import http.server
import socket
import sys
import threading
import time

TCP_UPSTREAM = ("127.0.0.1", 9001)
HTTP_UPSTREAM = ("127.0.0.1", 3000)
TCP_SHIELD = ("::1", 2222)
HTTP_SHIELD = ("::1", 8080)

# Must match the values multiprofile_smoke.sh renders.
TCP_RATE, TCP_MAX_CONNS = 5, 2
HTTP_RATE, HTTP_MAX_CONNS = 50, 20

failures = []


def check(name, cond, detail=""):
    print(("  ok   " if cond else "  FAIL ") + name + (" " + detail if detail else ""))
    if not cond:
        failures.append(name)


def echo_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(TCP_UPSTREAM)
    srv.listen(64)

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
            conn, _ = srv.accept()
            threading.Thread(target=serve, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()


def http_server():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(HTTP_UPSTREAM, Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def tcp_ok(timeout=3):
    """True if the shield lets a tcp-profile connection through.

    A refusal is not a failed connect: nginx accepts first and the
    js_access deny (or limit_conn) closes straight after, so the tell is
    an immediate EOF on the first read.
    """
    try:
        sock = socket.create_connection(TCP_SHIELD, timeout=timeout)
    except OSError:
        return False
    try:
        sock.sendall(b"probe")
        return sock.recv(16) == b"probe"
    except OSError:
        return False
    finally:
        sock.close()


def http_hit(timeout=3):
    """One complete HTTP request through the http profile."""
    try:
        sock = socket.create_connection(HTTP_SHIELD, timeout=timeout)
    except OSError:
        return False
    try:
        sock.sendall(b"GET /x HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
        return sock.recv(64).startswith(b"HTTP/1.1 200")
    except OSError:
        return False
    finally:
        sock.close()


def hold_http(n):
    """Open n concurrent http-profile connections and keep them open."""
    socks = []
    for _ in range(n):
        try:
            s = socket.create_connection(HTTP_SHIELD, timeout=3)
            s.sendall(b"GET /x HTTP/1.1\r\nHost: t\r\n\r\n")
            socks.append(s)
        except OSError:
            pass
    return socks


def main():
    echo_server()
    http_server()
    time.sleep(0.5)

    print("- the loose profile does not spend the tight profile's rate budget")
    # Well past TCP_RATE, well under HTTP_RATE. With one shared counter
    # the tcp connection that follows was refused.
    spent = sum(1 for _ in range(TCP_RATE * 4) if http_hit())
    check("http requests succeed", spent >= TCP_RATE * 4 - 1,
          f"({spent}/{TCP_RATE * 4})")
    check("tcp still accepted after http traffic", tcp_ok())

    print("- the loose profile does not spend the tight profile's concurrency")
    # More than TCP_MAX_CONNS held open, far fewer than HTTP_MAX_CONNS.
    # With one shared limit_conn zone the tcp connection was refused.
    held = hold_http(TCP_MAX_CONNS * 3)
    check("http connections held open", len(held) == TCP_MAX_CONNS * 3,
          f"({len(held)})")
    check("tcp still accepted while http connections are held", tcp_ok())
    for s in held:
        s.close()

    # Positive controls. Without these the test would pass just as well
    # against a shield that enforced nothing at all.
    print("- the tight profile's own limits still bite")
    time.sleep(1)
    accepted = sum(1 for _ in range(TCP_RATE * 4) if tcp_ok())
    check("tcp rate limit still refuses its own excess", accepted <= TCP_RATE,
          f"(accepted {accepted}, limit {TCP_RATE})")

    if failures:
        print("FAILED: " + ", ".join(failures))
        sys.exit(1)
    print("all checks passed")


if __name__ == "__main__":
    main()
