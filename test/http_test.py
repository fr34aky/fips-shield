#!/usr/bin/env python3
"""Behavioral test for the generic HTTP profile.

Runs inside the shield container's network namespace (see
http_smoke.sh) with a small HTTP app standing in for the protected
service. Asserts the request-level protections that only exist because
nginx parses HTTP — method allowlist, path allowlist, body cap,
per-node request rate — plus that legitimate traffic reaches the app
unchanged and the connection-level ban still applies.
"""

import http.server
import socket
import sys
import threading
import time
import urllib.error
import urllib.request

SHIELD = "http://[::1]:8080"
APP_PORT = 3000

failures = []
seen_paths = []


def check(name, cond, detail=""):
    if cond:
        print(f"PASS {name}")
    else:
        failures.append(name)
        print(f"FAIL {name} {detail}")


class App(http.server.BaseHTTPRequestHandler):
    """Echoes back what it received, so the test can prove the request
    arrived intact — and prove that rejected requests never arrive."""

    def _respond(self):
        seen_paths.append(self.path)
        body = f"app-ok {self.command} {self.path}".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Client", self.headers.get("X-Real-IP", "?"))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_HEAD = do_PUT = do_DELETE = _respond

    def log_message(self, *args):
        pass


def start_app():
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", APP_PORT), App)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def request(path="/", method="GET", body=None, timeout=5):
    """Returns (status, body) — status 0 when the connection is closed
    without a response (nginx 444)."""
    req = urllib.request.Request(SHIELD + path, method=method, data=body)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()
    except (urllib.error.URLError, ConnectionError, socket.timeout) as e:
        reason = getattr(e, "reason", e)
        if isinstance(reason, (ConnectionResetError, ConnectionAbortedError)):
            return 0, b""
        if isinstance(reason, (socket.timeout, TimeoutError)):
            return -1, b""
        return 0, b""


def request_full(path="/", method="GET", body=None, timeout=5):
    """Like request(), but also returns the response headers."""
    req = urllib.request.Request(SHIELD + path, method=method, data=body)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), dict(e.headers)
    except (urllib.error.URLError, ConnectionError, socket.timeout):
        return 0, b"", {}


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
    start_app()
    time.sleep(0.3)

    if mode == "expect-reject":
        status, _ = request("/allowed/x")
        check("banned node cannot reach the app", status in (0, -1),
              f"status={status}")
        check("banned node's request never reached the app",
              not any("/allowed/x" == p for p in seen_paths))
    else:
        status, body, hdrs = request_full("/allowed/hello")
        check("allowed request reaches the app",
              status == 200 and b"app-ok GET /allowed/hello" in body,
              f"status={status} body={body[:60]}")
        # If the PROXY-protocol/real-IP path broke, every peer would
        # look like the socket peer and all the per-node limits would
        # silently become global.
        check("app sees the peer's mesh address, not the proxy",
              hdrs.get("X-Client") == "::1",
              f"X-Client={hdrs.get('X-Client')}")

        status, body = request("/allowed/thing", method="POST", body=b"x=1")
        check("allowed method passes", status == 200 and b"POST" in body,
              f"status={status}")

        before = len(seen_paths)
        status, _ = request("/allowed/x", method="DELETE")
        # 403 from limit_except (access phase) rather than 405 from an
        # `if` in the rewrite phase — the point being that this request
        # is counted against the rate limit before it is refused.
        check("disallowed method is rejected (403)", status == 403,
              f"status={status}")
        check("rejected method never reached the app",
              len(seen_paths) == before)

        before = len(seen_paths)
        status, _ = request("/admin/secret")
        check("disallowed path is closed silently (444)", status == 0,
              f"status={status}")
        check("rejected path never reached the app",
              len(seen_paths) == before)

        # Path matching uses the decoded, normalised URI, so traversal
        # tricks cannot reach a hidden route.
        before = len(seen_paths)
        status, _ = request("/allowed/..%2fadmin/secret")
        check("encoded traversal does not bypass the path allowlist",
              status in (0, 400) and len(seen_paths) == before,
              f"status={status}")

        before = len(seen_paths)
        status, _ = request("/allowed/upload", method="POST",
                            body=b"z" * 200_000)
        check("oversized body is rejected (413)", status == 413,
              f"status={status}")
        check("oversized body never reached the app",
              len(seen_paths) == before)

        # Request rate: test env is 5r/s with burst 5, so a tight loop
        # of 40 must start getting 429s. Let the bucket refill first —
        # the checks above already spent part of this second's budget.
        time.sleep(2)
        codes = [request("/allowed/flood")[0] for _ in range(40)]
        check("request rate limit kicks in", codes.count(429) > 0,
              f"429s={codes.count(429)} of {len(codes)}")
        check("rate limit lets the burst through", codes.count(200) >= 5,
              f"200s={codes.count(200)}")

    if failures:
        print(f"\n{len(failures)} FAILED: {failures}")
        sys.exit(1)
    print("\nall tests passed")


if __name__ == "__main__":
    main()
