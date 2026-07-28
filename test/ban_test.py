#!/usr/bin/env python3
"""Ban-enforcement client steps for ban_smoke.sh, one mode per
invocation (the shell orchestrates docker-side actions between steps):

  benign         one EVENT round-trips                  -> exit 0
  expect-reject  connection attempt must be rejected    -> exit 0 if
                 rejected, 2 if the shield still serves us
  violate        trigger one kind-denied verdict        -> exit 0
  session-cut    connect, verify, idle, then expect the established
                 session to be cut (the shell bans us mid-idle)
"""

import sys
import time

from wslib import (drain, event, make_frame, read_frame, start_upstream,
                   upstream_saw, wait_for_shield, ws_connect)


def benign():
    sock = ws_connect()
    sock.settimeout(5)
    msg = event("ban-test-benign")
    sock.sendall(make_frame(msg.encode()))
    op, _, payload = read_frame(sock)
    assert op == 1 and payload.decode() == msg, (op, payload)
    sock.sendall(make_frame(b"", opcode=8))
    sock.close()


def expect_reject():
    # js_access denies after accept: the TCP connect may succeed, but
    # the handshake must never complete.
    try:
        sock = ws_connect()
    except (AssertionError, ConnectionError, OSError):
        return
    sock.close()
    sys.exit(2)


def violate():
    sock = ws_connect()
    sock.sendall(make_frame(event("ban-bait", kind=4).encode()))
    sock.settimeout(5)
    drain(sock)
    sock.close()


def session_cut():
    sock = ws_connect()
    sock.settimeout(15)
    msg = event("pre-ban")
    sock.sendall(make_frame(msg.encode()))
    op, _, payload = read_frame(sock)
    assert op == 1 and payload.decode() == msg, (op, payload)
    # The shell bans us now; recheck interval is 1s in the test env.
    time.sleep(3)
    sock.sendall(make_frame(event("post-ban").encode()))
    texts, saw_close = drain(sock)
    echoed = any("post-ban" in t and "NOTICE" not in t for t in texts)
    assert saw_close or not echoed, (texts, saw_close)
    # The upstream is the authority: a regression that forwards the
    # message and only then cuts the session would still satisfy the
    # check above, while violating the core guarantee.
    assert not upstream_saw("post-ban"), "banned node's message reached upstream"
    sock.close()


def main():
    mode = sys.argv[1]
    start_upstream()
    wait_for_shield()
    {"benign": benign, "expect-reject": expect_reject,
     "violate": violate, "session-cut": session_cut}[mode]()
    print(f"OK {mode}")


if __name__ == "__main__":
    main()
