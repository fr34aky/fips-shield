#!/usr/bin/env python3
"""Regression: query cost, not query shape.

The item-count metric measures how *enumerated* a query is, not how
*selective*, so it scored the broadest possible query at zero: an empty
filter passed, a REQ with no filter at all passed, "limit" was never
inspected at any value, and a 100 KB search term counted as one item.
NEG-OPEN — negentropy reconciliation, the most expensive thing strfry
does — carried a filter that was never inspected at all and was priced
under the loose message bucket.

The last two tests are the other half of the contract: ordinary queries
must still work, including an open-ended-but-narrowing subscription.
"""

import json
import sys
import time

sys.path.insert(0, "/test")
from wslib import (check, drain, failures, make_frame,  # noqa: E402
                   read_frame, start_upstream, upstream_saw,
                   wait_for_shield, ws_connect)


def send(sock, obj):
    sock.sendall(make_frame(json.dumps(obj).encode()))


def expect_cut(name, obj, marker):
    """The message must close the session and never reach the relay."""
    sock = ws_connect()
    sock.settimeout(5)
    send(sock, obj)
    texts, saw_close = drain(sock)
    noticed = any("fips-shield" in t for t in texts)
    check(name + ": cut", saw_close or noticed, f"texts={texts}")
    check(name + ": never reached upstream", not upstream_saw(marker))
    sock.close()


def expect_forwarded(name, obj, marker):
    """A legitimate message must still be relayed untouched."""
    sock = ws_connect()
    sock.settimeout(5)
    send(sock, obj)
    seen = False
    try:
        frame = read_frame(sock)
        seen = frame is not None and marker in frame[2].decode(
            "utf-8", "replace")
    except (ConnectionError, OSError):
        pass
    check(name + ": forwarded", seen)
    sock.close()


def main():
    start_upstream()
    wait_for_shield()

    expect_cut("REQ with a huge limit",
               ["REQ", "cut-limit", {"kinds": [1], "limit": 10_000_000}],
               "cut-limit")
    expect_cut("REQ with an empty filter",
               ["REQ", "cut-empty", {}], "cut-empty")
    expect_cut("REQ with no filter at all",
               ["REQ", "cut-nofilter"], "cut-nofilter")
    expect_cut("REQ with an oversized filter value",
               ["REQ", "cut-fat", {"kinds": [1], "search": "a" * 50_000}],
               "cut-fat")
    expect_cut("NEG-OPEN with an unbounded filter",
               ["NEG-OPEN", "cut-neg", {}, "6" * 64], "cut-neg")

    # Still-works half. A subscription with no time bound is normal —
    # only a filter that narrows *nothing* should be refused.
    expect_forwarded("ordinary REQ",
                     ["REQ", "ok-req", {"kinds": [1], "limit": 100}],
                     "ok-req")
    expect_forwarded("open-ended but narrowing REQ",
                     ["REQ", "ok-live", {"kinds": [1, 7]}], "ok-live")
    expect_forwarded("NEG-OPEN with a narrowing filter",
                     ["NEG-OPEN", "ok-neg", {"kinds": [1]}, "6" * 64],
                     "ok-neg")

    if failures:
        print("FAILURES:", failures)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
