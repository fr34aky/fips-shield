#!/usr/bin/env python3
"""Probe: do JavaScript prototype keys defeat the subscription cap and
the message-type allowlist?

st.subs and cfg.types are plain objects, so `"toString" in st.subs` and
`cfg.types["constructor"]` are truthy for names the engine never set.
"""

import json
import sys
import time

from wslib import (drain, make_frame, read_frame, start_upstream,
                   upstream_saw, wait_for_shield, ws_connect)

failures = []


def check(name, cond, detail=""):
    print(("PASS " if cond else "FAIL ") + name + ("" if cond else f" {detail}"))
    if not cond:
        failures.append(name)


def probe_type_allowlist():
    """['constructor', ...] is not a Nostr message type and must be
    refused by the allowlist."""
    sock = ws_connect()
    sock.settimeout(5)
    sock.sendall(make_frame(json.dumps(["constructor", "proto-probe"]).encode()))
    time.sleep(0.8)
    texts, saw_close = drain(sock)
    leaked = upstream_saw("proto-probe")
    check("type allowlist refuses prototype-named type",
          (saw_close or any("fips-shield" in t for t in texts)) and not leaked,
          f"reached upstream={leaked}")
    sock.close()


def probe_sub_cap():
    """CLOSE for a prototype-named id must not credit the subscription
    counter. Test env: SHIELD_WS_MAX_SUBS=2."""
    sock = ws_connect()
    sock.settimeout(5)
    for _ in range(5):
        sock.sendall(make_frame(json.dumps(["CLOSE", "toString"]).encode()))
    time.sleep(0.5)
    # With a correct counter, the 3rd distinct REQ must be refused.
    for i in range(6):
        sock.sendall(make_frame(
            json.dumps(["REQ", f"sub-{i}", {"kinds": [1]}]).encode()))
    time.sleep(1.0)
    texts, saw_close = drain(sock)
    over_cap_reached = upstream_saw("sub-5")
    check("subscription cap holds after prototype-key CLOSEs",
          not over_cap_reached,
          f"6th subscription reached upstream={over_cap_reached}, close={saw_close}")
    sock.close()


def main():
    start_upstream()
    wait_for_shield()
    probe_type_allowlist()
    probe_sub_cap()
    if failures:
        print(f"\n{len(failures)} CONFIRMED VULNERABLE: {failures}")
        sys.exit(1)
    print("\nno prototype-key issues observed")


if __name__ == "__main__":
    main()
