// fips-shield WebSocket inspection engine (njs, stream module).
//
// Runs as js_filter on the fips0-facing stream server, in front of the
// http proxy stage. Client->server bytes are parsed as WebSocket frames
// (RFC 6455) and the Nostr messages inside are checked against
// per-connection policy before being forwarded — a rejected message is
// never seen by the upstream. Server->client traffic is forwarded
// as-is; it is only examined to confirm the session was classified
// correctly (see the downstream backstop in filter()).
//
// Sessions that are not WebSocket (no "Upgrade: websocket" in the
// client handshake, e.g. NIP-11 fetches) pass through unmodified; the
// http stage forces "Connection: close" on those, so a client cannot
// smuggle a later upgrade past the sniffer on a kept-alive connection.
// The handshake is buffered whole and rejected if it uses bare-LF line
// endings, so this sniffer and nginx's parser cannot disagree about
// where the headers end or whether an upgrade was requested.
//
// The http stage strips Sec-WebSocket-Extensions from the handshake,
// so frames are never permessage-deflate compressed and the payloads
// parsed here are the payloads the relay would see.
//
// njs has no way to hard-terminate a session from a filter callback
// (s.done() is access/preread-only and exceptions do not abort), so a
// violation instead: drops all held data, sends the client a NOTICE
// plus a Close frame, sends the upstream a Close frame (a compliant
// relay closes the TCP connection, tearing the session down), and
// swallows everything afterwards. If the upstream ignores the Close,
// proxy_timeout reaps the now-silent session.
//
// Policy knobs arrive via js_var (see the profile's .stream template);
// unset knobs fall back to the defaults below.
//
// Ban enforcement, connection-rate limiting and verdict logging are
// service-agnostic and live in shield_core.js, which every profile
// shares; this module adds the protocol-aware layer plus the
// mid-session ban re-check (established sessions are cut with the
// usual Close choreography rather than left running).

import core from 'shield_core.js';

var num = core.num;
var keyset = core.keyset;

var OP_CONT = 0x0;
var OP_TEXT = 0x1;
var OP_BIN = 0x2;
var OP_CLOSE = 0x8;

var MAX_HANDSHAKE = 16384;
var DEFAULT_TYPES = 'EVENT,REQ,CLOSE,COUNT,AUTH,NEG-OPEN,NEG-MSG,NEG-CLOSE';

// Frames held awaiting inspection, and fragments per message. The
// message-size cap alone does not bound these: zero-length frames and
// control frames carry no payload, so a client could otherwise pin a
// fragmented message open and pile up buffers indefinitely. Both
// limits are far above anything a real client produces.
var MAX_PENDING_FRAMES = 256;
var MAX_FRAGMENTS = 64;

// All knobs come from the port-keyed policy string (see
// core/njs/shield_core.js): per-server js_var values are global by
// name in nginx and would leak between profiles.
function readCfg(s) {
    var p = core.policy(s);
    return {
        service: p.service || 'unknown',
        banFile: p.ban_file || '',
        banRecheck: num(p.ban_recheck, 10),
        maxMsg: num(p.ws_max_msg, 131072),
        maxSubs: num(p.ws_max_subs, 20),
        maxFilters: num(p.ws_max_filters, 10),
        maxFilterItems: num(p.ws_max_filter_items, 500),
        bMsg: bucket(num(p.ws_msg_rate, 20), num(p.ws_msg_burst, 100)),
        bEvent: bucket(num(p.ws_event_rate, 5), num(p.ws_event_burst, 50)),
        bReq: bucket(num(p.ws_req_rate, 5), num(p.ws_req_burst, 20)),
        types: keyset(p.nostr_types, DEFAULT_TYPES),
        kindDeny: keyset(p.nostr_kind_deny, '')
    };
}

function bucket(rate, burst) {
    return { rate: rate, burst: burst, tokens: burst, t: Date.now() };
}

function takeToken(b) {
    var now = Date.now();
    b.tokens = Math.min(b.burst, b.tokens + ((now - b.t) / 1000) * b.rate);
    b.t = now;
    if (b.tokens < 1) {
        return false;
    }
    b.tokens -= 1;
    return true;
}

// Index just past the blank line that ends an HTTP header block, or -1
// if it has not arrived yet. Both CRLF and bare-LF terminators are
// recognised — not to accept them, but so a bare-LF request is
// detected here instead of being forwarded uninspected while this
// sniffer waits forever for a CRLF pair that never comes.
function headerBlockEnd(buf) {
    for (var i = 0; i + 1 < buf.length; i++) {
        if (buf[i] !== 0x0a) {
            continue;
        }
        if (buf[i + 1] === 0x0a) {
            return i + 2;
        }
        if (buf[i + 1] === 0x0d && i + 2 < buf.length && buf[i + 2] === 0x0a) {
            return i + 3;
        }
    }
    return -1;
}

// True if the first `upto` bytes contain an LF not preceded by CR.
function hasBareLf(buf, upto) {
    for (var i = 0; i < upto; i++) {
        if (buf[i] === 0x0a && (i === 0 || buf[i - 1] !== 0x0d)) {
            return true;
        }
    }
    return false;
}

// Frame encoder for the injected NOTICE/Close frames. Client->server
// frames must be masked; an all-zero masking key is protocol-legal and
// leaves the payload bytes unchanged.
function wsFrame(op, payload, masked) {
    var len = payload.length;
    var head;
    if (len < 126) {
        head = Buffer.from([0x80 | op, len]);
    } else if (len < 65536) {
        head = Buffer.from([0x80 | op, 126, (len >> 8) & 0xff, len & 0xff]);
    } else {
        // Injected frames are always small; no 64-bit length support.
        throw new Error('frame too large to encode');
    }
    if (masked) {
        head[1] |= 0x80;
        return Buffer.concat([head, Buffer.from([0, 0, 0, 0]), payload]);
    }
    return Buffer.concat([head, payload]);
}

function closeFrame(code, reason, masked) {
    var r = Buffer.from(reason);
    var p = Buffer.concat([Buffer.from([(code >> 8) & 0xff, code & 0xff]), r]);
    return wsFrame(OP_CLOSE, p, masked);
}

function violate(s, cfg, st, rule, detail) {
    if (st.killed) {
        return;
    }
    st.killed = true;
    st.pending = [];
    st.msgParts = [];
    core.verdict(s, cfg.service, 'ws', rule, detail);
    var notice = JSON.stringify(['NOTICE', 'fips-shield: connection closed: ' + rule]);
    s.sendDownstream(wsFrame(OP_TEXT, Buffer.from(notice), false));
    s.sendDownstream(closeFrame(1008, rule, false));
    // Upstream close goes via s.send (violations only fire inside the
    // 'upstream' callback): sendUpstream() is a separate chain and can
    // overtake data frames already queued with s.send in this callback,
    // making the upstream drop approved messages still in flight.
    s.send(closeFrame(1008, rule, true), { flush: true });
}

function flush(s, st) {
    for (var i = 0; i < st.pending.length; i++) {
        var last = i === st.pending.length - 1;
        s.send(st.pending[i], last ? { flush: true } : undefined);
    }
    st.pending = [];
}

function inspect(s, cfg, st, buf) {
    if (!takeToken(cfg.bMsg)) {
        return violate(s, cfg, st, 'msg-rate');
    }
    var msg;
    try {
        msg = JSON.parse(buf.toString());
    } catch (e) {
        return violate(s, cfg, st, 'malformed', 'bad-json');
    }
    if (!Array.isArray(msg) || msg.length < 1 || typeof msg[0] !== 'string') {
        return violate(s, cfg, st, 'malformed', 'not-a-nostr-message');
    }
    var t = msg[0];
    if (!cfg.types[t]) {
        return violate(s, cfg, st, 'type-not-allowed', t);
    }
    if (t === 'EVENT') {
        if (!takeToken(cfg.bEvent)) {
            return violate(s, cfg, st, 'event-rate');
        }
        var ev = msg[1];
        if (typeof ev !== 'object' || ev === null || Array.isArray(ev) ||
            typeof ev.kind !== 'number') {
            return violate(s, cfg, st, 'malformed', 'bad-event');
        }
        if (cfg.kindDeny[String(ev.kind)]) {
            return violate(s, cfg, st, 'kind-denied', 'kind=' + ev.kind);
        }
    } else if (t === 'REQ' || t === 'COUNT') {
        if (!takeToken(cfg.bReq)) {
            return violate(s, cfg, st, 'req-rate');
        }
        var sid = msg[1];
        if (typeof sid !== 'string' || sid.length < 1 || sid.length > 64) {
            return violate(s, cfg, st, 'malformed', 'bad-subscription-id');
        }
        var nFilters = msg.length - 2;
        if (nFilters > cfg.maxFilters) {
            return violate(s, cfg, st, 'filter-complexity', 'filters=' + nFilters);
        }
        var items = 0;
        for (var i = 2; i < msg.length; i++) {
            var f = msg[i];
            if (typeof f !== 'object' || f === null || Array.isArray(f)) {
                return violate(s, cfg, st, 'malformed', 'bad-filter');
            }
            var ks = Object.keys(f);
            items += ks.length;
            for (var k = 0; k < ks.length; k++) {
                if (Array.isArray(f[ks[k]])) {
                    items += f[ks[k]].length;
                }
            }
        }
        if (items > cfg.maxFilterItems) {
            return violate(s, cfg, st, 'filter-complexity', 'items=' + items);
        }
        if (t === 'REQ' && !(sid in st.subs)) {
            if (st.subCount >= cfg.maxSubs) {
                return violate(s, cfg, st, 'too-many-subs', 'max=' + cfg.maxSubs);
            }
            st.subs[sid] = true;
            st.subCount++;
        }
    } else if (t === 'CLOSE') {
        if (typeof msg[1] === 'string' && msg[1] in st.subs) {
            delete st.subs[msg[1]];
            if (st.subCount > 0) {
                st.subCount--;
            }
        }
    }
    // AUTH and NEG-* pass under the overall message-rate bucket.
}

// Parse as many complete frames out of st.acc as available. Data
// frames are held in st.pending until the message they belong to
// passes inspection; control frames queue in-order behind them.
function pump(s, cfg, st) {
    while (!st.killed) {
        var acc = st.acc;
        if (acc.length < 2) {
            return;
        }
        var b0 = acc[0];
        var b1 = acc[1];
        var fin = (b0 & 0x80) !== 0;
        var op = b0 & 0x0f;
        if ((b0 & 0x70) !== 0) {
            return violate(s, cfg, st, 'protocol', 'rsv-bits-set');
        }
        if ((b1 & 0x80) === 0) {
            return violate(s, cfg, st, 'protocol', 'unmasked-client-frame');
        }
        var len = b1 & 0x7f;
        var off = 2;
        if (len === 126) {
            if (acc.length < 4) {
                return;
            }
            len = acc.readUInt16BE(2);
            off = 4;
        } else if (len === 127) {
            if (acc.length < 10) {
                return;
            }
            if (acc.readUInt32BE(2) !== 0) {
                return violate(s, cfg, st, 'oversized-message', '64bit-length');
            }
            len = acc.readUInt32BE(6);
            off = 10;
        }
        var control = op >= 0x8;
        if (control) {
            if (!fin || len > 125) {
                return violate(s, cfg, st, 'protocol', 'bad-control-frame');
            }
        } else {
            if (op === OP_BIN) {
                return violate(s, cfg, st, 'binary-frame');
            }
            if (op !== OP_TEXT && op !== OP_CONT) {
                return violate(s, cfg, st, 'protocol', 'opcode=' + op);
            }
            if (op === OP_TEXT && st.inMsg) {
                return violate(s, cfg, st, 'protocol', 'text-before-fin');
            }
            if (op === OP_CONT && !st.inMsg) {
                return violate(s, cfg, st, 'protocol', 'unexpected-continuation');
            }
            if (st.msgLen + len > cfg.maxMsg) {
                return violate(s, cfg, st, 'oversized-message', 'max=' + cfg.maxMsg);
            }
        }
        var end = off + 4 + len;
        if (acc.length < end) {
            return;
        }
        var raw = acc.slice(0, end);
        var key = acc.slice(off, off + 4);
        var payload = Buffer.from(acc.slice(off + 4, end));
        for (var i = 0; i < payload.length; i++) {
            payload[i] ^= key[i & 3];
        }
        st.acc = acc.slice(end);
        st.pending.push(raw);
        if (st.pending.length > MAX_PENDING_FRAMES) {
            return violate(s, cfg, st, 'frame-flood',
                           'pending=' + st.pending.length);
        }
        if (control) {
            // Close/ping/pong forward as-is once no data message is
            // partially held in front of them.
            if (!st.inMsg) {
                flush(s, st);
            }
        } else {
            st.msgParts.push(payload);
            if (st.msgParts.length > MAX_FRAGMENTS) {
                return violate(s, cfg, st, 'frame-flood',
                               'fragments=' + st.msgParts.length);
            }
            st.msgLen += len;
            st.inMsg = !fin;
            if (fin) {
                var msgBuf = Buffer.concat(st.msgParts);
                st.msgParts = [];
                st.msgLen = 0;
                inspect(s, cfg, st, msgBuf);
                if (!st.killed) {
                    flush(s, st);
                }
            }
        }
    }
}

function onData(s, cfg, st, data, flags) {
    if (st.killed) {
        return;
    }
    // Mid-session ban check: a node banned while connected is cut on
    // its next activity after the recheck interval.
    if (st.mode !== 'plain' && cfg.banFile) {
        var now = Date.now();
        if (now >= st.banCheckAt) {
            st.banCheckAt = now + cfg.banRecheck * 1000;
            if (core.isBanned(s.remoteAddress, cfg.banFile)) {
                return violate(s, cfg, st, 'banned', 'session-cut');
            }
        }
    }
    if (st.mode === 'plain') {
        s.send(data, flags);
        return;
    }
    if (st.mode === 'handshake') {
        if (data.length > 0) {
            st.hs = Buffer.concat([st.hs, data]);
            if (st.hs.length > MAX_HANDSHAKE) {
                return violate(s, cfg, st, 'oversized-handshake');
            }
            // Nothing is forwarded until the whole header block has
            // been seen and validated: forwarding a partial handshake
            // would let the http stage act on bytes this sniffer has
            // not classified yet.
            var end = headerBlockEnd(st.hs);
            if (end < 0) {
                return;
            }
            // A bare LF is a hard failure rather than something to
            // parse around. nginx accepts LF as a line terminator, so
            // tolerating it here means this sniffer and the http stage
            // can disagree about where headers end and whether the
            // request is an upgrade — which is a complete inspection
            // bypass, not a cosmetic difference. Conforming clients
            // always send CRLF.
            if (hasBareLf(st.hs, end)) {
                return violate(s, cfg, st, 'protocol', 'bare-lf-in-handshake');
            }
            var head = st.hs.slice(0, end).toString();
            var rest = st.hs.slice(end);
            st.hs = Buffer.from('');
            s.send(Buffer.from(head));
            if (/\r\nupgrade:[ \t]*websocket/i.test(head)) {
                st.mode = 'ws';
                st.acc = Buffer.from(rest);
                pump(s, cfg, st);
            } else {
                // Not a WebSocket. Pass through; the http stage closes
                // the connection after one response, and the downstream
                // watcher below kills the session if the upstream
                // nonetheless answers 101.
                st.mode = 'plain';
                if (rest.length > 0) {
                    s.send(Buffer.from(rest));
                }
            }
        }
    } else if (data.length > 0) {
        st.acc = Buffer.concat([st.acc, data]);
        pump(s, cfg, st);
    }
    if (flags.last && !st.killed) {
        // A partially received (uninspected) message is dropped, not
        // forwarded. Propagate the EOF so the upstream side finishes.
        s.send('', { last: true });
    }
}

function filter(s) {
    var cfg = readCfg(s);
    var st = {
        mode: 'handshake',
        hs: Buffer.from(''),
        acc: Buffer.from(''),
        pending: [],
        msgParts: [],
        msgLen: 0,
        inMsg: false,
        // Object.create(null): a plain {} inherits keys like
        // "toString", so `sid in st.subs` would be true for a
        // subscription the client never opened.
        subs: Object.create(null),
        subCount: 0,
        banCheckAt: Date.now() + cfg.banRecheck * 1000,
        checkedResponse: false,
        killed: false
    };
    s.on('upstream', function (data, flags) {
        try {
            onData(s, cfg, st, data, flags);
        } catch (e) {
            // Fail closed: an engine bug must not become a bypass.
            violate(s, cfg, st, 'engine-error', String(e));
        }
    });
    // Backstop against this sniffer and nginx's HTTP parser ever
    // disagreeing again: a session classified as non-WebSocket must
    // never see a 101 response. If it does, an upgrade was negotiated
    // that nothing inspected, so kill it rather than tunnel it.
    s.on('downstream', function (data, flags) {
        try {
            if (st.mode === 'plain' && !st.checkedResponse && data.length > 0) {
                st.checkedResponse = true;
                if (/^HTTP\/1\.[01] 101/.test(data.slice(0, 16).toString())) {
                    return violate(s, cfg, st, 'protocol', 'unclassified-upgrade');
                }
            }
            s.send(data, flags);
        } catch (e) {
            violate(s, cfg, st, 'engine-error', String(e));
        }
    });
}

export default { filter };
