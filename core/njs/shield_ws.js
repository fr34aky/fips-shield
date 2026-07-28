// fips-shield WebSocket inspection engine (njs, stream module).
//
// Runs as js_filter on the fips0-facing stream server, in front of the
// http proxy stage. Client->server bytes are parsed as WebSocket frames
// (RFC 6455) and the Nostr messages inside are checked against
// per-connection policy before being forwarded — a rejected message is
// never seen by the upstream. Server->client traffic passes untouched.
//
// Sessions that are not WebSocket (no "Upgrade: websocket" in the
// client handshake, e.g. NIP-11 fetches) pass through unmodified; the
// http stage forces "Connection: close" on those, so a client cannot
// smuggle a later upgrade past the sniffer on a kept-alive connection.
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
// Ban enforcement (Phase 3): the detection engine maintains a banlist
// file ("<ip> <until-epoch-seconds>" per line, atomically replaced —
// see docs/verdict-schema.md). The access hook rejects banned sources
// at connection accept; established sessions re-check every
// shield_ban_recheck seconds and are cut with the usual Close
// choreography. The file is re-read only when its mtime/size changes.

import fs from 'fs';

var OP_CONT = 0x0;
var OP_TEXT = 0x1;
var OP_BIN = 0x2;
var OP_CLOSE = 0x8;

var MAX_HANDSHAKE = 16384;
var DEFAULT_TYPES = 'EVENT,REQ,CLOSE,COUNT,AUTH,NEG-OPEN,NEG-MSG,NEG-CLOSE';

function num(v, dflt) {
    var n = parseFloat(v);
    return isNaN(n) ? dflt : n;
}

function keyset(v, dflt) {
    var raw = (v === undefined || v === '') ? dflt : v;
    var out = {};
    if (raw === '') {
        return out;
    }
    var parts = raw.split(',');
    for (var i = 0; i < parts.length; i++) {
        var p = parts[i].trim();
        if (p !== '') {
            out[p] = true;
        }
    }
    return out;
}

var banCache = { path: '', mtime: 0, size: -1, map: {} };

function loadBans(path) {
    var st;
    try {
        st = fs.statSync(path);
    } catch (e) {
        banCache.path = path;
        banCache.mtime = 0;
        banCache.size = -1;
        banCache.map = {};
        return banCache.map;
    }
    var mtime = st.mtimeMs !== undefined ? st.mtimeMs : Number(st.mtime);
    if (banCache.path === path && banCache.mtime === mtime &&
        banCache.size === st.size) {
        return banCache.map;
    }
    var map = {};
    try {
        var lines = fs.readFileSync(path, 'utf8').split('\n');
        for (var i = 0; i < lines.length; i++) {
            var parts = lines[i].trim().split(/\s+/);
            if (parts.length >= 2 && parts[0] !== '') {
                map[parts[0]] = parseInt(parts[1], 10);
            }
        }
    } catch (e) {
        // Unreadable mid-swap; keep the previous view until next check.
        return banCache.map;
    }
    banCache.path = path;
    banCache.mtime = mtime;
    banCache.size = st.size;
    banCache.map = map;
    return map;
}

function isBanned(ip, path) {
    if (!path) {
        return false;
    }
    var until = loadBans(path)[ip];
    return until !== undefined && until * 1000 > Date.now();
}

function readCfg(s) {
    var v = s.variables;
    return {
        service: v.shield_service || 'unknown',
        banFile: v.shield_ban_file || '',
        banRecheck: num(v.shield_ban_recheck, 10),
        maxMsg: num(v.shield_ws_max_msg, 131072),
        maxSubs: num(v.shield_ws_max_subs, 20),
        maxFilters: num(v.shield_ws_max_filters, 10),
        maxFilterItems: num(v.shield_ws_max_filter_items, 500),
        bMsg: bucket(num(v.shield_ws_msg_rate, 20), num(v.shield_ws_msg_burst, 100)),
        bEvent: bucket(num(v.shield_ws_event_rate, 5), num(v.shield_ws_event_burst, 50)),
        bReq: bucket(num(v.shield_ws_req_rate, 5), num(v.shield_ws_req_burst, 20)),
        types: keyset(v.shield_nostr_types, DEFAULT_TYPES),
        kindDeny: keyset(v.shield_nostr_kind_deny, '')
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
    var verdict = {
        ts: new Date().toISOString(),
        src: s.remoteAddress,
        service: cfg.service,
        layer: 'ws',
        rule: rule,
        detail: detail === undefined ? '' : String(detail)
    };
    // "shield-verdict" is the grep anchor for the Phase 3 detection
    // engine; keep the prefix and the JSON shape stable.
    s.warn('shield-verdict ' + JSON.stringify(verdict));
    try {
        s.variables.shield_verdict = rule;
    } catch (e) {
        // js_var not declared; the error log line above still carries it.
    }
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
            st.subCount--;
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
        if (control) {
            // Close/ping/pong forward as-is once no data message is
            // partially held in front of them.
            if (!st.inMsg) {
                flush(s, st);
            }
        } else {
            st.msgParts.push(payload);
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
            if (isBanned(s.remoteAddress, cfg.banFile)) {
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
            var idx = st.hs.indexOf('\r\n\r\n');
            if (idx < 0) {
                s.send(data);
                st.hsForwarded += data.length;
            } else {
                var end = idx + 4;
                var head = st.hs.slice(0, end).toString();
                // Forward the remainder of the headers; anything after
                // them in this chunk is frame data and goes through
                // inspection first.
                s.send(st.hs.slice(st.hsForwarded, end));
                if (/\r\nupgrade:[ \t]*websocket/i.test(head)) {
                    st.mode = 'ws';
                    st.acc = Buffer.from(st.hs.slice(end));
                    st.hs = Buffer.from('');
                    pump(s, cfg, st);
                } else {
                    // Not a WebSocket. Pass through; the http stage
                    // closes the connection after one response.
                    st.mode = 'plain';
                    s.send(st.hs.slice(end));
                    st.hs = Buffer.from('');
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
        hsForwarded: 0,
        acc: Buffer.from(''),
        pending: [],
        msgParts: [],
        msgLen: 0,
        inMsg: false,
        subs: {},
        subCount: 0,
        banCheckAt: Date.now() + cfg.banRecheck * 1000,
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
}

// js_access hook: reject banned sources at connection accept, before
// any proxying. Verdict rule "banned" is deliberately excluded from
// the detection engine's filters — enforcement must not feed back into
// detection.
function access(s) {
    var path = s.variables.shield_ban_file;
    if (path && isBanned(s.remoteAddress, path)) {
        s.warn('shield-verdict ' + JSON.stringify({
            ts: new Date().toISOString(),
            src: s.remoteAddress,
            service: s.variables.shield_service || 'unknown',
            layer: 'ban',
            rule: 'banned',
            detail: 'rejected-at-accept'
        }));
        s.deny();
        return;
    }
    s.allow();
}

export default { filter, access };
