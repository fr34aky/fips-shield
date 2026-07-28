// fips-shield core engine (njs, stream module) — service-agnostic.
//
// Everything here applies to any TCP service behind the shield:
//
//   * ban enforcement — the detection engine (Phase 3) maintains a
//     banlist file ("<ip> <until-epoch-seconds>" per line, atomically
//     replaced; see docs/verdict-schema.md). Banned sources are
//     rejected at connection accept, and profile filters re-check
//     established sessions. The file is re-read only when its
//     mtime/size changes.
//   * connection-rate limiting — a fixed window per source, counted in
//     a shared dict so all workers see one number. nginx's stream
//     module has limit_conn (concurrency) but no limit_req, so this
//     fills the gap for non-HTTP services.
//   * verdict logging — the single structured line format every
//     detection module emits.
//
// Protocol-aware inspection lives in profile modules (e.g.
// shield_ws.js), which import this one.

import fs from 'fs';

var banCache = { path: '', mtime: 0, size: -1, map: {} };

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
    // Expiry is honoured here too, so a stale file cannot extend a ban.
    return until !== undefined && until * 1000 > Date.now();
}

// "shield-verdict" is the grep anchor for the detection engine; keep
// the prefix and the JSON field order stable (docs/verdict-schema.md).
function verdict(s, service, layer, rule, detail) {
    s.warn('shield-verdict ' + JSON.stringify({
        ts: new Date().toISOString(),
        src: s.remoteAddress,
        service: service || 'unknown',
        layer: layer,
        rule: rule,
        detail: detail === undefined ? '' : String(detail)
    }));
    try {
        s.variables.shield_verdict = rule;
    } catch (e) {
        // js_var not declared in this server; the log line still carries it.
    }
}

// Fixed-window connection counter. Windows are cheap and predictable;
// a source that opens more than `rate` connections per window is
// refused for the remainder of it.
function connRateExceeded(s, cfg) {
    if (!cfg.connRate) {
        return false;
    }
    var dict = ngx.shared.shield_connrate;
    if (!dict) {
        return false;
    }
    var window = Math.floor(Date.now() / 1000 / cfg.connWindow);
    var n = dict.incr(s.remoteAddress + ':' + window, 1, 0);
    return n > cfg.connRate;
}

function accessCfg(s) {
    var v = s.variables;
    return {
        service: v.shield_service || 'unknown',
        banFile: v.shield_ban_file || '',
        connRate: num(v.shield_conn_rate, 0),
        connWindow: num(v.shield_conn_window, 60)
    };
}

// js_access hook, shared by every profile. Verdict rule "banned" is
// deliberately excluded from the detection filters: enforcement must
// not feed back into detection.
function access(s) {
    var cfg = accessCfg(s);
    if (cfg.banFile && isBanned(s.remoteAddress, cfg.banFile)) {
        verdict(s, cfg.service, 'ban', 'banned', 'rejected-at-accept');
        s.deny();
        return;
    }
    if (connRateExceeded(s, cfg)) {
        verdict(s, cfg.service, 'access', 'conn-rate', 'max=' + cfg.connRate);
        s.deny();
        return;
    }
    s.allow();
}

export default { access, isBanned, verdict, num, keyset };
