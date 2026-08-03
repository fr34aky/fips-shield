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

// map is Object.create(null) throughout: it is indexed by a client
// address, and on a plain object an inherited name like "constructor"
// answers with a function, which the isNaN() fail-closed check in
// isBanned() would then read as a ban.
var banCache = { path: '', mtime: 0, size: -1, map: Object.create(null) };

// Set by loadBans() when the banlist cannot be read at all. Reported by
// access(), which has the session object needed to log.
var banLoadFailed = false;

function portOf(s) {
    try {
        return s.variables.server_port;
    } catch (e) {
        return '?';
    }
}

// Log a configuration warning at most once per shared-dict entry
// lifetime (SHIELD_CONNRATE_TIMEOUT, default 5 min).
//
// A module-level "already warned" flag does NOT work here: njs gives
// each connection its own VM, so module state resets between
// connections and the warning would be written once per connection —
// into a log the fail2ban sidecar shares. The shared dict is the only
// state that outlives a connection, and add() succeeding exactly once
// per key lifetime is the gate. Re-warning every few minutes is also
// better than truly once: a misconfiguration keeps reminding you.
function warnPeriodically(s, key, msg) {
    var dict = ngx.shared.shield_connrate;
    if (!dict) {
        return;
    }
    var first = false;
    try {
        first = dict.add(key, 1);
    } catch (e) {
        // Key exists (some njs versions throw rather than return false).
        return;
    }
    if (first) {
        s.warn(msg);
    }
}

function num(v, dflt) {
    var n = parseFloat(v);
    return isNaN(n) ? dflt : n;
}

function keyset(v, dflt) {
    var raw = (v === undefined || v === '') ? dflt : v;
    // Object.create(null), not {}: these sets are indexed by
    // client-supplied strings, and a plain object would answer
    // truthily for inherited names like "constructor" or "toString",
    // admitting message types and kinds that were never configured.
    var out = Object.create(null);
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
        banLoadFailed = true;
        banCache.path = path;
        banCache.mtime = 0;
        banCache.size = -1;
        banCache.map = Object.create(null);
        return banCache.map;
    }
    banLoadFailed = false;
    var mtime = st.mtimeMs !== undefined ? st.mtimeMs : Number(st.mtime);
    if (banCache.path === path && banCache.mtime === mtime &&
        banCache.size === st.size) {
        return banCache.map;
    }
    var map = Object.create(null);
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
    if (until === undefined) {
        return false;
    }
    // A corrupt expiry must not read as "not banned": parseInt yields
    // NaN, and every comparison against NaN is false, so the old code
    // silently unbanned anyone whose line got mangled. Fail closed.
    if (isNaN(until)) {
        return true;
    }
    // 0 is a permanent ban (fail2ban's bantime = -1, written as 0 by
    // the backend). Otherwise expiry is honoured here too, so a stale
    // file cannot extend a ban past its "until".
    return until === 0 || until * 1000 > Date.now();
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

// Per-profile policy, read from a single js_var named after the
// listening port.
//
// nginx variables are global by name: two profiles each declaring
// `js_var $shield_conn_rate` share ONE value, and whichever file nginx
// parsed last wins for every server. That silently disabled the other
// profiles' limits. A port suffix makes the name unique by
// construction, since two servers cannot listen on the same port
// anyway.
//
// Format: semicolon-separated key=value pairs. Values may contain
// commas (message-type lists) but never semicolons.
function policy(s) {
    var out = {};
    var raw = '';
    try {
        raw = s.variables['shield_cfg_' + s.variables.server_port] || '';
    } catch (e) {
        // No policy declared for this listener: everything falls back
        // to the defaults below, which are the safe values.
        return out;
    }
    var parts = raw.split(';');
    for (var i = 0; i < parts.length; i++) {
        var eq = parts[i].indexOf('=');
        if (eq > 0) {
            out[parts[i].slice(0, eq).trim()] = parts[i].slice(eq + 1);
        }
    }
    return out;
}

function accessCfg(s) {
    var p = policy(s);
    return {
        service: p.service || 'unknown',
        banFile: p.ban_file || '',
        connRate: num(p.conn_rate, 0),
        connWindow: num(p.conn_window, 60)
    };
}

// js_access hook, shared by every profile. Verdict rule "banned" is
// deliberately excluded from the detection filters: enforcement must
// not feed back into detection.
function access(s) {
    var cfg = accessCfg(s);
    try {
        // The session log reads this; it comes from the policy rather
        // than a per-server js_var so it cannot leak between profiles.
        s.variables.shield_service = cfg.service;
    } catch (e) {
        // js_var not declared in this build of the config.
    }
    // An empty ban_file disables ban enforcement entirely — at accept
    // and, for profiles with a filter, mid-session too. That is a
    // survivable state (the rate and concurrency limits still apply),
    // so it must not refuse traffic; but it used to be completely
    // silent, which is how a deployment can look healthy while
    // enforcing nothing. Warn once per worker instead.
    if (!cfg.banFile) {
        warnPeriodically(s, '__shield_warn_nobanfile:' + portOf(s),
                         'shield-config no ban_file for port ' + portOf(s) +
                         ': BAN ENFORCEMENT IS DISABLED on this listener ' +
                         '(is SHIELD_BAN_FILE set?)');
    } else {
        var banned = isBanned(s.remoteAddress, cfg.banFile);
        // Report a banlist that cannot be read for the same reason: the
        // engine falls back to "nobody is banned" and would otherwise
        // do it without a word. Checked after isBanned(), which is what
        // sets the flag.
        if (banLoadFailed) {
            warnPeriodically(s, '__shield_warn_banload:' + portOf(s),
                             'shield-config banlist ' + cfg.banFile +
                             ' is missing or unreadable: ban enforcement ' +
                             'is inactive');
        }
        if (banned) {
            verdict(s, cfg.service, 'ban', 'banned', 'rejected-at-accept');
            s.deny();
            return;
        }
    }
    if (connRateExceeded(s, cfg)) {
        verdict(s, cfg.service, 'access', 'conn-rate', 'max=' + cfg.connRate);
        s.deny();
        return;
    }
    s.allow();
}

export default { access, isBanned, verdict, num, keyset, policy };
