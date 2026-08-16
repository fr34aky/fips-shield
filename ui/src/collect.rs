//! Reading state. Everything here is read-only by construction: the
//! only commands invoked are the query verbs of tools that already
//! exist, and the only files opened are logs, opened for reading.
//!
//! Nothing in this module writes, bans, unbans, or reloads. Adding a
//! verb that does belongs behind an authenticated, privileged path
//! (Phase C), not here.

use crate::json::{self, Obj};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Run a command and return stdout, or a reason it did not work.
///
/// The reason matters. A missing tool is an ordinary state here — the
/// eBPF guard is optional, and on a container deployment the host may
/// have no shield-config at all — but "unavailable" on its own sends
/// the reader hunting. The three causes need three different fixes:
///
///   not installed        -> install it, or point --shield-config at it
///   installed, exits 1   -> its own stderr says why (no shield.env,
///                           no permission to open the pinned maps)
///   installed, no perms  -> the unit is too locked down for this tool
///
/// So the message is carried to the page rather than collapsed into a
/// boolean.
fn run(bin: &str, args: &[&str]) -> Result<String, String> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .map_err(|e| format!("{bin}: {e}"))?;
    if out.status.success() {
        return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
    }
    let err = String::from_utf8_lossy(&out.stderr);
    let first = err.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    if first.is_empty() {
        Err(format!("{bin} exited {}", out.status))
    } else {
        Err(format!("{bin}: {first}"))
    }
}

pub struct Config {
    /// SOURCE, KEY, VALUE as produced by `shield-config show --porcelain`.
    pub entries: Vec<(String, String, String)>,
}

impl Config {
    pub fn load(shield_config: &Path, env_file: Option<&Path>) -> Result<Config, String> {
        let bin = shield_config
            .to_str()
            .ok_or_else(|| "shield-config path is not valid UTF-8".to_string())?;
        let out = match env_file.and_then(|p| p.to_str()) {
            Some(f) => run(bin, &["show", "--porcelain", "-f", f]),
            None => run(bin, &["show", "--porcelain"]),
        }?;
        let entries = out
            .lines()
            .filter_map(|l| {
                // SOURCE<TAB>KEY<TAB>VALUE — split on the first two only,
                // so a value containing a tab survives intact.
                let mut it = l.splitn(3, '\t');
                Some((
                    it.next()?.to_string(),
                    it.next()?.to_string(),
                    it.next().unwrap_or("").to_string(),
                ))
            })
            .collect();
        Ok(Config { entries })
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(_, k, _)| k == key)
            .map(|(_, _, v)| v.as_str())
    }

    pub fn source(&self, key: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(_, k, _)| k == key)
            .map(|(s, _, _)| s.as_str())
    }

    /// The enabled profiles, in configured order.
    pub fn profiles(&self) -> Vec<String> {
        self.get("SHIELD_PROFILES")
            .unwrap_or("strfry")
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    }
}

/// One protected service. One profile = one service.
pub struct Service {
    pub profile: String,
    /// The name used in log filenames; `strfry` has no *_SERVICE key.
    pub log_name: String,
    pub listen_port: String,
    pub upstream: String,
    pub preset: String,
    pub limits: Vec<(String, String, String)>,
}

/// Per-profile key naming. strfry predates the `SHIELD_<PROFILE>_`
/// convention and uses unprefixed names, so the mapping is explicit
/// rather than derived — deriving it would silently produce empty
/// fields for strfry.
fn keys_for(profile: &str) -> (&'static str, &'static str, &'static str, &'static str) {
    match profile {
        "strfry" => (
            "",
            "SHIELD_LISTEN_PORT",
            "SHIELD_UPSTREAM",
            "SHIELD_STRFRY_CONN_RATE",
        ),
        "http" => (
            "SHIELD_HTTP_SERVICE",
            "SHIELD_HTTP_LISTEN_PORT",
            "SHIELD_HTTP_UPSTREAM",
            "SHIELD_HTTP_CONN_RATE",
        ),
        "tcp" => (
            "SHIELD_TCP_SERVICE",
            "SHIELD_TCP_LISTEN_PORT",
            "SHIELD_TCP_UPSTREAM",
            "SHIELD_TCP_CONN_RATE",
        ),
        _ => ("", "", "", ""),
    }
}

pub fn services(cfg: &Config) -> Vec<Service> {
    cfg.profiles()
        .into_iter()
        .map(|profile| {
            let (svc_key, port_key, up_key, rate_key) = keys_for(&profile);
            let log_name = if svc_key.is_empty() {
                profile.clone()
            } else {
                cfg.get(svc_key).unwrap_or(&profile).to_string()
            };
            let preset = cfg
                .source(rate_key)
                .and_then(|s| s.strip_prefix("preset:"))
                .and_then(|s| s.split('/').nth(1))
                .unwrap_or("custom")
                .to_string();
            // Whatever this profile's preset defines, minus the plumbing
            // that is not a limit. Shown so the dashboard answers "what
            // is this service enforcing" without a second tool.
            let limits = cfg
                .entries
                .iter()
                .filter(|(_, k, _)| {
                    (k.contains("RATE")
                        || k.contains("MAX")
                        || k.contains("TIMEOUT")
                        || k.contains("BURST"))
                        && relevant_to(k, &profile)
                })
                .map(|(s, k, v)| (k.clone(), v.clone(), s.clone()))
                .collect();
            Service {
                profile: profile.clone(),
                log_name,
                listen_port: cfg.get(port_key).unwrap_or("").to_string(),
                upstream: cfg.get(up_key).unwrap_or("").to_string(),
                preset,
                limits,
            }
        })
        .collect()
}

fn relevant_to(key: &str, profile: &str) -> bool {
    match profile {
        "http" => key.starts_with("SHIELD_HTTP_"),
        "tcp" => key.starts_with("SHIELD_TCP_"),
        "strfry" => {
            key.starts_with("SHIELD_WS_")
                || key.starts_with("SHIELD_STRFRY_")
                || key == "SHIELD_MAX_CONNS_PER_NODE"
                || key.starts_with("SHIELD_HANDSHAKE_")
        }
        _ => false,
    }
}

pub struct Ban {
    pub addr: String,
    /// Unix seconds; 0 means permanent.
    pub until: u64,
}

pub fn bans(shield_ban: &Path) -> Result<Vec<Ban>, String> {
    let bin = shield_ban
        .to_str()
        .ok_or_else(|| "shield-ban path is not valid UTF-8".to_string())?;
    let out = run(bin, &["list"])?;
    Ok(out
        .lines()
        .filter_map(|l| {
            let mut f = l.split_whitespace();
            let addr = f.next()?.to_string();
            let until = f.next()?.parse().ok()?;
            Some(Ban { addr, until })
        })
        .collect())
}

pub fn guard_stats(fips_guard: &Path) -> Result<Vec<(String, String)>, String> {
    let bin = fips_guard
        .to_str()
        .ok_or_else(|| "fips-guard path is not valid UTF-8".to_string())?;
    let out = run(bin, &["stats"])?;
    Ok(out
        .lines()
        .filter_map(|l| {
            let l = l.trim_end();
            // "label            value" — the label may contain
            // spaces, so split on the run of spaces before the
            // value rather than on the first space.
            let idx = l.find("  ")?;
            let (label, value) = l.split_at(idx);
            Some((label.trim().to_string(), value.trim().to_string()))
        })
        .collect())
}

/// Read the last `n` lines of a file without loading all of it.
///
/// Log files grow without bound between rotations, so this seeks to the
/// end and walks back in chunks. A dashboard asking for 100 lines must
/// not read a gigabyte to find them.
pub fn tail(path: &Path, n: usize, max_bytes: u64) -> std::io::Result<Vec<String>> {
    let mut f = std::fs::File::open(path)?;
    let len = f.seek(SeekFrom::End(0))?;
    let want = max_bytes.min(len);
    f.seek(SeekFrom::End(-(want as i64)))?;
    let mut buf = vec![0u8; want as usize];
    f.read_exact(&mut buf)?;

    let text = String::from_utf8_lossy(&buf);
    let mut lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    // The first line is probably a fragment, since the window starts
    // mid-file. Drop it unless the window covers the whole file.
    if want < len && !lines.is_empty() {
        lines.remove(0);
    }
    let start = lines.len().saturating_sub(n);
    Ok(lines.split_off(start))
}

pub fn log_path(log_dir: &Path, name: &str, kind: &str) -> PathBuf {
    log_dir.join(format!("shield-{name}.{kind}.log"))
}

// ---------------------------------------------------------------- JSON

pub fn service_json(s: &Service) -> String {
    let limits = json::arr(s.limits.iter().map(|(k, v, src)| {
        let mut o = Obj::new();
        o.str("key", k).str("value", v).str("source", src);
        o.done()
    }));
    let mut o = Obj::new();
    o.str("profile", &s.profile)
        .str("name", &s.log_name)
        .str("port", &s.listen_port)
        .str("upstream", &s.upstream)
        .str("preset", &s.preset)
        .raw("limits", &limits);
    o.done()
}

pub fn ban_json(b: &Ban, now: u64) -> String {
    let mut o = Obj::new();
    o.str("addr", &b.addr).num("until", b.until);
    o.bool("permanent", b.until == 0);
    o.num("remaining", b.until.saturating_sub(now));
    o.done()
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn cfg(pairs: &[(&str, &str, &str)]) -> Config {
        Config {
            entries: pairs
                .iter()
                .map(|(s, k, v)| (s.to_string(), k.to_string(), v.to_string()))
                .collect(),
        }
    }

    #[test]
    fn profiles_split_and_trim() {
        let c = cfg(&[("custom", "SHIELD_PROFILES", "strfry, http ,tcp")]);
        assert_eq!(c.profiles(), vec!["strfry", "http", "tcp"]);
        // Absent means the documented default, not an empty dashboard.
        assert_eq!(cfg(&[]).profiles(), vec!["strfry"]);
        // A trailing comma must not produce a phantom service.
        let c = cfg(&[("custom", "SHIELD_PROFILES", "tcp,")]);
        assert_eq!(c.profiles(), vec!["tcp"]);
    }

    #[test]
    fn strfry_uses_unprefixed_keys() {
        // The regression this guards: deriving key names from the
        // profile would look for SHIELD_STRFRY_LISTEN_PORT, find
        // nothing, and render an empty port.
        let c = cfg(&[
            ("custom", "SHIELD_PROFILES", "strfry"),
            ("preset:strfry/strict", "SHIELD_LISTEN_PORT", "80"),
            ("preset:strfry/strict", "SHIELD_UPSTREAM", "127.0.0.1:7777"),
            ("preset:strfry/strict", "SHIELD_STRFRY_CONN_RATE", "30"),
        ]);
        let s = &services(&c)[0];
        assert_eq!(s.listen_port, "80");
        assert_eq!(s.upstream, "127.0.0.1:7777");
        assert_eq!(s.log_name, "strfry");
        assert_eq!(s.preset, "strict");
    }

    #[test]
    fn service_name_comes_from_the_service_key() {
        let c = cfg(&[
            ("custom", "SHIELD_PROFILES", "tcp"),
            ("custom", "SHIELD_TCP_SERVICE", "ssh"),
            ("preset:tcp/loose", "SHIELD_TCP_CONN_RATE", "30"),
        ]);
        let s = &services(&c)[0];
        assert_eq!(s.log_name, "ssh");
        assert_eq!(s.preset, "loose");
    }

    #[test]
    fn a_custom_rate_reports_as_custom_not_a_preset_name() {
        let c = cfg(&[
            ("custom", "SHIELD_PROFILES", "tcp"),
            ("custom", "SHIELD_TCP_CONN_RATE", "7"),
        ]);
        assert_eq!(services(&c)[0].preset, "custom");
    }

    #[test]
    fn limits_do_not_leak_between_profiles() {
        let c = cfg(&[
            ("custom", "SHIELD_PROFILES", "tcp"),
            ("preset:tcp/default", "SHIELD_TCP_CONN_RATE", "10"),
            ("preset:http/default", "SHIELD_HTTP_CONN_RATE", "120"),
        ]);
        let s = &services(&c)[0];
        assert!(s.limits.iter().any(|(k, _, _)| k == "SHIELD_TCP_CONN_RATE"));
        assert!(!s
            .limits
            .iter()
            .any(|(k, _, _)| k.starts_with("SHIELD_HTTP_")));
    }

    #[test]
    fn tail_returns_the_last_lines_and_drops_a_partial_first() {
        let dir = std::env::temp_dir().join(format!("shield-ui-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("t.log");
        let mut f = std::fs::File::create(&p).unwrap();
        for i in 0..500 {
            writeln!(f, "line-{i}").unwrap();
        }
        drop(f);

        let got = tail(&p, 3, 1 << 20).unwrap();
        assert_eq!(got, vec!["line-497", "line-498", "line-499"]);

        // A window that starts mid-file must not yield a fragment.
        let got = tail(&p, 1000, 40).unwrap();
        assert!(got.iter().all(|l| l.starts_with("line-")));
        assert!(got.len() < 500);

        // Asking for more than exists is not an error.
        assert_eq!(tail(&p, 10_000, 1 << 20).unwrap().len(), 500);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn guard_stats_labels_may_contain_spaces() {
        // "dropped (ban)      12" must not split at the first space.
        let line = "dropped (ban)      12";
        let idx = line.find("  ").unwrap();
        let (l, v) = line.split_at(idx);
        assert_eq!(l.trim(), "dropped (ban)");
        assert_eq!(v.trim(), "12");
    }
}
