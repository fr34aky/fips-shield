//! fips-shield read-only status dashboard.
//!
//! Answers "what is this node protecting, what is it enforcing, and who
//! is banned" without an ssh session and four tools. It is strictly
//! read-only: it runs the query verbs of tools that already exist and
//! reads log files. There is no ban, unban, config write, or reload
//! path here, and adding one belongs behind an authenticated privileged
//! helper rather than in this process.
//!
//! It binds loopback by default and refuses a routable address without
//! --insecure-bind. This is a control-plane view of a security tool: it
//! lists banned node identities and serves log contents, so on a mesh
//! where every peer is authenticated but not necessarily trusted, it is
//! the highest-value thing on the box. Reach it over an ssh tunnel:
//!
//!     ssh -N -L 8088:127.0.0.1:8088 <node>

mod collect;
mod http;
mod json;

use anyhow::{bail, Context, Result};
use clap::Parser;
use std::net::{IpAddr, SocketAddr, TcpListener};
use std::path::PathBuf;

const PAGE: &str = include_str!("page.html");

/// Cap on a single tail response, so a huge log cannot be turned into a
/// huge allocation by asking for it.
const MAX_TAIL_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TAIL_LINES: usize = 1000;

#[derive(Parser)]
#[command(
    name = "shield-ui",
    about = "Read-only status dashboard for fips-shield"
)]
struct Args {
    /// Address to bind. Must be a loopback address unless
    /// --insecure-bind is also given.
    #[arg(long, env = "SHIELD_UI_BIND", default_value = "127.0.0.1:8088")]
    bind: String,

    /// Permit binding a non-loopback address. Read the warning in
    /// docs/admin-ui.md first: this page has no authentication.
    #[arg(long, env = "SHIELD_UI_INSECURE_BIND")]
    insecure_bind: bool,

    /// shield.env to read. Defaults to whatever shield-config finds.
    #[arg(long, env = "SHIELD_UI_ENV_FILE")]
    env_file: Option<PathBuf>,

    #[arg(long, env = "SHIELD_UI_LOG_DIR", default_value = "/var/log/nginx")]
    log_dir: PathBuf,

    #[arg(
        long,
        env = "SHIELD_UI_CONFIG_BIN",
        default_value = "/usr/local/bin/shield-config"
    )]
    shield_config: PathBuf,

    #[arg(
        long,
        env = "SHIELD_UI_BAN_BIN",
        default_value = "/usr/local/bin/shield-ban"
    )]
    shield_ban: PathBuf,

    #[arg(
        long,
        env = "SHIELD_UI_GUARD_BIN",
        default_value = "/usr/local/bin/fips-guard"
    )]
    fips_guard: PathBuf,
}

struct State {
    args: Args,
}

impl State {
    fn config(&self) -> Result<collect::Config, String> {
        collect::Config::load(&self.args.shield_config, self.args.env_file.as_deref())
    }

    /// Service names that may be used to build a log path.
    ///
    /// Every log lookup is validated against this list. The name is
    /// interpolated into a filename, so accepting an arbitrary one would
    /// make `?service=../../etc/passwd` a file-read primitive — the
    /// whitelist is what makes that impossible rather than merely
    /// awkward.
    fn known_services(&self) -> Vec<String> {
        self.config()
            .map(|c| {
                collect::services(&c)
                    .into_iter()
                    .map(|s| s.log_name)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Where the reader should look when a tool did not run. Resolved
    /// from the actual flags, so it names the path in force rather than
    /// the default.
    fn hint(&self, what: &str) -> String {
        match what {
            "config" => format!(
                "shield-ui runs `{} show --porcelain`. Install it with `sudo make install` \
                 (host mode), or point --shield-config at it. In container mode it lives \
                 inside the image, so the host needs its own copy plus presets/. If it is \
                 installed, it may simply not have found a shield.env — pass --env-file.",
                self.args.shield_config.display()
            ),
            "bans" => format!(
                "shield-ui runs `{} list`. Install it with `sudo make install` or \
                 `sudo make install-guard`. With the eBPF backend it execs fips-guard, \
                 which needs CAP_BPF to open the pinned maps — a unit with an empty \
                 CapabilityBoundingSet cannot, even as root.",
                self.args.shield_ban.display()
            ),
            _ => format!(
                "shield-ui runs `{} stats`. This is optional: without the eBPF guard, \
                 bans are enforced by the banlist file. If you do run it, note that \
                 reading the pinned maps needs CAP_BPF.",
                self.args.fips_guard.display()
            ),
        }
    }
}

fn handle(st: &State, req: &http::Request) -> http::Response {
    match req.path.as_str() {
        "/" | "/index.html" => http::Response::html(PAGE.to_string()),
        "/api/status" => api_status(st),
        "/api/bans" => api_bans(st),
        "/api/logs" => api_logs(st, req),
        _ => http::Response::error(404, "no such endpoint"),
    }
}

fn api_status(st: &State) -> http::Response {
    let mut o = json::Obj::new();

    match st.config() {
        Ok(cfg) => {
            let svcs = collect::services(&cfg);
            o.raw(
                "services",
                &json::arr(svcs.iter().map(collect::service_json)),
            );
            o.str("bind_addr", cfg.get("SHIELD_BIND_ADDR").unwrap_or(""));
            o.str("preset", cfg.get("SHIELD_PRESET").unwrap_or("default"));
            o.bool("config_ok", true);
        }
        Err(e) => {
            // Rendered as a banner rather than an empty dashboard: an
            // unreadable config looks identical to "nothing configured"
            // otherwise, and those need different actions. The command's
            // own error is carried through, because "could not be run"
            // alone does not distinguish "not installed" from "installed
            // but found no shield.env".
            o.raw("services", "[]");
            o.bool("config_ok", false);
            o.str("config_error", &e);
            o.str("config_hint", &st.hint("config"));
        }
    }

    match collect::bans(&st.args.shield_ban) {
        Ok(bans) => {
            let now = collect::now();
            o.num("ban_count", bans.len() as u64);
            o.bool("bans_ok", true);
            let mut recent: Vec<_> = bans.iter().collect();
            recent.sort_by_key(|b| if b.until == 0 { u64::MAX } else { b.until });
            recent.reverse();
            o.raw(
                "bans",
                &json::arr(recent.iter().take(20).map(|b| collect::ban_json(b, now))),
            );
        }
        Err(e) => {
            o.bool("bans_ok", false);
            o.num("ban_count", 0);
            o.raw("bans", "[]");
            o.str("bans_error", &e);
            o.str("bans_hint", &st.hint("bans"));
        }
    }

    match collect::guard_stats(&st.args.fips_guard) {
        Ok(stats) => {
            o.bool("guard_ok", true);
            o.raw(
                "guard",
                &json::arr(stats.iter().map(|(k, v)| {
                    let mut g = json::Obj::new();
                    g.str("label", k).str("value", v);
                    g.done()
                })),
            );
        }
        Err(e) => {
            // Absent is normal: the eBPF backend is optional. But
            // "installed and failing" is not, and the two read
            // identically without the message.
            o.bool("guard_ok", false);
            o.raw("guard", "[]");
            o.bool("guard_installed", st.args.fips_guard.exists());
            o.str("guard_error", &e);
            o.str("guard_hint", &st.hint("guard"));
        }
    }

    o.num("now", collect::now());
    http::Response::json(o.done())
}

fn api_bans(st: &State) -> http::Response {
    let now = collect::now();
    match collect::bans(&st.args.shield_ban) {
        Ok(bans) => {
            let mut o = json::Obj::new();
            o.num("count", bans.len() as u64).raw(
                "bans",
                &json::arr(bans.iter().map(|b| collect::ban_json(b, now))),
            );
            http::Response::json(o.done())
        }
        Err(e) => http::Response::error(500, &e),
    }
}

fn api_logs(st: &State, req: &http::Request) -> http::Response {
    let Some(service) = req.param("service") else {
        return http::Response::error(400, "service is required");
    };
    let kind = req.param("kind").unwrap_or("stream");
    if !matches!(kind, "access" | "stream") {
        return http::Response::error(400, "kind must be access or stream");
    }
    // Whitelist, not sanitisation: the name goes into a filename.
    if !st.known_services().iter().any(|s| s == service) {
        return http::Response::error(404, "unknown service");
    }
    let n = req
        .param("n")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(100)
        .clamp(1, MAX_TAIL_LINES);

    let path = collect::log_path(&st.args.log_dir, service, kind);
    match collect::tail(&path, n, MAX_TAIL_BYTES) {
        Ok(lines) => {
            let mut o = json::Obj::new();
            o.str("service", service)
                .str("kind", kind)
                .raw("lines", &json::str_arr(lines.iter().map(|s| s.as_str())));
            http::Response::json(o.done())
        }
        // A log that does not exist yet is an ordinary state on a fresh
        // node, not a server error.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let mut o = json::Obj::new();
            o.str("service", service)
                .str("kind", kind)
                .raw("lines", "[]");
            http::Response::json(o.done())
        }
        Err(_) => http::Response::error(500, "log could not be read"),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let addr: SocketAddr = args
        .bind
        .parse()
        .with_context(|| format!("not a valid address: {}", args.bind))?;

    let loopback = match addr.ip() {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => v6.is_loopback(),
    };
    if !loopback && !args.insecure_bind {
        bail!(
            "refusing to bind {} — it is not a loopback address and this page has no \
             authentication. It lists banned node identities and serves log contents, so \
             exposing it on the mesh hands an attacker the shield's own view.\n\n\
             Reach it over an ssh tunnel instead:\n    \
             ssh -N -L {}:127.0.0.1:{} <node>\n\n\
             If you have put real authentication in front of it, pass --insecure-bind.",
            addr,
            addr.port(),
            addr.port()
        );
    }

    let listener = TcpListener::bind(addr).with_context(|| format!("cannot bind {addr}"))?;
    eprintln!("shield-ui: read-only dashboard on http://{addr}");
    if !loopback {
        eprintln!("shield-ui: WARNING - bound a routable address with no authentication");
    }

    let st = State { args };
    http::serve(listener, move |req| handle(&st, req));
}
