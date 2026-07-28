//! fips-shield guard: eBPF enforcement backend.
//!
//! Loads a tc clsact ingress classifier on the mesh interface and
//! manages the ban and throttle maps it reads. Implements the same
//! `ban | unban | check | list` CLI as the Phase 3 banlist backend
//! (docs/verdict-schema.md), so fail2ban can drive either one.
//!
//! There is no daemon: the maps are pinned to bpffs, and the tc filter
//! holds the program, so both survive the CLI process exiting. Ban
//! expiry is enforced in-kernel against the monotonic clock, so a
//! lapsed ban stops dropping even if nothing prunes the map.

use std::{
    net::{IpAddr, Ipv6Addr},
    path::{Path, PathBuf},
    process::ExitCode,
};

use anyhow::{anyhow, bail, Context, Result};
use aya::{
    maps::{Array, HashMap as BpfHashMap, Map, MapData, PerCpuArray},
    programs::{
        tc::{self, NlOptions, TcAttachOptions},
        SchedClassifier, TcAttachType,
    },
    EbpfLoader,
};
use clap::{Parser, Subcommand};

const BPF_OBJ: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/shield_guard.bpf.o"));

const PROG_NAME: &str = "shield_guard";
const DEFAULT_PIN_DIR: &str = "/sys/fs/bpf/fips-shield";
const DEFAULT_IFACE: &str = "fips0";

// Stats slots — keep in sync with ST_* in bpf/shield_guard.bpf.c.
const ST_PASSED: u32 = 0;
const ST_DROPPED_BAN: u32 = 1;
const ST_DROPPED_THROTTLE: u32 = 2;
const ST_NOT_IPV6: u32 = 3;

#[repr(C)]
#[derive(Clone, Copy)]
struct Addr6 {
    b: [u8; 16],
}
unsafe impl aya::Pod for Addr6 {}

#[repr(C)]
#[derive(Clone, Copy)]
struct BanVal {
    expires_mono_ns: u64,
    expires_epoch_s: u64,
}
unsafe impl aya::Pod for BanVal {}

#[repr(C)]
#[derive(Clone, Copy)]
struct Config {
    rate_pps: u64,
    burst_pkts: u64,
}
unsafe impl aya::Pod for Config {}

#[derive(Parser)]
#[command(
    name = "fips-guard",
    about = "eBPF enforcement backend for fips-shield (per-node drop/throttle on the mesh interface)"
)]
struct Cli {
    /// bpffs directory holding the pinned maps.
    #[arg(long, env = "SHIELD_GUARD_PIN_DIR", default_value = DEFAULT_PIN_DIR, global = true)]
    pin_dir: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Load and attach the classifier (idempotent; reuses pinned maps).
    Load {
        #[arg(long, env = "SHIELD_GUARD_IFACE", default_value = DEFAULT_IFACE)]
        iface: String,
        /// Per-source packet rate; 0 disables throttling.
        #[arg(long, env = "SHIELD_GUARD_RATE_PPS", default_value_t = 0)]
        rate: u64,
        /// Per-source burst in packets.
        #[arg(long, env = "SHIELD_GUARD_BURST_PKTS", default_value_t = 0)]
        burst: u64,
    },
    /// Detach the classifier and remove the pinned maps.
    Unload {
        #[arg(long, env = "SHIELD_GUARD_IFACE", default_value = DEFAULT_IFACE)]
        iface: String,
    },
    /// Ban a source for <seconds> (0 = until unbanned).
    Ban { ip: String, seconds: u64 },
    /// Remove a ban.
    Unban { ip: String },
    /// Exit 0 (and print the expiry) if banned, 1 if not.
    Check { ip: String },
    /// Print active bans as "<ip> <until-epoch-seconds>".
    List,
    /// Change the throttle at runtime.
    Throttle { rate: u64, burst: u64 },
    /// Packet counters and current configuration.
    Stats,
}

fn now_mono_ns() -> u64 {
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // CLOCK_MONOTONIC is the clock bpf_ktime_get_ns() reads.
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

fn now_epoch_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parses the address the way nginx and fail2ban print it. IPv4 is
/// accepted and reported as a no-op rather than an error: the mesh is
/// IPv6-only, and failing here would break the fail2ban action.
fn parse_v6(s: &str) -> Result<Option<Ipv6Addr>> {
    match s.parse::<IpAddr>() {
        Ok(IpAddr::V6(a)) => Ok(Some(a)),
        Ok(IpAddr::V4(_)) => Ok(None),
        Err(e) => bail!("invalid address {s}: {e}"),
    }
}

fn open_map(pin_dir: &Path, name: &str) -> Result<MapData> {
    let path = pin_dir.join(name);
    MapData::from_pin(&path).with_context(|| {
        format!(
            "cannot open pinned map {} (is the guard loaded? run: fips-guard load)",
            path.display()
        )
    })
}

fn bans_map(pin_dir: &Path) -> Result<BpfHashMap<MapData, Addr6, BanVal>> {
    Ok(BpfHashMap::try_from(Map::HashMap(open_map(
        pin_dir,
        "shield_bans",
    )?))?)
}

fn config_map(pin_dir: &Path) -> Result<Array<MapData, Config>> {
    Ok(Array::try_from(Map::Array(open_map(
        pin_dir,
        "shield_config",
    )?))?)
}

fn cmd_load(pin_dir: &Path, iface: &str, rate: u64, burst: u64) -> Result<()> {
    std::fs::create_dir_all(pin_dir)
        .with_context(|| format!("cannot create pin dir {} (is bpffs mounted at /sys/fs/bpf? mount -t bpf bpf /sys/fs/bpf)", pin_dir.display()))?;

    // The maps declare LIBBPF_PIN_BY_NAME, so they are pinned here and
    // an existing pin is reused: a reload keeps the active bans.
    let mut ebpf = EbpfLoader::new()
        .default_map_pin_directory(pin_dir)
        .load(BPF_OBJ)
        .context("failed to load BPF object")?;

    let prog: &mut SchedClassifier = ebpf
        .program_mut(PROG_NAME)
        .ok_or_else(|| anyhow!("program {PROG_NAME} missing from object"))?
        .try_into()?;
    prog.load().context("BPF verifier rejected the program")?;

    // Idempotent: adding clsact when it exists is not an error worth
    // failing on, and detaching a stale copy keeps reloads clean.
    let _ = tc::qdisc_add_clsact(iface);
    let _ = tc::qdisc_detach_program(iface, TcAttachType::Ingress, PROG_NAME);

    // Netlink (classic tc filter), not TCX: on kernel >= 6.6 aya would
    // default to TCX, whose bpf_link dies with this process — the
    // filter would vanish the moment the CLI exits. A netlink filter is
    // owned by the qdisc and outlives us, which is what a
    // fire-and-forget CLI needs (and it works on older kernels too).
    let link_id = prog
        .attach_with_options(
            iface,
            TcAttachType::Ingress,
            TcAttachOptions::Netlink(NlOptions::default()),
        )
        .with_context(|| format!("cannot attach to {iface} (does the interface exist?)"))?;

    // Dropping aya's link guard would detach the filter; leak it so the
    // attachment survives process exit.
    let link = prog.take_link(link_id)?;
    std::mem::forget(link);

    set_config(pin_dir, rate, burst)?;

    println!("loaded on {iface}, maps pinned at {}", pin_dir.display());
    if rate > 0 {
        println!("throttle: {rate} pkt/s per source, burst {burst}");
    } else {
        println!("throttle: disabled (bans only)");
    }
    Ok(())
}

fn cmd_unload(pin_dir: &Path, iface: &str) -> Result<()> {
    match tc::qdisc_detach_program(iface, TcAttachType::Ingress, PROG_NAME) {
        Ok(()) => println!("detached from {iface}"),
        Err(e) => eprintln!("warning: detach from {iface}: {e}"),
    }
    for name in [
        "shield_bans",
        "shield_throttle",
        "shield_config",
        "shield_stats",
    ] {
        let path = pin_dir.join(name);
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("cannot unpin {}", path.display()))?;
        }
    }
    let _ = std::fs::remove_dir(pin_dir);
    println!("unpinned maps");
    Ok(())
}

fn set_config(pin_dir: &Path, rate: u64, burst: u64) -> Result<()> {
    let mut cfg = config_map(pin_dir)?;
    cfg.set(
        0,
        Config {
            rate_pps: rate,
            // A rate with no burst would drop every packet; give it one
            // packet of headroom rather than silently blackholing.
            burst_pkts: if rate > 0 && burst == 0 { 1 } else { burst },
        },
        0,
    )?;
    Ok(())
}

fn cmd_ban(pin_dir: &Path, ip: &str, seconds: u64) -> Result<()> {
    let Some(addr) = parse_v6(ip)? else {
        eprintln!("note: {ip} is IPv4; the mesh is IPv6-only, nothing to do");
        return Ok(());
    };
    let mut bans = bans_map(pin_dir)?;
    let val = if seconds == 0 {
        BanVal {
            expires_mono_ns: 0,
            expires_epoch_s: 0,
        }
    } else {
        BanVal {
            expires_mono_ns: now_mono_ns() + seconds.saturating_mul(1_000_000_000),
            expires_epoch_s: now_epoch_s() + seconds,
        }
    };
    bans.insert(Addr6 { b: addr.octets() }, val, 0)
        .context("cannot insert ban")?;
    println!("banned {ip} until {}", val.expires_epoch_s);
    Ok(())
}

fn cmd_unban(pin_dir: &Path, ip: &str) -> Result<()> {
    let Some(addr) = parse_v6(ip)? else {
        eprintln!("note: {ip} is IPv4; the mesh is IPv6-only, nothing to do");
        return Ok(());
    };
    let mut bans = bans_map(pin_dir)?;
    // Unbanning something that is not banned is not an error.
    let _ = bans.remove(&Addr6 { b: addr.octets() });
    println!("unbanned {ip}");
    Ok(())
}

fn cmd_check(pin_dir: &Path, ip: &str) -> Result<bool> {
    let Some(addr) = parse_v6(ip)? else {
        println!("not banned {ip}");
        return Ok(false);
    };
    let mut bans = bans_map(pin_dir)?;
    let key = Addr6 { b: addr.octets() };
    match bans.get(&key, 0) {
        Ok(v) if v.expires_mono_ns == 0 || v.expires_mono_ns > now_mono_ns() => {
            println!("banned {ip} until {}", v.expires_epoch_s);
            Ok(true)
        }
        Ok(_) => {
            // Expired: the kernel already stopped dropping it; drop the
            // stale entry while we are here.
            let _ = bans.remove(&key);
            println!("not banned {ip}");
            Ok(false)
        }
        Err(_) => {
            println!("not banned {ip}");
            Ok(false)
        }
    }
}

fn cmd_list(pin_dir: &Path) -> Result<()> {
    let mut bans = bans_map(pin_dir)?;
    let now = now_mono_ns();
    let mut expired: Vec<Addr6> = Vec::new();
    let mut active: Vec<(Ipv6Addr, u64)> = Vec::new();

    for entry in bans.iter() {
        let (key, val) = entry?;
        if val.expires_mono_ns == 0 || val.expires_mono_ns > now {
            active.push((Ipv6Addr::from(key.b), val.expires_epoch_s));
        } else {
            expired.push(key);
        }
    }
    for key in expired {
        let _ = bans.remove(&key);
    }
    for (ip, until) in active {
        // Permanent bans print 0, matching "no expiry".
        println!("{ip} {until}");
    }
    Ok(())
}

fn cmd_stats(pin_dir: &Path) -> Result<()> {
    let stats: PerCpuArray<MapData, u64> =
        PerCpuArray::try_from(Map::PerCpuArray(open_map(pin_dir, "shield_stats")?))?;
    let sum = |slot: u32| -> Result<u64> { Ok(stats.get(&slot, 0)?.iter().sum()) };

    println!("passed             {}", sum(ST_PASSED)?);
    println!("dropped (ban)      {}", sum(ST_DROPPED_BAN)?);
    println!("dropped (throttle) {}", sum(ST_DROPPED_THROTTLE)?);
    println!("not ipv6           {}", sum(ST_NOT_IPV6)?);

    let cfg = config_map(pin_dir)?.get(&0, 0)?;
    if cfg.rate_pps > 0 {
        println!(
            "throttle           {} pkt/s per source, burst {}",
            cfg.rate_pps, cfg.burst_pkts
        );
    } else {
        println!("throttle           disabled");
    }
    let bans = bans_map(pin_dir)?;
    println!("bans               {}", bans.iter().count());
    Ok(())
}

fn main() -> ExitCode {
    // Rust ignores SIGPIPE, which turns `fips-guard list | head` into a
    // panic. Restore the default so piping into grep/head just ends.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };

    let cli = Cli::parse();
    let pin_dir = cli.pin_dir.as_path();

    let result = match &cli.cmd {
        Cmd::Load { iface, rate, burst } => cmd_load(pin_dir, iface, *rate, *burst),
        Cmd::Unload { iface } => cmd_unload(pin_dir, iface),
        Cmd::Ban { ip, seconds } => cmd_ban(pin_dir, ip, *seconds),
        Cmd::Unban { ip } => cmd_unban(pin_dir, ip),
        Cmd::Check { ip } => match cmd_check(pin_dir, ip) {
            // check reports "banned?" through the exit code.
            Ok(true) => return ExitCode::SUCCESS,
            Ok(false) => return ExitCode::FAILURE,
            Err(e) => Err(e),
        },
        Cmd::List => cmd_list(pin_dir),
        Cmd::Throttle { rate, burst } => set_config(pin_dir, *rate, *burst).map(|()| {
            if *rate > 0 {
                println!("throttle: {rate} pkt/s per source, burst {burst}");
            } else {
                println!("throttle: disabled");
            }
        }),
        Cmd::Stats => cmd_stats(pin_dir),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
