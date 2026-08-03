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
const ST_PARSE_FAILED: u32 = 4;

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
    /// Detach the classifier. Active bans are kept (the maps stay
    /// pinned) unless --purge is given.
    Unload {
        #[arg(long, env = "SHIELD_GUARD_IFACE", default_value = DEFAULT_IFACE)]
        iface: String,
        /// Also remove the pinned maps, discarding every active ban.
        #[arg(long)]
        purge: bool,
    },
    /// Ban a source for <seconds> (0 or negative = until unbanned).
    Ban { ip: String, seconds: i64 },
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

fn cmd_unload(pin_dir: &Path, iface: &str, purge: bool) -> Result<()> {
    let detached = match tc::qdisc_detach_program(iface, TcAttachType::Ingress, PROG_NAME) {
        Ok(()) => {
            println!("detached from {iface}");
            true
        }
        Err(e) => {
            eprintln!("warning: detach from {iface}: {e}");
            false
        }
    };
    if !purge {
        // Default: keep the maps pinned so a restart (systemd restarts
        // this unit whenever fips.service restarts) re-attaches with
        // every active ban intact.
        println!(
            "maps left pinned at {} (use --purge to discard bans)",
            pin_dir.display()
        );
        return Ok(());
    }
    if !detached {
        // Unpinning a still-attached program orphans it: it keeps
        // dropping traffic with no way left to manage its maps.
        bail!("refusing to purge maps: the program is still attached to {iface}");
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

/// Delete every entry whose ban has lapsed, returning how many went.
///
/// The BPF side only *checks* expiry, it never deletes — a lapsed entry
/// simply stops matching. Nothing else reclaims them, and shield_bans is
/// a fixed-size HASH rather than an LRU, so without this the map fills
/// with corpses until `bpf_map_update_elem` starts returning E2BIG and
/// no new node can be banned at all, host-wide, while `stats` still
/// reports drops and everything looks healthy. A mesh identity is a
/// keypair, so accumulating enough of them is cheap for an attacker.
fn prune_expired(bans: &mut BpfHashMap<MapData, Addr6, BanVal>) -> Result<usize> {
    let now = now_mono_ns();
    let mut expired: Vec<Addr6> = Vec::new();
    for entry in bans.iter() {
        let (key, val) = entry?;
        // 0 is permanent and never lapses.
        if val.expires_mono_ns != 0 && val.expires_mono_ns <= now {
            expired.push(key);
        }
    }
    let n = expired.len();
    for key in expired {
        let _ = bans.remove(&key);
    }
    Ok(n)
}

fn cmd_ban(pin_dir: &Path, ip: &str, seconds: i64) -> Result<()> {
    let Some(addr) = parse_v6(ip)? else {
        eprintln!("note: {ip} is IPv4; the mesh is IPv6-only, nothing to do");
        return Ok(());
    };
    let mut bans = bans_map(pin_dir)?;
    // fail2ban renders a permanent ban as -1, and 0 is this CLI's own
    // encoding for the same thing; both must mean "until unbanned"
    // rather than being rejected as a bad argument, which would leave
    // the peer unbanned while fail2ban logged a success.
    let val = if seconds <= 0 {
        BanVal {
            expires_mono_ns: 0,
            expires_epoch_s: 0,
        }
    } else {
        let secs = seconds as u64;
        BanVal {
            expires_mono_ns: now_mono_ns().saturating_add(secs.saturating_mul(1_000_000_000)),
            expires_epoch_s: now_epoch_s().saturating_add(secs),
        }
    };
    let key = Addr6 { b: addr.octets() };
    // A full map is the one failure that must not be terminal: fail2ban
    // logs the error and does not retry, so a single E2BIG would end
    // banning entirely until someone noticed. Reclaim the lapsed
    // entries nothing else reclaims, then try once more. Retrying on
    // any error rather than matching an errno keeps this robust to how
    // the failure is reported.
    if let Err(first) = bans.insert(key, val, 0) {
        let reclaimed = prune_expired(&mut bans)
            .context("ban failed and the expired-entry sweep also failed")?;
        bans.insert(key, val, 0).with_context(|| {
            format!(
                "cannot insert ban (first attempt: {first}); swept {reclaimed} \
                 expired entries and still could not insert — the ban map may \
                 be full of active bans"
            )
        })?;
        eprintln!("note: ban map was full; swept {reclaimed} expired entries");
    }
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
    prune_expired(&mut bans)?;
    let now = now_mono_ns();
    let mut active: Vec<(Ipv6Addr, u64)> = Vec::new();

    for entry in bans.iter() {
        let (key, val) = entry?;
        if val.expires_mono_ns == 0 || val.expires_mono_ns > now {
            active.push((Ipv6Addr::from(key.b), val.expires_epoch_s));
        }
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
    println!("parse failed       {}", sum(ST_PARSE_FAILED)?);

    let cfg = config_map(pin_dir)?.get(&0, 0)?;
    if cfg.rate_pps > 0 {
        println!(
            "throttle           {} pkt/s per source, burst {}",
            cfg.rate_pps, cfg.burst_pkts
        );
    } else {
        println!("throttle           disabled");
    }
    // Occupancy, not just a count: shield_bans is a fixed-size HASH, so
    // a map filling up is the difference between "banning works" and
    // "no new node can be banned at all", and it was previously
    // invisible until the first failure.
    // Capacity comes from the map itself rather than a constant
    // duplicated from shield_guard.bpf.c, which would silently drift.
    let md = open_map(pin_dir, "shield_bans")?;
    let capacity = md.info().map(|i| i.max_entries()).unwrap_or(0);
    let mut bans: BpfHashMap<MapData, Addr6, BanVal> = BpfHashMap::try_from(Map::HashMap(md))?;
    let total = bans.iter().count();
    let stale = prune_expired(&mut bans)?;
    println!(
        "bans               {}/{} active ({} expired reclaimed)",
        total.saturating_sub(stale),
        capacity,
        stale
    );
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
        Cmd::Unload { iface, purge } => cmd_unload(pin_dir, iface, *purge),
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
