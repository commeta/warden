//! `wardenctl` — control and diagnostics for Warden.
//!
//! Daemon commands talk to `/run/warden/control.sock` (root only).
//! Offline commands (`doctor`, `psi`, `mem-top`, `scan`, `check-config`)
//! work without a running daemon.

mod profile;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;
use warden_core::ipc::{Request, Response};
use warden_core::units::human_bytes;
use warden_core::{DEFAULT_CONFIG, Severity};

#[derive(Debug, Parser)]
#[command(name = "wardenctl", version, about = "Control and diagnostics for the Warden host guardian")]
struct Cli {
    /// Control socket of the daemon.
    #[arg(long, global = true, default_value = "/run/warden/control.sock")]
    socket: PathBuf,
    /// Print raw JSON instead of tables.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Daemon status: levels, sensors, learning state.
    Status,
    /// Recent events.
    Events {
        #[arg(short = 'n', long, default_value_t = 30)]
        limit: usize,
        /// Minimum severity (info, notice, warning, critical, emergency).
        #[arg(short, long)]
        severity: Option<Severity>,
        /// Keep printing new events.
        #[arg(short, long)]
        follow: bool,
    },
    /// Memory culprit ranking as the daemon would choose victims.
    Top {
        #[arg(short = 'n', long, default_value_t = 15)]
        limit: usize,
    },
    /// Heuristic suspicion scores (processes, IPs).
    Scores,
    /// Reload configuration (same as SIGHUP).
    Reload,
    /// Switch dry-run at runtime: `on`/`off` is kept across reloads and
    /// restarts (until the configuration's own `dry_run` is changed);
    /// `reset` returns to the configuration.
    DryRun {
        #[arg(value_parser = ["on", "off", "reset"])]
        state: String,
    },
    /// Web file-integrity monitoring.
    #[command(subcommand)]
    Fim(FimCmd),
    /// Block an IP address in the Warden nftables set.
    Block {
        ip: String,
        /// e.g. 1h, 30m, 7d
        #[arg(long)]
        ttl: Option<String>,
    },
    /// Remove an IP address from the blocklist.
    Unblock { ip: String },
    /// Show blocked addresses.
    Blocklist,
    /// Quarantined files.
    #[command(subcommand)]
    Quarantine(QuarantineCmd),
    /// Capture a diagnostic snapshot now.
    Snapshot { reason: Option<String> },
    /// The daemon's own CPU, I/O and memory per thread and per module.
    Profile {
        /// Seconds between the two samples used for rates.
        #[arg(short, long, default_value_t = 5)]
        interval: u64,
    },
    /// Kernel tuning recommendations and sysctl changes Warden applied.
    Tuning {
        /// Restore every sysctl Warden changed to its original value.
        #[arg(long)]
        revert: bool,
    },
    /// Offline: check what this host supports (PSI, pidfd, fanotify, ...).
    Doctor {
        #[arg(short, long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
    /// Offline: current Pressure Stall Information.
    Psi,
    /// Offline: per-process memory, swap and major faults (who is thrashing).
    MemTop {
        #[arg(short = 'n', long, default_value_t = 20)]
        limit: usize,
        /// rss | swap | peak | majflt
        #[arg(short, long, default_value = "rss")]
        sort: String,
        /// Sample twice over this interval and show major faults per second.
        #[arg(short, long)]
        interval: Option<String>,
    },
    /// Offline: who is using the disk — bounded `du -x` (one filesystem,
    /// allocated blocks, hard links once) with the biggest directories per
    /// level and the largest files.
    Du {
        /// Directory to walk (usually a mount point).
        #[arg(default_value = "/")]
        path: PathBuf,
        /// Directory levels to aggregate (1–4).
        #[arg(short, long, default_value_t = 2)]
        depth: usize,
        /// Entries per list.
        #[arg(short = 'n', long, default_value_t = 15)]
        top: usize,
        /// Stop after this many directory entries.
        #[arg(long, default_value_t = 5_000_000)]
        max_entries: u64,
        /// Stop after this long (e.g. 30s, 5m).
        #[arg(long, default_value = "5m")]
        max_time: String,
        /// Run at idle I/O priority and nice 19.
        #[arg(long)]
        idle: bool,
    },
    /// Offline: scan files/directories with the webshell signatures.
    Scan {
        path: PathBuf,
        #[arg(long, default_value_t = 40)]
        min_score: u32,
        /// Extra signature rule files (globs).
        #[arg(long)]
        rules: Vec<String>,
    },
    /// ModSecurity logs.
    #[command(subcommand)]
    Waf(WafCmd),
    /// Offline: validate configuration.
    CheckConfig {
        #[arg(default_value = DEFAULT_CONFIG)]
        path: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum FimCmd {
    /// Sites, file counts, flagged files, schedule.
    Status,
    /// Run a full verification scan now.
    Scan { site: Option<String> },
    /// Accept current state into the baseline (whole site or one file).
    Accept { site: String, path: Option<String> },
    /// Auto-accept unflagged changes for a while (deployments).
    Pause { site: String, duration: String },
}

#[derive(Debug, Subcommand)]
enum WafCmd {
    /// Offline: the ModSecurity logs Apache, nginx and Angie are configured
    /// to write, per virtual host, as `[[waf.log]]` entries.
    Discover {
        /// Configuration whose `process.web_users` decide who counts as a
        /// web account (for the ownership check of each log).
        #[arg(short, long, default_value = DEFAULT_CONFIG)]
        config: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum QuarantineCmd {
    List,
    Restore { id: String },
}

fn call(socket: &PathBuf, req: &Request) -> Result<Value> {
    let mut s = UnixStream::connect(socket)
        .with_context(|| format!("cannot connect to {} (is wardend running? are you root?)", socket.display()))?;
    s.set_read_timeout(Some(Duration::from_secs(3700)))?;
    let mut line = serde_json::to_string(req)?;
    line.push('\n');
    s.write_all(line.as_bytes())?;
    let mut r = BufReader::new(s);
    let mut resp = String::new();
    r.read_line(&mut resp)?;
    let resp: Response = serde_json::from_str(&resp).context("malformed response")?;
    if !resp.ok {
        bail!("{}", resp.error.unwrap_or_else(|| "request failed".into()));
    }
    Ok(resp.data)
}

fn pretty(v: &Value) -> String {
    serde_json::to_string_pretty(v).unwrap_or_default()
}

fn sev_color(s: &str) -> &'static str {
    match s {
        "emergency" | "critical" => "\x1b[1;31m",
        "warning" => "\x1b[33m",
        "notice" => "\x1b[36m",
        _ => "\x1b[2m",
    }
}

fn print_events(v: &Value, color: bool) {
    for e in v.as_array().into_iter().flatten() {
        let sev = e["severity"].as_str().unwrap_or("");
        let ts = warden_core::event::format_ts_ms(e["ts_ms"].as_u64().unwrap_or(0));
        let (c, r) = if color { (sev_color(sev), "\x1b[0m") } else { ("", "") };
        let resolved = if e["resolved"].as_bool() == Some(true) { " ✓" } else { "" };
        println!(
            "{ts} {c}{:<9}{r} {:<34} {}{resolved}",
            sev,
            e["kind"].as_str().unwrap_or(""),
            e["title"].as_str().unwrap_or("")
        );
        if let Some(a) = e["actions"].as_array()
            && !a.is_empty()
        {
            let names: Vec<&str> = a.iter().filter_map(|x| x["do"].as_str()).collect();
            println!("{:>30} actions: {}", "", names.join(", "));
        }
    }
}

/// `path` is the root of its filesystem (its parent is on another device).
fn is_mount_point(path: &std::path::Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(md) = std::fs::metadata(path) else { return false };
    match std::fs::canonicalize(path).ok().and_then(|p| p.parent().map(std::path::Path::to_path_buf)) {
        None => true, // "/"
        Some(parent) => std::fs::metadata(parent).map(|p| p.dev() != md.dev()).unwrap_or(false),
    }
}

/// Human-readable `wardenctl du` output.
fn du_text(rep: &warden_sys::du::DuReport, fs_used: Option<u64>) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let _ = writeln!(
        o,
        "{}: {} in {} entries, {:.1}s{}",
        rep.root.display(),
        human_bytes(rep.total),
        rep.entries,
        rep.elapsed.as_secs_f64(),
        rep.partial.map(|p| format!(" — PARTIAL ({p})")).unwrap_or_default()
    );
    let pct = |b: u64| if rep.total > 0 { b as f64 * 100.0 / rep.total as f64 } else { 0.0 };
    for (i, level) in rep.levels.iter().enumerate() {
        if level.is_empty() {
            continue;
        }
        let _ = writeln!(o, "\nLevel {} directories:", i + 1);
        for e in level {
            let _ = writeln!(o, "  {:>10}  {:>5.1}%  {}", human_bytes(e.bytes), pct(e.bytes), e.path.display());
        }
    }
    if rep.root_files > 0 {
        let _ = writeln!(o, "\nFiles directly in {}: {}", rep.root.display(), human_bytes(rep.root_files));
    }
    if !rep.largest_files.is_empty() {
        let _ = writeln!(o, "\nLargest files:");
        for e in &rep.largest_files {
            let _ = writeln!(o, "  {:>10}  {}", human_bytes(e.bytes), e.path.display());
        }
    }
    if rep.errors > 0 {
        let _ = writeln!(o, "\n{} directories could not be read", rep.errors);
    }
    if let Some(used) = fs_used
        && rep.partial.is_none()
        && used > rep.total + (used / 10).max(1 << 30)
    {
        let _ = writeln!(
            o,
            "\nThe filesystem reports {} used, {} more than the walk found: files deleted but still open \
             (`wardenctl snapshot`, `lsof +L1`), data under a mount point, or snapshots.",
            human_bytes(used),
            human_bytes(used - rep.total)
        );
    }
    o
}

fn mem_top(limit: usize, sort: &str, interval: Option<Duration>) -> Result<()> {
    use warden_sys::process;
    if let Ok(p) = warden_sys::psi::read(warden_sys::psi::Resource::Memory) {
        let full = p.full.unwrap_or_default();
        println!(
            "memory PSI: some avg10={:.2} avg60={:.2} | full avg10={:.2} avg60={:.2}  (full = all tasks stalled)",
            p.some.avg10, p.some.avg60, full.avg10, full.avg60
        );
    }
    if let Ok(m) = warden_sys::mem::meminfo() {
        println!(
            "available {} of {} ({:.1}%), swap used {} of {}\n",
            human_bytes(m.available),
            human_bytes(m.total),
            m.available_percent(),
            human_bytes(m.swap_used()),
            human_bytes(m.swap_total)
        );
    }
    let first = process::snapshot();
    let (table, rates) = if let Some(iv) = interval {
        std::thread::sleep(iv);
        let second = process::snapshot();
        let rates: std::collections::HashMap<i32, f64> = second
            .values()
            .filter_map(|p| {
                let a = first.get(&p.pid).filter(|a| a.start_time == p.start_time)?;
                Some((p.pid, p.majflt.saturating_sub(a.majflt) as f64 / iv.as_secs_f64()))
            })
            .collect();
        (second, Some(rates))
    } else {
        (first, None)
    };
    let mut v: Vec<&process::ProcInfo> =
        table.values().filter(|p| !p.kernel_thread && (p.rss > 0 || p.swap > 0)).collect();
    match sort {
        "swap" => v.sort_by_key(|b| std::cmp::Reverse(b.swap)),
        "peak" => v.sort_by_key(|b| std::cmp::Reverse(b.hwm)),
        "majflt" => match &rates {
            Some(r) => v.sort_by(|a, b| r.get(&b.pid).unwrap_or(&0.0).total_cmp(r.get(&a.pid).unwrap_or(&0.0))),
            None => v.sort_by_key(|b| std::cmp::Reverse(b.majflt)),
        },
        _ => v.sort_by_key(|b| std::cmp::Reverse(b.rss)),
    }
    println!(
        "{:>8} {:>10} {:>10} {:>10} {:>12}  COMMAND",
        "PID",
        "RSS",
        "SWAP",
        "PEAK",
        if rates.is_some() { "MAJFLT/s" } else { "MAJFLT" }
    );
    for p in v.into_iter().take(limit) {
        let mf = match &rates {
            Some(r) => format!("{:.1}", r.get(&p.pid).copied().unwrap_or(0.0)),
            None => p.majflt.to_string(),
        };
        println!(
            "{:>8} {:>10} {:>10} {:>10} {:>12}  {}",
            p.pid,
            human_bytes(p.rss),
            human_bytes(p.swap),
            human_bytes(p.hwm),
            mf,
            p.comm
        );
    }
    Ok(())
}

fn doctor(config: &std::path::Path, socket: &std::path::Path) {
    let ok = |b: bool| if b { "\x1b[32m✓\x1b[0m" } else { "\x1b[31m✗\x1b[0m" };
    let warn = "\x1b[33m!\x1b[0m";
    println!("Warden doctor — kernel {}\n", warden_sys::system::kernel_release());
    let root = warden_sys::sched::is_root();
    println!(" {} running as root", ok(root));
    let loaded = match warden_core::load::load(config) {
        Ok(l) => {
            println!(" {} configuration valid ({} file(s))", ok(true), l.files.len());
            Some(l.config)
        }
        Err(e) => {
            println!(" {} configuration: {e}", ok(false));
            None
        }
    };
    let psi = warden_sys::psi::available();
    println!(
        " {} PSI (/proc/pressure) {}",
        ok(psi),
        if psi { "" } else { "— boot with psi=1 (RHEL/CentOS) or use a 4.20+ kernel" }
    );
    match warden_sys::psi::Trigger::new(
        "/proc/pressure/memory",
        "some",
        Duration::from_millis(150),
        Duration::from_secs(1),
    ) {
        Ok(_) => println!(" {} PSI triggers (1s window)", ok(true)),
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
            let two = warden_sys::psi::Trigger::new(
                "/proc/pressure/memory",
                "some",
                Duration::from_millis(300),
                Duration::from_secs(2),
            )
            .is_ok();
            println!(
                " {warn} PSI triggers: only 2s-multiple windows (no CAP_SYS_RESOURCE){}",
                if two { " — fallback works" } else { "" }
            );
        }
        Err(e) => println!(" {} PSI triggers: {e}", ok(false)),
    }
    println!(" {} cgroup v2 (freeze/kill whole services)", ok(warden_sys::cgroup::is_v2()));
    let me = std::process::id() as i32;
    let pidfd = warden_sys::process::start_time(me).map(|_| {
        // SAFETY: plain syscall, fd closed immediately.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, me, 0) };
        if fd >= 0 {
            unsafe { libc::close(fd as i32) };
        }
        fd >= 0
    });
    println!(" {} pidfd (race-free kills, Linux 5.3+)", ok(pidfd == Some(true)));
    match warden_sys::proc_connector::Connector::open() {
        Ok(_) => println!(" {} netlink proc connector (real-time exec/uid/ptrace)", ok(true)),
        Err(e) => println!(" {} proc connector: {e} — process analysis falls back to periodic scans", ok(false)),
    }
    match warden_sys::fanotify::Fanotify::new() {
        Ok(_) => println!(" {} fanotify (real-time FIM with writer PID)", ok(true)),
        Err(e) => println!(" {} fanotify: {e} — FIM falls back to scheduled scans", ok(false)),
    }
    match warden_sys::fanotify_fid::FidWatcher::new() {
        Ok(mut w) => match w.watch_filesystem(std::path::Path::new("/"), libc::FAN_ATTRIB) {
            Ok(_) => println!(" {} fanotify filesystem marks (real-time SUID detection)", ok(true)),
            Err(e) => {
                println!(" {} fanotify filesystem mark on /: {e} — SUID files found by periodic walks", ok(false))
            }
        },
        Err(e) => println!(
            " {} fanotify FAN_REPORT_DFID_NAME: {e} (Linux 5.9+) — SUID files found by periodic walks",
            ok(false)
        ),
    }
    println!(" {} /dev/kmsg readable", ok(warden_sys::kmsg::Reader::open(true).is_ok()));
    for (sched, paths) in io_schedulers(loaded.as_ref()) {
        let pacing = loaded.as_ref().is_none_or(|c| c.daemon.pacing.enabled);
        let honours = warden_sys::pace::scheduler_honours_io_class(&sched);
        let mark = if honours { ok(true) } else { warn };
        let why = match (honours, pacing) {
            (true, _) => "honours I/O classes: scans in the idle class wait for the workload",
            (false, true) => "ignores I/O classes: only pacing ([daemon.pacing]) keeps scans out of the workload's way",
            (false, false) => "ignores I/O classes and [daemon.pacing] is off: scans compete with the workload",
        };
        println!(" {mark} I/O scheduler {sched} for {} — {why}", paths.join(", "));
    }
    println!(" {} nft (IP blocking)", ok(warden_sys::cmd::which("nft").is_some()));
    println!(" {} journalctl (auth events, journal vacuum)", ok(warden_sys::cmd::which("journalctl").is_some()));
    let systemd = std::path::Path::new("/run/systemd/system").exists();
    println!(" {} systemd", ok(systemd));
    if systemd {
        let probe = || -> std::io::Result<usize> {
            let mut c = warden_sys::dbus::Connection::system_bus()?;
            Ok(warden_detect::systemd::list_failed(&mut c)?.len())
        };
        match probe() {
            Ok(n) => println!(" {} systemd over D-Bus (instant unit failures; {n} failed now)", ok(true)),
            Err(e) => println!(" {} systemd over D-Bus: {e} — falls back to `systemctl` polling", ok(false)),
        }
    }
    let lsm = warden_sys::kernel::lsm_state();
    println!(
        "   LSM stack: {}  AppArmor: {}  SELinux: {}",
        lsm.stack.as_deref().unwrap_or("?"),
        match lsm.apparmor_enabled {
            Some(true) => format!("enabled ({} enforced profiles)", lsm.apparmor_enforced_profiles.unwrap_or(0)),
            Some(false) => "disabled".into(),
            None => "absent".into(),
        },
        match lsm.selinux_enforcing {
            Some(true) => "enforcing",
            Some(false) => "permissive",
            None => "absent",
        }
    );
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: valid out pointer.
    unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rl) };
    let mlock_ok = rl.rlim_cur == libc::RLIM_INFINITY || rl.rlim_cur >= 64 << 20;
    println!(
        " {} RLIMIT_MEMLOCK {} (unit file sets LimitMEMLOCK=infinity)",
        if mlock_ok { ok(true) } else { warn },
        if rl.rlim_cur == libc::RLIM_INFINITY { "unlimited".into() } else { human_bytes(rl.rlim_cur) }
    );
    if let Some(cs) = warden_sys::kernel::clock_status() {
        println!(
            " {} clock synchronised (max error {} ms)",
            if cs.synced { ok(true) } else { warn },
            cs.max_error_us / 1000
        );
    }
    if std::path::Path::new("/run/systemd/system").exists() {
        unit_check(ok, warn);
    }
    waf_doctor(loaded.as_ref(), ok, warn);
    let sock = loaded.as_ref().map_or_else(|| socket.to_path_buf(), |c| c.daemon.control_socket.clone());
    let daemon = UnixStream::connect(socket).is_ok() || UnixStream::connect(&sock).is_ok();
    println!(
        " {} wardend control socket reachable{}",
        if daemon { ok(true) } else { warn },
        if daemon { "" } else { " — daemon not running (systemctl status wardend)" }
    );
}

/// Doctor: the ModSecurity logs of this host, whether Warden follows them,
/// and whether a web account can write them.
fn waf_doctor(cfg: Option<&warden_core::Config>, ok: impl Fn(bool) -> &'static str, warn: &str) {
    let Some(cfg) = cfg else { return };
    if !cfg.waf.enabled {
        return;
    }
    let d = warden_detect::waf_discover::discover();
    let web = warden_detect::util::WebPrincipals::load(&cfg.process.web_users);
    let configured: Vec<&std::path::Path> = cfg.waf.logs.iter().map(|l| l.path.as_path()).collect();
    if d.found.is_empty() && configured.is_empty() {
        println!(" {warn} WAF: no ModSecurity log configured or found (wardenctl waf discover)");
        return;
    }
    for f in &d.found {
        let followed = cfg.waf.discover || configured.contains(&f.path.as_path());
        let mark = if followed { ok(true) } else { warn };
        let how = if configured.contains(&f.path.as_path()) {
            "configured"
        } else if cfg.waf.discover {
            "discovered"
        } else {
            "NOT followed: add it to [[waf.log]] or set waf.discover = true"
        };
        println!(" {mark} WAF {} ({} {}): {how}", f.path.display(), f.server, f.site);
    }
    // who can write what the daemon reads: the logs, and the storage of
    // concurrent logs (there the workers write every entry by design)
    let mut followed: Vec<(&std::path::Path, Option<&std::path::Path>)> =
        cfg.waf.logs.iter().map(|l| (l.path.as_path(), l.storage_dir.as_deref())).collect();
    if cfg.waf.discover {
        followed.extend(d.found.iter().map(|f| (f.path.as_path(), f.storage_dir.as_deref())));
    }
    let mut told = std::collections::HashSet::new();
    let what = if cfg.waf.trust_writable_logs {
        "blocks still follow from it (waf.trust_writable_logs = true)"
    } else {
        "its events do not block (waf.trust_writable_logs = false)"
    };
    for (log, storage) in followed {
        for p in std::iter::once(log).chain(storage) {
            if told.insert(p)
                && let Some(why) = web.can_write(p)
            {
                println!(" {warn} WAF log writable by a web user: {why} — a webshell could forge entries; {what}");
            }
        }
    }
    for n in &d.notes {
        println!(" {warn} WAF: {n}");
    }
}

/// `status`: the ModSecurity logs the daemon follows.
fn waf_status_text(v: &serde_json::Value) {
    let sources = v["sources"].as_array().map(Vec::as_slice).unwrap_or_default();
    let problems = v["problems"].as_array().map(Vec::as_slice).unwrap_or_default();
    if sources.is_empty() && problems.is_empty() {
        return;
    }
    println!("\nWAF logs:");
    for s in sources {
        println!(
            "  {:<10} {:<20} {}{}{}",
            s["format"].as_str().unwrap_or("?"),
            s["site"].as_str().unwrap_or("-"),
            s["path"].as_str().unwrap_or("?"),
            s["storage_dir"].as_str().map(|d| format!(" (storage {d})")).unwrap_or_default(),
            if s["discovered"].as_bool() == Some(true) { "  [discovered]" } else { "" }
        );
        if let Some(w) = s["writable_by_web_user"].as_str() {
            println!("  {:<31} ! writable by a web user: {w}", "");
        }
    }
    for p in problems {
        println!("  cannot open {}: {}", p["path"].as_str().unwrap_or("?"), p["error"].as_str().unwrap_or("?"));
    }
}

/// `wardenctl waf discover` as text: the sources, what to know about them,
/// and a `[[waf.log]]` snippet.
fn waf_discover_text(d: &warden_detect::waf_discover::Discovery, web: &warden_detect::util::WebPrincipals) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    if d.found.is_empty() {
        out.push_str("no ModSecurity log found in the Apache, nginx or Angie configuration\n");
    }
    for f in &d.found {
        let fmt = serde_json::to_value(f.format).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default();
        let _ = writeln!(out, "{:<7} {:<28} {:<11} {}", f.server, f.site, fmt, f.path.display());
        if let Some(dir) = &f.storage_dir {
            let _ = writeln!(out, "        storage {}", dir.display());
        }
        let _ = writeln!(out, "        from {}", f.origin);
        for n in &f.notes {
            let _ = writeln!(out, "        ! {n}");
        }
        let paths = std::iter::once(&f.path).chain(f.storage_dir.as_ref());
        if let Some(why) = paths.filter_map(|p| web.can_write(p)).next() {
            let _ = writeln!(
                out,
                "        ! writable by a web user ({why}): a webshell could forge entries — see waf.trust_writable_logs"
            );
        }
    }
    for n in &d.notes {
        let _ = writeln!(out, " ! {n}");
    }
    if !d.found.is_empty() {
        let _ = writeln!(
            out,
            "\n# With waf.discover = true (the default) wardend follows these by itself;\n# to pin them, put this into /etc/warden/conf.d/50-waf.toml:\n"
        );
        out.push_str(&d.toml());
    }
    out
}

/// Syscalls the daemon needs beyond `@system-service` (see the unit file).
pub const REQUIRED_SYSCALLS: &[&str] = &["fanotify_init", "fanotify_mark", "clock_adjtime"];
/// Capabilities the daemon needs for full functionality.
pub const REQUIRED_CAPS: &[&str] =
    &["cap_kill", "cap_sys_ptrace", "cap_sys_admin", "cap_net_admin", "cap_syslog", "cap_dac_override"];

/// Parse `systemctl show` output into key → value.
pub fn parse_show(s: &str) -> std::collections::HashMap<String, String> {
    s.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.to_owned(), v.to_owned())).collect()
}

/// Analyse the installed unit: findings as (severity: 0 ok / 1 warn / 2 error, message).
pub fn analyse_unit(p: &std::collections::HashMap<String, String>) -> Vec<(u8, String)> {
    let g = |k: &str| p.get(k).map(String::as_str).unwrap_or("");
    let mut out = Vec::new();
    if g("LoadState") != "loaded" {
        out.push((1, "wardend.service is not installed (run scripts/install.sh)".to_owned()));
        return out;
    }
    let state = format!("{}/{}", g("ActiveState"), g("SubState"));
    let crashed_sigsys = g("Result") == "core-dump" && g("ExecMainStatus") == "31";
    if crashed_sigsys {
        out.push((
            2,
            "wardend.service was killed by seccomp (SIGSYS): the installed unit is outdated — \
             reinstall it (scripts/install.sh) and `systemctl reset-failed wardend`"
                .to_owned(),
        ));
    } else if g("ActiveState") == "active" {
        out.push((0, format!("wardend.service {state}, restarts: {}", g("NRestarts"))));
    } else {
        out.push((1, format!("wardend.service {state} (result: {}, status {})", g("Result"), g("ExecMainStatus"))));
    }
    let filter = g("SystemCallFilter");
    if !filter.is_empty() && !filter.starts_with('~') {
        let allowed: std::collections::HashSet<&str> = filter.split_whitespace().collect();
        let missing: Vec<&str> = REQUIRED_SYSCALLS.iter().copied().filter(|s| !allowed.contains(s)).collect();
        let errno = !g("SystemCallErrorNumber").is_empty();
        match (missing.is_empty(), errno) {
            (true, _) => {
                out.push((0, "seccomp filter allows every syscall Warden needs".to_owned()));
                if !allowed.contains("cachestat") {
                    out.push((
                        1,
                        "seccomp filter does not allow cachestat: scans cannot evict the page cache they read \
                         (shows up as Warden memory in `systemctl status`) — update the unit"
                            .to_owned(),
                    ));
                }
                if !allowed.contains("open_by_handle_at") {
                    out.push((
                        1,
                        "seccomp filter does not allow open_by_handle_at: no real-time SUID detection, \
                         periodic walks only — update the unit"
                            .to_owned(),
                    ));
                }
            }
            (false, true) => out.push((
                1,
                format!("seccomp filter blocks {} (degraded: EPERM, not fatal) — update the unit", missing.join(", ")),
            )),
            (false, false) => out.push((
                2,
                format!(
                    "seccomp filter blocks {} and kills on violation — the daemon WILL crash; update the unit",
                    missing.join(", ")
                ),
            )),
        }
    }
    if !filter.is_empty() && !filter.starts_with('~') {
        let allowed: std::collections::HashSet<&str> = filter.split_whitespace().collect();
        let mounts: Vec<&str> =
            ["mount", "pivot_root", "move_mount", "open_tree"].into_iter().filter(|s| allowed.contains(s)).collect();
        if !mounts.is_empty() {
            out.push((
                1,
                format!(
                    "seccomp filter allows {} (@mount, units before 0.14.1): with CAP_SYS_ADMIN a compromised \
                     daemon or hook could remount — update the unit",
                    mounts.join(", ")
                ),
            ));
        }
    }
    let families = g("RestrictAddressFamilies");
    if !families.is_empty() && !families.starts_with('~') {
        let have: std::collections::HashSet<&str> = families.split_whitespace().collect();
        let missing: Vec<&str> = REQUIRED_FAMILIES
            .iter()
            .copied()
            .filter(|f| !have.contains(f.trim_start_matches("AF_")) && !have.contains(f))
            .collect();
        if !missing.is_empty() {
            out.push((
                1,
                format!(
                    "RestrictAddressFamilies blocks {} (proc connector and nftables need AF_NETLINK, \
                     webhooks AF_INET/AF_INET6) — update the unit",
                    missing.join(", ")
                ),
            ));
        }
    }
    let caps = g("CapabilityBoundingSet");
    if !caps.is_empty() {
        let have: std::collections::HashSet<&str> = caps.split_whitespace().collect();
        let missing: Vec<&str> = REQUIRED_CAPS.iter().copied().filter(|c| !have.contains(c)).collect();
        if !missing.is_empty() {
            out.push((1, format!("capabilities missing from the unit: {}", missing.join(", "))));
        }
        if !(have.contains("cap_setuid") && have.contains("cap_setgid")) {
            out.push((
                1,
                "the unit lacks CAP_SETUID/CAP_SETGID: hooks and commands with a `user` \
                 (daemon.command_user) fail instead of dropping root — update the unit"
                    .to_owned(),
            ));
        }
    }
    out
}

/// Address families the daemon opens (see `RestrictAddressFamilies` in the unit).
pub const REQUIRED_FAMILIES: &[&str] = &["AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"];

/// The I/O schedulers of the filesystems Warden scans: `/` and the FIM sites.
fn io_schedulers(cfg: Option<&warden_core::Config>) -> Vec<(String, Vec<String>)> {
    let mut paths = vec![std::path::PathBuf::from("/")];
    if let Some(c) = cfg {
        paths.extend(c.fim.sites.iter().map(|s| s.root.clone()));
    }
    let mut out: Vec<(String, Vec<String>)> = Vec::new();
    for p in paths {
        let Some(s) = warden_sys::pace::io_scheduler(&p) else { continue };
        let p = p.display().to_string();
        match out.iter_mut().find(|(x, _)| *x == s) {
            Some((_, v)) => v.push(p),
            None => out.push((s, vec![p])),
        }
    }
    out
}

/// One line about pacing for `wardenctl status`.
fn pacing_text(v: &Value) -> String {
    if v["enabled"].as_bool() != Some(true) {
        return "off".into();
    }
    let mut s = format!("on, yields above {}% I/O pressure", v["io_pressure_target_percent"]);
    if let Some(p) = v["io_pressure_percent"].as_f64() {
        s.push_str(&format!(" (now {p}%)"));
    }
    for (scan, st) in v["scans"].as_object().into_iter().flatten() {
        let mut parts = Vec::new();
        if st["active"].as_bool() == Some(true) {
            let duty = st["duty"].as_f64().unwrap_or(1.0);
            parts.push(format!("running at {:.0}% speed", duty * 100.0));
            if let Some(c) = st["io_class"].as_str() {
                parts.push(format!("{c} class"));
            }
        }
        let paced = st["paced_seconds"].as_f64().unwrap_or(0.0);
        if paced >= 1.0 {
            parts.push(format!("paused {}", humantime::format_duration(Duration::from_secs(paced as u64))));
        }
        if let Some(n) = st["deferrals"].as_u64().filter(|n| *n > 0) {
            parts.push(format!("postponed {n}×"));
        }
        if !parts.is_empty() {
            s.push_str(&format!("; {scan}: {}", parts.join(", ")));
        }
    }
    s
}

fn unit_check(ok: impl Fn(bool) -> &'static str, warn: &str) {
    let props = "LoadState,ActiveState,SubState,Result,ExecMainStatus,NRestarts,SystemCallFilter,SystemCallErrorNumber,CapabilityBoundingSet,RestrictAddressFamilies";
    let Ok(o) =
        warden_sys::cmd::run_cmd("systemctl", &["show", "wardend.service", "-p", props], Duration::from_secs(10))
    else {
        return;
    };
    for (sev, msg) in analyse_unit(&parse_show(&String::from_utf8_lossy(&o.stdout))) {
        let mark = match sev {
            0 => ok(true),
            1 => warn,
            _ => ok(false),
        };
        println!(" {mark} {msg}");
    }
}

fn main() -> Result<()> {
    // `wardenctl events | head`: end quietly when the reader goes away, like
    // every other Unix tool (Rust ignores SIGPIPE, and println! then panics
    // with "failed printing to stdout: Broken pipe")
    // SAFETY: restoring the default disposition of a signal, before any
    // thread is started.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
    let cli = Cli::parse();
    let color = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let out = |v: Value, json: bool| {
        if json {
            println!("{}", pretty(&v));
        }
        v
    };
    match cli.cmd {
        Cmd::Status => {
            let v = out(call(&cli.socket, &Request::Status)?, cli.json);
            if !cli.json {
                println!(
                    "Warden {} on {} — pid {}, up {}{}",
                    v["version"].as_str().unwrap_or("?"),
                    v["host"].as_str().unwrap_or("?"),
                    v["pid"],
                    humantime::format_duration(Duration::from_secs(v["uptime_seconds"].as_u64().unwrap_or(0))),
                    match (v["dry_run"].as_bool(), v["dry_run_source"].as_str()) {
                        (Some(true), Some("override")) => "  [DRY-RUN: wardenctl override]".to_owned(),
                        (Some(true), Some("cli")) => "  [DRY-RUN: --dry-run]".to_owned(),
                        (Some(true), _) => "  [DRY-RUN]".to_owned(),
                        (_, Some("override")) => "  [acting: wardenctl override]".to_owned(),
                        _ => String::new(),
                    }
                );
                println!("\nLevels:");
                for (k, l) in v["levels"].as_object().into_iter().flatten() {
                    println!("  {k:<12} {}", l.as_str().unwrap_or(""));
                }
                println!("\nSensors:");
                for (k, s) in v["sensors"].as_object().into_iter().flatten() {
                    let st = s["state"].as_str().unwrap_or("?");
                    let d = s.get("detail").and_then(|d| d.as_str()).unwrap_or("");
                    println!("  {k:<16} {st} {d}");
                }
                waf_status_text(&v["waf_sources"]);
                println!("\nFIM sites: {}", v["fim_sites"]);
                println!("Lineage: {}", v["lineage"]);
                println!("Max heuristic score: {}", v["heuristics_max_score"]);
                if v.get("pacing").is_some() {
                    println!("Pacing: {}", pacing_text(&v["pacing"]));
                }
                println!("Events dropped: {}", v["events_dropped"]);
                println!("Config: {}", v["config_files"]);
            }
        }
        Cmd::Events { limit, severity, follow } => {
            let v = call(&cli.socket, &Request::Events { limit, since_id: None, min_severity: severity })?;
            if cli.json {
                println!("{}", pretty(&v))
            } else {
                print_events(&v, color)
            }
            if follow {
                let mut last = v.as_array().and_then(|a| a.last()).and_then(|e| e["id"].as_u64());
                loop {
                    std::thread::sleep(Duration::from_secs(1));
                    let v =
                        call(&cli.socket, &Request::Events { limit: 1000, since_id: last, min_severity: severity })?;
                    if let Some(id) = v.as_array().and_then(|a| a.last()).and_then(|e| e["id"].as_u64()) {
                        last = Some(id);
                    }
                    if cli.json {
                        for e in v.as_array().into_iter().flatten() {
                            println!("{e}");
                        }
                    } else {
                        print_events(&v, color);
                    }
                }
            }
        }
        Cmd::Top { limit } => {
            let v = out(call(&cli.socket, &Request::Top { limit })?, cli.json);
            if !cli.json {
                println!(
                    "{:>8} {:<16} {:>10} {:>10} {:>10} {:>9} {:>6} {:>10}  PROTECTED",
                    "PID", "COMM", "RSS", "ANON", "SWAP", "MAJFLT/s", "ADJ", "SCORE(MiB)"
                );
                for c in v.as_array().into_iter().flatten() {
                    println!(
                        "{:>8} {:<16} {:>10} {:>10} {:>10} {:>9} {:>6} {:>10.0}  {}",
                        c["pid"],
                        c["comm"].as_str().unwrap_or(""),
                        human_bytes(c["rss"].as_u64().unwrap_or(0)),
                        human_bytes(c["anon"].as_u64().unwrap_or(0)),
                        human_bytes(c["swap"].as_u64().unwrap_or(0)),
                        c["majflt_per_sec"],
                        c["oom_score_adj"],
                        c["score"].as_f64().unwrap_or(0.0) / 1048576.0,
                        c["protected"].as_str().unwrap_or("-")
                    );
                }
            }
        }
        Cmd::Scores => {
            let v = out(call(&cli.socket, &Request::Scores)?, cli.json);
            if !cli.json {
                for s in v.as_array().into_iter().flatten() {
                    println!(
                        "{:>7.1}  {}{}  [{}]",
                        s["score"].as_f64().unwrap_or(0.0),
                        s["entity"].as_str().unwrap_or(""),
                        if s["contained"].as_bool() == Some(true) { " (contained)" } else { "" },
                        s["reasons"]
                            .as_array()
                            .map(|r| r.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(", "))
                            .unwrap_or_default()
                    );
                }
            }
        }
        Cmd::Reload => println!("{}", call(&cli.socket, &Request::Reload)?),
        Cmd::DryRun { state } => {
            let enabled = match state.as_str() {
                "on" => Some(true),
                "off" => Some(false),
                _ => None,
            };
            let v = call(&cli.socket, &Request::SetDryRun { enabled })?;
            if cli.json {
                println!("{}", pretty(&v));
            } else {
                println!(
                    "dry-run {} (decided by: {})",
                    if v["dry_run"].as_bool() == Some(true) { "on" } else { "off" },
                    v["source"].as_str().unwrap_or("?")
                );
                if let Some(w) = v["warning"].as_str() {
                    eprintln!("warning: {w}");
                }
            }
        }
        Cmd::Fim(f) => {
            let req = match f {
                FimCmd::Status => Request::FimStatus,
                FimCmd::Scan { site } => Request::FimScan { site },
                FimCmd::Accept { site, path } => Request::FimAccept { site, path },
                FimCmd::Pause { site, duration } => {
                    Request::FimPause { site, seconds: humantime::parse_duration(&duration)?.as_secs() }
                }
            };
            println!("{}", pretty(&call(&cli.socket, &req)?));
        }
        Cmd::Block { ip, ttl } => {
            let ttl_secs = ttl.map(|t| humantime::parse_duration(&t)).transpose()?.map(|d| d.as_secs());
            println!("{}", call(&cli.socket, &Request::Block { ip, ttl_secs })?);
        }
        Cmd::Unblock { ip } => println!("{}", call(&cli.socket, &Request::Unblock { ip })?),
        Cmd::Blocklist => {
            let v = out(call(&cli.socket, &Request::Blocklist)?, cli.json);
            if !cli.json {
                for b in v.as_array().into_iter().flatten() {
                    println!(
                        "{:<40} {}",
                        b["ip"].as_str().unwrap_or(""),
                        b["expires_seconds"]
                            .as_u64()
                            .map(|s| format!("expires in {}", humantime::format_duration(Duration::from_secs(s))))
                            .unwrap_or_else(|| "permanent".into())
                    );
                }
            }
        }
        Cmd::Quarantine(q) => {
            let v = match q {
                QuarantineCmd::List => call(&cli.socket, &Request::QuarantineList)?,
                QuarantineCmd::Restore { id } => call(&cli.socket, &Request::QuarantineRestore { id })?,
            };
            println!("{}", pretty(&v));
        }
        Cmd::Snapshot { reason } => println!("{}", call(&cli.socket, &Request::Snapshot { reason })?),
        Cmd::Profile { interval } => {
            let a = call(&cli.socket, &Request::Profile)?;
            std::thread::sleep(Duration::from_secs(interval.max(1)));
            let b = call(&cli.socket, &Request::Profile)?;
            if cli.json {
                println!("{}", pretty(&serde_json::json!({"before": a, "after": b})));
            } else {
                profile::print(&a, &b);
            }
        }
        Cmd::Tuning { revert: true } => {
            for l in call(&cli.socket, &Request::TuningRevert)?.as_array().into_iter().flatten() {
                println!("{}", l.as_str().unwrap_or(""));
            }
        }
        Cmd::Tuning { revert: false } => {
            let v = out(call(&cli.socket, &Request::Tuning)?, cli.json);
            if !cli.json {
                let adv = v["advice"].as_array().cloned().unwrap_or_default();
                println!("Recommendations ({}):", adv.len());
                for a in &adv {
                    println!(
                        "  [{}] {} = {} → {}\n      {}",
                        a["category"].as_str().unwrap_or(""),
                        a["key"].as_str().unwrap_or(""),
                        a["current"].as_str().unwrap_or(""),
                        a["recommended"].as_str().unwrap_or(""),
                        a["reason"].as_str().unwrap_or("")
                    );
                }
                let applied = v["applied"].as_array().cloned().unwrap_or_default();
                println!(
                    "\nApplied by Warden (auto_grow={}, persist={}): {}",
                    v["auto_grow"],
                    v["persist"],
                    if applied.is_empty() { "none".to_owned() } else { String::new() }
                );
                for c in &applied {
                    println!(
                        "  {} = {} (was {})",
                        c["key"].as_str().unwrap_or(""),
                        c["value"].as_str().unwrap_or(""),
                        c["original"].as_str().unwrap_or("")
                    );
                }
            }
        }
        Cmd::Doctor { config } => doctor(&config, &cli.socket),
        Cmd::Psi => {
            for r in [
                warden_sys::psi::Resource::Cpu,
                warden_sys::psi::Resource::Memory,
                warden_sys::psi::Resource::Io,
                warden_sys::psi::Resource::Irq,
            ] {
                if let Ok(p) = warden_sys::psi::read(r) {
                    let f = p
                        .full
                        .map(|f| format!("full avg10={:>6.2} avg60={:>6.2} avg300={:>6.2}", f.avg10, f.avg60, f.avg300))
                        .unwrap_or_default();
                    println!(
                        "{:<22} some avg10={:>6.2} avg60={:>6.2} avg300={:>6.2}   {f}",
                        r.path(),
                        p.some.avg10,
                        p.some.avg60,
                        p.some.avg300
                    );
                }
            }
        }
        Cmd::MemTop { limit, sort, interval } => {
            let iv = interval.map(|s| humantime::parse_duration(&s)).transpose()?;
            mem_top(limit, &sort, iv)?;
        }
        Cmd::Du { path, depth, top, max_entries, max_time, idle } => {
            if idle {
                let _ = warden_sys::sched::background_thread();
            }
            let opt = warden_sys::du::DuOptions {
                depth,
                top,
                max_entries,
                max_time: humantime::parse_duration(&max_time)?,
                min_file: 16 << 20,
                // the operator is waiting for the answer (`--idle` lowers
                // the priority if they are not)
                pace: false,
            };
            let rep =
                warden_sys::du::usage(&path, &opt, None).with_context(|| format!("cannot walk {}", path.display()))?;
            if cli.json {
                println!("{}", pretty(&serde_json::to_value(&rep)?));
            } else {
                // Comparing with `statvfs` only makes sense for a whole filesystem.
                let used =
                    is_mount_point(&path).then(|| warden_sys::mounts::statvfs(&path).ok().map(|u| u.used)).flatten();
                print!("{}", du_text(&rep, used));
            }
        }
        Cmd::Scan { path, min_score, rules } => {
            let found = warden_detect::fim::scan_tree(&path, &rules, min_score);
            if cli.json {
                let v: Vec<Value> = found.iter().map(|(p, v)| serde_json::json!({"path": p, "verdict": v})).collect();
                println!("{}", pretty(&Value::Array(v)));
            } else {
                for (p, v) in &found {
                    println!("{:>4}  {p}", v.score);
                    for h in &v.hits {
                        println!(
                            "        {} (+{}){}: {}",
                            h.id,
                            h.score,
                            if h.line > 0 { format!(" line {}", h.line) } else { String::new() },
                            h.excerpt
                        );
                    }
                }
                println!("{} suspicious file(s)", found.len());
            }
            if !found.is_empty() {
                std::process::exit(3);
            }
        }
        Cmd::Waf(WafCmd::Discover { config }) => {
            let d = warden_detect::waf_discover::discover();
            let web_users = warden_core::load::load(&config)
                .map(|l| l.config.process.web_users)
                .unwrap_or_else(|_| warden_core::Config::default().process.web_users);
            let web = warden_detect::util::WebPrincipals::load(&web_users);
            if cli.json {
                let mut v = serde_json::to_value(&d)?;
                if let Some(found) = v.get_mut("found").and_then(Value::as_array_mut) {
                    for (f, src) in found.iter_mut().zip(&d.found) {
                        f["writable_by_web_user"] = serde_json::json!(web.can_write(&src.path));
                    }
                }
                println!("{}", pretty(&v));
            } else {
                print!("{}", waf_discover_text(&d, &web));
            }
        }
        Cmd::CheckConfig { path } => match warden_core::load::load(&path) {
            Ok(l) => println!(
                "configuration OK ({} file(s): {})",
                l.files.len(),
                l.files.iter().map(|f| f.display().to_string()).collect::<Vec<_>>().join(", ")
            ),
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(1);
            }
        },
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn show(s: &str) -> std::collections::HashMap<String, String> {
        parse_show(s)
    }

    #[test]
    fn diagnoses_old_unit_sigsys_crash() {
        let p = show(
            "LoadState=loaded\nActiveState=activating\nSubState=auto-restart\nResult=core-dump\nExecMainStatus=31\n\
             SystemCallFilter=read write openat pidfd_open\nSystemCallErrorNumber=\nCapabilityBoundingSet=cap_kill\n",
        );
        let f = analyse_unit(&p);
        assert!(f.iter().any(|(s, m)| *s == 2 && m.contains("SIGSYS")));
        assert!(f.iter().any(|(s, m)| *s == 2 && m.contains("WILL crash")));
        assert!(f.iter().any(|(s, m)| *s == 1 && m.contains("cap_syslog")));
    }

    #[test]
    fn healthy_unit() {
        let p = show(&format!(
            "LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nExecMainStatus=0\nNRestarts=0\n\
             SystemCallFilter=read write cachestat open_by_handle_at {}\nSystemCallErrorNumber=EPERM\nCapabilityBoundingSet={}\n",
            REQUIRED_SYSCALLS.join(" "),
            REQUIRED_CAPS.join(" ")
        ));
        let f = analyse_unit(&p);
        assert!(f.iter().any(|(s, m)| *s == 1 && m.contains("CAP_SETUID")), "{f:?}");
        let p = show(&format!(
            "LoadState=loaded\nActiveState=active\nSubState=running\nResult=success\nExecMainStatus=0\nNRestarts=0\n\
             SystemCallFilter=read write cachestat open_by_handle_at {}\nSystemCallErrorNumber=EPERM\n\
             CapabilityBoundingSet={} cap_setuid cap_setgid\nRestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n",
            REQUIRED_SYSCALLS.join(" "),
            REQUIRED_CAPS.join(" ")
        ));
        let f = analyse_unit(&p);
        assert!(f.iter().all(|(s, _)| *s == 0), "{f:?}");
        // the 0.14.0 unit: @mount allowed, no address-family restriction needed
        let p = show(&format!(
            "LoadState=loaded\nActiveState=active\nSubState=running\nSystemCallFilter=read mount pivot_root {}\n\
             SystemCallErrorNumber=EPERM\nRestrictAddressFamilies=AF_UNIX AF_INET\n",
            REQUIRED_SYSCALLS.join(" ")
        ));
        let f = analyse_unit(&p);
        assert!(f.iter().any(|(s, m)| *s == 1 && m.contains("mount, pivot_root")), "{f:?}");
        assert!(f.iter().any(|(s, m)| *s == 1 && m.contains("AF_INET6, AF_NETLINK")), "{f:?}");
        // the 0.10 unit: works, but scans cannot evict their page cache
        let p = show(&format!(
            "LoadState=loaded\nActiveState=active\nSubState=running\nSystemCallFilter=read {}\nSystemCallErrorNumber=EPERM\n",
            REQUIRED_SYSCALLS.join(" ")
        ));
        assert!(analyse_unit(&p).iter().any(|(s, m)| *s == 1 && m.contains("cachestat")));
    }

    #[test]
    fn not_installed() {
        let f = analyse_unit(&show("LoadState=not-found\n"));
        assert_eq!(f[0].0, 1);
    }

    #[test]
    fn pacing_line() {
        let v = serde_json::json!({
            "enabled": true, "io_pressure_target_percent": 10.0, "io_pressure_percent": 23.4,
            "scans": {
                "du": {"active": true, "duty": 0.25, "io_class": "idle", "paced_seconds": 75.2, "deferrals": 0, "runs": 1},
                "suid": {"active": false, "duty": 1.0, "io_class": null, "paced_seconds": 0.0, "deferrals": 3, "runs": 0},
                "fim": {"active": false, "duty": 1.0, "paced_seconds": 0.2, "deferrals": 0, "runs": 4}
            }
        });
        assert_eq!(
            pacing_text(&v),
            "on, yields above 10.0% I/O pressure (now 23.4%); du: running at 25% speed, idle class, paused 1m 15s; suid: postponed 3×"
        );
        assert_eq!(pacing_text(&serde_json::json!({"enabled": false})), "off");
    }

    #[test]
    fn du_text_explains_hidden_space() {
        use warden_sys::du::{DuEntry, DuReport};
        let g = 1u64 << 30;
        let rep = DuReport {
            root: "/".into(),
            total: 10 * g,
            levels: vec![vec![DuEntry { path: "/var".into(), bytes: 8 * g }], vec![]],
            largest_files: vec![DuEntry { path: "/var/lib/mysql/ibdata1".into(), bytes: 5 * g }],
            entries: 1000,
            ..Default::default()
        };
        let t = du_text(&rep, Some(40 * g));
        assert!(t.contains("80.0%  /var"), "{t}");
        assert!(t.contains("ibdata1"));
        assert!(t.contains("30.0GiB more than the walk found"), "{t}");
        assert!(!du_text(&rep, Some(10 * g)).contains("more than the walk"));
        let partial = DuReport { partial: Some("time budget exhausted"), ..rep };
        let t = du_text(&partial, Some(40 * g));
        assert!(t.contains("PARTIAL") && !t.contains("more than the walk"));
    }
}
