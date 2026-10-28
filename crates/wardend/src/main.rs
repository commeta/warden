//! `wardend` — the Warden host guardian daemon.
#![cfg_attr(test, allow(clippy::unwrap_used))]

mod dryrun;
mod engine;
mod eventlog;
mod notify;
mod queue;
mod server;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::signal::unix::{SignalKind, signal};
use tracing_subscriber::EnvFilter;
use warden_core::config::LogFormat;
use warden_core::sync::lock;
use warden_core::{Config, Event, Severity};
use warden_detect::Shared;
use warden_respond::Responder;
use warden_sys::sdnotify;

/// How long shutdown waits for the threads that flush state (FIM baselines)
/// and for the action in progress to finish.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

#[cfg(feature = "alloc-stats")]
#[global_allocator]
static ALLOC: warden_detect::TrackingAlloc = warden_detect::TrackingAlloc;

#[derive(Debug, Parser)]
#[command(name = "wardend", version, about = "Warden host guardian daemon")]
struct Args {
    /// Main configuration file (drop-ins are read from `<dir>/conf.d/*.toml`).
    #[arg(short, long, default_value = warden_core::DEFAULT_CONFIG, env = "WARDEN_CONFIG")]
    config: PathBuf,
    /// Validate the configuration and exit.
    #[arg(long)]
    check_config: bool,
    /// Print the built-in default configuration as TOML and exit.
    #[arg(long)]
    print_defaults: bool,
    /// Force dry-run (detect and report, never act).
    #[arg(long)]
    dry_run: bool,
    /// Override the log level (trace, debug, info, warn, error).
    #[arg(long)]
    log_level: Option<String>,
}

fn init_logging(cfg: &Config, level: Option<&str>) {
    let filter = EnvFilter::try_from_env("WARDEN_LOG")
        .unwrap_or_else(|_| EnvFilter::new(level.unwrap_or(&cfg.daemon.log_level)));
    let fmt = match cfg.daemon.log_format {
        LogFormat::Auto if sdnotify::under_systemd() => LogFormat::Journal,
        LogFormat::Auto => LogFormat::Text,
        f => f,
    };
    let b = tracing_subscriber::fmt().with_env_filter(filter).with_target(false);
    match fmt {
        LogFormat::Json => b.json().flatten_event(true).init(),
        LogFormat::Journal => b.without_time().with_ansi(false).init(),
        _ => b.init(),
    }
}

fn prepare_dirs(cfg: &Config) {
    use std::os::unix::fs::PermissionsExt;
    for (d, mode) in [
        (cfg.daemon.state_dir.clone(), 0o700),
        (cfg.daemon.state_dir.join("fim"), 0o700),
        (cfg.actions.quarantine_dir.clone(), 0o700),
        (cfg.actions.snapshot_dir.clone(), 0o700),
        (cfg.daemon.runtime_dir.clone(), 0o755),
    ] {
        if std::fs::create_dir_all(&d).is_ok() {
            let _ = std::fs::set_permissions(&d, std::fs::Permissions::from_mode(mode));
        }
    }
    if let Some(p) = cfg.events.path.parent() {
        let _ = std::fs::create_dir_all(p);
    }
}

fn self_protect(cfg: &Config) {
    if cfg.daemon.mlock {
        match warden_sys::sched::mlock_all() {
            Ok(()) => tracing::info!("memory locked (mlockall): Warden stays responsive under swap storms"),
            Err(e) => tracing::warn!(error = %e, "mlockall failed (raise LimitMEMLOCK); continuing unlocked"),
        }
    }
    if let Err(e) = warden_sys::sched::set_oom_score_adj(cfg.daemon.oom_score_adj) {
        tracing::debug!(error = %e, "cannot set oom_score_adj");
    }
}

fn check_config(path: &std::path::Path) -> Result<()> {
    let l = warden_core::load::load(path)?;
    let c = &l.config;
    println!("configuration OK");
    for f in &l.files {
        println!("  file: {}", f.display());
    }
    if l.files.is_empty() {
        println!("  (no files found — built-in defaults)");
    }
    let on = |b: bool| if b { "on" } else { "off" };
    println!("  dry_run: {}", c.daemon.dry_run);
    println!(
        "  memory: {}  cpu: {}  io: {}  disk: {}  limits: {}  network: {}  systemd: {}  hardware: {}  kernel: {}",
        on(c.memory.enabled),
        on(c.cpu.enabled),
        on(c.io.enabled),
        on(c.disk.enabled),
        on(c.limits.enabled),
        on(c.network.enabled),
        on(c.systemd.enabled),
        on(c.hardware.enabled),
        on(c.kernel.enabled)
    );
    println!(
        "  process: {}  integrity: {}  auth: {}  fim: {} ({} sites)  heuristics: {}",
        on(c.process.enabled),
        on(c.integrity.enabled),
        on(c.auth.enabled),
        on(c.fim.enabled),
        c.fim.sites.len(),
        on(c.heuristics.enabled)
    );
    println!(
        "  policies: {}  notify: {} webhook(s), telegram {}, {} command(s)",
        c.policies.len(),
        c.notify.webhook.len(),
        on(c.notify.telegram.is_some()),
        c.notify.command.len()
    );
    let (_, errs) = warden_detect::fim::signatures::Signatures::load(&c.fim.signatures);
    for e in errs {
        println!("  WARNING: {e}");
    }
    for w in unknown_command_users(c) {
        println!("  WARNING: {w}");
    }
    Ok(())
}

/// Accounts configured for programs that this host does not know: a warning,
/// not an error (the guardian must still start; those programs fail when
/// they run, and say why).
fn unknown_command_users(c: &Config) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    c.command_users()
        .into_iter()
        .filter(|(_, u)| seen.insert(u.clone()))
        .filter_map(|(place, u)| {
            warden_sys::cmd::Credentials::lookup(&u)
                .err()
                .map(|e| format!("{place}: user {u:?}: {e} — that program will not run"))
        })
        .collect()
}

fn main() -> Result<()> {
    // the suspend-aware clock counts from here (see `warden_sys::clock`)
    warden_sys::clock::init();
    let args = Args::parse();
    if args.print_defaults {
        print!("{}", toml::to_string_pretty(&Config::default())?);
        return Ok(());
    }
    if args.check_config {
        if let Err(e) = check_config(&args.config) {
            eprintln!("{e:#}");
            std::process::exit(1);
        }
        return Ok(());
    }

    let loaded = warden_core::load::load(&args.config).with_context(|| format!("loading {}", args.config.display()))?;
    let cfg = loaded.config;
    init_logging(&cfg, args.log_level.as_deref());
    if !warden_sys::sched::is_root() {
        tracing::warn!(
            "not running as root: process actions, fanotify, proc connector and firewall will be unavailable"
        );
    }
    if warden_sys::sched::seccomp_mode() == Some(2) {
        tracing::info!(
            "running under a seccomp filter (systemd SystemCallFilter); blocked calls degrade sensors, see `wardenctl doctor`"
        );
    }
    if !warden_sys::psi::available() {
        tracing::warn!(
            "PSI is not available (kernel < 4.20, CONFIG_PSI=n or psi=0 on the command line); pressure detection degraded"
        );
    }
    for w in unknown_command_users(&cfg) {
        tracing::warn!("{w}");
    }
    #[cfg(feature = "alloc-stats")]
    warden_detect::prof::mark_tracking();
    warden_sys::selfstat::tune_malloc(cfg.daemon.malloc_arenas);
    prepare_dirs(&cfg);
    self_protect(&cfg);

    // One thread runs the engine, the control socket and the metrics
    // endpoint: they only route events and answer requests. Slow work goes
    // to a small blocking pool whose threads are kept, not re-created.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(8)
        .thread_keep_alive(Duration::from_secs(600))
        .thread_name("w-blocking")
        .build()?;
    let files: Vec<String> = loaded.files.iter().map(|p| p.display().to_string()).collect();
    rt.block_on(run(args, cfg, files))
}

/// Settings that are read once at startup and that a reload therefore does
/// not apply: the ones `old` and `new` disagree on.
fn restart_only_changes(old: &Config, new: &Config) -> Vec<&'static str> {
    let (a, b) = (&old.daemon, &new.daemon);
    let checks: [(&'static str, bool); 11] = [
        ("daemon.state_dir", a.state_dir != b.state_dir),
        ("daemon.runtime_dir", a.runtime_dir != b.runtime_dir),
        ("daemon.control_socket", a.control_socket != b.control_socket),
        ("daemon.log_level", a.log_level != b.log_level),
        ("daemon.log_format", a.log_format != b.log_format),
        ("daemon.mlock", a.mlock != b.mlock),
        ("daemon.oom_score_adj", a.oom_score_adj != b.oom_score_adj),
        ("daemon.malloc_arenas", a.malloc_arenas != b.malloc_arenas),
        ("daemon.hostname", a.hostname != b.hostname),
        ("metrics.enabled", old.metrics.enabled != new.metrics.enabled),
        ("metrics.listen", old.metrics.listen != new.metrics.listen),
    ];
    checks.into_iter().filter(|(_, changed)| *changed).map(|(n, _)| n).collect()
}

/// Hand `[daemon.pacing]` to the scans (warden-sys does not know the config).
fn apply_pacing(cfg: &Config) {
    let c = &cfg.daemon.pacing;
    warden_sys::pace::configure(warden_sys::pace::Params {
        enabled: c.enabled,
        target: c.io_pressure / 100.0,
        adaptive_class: c.io_class == warden_core::config::PacingIoClass::Adaptive,
        max_defer: c.max_defer,
        ..warden_sys::pace::Params::DEFAULT
    });
}

async fn run(args: Args, cfg: Config, files: Vec<String>) -> Result<()> {
    // configuration, `--dry-run` and a stored `wardenctl dry-run` override
    let (dry_run, dry_note) = dryrun::DryRun::load(&cfg.daemon.state_dir, cfg.daemon.dry_run, args.dry_run);
    tracing::info!(
        version = warden_core::VERSION,
        dry_run = dry_run.effective(),
        dry_run_source = dry_run.source().as_str(),
        files = ?files,
        "Warden starting"
    );
    apply_pacing(&cfg);
    let metrics_cfg = cfg.metrics.clone();
    let shared = Shared::new(cfg.clone());
    shared.dry_run.store(dry_run.effective(), Ordering::SeqCst);
    let dry_run = Arc::new(Mutex::new(dry_run));
    shared.metrics.set("warden_build_info", &[("version", warden_core::VERSION)], 1.0);

    let events = Arc::new(queue::EventQueue::new(engine::EVENT_QUEUE));
    let sink = engine::sink(shared.clone(), events.clone());

    // The action executor (two lanes) and the notifier each own a thread
    // and a bounded queue. All are supervised: a panic restarts the thread
    // instead of silently ending remediation (or notifications) for the
    // rest of the run. The lanes share budgets, cooldowns and the
    // firewall/quarantine handles; kills, stops, freezes, IP blocks and
    // quarantine take the urgent lane, so they never wait behind a
    // `systemctl restart`, `apt-get clean` or a hook in the slow one.
    let mut responder = Responder::new(&cfg);
    let mut slow_responder = responder.lane();
    let handles = responder.handles();
    let (respond_tx, respond_rx) = std::sync::mpsc::sync_channel(engine::WORKER_QUEUE);
    let (slow_tx, slow_rx) = std::sync::mpsc::sync_channel(engine::WORKER_QUEUE);
    let responder_thread = {
        let (s, b) = (shared.clone(), sink.clone());
        warden_detect::runtime::spawn_worker("respond", shared.clone(), sink.clone(), move || {
            engine::run_responder(&s, &mut responder, &respond_rx, &b)
        })?
    };
    let slow_responder_thread = {
        let (s, b) = (shared.clone(), sink.clone());
        warden_detect::runtime::spawn_worker("respond-slow", shared.clone(), sink.clone(), move || {
            engine::run_responder(&s, &mut slow_responder, &slow_rx, &b)
        })?
    };
    let (notify_tx, notify_rx) = std::sync::mpsc::sync_channel(engine::WORKER_QUEUE);
    let notifier_thread = {
        let s = shared.clone();
        warden_detect::runtime::spawn_worker("notify", shared.clone(), sink.clone(), move || {
            notify::run(&s, &notify_rx)
        })?
    };
    // Engine
    let ring: eventlog::Ring = Default::default();
    let eng = engine::Engine::new(
        shared.clone(),
        ring.clone(),
        notify_tx,
        engine::Lanes { urgent: respond_tx, slow: slow_tx },
    )?;
    tokio::spawn(engine::run(eng, events));

    // Detectors and sensors (only what the configuration enables)
    let supervisor = warden_detect::start(shared.clone(), sink.clone())?;

    // Control + metrics
    let (reload_tx, mut reload_rx) = tokio::sync::mpsc::channel::<()>(4);
    let config_files = Arc::new(Mutex::new(files));
    let ctx = server::Ctx {
        shared: shared.clone(),
        ring,
        handles,
        sink: sink.clone(),
        reload: reload_tx,
        config_files: config_files.clone(),
        running: Some(supervisor.registry.clone()),
        dry_run: dry_run.clone(),
    };
    let socket_path = cfg.daemon.control_socket.clone();
    // which socket file is ours: a daemon started while this one stops has
    // already put its own there, and must not lose it to our cleanup
    let mut socket_id = None;
    match server::bind_control(&socket_path) {
        Ok(listener) => {
            socket_id = server::file_id(&socket_path);
            tokio::spawn(server::control_server(ctx, listener));
        }
        Err(e) => tracing::error!(socket = %socket_path.display(), error = %e, "cannot create the control socket"),
    }
    if metrics_cfg.enabled {
        match tokio::net::TcpListener::bind(&metrics_cfg.listen).await {
            Ok(listener) => {
                tokio::spawn(server::metrics_server(shared.clone(), listener));
            }
            Err(e) => tracing::error!(listen = %metrics_cfg.listen, error = %e, "cannot start the metrics endpoint"),
        }
    }

    // Housekeeping: persist learned state, decay scores, publish gauges.
    {
        let s = shared.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(Duration::from_secs(60));
            loop {
                iv.tick().await;
                let s2 = s.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    if let Err(e) = lock(&s2.lineage).save() {
                        tracing::warn!(error = %e, "cannot save lineage");
                    }
                    let now = warden_sys::clock::now();
                    let mut h = lock(&s2.heuristics);
                    h.gc(now);
                    s2.metrics.set("warden_heuristics_max_score", &[], h.max_score(now));
                    s2.metrics.set("warden_dry_run", &[], if s2.is_dry_run() { 1.0 } else { 0.0 });
                })
                .await;
            }
        });
    }

    // systemd readiness + watchdog fed only while the fast scheduler is alive.
    let _ = sdnotify::notify("READY=1\nSTATUS=watching");
    if let Some(wd) = sdnotify::watchdog_interval() {
        let s = shared.clone();
        tokio::spawn(async move {
            let mut iv = tokio::time::interval(wd / 3);
            loop {
                iv.tick().await;
                let age = s.heartbeat_age().as_millis() as u64;
                if age < (wd.as_millis() as u64) / 2 {
                    let _ = sdnotify::notify("WATCHDOG=1");
                } else {
                    tracing::error!(age_ms = age, "fast scheduler heartbeat stale; withholding watchdog ping");
                }
            }
        });
    }
    sink.emit(
        Event::new(
            "warden.started",
            Severity::Info,
            format!("Warden {} started (dry_run={})", warden_core::VERSION, shared.is_dry_run()),
        )
        .source("daemon")
        .detail("dry_run", shared.is_dry_run())
        .detail("dry_run_source", lock(&dry_run).source().as_str())
        .fingerprint("warden.started"),
    );
    if let Some(c) = dry_note {
        tracing::warn!(enabled = c.enabled, source = c.source.as_str(), reason = %c.reason, "dry-run");
        sink.emit(dryrun::event(&c));
    }

    let mut hup = signal(SignalKind::hangup())?;
    let mut term = signal(SignalKind::terminate())?;
    let mut int = signal(SignalKind::interrupt())?;
    let mut usr1 = signal(SignalKind::user_defined1())?;
    loop {
        let do_reload = tokio::select! {
            _ = hup.recv() => true,
            Some(()) = reload_rx.recv() => true,
            _ = usr1.recv() => {
                tracing::info!(levels = ?*lock(&shared.levels), sensors = ?*lock(&shared.sensors), "status");
                false
            }
            _ = term.recv() => break,
            _ = int.recv() => break,
        };
        if do_reload {
            let _ = sdnotify::notify("RELOADING=1");
            match warden_core::load::load(&args.config) {
                Ok(l) => {
                    let c = l.config;
                    // a runtime override survives the reload unless the
                    // configuration's own dry_run changed
                    let dry_change = {
                        let mut d = lock(&dry_run);
                        let ch = d.reload(c.daemon.dry_run);
                        shared.dry_run.store(d.effective(), Ordering::SeqCst);
                        ch
                    };
                    if let Some(ch) = &dry_change {
                        tracing::warn!(enabled = ch.enabled, source = ch.source.as_str(), reason = %ch.reason, "dry-run");
                        sink.emit(dryrun::event(ch));
                    }
                    *lock(&config_files) = l.files.iter().map(|p| p.display().to_string()).collect();
                    let restart = restart_only_changes(&shared.config(), &c);
                    apply_pacing(&c);
                    shared.replace_config(c);
                    supervisor.reconcile();
                    let mut ev = Event::new("warden.reloaded", Severity::Info, "configuration reloaded")
                        .source("daemon")
                        .fingerprint(format!("warden.reloaded:{}", shared.generation()));
                    if restart.is_empty() {
                        tracing::info!("configuration reloaded");
                    } else {
                        // read once at startup: say so instead of ignoring the change
                        tracing::warn!(settings = ?restart, "configuration reloaded; these changes take effect after a restart");
                        ev = ev.detail("restart_required", restart.clone()).detail("hint", "systemctl restart wardend");
                        ev.severity = Severity::Notice;
                        ev.title = format!("configuration reloaded; restart to apply {}", restart.join(", "));
                    }
                    sink.emit(ev);
                }
                Err(e) => {
                    tracing::error!(error = %e, "reload failed; keeping the running configuration");
                    sink.emit(
                        Event::new(
                            "warden.reload_failed",
                            Severity::Warning,
                            format!("configuration reload failed: {e}"),
                        )
                        .source("daemon")
                        .fingerprint("warden.reload_failed"),
                    );
                }
            }
            let _ = sdnotify::notify("READY=1");
        }
    }

    tracing::info!("shutting down");
    let _ = sdnotify::notify("STOPPING=1");
    shared.begin_shutdown();
    let _ = lock(&shared.lineage).save();
    // Wait for what holds unsaved state: the FIM worker flushing baselines,
    // and the action in progress (it must not be cut off half way). Not
    // longer than the grace period: a stuck thread cannot hold up a stop.
    let deadline = Instant::now() + SHUTDOWN_GRACE;
    while Instant::now() < deadline
        && (!supervisor.registry.running().is_empty()
            || !responder_thread.is_finished()
            || !slow_responder_thread.is_finished()
            || !notifier_thread.is_finished())
    {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    let busy = supervisor.registry.running();
    let responder_busy = !responder_thread.is_finished() || !slow_responder_thread.is_finished();
    if !busy.is_empty() || responder_busy {
        tracing::warn!(components = ?busy, responder_busy, "stopping with threads still busy");
    }
    if socket_id.is_some() && server::file_id(&socket_path) == socket_id {
        let _ = std::fs::remove_file(&socket_path);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reload_names_the_settings_that_need_a_restart() {
        let a = Config::default();
        assert!(restart_only_changes(&a, &a).is_empty());
        let mut b = a.clone();
        b.metrics.listen = "127.0.0.1:9999".into();
        b.daemon.mlock = !a.daemon.mlock;
        b.memory.sustain = Duration::from_secs(1); // applied by a reload
        assert_eq!(restart_only_changes(&a, &b), ["daemon.mlock", "metrics.listen"]);
    }
}
