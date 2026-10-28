//! # warden-detect
//!
//! Everything that *observes*: polling detectors (run by two schedulers —
//! a fast, latency-critical one and a slow one for heavier scans) and
//! event-driven sensors (each in its own supervised thread).
//!
//! Only what the configuration enables is started: a disabled module has
//! no thread, no timer and no memory (see [`COMPONENTS`]).
//!
//! ```text
//!  fast scheduler (1s tick, stall detection)   slow scheduler
//!  ├─ memory  (PSI, swap storm, culprits)      ├─ disk (space, inodes, ro, prediction)
//!  ├─ cpu     (PSI, load, iowait, forks)       ├─ process (reverse shells, miners, hogs…)
//!  ├─ io      (PSI, top I/O processes)         ├─ integrity (system files, SUID, listeners)
//!  ├─ limits  (fds, pids, conntrack)           └─ systemd (failed units, auto-restart)
//!  ├─ network (overflows, SYN flood, errors)
//!  ├─ hardware (EDAC, thermal, clock)          sensors (threads)
//!  └─ kernel_state (taint, modules, LSM)       ├─ psi_trigger   ├─ kmsg
//!                                              ├─ proc_connector├─ auth
//!                                              ├─ fim (worker)  ├─ fim_realtime
//!                                              └─ access_log
//! ```
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod auth;
pub mod disk;
pub mod fim;
pub mod hardware;
pub mod health;
pub mod heuristics;
pub mod integrity;
pub mod kernel;
pub mod limits;
pub mod memory;
pub mod pressure;
pub mod process;
pub mod prof;
pub mod runtime;
pub mod systemd;
pub mod tuning;
pub mod util;
pub mod waf;
pub mod waf_discover;
pub mod waf_sources;

pub use runtime::{Cx, Detector, Metrics, SensorState, Shared, Sink, Wake};

pub use prof::TrackingAlloc;

use std::sync::Arc;
use warden_core::Config;
use warden_core::protect::Protection;

/// Latency-critical detectors (cheap reads of /proc and /sys only).
pub fn fast_detectors(cfg: &Config) -> Vec<Box<dyn Detector>> {
    let mut v: Vec<Box<dyn Detector>> = Vec::new();
    if cfg.memory.enabled {
        v.push(Box::new(memory::MemoryDetector::new(&cfg.memory, Protection::new(&cfg.protection))));
    }
    if cfg.cpu.enabled {
        v.push(Box::new(pressure::CpuDetector::new(&cfg.cpu)));
    }
    if cfg.io.enabled {
        v.push(Box::new(pressure::IoDetector::new(&cfg.io)));
    }
    if cfg.limits.enabled {
        v.push(Box::new(limits::LimitsDetector::new(&cfg.limits)));
    }
    if cfg.network.enabled {
        v.push(Box::new(limits::NetworkDetector::new(&cfg.network)));
    }
    if cfg.hardware.enabled {
        v.push(Box::new(hardware::HardwareDetector::new(&cfg.hardware)));
    }
    if cfg.kernel.enabled {
        v.push(Box::new(kernel::KernelStateDetector::new(&cfg.kernel)));
    }
    v
}

/// Heavier detectors that may block on filesystems or subprocesses.
pub fn slow_detectors(cfg: &Config) -> Vec<Box<dyn Detector>> {
    let mut v: Vec<Box<dyn Detector>> = Vec::new();
    if cfg.disk.enabled {
        v.push(Box::new(disk::DiskDetector::new(&cfg.disk).persisted(cfg.daemon.state_dir.join("disk-cleanups.json"))));
    }
    if cfg.process.enabled {
        v.push(Box::new(process::ProcessScanner::new(cfg)));
    }
    if cfg.integrity.enabled {
        v.push(Box::new(integrity::IntegrityDetector::new(cfg)));
    }
    if cfg.systemd.enabled {
        v.push(Box::new(systemd::SystemdDetector::new(&cfg.systemd)));
    }
    if cfg.tuning.advise {
        v.push(Box::new(tuning::TuningDetector::new(&cfg.tuning)));
    }
    v
}

fn slow_wanted(c: &Config) -> bool {
    c.disk.enabled || c.process.enabled || c.integrity.enabled || c.systemd.enabled || c.tuning.advise
}
fn health_wanted(c: &Config) -> bool {
    c.health.enabled && !c.health.checks.is_empty()
}
fn psi_wanted(c: &Config) -> bool {
    c.memory.enabled && c.memory.trigger.enabled
}
fn kmsg_wanted(c: &Config) -> bool {
    c.kernel.enabled && c.kernel.kmsg
}
fn auth_wanted(c: &Config) -> bool {
    c.auth.enabled
}
fn exec_wanted(c: &Config) -> bool {
    c.process.enabled && c.process.proc_connector
}
fn access_wanted(c: &Config) -> bool {
    c.fim.enabled && c.fim.sites.iter().any(|s| s.access_log.is_some())
}
fn waf_wanted(c: &Config) -> bool {
    c.waf.enabled && (!c.waf.logs.is_empty() || (c.waf.discover && waf_discover::web_server_present()))
}
fn fim_wanted(c: &Config) -> bool {
    c.fim.enabled && !c.fim.sites.is_empty()
}
fn suid_realtime_wanted(c: &Config) -> bool {
    c.integrity.enabled && c.integrity.suid_scan && c.integrity.suid_realtime
}
fn systemd_dbus_wanted(c: &Config) -> bool {
    // No thread at all on hosts without systemd (containers, other inits).
    c.systemd.enabled && c.systemd.dbus && std::path::Path::new("/run/systemd/system").exists()
}
fn fim_realtime_wanted(c: &Config) -> bool {
    fim_wanted(c) && c.fim.realtime
}

type Handle = std::io::Result<std::thread::JoinHandle<()>>;

fn spawn_slow(shared: Arc<Shared>, sink: Sink, lease: runtime::Lease) -> Handle {
    let mut s = runtime::Scheduler::new("slow", shared, sink, Box::new(slow_detectors));
    s.lease = Some(lease);
    std::thread::Builder::new().name("w-sched-slow".into()).spawn(move || s.run())
}
fn spawn_health(shared: Arc<Shared>, sink: Sink, lease: runtime::Lease) -> Handle {
    // Own thread: a hung endpoint must not delay disk or process checks.
    let mut s = runtime::Scheduler::new("health", shared, sink, Box::new(health::detectors));
    s.lease = Some(lease);
    std::thread::Builder::new().name("w-sched-health".into()).spawn(move || s.run())
}
fn spawn_psi(shared: Arc<Shared>, _: Sink, lease: runtime::Lease) -> Handle {
    runtime::spawn_sensor("psi_trigger", shared, Some(lease), memory::run_psi_trigger)
}
fn spawn_kmsg(shared: Arc<Shared>, sink: Sink, lease: runtime::Lease) -> Handle {
    runtime::spawn_sensor("kmsg", shared, Some(lease), move |sh| kernel::run_kmsg(sh, &sink))
}
fn spawn_auth(shared: Arc<Shared>, sink: Sink, lease: runtime::Lease) -> Handle {
    runtime::spawn_sensor("auth", shared, Some(lease), move |sh| auth::run_auth(sh, &sink))
}
fn spawn_exec(shared: Arc<Shared>, sink: Sink, lease: runtime::Lease) -> Handle {
    runtime::spawn_sensor("proc_connector", shared, Some(lease), move |sh| process::run_exec_sensor(sh, &sink))
}
fn spawn_access(shared: Arc<Shared>, _: Sink, lease: runtime::Lease) -> Handle {
    runtime::spawn_sensor("access_log", shared, Some(lease), fim::correlate::run_access_tail)
}
fn spawn_waf(shared: Arc<Shared>, sink: Sink, lease: runtime::Lease) -> Handle {
    runtime::spawn_sensor("waf", shared, Some(lease), move |sh| waf::run_waf(sh, &sink))
}
fn spawn_fim(shared: Arc<Shared>, sink: Sink, lease: runtime::Lease) -> Handle {
    // The channel exists before the thread does, so `fim_realtime` (started
    // right after) and the control socket can use it immediately.
    let (tx, rx) = std::sync::mpsc::channel();
    let token = shared.fim_token.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
    *runtime::lock(&shared.fim_tx) = Some(tx.clone());
    std::thread::Builder::new().name("w-fim".into()).spawn(move || {
        prof::set_thread_scope(prof::scope_id("fim"));
        shared.set_sensor("fim", SensorState::Running);
        let worker = fim::FimWorker::new(shared.clone(), sink);
        worker.run(rx, tx, token, lease);
    })
}
fn spawn_suid_realtime(shared: Arc<Shared>, _: Sink, lease: runtime::Lease) -> Handle {
    runtime::spawn_sensor("suid_realtime", shared, Some(lease), integrity::run_suid_realtime)
}
fn spawn_systemd_dbus(shared: Arc<Shared>, sink: Sink, lease: runtime::Lease) -> Handle {
    runtime::spawn_sensor("systemd_dbus", shared, Some(lease), move |sh| systemd::run_systemd_sensor(sh, &sink))
}
fn spawn_fim_realtime(shared: Arc<Shared>, _: Sink, lease: runtime::Lease) -> Handle {
    runtime::spawn_sensor("fim_realtime", shared, Some(lease), fim::run_realtime)
}

/// Everything that runs in its own thread, in start order. A component the
/// configuration does not want is not started at all — no thread, no
/// buffers, no compiled rules — and stops when a reload disables it.
pub const COMPONENTS: &[runtime::Component] = &[
    runtime::Component { name: "slow", sensor: false, wanted: slow_wanted, spawn: spawn_slow },
    runtime::Component { name: "health", sensor: false, wanted: health_wanted, spawn: spawn_health },
    runtime::Component { name: "psi_trigger", sensor: true, wanted: psi_wanted, spawn: spawn_psi },
    runtime::Component { name: "kmsg", sensor: true, wanted: kmsg_wanted, spawn: spawn_kmsg },
    runtime::Component { name: "auth", sensor: true, wanted: auth_wanted, spawn: spawn_auth },
    runtime::Component { name: "proc_connector", sensor: true, wanted: exec_wanted, spawn: spawn_exec },
    runtime::Component { name: "access_log", sensor: true, wanted: access_wanted, spawn: spawn_access },
    runtime::Component { name: "waf", sensor: true, wanted: waf_wanted, spawn: spawn_waf },
    runtime::Component { name: "fim", sensor: true, wanted: fim_wanted, spawn: spawn_fim },
    runtime::Component { name: "fim_realtime", sensor: true, wanted: fim_realtime_wanted, spawn: spawn_fim_realtime },
    runtime::Component {
        name: "suid_realtime",
        sensor: true,
        wanted: suid_realtime_wanted,
        spawn: spawn_suid_realtime,
    },
    runtime::Component { name: "systemd_dbus", sensor: true, wanted: systemd_dbus_wanted, spawn: spawn_systemd_dbus },
];

/// Handle to the running detectors; call [`Supervisor::reconcile`] after
/// every configuration change.
pub struct Supervisor {
    shared: Arc<Shared>,
    sink: Sink,
    pub registry: runtime::Registry,
}

impl Supervisor {
    pub fn reconcile(&self) {
        self.registry.reconcile(&self.shared, &self.sink, COMPONENTS);
    }
}

/// Start the fast scheduler (always: it feeds the systemd watchdog) and
/// every component the configuration enables.
pub fn start(shared: Arc<Shared>, sink: Sink) -> std::io::Result<Supervisor> {
    let mut fast = runtime::Scheduler::new("fast", shared.clone(), sink.clone(), Box::new(fast_detectors));
    fast.stall_detection = true;
    std::thread::Builder::new().name("w-sched-fast".into()).spawn(move || fast.run())?;
    let sup = Supervisor { shared, sink, registry: runtime::Registry::default() };
    sup.reconcile();
    Ok(sup)
}
