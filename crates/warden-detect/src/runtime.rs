//! Runtime plumbing shared by all detectors and sensors: the event sink,
//! shared state, metrics registry, the polling scheduler and the sensor
//! supervisor.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Condvar, Mutex, RwLock};
use std::time::{Duration, Instant};
use warden_core::{Config, Event, Severity};

pub use warden_core::sync::lock;
use warden_core::sync::{read, write};

// ---------------------------------------------------------------------------
// Sink
// ---------------------------------------------------------------------------

/// Where detectors send events. Never blocks: the daemon side uses a bounded
/// queue and counts drops.
#[derive(Clone)]
pub struct Sink {
    f: Arc<dyn Fn(Event) + Send + Sync>,
}

impl std::fmt::Debug for Sink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sink")
    }
}

impl Sink {
    pub fn new(f: impl Fn(Event) + Send + Sync + 'static) -> Self {
        Self { f: Arc::new(f) }
    }

    pub fn emit(&self, ev: Event) {
        (self.f)(ev)
    }

    /// A sink that stores events (tests, `wardenctl` offline tools).
    pub fn collector() -> (Self, Arc<Mutex<Vec<Event>>>) {
        let store = Arc::new(Mutex::new(Vec::new()));
        let s = store.clone();
        (Self::new(move |e| lock(&s).push(e)), store)
    }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct Metrics {
    values: Mutex<BTreeMap<String, (String, f64)>>,
}

fn escape_label(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

fn unescape_label(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut chars = v.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n') => out.push('\n'),
                Some(o) => out.push(o),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

fn key(name: &str, labels: &[(&str, &str)]) -> String {
    if labels.is_empty() {
        return name.to_owned();
    }
    let l: Vec<String> = labels.iter().map(|(k, v)| format!("{k}=\"{}\"", escape_label(v))).collect();
    format!("{name}{{{}}}", l.join(","))
}

impl Metrics {
    pub fn set(&self, name: &str, labels: &[(&str, &str)], v: f64) {
        lock(&self.values).insert(key(name, labels), (name.to_owned(), v));
    }

    pub fn inc(&self, name: &str, labels: &[(&str, &str)], by: f64) {
        let mut m = lock(&self.values);
        let e = m.entry(key(name, labels)).or_insert_with(|| (name.to_owned(), 0.0));
        e.1 += by;
    }

    pub fn get(&self, name: &str, labels: &[(&str, &str)]) -> Option<f64> {
        lock(&self.values).get(&key(name, labels)).map(|v| v.1)
    }

    /// Drop all series of a metric whose label set contains `label=value`.
    /// The values `label` has in the series of metric `name`.
    pub fn label_values(&self, name: &str, label: &str) -> Vec<String> {
        let needle = format!("{label}=\"");
        lock(&self.values)
            .iter()
            .filter(|(_, v)| v.0 == name)
            .filter_map(|(k, _)| {
                let at = k.find(&needle)? + needle.len();
                let rest = &k[at..];
                // values are escaped: an unescaped quote ends them
                let mut end = None;
                let mut esc = false;
                for (i, ch) in rest.char_indices() {
                    match ch {
                        '\\' if !esc => esc = true,
                        '"' if !esc => {
                            end = Some(i);
                            break;
                        }
                        _ => esc = false,
                    }
                }
                Some(unescape_label(&rest[..end?]))
            })
            .collect()
    }

    pub fn remove_matching(&self, name: &str, label: &str, value: &str) {
        let needle = format!("{label}=\"{}\"", escape_label(value));
        lock(&self.values).retain(|k, v| !(v.0 == name && k.contains(&needle)));
    }

    /// Prometheus text exposition format.
    pub fn render(&self) -> String {
        let m = lock(&self.values);
        let mut out = String::with_capacity(m.len() * 64);
        let mut last = "";
        for (k, (name, v)) in m.iter() {
            if name != last {
                let kind = if name.ends_with("_total") { "counter" } else { "gauge" };
                out.push_str(&format!("# TYPE {name} {kind}\n"));
                last = name;
            }
            if v.is_finite() {
                out.push_str(&format!("{k} {v}\n"));
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Shared state
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum SensorState {
    Starting,
    Running,
    Unavailable(String),
    Failed(String),
    Disabled,
}

/// Messages that wake the polling scheduler early.
#[derive(Debug, Clone)]
pub enum Wake {
    /// Run this detector now (e.g. a PSI trigger fired).
    Detector(&'static str),
    /// The configuration changed: rebuild detectors now.
    Reload,
    Shutdown,
}

/// Intern a short name as `&'static str` (detector names built from
/// configuration, e.g. health checks): leaked once per distinct name, not
/// once per reload.
pub fn intern(s: &str) -> &'static str {
    static NAMES: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
    let mut v = lock(&NAMES);
    if let Some(n) = v.iter().find(|n| **n == s) {
        return n;
    }
    let n: &'static str = Box::leak(s.to_owned().into_boxed_str());
    v.push(n);
    n
}

#[derive(Debug)]
pub struct Shared {
    config: RwLock<Arc<Config>>,
    generation: AtomicU64,
    pub metrics: Metrics,
    pub dry_run: AtomicBool,
    pub started: Instant,
    pub hostname: String,
    /// Recent kernel messages for diagnostic snapshots.
    pub kmsg_tail: Mutex<VecDeque<String>>,
    pub sensors: Mutex<BTreeMap<String, SensorState>>,
    /// Current level of each threshold detector (for `wardenctl status`).
    pub levels: Mutex<BTreeMap<String, String>>,
    pub users: Mutex<warden_sys::users::Users>,
    pub culprits: Mutex<Vec<crate::memory::Culprit>>,
    pub access: crate::fim::correlate::AccessLogs,
    pub waf: crate::waf::WafRecent,
    /// The logs the WAF sensor follows (for `wardenctl status` and `doctor`).
    pub waf_sources: Mutex<serde_json::Value>,
    /// Real-time SUID sensor ↔ integrity detector.
    pub suid_rt: Mutex<crate::integrity::SuidRealtime>,
    /// Failed systemd units, shared by the D-Bus sensor and the polling detector.
    pub systemd: Mutex<crate::systemd::UnitState>,
    /// Latest tuning recommendations (for `wardenctl tuning`).
    pub advice: Mutex<serde_json::Value>,
    pub lineage: Mutex<crate::heuristics::Lineage>,
    pub heuristics: Mutex<crate::heuristics::Heuristics>,
    pub fim_tx: Mutex<Option<Sender<crate::fim::FimMsg>>>,
    /// Identifies the FIM worker that owns `fim_tx`.
    pub fim_token: AtomicU64,
    pub dropped_events: AtomicU64,
    /// Updated by the fast scheduler on every loop ([`Shared::beat`]); the
    /// systemd watchdog is only fed while this keeps moving. Milliseconds
    /// since `started` on the monotonic clock: a wall-clock step (NTP, a
    /// resume from suspend) is not a stalled scheduler. (0.13.3 used the
    /// wall clock: such a step withheld `WATCHDOG=1` and made `/health`
    /// answer 503.)
    heartbeat_ms: AtomicU64,
    wake: Mutex<Vec<Sender<Wake>>>,
    reload_mx: Mutex<()>,
    reload_cv: Condvar,
    this: Mutex<std::sync::Weak<Shared>>,
    pub shutdown: AtomicBool,
}

impl Shared {
    pub fn new(config: Config) -> Arc<Self> {
        let hostname = config.daemon.hostname.clone().unwrap_or_else(warden_sys::system::hostname);
        let lineage = crate::heuristics::Lineage::new(
            Some(config.daemon.state_dir.join("lineage.json")),
            config.heuristics.lineage_learning,
            config.heuristics.lineage,
        );
        let mut heuristics = crate::heuristics::Heuristics::new(&config.heuristics);
        heuristics.set_ipv6_prefix(config.actions.firewall.ipv6_prefix);
        let waf = crate::waf::WafRecent::default();
        waf.set_ipv6_prefix(config.actions.firewall.ipv6_prefix);
        let sh = Arc::new(Self {
            this: Mutex::new(std::sync::Weak::new()),
            lineage: Mutex::new(lineage),
            heuristics: Mutex::new(heuristics),
            fim_tx: Mutex::new(None),
            fim_token: AtomicU64::new(0),
            dry_run: AtomicBool::new(config.daemon.dry_run),
            config: RwLock::new(Arc::new(config)),
            generation: AtomicU64::new(1),
            metrics: Metrics::default(),
            started: Instant::now(),
            hostname,
            kmsg_tail: Mutex::new(VecDeque::new()),
            sensors: Mutex::new(BTreeMap::new()),
            levels: Mutex::new(BTreeMap::new()),
            users: Mutex::new(warden_sys::users::Users::load()),
            culprits: Mutex::new(Vec::new()),
            access: Default::default(),
            waf,
            waf_sources: Mutex::new(serde_json::json!({ "sources": [], "problems": [] })),
            suid_rt: Mutex::new(Default::default()),
            systemd: Mutex::new(Default::default()),
            advice: Mutex::new(serde_json::Value::Array(Vec::new())),
            dropped_events: AtomicU64::new(0),
            heartbeat_ms: AtomicU64::new(0),
            wake: Mutex::new(Vec::new()),
            reload_mx: Mutex::new(()),
            reload_cv: Condvar::new(),
            shutdown: AtomicBool::new(false),
        });
        *lock(&sh.this) = Arc::downgrade(&sh);
        sh
    }

    pub fn config(&self) -> Arc<Config> {
        read(&self.config).clone()
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::SeqCst)
    }

    /// Install a new configuration and wake everything that caches it:
    /// schedulers rebuild their detectors, sensors restart, the FIM worker
    /// reloads its sites.
    pub fn replace_config(&self, c: Config) {
        // tables keyed by address follow the aggregation they were built with
        let prefix = c.actions.firewall.ipv6_prefix;
        lock(&self.heuristics).set_ipv6_prefix(prefix);
        self.waf.set_ipv6_prefix(prefix);
        *write(&self.config) = Arc::new(c);
        self.generation.fetch_add(1, Ordering::SeqCst);
        self.notify_all();
    }

    fn notify_all(&self) {
        {
            let _g = lock(&self.reload_mx);
            self.reload_cv.notify_all();
        }
        self.wake(Wake::Reload);
        if let Some(tx) = lock(&self.fim_tx).as_ref() {
            let _ = tx.send(crate::fim::FimMsg::Reload);
        }
    }

    /// Begin shutdown: every thread is woken and exits.
    pub fn begin_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        self.wake(Wake::Shutdown);
        {
            let _g = lock(&self.reload_mx);
            self.reload_cv.notify_all();
        }
        if let Some(tx) = lock(&self.fim_tx).as_ref() {
            let _ = tx.send(crate::fim::FimMsg::Reload);
        }
    }

    /// Sleep until the configuration generation differs from `generation`,
    /// shutdown starts, or `timeout` passes. No polling.
    pub fn wait_reload(&self, generation: u64, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let mut g = lock(&self.reload_mx);
        while self.generation() == generation && !self.is_shutting_down() {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return;
            }
            g = self.reload_cv.wait_timeout(g, left).map(|(g, _)| g).unwrap_or_else(|e| e.into_inner().0);
        }
    }

    pub fn is_dry_run(&self) -> bool {
        self.dry_run.load(Ordering::Relaxed)
    }

    pub fn set_sensor(&self, name: &str, st: SensorState) {
        let up = matches!(st, SensorState::Running);
        lock(&self.sensors).insert(name.to_owned(), st);
        self.metrics.set("warden_sensor_up", &[("sensor", name)], if up { 1.0 } else { 0.0 });
    }

    pub fn sensor_running(&self, name: &str) -> bool {
        matches!(lock(&self.sensors).get(name), Some(SensorState::Running))
    }

    pub fn set_level(&self, name: &str, level: &str) {
        lock(&self.levels).insert(name.to_owned(), level.to_owned());
    }

    /// The fast scheduler is alive (see `heartbeat_ms`).
    pub fn beat(&self) {
        self.heartbeat_ms.store(self.started.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    /// How long ago the fast scheduler last ran, on the monotonic clock.
    pub fn heartbeat_age(&self) -> Duration {
        let last = Duration::from_millis(self.heartbeat_ms.load(Ordering::Relaxed));
        self.started.elapsed().saturating_sub(last)
    }

    pub fn push_kmsg(&self, line: String) {
        let mut q = lock(&self.kmsg_tail);
        q.push_back(line);
        while q.len() > 500 {
            q.pop_front();
        }
    }

    pub fn register_wake(&self, tx: Sender<Wake>) {
        lock(&self.wake).push(tx);
    }

    pub fn wake(&self, w: Wake) {
        lock(&self.wake).retain(|tx| tx.send(w.clone()).is_ok());
    }

    pub fn user_name(&self, uid: u32) -> String {
        let mut u = lock(&self.users);
        if u.name(uid).is_none() {
            u.refresh();
        }
        u.display(uid)
    }

    pub fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    /// The registry, for helper threads that outlive a detector tick.
    pub fn metrics_handle(&self) -> Option<Arc<Shared>> {
        lock(&self.this).upgrade()
    }
}

// ---------------------------------------------------------------------------
// Detectors + scheduler
// ---------------------------------------------------------------------------

/// Execution context handed to a detector tick.
pub struct Cx<'a> {
    /// Monotonic "now" (stops during suspend): sustain, hysteresis, rates.
    pub now: Instant,
    /// "Now" on [`warden_sys::clock`], which keeps running during suspend:
    /// back-offs, schedules and ages the operator configures and reads in
    /// real time. Compare only with instants taken from the same clock.
    pub real: Instant,
    pub shared: &'a Shared,
    pub cfg: &'a Config,
    sink: &'a Sink,
    source: &'static str,
}

impl<'a> Cx<'a> {
    /// A context outside a scheduler (tests, one-shot tools).
    pub fn new(shared: &'a Shared, cfg: &'a Config, sink: &'a Sink, source: &'static str) -> Self {
        Self { now: Instant::now(), real: warden_sys::clock::now(), shared, cfg, sink, source }
    }

    pub fn emit(&self, mut ev: Event) {
        if ev.source.is_empty() {
            ev.source = self.source.to_owned();
        }
        self.sink.emit(ev);
    }

    pub fn metric(&self, name: &str, labels: &[(&str, &str)], v: f64) {
        self.shared.metrics.set(name, labels, v);
    }
}

/// A polling detector. `tick` must be fast and must not block on I/O that
/// can hang (network filesystems, subprocesses without timeouts).
pub trait Detector: Send {
    fn name(&self) -> &'static str;
    /// Profiling/heap scope; detectors of one kind (health checks) share it.
    fn module(&self) -> &'static str {
        self.name()
    }
    fn interval(&self) -> Duration;
    fn tick(&mut self, cx: &mut Cx<'_>);

    /// The parts of the configuration the detector is built from, as JSON
    /// pointers into it (`/memory`, `/protection`, `/daemon/state_dir`). A
    /// reload that changes none of them keeps the running detector exactly
    /// as it is — its levels, open conditions, learned baselines, schedules.
    fn sections(&self) -> &'static [&'static str];

    /// A reload changed one of [`Detector::sections`]: adopt `cfg` and keep
    /// what was learned. `false` when the detector cannot; it is then
    /// replaced by a new one, after [`Detector::close`].
    fn reconfigure(&mut self, _cfg: &Config) -> bool {
        false
    }

    /// The detector is about to be dropped (disabled by a reload, or
    /// replaced): the resolutions of the conditions it has open, so that
    /// none is left open for ever.
    fn close(&mut self) -> Vec<Event> {
        Vec::new()
    }
}

/// Do two configurations agree on `sections` (JSON pointers)?
pub fn same_sections(sections: &[&str], a: &serde_json::Value, b: &serde_json::Value) -> bool {
    sections.iter().all(|p| a.pointer(p) == b.pointer(p))
}

/// The title of a resolution sent because a detector stopped watching.
pub const NO_LONGER_WATCHED: &str = "no longer watched: the detector was disabled or rebuilt by a reload";

/// The resolution of a level-tracked condition whose detector stops
/// watching it (`fingerprint` without `:resolved`); `None` when it is OK.
pub fn close_level(kind: &str, fingerprint: &str, t: &warden_core::LevelTracker) -> Option<Event> {
    (t.level() > warden_core::Level::Ok).then(|| {
        Event::new(kind, Severity::Info, format!("{kind}: {NO_LONGER_WATCHED}"))
            .fingerprint(format!("{fingerprint}:resolved"))
            .detail("episode_seconds", t.episode_duration(Instant::now()).as_secs())
            .resolved()
    })
}

pub type Factory = Box<dyn Fn(&Config) -> Vec<Box<dyn Detector>> + Send>;

struct Slot {
    det: Box<dyn Detector>,
    scope: u8,
    next: Instant,
    disabled_until: Option<Instant>,
    panics: u32,
}

// ---------------------------------------------------------------------------
// Component registry: a module that is disabled has no thread at all
// ---------------------------------------------------------------------------

/// Running component threads by name. A component is started by
/// [`Registry::reconcile`] when the configuration wants it and stops itself
/// (through its [`Lease`]) when the configuration no longer does.
#[derive(Clone, Default)]
pub struct Registry {
    inner: Arc<Mutex<BTreeMap<&'static str, std::thread::JoinHandle<()>>>>,
}

/// A component's right to keep running.
pub struct Lease {
    pub name: &'static str,
    wanted: fn(&Config) -> bool,
    reg: Registry,
    shared: Arc<Shared>,
}

impl Lease {
    pub fn wanted(&self) -> bool {
        (self.wanted)(&self.shared.config()) && !self.shared.is_shutting_down()
    }

    /// The component has nothing to do. Returns `true` if it must exit now
    /// (it has been deregistered), `false` if a newer configuration wants it
    /// again. Checked under the registry lock, so a concurrent
    /// [`Registry::reconcile`] either sees the thread gone and starts a new
    /// one, or the thread sees the new configuration and carries on.
    pub fn release(&self) -> bool {
        let mut m = lock(&self.reg.inner);
        if self.wanted() {
            return false;
        }
        m.remove(self.name);
        true
    }
}

/// How to run one component.
pub struct Component {
    pub name: &'static str,
    /// Listed in `wardenctl status` sensors (schedulers are not).
    pub sensor: bool,
    pub wanted: fn(&Config) -> bool,
    pub spawn: fn(Arc<Shared>, Sink, Lease) -> std::io::Result<std::thread::JoinHandle<()>>,
}

impl Registry {
    /// Start every wanted component that is not running. Call after
    /// startup and after each configuration change.
    pub fn reconcile(&self, shared: &Arc<Shared>, sink: &Sink, components: &[Component]) {
        let cfg = shared.config();
        let mut m = lock(&self.inner);
        m.retain(|_, h| !h.is_finished());
        for c in components {
            if m.contains_key(c.name) || shared.is_shutting_down() {
                continue;
            }
            if !(c.wanted)(&cfg) {
                if c.sensor {
                    let state = lock(&shared.sensors).get(c.name).cloned();
                    if state != Some(SensorState::Disabled) {
                        shared.set_sensor(c.name, SensorState::Disabled);
                    }
                }
                continue;
            }
            let lease = Lease { name: c.name, wanted: c.wanted, reg: self.clone(), shared: shared.clone() };
            match (c.spawn)(shared.clone(), sink.clone(), lease) {
                Ok(h) => {
                    m.insert(c.name, h);
                }
                Err(e) => tracing::error!(component = c.name, error = %e, "cannot start thread"),
            }
        }
    }

    pub fn running(&self) -> Vec<&'static str> {
        lock(&self.inner).iter().filter(|(_, h)| !h.is_finished()).map(|(n, _)| *n).collect()
    }
}

/// Runs a set of polling detectors in one thread.
pub struct Scheduler {
    pub name: &'static str,
    shared: Arc<Shared>,
    sink: Sink,
    factory: Factory,
    wake_rx: Receiver<Wake>,
    /// Measure wake-up lateness to detect host-wide stalls, and keep the
    /// heartbeat the systemd watchdog depends on.
    pub stall_detection: bool,
    /// Exit when the configuration leaves this scheduler without detectors.
    pub lease: Option<Lease>,
}

/// With stall detection off the fast scheduler still refreshes the
/// heartbeat at least this often (WatchdogSec=30s needs < 15s).
const HEARTBEAT_MAX: Duration = Duration::from_secs(5);

impl Scheduler {
    pub fn new(name: &'static str, shared: Arc<Shared>, sink: Sink, factory: Factory) -> Self {
        let (tx, rx) = std::sync::mpsc::channel();
        shared.register_wake(tx);
        Self { name, shared, sink, factory, wake_rx: rx, stall_detection: false, lease: None }
    }

    fn slot(det: Box<dyn Detector>) -> Slot {
        Slot { scope: crate::prof::scope_id(det.module()), det, next: Instant::now(), disabled_until: None, panics: 0 }
    }

    fn build(&self, cfg: &Config) -> Vec<Slot> {
        (self.factory)(cfg).into_iter().map(Self::slot).collect()
    }

    /// A reload: keep every detector whose configuration did not change,
    /// let the others adopt the new one ([`Detector::reconfigure`]), and
    /// only rebuild what cannot — closing its open conditions first. (0.13.3
    /// rebuilt everything: open incidents were never resolved, a condition
    /// still holding was raised anew, the process scan was a "first scan"
    /// again and a critical disk started a new `du` walk on every reload.)
    fn rebuild(&self, old: Vec<Slot>, old_cfg: &serde_json::Value, cfg: &Config) -> Vec<Slot> {
        let new_cfg = serde_json::to_value(cfg).unwrap_or_default();
        let mut old: HashMap<&'static str, Slot> = old.into_iter().map(|s| (s.det.name(), s)).collect();
        let (mut kept, mut adopted, mut rebuilt) = (Vec::new(), Vec::new(), Vec::new());
        let mut out = Vec::new();
        for det in (self.factory)(cfg) {
            let name = det.name();
            let Some(mut slot) = old.remove(name) else {
                out.push(Self::slot(det)); // newly enabled
                continue;
            };
            if same_sections(det.sections(), old_cfg, &new_cfg) {
                kept.push(name);
                out.push(slot);
            } else if slot.det.reconfigure(cfg) {
                adopted.push(name);
                out.push(slot);
            } else {
                self.close(&mut slot);
                rebuilt.push(name);
                out.push(Self::slot(det));
            }
        }
        let mut removed = Vec::new();
        for (name, mut slot) in old {
            self.close(&mut slot);
            lock(&self.shared.levels).remove(name);
            self.shared.metrics.remove_matching("warden_detector_tick_seconds", "detector", name);
            removed.push(name);
        }
        tracing::info!(scheduler = self.name, ?kept, ?adopted, ?rebuilt, ?removed, "configuration reloaded");
        out
    }

    fn close(&self, slot: &mut Slot) {
        let name = slot.det.name();
        for mut ev in slot.det.close() {
            if ev.source.is_empty() {
                ev.source = name.to_owned();
            }
            ev = ev.detail("closed_by", "reload");
            self.sink.emit(ev);
        }
    }

    pub fn run(self) {
        let mut cfg = self.shared.config();
        let mut cfg_json = serde_json::to_value(&*cfg).unwrap_or_default();
        let mut generation = self.shared.generation();
        let mut slots = self.build(&cfg);
        tracing::info!(scheduler = self.name, detectors = ?slots.iter().map(|s| s.det.name()).collect::<Vec<_>>(), "scheduler started");
        let mut last_stall_report: Option<Instant> = None;
        let mut steal_before: Option<u64> = None;

        loop {
            if self.shared.is_shutting_down() {
                break;
            }
            if self.stall_detection {
                self.shared.beat();
            }
            if self.shared.generation() != generation {
                generation = self.shared.generation();
                cfg = self.shared.config();
                slots = self.rebuild(slots, &cfg_json, &cfg);
                cfg_json = serde_json::to_value(&*cfg).unwrap_or_default();
            }
            if slots.is_empty()
                && let Some(l) = &self.lease
            {
                if l.release() {
                    tracing::info!(scheduler = self.name, "no detectors enabled; scheduler thread stopped");
                    return;
                }
                // Wanted, but nothing to run yet: wait for the next reload.
                if let Ok(Wake::Shutdown) = self.wake_rx.recv_timeout(Duration::from_secs(3600)) {
                    break;
                }
                continue;
            }

            let now = Instant::now();
            // Sleep until the next detector is due — no fixed polling. Only
            // the fast scheduler wakes regularly: stall detection measures
            // how late a 1 s sleep returns, and the watchdog heartbeat must
            // stay fresh.
            let cap = if self.stall_detection {
                if cfg.stall.enabled { cfg.daemon.tick } else { HEARTBEAT_MAX }
            } else {
                Duration::from_secs(3600)
            };
            let next_due = slots.iter().map(|s| s.disabled_until.map_or(s.next, |d| d.max(s.next))).min();
            let wait = next_due.map_or(cap, |t| t.saturating_duration_since(now)).min(cap);
            let planned = now + wait;

            let mut forced: Option<&'static str> = None;
            if self.stall_detection && cfg.stall.enabled {
                steal_before = warden_sys::system::steal_ticks();
            }
            match self.wake_rx.recv_timeout(wait) {
                Ok(Wake::Shutdown) => break,
                Ok(Wake::Reload) => continue,
                Ok(Wake::Detector(n)) => forced = Some(n),
                Err(RecvTimeoutError::Timeout) => {
                    let lag = Instant::now().saturating_duration_since(planned);
                    if self.stall_detection {
                        // CPU time the hypervisor gave away while we waited,
                        // per CPU (the `cpu` line sums all of them)
                        let steal = steal_before.zip(warden_sys::system::steal_ticks()).map(|(a, b)| {
                            b.saturating_sub(a) as f64
                                / warden_sys::util::clk_tck() as f64
                                / warden_sys::util::nproc().max(1) as f64
                        });
                        self.check_stall(&cfg, lag, steal, &mut last_stall_report);
                    }
                }
                Err(RecvTimeoutError::Disconnected) => std::thread::sleep(wait),
            }

            let now = Instant::now();
            for slot in slots.iter_mut() {
                let due = slot.next <= now || forced == Some(slot.det.name());
                if !due || slot.disabled_until.is_some_and(|t| t > now) {
                    continue;
                }
                let name = slot.det.name();
                let real = warden_sys::clock::now();
                let mut cx = Cx { now, real, shared: &self.shared, cfg: &cfg, sink: &self.sink, source: name };
                let t = crate::prof::tick(slot.det.module(), slot.scope);
                let res = catch_unwind(AssertUnwindSafe(|| slot.det.tick(&mut cx)));
                let took = t.finish();
                // Asked after the tick: a detector may want to run sooner
                // (a background job to collect, a delayed first walk).
                slot.next = now + slot.det.interval();
                self.shared.metrics.set("warden_detector_tick_seconds", &[("detector", name)], took.as_secs_f64());
                if let Err(p) = res {
                    slot.panics += 1;
                    let backoff = Duration::from_secs(30u64.saturating_mul(1 << slot.panics.min(6)));
                    slot.disabled_until = Some(Instant::now() + backoff);
                    slot.next = Instant::now() + backoff;
                    let msg = panic_message(&p);
                    tracing::error!(detector = name, panic = %msg, ?backoff, "detector panicked; disabled temporarily");
                    self.shared.metrics.inc("warden_detector_panics_total", &[("detector", name)], 1.0);
                } else if took > Duration::from_secs(5) {
                    tracing::warn!(detector = name, took = ?took, "detector tick was slow");
                    self.sink.emit(
                        Event::new(
                            "warden.slow_detector",
                            Severity::Notice,
                            format!("detector {name} took {:.1}s", took.as_secs_f64()),
                        )
                        .source("scheduler")
                        .fingerprint(format!("warden.slow_detector:{name}"))
                        .detail("seconds", took.as_secs_f64()),
                    );
                }
            }
        }
        tracing::info!(scheduler = self.name, "scheduler stopped");
    }

    fn check_stall(&self, cfg: &Config, lag: Duration, steal: Option<f64>, last: &mut Option<Instant>) {
        let sc = &cfg.stall;
        self.shared.metrics.set("warden_scheduler_lag_seconds", &[("scheduler", self.name)], lag.as_secs_f64());
        if !sc.enabled || lag < sc.threshold {
            return;
        }
        // Do not report the same freeze repeatedly.
        if last.is_some_and(|t| t.elapsed() < Duration::from_secs(60)) {
            return;
        }
        *last = Some(Instant::now());
        let psi = |r, full: bool| {
            warden_sys::psi::read(r)
                .ok()
                .map(|p| if full { p.full.map(|f| f.avg10).unwrap_or(0.0) } else { p.some.avg10 })
        };
        let (cpu, memory, io) = (
            psi(warden_sys::psi::Resource::Cpu, false),
            psi(warden_sys::psi::Resource::Memory, true),
            psi(warden_sys::psi::Resource::Io, true),
        );
        let cause = stall_cause(lag, steal, [cpu, memory, io], warden_sys::system::is_virtualized());
        let secs = lag.as_secs_f64();
        let (sev, title, actions) = match cause {
            StallCause::Host => (
                if lag >= sc.critical { Severity::Critical } else { Severity::Warning },
                format!("host was unresponsive for {secs:.1}s (scheduler wake-up delayed)"),
                sc.actions.clone(),
            ),
            // The machine did not run, nothing on it was starved: a snapshot
            // would show a calm host, and one per pause pushed the snapshots
            // of real incidents out (the 0.14.1 lab: 25 of 32).
            StallCause::Steal => (
                Severity::Notice,
                format!(
                    "VM did not run for {secs:.1}s: the hypervisor gave its CPUs to others ({:.1}s of steal)",
                    steal.unwrap_or(0.0)
                ),
                Vec::new(),
            ),
            StallCause::Paused => (
                Severity::Notice,
                format!("VM did not run for {secs:.1}s (paused by the hypervisor or its host; no pressure inside)"),
                Vec::new(),
            ),
        };
        let mut ev = Event::new("system.stall", sev, title)
            .source("stall")
            .fingerprint(if cause == StallCause::Host { "system.stall".into() } else { "system.stall:vm".to_owned() })
            .detail("stall_seconds", secs)
            .detail("cause", cause.name())
            .actions(actions);
        if let Some(s) = steal {
            ev = ev.detail("steal_seconds", (s * 100.0).round() / 100.0);
        }
        if let Some(v) = cpu {
            ev = ev.detail("psi_cpu_some_avg10", v);
        }
        if let Some(v) = memory {
            ev = ev.detail("psi_memory_full_avg10", v);
        }
        if let Some(v) = io {
            ev = ev.detail("psi_io_full_avg10", v);
        }
        self.sink.emit(ev);
    }
}

/// Why the scheduler woke up late.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StallCause {
    /// Something on the machine held it up (or nothing explains it on
    /// bare metal): worth a warning and a snapshot.
    Host,
    /// The hypervisor ran other guests on our CPUs (steal time).
    Steal,
    /// A virtual machine that did not run at all, with no pressure inside:
    /// paused by the hypervisor, its host suspended or migrating.
    Paused,
}

impl StallCause {
    pub fn name(self) -> &'static str {
        match self {
            StallCause::Host => "host",
            StallCause::Steal => "hypervisor_steal",
            StallCause::Paused => "vm_paused",
        }
    }
}

/// PSI avg10 below this (percent) on every resource is "no pressure".
const CALM_PSI: f64 = 5.0;

/// Classify a late wake-up of `lag`: steal covering half of it is the
/// hypervisor; on a VM, a stall without any pressure inside is a pause.
pub fn stall_cause(lag: Duration, steal: Option<f64>, psi: [Option<f64>; 3], virtualized: bool) -> StallCause {
    if steal.is_some_and(|s| s >= lag.as_secs_f64() / 2.0) {
        return StallCause::Steal;
    }
    let calm = psi.iter().all(|p| p.is_some_and(|v| v < CALM_PSI));
    if virtualized && calm { StallCause::Paused } else { StallCause::Host }
}

pub fn panic_message(p: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = p.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = p.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown panic".into()
    }
}

// ---------------------------------------------------------------------------
// Sensor supervisor
// ---------------------------------------------------------------------------

/// Run a blocking event-driven sensor in its own thread, restarting it with
/// exponential backoff when it fails or panics.
///
/// The body returns `Ok(())` when it has nothing to do under the current
/// configuration and `Err` when it failed — or when it noticed a reload,
/// which restarts it at once without counting as a failure. When the
/// configuration no longer wants the sensor at all, the thread exits; the
/// [`Registry`] starts a new one if a later reload enables it again.
pub fn spawn_sensor<F>(
    name: &'static str,
    shared: Arc<Shared>,
    lease: Option<Lease>,
    body: F,
) -> std::io::Result<std::thread::JoinHandle<()>>
where
    F: Fn(&Arc<Shared>) -> Result<(), String> + Send + 'static,
{
    std::thread::Builder::new().name(format!("w-{name}")).spawn(move || {
        crate::prof::set_thread_scope(crate::prof::scope_id(name));
        let mut failures: u32 = 0;
        loop {
            if shared.is_shutting_down() {
                return;
            }
            if let Some(l) = &lease
                && !l.wanted()
            {
                if l.release() {
                    shared.set_sensor(name, SensorState::Disabled);
                    return;
                }
                continue;
            }
            let generation = shared.generation();
            shared.set_sensor(name, SensorState::Starting);
            let started = Instant::now();
            let r = catch_unwind(AssertUnwindSafe(|| body(&shared)));
            if shared.is_shutting_down() {
                return;
            }
            if shared.generation() != generation {
                // Reload: restart immediately with the new configuration.
                continue;
            }
            match r {
                Ok(Ok(())) => {
                    shared.set_sensor(name, SensorState::Disabled);
                    // Nothing to do until the configuration changes.
                    shared.wait_reload(generation, Duration::from_secs(3600));
                    continue;
                }
                Ok(Err(e)) => {
                    tracing::warn!(sensor = name, error = %e, "sensor unavailable");
                    shared.set_sensor(name, SensorState::Unavailable(e));
                }
                Err(p) => {
                    let m = panic_message(&p);
                    tracing::error!(sensor = name, panic = %m, "sensor panicked");
                    shared.set_sensor(name, SensorState::Failed(m));
                }
            }
            if started.elapsed() > Duration::from_secs(300) {
                failures = 0;
            }
            failures += 1;
            let backoff = Duration::from_secs((5u64 << failures.min(6)).min(600));
            shared.wait_reload(generation, backoff);
        }
    })
}

// ---------------------------------------------------------------------------
// Worker supervisor
// ---------------------------------------------------------------------------

/// Run a queue-consuming worker (the action executor, the notifier) on its
/// own thread and keep it alive: when `body` panics the failure is logged,
/// counted and reported as an event, and the body is run again after a short
/// backoff. State captured by the closure (the queue, the executor)
/// survives, so only the item that caused the panic is lost.
///
/// `body` returns when its queue is closed or the daemon is shutting down;
/// that ends the thread. Without this a panic would silently end the thread,
/// the queue would close, and every later event would be dropped without
/// anyone noticing that remediation had stopped.
pub fn spawn_worker<F>(
    name: &'static str,
    shared: Arc<Shared>,
    sink: Sink,
    mut body: F,
) -> std::io::Result<std::thread::JoinHandle<()>>
where
    F: FnMut() + Send + 'static,
{
    std::thread::Builder::new().name(format!("w-{name}")).spawn(move || {
        crate::prof::set_thread_scope(crate::prof::scope_id(name));
        let mut panics: u32 = 0;
        loop {
            let started = Instant::now();
            match catch_unwind(AssertUnwindSafe(&mut body)) {
                Ok(()) => return,
                Err(p) => {
                    if started.elapsed() > Duration::from_secs(300) {
                        panics = 0;
                    }
                    panics += 1;
                    let msg = panic_message(&p);
                    tracing::error!(worker = name, panic = %msg, "worker thread panicked; restarting it");
                    shared.metrics.inc("warden_worker_panics_total", &[("worker", name)], 1.0);
                    sink.emit(
                        Event::new(
                            "warden.worker_panic",
                            Severity::Warning,
                            format!("the {name} thread panicked and was restarted: {msg}"),
                        )
                        .source("daemon")
                        .fingerprint(format!("warden.worker_panic:{name}")),
                    );
                    if shared.is_shutting_down() {
                        return;
                    }
                    // 0.5 s, 1 s, ... 16 s: a deterministic crash must not spin
                    std::thread::sleep(Duration::from_millis(500u64 << (panics - 1).min(5)));
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {

    /// The 0.14.1 lab: 21 stalls of 5–21 s in 40 idle hours on a VM with
    /// PSI near zero, each with a snapshot. They are pauses of the VM.
    #[test]
    fn a_calm_vm_that_did_not_run_was_paused() {
        let lag = Duration::from_secs_f64(5.6);
        let calm = [Some(0.4), Some(0.0), Some(0.16)];
        assert_eq!(stall_cause(lag, Some(0.0), calm, true), StallCause::Paused);
        assert_eq!(stall_cause(lag, Some(4.0), calm, true), StallCause::Steal);
        // pressure inside the VM, or bare metal: the host itself froze
        assert_eq!(stall_cause(lag, Some(0.0), [Some(0.4), Some(36.9), Some(85.0)], true), StallCause::Host);
        assert_eq!(stall_cause(lag, None, calm, false), StallCause::Host);
        // PSI unreadable: not "calm"
        assert_eq!(stall_cause(lag, None, [None, None, None], true), StallCause::Host);
    }
    use super::*;

    #[test]
    fn worker_survives_a_panic_and_keeps_serving() {
        let shared = Shared::new(Config::default());
        let (sink, store) = Sink::collector();
        let (tx, rx) = std::sync::mpsc::channel::<u32>();
        let done = Arc::new(Mutex::new(Vec::new()));
        let d = done.clone();
        let h = spawn_worker("test-worker", shared.clone(), sink, move || {
            while let Ok(n) = rx.recv() {
                assert_ne!(n, 13, "unlucky item");
                lock(&d).push(n);
            }
        })
        .unwrap();
        for n in [1, 13, 2, 3] {
            tx.send(n).unwrap();
        }
        drop(tx);
        h.join().unwrap();
        assert_eq!(*lock(&done), vec![1, 2, 3], "the item after the panic is still served");
        let events = lock(&store);
        assert!(events.iter().any(|e| e.kind == "warden.worker_panic" && e.title.contains("unlucky item")));
    }

    #[test]
    fn metrics_render() {
        let m = Metrics::default();
        m.set("warden_disk_used_percent", &[("mount", "/")], 42.5);
        m.inc("warden_events_total", &[("kind", "a\"b")], 1.0);
        m.inc("warden_events_total", &[("kind", "a\"b")], 2.0);
        let r = m.render();
        assert!(r.contains("# TYPE warden_disk_used_percent gauge"));
        assert!(r.contains("warden_disk_used_percent{mount=\"/\"} 42.5"));
        assert!(r.contains("# TYPE warden_events_total counter"));
        assert!(r.contains("warden_events_total{kind=\"a\\\"b\"} 3"));
        m.set("warden_iface_errors_per_second", &[("iface", "eth0")], 0.0);
        m.set("warden_iface_errors_per_second", &[("iface", "we\"ird\\")], 0.0);
        let mut ifs = m.label_values("warden_iface_errors_per_second", "iface");
        ifs.sort();
        assert_eq!(ifs, ["eth0", "we\"ird\\"]);
        m.remove_matching("warden_disk_used_percent", "mount", "/");
        assert!(!m.render().contains("disk_used"));
    }

    struct Boom;
    impl Detector for Boom {
        fn name(&self) -> &'static str {
            "boom"
        }
        fn sections(&self) -> &'static [&'static str] {
            &[]
        }
        fn interval(&self) -> Duration {
            Duration::from_millis(10)
        }
        fn tick(&mut self, _: &mut Cx<'_>) {
            panic!("boom");
        }
    }

    struct Count(Arc<AtomicU64>);
    impl Detector for Count {
        fn name(&self) -> &'static str {
            "count"
        }
        fn sections(&self) -> &'static [&'static str] {
            &[]
        }
        fn interval(&self) -> Duration {
            Duration::from_millis(10)
        }
        fn tick(&mut self, cx: &mut Cx<'_>) {
            self.0.fetch_add(1, Ordering::SeqCst);
            cx.emit(Event::new("t", Severity::Info, "t"));
        }
    }

    #[test]
    fn scheduler_survives_panics() {
        let shared = Shared::new(Config::default());
        let (sink, store) = Sink::collector();
        let n = Arc::new(AtomicU64::new(0));
        let n2 = n.clone();
        let sched = Scheduler::new(
            "test",
            shared.clone(),
            sink,
            Box::new(move |_| vec![Box::new(Boom) as Box<dyn Detector>, Box::new(Count(n2.clone()))]),
        );
        let h = std::thread::spawn(move || sched.run());
        // generous: the first panic may print a symbolized backtrace
        std::thread::sleep(Duration::from_millis(1500));
        shared.shutdown.store(true, Ordering::SeqCst);
        shared.wake(Wake::Shutdown);
        h.join().unwrap();
        assert!(n.load(Ordering::SeqCst) >= 3);
        assert!(lock(&store).iter().all(|e| e.source == "count"));
        assert_eq!(shared.metrics.get("warden_detector_panics_total", &[("detector", "boom")]), Some(1.0));
    }

    /// Counts its ticks; holds one open condition, adopts a new
    /// `[memory]` only when `adopt` says so.
    struct Hourly {
        ticks: Arc<AtomicU64>,
        adopt: bool,
        open: bool,
    }
    impl Detector for Hourly {
        fn name(&self) -> &'static str {
            "hourly"
        }
        fn interval(&self) -> Duration {
            Duration::from_secs(3600)
        }
        fn tick(&mut self, _: &mut Cx<'_>) {
            self.ticks.fetch_add(1, Ordering::SeqCst);
            self.open = true;
        }
        fn sections(&self) -> &'static [&'static str] {
            &["/memory"]
        }
        fn reconfigure(&mut self, _: &Config) -> bool {
            self.adopt
        }
        fn close(&mut self) -> Vec<Event> {
            if std::mem::take(&mut self.open) {
                vec![Event::new("t.cond", Severity::Info, "closed").fingerprint("t.cond:resolved").resolved()]
            } else {
                vec![]
            }
        }
    }

    type Running = (Arc<Shared>, Arc<Mutex<Vec<Event>>>, Arc<AtomicU64>, std::thread::JoinHandle<()>);

    fn hourly_scheduler(adopt: bool) -> Running {
        let shared = Shared::new(Config::default());
        let (sink, store) = Sink::collector();
        let n = Arc::new(AtomicU64::new(0));
        let n2 = n.clone();
        let sched = Scheduler::new(
            "t2",
            shared.clone(),
            sink,
            Box::new(move |c: &Config| {
                if c.memory.enabled {
                    vec![Box::new(Hourly { ticks: n2.clone(), adopt, open: false }) as _]
                } else {
                    vec![]
                }
            }),
        );
        let h = std::thread::spawn(move || sched.run());
        std::thread::sleep(Duration::from_millis(300));
        assert_eq!(n.load(Ordering::SeqCst), 1, "ran once, then sleeps for the interval");
        (shared, store, n, h)
    }

    #[test]
    fn a_reload_keeps_a_detector_whose_configuration_did_not_change() {
        let (shared, store, n, h) = hourly_scheduler(false);
        // logrotate's SIGHUP: same configuration — nothing is rebuilt, nothing runs early
        shared.replace_config(Config::default());
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(n.load(Ordering::SeqCst), 1);
        assert!(lock(&store).is_empty());
        // a change elsewhere ([cpu]) does not concern it either
        let mut c = Config::default();
        c.cpu.load_per_cpu_warning += 1.0;
        shared.replace_config(c);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(n.load(Ordering::SeqCst), 1);
        shared.begin_shutdown();
        h.join().unwrap();
    }

    #[test]
    fn a_reload_that_changes_the_section_reconfigures_or_rebuilds_and_closes() {
        // the detector adopts the change: kept, no close, no early run
        let (shared, store, n, h) = hourly_scheduler(true);
        let mut c = Config::default();
        c.memory.sustain = Duration::from_secs(99);
        shared.replace_config(c);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(n.load(Ordering::SeqCst), 1);
        assert!(lock(&store).is_empty());
        shared.begin_shutdown();
        h.join().unwrap();

        // it cannot: its open condition is closed, a fresh detector runs at once
        let (shared, store, n, h) = hourly_scheduler(false);
        let mut c = Config::default();
        c.memory.sustain = Duration::from_secs(99);
        shared.replace_config(c.clone());
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(n.load(Ordering::SeqCst), 2);
        {
            let ev = lock(&store);
            assert_eq!(ev.len(), 1);
            assert!(ev[0].resolved && ev[0].source == "hourly" && ev[0].details["closed_by"] == "reload");
        }
        // disabled: closed, and its level and tick series go away
        shared.set_level("hourly", "warning");
        assert!(shared.metrics.get("warden_detector_tick_seconds", &[("detector", "hourly")]).is_some());
        c.memory.enabled = false;
        shared.replace_config(c);
        std::thread::sleep(Duration::from_millis(200));
        assert_eq!(lock(&store).len(), 2, "the rebuilt detector's condition is closed too");
        assert!(!lock(&shared.levels).contains_key("hourly"));
        assert!(shared.metrics.get("warden_detector_tick_seconds", &[("detector", "hourly")]).is_none());
        shared.begin_shutdown();
        h.join().unwrap();
    }

    fn fim_wanted(c: &Config) -> bool {
        c.fim.enabled
    }

    fn spawn_dummy(shared: Arc<Shared>, _: Sink, lease: Lease) -> std::io::Result<std::thread::JoinHandle<()>> {
        spawn_sensor("dummy", shared, Some(lease), |sh| {
            let g = sh.generation();
            while sh.generation() == g && !sh.is_shutting_down() {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err("reloaded".into())
        })
    }

    #[test]
    fn disabled_components_have_no_thread() {
        let mut cfg = Config::default();
        cfg.fim.enabled = false;
        let shared = Shared::new(cfg.clone());
        let (sink, _) = Sink::collector();
        let reg = Registry::default();
        let comps = [Component { name: "dummy", sensor: true, wanted: fim_wanted, spawn: spawn_dummy }];
        reg.reconcile(&shared, &sink, &comps);
        assert!(reg.running().is_empty());
        assert_eq!(lock(&shared.sensors).get("dummy"), Some(&SensorState::Disabled));

        cfg.fim.enabled = true;
        shared.replace_config(cfg.clone());
        reg.reconcile(&shared, &sink, &comps);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(reg.running(), vec!["dummy"]);

        cfg.fim.enabled = false;
        shared.replace_config(cfg.clone());
        reg.reconcile(&shared, &sink, &comps);
        std::thread::sleep(Duration::from_millis(200));
        assert!(reg.running().is_empty(), "thread exited after being disabled");

        cfg.fim.enabled = true;
        shared.replace_config(cfg);
        reg.reconcile(&shared, &sink, &comps);
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(reg.running(), vec!["dummy"], "re-enabled by a later reload");
        shared.begin_shutdown();
    }

    #[test]
    fn interned_names_are_shared() {
        let a = intern("health:web");
        let b = intern(&format!("health:{}", "web"));
        assert!(std::ptr::eq(a, b));
    }
}
