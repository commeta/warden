//! Adaptive pacing of background scans.
//!
//! A scan — the disk-usage walk, the SUID/SGID walk, a FIM full scan — is a
//! long burst of metadata and read I/O. On a busy machine it should yield:
//! wait for a quieter moment to start, and once started spread its I/O over
//! time instead of adding to the queue the workload is waiting on.
//!
//! * **Signal.** I/O pressure (PSI `some`): the share of time at least one
//!   task waited for I/O. A scan's own waits count there too, so the pressure
//!   the *others* feel is measured while the scan pauses — during a pause
//!   every stall belongs to someone else. While the scan works, the
//!   system-wide stall minus the stall of Warden's own cgroup is a lower
//!   bound of the others' stall; when even that bound is high the scan backs
//!   off at once instead of waiting for its next pause.
//! * **Duty cycle.** The scan works in quanta (200 ms) and pauses after each
//!   so that work / (work + pause) = duty. Above the target pressure the duty
//!   halves, down to the scan's floor (so the scan always finishes); below
//!   half the target it grows back. At full speed a short probe pause (50 ms
//!   per 2 s of work: 2.5 %) keeps the measurement fresh.
//! * **I/O class.** While the duty is reduced or the pressure is noticeable
//!   the scanning thread is in the idle class (bfq and mq-deadline then serve
//!   it only when the disk is otherwise idle); on a quiet disk it moves to
//!   best-effort level 7, so that the occasional write of a quiet host does
//!   not stall it for seconds. The `none` and `kyber` schedulers (the default
//!   for NVMe) ignore classes: there only the duty cycle protects the
//!   workload (`wardenctl doctor` shows the scheduler).
//! * **Start.** A scheduled scan whose start finds the disk busy is postponed
//!   ([`Deferral`]) for at most `max_defer`.
//!
//! Scans the operator starts (`wardenctl du`, `wardenctl fim scan`) and
//! cleanup actions are never paced: someone is waiting for them.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Params {
    pub enabled: bool,
    /// Share of time (0–1) other tasks may wait for I/O before scans slow
    /// down and scheduled scans are postponed.
    pub target: f64,
    /// Move the scanning thread between the idle and best-effort I/O classes
    /// with the pressure (otherwise it stays where it was put — idle).
    pub adaptive_class: bool,
    /// Longest a scheduled scan may be postponed because the disk is busy.
    pub max_defer: Duration,
    /// Work between two decisions.
    pub quantum: Duration,
    /// Length of a measuring pause at full speed...
    pub probe: Duration,
    /// ...taken after this much work.
    pub probe_every: Duration,
}

impl Params {
    pub const DEFAULT: Params = Params {
        enabled: true,
        target: 0.10,
        adaptive_class: true,
        max_defer: Duration::from_secs(3600),
        quantum: Duration::from_millis(200),
        probe: Duration::from_millis(50),
        probe_every: Duration::from_secs(2),
    };
}

impl Default for Params {
    fn default() -> Self {
        Self::DEFAULT
    }
}

static PARAMS: RwLock<Params> = RwLock::new(Params::DEFAULT);

/// Set the parameters used by pacers created from now on (start, reload).
pub fn configure(p: Params) {
    *PARAMS.write().unwrap_or_else(PoisonError::into_inner) = p;
}

pub fn params() -> Params {
    *PARAMS.read().unwrap_or_else(PoisonError::into_inner)
}

/// Pauses longer than this are cut (a floor of 0.05 would otherwise mean
/// almost 4 s of sleep per quantum).
const MAX_PAUSE: Duration = Duration::from_secs(2);
/// The pacer looks at the clock once per this many steps.
const STEP_STRIDE: u32 = 32;

/// Cumulative I/O stall counters at one moment.
#[derive(Debug, Clone, Copy)]
pub struct Sample {
    pub at: Instant,
    /// System-wide PSI `some` total, µs.
    pub system_us: u64,
    /// The same for Warden's own cgroup (absent outside cgroup v2).
    pub own_us: Option<u64>,
}

/// Source of [`Sample`]s (the real one reads `/proc/pressure/io` and the own
/// cgroup's `io.pressure`; tests inject their own).
pub type Probe = Box<dyn FnMut() -> Option<Sample> + Send>;

fn proc_probe() -> Probe {
    let own = crate::selfstat::self_cgroup()
        .map(|cg| cg.trim_end_matches('/').to_owned())
        .filter(|cg| !cg.is_empty())
        .map(|cg| PathBuf::from(format!("{}{cg}/io.pressure", crate::cgroup::ROOT)));
    Box::new(move || {
        let system_us = crate::psi::read(crate::psi::Resource::Io).ok()?.some.total_us;
        let own_us = own.as_ref().and_then(|p| crate::psi::read_path(p).ok()).map(|p| p.some.total_us);
        Some(Sample { at: Instant::now(), system_us, own_us })
    })
}

/// The I/O pressure right now: PSI `some` avg10 as a share (0–1).
pub fn io_pressure() -> Option<f64> {
    crate::psi::read(crate::psi::Resource::Io).ok().map(|p| p.some.avg10 / 100.0)
}

/// The duty-cycle controller (no clock, no I/O: unit-testable).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Control {
    pub duty: f64,
    pub floor: f64,
    /// Smoothed share of time the others waited for I/O.
    pub pressure: Option<f64>,
}

impl Control {
    pub fn new(floor: f64) -> Self {
        Self { duty: 1.0, floor: floor.clamp(0.05, 1.0), pressure: None }
    }

    /// Take one measurement of the others' stall share.
    pub fn observe(&mut self, share: f64, target: f64) {
        let share = share.clamp(0.0, 1.0);
        let p = self.pressure.map_or(share, |old| 0.5 * old + 0.5 * share);
        self.pressure = Some(p);
        if p >= target {
            self.duty = (self.duty * 0.5).max(self.floor);
        } else if p < target / 2.0 {
            self.duty = (self.duty * 1.25 + 0.05).min(1.0);
        }
    }

    /// The pause that keeps `worked` at the current duty.
    pub fn pause_for(&self, worked: Duration) -> Duration {
        if self.duty >= 1.0 { Duration::ZERO } else { worked.mul_f64((1.0 - self.duty) / self.duty) }
    }

    /// Idle class while backing off or while others are noticeably waiting.
    pub fn idle_class(&self, target: f64) -> bool {
        self.duty < 1.0 || self.pressure.is_none_or(|p| p >= target / 2.0)
    }
}

/// Paces the loop of one scan on the calling thread: call [`Pacer::step`]
/// once per unit of work (a directory entry, a file).
pub struct Pacer {
    scan: &'static str,
    p: Params,
    ctl: Control,
    manage_class: bool,
    /// The class this pacer put the thread in (`Some(true)` = idle).
    idle: Option<bool>,
    probe: Probe,
    calls: u32,
    /// Start of the current work slice.
    slice: Instant,
    /// Counters at the start of the current slice (for the in-work bound).
    mark: Option<Sample>,
    since_probe: Duration,
    work: Duration,
    paced: Duration,
    published: Duration,
}

impl Pacer {
    /// A pacer with the configured parameters. `floor` is the lowest duty
    /// (how much slower than unpaced the scan may get: 0.25 = at most 4×);
    /// `manage_class`: the thread is a background thread whose I/O class
    /// the pacer may change.
    pub fn new(scan: &'static str, floor: f64, manage_class: bool) -> Self {
        let p = params();
        if !p.enabled {
            return Self::off(scan);
        }
        Self::with_probe(scan, floor, manage_class, p, proc_probe())
    }

    /// A pacer that does nothing (operator-initiated scans, pacing disabled).
    pub fn off(scan: &'static str) -> Self {
        let p = Params { enabled: false, ..Params::DEFAULT };
        Self::build(scan, 1.0, false, p, Box::new(|| None))
    }

    pub fn with_probe(scan: &'static str, floor: f64, manage_class: bool, p: Params, probe: Probe) -> Self {
        let mut s = Self::build(scan, floor, manage_class, p, probe);
        if s.p.enabled {
            with_stats(scan, |st| {
                st.runs += 1;
                st.active = true;
            });
            // An informed start: one measurement before the first quantum.
            s.pause(s.p.probe);
            s.apply_class();
            s.publish();
            s.slice = Instant::now();
        }
        s
    }

    fn build(scan: &'static str, floor: f64, manage_class: bool, p: Params, probe: Probe) -> Self {
        Self {
            scan,
            p,
            ctl: Control::new(floor),
            manage_class,
            idle: None,
            probe,
            calls: 0,
            slice: Instant::now(),
            mark: None,
            since_probe: Duration::ZERO,
            work: Duration::ZERO,
            paced: Duration::ZERO,
            published: Duration::ZERO,
        }
    }

    /// One unit of work done; pauses when the quantum is used up.
    #[inline]
    pub fn step(&mut self) {
        if !self.p.enabled {
            return;
        }
        self.calls = self.calls.wrapping_add(1);
        if !self.calls.is_multiple_of(STEP_STRIDE) {
            return;
        }
        let worked = self.slice.elapsed();
        if worked >= self.p.quantum {
            self.end_slice(worked);
        }
    }

    /// The caller slept `d` for its own reasons (a rate limit): not work.
    pub fn exclude(&mut self, d: Duration) {
        self.slice = self.slice.checked_add(d).map_or(self.slice, |t| t.min(Instant::now()));
    }

    fn end_slice(&mut self, worked: Duration) {
        self.work += worked;
        self.since_probe += worked;
        let now = (self.probe)();
        if let (Some(a), Some(b)) = (self.mark, now)
            && let (Some(oa), Some(ob)) = (a.own_us, b.own_us)
        {
            // what the others waited at least: system-wide minus our own
            let wall = b.at.saturating_duration_since(a.at).as_micros().max(1) as f64;
            let others = b.system_us.saturating_sub(a.system_us).saturating_sub(ob.saturating_sub(oa)) as f64 / wall;
            if others >= self.p.target {
                self.ctl.observe(others, self.p.target);
            }
        }
        let mut pause = self.ctl.pause_for(worked);
        if pause.is_zero() && self.since_probe >= self.p.probe_every {
            pause = self.p.probe;
        }
        if pause.is_zero() {
            self.mark = now;
        } else {
            self.pause(pause.min(MAX_PAUSE));
        }
        self.apply_class();
        self.publish();
        self.slice = Instant::now();
    }

    /// Sleep and measure what the others waited meanwhile.
    fn pause(&mut self, d: Duration) {
        let a = (self.probe)();
        let t0 = Instant::now();
        std::thread::sleep(d);
        self.paced += t0.elapsed();
        let b = (self.probe)();
        if let (Some(a), Some(b)) = (a, b) {
            let wall = b.at.saturating_duration_since(a.at).as_micros().max(1) as f64;
            self.ctl.observe(b.system_us.saturating_sub(a.system_us) as f64 / wall, self.p.target);
        }
        self.since_probe = Duration::ZERO;
        self.mark = b;
    }

    fn apply_class(&mut self) {
        if !(self.manage_class && self.p.adaptive_class) {
            return;
        }
        let idle = self.ctl.idle_class(self.p.target);
        if self.idle != Some(idle) {
            // a failure (seccomp, no permission) is not retried every slice
            let _ = crate::sched::set_thread_io_class(idle);
            self.idle = Some(idle);
        }
    }

    fn publish(&mut self) {
        let delta = self.paced.saturating_sub(self.published);
        self.published = self.paced;
        let (ctl, idle) = (self.ctl, self.idle);
        with_stats(self.scan, |st| {
            st.duty = ctl.duty;
            st.io_pressure = ctl.pressure.map(|p| (p * 1000.0).round() / 1000.0);
            st.io_class = idle.map(|i| if i { "idle" } else { "best-effort" });
            st.paced_seconds += delta.as_secs_f64();
        });
    }

    /// Time spent working (pauses excluded).
    pub fn work_time(&self) -> Duration {
        self.work + self.slice.elapsed()
    }

    /// Time spent in pauses.
    pub fn paced(&self) -> Duration {
        self.paced
    }

    pub fn duty(&self) -> f64 {
        self.ctl.duty
    }

    pub fn is_on(&self) -> bool {
        self.p.enabled
    }
}

impl Drop for Pacer {
    fn drop(&mut self) {
        if !self.p.enabled {
            return;
        }
        self.publish();
        with_stats(self.scan, |st| st.active = false);
        // a long-lived thread (the FIM worker) goes back to the idle class
        if self.idle == Some(false) {
            let _ = crate::sched::set_thread_io_class(true);
        }
    }
}

/// Postpones a scheduled scan while the disk is busy, for at most
/// `max_defer` in a row.
#[derive(Debug, Default)]
pub struct Deferral {
    since: Option<Instant>,
}

/// Retry interval of a postponed scan.
pub const DEFER_STEP: Duration = Duration::from_secs(120);

impl Deferral {
    /// `pressure`: the I/O pressure now ([`io_pressure`]). `None` — start
    /// now; `Some(d)` — look again in `d`.
    pub fn check(&mut self, p: &Params, scan: &'static str, now: Instant, pressure: Option<f64>) -> Option<Duration> {
        let busy = p.enabled && pressure.is_some_and(|x| x >= p.target);
        let since = *self.since.get_or_insert(now);
        let waited = now.saturating_duration_since(since);
        if !busy || waited >= p.max_defer {
            self.since = None;
            return None;
        }
        with_stats(scan, |st| st.deferrals += 1);
        Some(DEFER_STEP.min(p.max_defer - waited).max(Duration::from_secs(1)))
    }

    /// How long the scan has been waiting (for logs and status).
    pub fn waiting(&self, now: Instant) -> Option<Duration> {
        self.since.map(|s| now.saturating_duration_since(s))
    }
}

/// What pacing did to one kind of scan since the daemon started.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct ScanStats {
    /// A scan of this kind is running now.
    pub active: bool,
    /// Its current (or last) duty: 1 = full speed.
    pub duty: f64,
    /// Smoothed share of time other tasks waited for I/O (0–1), last measured.
    pub io_pressure: Option<f64>,
    /// The I/O class the pacer put the thread in (`None`: left as it was).
    pub io_class: Option<&'static str>,
    pub runs: u64,
    /// Total time spent in pauses.
    pub paced_seconds: f64,
    /// Scheduled starts postponed because the disk was busy.
    pub deferrals: u64,
}

static STATS: Mutex<BTreeMap<&'static str, ScanStats>> = Mutex::new(BTreeMap::new());

fn with_stats(scan: &'static str, f: impl FnOnce(&mut ScanStats)) {
    let mut m = STATS.lock().unwrap_or_else(PoisonError::into_inner);
    f(m.entry(scan).or_insert_with(|| ScanStats { duty: 1.0, ..Default::default() }));
}

/// Pacing statistics per kind of scan (`du`, `suid`, `fim`).
pub fn stats() -> BTreeMap<&'static str, ScanStats> {
    STATS.lock().unwrap_or_else(PoisonError::into_inner).clone()
}

/// The I/O scheduler of the block device holding `path` (`none`, `bfq`,
/// `mq-deadline`, `kyber`), following device-mapper and md devices to the
/// first underlying disk.
pub fn io_scheduler(path: &std::path::Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    let dev = std::fs::metadata(path).ok()?.dev();
    let (maj, min) = (libc::major(dev), libc::minor(dev));
    let mut dir = std::fs::canonicalize(format!("/sys/dev/block/{maj}:{min}")).ok()?;
    for _ in 0..4 {
        // a stacked device (dm, md): the first device below it
        if let Some(lower) = std::fs::read_dir(dir.join("slaves"))
            .ok()
            .and_then(|mut rd| rd.find_map(Result::ok))
            .and_then(|e| std::fs::canonicalize(e.path()).ok())
        {
            dir = lower;
            continue;
        }
        // a partition: the queue belongs to the parent disk
        if !dir.join("queue").exists() && dir.join("partition").exists() {
            dir = dir.parent()?.to_path_buf();
            continue;
        }
        break;
    }
    let s = std::fs::read_to_string(dir.join("queue/scheduler")).ok()?;
    // "mq-deadline kyber [bfq] none" → the bracketed one
    let cur = s.split_whitespace().find(|w| w.starts_with('[')).unwrap_or_else(|| s.trim());
    Some(cur.trim_matches(['[', ']']).to_owned())
}

/// Do requests of the idle class wait for the others with this scheduler?
pub fn scheduler_honours_io_class(s: &str) -> bool {
    matches!(s, "bfq" | "mq-deadline" | "cfq")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn thread_cpu_us() -> f64 {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        // SAFETY: valid out pointer.
        unsafe { libc::clock_gettime(libc::CLOCK_THREAD_CPUTIME_ID, &mut ts) };
        ts.tv_sec as f64 * 1e6 + ts.tv_nsec as f64 / 1e3
    }

    /// A fake PSI: the others wait `share` per mille of the time (changeable);
    /// we wait `own` per mille of the time we *work* (thread CPU time: a
    /// sleeping scan does not stall), like a real scan on a cold cache.
    fn fake(share: Arc<AtomicU64>, own: u64) -> Probe {
        let mut last = Instant::now();
        let mut last_cpu = thread_cpu_us();
        let (mut sys, mut mine) = (0f64, 0f64);
        Box::new(move || {
            let now = Instant::now();
            let cpu = thread_cpu_us();
            let dt = now.duration_since(last).as_micros() as f64;
            let ours = (cpu - last_cpu).clamp(0.0, dt) * own as f64 / 1000.0;
            (last, last_cpu) = (now, cpu);
            let others = share.load(Ordering::Relaxed) as f64 / 1000.0;
            mine += ours;
            // "some": at least one task waits — the union of both
            sys += dt * others + ours * (1.0 - others);
            Some(Sample { at: now, system_us: sys as u64, own_us: Some(mine as u64) })
        })
    }

    fn fast() -> Params {
        Params {
            quantum: Duration::from_millis(10),
            probe: Duration::from_millis(5),
            probe_every: Duration::from_millis(40),
            adaptive_class: false,
            ..Params::DEFAULT
        }
    }

    fn run(p: &mut Pacer, for_: Duration) {
        let end = Instant::now() + for_;
        while Instant::now() < end {
            p.step();
            std::hint::spin_loop();
        }
    }

    #[test]
    fn controller_backs_off_under_pressure_and_recovers() {
        let mut c = Control::new(0.25);
        for _ in 0..3 {
            c.observe(0.4, 0.1);
        }
        assert_eq!(c.duty, 0.25, "halved down to the floor, never below");
        assert!(c.idle_class(0.1));
        assert_eq!(c.pause_for(Duration::from_millis(200)), Duration::from_millis(600));
        for _ in 0..20 {
            c.observe(0.0, 0.1);
        }
        assert_eq!(c.duty, 1.0);
        assert!(!c.idle_class(0.1), "a quiet disk: best effort");
        assert_eq!(c.pause_for(Duration::from_millis(200)), Duration::ZERO);
        // between half the target and the target: hold
        c.duty = 0.5;
        c.pressure = Some(0.07);
        c.observe(0.07, 0.1);
        assert_eq!(c.duty, 0.5);
    }

    #[test]
    fn a_quiet_disk_costs_only_the_probes() {
        let share = Arc::new(AtomicU64::new(0));
        let mut p = Pacer::with_probe("test-quiet", 0.25, false, fast(), fake(share, 900));
        run(&mut p, Duration::from_millis(400));
        assert_eq!(p.duty(), 1.0, "our own stall (90 %) must not slow us down");
        let total = p.work_time() + p.paced();
        assert!(p.paced().as_secs_f64() < total.as_secs_f64() * 0.25, "paced {:?} of {total:?}", p.paced());
    }

    #[test]
    fn a_busy_disk_spreads_the_work() {
        let share = Arc::new(AtomicU64::new(500));
        let mut p = Pacer::with_probe("test-busy", 0.25, false, fast(), fake(share.clone(), 300));
        run(&mut p, Duration::from_millis(500));
        assert_eq!(p.duty(), 0.25);
        assert!(p.paced() > p.work_time(), "work {:?}, paced {:?}", p.work_time(), p.paced());
        let st = stats()["test-busy"].clone();
        assert!(st.active && st.runs == 1 && st.paced_seconds > 0.0, "{st:?}");
        // the workload goes quiet: back to full speed
        share.store(0, Ordering::Relaxed);
        run(&mut p, Duration::from_millis(600));
        assert_eq!(p.duty(), 1.0);
        drop(p);
        assert!(!stats()["test-busy"].active);
    }

    #[test]
    fn the_others_are_seen_while_working_too() {
        // the others wait while we work; the lower bound (system minus own)
        // catches it before the first full-speed probe
        let share = Arc::new(AtomicU64::new(0));
        let p = Params { probe_every: Duration::from_secs(3600), ..fast() };
        let mut pacer = Pacer::with_probe("test-inwork", 0.25, false, p, fake(share.clone(), 200));
        share.store(600, Ordering::Relaxed);
        run(&mut pacer, Duration::from_millis(100));
        assert!(pacer.duty() < 1.0);
    }

    #[test]
    fn a_disabled_pacer_never_sleeps() {
        let mut p = Pacer::off("test-off");
        let t = Instant::now();
        for _ in 0..1_000_000 {
            p.step();
        }
        assert!(t.elapsed() < Duration::from_secs(1));
        assert!(p.paced().is_zero());
        assert!(!stats().contains_key("test-off"));
    }

    #[test]
    fn scheduled_scans_wait_for_a_quiet_disk_but_not_for_ever() {
        let p = Params { max_defer: Duration::from_secs(600), ..Params::DEFAULT };
        let mut d = Deferral::default();
        let t = Instant::now();
        assert_eq!(d.check(&p, "test-defer", t, Some(0.02)), None, "quiet: start");
        assert_eq!(d.check(&p, "test-defer", t, Some(0.30)), Some(DEFER_STEP));
        assert_eq!(d.waiting(t + Duration::from_secs(5)), Some(Duration::from_secs(5)));
        let late = t + Duration::from_secs(540);
        assert_eq!(d.check(&p, "test-defer", late, Some(0.30)), Some(Duration::from_secs(60)), "up to the cap");
        assert_eq!(d.check(&p, "test-defer", t + Duration::from_secs(600), Some(0.30)), None, "the cap: run anyway");
        assert_eq!(d.waiting(t), None);
        assert_eq!(stats()["test-defer"].deferrals, 2);
        let off = Params { enabled: false, ..p };
        assert_eq!(d.check(&off, "test-defer", t, Some(0.9)), None);
        assert_eq!(d.check(&p, "test-defer", t, None), None, "no PSI: never postpone");
    }

    #[test]
    fn scheduler_of_the_root_filesystem() {
        // informative: containers and tmpfs roots have none
        let s = io_scheduler(std::path::Path::new("/"));
        eprintln!("I/O scheduler of /: {s:?}");
        if let Some(s) = s {
            assert!(!s.is_empty() && !s.contains('['));
        }
        assert!(scheduler_honours_io_class("bfq") && !scheduler_honours_io_class("none"));
    }
}
