//! CPU and I/O pressure detectors.

use crate::runtime::{Cx, Detector};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use warden_core::config::{CpuConfig, IoConfig};
use warden_core::ratelimit::CounterRate;
use warden_core::units::human_bytes;
use warden_core::{Event, Level, LevelTracker, Severity, Transition};
use warden_sys::{process, psi, system};

fn level_str(l: Level) -> &'static str {
    match l {
        Level::Ok => "ok",
        Level::Warning => "warning",
        Level::Critical => "critical",
    }
}

/// Processes currently in uninterruptible sleep (`D`), usually stuck on
/// storage or a dead NFS server.
pub fn d_state_processes(limit: usize) -> Vec<serde_json::Value> {
    let mut v = Vec::new();
    for pid in process::pids() {
        if let Ok(st) = process::read_stat(pid)
            && st.state == 'D'
            && !process::is_kernel_thread(&st)
        {
            let wchan = std::fs::read_to_string(format!("/proc/{pid}/wchan")).unwrap_or_default();
            v.push(serde_json::json!({"pid": pid, "comm": st.comm, "wchan": wchan.trim()}));
            if v.len() >= limit {
                break;
            }
        }
    }
    v
}

/// What the CPU detector reads on one tick (split from [`CpuDetector::evaluate`]
/// so the decisions can be tested with synthetic series).
#[derive(Debug, Clone, Copy, Default)]
pub struct CpuSample {
    pub stat: system::Stat,
    /// 5-minute load average.
    pub load5: Option<f64>,
    pub ncpu: f64,
    pub psi: Option<psi::Psi>,
}

impl CpuSample {
    pub fn read() -> Option<Self> {
        Some(Self {
            stat: system::stat().ok()?,
            load5: system::loadavg().ok().map(|l| l.five),
            ncpu: warden_sys::util::nproc() as f64,
            psi: psi::read(psi::Resource::Cpu).ok(),
        })
    }
}

pub struct CpuDetector {
    cfg: CpuConfig,
    tracker: LevelTracker,
    prev_cpu: Option<system::CpuTimes>,
    forks: CounterRate,
    fork_hot: u32,
    last_fork_alert: Option<Instant>,
}

impl CpuDetector {
    pub fn new(cfg: &CpuConfig) -> Self {
        Self {
            tracker: LevelTracker::new(cfg.sustain / 2, cfg.sustain, cfg.clear_after, Duration::from_secs(1800)),
            cfg: cfg.clone(),
            prev_cpu: None,
            forks: CounterRate::default(),
            fork_hot: 0,
            last_fork_alert: None,
        }
    }
}

impl Detector for CpuDetector {
    fn name(&self) -> &'static str {
        "cpu"
    }

    fn interval(&self) -> Duration {
        self.cfg.interval
    }

    fn sections(&self) -> &'static [&'static str] {
        &["/cpu"]
    }

    fn reconfigure(&mut self, cfg: &warden_core::Config) -> bool {
        let c = &cfg.cpu;
        self.tracker.retune(c.sustain / 2, c.sustain, c.clear_after, Duration::from_secs(1800));
        self.cfg = c.clone();
        true
    }

    fn close(&mut self) -> Vec<Event> {
        crate::runtime::close_level("cpu.pressure", "cpu.pressure", &self.tracker).into_iter().collect()
    }

    fn tick(&mut self, cx: &mut Cx<'_>) {
        if let Some(s) = CpuSample::read() {
            self.evaluate(cx, s);
        }
    }
}

impl CpuDetector {
    pub fn evaluate(&mut self, cx: &Cx<'_>, s: CpuSample) {
        let (st, ncpu, p) = (s.stat, s.ncpu.max(1.0), s.psi);

        let iowait = match self.prev_cpu.replace(st.cpu) {
            Some(prev) => {
                let dt = st.cpu.total().saturating_sub(prev.total()) as f64;
                if dt > 0.0 { st.cpu.iowait.saturating_sub(prev.iowait) as f64 * 100.0 / dt } else { 0.0 }
            }
            None => 0.0,
        };
        let fork_rate = self.forks.update(cx.now, st.processes).unwrap_or(0.0);
        let load_per_cpu = s.load5.map(|l| l / ncpu).unwrap_or(0.0);
        let psi60 = p.map(|p| p.some.avg60).unwrap_or(0.0);

        cx.metric("warden_cpu_iowait_percent", &[], iowait);
        cx.metric("warden_load_per_cpu", &[], load_per_cpu);
        cx.metric("warden_procs_blocked", &[], st.procs_blocked as f64);
        cx.metric("warden_forks_per_second", &[], fork_rate);
        if let Some(p) = p {
            cx.metric("warden_psi_avg10", &[("resource", "cpu"), ("kind", "some")], p.some.avg10);
            cx.metric("warden_psi_avg60", &[("resource", "cpu"), ("kind", "some")], p.some.avg60);
        }

        let c = &self.cfg;
        let raw = if psi60 >= c.psi_some_avg60_critical || load_per_cpu >= c.load_per_cpu_critical {
            Level::Critical
        } else if psi60 >= c.psi_some_avg60_warning
            || load_per_cpu >= c.load_per_cpu_warning
            || iowait >= c.iowait_warning_percent
            || st.procs_blocked >= c.blocked_tasks_warning
        {
            Level::Warning
        } else {
            Level::Ok
        };

        let tr = self.tracker.update(cx.now, raw);
        let mk = |sev: Severity, title: String| {
            let mut ev = Event::new("cpu.pressure", sev, title)
                .fingerprint(format!("cpu.pressure:{sev}"))
                .detail("psi_some_avg60", psi60)
                .detail("load5_per_cpu", (load_per_cpu * 100.0).round() / 100.0)
                .detail("iowait_percent", iowait.round())
                .detail("procs_blocked", st.procs_blocked)
                .detail("cpus", ncpu);
            if st.procs_blocked >= c.blocked_tasks_warning {
                ev = ev.detail("d_state", d_state_processes(10));
            }
            ev
        };
        match tr {
            Transition::Raised(Level::Critical) | Transition::Repeated(Level::Critical) => cx.emit(
                mk(Severity::Critical, format!("CPU saturated: PSI some avg60 {psi60:.0}%, load/cpu {load_per_cpu:.1}"))
                    .actions(c.on_critical.clone()),
            ),
            Transition::Raised(Level::Warning) | Transition::Lowered(Level::Warning) => cx.emit(mk(
                Severity::Warning,
                format!(
                    "CPU pressure: PSI some avg60 {psi60:.0}%, load/cpu {load_per_cpu:.1}, iowait {iowait:.0}%, D-state {}",
                    st.procs_blocked
                ),
            )),
            Transition::Cleared => cx.emit(
                Event::new("cpu.pressure", Severity::Info, "CPU pressure resolved")
                    .fingerprint("cpu.pressure:resolved")
                    .resolved(),
            ),
            _ => {}
        }
        cx.shared.set_level("cpu", level_str(self.tracker.level()));
        cx.metric("warden_level", &[("detector", "cpu")], self.tracker.level() as u8 as f64);

        // Fork storm: needs two consecutive hot samples.
        if fork_rate >= c.fork_rate_warning {
            self.fork_hot += 1;
        } else {
            self.fork_hot = 0;
        }
        if self.fork_hot >= 2
            && self.last_fork_alert.is_none_or(|t| cx.now.saturating_duration_since(t) > Duration::from_secs(600))
        {
            self.last_fork_alert = Some(cx.now);
            let mut by_comm: HashMap<String, usize> = HashMap::new();
            for p in process::snapshot_light().values() {
                *by_comm.entry(p.comm.clone()).or_default() += 1;
            }
            let mut top: Vec<(String, usize)> = by_comm.into_iter().collect();
            top.sort_by_key(|b| std::cmp::Reverse(b.1));
            top.truncate(5);
            cx.emit(
                Event::new(
                    "cpu.fork_storm",
                    Severity::Warning,
                    format!("process creation storm: {fork_rate:.0} forks/s"),
                )
                .fingerprint("cpu.fork_storm")
                .detail("forks_per_sec", fork_rate.round())
                .detail("most_common", serde_json::json!(top)),
            );
        }
    }
}

/// Per-process `(read_bytes, write_bytes, comm)` keyed by identity.
type IoSample = HashMap<(i32, u64), (u64, u64, String)>;

pub struct IoDetector {
    cfg: IoConfig,
    tracker: LevelTracker,
    prev_io: Option<(Instant, IoSample)>,
}

impl IoDetector {
    pub fn new(cfg: &IoConfig) -> Self {
        Self {
            tracker: LevelTracker::new(cfg.sustain / 2, cfg.sustain, cfg.clear_after, Duration::from_secs(1800)),
            cfg: cfg.clone(),
            prev_io: None,
        }
    }

    fn sample_io() -> IoSample {
        let mut m = HashMap::new();
        for p in process::snapshot_light().values() {
            if p.kernel_thread {
                continue;
            }
            if let Some((r, w)) = process::io_bytes(p.pid) {
                m.insert((p.pid, p.start_time), (r, w, p.comm.clone()));
            }
        }
        m
    }

    /// Top block-I/O producers between the previous and the current sample.
    fn top_io(&mut self, now: Instant) -> Vec<serde_json::Value> {
        let cur = Self::sample_io();
        let mut out = Vec::new();
        if let Some((t, prev)) = &self.prev_io {
            let dt = now.saturating_duration_since(*t).as_secs_f64().max(0.1);
            let mut rates: Vec<(f64, f64, i32, String)> = cur
                .iter()
                .filter_map(|(k, (r, w, comm))| {
                    let (pr, pw, _) = prev.get(k)?;
                    Some((r.saturating_sub(*pr) as f64 / dt, w.saturating_sub(*pw) as f64 / dt, k.0, comm.clone()))
                })
                .filter(|x| x.0 + x.1 > 0.0)
                .collect();
            rates.sort_by(|a, b| (b.0 + b.1).total_cmp(&(a.0 + a.1)));
            out = rates
                .into_iter()
                .take(5)
                .map(|(r, w, pid, comm)| {
                    serde_json::json!({"pid": pid, "comm": comm, "read_per_sec": human_bytes(r as u64), "write_per_sec": human_bytes(w as u64)})
                })
                .collect();
        }
        self.prev_io = Some((now, cur));
        out
    }
}

impl Detector for IoDetector {
    fn name(&self) -> &'static str {
        "io"
    }

    fn interval(&self) -> Duration {
        self.cfg.interval
    }

    fn sections(&self) -> &'static [&'static str] {
        &["/io"]
    }

    fn reconfigure(&mut self, cfg: &warden_core::Config) -> bool {
        let c = &cfg.io;
        self.tracker.retune(c.sustain / 2, c.sustain, c.clear_after, Duration::from_secs(1800));
        self.cfg = c.clone();
        true
    }

    fn close(&mut self) -> Vec<Event> {
        crate::runtime::close_level("io.pressure", "io.pressure", &self.tracker).into_iter().collect()
    }

    fn tick(&mut self, cx: &mut Cx<'_>) {
        if let Ok(p) = psi::read(psi::Resource::Io) {
            self.evaluate(cx, p, Self::top_io);
        }
    }
}

impl IoDetector {
    /// `top`: who does the I/O (sampled only while elevated).
    pub fn evaluate(
        &mut self,
        cx: &Cx<'_>,
        p: psi::Psi,
        top: impl FnOnce(&mut Self, Instant) -> Vec<serde_json::Value>,
    ) {
        let full = p.full.map(|f| f.avg10).unwrap_or(0.0);
        cx.metric("warden_psi_avg10", &[("resource", "io"), ("kind", "some")], p.some.avg10);
        cx.metric("warden_psi_avg10", &[("resource", "io"), ("kind", "full")], full);
        let c = self.cfg.clone();
        let raw = if full >= c.psi_full_avg10_critical {
            Level::Critical
        } else if full >= c.psi_full_avg10_warning {
            Level::Warning
        } else {
            Level::Ok
        };
        // Keep a per-process I/O sample while elevated so the event can name
        // the processes hammering the disks.
        let top = if raw > Level::Ok || self.tracker.level() > Level::Ok {
            top(self, cx.now)
        } else {
            self.prev_io = None;
            Vec::new()
        };
        match self.tracker.update(cx.now, raw) {
            Transition::Raised(l) | Transition::Repeated(l) | Transition::Lowered(l) if l > Level::Ok => {
                let sev = if l == Level::Critical { Severity::Critical } else { Severity::Warning };
                let mut ev = Event::new("io.pressure", sev, format!("I/O stall: PSI io full avg10 {full:.1}%"))
                    .fingerprint(format!("io.pressure:{sev}"))
                    .detail("psi_full_avg10", full)
                    .detail("psi_some_avg10", p.some.avg10)
                    .detail("top_io", top);
                if l == Level::Critical {
                    ev = ev.actions(c.on_critical.clone()).detail("d_state", d_state_processes(10));
                }
                cx.emit(ev);
            }
            Transition::Cleared => cx.emit(
                Event::new("io.pressure", Severity::Info, "I/O pressure resolved")
                    .fingerprint("io.pressure:resolved")
                    .resolved(),
            ),
            _ => {}
        }
        cx.shared.set_level("io", level_str(self.tracker.level()));
        cx.metric("warden_level", &[("detector", "io")], self.tracker.level() as u8 as f64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{Shared, Sink};
    use warden_sys::psi::{Psi, PsiLine};

    fn psi(some60: f64, full10: f64) -> Psi {
        Psi {
            some: PsiLine { avg10: some60, avg60: some60, avg300: 0.0, total_us: 0 },
            full: Some(PsiLine { avg10: full10, avg60: full10, avg300: 0.0, total_us: 0 }),
        }
    }

    /// Run `series` (one value per 5 s tick) and return (second, title) of
    /// every event.
    fn run<D>(d: &mut D, series: &[f64], mut step: impl FnMut(&mut D, &Cx<'_>, f64)) -> Vec<(u64, String)> {
        let cfg = warden_core::Config::default();
        let shared = Shared::new(cfg.clone());
        let (sink, events) = Sink::collector();
        let t0 = Instant::now();
        let mut out = Vec::new();
        for (i, v) in series.iter().enumerate() {
            let mut cx = Cx::new(&shared, &cfg, &sink, "test");
            cx.now = t0 + Duration::from_secs(5 * i as u64);
            step(d, &cx, *v);
            for e in crate::runtime::lock(&events).drain(..) {
                out.push((5 * i as u64, e.title));
            }
        }
        out
    }

    fn cpu(d: &mut CpuDetector, cx: &Cx<'_>, psi60: f64, forks: u64) {
        let stat = system::Stat { processes: forks, ..Default::default() };
        d.evaluate(cx, CpuSample { stat, load5: Some(0.5), ncpu: 4.0, psi: Some(psi(psi60, 0.0)) });
    }

    #[test]
    fn cpu_pressure_must_be_sustained_and_clears_with_hysteresis() {
        let c = CpuConfig::default(); // warning at 60 %, sustain 2 min (warning after 1), clear after 2 min
        assert_eq!((c.sustain, c.clear_after), (Duration::from_secs(120), Duration::from_secs(120)));
        let mut d = CpuDetector::new(&c);
        // 30 s spike: nothing; then 4 min at 70 %; then quiet
        let mut series = vec![10.0; 2];
        series.extend([75.0; 6]);
        series.extend([10.0; 4]);
        series.extend([70.0; 48]);
        series.extend([10.0; 40]);
        let ev = run(&mut d, &series, |d, cx, v| cpu(d, cx, v, 0));
        let titles: Vec<&str> = ev.iter().map(|(_, t)| t.as_str()).collect();
        assert_eq!(titles.len(), 2, "{ev:?}");
        assert!(titles[0].starts_with("CPU pressure: PSI some avg60 70%"), "{ev:?}");
        assert_eq!(titles[1], "CPU pressure resolved");
        // warning one sustain/2 after the rise at 60 s; resolved clear_after after the fall at 300 s
        assert_eq!(ev[0].0, 60 + 60);
        assert_eq!(ev[1].0, 300 + 120);
    }

    #[test]
    fn cpu_saturation_goes_critical_with_its_actions() {
        let c = CpuConfig { on_critical: vec![warden_core::ActionSpec::Snapshot], ..Default::default() };
        let mut d = CpuDetector::new(&c);
        let cfg = warden_core::Config { cpu: c, ..Default::default() };
        let shared = Shared::new(cfg.clone());
        let (sink, events) = Sink::collector();
        let t0 = Instant::now();
        for i in 0..40u64 {
            let mut cx = Cx::new(&shared, &cfg, &sink, "test");
            cx.now = t0 + Duration::from_secs(5 * i);
            cpu(&mut d, &cx, 95.0, 0);
        }
        let ev = crate::runtime::lock(&events);
        let crit: Vec<_> = ev.iter().filter(|e| e.severity == Severity::Critical).collect();
        assert_eq!(crit.len(), 1, "{:?}", ev.iter().map(|e| &e.title).collect::<Vec<_>>());
        assert_eq!(crit[0].actions, vec![warden_core::ActionSpec::Snapshot]);
        assert_eq!(crit[0].fingerprint, "cpu.pressure:critical");
        assert_eq!(crate::runtime::lock(&shared.levels)["cpu"], "critical");
    }

    #[test]
    fn a_fork_storm_needs_two_hot_samples_and_is_rate_limited() {
        let mut d = CpuDetector::new(&CpuConfig::default()); // 1500 forks/s
        let mut forks = 0u64;
        // 5 s ticks: one hot tick (a burst), quiet, 3 hot ticks, quiet, 2 hot ticks 20 s later
        let rates = [0.0, 2000.0, 10.0, 2000.0, 2000.0, 2000.0, 10.0, 2000.0, 2000.0];
        let ev = run(&mut d, &rates, |d, cx, r| {
            forks += (r * 5.0) as u64;
            cpu(d, cx, 5.0, forks)
        });
        let storms: Vec<_> = ev.iter().filter(|(_, t)| t.starts_with("process creation storm")).collect();
        assert_eq!(storms.len(), 1, "one alert per 10 minutes: {ev:?}");
        assert_eq!(storms[0].0, 20, "at the second consecutive hot sample");
    }

    #[test]
    fn io_stall_raises_names_the_level_and_resolves() {
        let mut d = IoDetector::new(&IoConfig::default()); // full avg10 25 % / 60 %, sustain 60 s, clear 120 s
        let mut sampled = 0;
        let mut series = vec![0.0; 2];
        series.extend([30.0; 24]); // 2 min of warning-level stall
        series.extend([70.0; 24]); // 2 min critical
        series.extend([0.0; 30]);
        let ev = run(&mut d, &series, |d, cx, v| {
            d.evaluate(cx, psi(v, v), |_, _| {
                sampled += 1;
                vec![serde_json::json!({"pid": 1, "comm": "dd"})]
            })
        });
        let titles: Vec<&str> = ev.iter().map(|(_, t)| t.as_str()).collect();
        assert_eq!(
            titles,
            ["I/O stall: PSI io full avg10 30.0%", "I/O stall: PSI io full avg10 70.0%", "I/O pressure resolved"],
            "{ev:?}"
        );
        assert_eq!(ev[0].0, 10 + 30, "warning after sustain/2");
        assert_eq!(ev[1].0, 130 + 60, "critical after the full sustain");
        assert!(sampled > 0 && sampled < series.len(), "per-process sampling only while elevated");
    }
}
