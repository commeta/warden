//! Memory pressure, swap storms and OOM prevention.
//!
//! Signals:
//! * PSI `memory` (some/full avg10) — the time tasks lose waiting for memory,
//!   which rises long before `MemAvailable` hits zero;
//! * `MemAvailable` / swap usage;
//! * paging rates (`pswpin + pswpout`, `pgmajfault`) — a host can live
//!   with full swap, it dies when it keeps *moving* pages (thrashing);
//! * kernel OOM kills (`oom_kill` counter).
//!
//! The culprit ranking follows the kernel OOM badness, counted by what
//! killing the process would actually free — its anonymous memory and swap
//! (`RssAnon + VmSwap`; file-backed pages are reclaimable anyway, shared
//! memory outlives the process) — plus the `oom_score_adj` share of RAM, and
//! boosts processes that are actively thrashing, so the victim is chosen
//! *before* the kernel has to.
//!
//! Every proposed kill is then checked ([`KillGate`]): once the victim is
//! gone, MemAvailable must have risen by at least half of what it held.
//! If it did not, the memory is held by something killing processes does
//! not release (tmpfs, shared memory, kernel slab) and kills stop for the
//! rest of the episode (`memory.kill_ineffective`); kills that do help are
//! capped per episode (`memory.max_kills_per_episode`).

use crate::runtime::{Cx, Detector, lock};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use warden_core::config::{CulpritConfig, MemoryConfig};
use warden_core::protect::{ProcAttrs, Protection};
use warden_core::ratelimit::CounterRate;
use warden_core::units::human_bytes;
use warden_core::{Event, GlobList, Level, LevelTracker, ProcessRef, Severity, Subject, Transition};
use warden_sys::{mem, process, psi};

#[derive(Debug, Clone, serde::Serialize)]
pub struct Culprit {
    pub pid: i32,
    pub start_time: u64,
    pub comm: String,
    pub uid: u32,
    pub rss: u64,
    /// Anonymous memory (`RssAnon`; the whole RSS on kernels before 4.5).
    pub anon: u64,
    /// Shared memory mapped by the process (`RssShmem`): not freed by a kill.
    pub shmem: u64,
    pub swap: u64,
    pub majflt_per_sec: f64,
    pub oom_score_adj: i32,
    pub score: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    /// Why this process will not be touched, if protected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protected: Option<String>,
}

/// Per-process paging history for activity scoring.
#[derive(Debug, Default)]
pub struct Activity {
    prev: HashMap<(i32, u64), (u64, Instant)>,
}

impl Activity {
    /// Record every process's major-fault counter now (`/proc/<pid>/stat`
    /// only), so that the next [`rank_culprits`] has a rate for each. The
    /// memory detector samples on every tick while memory is elevated: the
    /// first kill decision then knows who is thrashing (0.13.3 measured
    /// only between two rankings, and the first ranking — the one that
    /// picks the victim — had no history: every rate was 0).
    pub fn sample(&mut self) {
        let now = Instant::now();
        self.prev = process::snapshot_light()
            .into_values()
            .filter(|p| !p.kernel_thread)
            .map(|p| ((p.pid, p.start_time), (p.majflt, now)))
            .collect();
    }

    pub fn is_empty(&self) -> bool {
        self.prev.is_empty()
    }

    /// Forget the history (the episode is over).
    pub fn clear(&mut self) {
        self.prev.clear();
    }
}

/// Rank processes by "how much killing them would help".
pub fn rank_culprits(
    cfg: &CulpritConfig,
    protection: &Protection,
    activity: &mut Activity,
    mem_total: u64,
    limit: usize,
) -> Vec<Culprit> {
    let now = Instant::now();
    let prefer = GlobList::new(&cfg.prefer);
    let avoid = GlobList::new(&cfg.avoid);
    let snap = process::snapshot();
    let mut next_prev = HashMap::with_capacity(snap.len());
    let mut v: Vec<Culprit> = Vec::new();

    for p in snap.values() {
        if p.kernel_thread || p.pid <= 1 {
            continue;
        }
        let key = (p.pid, p.start_time);
        let rate = activity
            .prev
            .get(&key)
            .map(|(m, t)| {
                let dt = now.saturating_duration_since(*t).as_secs_f64();
                if dt > 0.0 { p.majflt.saturating_sub(*m) as f64 / dt } else { 0.0 }
            })
            .unwrap_or(0.0);
        next_prev.insert(key, (p.majflt, now));

        // what a kill frees: anonymous memory and swap
        let anon = p.rss_anon.unwrap_or(p.rss);
        let badness = anon + p.swap;
        if badness < cfg.min_rss.as_u64() {
            continue;
        }
        let adj = process::oom_score_adj(p.pid).unwrap_or(0);
        if adj <= -1000 {
            continue; // explicitly exempted by the administrator
        }
        let mut score = badness as f64;
        if cfg.use_oom_score_adj {
            score += adj as f64 / 1000.0 * mem_total as f64;
        }
        if score <= 0.0 {
            continue;
        }
        if prefer.is_match(&p.comm) {
            score *= cfg.prefer_factor;
        }
        if avoid.is_match(&p.comm) {
            score *= cfg.avoid_factor;
        }
        score *= 1.0 + (rate / 500.0).min(1.0);
        v.push(Culprit {
            pid: p.pid,
            start_time: p.start_time,
            comm: p.comm.clone(),
            uid: p.ruid,
            rss: p.rss,
            anon,
            shmem: p.rss_shmem,
            swap: p.swap,
            majflt_per_sec: (rate * 10.0).round() / 10.0,
            oom_score_adj: adj,
            score,
            cgroup: None,
            exe: None,
            protected: None,
        });
    }
    activity.prev = next_prev;
    v.sort_by(|a, b| b.score.total_cmp(&a.score));
    v.truncate(limit);
    for c in &mut v {
        c.cgroup = process::cgroup(c.pid);
        c.exe = process::exe(c.pid);
        let genuine = c.exe.as_deref().and_then(|e| process::verify_daemon(c.pid, &c.comm, e));
        c.protected = protection
            .check(&ProcAttrs {
                pid: c.pid,
                comm: &c.comm,
                exe: c.exe.as_deref(),
                cgroup: c.cgroup.as_deref(),
                uid: Some(c.uid),
                kernel_thread: false,
                genuine,
            })
            .err();
    }
    v
}

/// A kill smaller than this is not judged: MemAvailable moves by that much
/// on its own.
const JUDGE_MIN: u64 = 64 << 20;

/// Whether killing helps, for one pressure episode (or swap storm).
#[derive(Debug, Default)]
pub struct KillGate {
    pending: Option<KillCheck>,
    /// Kills that freed what was expected.
    effective: u32,
    /// Why kills are withheld for the rest of the episode.
    withheld: Option<String>,
}

#[derive(Debug, Clone)]
struct KillCheck {
    pid: i32,
    start_time: u64,
    comm: String,
    /// What the victim held: anonymous memory + swap.
    expected: u64,
    available_before: u64,
    at: Instant,
}

/// A kill that did not free what its victim held.
#[derive(Debug, Clone)]
pub struct Ineffective {
    pub pid: i32,
    pub comm: String,
    pub expected: u64,
    pub freed: u64,
    pub reason: String,
}

impl KillGate {
    /// May the event carry a kill? `Err` says why not.
    pub fn admit(&self, max_kills: u32) -> Result<(), String> {
        if let Some(r) = &self.withheld {
            return Err(r.clone());
        }
        if max_kills > 0 && self.effective >= max_kills {
            return Err(format!(
                "{} kill(s) in this episode already (memory.max_kills_per_episode); the rest is left to the kernel OOM killer",
                self.effective
            ));
        }
        Ok(())
    }

    /// A kill of `victim` was proposed while `available` bytes were
    /// available. A pending kill whose victim is still alive (dry-run, a
    /// refusal, a cooldown) is replaced: it did not happen.
    pub fn proposed(&mut self, victim: &Culprit, available: u64, now: Instant) {
        self.pending = Some(KillCheck {
            pid: victim.pid,
            start_time: victim.start_time,
            comm: victim.comm.clone(),
            expected: victim.anon + victim.swap,
            available_before: available,
            at: now,
        });
    }

    /// Every tick: judge the pending kill once its victim is gone. `alive`
    /// says whether `(pid, start_time)` still runs; a kill that did not
    /// happen within `timeout` is forgotten.
    pub fn observe(
        &mut self,
        now: Instant,
        available: u64,
        alive: impl Fn(i32, u64) -> bool,
        timeout: Duration,
    ) -> Option<Ineffective> {
        let p = self.pending.as_ref()?;
        if alive(p.pid, p.start_time) {
            if now.saturating_duration_since(p.at) > timeout {
                self.pending = None;
            }
            return None;
        }
        let p = self.pending.take()?;
        let freed = available.saturating_sub(p.available_before);
        if p.expected < JUDGE_MIN || freed.saturating_mul(2) >= p.expected {
            self.effective += 1;
            return None;
        }
        let reason = format!(
            "killing {}[{}] was expected to free about {} (anonymous memory + swap) but MemAvailable rose by {}: \
             the memory is held by something a kill does not release; no further kills in this episode",
            p.comm,
            p.pid,
            human_bytes(p.expected),
            human_bytes(freed)
        );
        self.withheld = Some(reason.clone());
        Some(Ineffective { pid: p.pid, comm: p.comm, expected: p.expected, freed, reason })
    }

    /// The episode ended.
    pub fn reset(&mut self) {
        *self = Self::default();
    }

    /// Let `ev` carry its kill actions or strip them; a kill that stays is
    /// recorded for judgement.
    fn gate(&mut self, ev: &mut Event, victim: Option<&Culprit>, available: u64, now: Instant, max_kills: u32) {
        if !ev.actions.iter().any(warden_core::ActionSpec::is_kill) {
            return;
        }
        match (self.admit(max_kills), victim) {
            (Err(reason), _) => {
                ev.actions.retain(|a| !a.is_kill());
                ev.details.insert("kill_withheld".into(), reason.into());
            }
            (Ok(()), Some(v)) => self.proposed(v, available, now),
            (Ok(()), None) => {}
        }
    }
}

/// Is `(pid, start_time)` still a live process (a zombie has freed its memory)?
fn alive(pid: i32, start_time: u64) -> bool {
    process::read_stat(pid).is_ok_and(|s| s.starttime == start_time && !matches!(s.state, 'Z' | 'X'))
}

pub struct MemoryDetector {
    cfg: MemoryConfig,
    protection: Protection,
    tracker: LevelTracker,
    storm: LevelTracker,
    swap_rate: CounterRate,
    maj_rate: CounterRate,
    oom: CounterRate,
    direct_reclaim: CounterRate,
    activity: Activity,
    /// The level last published to `status` (`None`: not yet — the first
    /// tick publishes it, so a calm host shows "memory ok" too).
    last_level: Option<Level>,
    gate: KillGate,
    storm_gate: KillGate,
    /// Liveness of a victim (a stub in tests).
    alive: fn(i32, u64) -> bool,
}

impl MemoryDetector {
    pub fn new(cfg: &MemoryConfig, protection: Protection) -> Self {
        let tracker = LevelTracker::new(cfg.sustain / 2, cfg.sustain, cfg.clear_after, cfg.repeat);
        let storm =
            LevelTracker::new(cfg.swap_storm.sustain, cfg.swap_storm.sustain, Duration::from_secs(30), cfg.repeat);
        Self {
            cfg: cfg.clone(),
            protection,
            tracker,
            storm,
            swap_rate: CounterRate::default(),
            maj_rate: CounterRate::default(),
            oom: CounterRate::default(),
            direct_reclaim: CounterRate::default(),
            activity: Activity::default(),
            last_level: None,
            gate: KillGate::default(),
            storm_gate: KillGate::default(),
            alive,
        }
    }

    fn victim<'a>(&self, ranking: &'a [Culprit]) -> Option<&'a Culprit> {
        ranking.iter().find(|c| c.protected.is_none())
    }

    fn culprit_ref(c: &Culprit, cx: &Cx<'_>) -> ProcessRef {
        ProcessRef {
            pid: c.pid,
            start_time: c.start_time,
            comm: c.comm.clone(),
            exe: c.exe.clone(),
            cmdline: process::cmdline(c.pid, 512),
            uid: Some(c.uid),
            user: Some(cx.shared.user_name(c.uid)),
            ppid: None,
            container: c.cgroup.as_deref().and_then(warden_sys::cgroup::container_of),
            cgroup: c.cgroup.clone(),
        }
    }

    fn pressure_event(
        &mut self,
        cx: &Cx<'_>,
        kind: &str,
        sev: Severity,
        title: String,
        actions: Vec<warden_core::ActionSpec>,
        facts: &Facts,
    ) -> (Event, Option<Culprit>) {
        let ranking = rank_culprits(&self.cfg.culprit, &self.protection, &mut self.activity, facts.total, 8);
        *lock(&cx.shared.culprits) = ranking.clone();
        let top: Vec<serde_json::Value> = ranking
            .iter()
            .take(5)
            .map(|c| {
                serde_json::json!({
                    "pid": c.pid, "comm": c.comm, "rss": human_bytes(c.rss), "anon": human_bytes(c.anon),
                    "shmem": human_bytes(c.shmem), "swap": human_bytes(c.swap),
                    "majflt_per_sec": c.majflt_per_sec, "score": (c.score / 1048576.0).round(),
                    "protected": c.protected,
                })
            })
            .collect();
        let cgroups: Vec<serde_json::Value> = if warden_sys::cgroup::is_v2() {
            // Ranked by memory the cgroup pins; page cache and reclaimable
            // slab are listed separately — a backup job that read 3 GiB of
            // files holds cache, not the RAM that is causing the pressure.
            warden_sys::cgroup::top_memory(3, 5)
                .into_iter()
                .map(|(p, m)| {
                    serde_json::json!({
                        "cgroup": p, "memory": human_bytes(m.current), "pinned": human_bytes(m.pinned()),
                        "anon": human_bytes(m.anon), "page_cache": human_bytes(m.file),
                        "kernel": human_bytes(m.kernel), "reclaimable": human_bytes(m.reclaimable()),
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        let mut ev = Event::new(kind, sev, title)
            .detail("psi_some_avg10", facts.psi_some10)
            .detail("psi_full_avg10", facts.psi_full10)
            .detail("available", human_bytes(facts.available))
            .detail("available_percent", round1(facts.available_pct))
            .detail("threshold_warning", human_bytes(facts.warn_bytes))
            .detail("threshold_critical", human_bytes(facts.crit_bytes))
            .detail("swap_used_percent", round1(facts.swap_pct))
            .detail("swap_pages_per_sec", round1(facts.swap_rate))
            .detail("majflt_per_sec", round1(facts.maj_rate))
            .detail("top_processes", top)
            .detail("episode_seconds", self.tracker.episode_duration(cx.now).as_secs());
        if !cgroups.is_empty() {
            ev = ev.detail("top_cgroups", cgroups);
        }
        // Which services/containers are actually stalling (per-cgroup PSI).
        let stalled: Vec<serde_json::Value> = if warden_sys::cgroup::is_v2() {
            warden_sys::cgroup::top_memory_pressure(3, 5)
                .into_iter()
                .map(|(p, v)| {
                    serde_json::json!({
                        "cgroup": p, "psi_some_avg10": v,
                        "container": warden_sys::cgroup::container_of(&p),
                    })
                })
                .collect()
        } else {
            Vec::new()
        };
        if !stalled.is_empty() {
            ev = ev.detail("most_stalled_cgroups", stalled);
        }
        let victim = self.victim(&ranking).cloned();
        match &victim {
            Some(v) => {
                let r = Self::culprit_ref(v, cx);
                ev = ev
                    .fingerprint(format!("{kind}:{}:{}", sev, v.pid))
                    .detail(
                        "culprit",
                        format!(
                            "{} (RSS {}, of it anonymous {}, swap {})",
                            r,
                            human_bytes(v.rss),
                            human_bytes(v.anon),
                            human_bytes(v.swap)
                        ),
                    )
                    .subject(Subject::Process(r))
                    .actions(actions);
            }
            None => {
                // Only process-independent actions make sense without a victim.
                let a = actions
                    .into_iter()
                    .filter(|a| !a.is_kill() && !matches!(a, warden_core::ActionSpec::Stop))
                    .collect();
                ev = ev
                    .fingerprint(format!("{kind}:{sev}"))
                    .detail("culprit", "none eligible (all candidates protected)")
                    .actions(a);
            }
        }
        (ev, victim)
    }

    /// `memory.kill_ineffective`: what was killed, what it freed, and where
    /// the memory is instead.
    fn ineffective_event(kind: &str, j: &Ineffective, mi: &mem::MemInfo) -> Event {
        Event::new(
            "memory.kill_ineffective",
            Severity::Warning,
            format!(
                "killing {}[{}] did not relieve memory pressure (freed {} of about {}); further kills withheld until the episode ends",
                j.comm,
                j.pid,
                human_bytes(j.freed),
                human_bytes(j.expected)
            ),
        )
        .fingerprint(format!("memory.kill_ineffective:{kind}"))
        .detail("episode_of", kind)
        .detail("victim_pid", j.pid)
        .detail("victim_comm", j.comm.clone())
        .detail("expected", human_bytes(j.expected))
        .detail("freed", human_bytes(j.freed))
        .detail("reason", j.reason.clone())
        .detail("shmem", human_bytes(mi.shmem))
        .detail("slab_unreclaimable", human_bytes(mi.slab_unreclaim))
        .detail("anon_pages", human_bytes(mi.anon_pages))
        .detail(
            "hint",
            "look for large files on tmpfs (/dev/shm, /run, /tmp on tmpfs: `df -h -t tmpfs`), shared memory \
             segments (`ipcs -m`), memfd/deleted files held open, and kernel slab (`slabtop`)",
        )
    }
}

/// "Available memory" thresholds in bytes for a machine (or container) with
/// `total` bytes: the configured percentages, clamped to absolute bounds when
/// `auto_scale` is on. Returns `(warning, critical)`.
pub fn effective_thresholds(cfg: &MemoryConfig, total: u64) -> (u64, u64) {
    let pct = |p: f64| (total as f64 * p / 100.0) as u64;
    let (w, c) = (pct(cfg.available_warning_percent), pct(cfg.available_critical_percent));
    if !cfg.auto_scale {
        return (w, c);
    }
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    // Floors protect small VPSes (8% of 1GiB is only 80MiB), but never exceed
    // a quarter / an eighth of RAM; caps stop huge hosts from alerting with
    // tens of gigabytes still free.
    let w = w.clamp((256 * MIB).min(total / 4), 8 * GIB);
    let c = c.clamp((128 * MIB).min(total / 8), 2 * GIB).min(w);
    (w, c)
}

/// Memory as seen by the workload: the host, or — inside a container — the
/// cgroup limit, its usage without reclaimable cache, and the cgroup's PSI.
#[derive(Debug, Clone, Copy)]
pub struct MemView {
    pub total: u64,
    pub available: u64,
    pub container: bool,
}

pub fn mem_view(mi: &mem::MemInfo) -> MemView {
    if let Some((limit, used)) = warden_sys::cgroup::namespace_memory_limit()
        && limit < mi.total
    {
        return MemView { total: limit, available: limit.saturating_sub(used).min(mi.available), container: true };
    }
    MemView { total: mi.total, available: mi.available, container: false }
}

/// What the memory detector reads on one tick.
#[derive(Debug, Clone, Copy)]
pub struct MemorySample {
    pub mi: mem::MemInfo,
    pub view: MemView,
    pub psi: Option<psi::Psi>,
    pub vm: mem::VmCounters,
}

impl MemorySample {
    pub fn read() -> Option<Self> {
        let mi = mem::meminfo().ok()?;
        let view = mem_view(&mi);
        // Inside a container the host-wide /proc/pressure would blame us for
        // the neighbours' stalls: prefer the cgroup's own PSI.
        let psi = if view.container {
            psi::read_path(format!("{}/memory.pressure", warden_sys::cgroup::ROOT)).ok()
        } else {
            None
        }
        .or_else(|| psi::read(psi::Resource::Memory).ok());
        Some(Self { mi, view, psi, vm: mem::vm_counters().unwrap_or_default() })
    }
}

struct Facts {
    total: u64,
    available: u64,
    warn_bytes: u64,
    crit_bytes: u64,
    available_pct: f64,
    swap_pct: f64,
    psi_some10: f64,
    psi_full10: f64,
    swap_rate: f64,
    maj_rate: f64,
}

fn round1(v: f64) -> f64 {
    (v * 10.0).round() / 10.0
}

impl Detector for MemoryDetector {
    fn name(&self) -> &'static str {
        "memory"
    }

    fn interval(&self) -> Duration {
        self.cfg.interval
    }

    fn sections(&self) -> &'static [&'static str] {
        &["/memory", "/protection"]
    }

    fn reconfigure(&mut self, cfg: &warden_core::Config) -> bool {
        let c = &cfg.memory;
        self.tracker.retune(c.sustain / 2, c.sustain, c.clear_after, c.repeat);
        self.storm.retune(c.swap_storm.sustain, c.swap_storm.sustain, Duration::from_secs(30), c.repeat);
        self.protection = Protection::new(&cfg.protection);
        self.cfg = c.clone();
        true
    }

    fn close(&mut self) -> Vec<Event> {
        let mut v: Vec<Event> = crate::runtime::close_level("memory.pressure", "memory.pressure", &self.tracker)
            .into_iter()
            .chain(crate::runtime::close_level("memory.swap_storm", "memory.swap_storm", &self.storm))
            .collect();
        v.iter_mut().for_each(|e| e.subject = Subject::System);
        v
    }

    fn tick(&mut self, cx: &mut Cx<'_>) {
        if let Some(s) = MemorySample::read() {
            self.evaluate(cx, s);
        }
    }
}

impl MemoryDetector {
    pub fn evaluate(&mut self, cx: &Cx<'_>, s: MemorySample) {
        let MemorySample { mi, view, psi: p, vm } = s;
        let (warn_bytes, crit_bytes) = effective_thresholds(&self.cfg, view.total);
        let swap_rate = self.swap_rate.update(cx.now, vm.pswpin.saturating_add(vm.pswpout)).unwrap_or(0.0);
        let maj_rate = self.maj_rate.update(cx.now, vm.pgmajfault).unwrap_or(0.0);
        let reclaim = self.direct_reclaim.update(cx.now, vm.pgscan_direct).unwrap_or(0.0);
        let f = Facts {
            total: view.total,
            available: view.available,
            warn_bytes,
            crit_bytes,
            available_pct: if view.total == 0 { 100.0 } else { view.available as f64 * 100.0 / view.total as f64 },
            swap_pct: mi.swap_used_percent(),
            psi_some10: p.map(|p| p.some.avg10).unwrap_or(0.0),
            psi_full10: p.and_then(|p| p.full).map(|f| f.avg10).unwrap_or(0.0),
            swap_rate,
            maj_rate,
        };

        // --- did the last kill help? ---
        let timeout = self.cfg.repeat * 2 + Duration::from_secs(10);
        for (gate, kind) in [(&mut self.gate, "memory.pressure"), (&mut self.storm_gate, "memory.swap_storm")] {
            if let Some(j) = gate.observe(cx.now, f.available, self.alive, timeout) {
                tracing::warn!(victim = %j.comm, pid = j.pid, freed = j.freed, expected = j.expected, "kill did not free memory");
                cx.emit(Self::ineffective_event(kind, &j, &mi));
            }
        }

        cx.metric("warden_memory_total_bytes", &[], view.total as f64);
        cx.metric("warden_memory_available_bytes", &[], view.available as f64);
        cx.metric("warden_memory_threshold_bytes", &[("level", "warning")], warn_bytes as f64);
        cx.metric("warden_memory_threshold_bytes", &[("level", "critical")], crit_bytes as f64);
        cx.metric("warden_memory_container_view", &[], if view.container { 1.0 } else { 0.0 });
        cx.metric("warden_swap_used_bytes", &[], mi.swap_used() as f64);
        cx.metric("warden_swap_total_bytes", &[], mi.swap_total as f64);
        cx.metric("warden_swap_pages_per_second", &[], swap_rate);
        cx.metric("warden_major_faults_per_second", &[], maj_rate);
        cx.metric("warden_direct_reclaim_pages_per_second", &[], reclaim);
        if let Some(p) = p {
            cx.metric("warden_psi_avg10", &[("resource", "memory"), ("kind", "some")], p.some.avg10);
            cx.metric("warden_psi_avg60", &[("resource", "memory"), ("kind", "some")], p.some.avg60);
            if let Some(full) = p.full {
                cx.metric("warden_psi_avg10", &[("resource", "memory"), ("kind", "full")], full.avg10);
                cx.metric("warden_psi_avg60", &[("resource", "memory"), ("kind", "full")], full.avg60);
            }
        }

        // --- kernel OOM kills (only if the kmsg sensor cannot report them) ---
        if let Some(d) = self.oom.delta(cx.now, vm.oom_kill)
            && d > 0
        {
            cx.metric("warden_kernel_oom_kills", &[], vm.oom_kill as f64);
            if self.cfg.report_oom_kills && !cx.shared.sensor_running("kmsg") {
                cx.emit(
                    Event::new("memory.oom_kill", Severity::Warning, format!("kernel OOM killer fired {d} time(s)"))
                        .fingerprint("memory.oom_kill")
                        .detail("count", d)
                        .actions(cx.cfg.kernel.on_oom_kill.clone()),
                );
            }
        }

        // --- pressure level ---
        let c = &self.cfg;
        let raw = if f.psi_full10 >= c.psi_full_avg10_critical || f.available <= f.crit_bytes {
            Level::Critical
        } else if f.psi_full10 >= c.psi_full_avg10_warning
            || f.psi_some10 >= c.psi_some_avg10_warning
            || f.available <= f.warn_bytes
            || (mi.swap_total > 0 && f.swap_pct >= c.swap_used_warning_percent)
        {
            Level::Warning
        } else {
            Level::Ok
        };

        let storm_like = f.swap_rate >= self.cfg.swap_storm.min_swap_pages_per_sec
            || f.maj_rate >= self.cfg.swap_storm.min_majfault_per_sec;
        let elevated = raw >= Level::Warning || self.tracker.level() > Level::Ok || storm_like;
        match self.tracker.update(cx.now, raw) {
            Transition::Raised(Level::Critical) | Transition::Repeated(Level::Critical) => {
                let title = format!(
                    "memory pressure critical: PSI full {:.1}%, available {:.1}%",
                    f.psi_full10, f.available_pct
                );
                let (a, held) = self.process_actions(self.cfg.on_critical.clone(), &f);
                let (mut ev, victim) = self.pressure_event(cx, "memory.pressure", Severity::Critical, title, a, &f);
                Self::explain_held(&mut ev, held, &f);
                self.gate.gate(&mut ev, victim.as_ref(), f.available, cx.now, self.cfg.max_kills_per_episode);
                cx.emit(ev);
            }
            Transition::Raised(Level::Warning) | Transition::Lowered(Level::Warning) => {
                let title = format!(
                    "memory pressure elevated: PSI some {:.1}% full {:.1}%, available {:.1}%, swap {:.0}%",
                    f.psi_some10, f.psi_full10, f.available_pct, f.swap_pct
                );
                let (a, held) = self.process_actions(self.cfg.on_warning.clone(), &f);
                let (mut ev, victim) = self.pressure_event(cx, "memory.pressure", Severity::Warning, title, a, &f);
                Self::explain_held(&mut ev, held, &f);
                self.gate.gate(&mut ev, victim.as_ref(), f.available, cx.now, self.cfg.max_kills_per_episode);
                cx.emit(ev);
            }
            Transition::Cleared => {
                self.gate.reset();
                let secs = self.tracker.episode_duration(cx.now).as_secs();
                cx.emit(
                    Event::new("memory.pressure", Severity::Info, format!("memory pressure resolved after {secs}s"))
                        .fingerprint("memory.pressure:resolved")
                        .detail("episode_seconds", secs)
                        .resolved(),
                );
            }
            _ => {}
        }
        if self.last_level != Some(self.tracker.level()) {
            self.last_level = Some(self.tracker.level());
            cx.shared.set_level("memory", &format!("{:?}", self.tracker.level()).to_lowercase());
        }
        cx.metric("warden_level", &[("detector", "memory")], self.tracker.level() as u8 as f64);

        // --- swap storm (prolonged thrashing) ---
        let s = &self.cfg.swap_storm;
        if s.enabled {
            let paging = f.swap_rate >= s.min_swap_pages_per_sec || f.maj_rate >= s.min_majfault_per_sec;
            let raw = if paging && f.psi_full10 >= s.psi_full_avg10 { Level::Critical } else { Level::Ok };
            match self.storm.update(cx.now, raw) {
                Transition::Raised(Level::Critical) | Transition::Repeated(Level::Critical) => {
                    let lasted = self.storm.episode_duration(cx.now).as_secs();
                    let title = format!(
                        "swap storm for {lasted}s: {:.0} pages/s swapped, {:.0} major faults/s, PSI full {:.1}%",
                        f.swap_rate, f.maj_rate, f.psi_full10
                    );
                    let a = s.actions.clone();
                    let (ev, victim) = self.pressure_event(cx, "memory.swap_storm", Severity::Critical, title, a, &f);
                    let mut ev = ev.detail("storm_seconds", lasted);
                    let max = self.cfg.max_kills_per_episode;
                    self.storm_gate.gate(&mut ev, victim.as_ref(), f.available, cx.now, max);
                    cx.emit(ev);
                }
                Transition::Cleared => {
                    self.storm_gate.reset();
                    cx.emit(
                        Event::new("memory.swap_storm", Severity::Info, "swap storm subsided")
                            .fingerprint("memory.swap_storm:resolved")
                            .resolved(),
                    );
                }
                _ => {}
            }
        }

        // Paging activity, from the first elevated reading on and taken at
        // the end of the tick: the next ranking — the first kill decision
        // among them — has a rate over one interval for every process.
        if elevated {
            self.activity.sample();
        } else if !self.activity.is_empty() {
            self.activity.clear();
        }
    }
}

impl MemoryDetector {
    /// The actions of a pressure level, without the ones that act on a
    /// process when memory is not actually short (N22 of the 0.14.1
    /// review): MemAvailable above the warning threshold means the stall
    /// is paging in from a slow disk or swap, and a kill frees nothing
    /// that helps. Returns the actions and whether some were held back.
    fn process_actions(&self, mut a: Vec<warden_core::ActionSpec>, f: &Facts) -> (Vec<warden_core::ActionSpec>, bool) {
        let short = f.available <= f.warn_bytes;
        if short || self.cfg.act_on_psi_alone || !a.iter().any(warden_core::ActionSpec::is_containment) {
            return (a, false);
        }
        a.retain(|x| !x.is_containment());
        (a, true)
    }

    fn explain_held(ev: &mut Event, held: bool, f: &Facts) {
        let io = warden_sys::psi::read(warden_sys::psi::Resource::Io).ok().and_then(|p| p.full).map(|l| l.avg10);
        if let Some(io) = io {
            ev.details.insert("psi_io_full_avg10".into(), io.into());
            if io >= f.psi_full10 {
                ev.details.insert("io_bound".into(), true.into());
            }
        }
        if held {
            ev.details.insert(
                "kill_withheld".into(),
                format!(
                    "MemAvailable {} is above the warning threshold {}: memory is not short, tasks stall paging in \
                     from disk or swap{}, and killing a process would not help (memory.act_on_psi_alone = false)",
                    human_bytes(f.available),
                    human_bytes(f.warn_bytes),
                    io.map(|v| format!(" (PSI io full {v:.1}%)")).unwrap_or_default()
                )
                .into(),
            );
        }
    }
}

/// Kernel PSI trigger sensor: blocks in `poll(POLLPRI)` and wakes the memory
/// detector the moment the stall budget is exceeded.
pub fn run_psi_trigger(shared: &std::sync::Arc<crate::runtime::Shared>) -> Result<(), String> {
    let cfg = shared.config();
    let t = &cfg.memory.trigger;
    if !cfg.memory.enabled || !t.enabled {
        return Ok(());
    }
    let generation = shared.generation();
    let kind = t.kind.as_str();
    let trig = match psi::Trigger::new(psi::Resource::Memory.path(), kind, t.stall, t.window) {
        Ok(tr) => tr,
        Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
            // Without CAP_SYS_RESOURCE the kernel only accepts windows that are
            // multiples of 2s; scale the stall budget proportionally.
            let w = Duration::from_secs(2 * (t.window.as_secs_f64() / 2.0).ceil().max(1.0) as u64);
            let stall = t.stall.mul_f64(w.as_secs_f64() / t.window.as_secs_f64());
            tracing::info!(window = ?w, stall = ?stall, "PSI trigger: falling back to unprivileged window granularity");
            psi::Trigger::new(psi::Resource::Memory.path(), kind, stall, w).map_err(|e| format!("PSI trigger: {e}"))?
        }
        Err(e) => return Err(format!("PSI trigger: {e} (kernel without CONFIG_PSI or psi=0?)")),
    };
    shared.set_sensor("psi_trigger", crate::runtime::SensorState::Running);
    let mut last = Instant::now() - Duration::from_secs(10);
    loop {
        if shared.is_shutting_down() || shared.generation() != generation {
            return Err("reloading".into());
        }
        match trig.wait(Duration::from_secs(2)) {
            Ok(true) => {
                shared.metrics.inc("warden_psi_trigger_fired_total", &[("resource", "memory")], 1.0);
                if last.elapsed() >= Duration::from_millis(500) {
                    last = Instant::now();
                    shared.wake(crate::runtime::Wake::Detector("memory"));
                }
                // The kernel re-arms the trigger per window; avoid spinning.
                std::thread::sleep(Duration::from_millis(250));
            }
            Ok(false) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{Shared, Sink};
    use warden_sys::psi::{Psi, PsiLine};

    const GIB: u64 = 1 << 30;

    /// 16 GiB host, `avail` GiB available, PSI some/full avg10, cumulative
    /// paging counters.
    fn sample(avail: u64, some: f64, full: f64, paged: u64, oom: u64) -> MemorySample {
        let mi = mem::MemInfo {
            total: 16 * GIB,
            available: avail * GIB,
            swap_total: 4 * GIB,
            swap_free: 4 * GIB,
            ..Default::default()
        };
        let line = |v: f64| PsiLine { avg10: v, avg60: v, avg300: 0.0, total_us: 0 };
        MemorySample {
            mi,
            view: MemView { total: mi.total, available: mi.available, container: false },
            psi: Some(Psi { some: line(some), full: Some(line(full)) }),
            vm: mem::VmCounters { pswpout: paged, oom_kill: oom, ..Default::default() },
        }
    }

    /// One sample every 2 s (the default interval); (second, event).
    fn run(cfg: &warden_core::Config, series: &[MemorySample]) -> Vec<(u64, Event)> {
        let mut d = MemoryDetector::new(&cfg.memory, Protection::new(&cfg.protection));
        let shared = Shared::new(cfg.clone());
        let (sink, events) = Sink::collector();
        let t0 = std::time::Instant::now();
        let mut out = Vec::new();
        for (i, s) in series.iter().enumerate() {
            let mut cx = Cx::new(&shared, cfg, &sink, "test");
            cx.now = t0 + Duration::from_secs(2 * i as u64);
            d.evaluate(&cx, *s);
            out.extend(lock(&events).drain(..).map(|e| (2 * i as u64, e)));
        }
        out
    }

    #[test]
    fn pressure_rises_repeats_while_critical_and_resolves() {
        let cfg = warden_core::Config::default(); // full 10 % / 30 %, sustain 20 s, repeat 30 s, clear 60 s
        let mut series = vec![sample(8, 0.0, 0.0, 0, 0); 3];
        series.extend(vec![sample(8, 20.0, 15.0, 0, 0); 10]); // 6..24 s: warning level
        series.extend(vec![sample(8, 60.0, 40.0, 0, 0); 30]); // 26..84 s: critical level
        series.extend(vec![sample(8, 0.0, 0.0, 0, 0); 40]);
        let ev = run(&cfg, &series);
        let got: Vec<(u64, Severity)> = ev.iter().map(|(t, e)| (*t, e.severity)).collect();
        assert_eq!(
            got,
            [
                (16, Severity::Warning),  // sustain/2 after 6 s
                (46, Severity::Critical), // full sustain after 26 s
                (76, Severity::Critical), // repeated: the remediation did not help
                (146, Severity::Info),    // clear_after after 86 s
            ],
            "{:?}",
            ev.iter().map(|(t, e)| (t, &e.title)).collect::<Vec<_>>()
        );
        let crit = &ev[1].1;
        assert!(crit.title.starts_with("memory pressure critical: PSI full 40.0%"));
        assert!(crit.fingerprint.starts_with("memory.pressure:critical"), "{}", crit.fingerprint);
        assert!(crit.details.contains_key("top_processes") && crit.details.contains_key("culprit"));
        let resolved = &ev[3].1;
        assert!(resolved.resolved && resolved.fingerprint == "memory.pressure:resolved");
        assert_eq!(resolved.details["episode_seconds"], 140, "from the first elevated sample to the resolution");
    }

    /// A reload in the middle of an incident: the level and the episode
    /// stay (no second "critical" before `repeat`, a resolution at the end).
    /// 0.13.3 rebuilt the detector: the incident was raised anew and never
    /// resolved.
    #[test]
    fn a_reload_during_an_incident_keeps_it() {
        let cfg = warden_core::Config::default();
        let mut d = MemoryDetector::new(&cfg.memory, Protection::new(&cfg.protection));
        let shared = Shared::new(cfg.clone());
        let (sink, events) = Sink::collector();
        let t0 = std::time::Instant::now();
        let mut out = Vec::new();
        let mut feed = |d: &mut MemoryDetector, from: u64, to: u64, s: MemorySample| {
            for i in from..to {
                let mut cx = Cx::new(&shared, &cfg, &sink, "test");
                cx.now = t0 + Duration::from_secs(2 * i);
                d.evaluate(&cx, s);
                out.extend(lock(&events).drain(..).map(|e| (2 * i, e.severity, e.resolved)));
            }
        };
        feed(&mut d, 0, 15, sample(8, 60.0, 40.0, 0, 0)); // critical from 20 s
        let mut c2 = cfg.clone();
        c2.memory.psi_full_avg10_critical = 35.0;
        assert!(d.reconfigure(&c2));
        feed(&mut d, 15, 20, sample(8, 60.0, 40.0, 0, 0)); // still critical: no new "raised"
        feed(&mut d, 20, 60, sample(8, 0.0, 0.0, 0, 0));
        let crit: Vec<u64> = out.iter().filter(|e| e.1 == Severity::Critical).map(|e| e.0).collect();
        assert_eq!(crit, [20], "one incident: {out:?}");
        assert!(out.iter().any(|e| e.2), "and it is resolved: {out:?}");
        assert!(d.close().is_empty(), "nothing open at the end");
    }

    /// Paging activity is sampled from the first elevated reading on (so
    /// the first kill decision has rates) and forgotten when memory is fine.
    #[test]
    fn paging_activity_is_sampled_while_memory_is_elevated() {
        let cfg = warden_core::Config::default();
        let mut d = MemoryDetector::new(&cfg.memory, Protection::new(&cfg.protection));
        let shared = Shared::new(cfg.clone());
        let (sink, _) = Sink::collector();
        let cx = Cx::new(&shared, &cfg, &sink, "test");
        d.evaluate(&cx, sample(8, 0.0, 0.0, 0, 0));
        assert!(d.activity.is_empty(), "nothing to watch on a calm host");
        d.evaluate(&cx, sample(8, 40.0, 15.0, 0, 0)); // elevated, long before `sustain`
        assert!(!d.activity.is_empty());
        let me = (std::process::id() as i32, process::start_time(std::process::id() as i32).unwrap());
        assert!(d.activity.prev.contains_key(&me));
        d.evaluate(&cx, sample(8, 0.0, 0.0, 0, 0));
        assert!(d.activity.is_empty());
    }

    /// N22, the 0.14.1 lab: PSI memory full 36.9 % while 69 % of RAM was
    /// available (the disk was the bottleneck) — Warden killed a compiler
    /// and freed nothing that helped. PSI alone no longer kills.
    #[test]
    fn psi_alone_does_not_kill_when_memory_is_available() {
        let cfg = warden_core::Config::default();
        let series = vec![sample(11, 38.0, 37.0, 0, 0); 30]; // 11 of 16 GiB available
        let ev = run(&cfg, &series);
        let crit: Vec<&Event> = ev.iter().map(|(_, e)| e).filter(|e| e.severity == Severity::Critical).collect();
        assert!(!crit.is_empty());
        for e in &crit {
            assert!(!e.actions.iter().any(|a| a.is_containment()), "{:?}", e.actions);
            assert!(e.actions.contains(&warden_core::ActionSpec::Snapshot), "the snapshot stays");
            assert!(e.details["kill_withheld"].as_str().unwrap().contains("act_on_psi_alone"));
        }
        // memory really short, or the operator's choice: nothing is held
        // back (whether a kill follows depends on an eligible victim on the
        // machine running the test)
        let held = |cfg: &warden_core::Config, avail: u64| {
            run(cfg, &vec![sample(avail, 38.0, 37.0, 0, 0); 30])
                .iter()
                .any(|(_, e)| e.severity == Severity::Critical && e.details.contains_key("kill_withheld"))
        };
        assert!(!held(&cfg, 0));
        let mut opt_in = warden_core::Config::default();
        opt_in.memory.act_on_psi_alone = true;
        assert!(!held(&opt_in, 11));
    }

    #[test]
    fn low_available_memory_alone_is_critical() {
        let cfg = warden_core::Config::default(); // 16 GiB: warning ≤ 1.28 GiB, critical ≤ 0.48 GiB (auto_scale)
        let (w, c) = effective_thresholds(&cfg.memory, 16 * GIB);
        assert!(w > GIB && c < GIB);
        let ev = run(&cfg, &vec![sample(0, 0.0, 0.0, 0, 0); 12]);
        assert_eq!(ev.iter().filter(|(_, e)| e.severity == Severity::Critical).count(), 1);
        // 10 GiB free with no stall: nothing
        assert!(run(&cfg, &vec![sample(10, 1.0, 0.0, 0, 0); 30]).is_empty());
    }

    #[test]
    fn a_swap_storm_needs_paging_and_stall_held_for_a_minute() {
        let cfg = warden_core::Config::default(); // 2000 pages/s + PSI full 10 % for 60 s
        let mut series = Vec::new();
        let mut paged = 0;
        for i in 0..80 {
            // paging at 3000 pages/s throughout; the stall only from 10 s to 100 s
            paged += 6000;
            let full = if (5..50).contains(&i) { 12.0 } else { 0.0 };
            series.push(sample(8, full, full, paged, 0));
        }
        let ev = run(&cfg, &series);
        let storm: Vec<&(u64, Event)> = ev.iter().filter(|(_, e)| e.kind == "memory.swap_storm").collect();
        assert_eq!(storm.len(), 2, "{:?}", storm.iter().map(|(t, e)| (t, &e.title)).collect::<Vec<_>>());
        assert_eq!(storm[0].0, 70);
        assert!(storm[0].1.title.starts_with("swap storm for 60s: 3000 pages/s"), "{}", storm[0].1.title);
        assert_eq!(storm[0].1.details["storm_seconds"], 60);
        assert_eq!(storm[1].1.title, "swap storm subsided");
        assert_eq!(storm[1].0, 100 + 30);
    }

    #[test]
    fn oom_kills_are_reported_once_per_increase_unless_kmsg_does_it() {
        let cfg = warden_core::Config::default();
        let series: Vec<MemorySample> = [0, 0, 2, 2, 3].iter().map(|&n| sample(8, 0.0, 0.0, 0, n)).collect();
        let titles: Vec<String> = run(&cfg, &series).into_iter().map(|(_, e)| e.title).collect();
        assert_eq!(titles, ["kernel OOM killer fired 2 time(s)", "kernel OOM killer fired 1 time(s)"]);
    }
    use warden_core::config::ProtectionConfig;

    #[test]
    fn thresholds_scale_with_ram() {
        let cfg = MemoryConfig::default(); // 8% / 3%
        const GIB: u64 = 1 << 30;
        const MIB: u64 = 1 << 20;
        // 1 GiB VPS: raised to floors (8% would be 80MiB)
        assert_eq!(effective_thresholds(&cfg, GIB), (256 * MIB, 128 * MIB));
        // 512 MiB: floors limited to 1/4 and 1/8 of RAM
        assert_eq!(effective_thresholds(&cfg, 512 * MIB), (128 * MIB, 64 * MIB));
        // 16 GiB: plain percentages
        let (w, c) = effective_thresholds(&cfg, 16 * GIB);
        assert_eq!((w / MIB, c / MIB), (1310, 491));
        // 512 GiB: capped (8% would be 41 GiB)
        assert_eq!(effective_thresholds(&cfg, 512 * GIB), (8 * GIB, 2 * GIB));
        // auto_scale off → pure percentages
        let off = MemoryConfig { auto_scale: false, ..Default::default() };
        assert_eq!(effective_thresholds(&off, 512 * GIB).0, (512.0 * GIB as f64 * 0.08) as u64);
    }

    fn culprit(pid: i32, anon_mib: u64) -> Culprit {
        Culprit {
            pid,
            start_time: 7,
            comm: "php-fpm8.3".into(),
            uid: 33,
            rss: (anon_mib + 100) << 20,
            anon: anon_mib << 20,
            shmem: 100 << 20,
            swap: 0,
            majflt_per_sec: 0.0,
            oom_score_adj: 0,
            score: 1.0,
            cgroup: None,
            exe: None,
            protected: None,
        }
    }

    fn kill_event() -> Event {
        Event::new("memory.pressure", Severity::Critical, "t").actions(vec![
            warden_core::ActionSpec::Snapshot,
            warden_core::ActionSpec::Kill { tree: false, grace: None },
        ])
    }

    const MIB: u64 = 1 << 20;

    #[test]
    fn a_kill_that_frees_nothing_stops_further_kills() {
        let t0 = Instant::now();
        let mut g = KillGate::default();
        let timeout = Duration::from_secs(70);
        // pressure caused by a 2 GiB tmpfs file: the victim's 512 MiB anonymous
        // memory is freed, but other processes take it at once
        let mut ev = kill_event();
        g.gate(&mut ev, Some(&culprit(100, 512)), 300 * MIB, t0, 3);
        assert_eq!(ev.actions.len(), 2, "the first kill is allowed");
        // still alive (the responder has not acted yet): nothing to judge
        assert!(g.observe(t0 + Duration::from_secs(2), 300 * MIB, |_, _| true, timeout).is_none());
        // gone, MemAvailable rose by 20 MiB only
        let j = g.observe(t0 + Duration::from_secs(4), 320 * MIB, |_, _| false, timeout).unwrap();
        assert_eq!((j.pid, j.freed, j.expected), (100, 20 * MIB, 512 * MIB));
        assert!(j.reason.contains("no further kills"), "{}", j.reason);
        // the next critical event of the episode keeps its snapshot, loses the kill
        let mut ev = kill_event();
        g.gate(&mut ev, Some(&culprit(101, 512)), 320 * MIB, t0 + Duration::from_secs(30), 3);
        assert_eq!(ev.actions, vec![warden_core::ActionSpec::Snapshot]);
        assert!(ev.details["kill_withheld"].as_str().unwrap().contains("php-fpm8.3[100]"));
        // a new episode starts clean
        g.reset();
        let mut ev = kill_event();
        g.gate(&mut ev, Some(&culprit(102, 512)), 300 * MIB, t0 + Duration::from_secs(300), 3);
        assert_eq!(ev.actions.len(), 2);
    }

    #[test]
    fn effective_kills_are_capped_per_episode() {
        let t0 = Instant::now();
        let mut g = KillGate::default();
        let timeout = Duration::from_secs(70);
        let mut avail = 100 * MIB;
        for i in 0..3 {
            let mut ev = kill_event();
            g.gate(&mut ev, Some(&culprit(200 + i, 512)), avail, t0, 3);
            assert_eq!(ev.actions.len(), 2, "kill #{i}");
            avail += 400 * MIB; // freed most of what it held
            assert!(g.observe(t0, avail, |_, _| false, timeout).is_none());
        }
        let mut ev = kill_event();
        g.gate(&mut ev, Some(&culprit(300, 512)), avail, t0, 3);
        assert_eq!(ev.actions.len(), 1, "the fourth kill is withheld");
        assert!(ev.details["kill_withheld"].as_str().unwrap().contains("max_kills_per_episode"));
        // 0 = no limit
        let mut ev = kill_event();
        g.gate(&mut ev, Some(&culprit(300, 512)), avail, t0, 0);
        assert_eq!(ev.actions.len(), 2);
    }

    #[test]
    fn a_kill_that_did_not_happen_is_not_judged() {
        let t0 = Instant::now();
        let mut g = KillGate::default();
        let timeout = Duration::from_secs(70);
        // dry-run: the victim stays alive and is forgotten after the timeout
        g.proposed(&culprit(400, 512), 100 * MIB, t0);
        assert!(g.observe(t0 + Duration::from_secs(60), 100 * MIB, |_, _| true, timeout).is_none());
        assert!(g.pending.is_some());
        assert!(g.observe(t0 + Duration::from_secs(71), 100 * MIB, |_, _| true, timeout).is_none());
        assert!(g.pending.is_none());
        assert!(g.admit(3).is_ok());
        // a small victim is not judged by MemAvailable (noise)
        g.proposed(&culprit(401, 40), 100 * MIB, t0);
        assert!(g.observe(t0, 100 * MIB, |_, _| false, timeout).is_none());
        assert!(g.admit(3).is_ok());
    }

    #[test]
    fn ranking_on_live_system() {
        let cfg = CulpritConfig { min_rss: warden_core::ByteSize(0), ..Default::default() };
        let prot = Protection::new(&ProtectionConfig::default());
        let mut act = Activity::default();
        let r = rank_culprits(&cfg, &prot, &mut act, 8 << 30, 5);
        assert!(!r.is_empty());
        assert!(r.windows(2).all(|w| w[0].score >= w[1].score));
        // the badness counts what a kill frees: never more than the RSS
        assert!(r.iter().all(|c| c.anon <= c.rss), "{r:?}");
        // Warden's own test process must never be a victim.
        let me = std::process::id() as i32;
        assert!(r.iter().filter(|c| c.pid == me).all(|c| c.protected.is_some()));
    }
}
