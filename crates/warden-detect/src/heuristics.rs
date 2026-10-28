//! Heuristic suspicion scoring and process-lineage learning.
//!
//! Single findings are often ambiguous (a PHP worker running `id` may be a
//! monitoring plugin). Scores accumulate per process and per remote IP with
//! exponential decay; crossing `alert_score` raises an alert, crossing
//! `contain_score` contains the process, crossing `ip_block_score` blocks the
//! address. Lineage learning remembers which programs each service normally
//! starts and reports never-seen pairs after the learning period.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use warden_core::config::HeuristicsConfig;
use warden_core::event::now_ms;
use warden_core::{ActionSpec, Event, ProcessRef, Severity, Subject};

#[derive(Debug, Clone)]
struct Entry {
    score: f64,
    at: Instant,
    label: String,
    reasons: Vec<String>,
    alerted: bool,
    contained: bool,
    process: Option<ProcessRef>,
}

impl Entry {
    fn decayed(&self, now: Instant, half_life: Duration) -> f64 {
        let dt = now.saturating_duration_since(self.at).as_secs_f64();
        let hl = half_life.as_secs_f64().max(1.0);
        self.score * 0.5f64.powf(dt / hl)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScoreView {
    pub entity: String,
    pub score: f64,
    pub reasons: Vec<String>,
    pub contained: bool,
}

#[derive(Debug)]
pub struct Heuristics {
    cfg: HeuristicsConfig,
    procs: HashMap<(i32, u64), Entry>,
    ips: HashMap<IpAddr, Entry>,
    /// Expiry runs when a table grows past its mark (doubling after each
    /// pass), never on every event: before 0.14.2 the address table was
    /// not expired at all unless the process table was large (N3).
    procs_gc_at: usize,
    ips_gc_at: usize,
    evicted: u64,
}

/// Entries per table at most; past it the lowest scores are forgotten.
const MAX_ENTRIES: usize = 50_000;
const GC_MIN: usize = 4096;

impl Heuristics {
    pub fn new(cfg: &HeuristicsConfig) -> Self {
        Self {
            cfg: cfg.clone(),
            procs: HashMap::new(),
            ips: HashMap::new(),
            procs_gc_at: GC_MIN,
            ips_gc_at: GC_MIN,
            evicted: 0,
        }
    }

    /// (processes, addresses, entries evicted by the cap)
    pub fn table_sizes(&self) -> (usize, usize, u64) {
        (self.procs.len(), self.ips.len(), self.evicted)
    }

    /// Expire decayed entries when a table has grown; cap both tables.
    fn housekeeping(&mut self, now: Instant) {
        let hl = self.cfg.half_life;
        if self.procs.len() > self.procs_gc_at {
            self.procs.retain(|_, e| e.decayed(now, hl) >= 1.0);
            self.procs_gc_at = (self.procs.len() * 2).clamp(GC_MIN, MAX_ENTRIES);
        }
        if self.ips.len() > self.ips_gc_at {
            self.ips.retain(|_, e| e.decayed(now, hl) >= 1.0);
            self.ips_gc_at = (self.ips.len() * 2).clamp(GC_MIN, MAX_ENTRIES);
        }
        let keep = MAX_ENTRIES - MAX_ENTRIES / 10;
        // score in tenths, as the thresholds compare it
        let rank = |e: &Entry| (e.decayed(now, hl) * 10.0) as i64;
        if self.procs.len() > MAX_ENTRIES {
            self.evicted += warden_core::ratelimit::evict_lowest(&mut self.procs, keep, rank) as u64;
        }
        if self.ips.len() > MAX_ENTRIES {
            self.evicted += warden_core::ratelimit::evict_lowest(&mut self.ips, keep, rank) as u64;
        }
    }

    pub fn set_config(&mut self, cfg: &HeuristicsConfig) {
        self.cfg = cfg.clone();
    }

    fn weight(&self, kind: &str) -> f64 {
        let k = kind.strip_prefix("security.").unwrap_or(kind);
        self.cfg.weights.get(k).copied().unwrap_or(0.0)
    }

    fn bump(e: &mut Entry, w: f64, reason: &str, now: Instant, hl: Duration) {
        e.score = e.decayed(now, hl) + w;
        e.at = now;
        if e.reasons.len() < 12 && !e.reasons.iter().any(|r| r == reason) {
            e.reasons.push(reason.to_owned());
        }
    }

    /// Account a security event; returns escalation events.
    pub fn record(&mut self, ev: &Event, now: Instant) -> Vec<Event> {
        if !self.cfg.enabled || ev.resolved || !ev.kind.starts_with("security.") {
            return Vec::new();
        }
        let w = self.weight(&ev.kind);
        if w <= 0.0 {
            return Vec::new();
        }
        let hl = self.cfg.half_life;
        let reason = ev.kind.trim_start_matches("security.").to_owned();
        let mut out = Vec::new();

        if let Subject::Process(p) = &ev.subject {
            let e = self.procs.entry((p.pid, p.start_time)).or_insert_with(|| Entry {
                score: 0.0,
                at: now,
                label: format!("{}[{}]", p.comm, p.pid),
                reasons: Vec::new(),
                alerted: false,
                contained: false,
                process: Some(p.clone()),
            });
            Self::bump(e, w, &reason, now, hl);
            // Round so that decay over a few seconds does not keep a score
            // a hair below an integer threshold.
            let s = (e.score * 10.0).round() / 10.0;
            // Actions withheld on purpose (a process found at startup with
            // act_on_existing = false, a policy alert_only): the evidence
            // counts, but this event cannot make us contain the process.
            let withheld = ev.details.get(warden_core::event::ACTIONS_WITHHELD).cloned();
            if s >= self.cfg.contain_score && !e.contained && withheld.is_none() {
                e.contained = true;
                out.push(
                    Event::new(
                        "heuristics.contain",
                        Severity::Critical,
                        format!("{} reached suspicion score {s:.0} ({}) — containing", e.label, e.reasons.join(", ")),
                    )
                    .subject(ev.subject.clone())
                    .fingerprint(format!("heuristics.contain:{}:{}", p.pid, p.start_time))
                    .detail("score", s.round())
                    .detail("reasons", e.reasons.clone())
                    .actions(self.cfg.on_contain.clone()),
                );
            } else if s >= self.cfg.alert_score && !e.alerted {
                e.alerted = true;
                let mut sus = Event::new(
                    "heuristics.suspicious",
                    Severity::Warning,
                    format!("{} accumulated suspicion score {s:.0}: {}", e.label, e.reasons.join(", ")),
                )
                .subject(ev.subject.clone())
                .fingerprint(format!("heuristics.suspicious:{}:{}", p.pid, p.start_time))
                .detail("score", s.round())
                .detail("reasons", e.reasons.clone());
                if let Some(why) = withheld.filter(|_| s >= self.cfg.contain_score) {
                    sus = sus.detail("containment_withheld", why);
                }
                out.push(sus);
            }
            // Half the weight flows to the parent: a worker that keeps
            // spawning suspicious children becomes suspicious itself.
            if let Some(ppid) = p.ppid
                && ppid > 1
                && let Some(pst) = warden_sys::process::start_time(ppid)
            {
                let pe = self.procs.entry((ppid, pst)).or_insert_with(|| Entry {
                    score: 0.0,
                    at: now,
                    label: format!("parent[{ppid}]"),
                    reasons: Vec::new(),
                    alerted: false,
                    contained: false,
                    process: None,
                });
                Self::bump(pe, w / 2.0, &format!("child:{reason}"), now, hl);
            }
        }

        let ip = match &ev.subject {
            Subject::Ip { addr } => Some(*addr),
            _ => ev.details.get("ip").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()),
        };
        if let Some(ip) = ip {
            let e = self.ips.entry(ip).or_insert_with(|| Entry {
                score: 0.0,
                at: now,
                label: ip.to_string(),
                reasons: Vec::new(),
                alerted: false,
                contained: false,
                process: None,
            });
            Self::bump(e, w, &reason, now, hl);
            let already_blocking = ev.actions.iter().any(|a| matches!(a, ActionSpec::BlockIp { .. }));
            // The source decided not to block this address (switched off by
            // the operator, allowlisted, a policy): the evidence still counts
            // towards the score, but this event does not trigger the block —
            // a later event from a source that does block may.
            let held = ev.details.contains_key(warden_core::event::IP_BLOCK_OFF)
                || ev.details.contains_key(warden_core::event::ACTIONS_WITHHELD)
                || ev.details.get("allowlisted").and_then(|v| v.as_bool()) == Some(true);
            if (e.score * 10.0).round() / 10.0 >= self.cfg.ip_block_score && !e.contained && !already_blocking && !held
            {
                e.contained = true;
                out.push(
                    Event::new(
                        "heuristics.ip_threshold",
                        Severity::Warning,
                        format!("remote {ip} reached suspicion score {:.0} ({})", e.score, e.reasons.join(", ")),
                    )
                    .subject(Subject::Ip { addr: ip })
                    .fingerprint(format!("heuristics.ip_threshold:{ip}"))
                    .detail("score", e.score.round())
                    .detail("reasons", e.reasons.clone())
                    .actions(vec![ActionSpec::BlockIp { ttl: None }]),
                );
            }
        }
        self.housekeeping(now);
        out
    }

    pub fn gc(&mut self, now: Instant) {
        let hl = self.cfg.half_life;
        self.procs.retain(|_, e| e.decayed(now, hl) >= 1.0);
        self.ips.retain(|_, e| e.decayed(now, hl) >= 1.0);
        self.procs_gc_at = (self.procs.len() * 2).clamp(GC_MIN, MAX_ENTRIES);
        self.ips_gc_at = (self.ips.len() * 2).clamp(GC_MIN, MAX_ENTRIES);
    }

    pub fn view(&self, now: Instant) -> Vec<ScoreView> {
        let hl = self.cfg.half_life;
        let mut v: Vec<ScoreView> = self
            .procs
            .values()
            .map(|e| ScoreView {
                entity: match &e.process {
                    Some(p) => format!("process {p}"),
                    None => format!("process {}", e.label),
                },
                score: (e.decayed(now, hl) * 10.0).round() / 10.0,
                reasons: e.reasons.clone(),
                contained: e.contained,
            })
            .chain(self.ips.values().map(|e| ScoreView {
                entity: format!("ip {}", e.label),
                score: (e.decayed(now, hl) * 10.0).round() / 10.0,
                reasons: e.reasons.clone(),
                contained: e.contained,
            }))
            .filter(|v| v.score >= 1.0)
            .collect();
        v.sort_by(|a, b| b.score.total_cmp(&a.score));
        v
    }

    pub fn max_score(&self, now: Instant) -> f64 {
        let hl = self.cfg.half_life;
        self.procs.values().chain(self.ips.values()).map(|e| e.decayed(now, hl)).fold(0.0, f64::max)
    }
}

// ---------------------------------------------------------------------------

#[derive(Debug, Default, Serialize, Deserialize)]
struct LineageFile {
    started_ms: u64,
    pairs: BTreeMap<String, Vec<String>>,
}

/// Learned `parent → child executable` pairs per service account.
#[derive(Debug)]
pub struct Lineage {
    path: Option<PathBuf>,
    started_ms: u64,
    learning: Duration,
    pairs: HashMap<String, HashSet<String>>,
    dirty: bool,
    enabled: bool,
}

impl Lineage {
    pub fn new(path: Option<PathBuf>, learning: Duration, enabled: bool) -> Self {
        let mut l = Self { path, started_ms: now_ms(), learning, pairs: HashMap::new(), dirty: true, enabled };
        if let Some(p) = &l.path
            && let Ok(s) = std::fs::read_to_string(p)
            && let Ok(f) = serde_json::from_str::<LineageFile>(&s)
        {
            l.started_ms = f.started_ms;
            l.pairs = f.pairs.into_iter().map(|(k, v)| (k, v.into_iter().collect())).collect();
            l.dirty = false;
        }
        l
    }

    pub fn learning(&self) -> bool {
        now_ms().saturating_sub(self.started_ms) < self.learning.as_millis() as u64
    }

    pub fn learning_remaining(&self) -> Duration {
        Duration::from_millis(
            (self.learning.as_millis() as u64).saturating_sub(now_ms().saturating_sub(self.started_ms)),
        )
    }

    /// Record a pair; returns true when it is new *and* learning is over.
    pub fn observe(&mut self, parent_key: &str, child: &str) -> bool {
        if !self.enabled {
            return false;
        }
        let set = self.pairs.entry(parent_key.to_owned()).or_default();
        if set.len() > 512 || set.contains(child) {
            return false;
        }
        set.insert(child.to_owned());
        self.dirty = true;
        !self.learning()
    }

    pub fn pairs(&self) -> usize {
        self.pairs.values().map(HashSet::len).sum()
    }

    pub fn save(&mut self) -> std::io::Result<()> {
        let Some(p) = self.path.clone() else { return Ok(()) };
        if !self.dirty {
            return Ok(());
        }
        let f = LineageFile {
            started_ms: self.started_ms,
            pairs: self
                .pairs
                .iter()
                .map(|(k, v)| {
                    let mut v: Vec<String> = v.iter().cloned().collect();
                    v.sort();
                    (k.clone(), v)
                })
                .collect(),
        };
        warden_sys::util::write_atomic(&p, serde_json::to_string_pretty(&f)?.as_bytes())?;
        self.dirty = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proc_event(kind: &str) -> Event {
        Event::new(kind, Severity::Warning, "x").subject(Subject::Process(ProcessRef {
            pid: 999_999,
            start_time: 1,
            comm: "sh".into(),
            ..Default::default()
        }))
    }

    #[test]
    fn scores_accumulate_and_escalate_once() {
        let mut h = Heuristics::new(&HeuristicsConfig::default());
        let now = Instant::now();
        // web_spawn = 30, alert at 60, contain at 120
        assert!(h.record(&proc_event("security.web_spawn"), now).is_empty());
        let v = h.record(&proc_event("security.web_spawn"), now);
        assert_eq!(v[0].kind, "heuristics.suspicious");
        assert!(h.record(&proc_event("security.web_spawn"), now).is_empty());
        let v = h.record(&proc_event("security.web_spawn"), now);
        assert_eq!(v[0].kind, "heuristics.contain");
        assert!(!v[0].actions.is_empty());
        assert!(h.record(&proc_event("security.web_spawn"), now).is_empty());
        assert!(h.max_score(now) >= 150.0);
    }

    /// Evidence from a process found at startup with act_on_existing =
    /// false counts, but cannot contain it (0.13.3 contained it anyway,
    /// one step after the detector had stripped its own actions).
    #[test]
    fn withheld_evidence_never_triggers_containment() {
        let mut h = Heuristics::new(&HeuristicsConfig::default());
        let now = Instant::now();
        let withheld = || {
            proc_event("security.web_spawn")
                .detail(warden_core::event::ACTIONS_WITHHELD, "process.act_on_existing = false")
        };
        // 30, 60 (suspicious), 90, 120: no containment
        let mut all = Vec::new();
        for _ in 0..5 {
            all.extend(h.record(&withheld(), now));
        }
        assert_eq!(all.len(), 1, "{:?}", all.iter().map(|e| &e.kind).collect::<Vec<_>>());
        assert_eq!(all[0].kind, "heuristics.suspicious");
        assert!(all.iter().all(|e| e.actions.is_empty()));
        // fresh evidence the operator did not withhold may contain it
        let v = h.record(&proc_event("security.web_spawn"), now);
        assert_eq!(v[0].kind, "heuristics.contain");
        // the suspicious alert says containment was held back when it would have happened
        let mut h = Heuristics::new(&HeuristicsConfig { alert_score: 120.0, ..Default::default() });
        let mut all = Vec::new();
        for _ in 0..4 {
            all.extend(h.record(&withheld(), now));
        }
        assert_eq!(all[0].details["containment_withheld"], "process.act_on_existing = false");
    }

    #[test]
    fn scores_decay() {
        let mut h = Heuristics::new(&HeuristicsConfig::default());
        let now = Instant::now();
        h.record(&proc_event("security.exec_from_writable"), now);
        let later = now + Duration::from_secs(30 * 60);
        assert!((h.max_score(later) - 20.0).abs() < 0.5);
    }

    #[test]
    fn ip_threshold_blocks() {
        let mut h = Heuristics::new(&HeuristicsConfig::default());
        let now = Instant::now();
        let ev = Event::new("security.webshell_access", Severity::Warning, "x").detail("ip", "203.0.113.7");
        let v = h.record(&ev, now);
        assert_eq!(v[0].kind, "heuristics.ip_threshold");
        assert!(matches!(v[0].actions[0], ActionSpec::BlockIp { .. }));
    }

    #[test]
    fn an_address_the_source_chose_not_to_block_is_blocked_only_by_a_source_that_blocks() {
        let mut h = Heuristics::new(&HeuristicsConfig::default());
        let now = Instant::now();
        let ssh = Event::new("security.ssh_bruteforce", Severity::Warning, "x")
            .detail("ip", "203.0.113.8")
            .detail(warden_core::event::IP_BLOCK_OFF, "auth.ssh_block = false");
        assert!(h.record(&ssh, now).is_empty(), "60 points, but blocking is off for SSH");
        let allowed = Event::new("security.webshell_access", Severity::Critical, "x")
            .detail("ip", "203.0.113.8")
            .detail("allowlisted", true);
        assert!(h.record(&allowed, now).is_empty());
        // a source that does block: the accumulated evidence counts
        let web = Event::new("security.webshell_access", Severity::Critical, "x").detail("ip", "203.0.113.8");
        let v = h.record(&web, now);
        assert_eq!(v.len(), 1);
        assert!(v[0].details["reasons"].as_array().unwrap().iter().any(|r| r == "ssh_bruteforce"));
    }

    #[test]
    fn lineage_learning_and_persistence() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("lineage.json");
        let mut l = Lineage::new(Some(p.clone()), Duration::from_secs(3600), true);
        assert!(!l.observe("www-data:php-fpm8.3", "/usr/sbin/sendmail"));
        l.save().unwrap();
        let mut l2 = Lineage::new(Some(p), Duration::ZERO, true);
        assert_eq!(l2.pairs(), 1);
        assert!(!l2.observe("www-data:php-fpm8.3", "/usr/sbin/sendmail"));
        assert!(l2.observe("www-data:php-fpm8.3", "/usr/bin/nc"));
        assert!(!l2.observe("www-data:php-fpm8.3", "/usr/bin/nc"));
    }
}
