//! The event model. Every detector speaks only in [`Event`]s; the engine
//! applies policy, notifies, records and executes the attached actions.

use crate::action::ActionSpec;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[default]
    Info,
    Notice,
    Warning,
    Critical,
    Emergency,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Notice => "notice",
            Severity::Warning => "warning",
            Severity::Critical => "critical",
            Severity::Emergency => "emergency",
        }
    }

    pub fn emoji(self) -> &'static str {
        match self {
            Severity::Info => "ℹ️",
            Severity::Notice => "🔵",
            Severity::Warning => "🟠",
            Severity::Critical => "🔴",
            Severity::Emergency => "🚨",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(Severity::Info),
            "notice" => Ok(Severity::Notice),
            "warning" | "warn" => Ok(Severity::Warning),
            "critical" | "crit" => Ok(Severity::Critical),
            "emergency" | "emerg" => Ok(Severity::Emergency),
            other => Err(format!("unknown severity {other:?}")),
        }
    }
}

/// Identity of a process. `start_time` (clock ticks after boot, field 22 of
/// `/proc/<pid>/stat`) makes the reference immune to PID reuse: every action
/// re-validates it before touching the process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProcessRef {
    pub pid: i32,
    pub start_time: u64,
    pub comm: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exe: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmdline: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ppid: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,
    /// Container the process runs in (`docker:web-1`, `k8s:pod/...`), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container: Option<String>,
}

impl fmt::Display for ProcessRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}[{}]", self.comm, self.pid)?;
        if let Some(u) = &self.user {
            write!(f, " user={u}")?;
        } else if let Some(u) = self.uid {
            write!(f, " uid={u}")?;
        }
        if let Some(exe) = &self.exe {
            write!(f, " exe={exe}")?;
        }
        if let Some(c) = &self.container {
            write!(f, " container={c}")?;
        }
        Ok(())
    }
}

/// What the event is about. Actions are resolved against the subject:
/// `kill` kills the subject process, `quarantine` quarantines the subject
/// file, `block_ip` blocks the subject address, and so on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Subject {
    #[default]
    System,
    Process(ProcessRef),
    File {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        site: Option<String>,
    },
    Mount {
        path: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        device: Option<String>,
    },
    Unit {
        name: String,
    },
    Ip {
        addr: IpAddr,
    },
    User {
        name: String,
    },
    Cgroup {
        path: String,
    },
}

impl fmt::Display for Subject {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Subject::System => f.write_str("system"),
            Subject::Process(p) => write!(f, "process {p}"),
            Subject::File { path, site: Some(s) } => write!(f, "file {path} (site {s})"),
            Subject::File { path, site: None } => write!(f, "file {path}"),
            Subject::Mount { path, .. } => write!(f, "mount {path}"),
            Subject::Unit { name } => write!(f, "unit {name}"),
            Subject::Ip { addr } => write!(f, "ip {addr}"),
            Subject::User { name } => write!(f, "user {name}"),
            Subject::Cgroup { path } => write!(f, "cgroup {path}"),
        }
    }
}

static NEXT_ID: AtomicU64 = AtomicU64::new(0);

/// Seed from the wall clock on first use: ids of a new run are larger than
/// those of the previous one as long as the clock did not go backwards (see
/// [`resume_ids_after`] for when it did).
fn seeded() {
    if NEXT_ID.load(Ordering::Relaxed) == 0 {
        let seed = now_ms().saturating_mul(1000);
        let _ = NEXT_ID.compare_exchange(0, seed, Ordering::SeqCst, Ordering::Relaxed);
    }
}

fn next_id() -> u64 {
    seeded();
    NEXT_ID.fetch_add(1, Ordering::SeqCst)
}

/// Make every id handed out from now on greater than `last` — the highest id
/// found in the persisted event journal. A clock that stepped back across a
/// restart (the daemon itself reports `clock_unsynchronized`) would
/// otherwise reuse ids and break `wardenctl events --since-id`.
pub fn resume_ids_after(last: u64) {
    seeded();
    NEXT_ID.fetch_max(last.saturating_add(1), Ordering::SeqCst);
}

/// Detail key set on an event whose source deliberately does not block its
/// address (`auth.ssh_block = false`, `waf.block = false`,
/// `fim.block_attackers = false`, a policy that took the block away). The
/// value says why. Heuristics still count the event towards the address's
/// suspicion score, but it cannot be the event that triggers their block.
pub const IP_BLOCK_OFF: &str = "ip_block_off";

/// Detail key set on an event whose actions were withheld on purpose: a
/// process found at startup with `process.act_on_existing = false`, a policy
/// `alert_only`. The value says why. Heuristics still count the event
/// towards the process's suspicion score, but it cannot be the event that
/// makes them contain the process (`heuristics.contain` and its
/// `on_contain` actions) — otherwise the operator's "do not act" would be
/// undone one step later (0.13.3).
pub const ACTIONS_WITHHELD: &str = "actions_withheld";

/// End the episodes an event closes, in a de-duplication table keyed by
/// fingerprint (called after the event itself was recorded).
///
/// A condition and its resolution alternate. The resolution of condition
/// `X` has the fingerprint `X:resolved`; the condition's own fingerprint is
/// `X` or `X:<detail>` — detectors add the severity or the PID
/// (`cpu.pressure:warning`, `disk.space:/:critical`,
/// `memory.pressure:warning:1234`). So:
///
/// * `X:resolved` ends `X` and every `X:…`: when the condition comes back
///   it is a new episode, not a repeat of the last one;
/// * a condition ends the resolutions of itself and of every colon-prefix of
///   its fingerprint: when it clears again, that is reported too.
///
/// Without this a link going down, up and down within the window, or a disk
/// at "warning → resolved → warning" within the notifier's 15 minutes, lost
/// the last change, and the chat kept showing "resolved".
pub fn end_episodes<V>(seen: &mut HashMap<String, V>, fingerprint: &str) {
    if let Some(cond) = fingerprint.strip_suffix(":resolved") {
        seen.retain(|k, _| {
            let ends =
                k == cond || (k != fingerprint && k.strip_prefix(cond).is_some_and(|rest| rest.starts_with(':')));
            !ends
        });
    } else {
        let mut p = fingerprint;
        loop {
            seen.remove(&format!("{p}:resolved"));
            match p.rfind(':') {
                Some(i) => p = &p[..i],
                None => break,
            }
        }
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

pub fn format_ts_ms(ms: u64) -> String {
    let t = UNIX_EPOCH + std::time::Duration::from_millis(ms);
    humantime::format_rfc3339_seconds(t).to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub id: u64,
    /// Unix time, milliseconds.
    pub ts_ms: u64,
    /// Hierarchical kind, e.g. `memory.pressure`, `security.privilege_escalation`.
    pub kind: String,
    pub severity: Severity,
    /// Detector that produced the event.
    pub source: String,
    pub title: String,
    pub subject: Subject,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub details: BTreeMap<String, serde_json::Value>,
    /// Deduplication key; events with the same fingerprint are coalesced.
    pub fingerprint: String,
    /// Proposed remediation; filtered by policy and safety guards.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub actions: Vec<ActionSpec>,
    /// `true` for "condition cleared" events.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub resolved: bool,
}

impl Event {
    pub fn new(kind: impl Into<String>, severity: Severity, title: impl Into<String>) -> Self {
        let kind = kind.into();
        Self {
            id: next_id(),
            ts_ms: now_ms(),
            fingerprint: kind.clone(),
            kind,
            severity,
            source: String::new(),
            title: title.into(),
            subject: Subject::System,
            details: BTreeMap::new(),
            actions: Vec::new(),
            resolved: false,
        }
    }

    pub fn source(mut self, s: impl Into<String>) -> Self {
        self.source = s.into();
        self
    }

    pub fn subject(mut self, s: Subject) -> Self {
        self.subject = s;
        self
    }

    pub fn detail(mut self, k: impl Into<String>, v: impl Into<serde_json::Value>) -> Self {
        self.details.insert(k.into(), v.into());
        self
    }

    pub fn fingerprint(mut self, f: impl Into<String>) -> Self {
        self.fingerprint = f.into();
        self
    }

    pub fn actions(mut self, a: Vec<ActionSpec>) -> Self {
        self.actions = a;
        self
    }

    pub fn resolved(mut self) -> Self {
        self.resolved = true;
        self
    }

    pub fn time(&self) -> String {
        format_ts_ms(self.ts_ms)
    }

    pub fn process(&self) -> Option<&ProcessRef> {
        match &self.subject {
            Subject::Process(p) => Some(p),
            _ => None,
        }
    }

    /// Environment for operator hooks (`exec` actions, notification
    /// commands). The JSON is capped below the kernel's limit for one
    /// environment string (128 KiB); a larger event is passed without its
    /// `details`.
    pub fn hook_env(&self) -> Vec<(&'static str, String)> {
        const MAX_ENV_STRING: usize = 100_000;
        let mut json = serde_json::to_string(self).unwrap_or_default();
        if json.len() > MAX_ENV_STRING {
            let mut slim = self.clone();
            slim.details.clear();
            json = serde_json::to_string(&slim).unwrap_or_default();
        }
        vec![
            ("WARDEN_EVENT_JSON", json),
            ("WARDEN_EVENT_KIND", self.kind.clone()),
            ("WARDEN_SEVERITY", self.severity.as_str().to_owned()),
            ("WARDEN_SUBJECT", self.subject.to_string()),
            ("WARDEN_TITLE", self.title.clone()),
        ]
    }

    /// How much losing this event would cost, 0 (routine) to 4: what an
    /// event queue that overflows keeps longest. The severity, one level up
    /// for `security.*`; resolutions at least 2 (a lost one leaves an
    /// incident open), action results at least 3 (the record of what
    /// Warden did; their number is bounded by the action budgets).
    pub fn priority(&self) -> u8 {
        let mut p = match self.severity {
            Severity::Info => 0,
            Severity::Notice => 1,
            Severity::Warning => 2,
            Severity::Critical => 3,
            Severity::Emergency => 4,
        };
        if self.kind.starts_with("security.") {
            p += 1;
        }
        if self.resolved {
            p = p.max(2);
        }
        if self.kind.starts_with("action.") {
            p = p.max(3);
        }
        p.min(4)
    }

    /// Whether the actions include urgent containment ([`ActionSpec::is_urgent`]).
    pub fn has_urgent_actions(&self) -> bool {
        self.actions.iter().any(ActionSpec::is_urgent)
    }

    /// One-line human summary used by log output and notifications.
    pub fn summary(&self) -> String {
        let state = if self.resolved { " [resolved]" } else { "" };
        format!("[{}] {}{}: {} ({})", self.severity, self.kind, state, self.title, self.subject)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_order_and_parse() {
        assert!(Severity::Critical > Severity::Warning);
        assert_eq!("crit".parse::<Severity>().unwrap(), Severity::Critical);
        assert!("bogus".parse::<Severity>().is_err());
    }

    #[test]
    fn ids_are_monotonic() {
        let a = Event::new("a", Severity::Info, "a");
        let b = Event::new("b", Severity::Info, "b");
        assert!(b.id > a.id);
        // a journal written by a run whose clock was ahead of ours
        let far = b.id + 1_000_000;
        resume_ids_after(far);
        assert!(Event::new("c", Severity::Info, "c").id > far);
        // resuming below the current counter never moves it back
        resume_ids_after(1);
        assert!(Event::new("d", Severity::Info, "d").id > far);
    }

    #[test]
    fn a_resolution_ends_the_condition_whatever_detail_its_fingerprint_carries() {
        let table = |keys: &[&str]| -> HashMap<String, ()> { keys.iter().map(|k| ((*k).to_owned(), ())).collect() };
        let keys = |m: &HashMap<String, ()>| {
            let mut v: Vec<String> = m.keys().cloned().collect();
            v.sort();
            v
        };
        let mut m = table(&[
            "disk.space:/:warning",
            "disk.space:/:critical",
            "disk.space:/home:warning",
            "network.link:eth0",
            "network.link:eth01",
            "disk.space:/:resolved",
        ]);
        end_episodes(&mut m, "disk.space:/:resolved");
        assert_eq!(
            keys(&m),
            ["disk.space:/:resolved", "disk.space:/home:warning", "network.link:eth0", "network.link:eth01"]
        );
        end_episodes(&mut m, "network.link:eth0:resolved");
        assert_eq!(keys(&m), ["disk.space:/:resolved", "disk.space:/home:warning", "network.link:eth01"]);
        // the condition comes back: its earlier resolution is forgotten
        let mut m = table(&["disk.space:/:resolved", "memory.pressure:resolved", "disk.space:/home:resolved"]);
        end_episodes(&mut m, "disk.space:/:warning");
        end_episodes(&mut m, "memory.pressure:critical:1234");
        assert_eq!(keys(&m), ["disk.space:/home:resolved"]);
    }

    #[test]
    fn hook_env_is_bounded() {
        let small = Event::new("k.x", Severity::Warning, "t").detail("a", 1);
        let env: std::collections::HashMap<_, _> = small.hook_env().into_iter().collect();
        assert_eq!(env["WARDEN_EVENT_KIND"], "k.x");
        assert_eq!(env["WARDEN_SEVERITY"], "warning");
        assert!(env["WARDEN_EVENT_JSON"].contains("\"a\":1"));
        let big = Event::new("k.x", Severity::Warning, "t").detail("blob", "x".repeat(300_000));
        let env: std::collections::HashMap<_, _> = big.hook_env().into_iter().collect();
        assert!(env["WARDEN_EVENT_JSON"].len() < 100_000);
        assert!(env["WARDEN_EVENT_JSON"].contains("k.x"));
    }

    #[test]
    fn event_roundtrips_json() {
        let e = Event::new("security.test", Severity::Critical, "x")
            .subject(Subject::Process(ProcessRef { pid: 42, start_time: 7, comm: "sh".into(), ..Default::default() }))
            .detail("k", 1)
            .actions(vec![ActionSpec::Snapshot]);
        let s = serde_json::to_string(&e).unwrap();
        let back: Event = serde_json::from_str(&s).unwrap();
        assert_eq!(back.kind, "security.test");
        assert_eq!(back.process().unwrap().pid, 42);
        assert_eq!(back.actions, vec![ActionSpec::Snapshot]);
    }
}
