//! Conditions: the lifecycle every "something is wrong" a detector reports
//! has to have.
//!
//! ```text
//!   hold() ─▶ Opened ─▶ (holds) ─▶ Reminder 1 … n (backoff) ─▶ (stops holding
//!                 ▲          └──▶ Escalated / Lowered           for clear_after)
//!                 └──────────────────────────────────────────────▶ Closed
//! ```
//!
//! A detector calls [`Conditions::hold`] for every condition that holds on a
//! pass (a scan, a tick) and [`Conditions::sweep`] at the end of it: what
//! has not held for `clear_after` is closed, and the detector reports its
//! resolution. While a condition holds it is reported again with an
//! exponential backoff (`first_reminder`, doubling, at most
//! `max_reminder`) instead of on a fixed cooldown: a worker that stays
//! over a limit for days is one problem, not a message every ten minutes
//! (0.13.3: `process.cpu_hog`, `process.limit_exceeded`,
//! `process.uninterruptible`, `limits.process_fds`, `security.miner_port`
//! repeated forever and were never resolved).
//!
//! Fingerprints follow the convention of [`crate::event::end_episodes`]: a
//! condition `key` (`kind` or `kind:<subject>`) is reported as
//! `key:<severity>` and resolved as `key:resolved`.

use crate::event::{Event, Severity, Subject};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

/// How a family of conditions is reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    /// First reminder after the condition opened.
    pub first_reminder: Duration,
    /// Reminders double up to this interval.
    pub max_reminder: Duration,
    /// A condition that has not held for this long is closed.
    pub clear_after: Duration,
}

impl Policy {
    pub const fn new(first_reminder: Duration, max_reminder: Duration, clear_after: Duration) -> Self {
        Self { first_reminder, max_reminder, clear_after }
    }
}

/// The interval before reminder `n + 1` (0-based): `first`, `2·first`,
/// `4·first` … capped at `max`.
pub fn backoff(first: Duration, max: Duration, n: u32) -> Duration {
    first.saturating_mul(1u32 << n.min(20)).min(max)
}

/// What to report for a condition that holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Report {
    /// It just started: report it (with its actions).
    Opened,
    /// Its severity went up / down: report the change.
    Escalated,
    Lowered,
    /// Still holding: the `n`-th reminder (1-based).
    Reminder(u32),
}

impl Report {
    /// A first report or a change, as opposed to a reminder.
    pub fn is_new(self) -> bool {
        !matches!(self, Report::Reminder(_))
    }
}

#[derive(Debug, Clone)]
struct Open {
    kind: String,
    severity: Severity,
    subject: Subject,
    label: String,
    opened: Instant,
    /// Last pass it held (monotonic clock: hysteresis).
    seen: Instant,
    /// Last report (real clock: an interval a person reads).
    reported: Instant,
    reminders: u32,
}

/// A condition that was closed: report its resolution with [`Closed::event`].
#[derive(Debug, Clone, PartialEq)]
pub struct Closed {
    pub key: String,
    pub kind: String,
    pub severity: Severity,
    pub subject: Subject,
    pub label: String,
    /// From the opening to the last pass it held.
    pub lasted: Duration,
}

impl Closed {
    /// The resolution: `kind`, `info`, `key:resolved`, the subject the
    /// condition was reported with.
    pub fn event(&self, title: impl Into<String>) -> Event {
        Event::new(self.kind.clone(), Severity::Info, title)
            .subject(self.subject.clone())
            .fingerprint(format!("{}:resolved", self.key))
            .detail("lasted_seconds", self.lasted.as_secs())
            .resolved()
    }

    /// [`Closed::event`] with a title made from the label.
    pub fn resolved_event(&self) -> Event {
        self.event(format!("{} — no longer the case", self.label))
    }
}

/// The open conditions of one detector.
#[derive(Debug, Clone)]
pub struct Conditions {
    policy: Policy,
    open: BTreeMap<String, Open>,
}

impl Conditions {
    pub fn new(policy: Policy) -> Self {
        Self { policy, open: BTreeMap::new() }
    }

    pub fn policy(&self) -> Policy {
        self.policy
    }

    /// A reload changed the timings: open conditions keep their state.
    pub fn set_policy(&mut self, policy: Policy) {
        self.policy = policy;
    }

    /// The fingerprint of a report of `key` at `sev`.
    pub fn fingerprint(key: &str, sev: Severity) -> String {
        format!("{key}:{sev}")
    }

    /// `key` (of `kind`) holds at `sev` on this pass. Returns what to report,
    /// `None` when nothing is due. `now` is the monotonic clock, `real` the
    /// one that runs during suspend (see `warden_sys::clock`).
    pub fn hold(&mut self, key: &str, kind: &str, sev: Severity, now: Instant, real: Instant) -> Option<Report> {
        let Some(o) = self.open.get_mut(key) else {
            self.open.insert(
                key.to_owned(),
                Open {
                    kind: kind.to_owned(),
                    severity: sev,
                    subject: Subject::System,
                    label: key.to_owned(),
                    opened: now,
                    seen: now,
                    reported: real,
                    reminders: 0,
                },
            );
            return Some(Report::Opened);
        };
        o.seen = now;
        if sev != o.severity {
            let up = sev > o.severity;
            o.severity = sev;
            o.reported = real;
            o.reminders = 0;
            return Some(if up { Report::Escalated } else { Report::Lowered });
        }
        let due = backoff(self.policy.first_reminder, self.policy.max_reminder, o.reminders);
        if real.saturating_duration_since(o.reported) >= due {
            o.reminders += 1;
            o.reported = real;
            return Some(Report::Reminder(o.reminders));
        }
        None
    }

    /// What the resolution of `key` says: the subject it was reported with
    /// and a short label ("php-fpm8.3[812] over limit \"fat worker\"").
    pub fn describe(&mut self, key: &str, subject: Subject, label: impl Into<String>) {
        if let Some(o) = self.open.get_mut(key) {
            o.subject = subject;
            o.label = label.into();
        }
    }

    /// Drop `key` without a resolution: it was opened but never reported
    /// (the process vanished before its details could be read).
    pub fn forget(&mut self, key: &str) {
        self.open.remove(key);
    }

    pub fn is_open(&self, key: &str) -> bool {
        self.open.contains_key(key)
    }

    pub fn severity(&self, key: &str) -> Option<Severity> {
        self.open.get(key).map(|o| o.severity)
    }

    /// The interval to the next reminder of `key`, for "next reminder in".
    pub fn next_reminder_in(&self, key: &str) -> Option<Duration> {
        self.open.get(key).map(|o| backoff(self.policy.first_reminder, self.policy.max_reminder, o.reminders))
    }

    pub fn len(&self) -> usize {
        self.open.len()
    }

    pub fn is_empty(&self) -> bool {
        self.open.is_empty()
    }

    /// The worst open severity among conditions of kinds `filter` accepts.
    pub fn worst(&self, filter: impl Fn(&str) -> bool) -> Option<Severity> {
        self.open.values().filter(|o| filter(&o.kind)).map(|o| o.severity).max()
    }

    /// Close the conditions of kinds `filter` accepts that have not held
    /// for `clear_after`. Call it after a pass that checked those kinds (a
    /// check that runs every 4th scan sweeps only on those scans).
    pub fn sweep(&mut self, now: Instant, filter: impl Fn(&str) -> bool) -> Vec<Closed> {
        let clear = self.policy.clear_after;
        let gone: Vec<String> = self
            .open
            .iter()
            .filter(|(_, o)| filter(&o.kind) && now.saturating_duration_since(o.seen) >= clear)
            .map(|(k, _)| k.clone())
            .collect();
        gone.into_iter().filter_map(|k| self.take(&k)).collect()
    }

    /// Close one condition now (its subject is known to be gone).
    pub fn close(&mut self, key: &str) -> Option<Closed> {
        self.take(key)
    }

    /// Close everything (the detector is being removed).
    pub fn close_all(&mut self) -> Vec<Closed> {
        let keys: Vec<String> = self.open.keys().cloned().collect();
        keys.into_iter().filter_map(|k| self.take(&k)).collect()
    }

    fn take(&mut self, key: &str) -> Option<Closed> {
        self.open.remove(key).map(|o| Closed {
            key: key.to_owned(),
            kind: o.kind,
            severity: o.severity,
            subject: o.subject,
            label: o.label,
            lasted: o.seen.saturating_duration_since(o.opened),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(60);

    fn conds() -> Conditions {
        Conditions::new(Policy::new(10 * MIN, 24 * 60 * MIN, 2 * MIN))
    }

    #[test]
    fn backoff_doubles_and_is_capped() {
        let b: Vec<u64> = (0..10).map(|n| backoff(10 * MIN, 6 * 60 * MIN, n).as_secs() / 60).collect();
        assert_eq!(b, [10, 20, 40, 80, 160, 320, 360, 360, 360, 360]);
        assert_eq!(backoff(MIN, Duration::MAX, 1000), MIN.saturating_mul(1 << 20));
    }

    #[test]
    fn opens_reminds_with_backoff_and_closes() {
        let mut c = conds();
        let t0 = Instant::now();
        let k = "process.cpu_hog:812:99";
        let at = |m: u32| t0 + m * MIN;
        let mut reports = Vec::new();
        // holds every minute for 3 hours
        for m in 0..=180 {
            if let Some(r) = c.hold(k, "process.cpu_hog", Severity::Warning, at(m), at(m)) {
                reports.push((m, r));
            }
            assert!(c.sweep(at(m), |_| true).is_empty());
        }
        assert_eq!(
            reports,
            [
                (0, Report::Opened),
                (10, Report::Reminder(1)),
                (30, Report::Reminder(2)),
                (70, Report::Reminder(3)),
                (150, Report::Reminder(4)),
            ]
        );
        assert_eq!(c.next_reminder_in(k), Some(160 * MIN));
        c.describe(k, Subject::System, "php-fpm8.3[812] at 100% CPU");
        // stops holding: closed after clear_after, once
        assert!(c.sweep(at(181), |_| true).is_empty());
        let closed = c.sweep(at(182), |_| true);
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].lasted, 180 * MIN);
        let ev = closed[0].resolved_event();
        assert_eq!(ev.fingerprint, "process.cpu_hog:812:99:resolved");
        assert!(ev.resolved && ev.title.starts_with("php-fpm8.3[812] at 100% CPU"));
        assert!(c.is_empty());
        // and opens anew
        assert_eq!(c.hold(k, "process.cpu_hog", Severity::Warning, at(200), at(200)), Some(Report::Opened));
    }

    #[test]
    fn a_severity_change_is_reported_at_once() {
        let mut c = conds();
        let t0 = Instant::now();
        assert_eq!(c.hold("x", "x", Severity::Warning, t0, t0), Some(Report::Opened));
        assert_eq!(c.hold("x", "x", Severity::Critical, t0, t0), Some(Report::Escalated));
        assert_eq!(c.hold("x", "x", Severity::Critical, t0, t0), None);
        assert_eq!(c.hold("x", "x", Severity::Warning, t0, t0), Some(Report::Lowered));
        assert_eq!(Conditions::fingerprint("disk.inodes:/", Severity::Critical), "disk.inodes:/:critical");
    }

    #[test]
    fn sweep_only_touches_the_kinds_that_were_checked() {
        let mut c = conds();
        let t0 = Instant::now();
        c.hold("limits.process_fds:1:1", "limits.process_fds", Severity::Warning, t0, t0);
        c.hold("process.cpu_hog:2:2", "process.cpu_hog", Severity::Warning, t0, t0);
        let later = t0 + 10 * MIN;
        let closed = c.sweep(later, |k| k != "limits.process_fds");
        assert_eq!(closed.iter().map(|c| c.key.as_str()).collect::<Vec<_>>(), ["process.cpu_hog:2:2"]);
        assert!(c.is_open("limits.process_fds:1:1"));
        assert_eq!(c.worst(|_| true), Some(Severity::Warning));
        assert_eq!(c.close_all().len(), 1);
    }

    #[test]
    fn reminders_follow_the_real_clock() {
        // asleep for 8 hours: the monotonic clock moved a minute, the real one 8 h
        let mut c = conds();
        let t0 = Instant::now();
        c.hold("x", "x", Severity::Warning, t0, t0);
        let r = c.hold("x", "x", Severity::Warning, t0 + MIN, t0 + 8 * 60 * MIN);
        assert_eq!(r, Some(Report::Reminder(1)));
        // ...and clear_after the monotonic one
        assert!(c.sweep(t0 + 2 * MIN, |_| true).is_empty());
    }
}
