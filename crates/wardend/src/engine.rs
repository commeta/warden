//! The event engine: policy → dedup → journal → heuristics → notifications
//! → remediation. Remediation results come back as `action.*` events.

use crate::eventlog::{EventLog, Ring};
use crate::queue::{Dropped, EventQueue};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::mpsc::{RecvTimeoutError, SyncSender, TrySendError};
use std::time::{Duration, Instant};
use warden_core::policy::Policy;
use warden_core::sync::lock;
use warden_core::{Event, Severity};
use warden_detect::{Shared, Sink};
use warden_respond::{ActionResult, Responder, Status, snapshot};

/// Events queued for the action executor / the notifier. Both consume
/// slowly by nature (a `systemctl restart`, a webhook that times out); the
/// bound keeps a stuck consumer from turning an event storm into unbounded
/// (and, under `mlockall`, never-returned) memory.
pub const WORKER_QUEUE: usize = 1024;

/// Events between the detectors and the engine ([`EventQueue`]).
pub const EVENT_QUEUE: usize = 8192;

/// Build the sink detectors write into (bounded, never blocks; under a
/// flood the least important events go first).
pub fn sink(shared: Arc<Shared>, queue: Arc<EventQueue>) -> Sink {
    Sink::new(move |ev| {
        if let Some(d) = queue.push(ev) {
            let p = match d {
                Dropped::Incoming(p) | Dropped::Evicted(p) => p,
            };
            shared.dropped_events.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            shared.metrics.inc("warden_events_dropped_total", &[("priority", PRIORITY_LABELS[usize::from(p)])], 1.0);
        }
    })
}

const PRIORITY_LABELS: [&str; 5] = ["0", "1", "2", "3", "4"];

/// The executor's two queues (see [`warden_core::ActionSpec::is_urgent`]).
pub struct Lanes {
    pub urgent: SyncSender<Event>,
    pub slow: SyncSender<Event>,
}

pub struct Engine {
    shared: Arc<Shared>,
    policy: Policy,
    log: EventLog,
    dedup: HashMap<String, (Instant, Severity)>,
    dedup_gc_at: usize,
    generation: u64,
    notify_tx: SyncSender<Event>,
    respond: Lanes,
    /// Any notification channel configured? (Otherwise events are not
    /// copied to the notifier thread at all.)
    notify_enabled: bool,
    queue_drops: std::sync::atomic::AtomicU64,
}

fn notify_enabled(c: &warden_core::config::NotifyConfig) -> bool {
    !c.webhook.is_empty() || c.telegram.is_some() || !c.command.is_empty()
}

impl Engine {
    pub fn new(shared: Arc<Shared>, ring: Ring, notify_tx: SyncSender<Event>, respond: Lanes) -> std::io::Result<Self> {
        let cfg = shared.config();
        let policy = Policy::new(&cfg.policies).unwrap_or_default();
        Ok(Self {
            log: EventLog::spawn(&cfg.events, ring, shared.clone())?,
            policy,
            notify_enabled: notify_enabled(&cfg.notify),
            queue_drops: Default::default(),
            dedup: HashMap::new(),
            dedup_gc_at: 4096,
            generation: shared.generation(),
            shared,
            notify_tx,
            respond,
        })
    }

    fn maybe_reload(&mut self) {
        if self.shared.generation() == self.generation {
            return;
        }
        self.generation = self.shared.generation();
        let cfg = self.shared.config();
        match Policy::new(&cfg.policies) {
            Ok(p) => self.policy = p,
            Err(e) => tracing::error!(error = %e, "policy rejected on reload; keeping previous"),
        }
        self.log.reconfigure(&cfg.events);
        self.notify_enabled = notify_enabled(&cfg.notify);
        lock(&self.shared.heuristics).set_config(&cfg.heuristics);
    }

    /// Process one event (and any escalations it triggers).
    pub fn process(&mut self, ev: Event) {
        self.maybe_reload();
        let mut queue = vec![ev];
        while let Some(ev) = queue.pop() {
            let Some(ev) = self.policy.apply(ev) else {
                self.shared.metrics.inc("warden_events_suppressed_total", &[], 1.0);
                continue;
            };
            if self.duplicate(&ev) {
                self.shared.metrics.inc("warden_events_deduplicated_total", &[], 1.0);
                continue;
            }
            self.shared.metrics.inc(
                "warden_events_total",
                &[("kind", &ev.kind), ("severity", ev.severity.as_str())],
                1.0,
            );
            log_event(&ev);
            self.log.record(&ev);

            // suspicion decays in real time (see `warden_sys::clock`)
            let escalations = lock(&self.shared.heuristics).record(&ev, warden_sys::clock::now());
            for mut e in escalations {
                e.source = "heuristics".into();
                queue.push(e);
            }
            if self.notify_enabled {
                self.enqueue(&self.notify_tx, "notify", ev.clone());
            }
            if !ev.actions.is_empty() && !ev.resolved {
                if ev.has_urgent_actions() {
                    self.enqueue(&self.respond.urgent, "respond", ev);
                } else {
                    self.enqueue(&self.respond.slow, "respond-slow", ev);
                }
            }
        }
    }

    /// Hand an event to a worker without ever blocking the engine. A full
    /// queue means the worker is stuck: the event is dropped and counted.
    fn enqueue(&self, tx: &SyncSender<Event>, queue: &str, ev: Event) {
        match tx.try_send(ev) {
            Ok(()) => {}
            Err(TrySendError::Full(ev)) => {
                self.shared.metrics.inc("warden_queue_dropped_total", &[("queue", queue)], 1.0);
                // the first drop and then every thousandth: a stuck worker
                // must not also flood the log
                let n = self.queue_drops.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if n.is_multiple_of(1000) {
                    tracing::error!(queue, kind = %ev.kind, dropped = n + 1, "worker queue is full (is the thread stuck?); event dropped");
                }
            }
            // only at shutdown
            Err(TrySendError::Disconnected(_)) => {}
        }
    }

    /// Drop exact repeats of action-less events within the dedup window.
    fn duplicate(&mut self, ev: &Event) -> bool {
        if !ev.actions.is_empty() {
            return false;
        }
        let window = self.shared.config().events.dedup_window;
        // a repeat "within a minute" means a real minute, sleep included
        let now = warden_sys::clock::now();
        let dup = self
            .dedup
            .get(&ev.fingerprint)
            .is_some_and(|(t, s)| now.saturating_duration_since(*t) < window && ev.severity <= *s);
        if !dup {
            self.dedup.insert(ev.fingerprint.clone(), (now, ev.severity));
            // A condition and its resolution alternate: either one ends the
            // other's episode (see `end_episodes`).
            warden_core::event::end_episodes(&mut self.dedup, &ev.fingerprint);
            if self.dedup.len() > self.dedup_gc_at {
                self.dedup.retain(|_, (t, _)| now.saturating_duration_since(*t) < window);
                self.dedup_gc_at = (self.dedup.len() * 2).max(4096);
            }
        }
        dup
    }
}

fn log_event(ev: &Event) {
    let subject = ev.subject.to_string();
    match ev.severity {
        Severity::Info => tracing::info!(kind = %ev.kind, id = ev.id, %subject, resolved = ev.resolved, "{}", ev.title),
        Severity::Notice => tracing::info!(kind = %ev.kind, id = ev.id, %subject, "{}", ev.title),
        Severity::Warning => tracing::warn!(kind = %ev.kind, id = ev.id, %subject, "{}", ev.title),
        Severity::Critical | Severity::Emergency => {
            tracing::error!(kind = %ev.kind, id = ev.id, severity = %ev.severity, %subject, "{}", ev.title)
        }
    }
}

pub async fn run(mut engine: Engine, queue: Arc<EventQueue>) {
    let scope = warden_detect::prof::scope_id("engine");
    loop {
        let ev = queue.pop().await;
        let _g = warden_detect::prof::enter(scope);
        engine.process(ev);
    }
}

/// Convert the `index`-th action result of `src` into an event for the
/// journal and notifications.
pub fn result_event(src: &Event, index: usize, r: &ActionResult) -> Event {
    let sev = match r.status {
        Status::Done if r.action == "snapshot" => Severity::Info,
        // a cleanup that found nothing to free is not news
        Status::Done if r.freed_bytes == Some(0) => Severity::Notice,
        Status::Done => Severity::Warning,
        Status::Failed => Severity::Warning,
        Status::DryRun | Status::Refused => Severity::Notice,
        Status::Skipped => Severity::Info,
    };
    let status = serde_json::to_value(r.status).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default();
    let mut ev = Event::new(
        format!("action.{}", r.action),
        sev,
        format!("{} {} → {}: {}", r.action, r.target, status, r.message),
    )
    .source("responder")
    .subject(src.subject.clone())
    // the index keeps two actions of the same kind in one playbook apart
    // (two `delete_old` steps were deduplicated into one)
    .fingerprint(format!("action:{}:{}:{index}", r.action, src.id))
    .detail("status", status)
    .detail("cause_id", src.id)
    .detail("cause_kind", src.kind.clone())
    .detail("cause", src.title.clone());
    if let Some(b) = r.freed_bytes {
        ev = ev.detail("freed_bytes", b);
    }
    ev
}

/// Remediation thread body: executes actions sequentially (predictable
/// ordering, no two kills racing each other) and feeds results back as
/// events. The executor is owned by this thread alone — nothing the control
/// socket needs sits behind its lock (see `warden_respond::Handles`).
///
/// Returns when the queue closes or the daemon shuts down; actions still
/// queued at shutdown are not started.
pub fn run_responder(shared: &Shared, responder: &mut Responder, rx: &std::sync::mpsc::Receiver<Event>, back: &Sink) {
    let mut generation = shared.generation();
    loop {
        let ev = match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(ev) => ev,
            Err(RecvTimeoutError::Timeout) if shared.is_shutting_down() => return,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        if shared.is_shutting_down() {
            tracing::warn!(kind = %ev.kind, "shutting down: queued remediation not started");
            return;
        }
        if shared.generation() != generation {
            generation = shared.generation();
            responder.reconfigure(&shared.config());
        }
        // Only a snapshot uses the daemon-side extras; do not render all
        // metrics and copy the kernel log for every kill or cleanup.
        let extras = if ev.actions.iter().any(|a| matches!(a, warden_core::ActionSpec::Snapshot)) {
            snapshot::Extras {
                kmsg_tail: lock(&shared.kmsg_tail).iter().cloned().collect(),
                metrics: shared.metrics.render(),
                culprits: serde_json::to_value(&*lock(&shared.culprits)).unwrap_or_default(),
                hostname: shared.hostname.clone(),
            }
        } else {
            snapshot::Extras { hostname: shared.hostname.clone(), ..Default::default() }
        };
        let results = responder.execute(&ev, shared.is_dry_run(), &extras);
        for (i, r) in results.iter().enumerate() {
            let status =
                serde_json::to_value(r.status).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default();
            shared.metrics.inc("warden_actions_total", &[("action", &r.action), ("status", &status)], 1.0);
            if let Some(b) = r.freed_bytes {
                shared.metrics.inc("warden_bytes_reclaimed_total", &[("action", &r.action)], b as f64);
            }
            back.emit(result_event(&ev, i, r));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warden_core::{ActionSpec, Config};

    #[test]
    fn engine_pipeline() {
        let d = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.events.path = d.path().join("events.jsonl");
        cfg.daemon.state_dir = d.path().to_path_buf();
        cfg.notify.command =
            toml::from_str::<toml::Table>("[[c]]\nprogram = '/bin/true'\n").unwrap()["c"].clone().try_into().unwrap();
        cfg.policies = toml::from_str::<toml::Table>("[[policy]]\nkind = 'noise.*'\neffect = 'suppress'\n")
            .unwrap()
            .get("policy")
            .unwrap()
            .clone()
            .try_into()
            .unwrap();
        let shared = Shared::new(cfg);
        let (ntx, nrx) = std::sync::mpsc::sync_channel(WORKER_QUEUE);
        let (rtx, rrx) = std::sync::mpsc::sync_channel(WORKER_QUEUE);
        let (stx, srx) = std::sync::mpsc::sync_channel(WORKER_QUEUE);
        let ring: Ring = Default::default();
        let mut e = Engine::new(shared.clone(), ring.clone(), ntx, Lanes { urgent: rtx, slow: stx }).unwrap();

        e.process(Event::new("noise.x", Severity::Critical, "suppressed"));
        e.process(Event::new("disk.space", Severity::Warning, "a").fingerprint("f"));
        e.process(Event::new("disk.space", Severity::Warning, "a").fingerprint("f")); // dedup
        e.process(Event::new("memory.pressure", Severity::Critical, "kill").actions(vec![ActionSpec::Snapshot]));
        // heuristics escalation: two web_spawn findings on the same process
        let p = warden_core::ProcessRef { pid: 999_998, start_time: 3, comm: "sh".into(), ..Default::default() };
        for i in 0..2 {
            e.process(
                Event::new("security.web_spawn", Severity::Warning, "spawn")
                    .subject(warden_core::Subject::Process(p.clone()))
                    .fingerprint(format!("spawn-{i}")),
            );
        }
        let kinds: Vec<String> = lock(&ring)
            .iter()
            .map(|e| serde_json::from_str::<serde_json::Value>(&e.json).unwrap()["kind"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(kinds.iter().filter(|k| *k == "disk.space").count(), 1);
        assert!(!kinds.iter().any(|k| k.starts_with("noise")));
        assert!(kinds.iter().any(|k| k == "heuristics.suspicious"));
        // a snapshot alone is not urgent: the slow lane
        assert_eq!((rrx.try_iter().count(), srx.try_iter().count()), (0, 1));
        assert!(nrx.try_iter().count() >= 4);
        // the journal is written by its own thread: give it a moment
        let lines = || std::fs::read_to_string(d.path().join("events.jsonl")).map(|s| s.lines().count()).unwrap_or(0);
        let t = std::time::Instant::now();
        while lines() < 4 && t.elapsed() < std::time::Duration::from_secs(5) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(lines() >= 4, "{} lines in the journal", lines());
    }

    #[test]
    fn containment_does_not_queue_behind_cleanups() {
        let d = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.events.path = d.path().join("events.jsonl");
        cfg.daemon.state_dir = d.path().to_path_buf();
        let shared = Shared::new(cfg);
        let (ntx, _nrx) = std::sync::mpsc::sync_channel(WORKER_QUEUE);
        let (rtx, rrx) = std::sync::mpsc::sync_channel(WORKER_QUEUE);
        let (stx, srx) = std::sync::mpsc::sync_channel(WORKER_QUEUE);
        let mut e = Engine::new(shared, Default::default(), ntx, Lanes { urgent: rtx, slow: stx }).unwrap();
        e.process(Event::new("disk.space", Severity::Critical, "full").actions(vec![ActionSpec::AptClean]));
        e.process(
            Event::new("memory.pressure", Severity::Critical, "oom")
                .fingerprint("m")
                .actions(vec![ActionSpec::Snapshot, ActionSpec::Kill { tree: false, grace: None }]),
        );
        e.process(Event::new("security.reverse_shell", Severity::Critical, "rs").actions(vec![ActionSpec::Stop]));
        let urgent: Vec<String> = rrx.try_iter().map(|e| e.kind).collect();
        let slow: Vec<String> = srx.try_iter().map(|e| e.kind).collect();
        assert_eq!(urgent, ["memory.pressure", "security.reverse_shell"]);
        assert_eq!(slow, ["disk.space"]);
    }

    #[test]
    fn a_condition_that_comes_back_after_its_resolution_is_recorded_again() {
        let d = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.events.path = d.path().join("events.jsonl");
        cfg.daemon.state_dir = d.path().to_path_buf();
        let shared = Shared::new(cfg);
        let (ntx, _nrx) = std::sync::mpsc::sync_channel(WORKER_QUEUE);
        let (rtx, _rrx) = std::sync::mpsc::sync_channel(WORKER_QUEUE);
        let (stx, _srx) = std::sync::mpsc::sync_channel(WORKER_QUEUE);
        let ring: Ring = Default::default();
        let mut e = Engine::new(shared, ring.clone(), ntx, Lanes { urgent: rtx, slow: stx }).unwrap();
        let down = || Event::new("network.link_down", Severity::Warning, "eth0 down").fingerprint("network.link:eth0");
        let up = || {
            Event::new("network.link_up", Severity::Info, "eth0 up")
                .fingerprint("network.link:eth0:resolved")
                .resolved()
        };
        // a flap within the dedup window: down, up, down, up
        for ev in [down(), up(), down(), up()] {
            e.process(ev);
        }
        // a plain repeat is still a duplicate
        e.process(up());
        // a condition whose fingerprint carries the severity, as disks do
        let warn = || Event::new("disk.space", Severity::Warning, "/ warning").fingerprint("disk.space:/:warning");
        let ok = || Event::new("disk.space", Severity::Info, "/ ok").fingerprint("disk.space:/:resolved").resolved();
        for ev in [warn(), ok(), warn(), ok()] {
            e.process(ev);
        }
        let titles: Vec<String> = lock(&ring)
            .iter()
            .map(|r| serde_json::from_str::<serde_json::Value>(&r.json).unwrap()["title"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            titles,
            ["eth0 down", "eth0 up", "eth0 down", "eth0 up", "/ warning", "/ ok", "/ warning", "/ ok"],
            "the last state must be the real one"
        );
    }

    #[test]
    fn result_events() {
        let src = Event::new("memory.pressure", Severity::Critical, "x");
        let r = ActionResult {
            action: "kill".into(),
            target: "php[1]".into(),
            status: Status::Done,
            message: "terminated".into(),
            freed_bytes: Some(10),
        };
        let e = result_event(&src, 0, &r);
        assert_eq!(e.kind, "action.kill");
        assert_eq!(e.severity, Severity::Warning);
        assert_eq!(e.details["status"], "done");
        // two steps of the same kind in one playbook are distinct events
        assert_ne!(result_event(&src, 2, &r).fingerprint, result_event(&src, 3, &r).fingerprint);
        let nothing = ActionResult { freed_bytes: Some(0), ..r.clone() };
        assert_eq!(result_event(&src, 0, &nothing).severity, Severity::Notice);
    }
}
