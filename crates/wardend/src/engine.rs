//! The event engine: policy → dedup → journal → heuristics → notifications
//! → remediation. Remediation results come back as `action.*` events.

use crate::eventlog::{EventLog, Ring};
use crate::queue::{BlockQueue, Dropped, EventQueue, LaneQueue};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::mpsc::{RecvTimeoutError, SyncSender, TrySendError};
use std::time::{Duration, Instant};
use warden_core::policy::Policy;
use warden_core::sync::lock;
use warden_core::{ActionSpec, Event, Severity};
use warden_detect::{Shared, Sink};
use warden_respond::{ActionResult, BlockJob, Responder, Status, snapshot};

/// Events queued for the action executor / the notifier. Both consume
/// slowly by nature (a `systemctl restart`, a webhook that times out); the
/// bound keeps a stuck consumer from turning an event storm into unbounded
/// (and, under `mlockall`, never-returned) memory.
pub const WORKER_QUEUE: usize = 1024;

/// Events between the detectors and the engine ([`EventQueue`]).
pub const EVENT_QUEUE: usize = 8192;

/// `block_ip` jobs waiting for the network lane. The lane takes 512 per nft
/// transaction; this is a minute of a flood far beyond `max_blocks_per_hour`.
pub const BLOCK_QUEUE: usize = 16_384;
/// Blocks per nft transaction at most, and how long a block waits for
/// others to join it (A.1 of the 0.15 plan).
pub const BLOCK_BATCH: usize = 512;
pub const BLOCK_LINGER: Duration = Duration::from_millis(100);
/// The network lane counts the blocklist again this often.
pub const BLOCKLIST_RECONCILE: Duration = Duration::from_secs(60);
/// Lost work is summed up in one `warden.queue_overflow` event at most this
/// often.
const OVERFLOW_REPORT: Duration = Duration::from_secs(60);

/// Build the sink detectors write into (bounded, never blocks; under a
/// flood the least important events go first).
pub fn sink(shared: Arc<Shared>, queue: Arc<EventQueue>) -> Sink {
    Sink::new(move |ev| {
        if let Some((d, _)) = queue.push(ev) {
            let p = match d {
                Dropped::Incoming(p) | Dropped::Evicted(p) => p,
            };
            shared.dropped_events.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            shared.metrics.inc("warden_events_dropped_total", &[("priority", PRIORITY_LABELS[usize::from(p)])], 1.0);
        }
    })
}

const PRIORITY_LABELS: [&str; 5] = ["0", "1", "2", "3", "4"];

/// The executor's three queues: containment (kill, stop, freeze,
/// quarantine, throttle — [`warden_core::ActionSpec::is_urgent`]) by
/// priority, the network lane (`block_ip` jobs, batched) and the slow lane
/// (everything else).
#[derive(Clone)]
pub struct Lanes {
    pub contain: Arc<LaneQueue>,
    pub network: Arc<BlockQueue>,
    pub slow: SyncSender<Event>,
}

/// Work the engine could not queue, by queue and event kind, until it is
/// reported.
#[derive(Debug, Default)]
struct Overflow {
    dropped: BTreeMap<String, BTreeMap<String, u64>>,
    reported: Option<Instant>,
}

impl Overflow {
    fn note(&mut self, queue: &str, kind: &str) {
        *self.dropped.entry(queue.to_owned()).or_default().entry(kind.to_owned()).or_default() += 1;
    }

    /// The `warden.queue_overflow` event for what was lost, at most once
    /// per [`OVERFLOW_REPORT`]. A lost kill is the worst thing the daemon
    /// can do quietly: in 0.14.2 it was a metric and a log line per
    /// thousand (N23).
    fn report(&mut self, now: Instant) -> Option<Event> {
        if self.dropped.is_empty() || self.reported.is_some_and(|t| now.saturating_duration_since(t) < OVERFLOW_REPORT)
        {
            return None;
        }
        self.reported = Some(now);
        let dropped = std::mem::take(&mut self.dropped);
        let total: u64 = dropped.values().flat_map(|k| k.values()).sum();
        let what: Vec<String> = dropped
            .iter()
            .map(|(q, kinds)| {
                let k: Vec<String> = kinds.iter().map(|(k, n)| format!("{n} × {k}")).collect();
                format!("{q}: {}", k.join(", "))
            })
            .collect();
        let sev = if dropped.contains_key("contain") { Severity::Critical } else { Severity::Warning };
        Some(
            Event::new(
                "warden.queue_overflow",
                sev,
                format!("{total} event(s) not handed to a worker (queue full): {}", what.join("; ")),
            )
            .source("engine")
            .fingerprint(format!("warden.queue_overflow:{}", warden_core::event::now_ms()))
            .detail("dropped", serde_json::to_value(&dropped).unwrap_or_default())
            .detail("total", total)
            .detail("hint", "a lane is stuck or overwhelmed: see `wardenctl profile` and warden_queue_dropped_total"),
        )
    }
}

/// Informational events recorded per kind and minute (`events.max_info_per_minute`).
#[derive(Debug, Default)]
struct InfoLimit {
    window: Option<Instant>,
    seen: HashMap<String, usize>,
    held: BTreeMap<String, u64>,
}

impl InfoLimit {
    /// Is `ev` held back from the journal? Only plain informational
    /// findings are: resolutions, action results and the daemon's own
    /// events always pass.
    fn holds(&mut self, ev: &Event, limit: usize, now: Instant) -> bool {
        if limit == 0
            || ev.severity != Severity::Info
            || ev.resolved
            || ev.kind.starts_with("action.")
            || ev.kind.starts_with("warden.")
        {
            return false;
        }
        if self.window.is_none() {
            self.window = Some(now);
        }
        let n = self.seen.entry(ev.kind.clone()).or_default();
        *n += 1;
        if *n <= limit {
            return false;
        }
        *self.held.entry(ev.kind.clone()).or_default() += 1;
        true
    }

    /// At the end of a minute: the summary of what was held back, if anything.
    fn roll(&mut self, now: Instant) -> Option<Event> {
        let start = self.window?;
        if now.saturating_duration_since(start) < Duration::from_secs(60) {
            return None;
        }
        self.window = None;
        self.seen.clear();
        let held = std::mem::take(&mut self.held);
        if held.is_empty() {
            return None;
        }
        let total: u64 = held.values().sum();
        let what: Vec<String> = held.iter().map(|(k, n)| format!("{n} × {k}")).collect();
        Some(
            Event::new(
                "warden.journal_suppressed",
                Severity::Notice,
                format!("{total} informational event(s) not recorded in the last minute: {}", what.join(", ")),
            )
            .source("engine")
            .fingerprint(format!("warden.journal_suppressed:{}", warden_core::event::now_ms()))
            .detail("suppressed", serde_json::to_value(&held).unwrap_or_default())
            .detail("total", total)
            .detail(
                "hint",
                "events.max_info_per_minute; the metric warden_journal_suppressed_total counts them by kind",
            ),
        )
    }
}

/// Fingerprints remembered for deduplication at most.
const DEDUP_CAP: usize = 20_000;

pub struct Engine {
    shared: Arc<Shared>,
    policy: Policy,
    log: EventLog,
    dedup: HashMap<String, (Instant, Severity)>,
    dedup_gc_at: usize,
    dedup_evicted: u64,
    generation: u64,
    notify_tx: SyncSender<Event>,
    respond: Lanes,
    /// Any notification channel configured? (Otherwise events are not
    /// copied to the notifier thread at all.)
    notify_enabled: bool,
    queue_drops: u64,
    overflow: Overflow,
    info: InfoLimit,
    max_info_per_minute: usize,
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
            queue_drops: 0,
            overflow: Overflow::default(),
            info: InfoLimit::default(),
            max_info_per_minute: cfg.events.max_info_per_minute,
            dedup: HashMap::new(),
            dedup_gc_at: 4096,
            dedup_evicted: 0,
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
        self.max_info_per_minute = cfg.events.max_info_per_minute;
        self.notify_enabled = notify_enabled(&cfg.notify);
        lock(&self.shared.heuristics).set_config(&cfg.heuristics);
    }

    /// Process one event (and any escalations it triggers).
    pub fn process(&mut self, ev: Event) {
        self.maybe_reload();
        let mut queue = vec![ev];
        let now = Instant::now();
        // the minute's summaries come first, before what they are about
        queue.extend(self.overflow.report(now));
        queue.extend(self.info.roll(now));
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
            if self.info.holds(&ev, self.max_info_per_minute, now) {
                // counted, scored, notified and acted on — just not recorded
                self.shared.metrics.inc("warden_journal_suppressed_total", &[("kind", &ev.kind)], 1.0);
            } else {
                log_event(&ev);
                self.log.record(&ev);
            }

            // suspicion decays in real time (see `warden_sys::clock`)
            let escalations = lock(&self.shared.heuristics).record(&ev, warden_sys::clock::now());
            for mut e in escalations {
                e.source = "heuristics".into();
                queue.push(e);
            }
            if self.notify_enabled {
                let r = try_send(&self.notify_tx, ev.clone());
                self.lost("notify", r.as_ref().map(|e| e.kind.as_str()));
            }
            if !ev.actions.is_empty() && !ev.resolved {
                self.dispatch(ev);
            }
        }
    }

    /// Hand an event's actions to the executor's lanes without ever
    /// blocking the engine: every `block_ip` step to the network lane as a
    /// job of its own, the event to the containment lane if it carries
    /// containment, else to the slow lane if anything is left for it.
    fn dispatch(&mut self, ev: Event) {
        for (i, a) in ev.actions.iter().enumerate() {
            if let ActionSpec::BlockIp { ttl } = a
                && !self.respond.network.push(BlockJob::of(&ev, i, *ttl))
            {
                self.lost("network", Some(&ev.kind));
            }
        }
        if ev.has_urgent_actions() {
            // a full lane gives up its least important event, never a kill for a hook
            if let Some((_, old)) = self.respond.contain.push(ev) {
                self.lost("contain", Some(&old.kind));
            }
        } else if ev.has_slow_actions() {
            let r = try_send(&self.respond.slow, ev);
            self.lost("respond-slow", r.as_ref().map(|e| e.kind.as_str()));
        }
    }

    /// Account for work that could not be queued (`kind` of the event
    /// lost, if one was): a metric, a log line for the first and every
    /// thousandth loss, and the minute's `warden.queue_overflow` event.
    fn lost(&mut self, queue: &str, kind: Option<&str>) {
        let Some(kind) = kind else { return };
        self.shared.metrics.inc("warden_queue_dropped_total", &[("queue", queue)], 1.0);
        let n = self.queue_drops;
        self.queue_drops += 1;
        if n.is_multiple_of(1000) {
            tracing::error!(queue, kind, dropped = n + 1, "worker queue is full (is the thread stuck?); event dropped");
        }
        self.overflow.note(queue, kind);
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
                // a flood of distinct fingerprints within the window (one
                // per address) is bounded too: the oldest go first, and a
                // forgotten one only means a repeat is journaled again
                if self.dedup.len() > DEDUP_CAP {
                    let n =
                        warden_core::ratelimit::evict_lowest(&mut self.dedup, DEDUP_CAP - DEDUP_CAP / 10, |(t, _)| *t);
                    self.dedup_evicted += n as u64;
                    self.shared.metrics.set(
                        "warden_state_evicted_total",
                        &[("table", "event_dedup")],
                        self.dedup_evicted as f64,
                    );
                }
                self.dedup_gc_at = (self.dedup.len() * 2).clamp(4096, DEDUP_CAP);
            }
        }
        dup
    }
}

/// Queue to a worker's channel; the event back when it is full.
fn try_send(tx: &SyncSender<Event>, ev: Event) -> Option<Event> {
    match tx.try_send(ev) {
        Ok(()) => None,
        Err(TrySendError::Full(ev)) => Some(ev),
        // only at shutdown
        Err(TrySendError::Disconnected(_)) => None,
    }
}

/// The daemon's own log line for an event. Informational findings are
/// debug output: the journal has them, and under a flood (120 000
/// `waf.hit` a minute) a line each went to journald as well (N33).
fn log_event(ev: &Event) {
    let subject = ev.subject.to_string();
    match ev.severity {
        Severity::Info => {
            tracing::debug!(kind = %ev.kind, id = ev.id, %subject, resolved = ev.resolved, "{}", ev.title)
        }
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

/// What a lane thread waits on.
pub enum Next {
    Event(Box<Event>),
    Timeout,
    Closed,
}

/// The slow lane's channel as a [`Next`] source.
pub fn from_channel(rx: &std::sync::mpsc::Receiver<Event>) -> impl FnMut(Duration) -> Next + '_ {
    move |t| match rx.recv_timeout(t) {
        Ok(ev) => Next::Event(Box::new(ev)),
        Err(RecvTimeoutError::Timeout) => Next::Timeout,
        Err(RecvTimeoutError::Disconnected) => Next::Closed,
    }
}

/// The containment lane's queue as a [`Next`] source.
pub fn from_lane(q: &LaneQueue) -> impl FnMut(Duration) -> Next + '_ {
    move |t| q.pop_timeout(t).map_or(Next::Timeout, |e| Next::Event(Box::new(e)))
}

/// Remediation thread body (containment and slow lanes): executes actions
/// sequentially (predictable ordering, no two kills racing each other) and
/// feeds results back as events. `block_ip` steps are not run here: the
/// engine handed them to the network lane ([`run_network`]). The executor is
/// owned by this thread alone — nothing the control socket needs sits
/// behind its lock (see `warden_respond::Handles`).
///
/// Returns when the queue closes or the daemon shuts down; actions still
/// queued at shutdown are not started.
pub fn run_responder(shared: &Shared, responder: &mut Responder, mut next: impl FnMut(Duration) -> Next, back: &Sink) {
    let mut generation = shared.generation();
    loop {
        let ev = match next(Duration::from_millis(500)) {
            Next::Event(ev) => *ev,
            Next::Timeout if shared.is_shutting_down() => return,
            Next::Timeout => continue,
            Next::Closed => return,
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
        let results = responder.execute_indexed(&ev, shared.is_dry_run(), &extras, true);
        for (i, r) in &results {
            report(shared, back, &ev, *i, r);
        }
    }
}

/// Count an action result and feed it back as an event.
fn report(shared: &Shared, back: &Sink, src: &Event, index: usize, r: &ActionResult) {
    let status = serde_json::to_value(r.status).ok().and_then(|v| v.as_str().map(str::to_owned)).unwrap_or_default();
    shared.metrics.inc("warden_actions_total", &[("action", &r.action), ("status", &status)], 1.0);
    if let Some(b) = r.freed_bytes {
        shared.metrics.inc("warden_bytes_reclaimed_total", &[("action", &r.action)], b as f64);
    }
    back.emit(result_event(src, index, r));
}

/// The network lane: `block_ip` jobs in batches of up to [`BLOCK_BATCH`],
/// each batch one nft transaction (N23: one `nft` process per address, in
/// the lane that also runs kills, held a kill up for 2.5 s at 400 attacking
/// addresses a second, and for about 94 s near `max_blocked`). Once a
/// minute the blocklist is counted again.
pub fn run_network(shared: &Shared, responder: &mut Responder, q: &BlockQueue, back: &Sink) {
    let mut generation = shared.generation();
    let mut reconciled = Instant::now();
    loop {
        if shared.is_shutting_down() {
            return;
        }
        let jobs = q.take_batch(BLOCK_BATCH, BLOCK_LINGER, Duration::from_millis(500));
        if shared.is_shutting_down() {
            if !jobs.is_empty() {
                tracing::warn!(blocks = jobs.len(), "shutting down: queued blocks not made");
            }
            return;
        }
        if shared.generation() != generation {
            generation = shared.generation();
            responder.reconfigure(&shared.config());
        }
        if !jobs.is_empty() {
            let (n, started) = (jobs.len(), Instant::now());
            let results = responder.execute_blocks(jobs, shared.is_dry_run());
            shared.metrics.inc("warden_firewall_batches_total", &[], 1.0);
            shared.metrics.inc("warden_firewall_batched_blocks_total", &[], n as f64);
            shared.metrics.inc("warden_firewall_batch_seconds_total", &[], started.elapsed().as_secs_f64());
            for (job, r) in results {
                report(shared, back, &job.event, job.index, &r);
            }
            shared.metrics.set("warden_queue_length", &[("queue", "network")], q.len() as f64);
        }
        if reconciled.elapsed() >= BLOCKLIST_RECONCILE {
            reconciled = Instant::now();
            match responder.reconcile_firewall() {
                Ok(n) => shared.metrics.set("warden_blocklist_entries", &[], n as f64),
                Err(e) => {
                    tracing::warn!(error = %e, "cannot count the blocklist (the table is recreated at the next block)")
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use warden_core::{ActionSpec, Config, ProcessRef, Subject};

    struct Test {
        _dir: tempfile::TempDir,
        shared: Arc<Shared>,
        ring: Ring,
        contain: Arc<LaneQueue>,
        network: Arc<BlockQueue>,
        slow: std::sync::mpsc::Receiver<Event>,
        notify: std::sync::mpsc::Receiver<Event>,
        engine: Engine,
    }

    fn setup_with(cfg: impl FnOnce(&mut Config), contain_cap: usize) -> Test {
        let d = tempfile::tempdir().unwrap();
        let mut c = Config::default();
        c.events.path = d.path().join("events.jsonl");
        c.daemon.state_dir = d.path().to_path_buf();
        cfg(&mut c);
        let shared = Shared::new(c);
        let (ntx, nrx) = std::sync::mpsc::sync_channel(WORKER_QUEUE);
        let (stx, srx) = std::sync::mpsc::sync_channel(WORKER_QUEUE);
        let contain = Arc::new(LaneQueue::new(contain_cap));
        let network = Arc::new(BlockQueue::new(BLOCK_QUEUE));
        let ring: Ring = Default::default();
        let lanes = Lanes { contain: contain.clone(), network: network.clone(), slow: stx };
        let engine = Engine::new(shared.clone(), ring.clone(), ntx, lanes).unwrap();
        Test { _dir: d, shared, ring, contain, network, slow: srx, notify: nrx, engine }
    }

    fn setup() -> Test {
        setup_with(|_| {}, WORKER_QUEUE)
    }

    fn kinds(ring: &Ring) -> Vec<String> {
        lock(ring)
            .iter()
            .map(|e| serde_json::from_str::<serde_json::Value>(&e.json).unwrap()["kind"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn engine_pipeline() {
        let mut t = setup_with(
            |c| {
                c.notify.command = toml::from_str::<toml::Table>("[[c]]\nprogram = '/bin/true'\n").unwrap()["c"]
                    .clone()
                    .try_into()
                    .unwrap();
                c.policies = toml::from_str::<toml::Table>("[[policy]]\nkind = 'noise.*'\neffect = 'suppress'\n")
                    .unwrap()
                    .get("policy")
                    .unwrap()
                    .clone()
                    .try_into()
                    .unwrap();
            },
            WORKER_QUEUE,
        );
        let e = &mut t.engine;
        e.process(Event::new("noise.x", Severity::Critical, "suppressed"));
        e.process(Event::new("disk.space", Severity::Warning, "a").fingerprint("f"));
        e.process(Event::new("disk.space", Severity::Warning, "a").fingerprint("f")); // dedup
        e.process(Event::new("memory.pressure", Severity::Critical, "kill").actions(vec![ActionSpec::Snapshot]));
        // heuristics escalation: two web_spawn findings on the same process
        let p = ProcessRef { pid: 999_998, start_time: 3, comm: "sh".into(), ..Default::default() };
        for i in 0..2 {
            e.process(
                Event::new("security.web_spawn", Severity::Warning, "spawn")
                    .subject(Subject::Process(p.clone()))
                    .fingerprint(format!("spawn-{i}")),
            );
        }
        let kinds = kinds(&t.ring);
        assert_eq!(kinds.iter().filter(|k| *k == "disk.space").count(), 1);
        assert!(!kinds.iter().any(|k| k.starts_with("noise")));
        assert!(kinds.iter().any(|k| k == "heuristics.suspicious"));
        // a snapshot alone is not containment: the slow lane
        assert_eq!((t.contain.len(), t.slow.try_iter().count()), (0, 1));
        assert!(t.notify.try_iter().count() >= 4);
        // the journal is written by its own thread: give it a moment
        let path = t.shared.config().events.path.clone();
        let lines = || std::fs::read_to_string(&path).map(|s| s.lines().count()).unwrap_or(0);
        let started = std::time::Instant::now();
        while lines() < 4 && started.elapsed() < std::time::Duration::from_secs(5) {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(lines() >= 4, "{} lines in the journal", lines());
    }

    /// N3 for the engine: one fingerprint per address (`waf.hit:<ip>`) from
    /// a flood of addresses does not grow the dedup table without bound, and
    /// a recent fingerprint is still deduplicated.
    #[test]
    fn the_dedup_table_is_bounded() {
        let mut t = setup();
        let e = &mut t.engine;
        let ev = |i: usize| Event::new("waf.hit", Severity::Info, "hit").fingerprint(format!("waf.hit:{i}"));
        for i in 0..DEDUP_CAP * 2 {
            assert!(!e.duplicate(&ev(i)));
        }
        assert!(e.dedup.len() <= DEDUP_CAP, "{}", e.dedup.len());
        assert!(e.dedup_evicted > 0);
        assert!(e.duplicate(&ev(DEDUP_CAP * 2 - 1)), "the newest are kept");
    }

    /// Kills, stops and quarantine go to the containment lane; `block_ip`
    /// steps to the network lane as jobs of their own (with their place in
    /// the playbook); cleanups, hooks and snapshots to the slow lane.
    #[test]
    fn each_kind_of_action_takes_its_own_lane() {
        let mut t = setup();
        let e = &mut t.engine;
        e.process(Event::new("disk.space", Severity::Critical, "full").actions(vec![ActionSpec::AptClean]));
        e.process(
            Event::new("memory.pressure", Severity::Critical, "oom")
                .fingerprint("m")
                .actions(vec![ActionSpec::Snapshot, ActionSpec::Kill { tree: false, grace: None }]),
        );
        e.process(Event::new("security.reverse_shell", Severity::Critical, "rs").actions(vec![ActionSpec::Stop]));
        e.process(
            Event::new("security.waf_attack", Severity::Warning, "attacker")
                .subject(Subject::Ip { addr: "203.0.113.9".parse().unwrap() })
                .actions(vec![ActionSpec::BlockIp { ttl: None }]),
        );
        // a playbook with both: the stop to containment, the block to the network lane
        e.process(
            Event::new("security.webshell_access", Severity::Critical, "both")
                .subject(Subject::Ip { addr: "203.0.113.10".parse().unwrap() })
                .actions(vec![ActionSpec::Snapshot, ActionSpec::BlockIp { ttl: None }, ActionSpec::Stop]),
        );
        let mut contain = Vec::new();
        while let Some(ev) = t.contain.pop_timeout(Duration::ZERO) {
            contain.push(ev.kind);
        }
        let slow: Vec<String> = t.slow.try_iter().map(|e| e.kind).collect();
        let blocks = t.network.take_batch(10, Duration::ZERO, Duration::ZERO);
        assert_eq!(contain, ["memory.pressure", "security.reverse_shell", "security.webshell_access"]);
        assert_eq!(slow, ["disk.space"]);
        let b: Vec<(String, usize)> = blocks.iter().map(|j| (j.event.kind.clone(), j.index)).collect();
        assert_eq!(b, [("security.waf_attack".to_owned(), 0), ("security.webshell_access".to_owned(), 1)]);
    }

    /// A full containment lane gives up its least important event and the
    /// loss is reported once a minute in `warden.queue_overflow` — a lost
    /// kill is no longer only a metric (N23).
    #[test]
    fn lost_containment_is_reported() {
        let mut t = setup_with(|_| {}, 2);
        let stop = |i: usize| {
            Event::new("security.reverse_shell", Severity::Critical, "rs")
                .fingerprint(format!("rs{i}"))
                .actions(vec![ActionSpec::Stop])
        };
        for i in 0..3 {
            t.engine.process(stop(i));
        }
        assert_eq!(t.contain.len(), 2);
        // the next event brings the report of the first loss along
        t.engine.process(Event::new("disk.space", Severity::Warning, "x"));
        let ring = lock(&t.ring);
        let report = ring
            .iter()
            .map(|e| serde_json::from_str::<serde_json::Value>(&e.json).unwrap())
            .find(|v| v["kind"] == "warden.queue_overflow")
            .expect("an overflow report");
        assert_eq!(report["severity"], "critical");
        assert_eq!(report["details"]["dropped"]["contain"]["security.reverse_shell"], 1);
        assert_eq!(report["details"]["total"], 1);
        drop(ring);
        // later losses within the minute are summed up in the next report
        for i in 3..5 {
            t.engine.process(stop(i));
        }
        t.engine.process(Event::new("disk.space", Severity::Warning, "y"));
        assert_eq!(kinds(&t.ring).iter().filter(|k| *k == "warden.queue_overflow").count(), 1);
        assert_eq!(t.shared.metrics.get("warden_queue_dropped_total", &[("queue", "contain")]), Some(3.0));
        assert_eq!(t.engine.overflow.dropped["contain"]["security.reverse_shell"], 2);
    }

    /// N33 (part): a flood of informational findings is counted, not
    /// recorded line by line; resolutions and action results always are.
    #[test]
    fn a_flood_of_informational_events_is_counted_not_recorded() {
        let mut t = setup_with(|c| c.events.max_info_per_minute = 5, WORKER_QUEUE);
        for i in 0..50 {
            t.engine.process(Event::new("waf.hit", Severity::Info, "hit").fingerprint(format!("waf.hit:{i}")));
        }
        for i in 0..3 {
            t.engine.process(
                Event::new("network.link_up", Severity::Info, "up").fingerprint(format!("l{i}:resolved")).resolved(),
            );
        }
        let k = kinds(&t.ring);
        assert_eq!(k.iter().filter(|k| *k == "waf.hit").count(), 5);
        assert_eq!(k.iter().filter(|k| *k == "network.link_up").count(), 3, "resolutions always pass");
        assert_eq!(t.shared.metrics.get("warden_journal_suppressed_total", &[("kind", "waf.hit")]), Some(45.0));
        // the minute's summary
        let mut l = InfoLimit::default();
        let t0 = Instant::now();
        for _ in 0..10 {
            l.holds(&Event::new("waf.hit", Severity::Info, "x"), 4, t0);
        }
        assert!(l.roll(t0 + Duration::from_secs(30)).is_none());
        let sum = l.roll(t0 + Duration::from_secs(61)).unwrap();
        assert_eq!(sum.kind, "warden.journal_suppressed");
        assert_eq!(sum.details["suppressed"]["waf.hit"], 6);
        assert!(!l.holds(&Event::new("waf.hit", Severity::Info, "x"), 4, t0 + Duration::from_secs(62)), "a new minute");
    }

    #[test]
    fn a_condition_that_comes_back_after_its_resolution_is_recorded_again() {
        let mut t = setup();
        let e = &mut t.engine;
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
        let titles: Vec<String> = lock(&t.ring)
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

    /// nft that takes `delay` per call and remembers nothing.
    #[derive(Debug)]
    struct SlowNft {
        delay: Duration,
        calls: AtomicUsize,
    }

    impl warden_respond::firewall::Backend for SlowNft {
        fn apply(&self, _script: &str) -> Result<(), String> {
            std::thread::sleep(self.delay);
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn list_set(&self, _t: &str, _s: &str) -> Result<serde_json::Value, String> {
            std::thread::sleep(self.delay);
            Ok(serde_json::json!({"nftables": []}))
        }
        fn list_sets(&self, _t: &str) -> Result<serde_json::Value, String> {
            Ok(serde_json::json!({"nftables": []}))
        }
        fn available(&self) -> Result<(), String> {
            Ok(())
        }
    }

    /// N23, the regression test of the 0.15 plan (A.1): 10 000 blocks are
    /// waiting, nft takes 10 ms a call — and a kill still runs at once and
    /// is not lost; the blocks go in batches. In 0.14.2 the kill queued
    /// behind every block (one nft process each: 100 s here), and with the
    /// queue full it was dropped.
    #[test]
    fn a_storm_of_blocks_does_not_hold_up_a_kill() {
        let mut t = setup_with(
            |c| {
                c.daemon.dry_run = false;
                c.actions.firewall.max_blocks_per_hour = 20_000;
                c.actions.firewall.protect_ssh_sessions = false;
                c.actions.kill_grace = Duration::from_secs(2);
            },
            WORKER_QUEUE,
        );
        t.shared.dry_run.store(false, Ordering::SeqCst);
        let nft = Arc::new(SlowNft { delay: Duration::from_millis(10), calls: AtomicUsize::new(0) });
        let cfg = t.shared.config();
        let mut contain_r = Responder::with_backend(&cfg, nft.clone());
        let mut net_r = contain_r.lane();
        let results: Arc<Mutex<Vec<Event>>> = Default::default();
        let back = {
            let r = results.clone();
            Sink::new(move |ev| lock(&r).push(ev))
        };
        let contain_thread = {
            let (s, q, b) = (t.shared.clone(), t.contain.clone(), back.clone());
            std::thread::spawn(move || run_responder(&s, &mut contain_r, from_lane(&q), &b))
        };
        let net_thread = {
            let (s, q, b) = (t.shared.clone(), t.network.clone(), back.clone());
            std::thread::spawn(move || run_network(&s, &mut net_r, &q, &b))
        };
        for i in 0..10_000u32 {
            t.engine.process(
                Event::new("security.waf_attack", Severity::Warning, "attacker")
                    .subject(Subject::Ip {
                        addr: std::net::IpAddr::V4(std::net::Ipv4Addr::from((10u32 << 24) | (i + 1))),
                    })
                    .fingerprint(format!("a{i}"))
                    .actions(vec![ActionSpec::BlockIp { ttl: None }]),
            );
        }
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let st = warden_sys::process::start_time(pid).unwrap();
        let started = Instant::now();
        t.engine.process(
            Event::new("security.reverse_shell", Severity::Critical, "rs")
                .subject(Subject::Process(ProcessRef {
                    pid,
                    start_time: st,
                    comm: "sleep".into(),
                    ..Default::default()
                }))
                .actions(vec![ActionSpec::Kill { tree: false, grace: None }]),
        );
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break s;
            }
            assert!(started.elapsed() < Duration::from_secs(5), "the kill never came");
            std::thread::sleep(Duration::from_millis(1));
        };
        let took = started.elapsed();
        assert!(!status.success());
        assert!(took < Duration::from_millis(500), "the kill waited {took:?} behind the blocks");
        // every block is made, in batches
        let deadline = Instant::now() + Duration::from_secs(60);
        let blocks = || lock(&results).iter().filter(|e| e.kind == "action.block_ip").count();
        while blocks() < 10_000 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(blocks(), 10_000);
        let done =
            lock(&results).iter().filter(|e| e.kind == "action.block_ip" && e.details["status"] == "done").count();
        assert_eq!(done, 10_000);
        let calls = nft.calls.load(Ordering::Relaxed);
        eprintln!("kill after {took:?} behind 10 000 blocks; {calls} nft transactions for the blocks");
        assert!(calls < 100, "{calls} nft transactions for 10 000 blocks");
        let kill = lock(&results).iter().find(|e| e.kind == "action.kill").cloned().unwrap();
        assert_eq!(kill.details["status"], "done", "{}", kill.title);
        assert!(!kinds(&t.ring).contains(&"warden.queue_overflow".to_owned()));
        t.shared.begin_shutdown();
        contain_thread.join().unwrap();
        net_thread.join().unwrap();
    }
}
