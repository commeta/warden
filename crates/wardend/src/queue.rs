//! Bounded queues between the daemon's threads.
//!
//! * [`EventQueue`] — detectors → engine (async side);
//! * [`LaneQueue`] — engine → the containment lane of the executor (a thread);
//! * [`BlockQueue`] — engine → the network lane (`block_ip` jobs, taken in
//!   batches).
//!
//! The event queues never block a producer, and when one is full it does
//! not simply refuse the newcomer: it gives up the oldest event of the
//! *lowest* priority ([`Event::priority`]) below the newcomer's. An attacker
//! who floods the host with noise (thousands of info and notice events) can
//! fill it, but cannot push a `security.*` finding or a critical event out of
//! it — those are dropped only for one another. (0.14.0 used a plain channel:
//! when it was full, whatever came next was lost; 0.14.2 still did that for
//! the executor's queues, where a storm of blocks could push a kill out —
//! N23.)
//!
//! Events leave in arrival order (FIFO): the priority decides only what is
//! dropped, so the lifecycle of a condition (opened, escalated, resolved)
//! is never reordered.

use std::collections::VecDeque;
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;
use warden_core::Event;
use warden_core::sync::lock;
use warden_respond::BlockJob;

/// Priorities run 0..=MAX_PRIORITY.
const LEVELS: usize = 5;

/// What a push had to give up (and it is handed back to the caller).
#[derive(Debug, PartialEq, Eq)]
pub enum Dropped {
    /// The newcomer: the queue is full of events at least as important.
    Incoming(u8),
    /// An older, less important event made room for the newcomer.
    Evicted(u8),
}

/// The bounded priority buffer both event queues are built on.
#[derive(Debug)]
struct Buf {
    events: VecDeque<(u8, Event)>,
    /// Queued events per priority: whether something lower than a newcomer
    /// is there is known without a scan.
    per_level: [usize; LEVELS],
    cap: usize,
}

impl Buf {
    fn new(cap: usize) -> Self {
        Self { events: VecDeque::with_capacity(cap.min(1024)), per_level: [0; LEVELS], cap: cap.max(1) }
    }

    /// O(1), or one scan when an important event has to evict a lesser one.
    fn push(&mut self, ev: Event) -> Option<(Dropped, Event)> {
        let p = ev.priority().min(LEVELS as u8 - 1);
        let mut dropped = None;
        if self.events.len() >= self.cap {
            let Some(lowest) = (0..p).find(|&l| self.per_level[usize::from(l)] > 0) else {
                return Some((Dropped::Incoming(p), ev));
            };
            if let Some(i) = self.events.iter().position(|(l, _)| *l == lowest)
                && let Some((_, old)) = self.events.remove(i)
            {
                self.per_level[usize::from(lowest)] -= 1;
                dropped = Some((Dropped::Evicted(lowest), old));
            }
        }
        self.events.push_back((p, ev));
        self.per_level[usize::from(p)] += 1;
        dropped
    }

    fn pop(&mut self) -> Option<Event> {
        let (p, ev) = self.events.pop_front()?;
        self.per_level[usize::from(p)] -= 1;
        Some(ev)
    }
}

/// Detectors → engine.
pub struct EventQueue {
    inner: Mutex<Buf>,
    ready: Notify,
}

impl EventQueue {
    pub fn new(cap: usize) -> Self {
        Self { inner: Mutex::new(Buf::new(cap)), ready: Notify::new() }
    }

    /// Queue `ev`; never blocks (beyond the lock, held for O(1) — or one
    /// scan when an important event has to evict a lesser one).
    pub fn push(&self, ev: Event) -> Option<(Dropped, Event)> {
        let dropped = lock(&self.inner).push(ev);
        self.ready.notify_one();
        dropped
    }

    fn try_pop(&self) -> Option<Event> {
        lock(&self.inner).pop()
    }

    /// The next event, in arrival order (waits for one).
    pub async fn pop(&self) -> Event {
        loop {
            if let Some(ev) = self.try_pop() {
                return ev;
            }
            // a push between the check and here leaves a permit: not lost
            self.ready.notified().await;
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        lock(&self.inner).events.len()
    }
}

/// Engine → a lane thread of the executor: the same priority buffer, with
/// a blocking pop.
pub struct LaneQueue {
    inner: Mutex<Buf>,
    ready: Condvar,
}

impl LaneQueue {
    pub fn new(cap: usize) -> Self {
        Self { inner: Mutex::new(Buf::new(cap)), ready: Condvar::new() }
    }

    pub fn push(&self, ev: Event) -> Option<(Dropped, Event)> {
        let dropped = lock(&self.inner).push(ev);
        self.ready.notify_one();
        dropped
    }

    /// The next event, waiting at most `timeout`.
    pub fn pop_timeout(&self, timeout: Duration) -> Option<Event> {
        let deadline = Instant::now() + timeout;
        let mut q = lock(&self.inner);
        loop {
            if let Some(ev) = q.pop() {
                return Some(ev);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            q = self.ready.wait_timeout(q, left).map(|(g, _)| g).unwrap_or_else(|e| e.into_inner().0);
        }
    }

    pub fn len(&self) -> usize {
        lock(&self.inner).events.len()
    }
}

/// Engine → network lane: `block_ip` jobs, all of the same weight (FIFO,
/// a full queue refuses the newcomer), taken in batches.
pub struct BlockQueue {
    inner: Mutex<VecDeque<BlockJob>>,
    ready: Condvar,
    cap: usize,
}

impl BlockQueue {
    pub fn new(cap: usize) -> Self {
        Self { inner: Mutex::new(VecDeque::new()), ready: Condvar::new(), cap: cap.max(1) }
    }

    /// Queue a job; `false` (and the job is dropped) when the queue is full.
    pub fn push(&self, job: BlockJob) -> bool {
        let mut q = lock(&self.inner);
        if q.len() >= self.cap {
            return false;
        }
        q.push_back(job);
        drop(q);
        self.ready.notify_one();
        true
    }

    /// The next batch: waits up to `idle` for a first job (an empty batch
    /// when none comes), then up to `linger` more for others to join it,
    /// until there are `max`. One nft transaction per batch instead of one
    /// process per address (N23: 200 blocks one by one 620 ms, in one
    /// transaction 3 ms).
    pub fn take_batch(&self, max: usize, linger: Duration, idle: Duration) -> Vec<BlockJob> {
        let mut q = lock(&self.inner);
        let first = Instant::now() + idle;
        while q.is_empty() {
            let left = first.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Vec::new();
            }
            q = self.ready.wait_timeout(q, left).map(|(g, _)| g).unwrap_or_else(|e| e.into_inner().0);
        }
        let deadline = Instant::now() + linger;
        while q.len() < max {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            q = self.ready.wait_timeout(q, left).map(|(g, _)| g).unwrap_or_else(|e| e.into_inner().0);
        }
        let n = q.len().min(max);
        q.drain(..n).collect()
    }

    pub fn len(&self) -> usize {
        lock(&self.inner).len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use warden_core::Severity;

    fn ev(kind: &str, sev: Severity) -> Event {
        Event::new(kind, sev, "t")
    }

    #[test]
    fn a_flood_of_noise_cannot_push_out_what_matters() {
        let q = EventQueue::new(100);
        let webshell = ev("security.webshell", Severity::Warning).fingerprint("ws");
        assert!(q.push(webshell).is_none());
        for i in 0..1000 {
            q.push(ev("noise.x", Severity::Info).fingerprint(format!("n{i}")));
        }
        assert_eq!(q.len(), 100);
        // a critical event arriving into the full queue evicts noise
        let (d, old) = q.push(ev("memory.pressure", Severity::Critical)).unwrap();
        assert_eq!((d, old.kind.as_str()), (Dropped::Evicted(0), "noise.x"));
        // more noise is refused, not the important events
        assert_eq!(q.push(ev("noise.x", Severity::Info)).unwrap().0, Dropped::Incoming(0));
        let mut kinds = Vec::new();
        while let Some(e) = q.try_pop() {
            kinds.push(e.kind);
        }
        assert_eq!(kinds.first().map(String::as_str), Some("security.webshell"), "arrival order is kept");
        assert_eq!(kinds.last().map(String::as_str), Some("memory.pressure"));
        assert_eq!(kinds.len(), 100);
    }

    #[test]
    fn important_events_drop_only_for_one_another() {
        let q = EventQueue::new(3);
        for _ in 0..2 {
            q.push(ev("security.x", Severity::Critical)); // priority 4
        }
        q.push(ev("disk.space", Severity::Critical)); // 3
        // a lesser one is refused; an equal one has nothing below it to evict
        assert_eq!(q.push(ev("cpu.pressure", Severity::Warning)).unwrap().0, Dropped::Incoming(2));
        assert_eq!(q.push(ev("security.y", Severity::Emergency)).unwrap().0, Dropped::Evicted(3));
        assert_eq!(q.push(ev("security.z", Severity::Emergency)).unwrap().0, Dropped::Incoming(4));
        assert_eq!(q.len(), 3);
    }

    #[test]
    fn priorities() {
        assert_eq!(ev("noise", Severity::Info).priority(), 0);
        assert_eq!(ev("security.ssh_login", Severity::Info).priority(), 1);
        assert_eq!(ev("security.webshell", Severity::Critical).priority(), 4);
        assert_eq!(ev("disk.space", Severity::Info).resolved().priority(), 2);
        assert_eq!(ev("action.kill", Severity::Notice).priority(), 3);
    }

    #[tokio::test]
    async fn pop_waits_for_a_push() {
        let q = std::sync::Arc::new(EventQueue::new(10));
        let q2 = q.clone();
        let t = tokio::spawn(async move { q2.pop().await.kind });
        tokio::task::yield_now().await;
        q.push(ev("late", Severity::Info));
        assert_eq!(t.await.unwrap(), "late");
    }

    #[test]
    fn a_lane_queue_keeps_the_kill_and_wakes_its_thread() {
        let q = std::sync::Arc::new(LaneQueue::new(4));
        for _ in 0..4 {
            q.push(ev("memory.pressure", Severity::Warning));
        }
        // a kill of a reverse shell into the full lane: a lesser event goes
        let (d, old) = q.push(ev("security.reverse_shell", Severity::Critical)).unwrap();
        assert_eq!((d, old.kind.as_str()), (Dropped::Evicted(2), "memory.pressure"));
        let q2 = q.clone();
        let t = std::thread::spawn(move || {
            let mut kinds = Vec::new();
            while let Some(e) = q2.pop_timeout(Duration::from_millis(200)) {
                kinds.push(e.kind);
            }
            kinds
        });
        let kinds = t.join().unwrap();
        assert_eq!(kinds.last().map(String::as_str), Some("security.reverse_shell"));
        assert_eq!(kinds.len(), 4);
        assert!(q.pop_timeout(Duration::from_millis(10)).is_none());
    }

    #[test]
    fn blocks_are_taken_in_batches() {
        let q = std::sync::Arc::new(BlockQueue::new(3));
        let job = |i: u8| {
            let e = Event::new("security.waf_attack", Severity::Warning, "x")
                .subject(warden_core::Subject::Ip { addr: std::net::IpAddr::from([203, 0, 113, i]) });
            BlockJob::of(&e, 0, None)
        };
        // nothing queued: an empty batch after `idle`
        let t = Instant::now();
        assert!(q.take_batch(10, Duration::from_millis(5), Duration::from_millis(30)).is_empty());
        assert!(t.elapsed() >= Duration::from_millis(30));
        for i in 0..3 {
            assert!(q.push(job(i)));
        }
        assert!(!q.push(job(9)), "full: the newcomer is refused");
        // at most `max` at a time, without lingering once there are that many
        let t = Instant::now();
        assert_eq!(q.take_batch(2, Duration::from_secs(5), Duration::from_secs(1)).len(), 2);
        assert!(t.elapsed() < Duration::from_secs(1));
        // a lone job waits `linger` for company, then goes
        let t = Instant::now();
        assert_eq!(q.take_batch(10, Duration::from_millis(50), Duration::from_secs(1)).len(), 1);
        assert!(t.elapsed() >= Duration::from_millis(50));
        // jobs that arrive during the linger join the batch
        let q2 = q.clone();
        let feeder = std::thread::spawn(move || {
            for i in 0..2 {
                std::thread::sleep(Duration::from_millis(10));
                assert!(q2.push(job(i)));
            }
        });
        let b = q.take_batch(10, Duration::from_millis(200), Duration::from_secs(1));
        feeder.join().unwrap();
        assert!(!b.is_empty());
        assert_eq!(b.len() + q.len(), 2);
    }
}
