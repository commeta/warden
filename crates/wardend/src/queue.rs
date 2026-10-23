//! The queue from the detectors to the engine.
//!
//! Bounded, never blocks a detector, and when it is full it does not simply
//! refuse the newcomer: it gives up the oldest event of the *lowest*
//! priority ([`Event::priority`]) below the newcomer's. An attacker who
//! floods the host with noise (thousands of info and notice events) can
//! fill it, but cannot push a `security.*` finding or a critical event out
//! of it — those are dropped only for one another. (0.14.0 used a plain
//! channel: when it was full, whatever came next was lost.)
//!
//! Events leave in arrival order (FIFO): the priority decides only what is
//! dropped, so the lifecycle of a condition (opened, escalated, resolved)
//! is never reordered.

use std::collections::VecDeque;
use std::sync::Mutex;
use tokio::sync::Notify;
use warden_core::Event;
use warden_core::sync::lock;

/// Priorities run 0..=MAX_PRIORITY.
const LEVELS: usize = 5;

pub struct EventQueue {
    inner: Mutex<Inner>,
    ready: Notify,
    cap: usize,
}

struct Inner {
    events: VecDeque<(u8, Event)>,
    /// Queued events per priority: whether something lower than a newcomer
    /// is there is known without a scan.
    per_level: [usize; LEVELS],
}

/// What [`EventQueue::push`] had to give up.
#[derive(Debug, PartialEq, Eq)]
pub enum Dropped {
    /// The newcomer: the queue is full of events at least as important.
    Incoming(u8),
    /// An older, less important event made room for the newcomer.
    Evicted(u8),
}

impl EventQueue {
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Mutex::new(Inner { events: VecDeque::with_capacity(cap.min(1024)), per_level: [0; LEVELS] }),
            ready: Notify::new(),
            cap: cap.max(1),
        }
    }

    /// Queue `ev`; never blocks (beyond the lock, held for O(1) — or one
    /// scan when an important event has to evict a lesser one).
    pub fn push(&self, ev: Event) -> Option<Dropped> {
        let p = ev.priority().min(LEVELS as u8 - 1);
        let mut q = lock(&self.inner);
        let mut dropped = None;
        if q.events.len() >= self.cap {
            let Some(lowest) = (0..p).find(|&l| q.per_level[usize::from(l)] > 0) else {
                return Some(Dropped::Incoming(p));
            };
            if let Some(i) = q.events.iter().position(|(l, _)| *l == lowest) {
                q.events.remove(i);
                q.per_level[usize::from(lowest)] -= 1;
                dropped = Some(Dropped::Evicted(lowest));
            }
        }
        q.events.push_back((p, ev));
        q.per_level[usize::from(p)] += 1;
        drop(q);
        self.ready.notify_one();
        dropped
    }

    fn try_pop(&self) -> Option<Event> {
        let mut q = lock(&self.inner);
        let (p, ev) = q.events.pop_front()?;
        q.per_level[usize::from(p)] -= 1;
        Some(ev)
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
        assert_eq!(q.push(webshell), None);
        for i in 0..1000 {
            q.push(ev("noise.x", Severity::Info).fingerprint(format!("n{i}")));
        }
        assert_eq!(q.len(), 100);
        // a critical event arriving into the full queue evicts noise
        assert_eq!(q.push(ev("memory.pressure", Severity::Critical)), Some(Dropped::Evicted(0)));
        // more noise is refused, not the important events
        assert_eq!(q.push(ev("noise.x", Severity::Info)), Some(Dropped::Incoming(0)));
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
        assert_eq!(q.push(ev("cpu.pressure", Severity::Warning)), Some(Dropped::Incoming(2)));
        assert_eq!(q.push(ev("security.y", Severity::Emergency)), Some(Dropped::Evicted(3)));
        assert_eq!(q.push(ev("security.z", Severity::Emergency)), Some(Dropped::Incoming(4)));
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
}
