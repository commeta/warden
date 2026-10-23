//! Rate limiting, cooldowns and counter-to-rate conversion.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::time::{Duration, Instant};

/// At most `max` hits per sliding `window`.
#[derive(Debug, Clone)]
pub struct SlidingWindow {
    window: Duration,
    max: usize,
    hits: VecDeque<Instant>,
}

impl SlidingWindow {
    pub fn new(window: Duration, max: usize) -> Self {
        Self { window, max, hits: VecDeque::new() }
    }

    fn evict(&mut self, now: Instant) {
        while let Some(&front) = self.hits.front() {
            if now.saturating_duration_since(front) >= self.window {
                self.hits.pop_front();
            } else {
                break;
            }
        }
    }

    /// Record a hit if allowed; returns whether it was allowed.
    pub fn allow(&mut self, now: Instant) -> bool {
        self.evict(now);
        if self.hits.len() < self.max {
            self.hits.push_back(now);
            true
        } else {
            false
        }
    }

    /// Would a hit be allowed now? Nothing is recorded: for a caller that
    /// learns only afterwards whether the thing really happened (an action
    /// that may be refused, skipped or turn out to be a dry run).
    pub fn peek(&mut self, now: Instant) -> bool {
        self.evict(now);
        self.hits.len() < self.max
    }

    /// Record a hit that happened (after a successful [`SlidingWindow::peek`]).
    pub fn record(&mut self, now: Instant) {
        self.evict(now);
        self.hits.push_back(now);
    }

    /// Take back a hit recorded at `at` (a reservation that was not used).
    pub fn unrecord(&mut self, at: Instant) {
        if let Some(i) = self.hits.iter().rposition(|t| *t == at) {
            self.hits.remove(i);
        }
    }

    pub fn max(&self) -> usize {
        self.max
    }

    pub fn count(&mut self, now: Instant) -> usize {
        self.evict(now);
        self.hits.len()
    }

    /// Change the limit without forgetting recorded hits (config reload).
    pub fn set_max(&mut self, max: usize) {
        self.max = max;
    }
}

/// Per-key cooldown.
#[derive(Debug, Clone)]
pub struct Cooldown<K: Eq + Hash> {
    period: Duration,
    last: HashMap<K, Instant>,
    /// Garbage-collect when the map grows past this (amortised: doubling
    /// after each pass, so a flood of distinct keys costs O(1) per call
    /// instead of a full scan on every insert).
    gc_at: usize,
}

const GC_MIN: usize = 4096;

impl<K: Eq + Hash + Clone> Cooldown<K> {
    pub fn new(period: Duration) -> Self {
        Self { period, last: HashMap::new(), gc_at: GC_MIN }
    }

    /// Returns true (and arms the cooldown) if the key is not cooling down.
    pub fn ready(&mut self, key: &K, now: Instant) -> bool {
        if self.cooling(key, now) {
            return false;
        }
        self.arm(key, now);
        true
    }

    /// Whether the key is still cooling down, without arming it: for callers
    /// that decide only later whether the thing actually happened (an action
    /// that may turn out to be a dry run or be refused by a budget).
    pub fn cooling(&self, key: &K, now: Instant) -> bool {
        self.last.get(key).is_some_and(|t| now.saturating_duration_since(*t) < self.period)
    }

    /// Start (or restart) the cooldown of a key.
    pub fn arm(&mut self, key: &K, now: Instant) {
        self.last.insert(key.clone(), now);
        if self.last.len() > self.gc_at {
            self.gc(now);
        }
    }

    pub fn set_period(&mut self, p: Duration) {
        self.period = p;
    }

    pub fn gc(&mut self, now: Instant) {
        let p = self.period;
        self.last.retain(|_, t| now.saturating_duration_since(*t) < p);
        self.gc_at = (self.last.len() * 2).max(GC_MIN);
    }

    pub fn len(&self) -> usize {
        self.last.len()
    }

    pub fn is_empty(&self) -> bool {
        self.last.is_empty()
    }
}

/// Count events per key in a sliding window (brute-force detection etc.).
#[derive(Debug, Clone)]
pub struct KeyedWindow<K: Eq + Hash> {
    window: Duration,
    map: HashMap<K, VecDeque<Instant>>,
    gc_at: usize,
}

/// Hits remembered per key: thresholds are far lower, and a flood from one
/// source must not grow the queue without bound.
const MAX_PER_KEY: usize = 4096;

impl<K: Eq + Hash + Clone> KeyedWindow<K> {
    pub fn new(window: Duration) -> Self {
        Self { window, map: HashMap::new(), gc_at: 65_536 }
    }

    /// Add a hit and return the number of hits for the key inside the window.
    pub fn add(&mut self, key: K, now: Instant) -> usize {
        let w = self.window;
        let q = self.map.entry(key).or_default();
        q.push_back(now);
        while let Some(&f) = q.front() {
            if now.saturating_duration_since(f) >= w || q.len() > MAX_PER_KEY {
                q.pop_front();
            } else {
                break;
            }
        }
        let n = q.len();
        if self.map.len() > self.gc_at {
            self.gc(now);
        }
        n
    }

    pub fn reset(&mut self, key: &K) {
        self.map.remove(key);
    }

    pub fn gc(&mut self, now: Instant) {
        let w = self.window;
        self.map.retain(|_, q| q.back().is_some_and(|b| now.saturating_duration_since(*b) < w));
        self.gc_at = (self.map.len() * 2).max(65_536);
    }
}

/// Converts a monotonically increasing kernel counter into a per-second rate.
/// Counter resets (wraps, reboot of a namespace) yield `None` once.
#[derive(Debug, Clone, Copy, Default)]
pub struct CounterRate {
    last: Option<(Instant, u64)>,
}

impl CounterRate {
    pub fn update(&mut self, now: Instant, value: u64) -> Option<f64> {
        let prev = self.last.replace((now, value));
        let (t, v) = prev?;
        let dt = now.saturating_duration_since(t).as_secs_f64();
        if dt <= 0.0 || value < v {
            return None;
        }
        Some((value - v) as f64 / dt)
    }

    pub fn delta(&mut self, now: Instant, value: u64) -> Option<u64> {
        let prev = self.last.replace((now, value));
        let (_, v) = prev?;
        value.checked_sub(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unused_reservation_is_given_back() {
        let t = Instant::now();
        let mut w = SlidingWindow::new(Duration::from_secs(60), 1);
        w.record(t);
        assert!(!w.peek(t));
        w.unrecord(t);
        assert!(w.peek(t));
        w.unrecord(t); // nothing there: no-op
        assert_eq!(w.count(t), 0);
    }

    #[test]
    fn peek_does_not_count() {
        let t = Instant::now();
        let mut w = SlidingWindow::new(Duration::from_secs(3600), 2);
        for _ in 0..10 {
            assert!(w.peek(t), "asking is free");
        }
        w.record(t);
        w.record(t);
        assert!(!w.peek(t));
        assert!(w.peek(t + Duration::from_secs(3600)));
    }

    #[test]
    fn sliding_window_limits() {
        let s = Instant::now();
        let mut w = SlidingWindow::new(Duration::from_secs(10), 2);
        assert!(w.allow(s));
        assert!(w.allow(s + Duration::from_secs(1)));
        assert!(!w.allow(s + Duration::from_secs(2)));
        assert!(w.allow(s + Duration::from_secs(10)));
    }

    #[test]
    fn cooldown_per_key() {
        let s = Instant::now();
        let mut c = Cooldown::new(Duration::from_secs(5));
        assert!(c.ready(&"a", s));
        assert!(!c.ready(&"a", s + Duration::from_secs(1)));
        assert!(c.ready(&"b", s + Duration::from_secs(1)));
        assert!(c.ready(&"a", s + Duration::from_secs(5)));
    }

    #[test]
    fn checking_a_cooldown_does_not_arm_it() {
        let s = Instant::now();
        let mut c = Cooldown::new(Duration::from_secs(5));
        assert!(!c.cooling(&"a", s));
        assert!(!c.cooling(&"a", s), "a check alone must not start the cooldown");
        c.arm(&"a", s);
        assert!(c.cooling(&"a", s + Duration::from_secs(4)));
        assert!(!c.cooling(&"a", s + Duration::from_secs(5)));
    }

    #[test]
    fn keyed_window_counts() {
        let s = Instant::now();
        let mut k = KeyedWindow::new(Duration::from_secs(60));
        assert_eq!(k.add("1.2.3.4", s), 1);
        assert_eq!(k.add("1.2.3.4", s + Duration::from_secs(10)), 2);
        assert_eq!(k.add("1.2.3.4", s + Duration::from_secs(70)), 1);
    }

    #[test]
    fn counter_rate() {
        let s = Instant::now();
        let mut r = CounterRate::default();
        assert_eq!(r.update(s, 100), None);
        assert_eq!(r.update(s + Duration::from_secs(2), 300), Some(100.0));
        assert_eq!(r.update(s + Duration::from_secs(3), 10), None); // reset
    }

    #[test]
    fn floods_of_distinct_keys_stay_cheap_and_bounded() {
        let now = Instant::now();
        let mut c: Cooldown<u32> = Cooldown::new(Duration::from_secs(600));
        let t = std::time::Instant::now();
        for i in 0..100_000u32 {
            assert!(c.ready(&i, now));
        }
        // amortised GC: 100k distinct live keys in well under a second
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
        let mut w: KeyedWindow<u8> = KeyedWindow::new(Duration::from_secs(600));
        for _ in 0..10_000 {
            w.add(1, now);
        }
        assert_eq!(w.add(1, now), MAX_PER_KEY);
    }
}
