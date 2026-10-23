//! A clock that keeps running while the machine is suspended.
//!
//! `std::time::Instant` is `CLOCK_MONOTONIC`, which stops during suspend. For
//! a server that never sleeps that does not matter; on a laptop or a desktop
//! that sleeps every night, every interval measured with it — "once a day",
//! "at most N per hour", "reminder in 2 h", "15 min dedup", "this report is
//! 3 h old" — silently stretches by the time spent asleep.
//!
//! [`now`] returns an `Instant` that also advances during suspend: the
//! monotonic clock plus the time slept since the daemon started
//! (`CLOCK_BOOTTIME` − `CLOCK_MONOTONIC`, Linux 2.6.39+). Use it for what is
//! configured and read in real time: windows, cooldowns, budgets, back-offs,
//! schedules, decay, ages shown to the operator. Keep `Instant::now` for what
//! must be *continuous*: sustain and hysteresis (two readings eight hours
//! apart around a suspend are not "pressure held for a minute"), timeouts,
//! rates, durations of work.
//!
//! Instants from the two clocks must not be compared with each other: an
//! `Instant` stored from [`now`] is compared with [`now`] again
//! (`saturating_duration_since`, never `elapsed`).

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

fn read(clock: libc::clockid_t) -> Duration {
    let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid out pointer; both clocks exist on every supported kernel.
    unsafe { libc::clock_gettime(clock, &mut ts) };
    Duration::new(ts.tv_sec.max(0) as u64, ts.tv_nsec.clamp(0, 999_999_999) as u32)
}

/// `CLOCK_BOOTTIME` − `CLOCK_MONOTONIC`: total suspend time since boot.
fn suspended_since_boot() -> Duration {
    let mono = read(libc::CLOCK_MONOTONIC);
    let boot = read(libc::CLOCK_BOOTTIME);
    boot.saturating_sub(mono)
}

/// Suspend time folded into [`now`]: never decreases.
#[derive(Debug)]
pub struct Slept {
    base: Duration,
    max_ns: AtomicU64,
}

impl Slept {
    pub fn new(suspended_since_boot: Duration) -> Self {
        Self { base: suspended_since_boot, max_ns: AtomicU64::new(0) }
    }

    /// Fold in a new reading of the suspend time since boot. The two clocks
    /// are read one after the other, so consecutive readings jitter by a
    /// few hundred nanoseconds; the result is the largest value seen, which
    /// keeps [`now`] monotonic.
    pub fn update(&self, suspended_since_boot: Duration) -> Duration {
        let v = suspended_since_boot.saturating_sub(self.base).as_nanos().min(u64::MAX as u128) as u64;
        let prev = self.max_ns.fetch_max(v, Ordering::Relaxed);
        Duration::from_nanos(prev.max(v))
    }
}

fn slept_state() -> &'static Slept {
    static S: OnceLock<Slept> = OnceLock::new();
    S.get_or_init(|| Slept::new(suspended_since_boot()))
}

/// Time this process has spent suspended (0 on a machine that did not sleep).
pub fn slept() -> Duration {
    slept_state().update(suspended_since_boot() + simulated())
}

#[cfg(feature = "test-util")]
static SIMULATED_NS: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "test-util")]
fn simulated() -> Duration {
    Duration::from_nanos(SIMULATED_NS.load(Ordering::Relaxed))
}

#[cfg(not(feature = "test-util"))]
fn simulated() -> Duration {
    Duration::ZERO
}

/// Tests of other crates: pretend the machine was suspended for `d`
/// (process-wide — keep such a test alone in its own test binary).
#[cfg(feature = "test-util")]
pub fn simulate_suspend(d: Duration) {
    SIMULATED_NS.fetch_add(d.as_nanos().min(u64::MAX as u128) as u64, Ordering::Relaxed);
}

/// "Now" on a clock that also runs during suspend (see the module docs).
pub fn now() -> Instant {
    // read the suspend time first: an `Instant` taken before it can only be
    // older, never newer, than the suspend time added to it
    let s = slept();
    Instant::now() + s
}

/// Start the clock (the first call fixes the base): call early in `main`.
pub fn init() {
    let _ = slept_state();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suspend_time_is_added_and_never_taken_back() {
        let s = Slept::new(Duration::from_secs(100));
        assert_eq!(s.update(Duration::from_secs(100)), Duration::ZERO, "no sleep since start");
        // 8 h of suspend
        assert_eq!(s.update(Duration::from_secs(100 + 8 * 3600)), Duration::from_secs(8 * 3600));
        // a reading a few hundred ns lower (the clocks are read one by one)
        let jitter = Duration::from_secs(100 + 8 * 3600) - Duration::from_nanos(300);
        assert_eq!(s.update(jitter), Duration::from_secs(8 * 3600));
        // a reading below the base (cannot happen, must not underflow)
        assert_eq!(s.update(Duration::ZERO), Duration::from_secs(8 * 3600));
    }

    #[test]
    fn the_real_clock_runs_with_the_monotonic_one_while_awake() {
        init();
        let (a, m) = (now(), Instant::now());
        assert!(a + Duration::from_millis(5) >= m, "never behind the monotonic clock");
        std::thread::sleep(Duration::from_millis(20));
        let b = now();
        let d = b.saturating_duration_since(a);
        assert!(d >= Duration::from_millis(20) && d < Duration::from_secs(5), "{d:?}");
        // monotonic over many readings
        let mut last = now();
        for _ in 0..10_000 {
            let n = now();
            assert!(n >= last);
            last = n;
        }
        eprintln!("this machine has been suspended for {:?} since boot", suspended_since_boot());
    }
}
