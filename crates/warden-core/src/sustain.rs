//! Hysteresis for threshold-based detectors.
//!
//! A raw reading crosses a threshold many times per minute on a busy host.
//! [`LevelTracker`] only reports a level after it has been held for a
//! *sustain* period, re-reports it periodically while it persists (so a
//! remediation that did not help is retried on the next culprit), and only
//! declares recovery after the reading stayed below for *clear_after*.

use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Level {
    #[default]
    Ok,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transition {
    None,
    /// Level went up (fire an event with this level).
    Raised(Level),
    /// Still at this level after `repeat` (fire again).
    Repeated(Level),
    /// Went down to a non-OK level.
    Lowered(Level),
    /// Back to OK.
    Cleared,
}

#[derive(Debug, Clone)]
pub struct LevelTracker {
    pub sustain_warning: Duration,
    pub sustain_critical: Duration,
    pub clear_after: Duration,
    pub repeat: Duration,
    current: Level,
    warn_since: Option<Instant>,
    crit_since: Option<Instant>,
    below_since: Option<Instant>,
    last_fired: Option<Instant>,
    /// When the current non-OK episode started (for "lasted N s" reporting).
    episode_start: Option<Instant>,
}

impl LevelTracker {
    pub fn new(sustain_warning: Duration, sustain_critical: Duration, clear_after: Duration, repeat: Duration) -> Self {
        Self {
            sustain_warning,
            sustain_critical,
            clear_after,
            repeat,
            current: Level::Ok,
            warn_since: None,
            crit_since: None,
            below_since: None,
            last_fired: None,
            episode_start: None,
        }
    }

    pub fn level(&self) -> Level {
        self.current
    }

    /// New timings from a reload: the current level, the episode and the
    /// time held so far are kept (a reload is not a recovery).
    pub fn retune(
        &mut self,
        sustain_warning: Duration,
        sustain_critical: Duration,
        clear_after: Duration,
        repeat: Duration,
    ) {
        self.sustain_warning = sustain_warning;
        self.sustain_critical = sustain_critical;
        self.clear_after = clear_after;
        self.repeat = repeat;
    }

    /// How long the current (or just-cleared) episode has lasted.
    pub fn episode_duration(&self, now: Instant) -> Duration {
        self.episode_start.map(|s| now.saturating_duration_since(s)).unwrap_or_default()
    }

    pub fn update(&mut self, now: Instant, raw: Level) -> Transition {
        // Track continuous holding of each level.
        if raw >= Level::Warning {
            self.warn_since.get_or_insert(now);
        } else {
            self.warn_since = None;
        }
        if raw >= Level::Critical {
            self.crit_since.get_or_insert(now);
        } else {
            self.crit_since = None;
        }

        let held = |since: Option<Instant>, d: Duration| since.is_some_and(|s| now.saturating_duration_since(s) >= d);
        let target = if held(self.crit_since, self.sustain_critical) {
            Level::Critical
        } else if held(self.warn_since, self.sustain_warning) {
            Level::Warning
        } else {
            Level::Ok
        };

        if target > self.current {
            if self.current == Level::Ok {
                self.episode_start = self.warn_since;
            }
            self.current = target;
            self.below_since = None;
            self.last_fired = Some(now);
            return Transition::Raised(target);
        }

        if raw >= self.current {
            self.below_since = None;
            if self.current > Level::Ok
                && !self.repeat.is_zero()
                && self.last_fired.is_some_and(|t| now.saturating_duration_since(t) >= self.repeat)
            {
                self.last_fired = Some(now);
                return Transition::Repeated(self.current);
            }
            return Transition::None;
        }

        // raw < current: wait for clear_after before stepping down.
        let since = *self.below_since.get_or_insert(now);
        if now.saturating_duration_since(since) >= self.clear_after {
            self.below_since = None;
            self.current = raw;
            if raw == Level::Ok {
                return Transition::Cleared;
            }
            self.last_fired = Some(now);
            return Transition::Lowered(raw);
        }
        Transition::None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn requires_sustain_before_raising() {
        let s = t0();
        let mut t =
            LevelTracker::new(Duration::from_secs(5), Duration::from_secs(10), Duration::from_secs(5), Duration::ZERO);
        assert_eq!(t.update(s, Level::Critical), Transition::None);
        assert_eq!(t.update(s + Duration::from_secs(5), Level::Critical), Transition::Raised(Level::Warning));
        assert_eq!(t.update(s + Duration::from_secs(9), Level::Critical), Transition::None);
        assert_eq!(t.update(s + Duration::from_secs(10), Level::Critical), Transition::Raised(Level::Critical));
    }

    #[test]
    fn interruption_resets_sustain() {
        let s = t0();
        let mut t =
            LevelTracker::new(Duration::from_secs(5), Duration::from_secs(5), Duration::from_secs(5), Duration::ZERO);
        t.update(s, Level::Critical);
        t.update(s + Duration::from_secs(3), Level::Ok);
        assert_eq!(t.update(s + Duration::from_secs(6), Level::Critical), Transition::None);
        assert_eq!(t.update(s + Duration::from_secs(11), Level::Critical), Transition::Raised(Level::Critical));
    }

    #[test]
    fn repeats_while_active_and_clears_with_hysteresis() {
        let s = t0();
        let mut t = LevelTracker::new(Duration::ZERO, Duration::ZERO, Duration::from_secs(10), Duration::from_secs(30));
        assert_eq!(t.update(s, Level::Critical), Transition::Raised(Level::Critical));
        assert_eq!(t.update(s + Duration::from_secs(29), Level::Critical), Transition::None);
        assert_eq!(t.update(s + Duration::from_secs(30), Level::Critical), Transition::Repeated(Level::Critical));
        // drops but not long enough
        assert_eq!(t.update(s + Duration::from_secs(31), Level::Ok), Transition::None);
        assert_eq!(t.update(s + Duration::from_secs(35), Level::Ok), Transition::None);
        assert_eq!(t.update(s + Duration::from_secs(41), Level::Ok), Transition::Cleared);
        assert_eq!(t.level(), Level::Ok);
        assert!(t.episode_duration(s + Duration::from_secs(41)) >= Duration::from_secs(41));
    }

    #[test]
    fn steps_down_to_warning() {
        let s = t0();
        let mut t = LevelTracker::new(Duration::ZERO, Duration::ZERO, Duration::from_secs(1), Duration::ZERO);
        t.update(s, Level::Critical);
        assert_eq!(t.update(s + Duration::from_secs(1), Level::Warning), Transition::None);
        assert_eq!(t.update(s + Duration::from_secs(2), Level::Warning), Transition::Lowered(Level::Warning));
    }
}
