//! Hardware health (ECC errors, temperatures) and clock synchronisation.

use crate::limits::Thresholds;
use crate::runtime::{Cx, Detector};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use warden_core::config::HardwareConfig;
use warden_core::{Event, Level, Severity, Transition};
use warden_sys::{hw, kernel};

pub struct HardwareDetector {
    cfg: HardwareConfig,
    edac: HashMap<String, (u64, u64)>,
    thermal: Thresholds,
    unsync_since: Option<Instant>,
    clock_alerted: bool,
}

impl HardwareDetector {
    pub fn new(cfg: &HardwareConfig) -> Self {
        Self {
            cfg: cfg.clone(),
            edac: HashMap::new(),
            thermal: Thresholds::new(Duration::from_secs(60), Duration::from_secs(300), Duration::from_secs(3600)),
            unsync_since: None,
            clock_alerted: false,
        }
    }
}

/// What the hardware detector reads on one tick.
#[derive(Debug, Clone, Default)]
pub struct HwSample {
    pub edac: Vec<hw::EdacController>,
    pub thermal: Vec<hw::ThermalZone>,
    pub clock: Option<kernel::ClockStatus>,
}

impl HwSample {
    pub fn read(cfg: &HardwareConfig) -> Self {
        Self {
            edac: if cfg.edac { hw::edac() } else { Vec::new() },
            thermal: if cfg.thermal { hw::thermal() } else { Vec::new() },
            clock: if cfg.clock { kernel::clock_status() } else { None },
        }
    }
}

impl Detector for HardwareDetector {
    fn name(&self) -> &'static str {
        "hardware"
    }

    fn interval(&self) -> Duration {
        self.cfg.interval
    }

    fn tick(&mut self, cx: &mut Cx<'_>) {
        let s = HwSample::read(&self.cfg);
        self.evaluate(cx, s);
    }

    fn sections(&self) -> &'static [&'static str] {
        &["/hardware"]
    }

    fn reconfigure(&mut self, cfg: &warden_core::Config) -> bool {
        self.cfg = cfg.hardware.clone();
        true
    }

    fn close(&mut self) -> Vec<Event> {
        let mut v: Vec<Event> = self
            .thermal
            .open()
            .filter_map(|(k, t)| {
                crate::runtime::close_level("hardware.temperature", &format!("hardware.temperature:{k}"), t)
            })
            .collect();
        if self.clock_alerted {
            v.push(
                Event::new(
                    "system.clock_unsynchronized",
                    Severity::Info,
                    format!("system.clock_unsynchronized: {}", crate::runtime::NO_LONGER_WATCHED),
                )
                .fingerprint("system.clock_unsynchronized:resolved")
                .resolved(),
            );
        }
        v
    }
}

impl HardwareDetector {
    pub fn evaluate(&mut self, cx: &Cx<'_>, s: HwSample) {
        if self.cfg.edac {
            for mc in s.edac {
                cx.metric("warden_edac_corrected_total", &[("mc", &mc.name)], mc.ce as f64);
                cx.metric("warden_edac_uncorrected_total", &[("mc", &mc.name)], mc.ue as f64);
                if let Some((ce, ue)) = self.edac.insert(mc.name.clone(), (mc.ce, mc.ue)) {
                    if mc.ue > ue {
                        cx.emit(
                            Event::new(
                                "hardware.memory_uncorrected",
                                Severity::Critical,
                                format!("{}: {} uncorrectable ECC memory error(s)", mc.name, mc.ue - ue),
                            )
                            .fingerprint(format!("hardware.memory_uncorrected:{}", mc.name))
                            .detail("hint", "data corruption risk — schedule DIMM replacement immediately"),
                        );
                    } else if mc.ce > ce {
                        cx.emit(
                            Event::new(
                                "hardware.memory_corrected",
                                Severity::Warning,
                                format!("{}: {} corrected ECC memory error(s)", mc.name, mc.ce - ce),
                            )
                            .fingerprint(format!("hardware.memory_corrected:{}", mc.name))
                            .detail("total_corrected", mc.ce),
                        );
                    }
                }
            }
        }
        if self.cfg.thermal {
            for z in s.thermal {
                let key = format!("{}:{}", z.zone, z.kind);
                cx.metric("warden_temperature_celsius", &[("zone", &z.zone), ("type", &z.kind)], z.celsius);
                match self.thermal.update(
                    &key,
                    cx.now,
                    z.celsius,
                    self.cfg.thermal_warning_c,
                    self.cfg.thermal_critical_c,
                ) {
                    Transition::Raised(l) | Transition::Repeated(l) if l > Level::Ok => {
                        let sev = if l == Level::Critical { Severity::Critical } else { Severity::Warning };
                        cx.emit(
                            Event::new(
                                "hardware.temperature",
                                sev,
                                format!("{} ({}) at {:.0}°C", z.zone, z.kind, z.celsius),
                            )
                            .fingerprint(format!("hardware.temperature:{key}:{sev}"))
                            .detail("celsius", z.celsius),
                        );
                    }
                    Transition::Cleared => cx.emit(
                        Event::new("hardware.temperature", Severity::Info, format!("{} temperature normal", z.zone))
                            .fingerprint(format!("hardware.temperature:{key}:resolved"))
                            .resolved(),
                    ),
                    _ => {}
                }
            }
        }
        if self.cfg.clock
            && let Some(cs) = s.clock
        {
            cx.metric("warden_clock_synced", &[], if cs.synced { 1.0 } else { 0.0 });
            cx.metric("warden_clock_max_error_seconds", &[], cs.max_error_us as f64 / 1e6);
            cx.metric("warden_clock_est_error_seconds", &[], cs.est_error_us as f64 / 1e6);
            let bad = clock_bad(&cs, self.cfg.clock_max_error);
            if bad {
                let since = *self.unsync_since.get_or_insert(cx.now);
                // Give NTP time after boot / network outages.
                if !self.clock_alerted && cx.now.saturating_duration_since(since) > Duration::from_secs(900) {
                    self.clock_alerted = true;
                    cx.emit(
                        Event::new("system.clock_unsynchronized", Severity::Warning, "system clock is not synchronised (NTP)")
                            .fingerprint("system.clock_unsynchronized:warning")
                            .detail("synced", cs.synced)
                            .detail("est_error_ms", cs.est_error_us / 1000)
                            .detail("max_error_ms", cs.max_error_us / 1000)
                            .detail("hint", "TLS, Kerberos, TOTP and log correlation break with clock drift; check chrony/systemd-timesyncd"),
                    );
                }
            } else {
                if self.clock_alerted {
                    cx.emit(
                        Event::new("system.clock_unsynchronized", Severity::Info, "clock synchronised again")
                            .fingerprint("system.clock_unsynchronized:resolved")
                            .resolved(),
                    );
                }
                self.unsync_since = None;
                self.clock_alerted = false;
            }
        }
        let mut level = self.thermal.worst();
        if self.clock_alerted {
            level = level.max(Level::Warning);
        }
        cx.shared.set_level("hardware", &format!("{level:?}").to_lowercase());
    }
}

/// Is the clock out of sync? `STA_UNSYNC` (what `timedatectl` reports as
/// "System clock synchronized") or the NTP daemon's *estimated* error above
/// the limit. `maxerror` is deliberately not used: it is a worst-case bound
/// that the kernel grows by 500 µs every second between NTP updates, so with
/// systemd-timesyncd's 2048 s poll it climbs past 1 s on a perfectly healthy
/// host (the kernel itself raises `STA_UNSYNC` when it reaches 16 s).
pub fn clock_bad(cs: &kernel::ClockStatus, limit: Duration) -> bool {
    !cs.synced || cs.est_error_us.max(0) as u128 > limit.as_micros()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{Shared, Sink, lock};

    /// One sample per minute (the default interval); (minute, event).
    fn run(series: Vec<HwSample>) -> Vec<(u64, Event)> {
        let cfg = warden_core::Config::default();
        let mut d = HardwareDetector::new(&cfg.hardware);
        let shared = Shared::new(cfg.clone());
        let (sink, events) = Sink::collector();
        let t0 = Instant::now();
        let mut out = Vec::new();
        for (i, s) in series.into_iter().enumerate() {
            let mut cx = Cx::new(&shared, &cfg, &sink, "test");
            cx.now = t0 + Duration::from_secs(60 * i as u64);
            d.evaluate(&cx, s);
            out.extend(lock(&events).drain(..).map(|e| (i as u64, e)));
        }
        out
    }

    #[test]
    fn ecc_errors_are_reported_as_they_grow() {
        let mc =
            |ce, ue| HwSample { edac: vec![hw::EdacController { name: "mc0".into(), ce, ue }], ..Default::default() };
        // counters that were already non-zero at start are history, not news
        let ev = run(vec![mc(40, 0), mc(40, 0), mc(43, 0), mc(44, 1), mc(44, 1)]);
        let got: Vec<(u64, Severity, &str)> = ev.iter().map(|(t, e)| (*t, e.severity, e.title.as_str())).collect();
        assert_eq!(
            got,
            [
                (2, Severity::Warning, "mc0: 3 corrected ECC memory error(s)"),
                (3, Severity::Critical, "mc0: 1 uncorrectable ECC memory error(s)"),
            ]
        );
    }

    #[test]
    fn temperature_needs_a_minute_and_five_to_clear() {
        let z = |c| HwSample {
            thermal: vec![hw::ThermalZone { zone: "thermal_zone0".into(), kind: "x86_pkg_temp".into(), celsius: c }],
            ..Default::default()
        };
        let ev = run([70.0, 90.0, 90.0, 97.0, 97.0, 60.0, 60.0, 60.0, 60.0, 60.0, 60.0].into_iter().map(z).collect());
        let got: Vec<(u64, Severity, &str)> =
            ev.iter().map(|(t, e)| (*t, e.severity, e.fingerprint.as_str())).collect();
        let fp = "hardware.temperature:thermal_zone0:x86_pkg_temp";
        assert_eq!(
            got,
            [
                (2, Severity::Warning, format!("{fp}:warning").as_str()),
                (4, Severity::Critical, format!("{fp}:critical").as_str()),
                (10, Severity::Info, "hardware.temperature:thermal_zone0:x86_pkg_temp:resolved"),
            ]
        );
    }

    #[test]
    fn an_unsynchronised_clock_is_reported_after_15_minutes_once() {
        let c = |synced| HwSample {
            clock: Some(kernel::ClockStatus { synced, max_error_us: 0, est_error_us: 0 }),
            ..Default::default()
        };
        let mut series: Vec<HwSample> = (0..20).map(|_| c(false)).collect();
        series.push(c(true));
        series.push(c(true));
        let ev = run(series);
        let got: Vec<(u64, &str)> = ev.iter().map(|(t, e)| (*t, e.fingerprint.as_str())).collect();
        assert_eq!(got, [(16, "system.clock_unsynchronized:warning"), (20, "system.clock_unsynchronized:resolved")]);
    }

    #[test]
    fn clock_check_ignores_growing_max_error() {
        let limit = Duration::from_millis(500);
        let cs = |synced, est, max| kernel::ClockStatus { synced, est_error_us: est, max_error_us: max };
        // Just before a timesyncd poll: maxerror ≈ 1 s, estimate tiny → fine.
        assert!(!clock_bad(&cs(true, 1_200, 1_024_000), limit));
        assert!(clock_bad(&cs(false, 0, 16_000_000), limit));
        assert!(clock_bad(&cs(true, 800_000, 900_000), limit));
    }
}
