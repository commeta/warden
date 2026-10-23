//! Regression tests from the 0.13.0 review (docs/reviews/audit-0.13.0.ru.md).
//!
//! Each test states the *intended* behaviour and names the section of the
//! report. They failed on 0.13.0; the ones fixed in 0.13.1 run by default,
//! the rest are still ignored (Sprint 1). Run them all with
//! `cargo test -p warden-detect --test review_0_13 -- --include-ignored`.
#![allow(clippy::unwrap_used)]

use std::collections::{BTreeSet, HashMap, HashSet};
use std::time::{Duration, Instant};
use warden_core::Event;
use warden_core::config::{HeuristicsConfig, KernelConfig, SystemdConfig};
use warden_detect::runtime::{Cx, Detector, Shared, Sink};
use warden_detect::systemd::UnitSnapshot;

/// §3.4 — the "link up" event must name the "link down" incident it closes.
/// Fixed in 0.13.1 with the project-wide convention: the resolution's
/// fingerprint is the condition's plus `:resolved` (the review suggested one
/// shared fingerprint, but the engine's dedup would then drop the Info
/// resolution that follows a Warning within the window).
#[test]
fn link_down_and_link_up_share_a_fingerprint() {
    let mut a = warden_detect::kernel::KmsgAnalyzer::new(&KernelConfig::default());
    let now = Instant::now();
    let down = a.analyze("r8169 0000:04:00.0 enp4s0: Link is Down", now);
    let up = a.analyze("r8169 0000:04:00.0 enp4s0: Link is Up - 100Mbps/Full - flow control rx/tx", now);
    assert_eq!(down.len(), 1);
    assert_eq!(up.len(), 1);
    assert!(up[0].resolved);
    assert_eq!(
        up[0].fingerprint,
        format!("{}:resolved", down[0].fingerprint),
        "the resolution must name the incident it closes"
    );
    // a flap within the analyzer's cooldown is still reported in full
    let down2 = a.analyze("r8169 0000:04:00.0 enp4s0: Link is Down", now);
    assert_eq!(down2.len(), 1, "the second outage was swallowed by the cooldown");
    // but the same state again is not news
    assert!(a.analyze("r8169 0000:04:00.0 enp4s0: Link is Down", now).is_empty());
}

/// §3.3 — a timer-started oneshot that is merely *activating* again has not
/// recovered: reconciliation saw it leave the failed list while it ran.
/// Fixed in 0.13.2: reconciliation also asks for `activating` and
/// `deactivating` units, and those stay failed until they settle.
#[test]
fn a_unit_that_is_only_restarting_is_not_reported_as_recovered() {
    let cfg = warden_core::Config::default();
    let shared = Shared::new(cfg.clone());
    let (sink, events) = Sink::collector();
    let cx = Cx::new(&shared, &cfg, &sink, "systemd");
    let rules = warden_detect::systemd::UnitRules::new(&SystemdConfig::default());
    let mut st = warden_detect::systemd::UnitState::default();
    let unit = || "fwupd-refresh.service".to_owned();
    rules.reconcile(&mut st, &cx, UnitSnapshot::failed(BTreeSet::from([unit()])), "dbus");
    // The timer starts the unit again (ActiveState=activating): it is no
    // longer among the failed units, but it has not recovered yet.
    let activating = UnitSnapshot { failed: BTreeSet::new(), transitional: BTreeSet::from([unit()]) };
    rules.reconcile(&mut st, &cx, activating, "dbus");
    let titles: Vec<String> = events.lock().unwrap().iter().map(|e| e.title.clone()).collect();
    assert!(
        !titles.iter().any(|t| t.contains("recovered")),
        "reported recovery of a unit that is still starting: {titles:?}"
    );
}

/// §2.6 — `auth.ssh_block = false` (and `waf.block = false`) must mean that
/// Warden does not block the address; the heuristics must not add the block
/// the operator switched off. Fixed in 0.13.2: such events carry
/// `ip_block_off`, and the heuristics do not block on them.
#[test]
fn heuristics_do_not_block_what_the_operator_said_not_to_block() {
    let mut h = warden_detect::heuristics::Heuristics::new(&HeuristicsConfig::default());
    // what auth.rs really emits with ssh_block = false
    let cfg = warden_core::config::AuthConfig { ssh_max_failures: 3, ssh_block: false, ..Default::default() };
    let mut auth = warden_detect::auth::AuthAnalyzer::new(&cfg, &[], &[]);
    let now = Instant::now();
    let mut found = Vec::new();
    for port in 1..=3 {
        found = auth.analyze("sshd", &format!("Failed password for root from 198.51.100.23 port {port} ssh2"), now);
    }
    assert_eq!(found.len(), 1, "the brute force is still reported");
    let ev = &found[0];
    assert!(ev.actions.is_empty());
    let out = h.record(ev, now);
    let blocks: Vec<&Event> =
        out.iter().filter(|e| e.actions.iter().any(|a| matches!(a, warden_core::ActionSpec::BlockIp { .. }))).collect();
    assert!(blocks.is_empty(), "heuristics added a block: {:?}", blocks.iter().map(|e| &e.kind).collect::<Vec<_>>());
}

/// §5.2 — a file whose content, mode and owner did not change is not news:
/// Chrome's daily cron rewrites its apt source with the same text, and the
/// review log shows two "metadata changed" notices with empty diffs for it.
/// Fixed in 0.13.1.
#[test]
fn rewriting_a_file_with_identical_content_is_not_reported() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("google-chrome.sources");
    std::fs::write(&f, "Types: deb\nURIs: https://dl.google.com/linux/chrome/deb/\n").unwrap();
    let mut cfg = warden_core::Config::default();
    cfg.daemon.state_dir = d.path().join("state");
    cfg.integrity.files = vec![f.to_string_lossy().into_owned()];
    cfg.integrity.suid_scan = false;
    cfg.integrity.listeners = false;
    let shared = Shared::new(cfg.clone());
    let (sink, events) = Sink::collector();
    let mut det = warden_detect::integrity::IntegrityDetector::new(&cfg);
    det.tick(&mut Cx::new(&shared, &cfg, &sink, "integrity")); // baseline
    // same bytes, new inode (write + rename, as the cron job does)
    let tmp = d.path().join("x.tmp");
    std::fs::write(&tmp, std::fs::read(&f).unwrap()).unwrap();
    std::fs::rename(&tmp, &f).unwrap();
    det.tick(&mut Cx::new(&shared, &cfg, &sink, "integrity"));
    let titles: Vec<String> = events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.kind != "integrity.baseline_created")
        .map(|e| e.title.clone())
        .collect();
    assert!(titles.is_empty(), "{titles:?}");
    // a permission change on the same bytes is still reported
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o666)).unwrap();
    det.tick(&mut Cx::new(&shared, &cfg, &sink, "integrity"));
    let ev = events.lock().unwrap();
    let last = ev.last().unwrap();
    assert!(last.title.ends_with("metadata changed"), "{}", last.title);
    assert!(last.details.contains_key("mode"), "{:?}", last.details);
}

/// §5.3 — `fs.suid_dumpable = 2` is the safe, intended setting when core
/// dumps go to a pipe (apport, systemd-coredump): the kernel then never
/// writes a root-readable dump into the process's directory. Fixed in 0.13.1.
#[test]
fn suid_dumpable_2_with_a_core_pipe_is_not_flagged() {
    let mut sysctl = HashMap::new();
    sysctl.insert("fs.suid_dumpable".to_owned(), "2".to_owned());
    sysctl.insert(
        "kernel.core_pattern".to_owned(),
        "|/usr/share/apport/apport -p%p -s%s -c%c -d%d -P%P -u%u -g%g -F%F -- %E".to_owned(),
    );
    let env = warden_detect::tuning::Env {
        ram: 16 << 30,
        swap_total: 2 << 30,
        sysctl,
        thp: None,
        workloads: HashSet::new(),
        psi: true,
    };
    let keys: Vec<String> = warden_detect::tuning::advise(&env).into_iter().map(|a| a.key.to_string()).collect();
    assert!(!keys.iter().any(|k| k == "fs.suid_dumpable"), "{keys:?}");
}

/// §3.1 — ages and "next attempt in" shown in events, back-offs, schedules,
/// dedup windows and budgets must not shrink by the time the machine was
/// suspended: on a laptop the ages in the review log were 2 h 20 min short.
/// Since 0.13.3 they run on `warden_sys::clock`, which adds the suspend time
/// (CLOCK_BOOTTIME − CLOCK_MONOTONIC) to the monotonic clock; sustain and
/// hysteresis stay monotonic. (`tests/suspend.rs` simulates a suspend.)
#[test]
fn ages_in_events_are_measured_with_a_clock_that_runs_in_suspend() {
    // CLOCK_MONOTONIC (std::time::Instant) vs CLOCK_BOOTTIME: equal on a
    // machine that never slept; the difference is the total suspend time.
    let mut mono = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let mut boot = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    // SAFETY: valid out pointers.
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut mono);
        libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut boot);
    }
    let slept = Duration::new((boot.tv_sec - mono.tv_sec).max(0) as u64, 0);
    eprintln!("time spent in suspend since boot: {slept:?} (Instant-based ages would be short by this much)");
    assert!(boot.tv_sec >= mono.tv_sec);
    // the real clock is the monotonic one plus what this process slept
    warden_sys::clock::init();
    let (real, mono) = (warden_sys::clock::now(), Instant::now());
    assert!(real + Duration::from_millis(5) >= mono);
    assert!(real.saturating_duration_since(mono) <= warden_sys::clock::slept() + Duration::from_millis(5));
}
