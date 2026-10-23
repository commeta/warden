//! Schedules count the time the machine was suspended (`warden_sys::clock`).
//! Alone in this binary: the simulated suspend is process-wide.
#![allow(clippy::unwrap_used)]

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, Instant};
use warden_detect::runtime::{Cx, Detector, Shared, Sink, lock};

#[test]
fn a_daily_suid_walk_is_due_after_a_day_even_if_the_machine_slept_through_it() {
    // nothing here waits for a quiet disk
    warden_sys::pace::configure(warden_sys::pace::Params { enabled: false, ..Default::default() });
    let d = tempfile::tempdir().unwrap();
    let root = d.path().join("root");
    std::fs::create_dir(&root).unwrap();
    let mut cfg = warden_core::Config::default();
    cfg.daemon.state_dir = d.path().join("state");
    cfg.integrity.files = vec![];
    cfg.integrity.listeners = false;
    cfg.integrity.suid_realtime = false;
    cfg.integrity.suid_paths = vec![root.to_string_lossy().into_owned()];
    cfg.integrity.suid_delay = Duration::ZERO;
    cfg.integrity.suid_interval = Duration::from_secs(24 * 3600);
    let shared = Shared::new(cfg.clone());
    let (sink, events) = Sink::collector();
    let mut det = warden_detect::integrity::IntegrityDetector::new(&cfg);
    // tick until the walk in flight has been collected
    let settle = |det: &mut warden_detect::integrity::IntegrityDetector| {
        let t = Instant::now();
        loop {
            det.tick(&mut Cx::new(&shared, &cfg, &sink, "integrity"));
            std::thread::sleep(Duration::from_millis(50));
            det.tick(&mut Cx::new(&shared, &cfg, &sink, "integrity"));
            if det.interval() > Duration::from_secs(2) || t.elapsed() > Duration::from_secs(10) {
                break;
            }
        }
    };
    settle(&mut det); // the first baseline
    let new_suid = || lock(&events).iter().filter(|e| e.kind == "security.new_suid").count();
    let f = root.join("rootme");
    std::fs::write(&f, "x").unwrap();
    std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o4755)).unwrap();
    settle(&mut det);
    assert_eq!(new_suid(), 0, "the next walk is a day away");
    // overnight: 25 hours with the lid closed
    warden_sys::clock::simulate_suspend(Duration::from_secs(25 * 3600));
    settle(&mut det);
    assert_eq!(new_suid(), 1, "a day has passed: the walk ran and found it");
}
