//! Real-time windows count the time the machine was suspended
//! (`warden_sys::clock`). Alone in this binary: the simulated suspend is
//! process-wide.
#![allow(clippy::unwrap_used)]

use std::time::Duration;
use warden_core::{ActionSpec, Config, Event, Severity, Subject};
use warden_respond::{Responder, Status};

#[test]
fn a_cooldown_and_the_hourly_budget_run_on_while_the_machine_sleeps() {
    let mut cfg = Config::default(); // per-target cooldown 60 s
    cfg.actions.max_actions_per_hour = 2;
    let mut r = Responder::new(&cfg);
    let hook = |tag: &str| ActionSpec::Exec {
        program: "sh".into(),
        args: vec!["-c".into(), format!("echo {tag}")],
        timeout: Some(Duration::from_secs(5)),
        user: None,
    };
    let ev = |tag: &str| {
        Event::new("disk.space", Severity::Critical, "full")
            .subject(Subject::Mount { path: "/".into(), device: None })
            .actions(vec![hook(tag)])
    };
    let run = |r: &mut Responder, e: &Event| r.execute(e, false, &Default::default())[0].status;
    assert_eq!(run(&mut r, &ev("a")), Status::Done);
    assert_eq!(run(&mut r, &ev("a")), Status::Skipped, "cooling down");
    // the lid is closed for two minutes: the cooldown is over
    warden_sys::clock::simulate_suspend(Duration::from_secs(120));
    assert_eq!(run(&mut r, &ev("a")), Status::Done);
    // two actions this hour: the budget is used up...
    assert_eq!(run(&mut r, &ev("b")), Status::Refused);
    // ...until an hour has passed, asleep or not
    warden_sys::clock::simulate_suspend(Duration::from_secs(3600));
    assert_eq!(run(&mut r, &ev("b")), Status::Done);
}
