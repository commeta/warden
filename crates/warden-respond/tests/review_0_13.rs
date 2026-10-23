//! Regression tests from the 0.13.0 review (docs/reviews/audit-0.13.0.ru.md).
//! They state the intended behaviour; they failed on 0.13.0 and pass since 0.13.1.
#![allow(clippy::unwrap_used)]

use std::time::Duration;
use warden_core::{ActionSpec, Config, Event, Severity, Subject};
use warden_respond::{Responder, Status};

fn hook(tag: &str) -> ActionSpec {
    ActionSpec::Exec {
        program: "sh".into(),
        args: vec!["-c".into(), format!("echo {tag}")],
        timeout: Some(Duration::from_secs(5)),
        user: None,
    }
}

/// §2.3 — what dry-run *would* have done must not arm the per-target
/// cooldown: after `wardenctl dry-run off` the first real occurrence has to
/// be acted on, not skipped as "ran recently".
#[test]
fn a_dry_run_does_not_start_the_cooldown_of_the_real_action() {
    let mut r = Responder::new(&Config::default());
    let ev = Event::new("disk.space", Severity::Critical, "full")
        .subject(Subject::Mount { path: "/".into(), device: None })
        .actions(vec![hook("cleanup")]);
    let dry = r.execute(&ev, true, &Default::default());
    assert_eq!(dry[0].status, Status::DryRun);
    // the operator switches remediation on a minute later
    let real = r.execute(&ev, false, &Default::default());
    assert_eq!(real[0].status, Status::Done, "{}", real[0].message);
}

/// §2.3 — an action refused by the circuit breaker did not run either: it
/// must not hold the cooldown for the next attempt.
#[test]
fn a_refused_action_does_not_start_the_cooldown() {
    let mut cfg = Config::default();
    cfg.actions.max_actions_per_hour = 1;
    let mut r = Responder::new(&cfg);
    let first = Event::new("t", Severity::Warning, "a").actions(vec![hook("a")]);
    assert_eq!(r.execute(&first, false, &Default::default())[0].status, Status::Done);
    let second = Event::new("t", Severity::Warning, "b").actions(vec![hook("b")]);
    assert_eq!(r.execute(&second, false, &Default::default())[0].status, Status::Refused);
    // budget raised by a reload: the refused step is not "recent"
    let mut cfg = Config::default();
    cfg.actions.max_actions_per_hour = 10;
    r.reconfigure(&cfg);
    let res = r.execute(&second, false, &Default::default());
    assert_eq!(res[0].status, Status::Done, "{}", res[0].message);
}
