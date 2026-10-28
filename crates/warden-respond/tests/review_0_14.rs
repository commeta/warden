//! Regression tests from the 0.14.1 review (N1): a flood of blocks must not
//! leave a compromise uncontained, and hooks must not use up the budget
//! containment needs.
#![allow(clippy::unwrap_used)]

use std::time::Duration;
use warden_core::{ActionSpec, Config, Event, ProcessRef, Severity, Subject};
use warden_respond::{Responder, Status};

fn block(ip: &str) -> Event {
    Event::new("security.waf_attack", Severity::Warning, "attacker")
        .subject(Subject::Ip { addr: ip.parse().unwrap() })
        .actions(vec![ActionSpec::BlockIp { ttl: Some(Duration::from_secs(60)) }])
}

fn hook(tag: &str) -> Event {
    Event::new("disk.space", Severity::Warning, tag).actions(vec![ActionSpec::Exec {
        program: "sh".into(),
        args: vec!["-c".into(), "true".into()],
        timeout: Some(Duration::from_secs(5)),
        user: None,
    }])
}

fn kill(child: &std::process::Child) -> Event {
    let pid = child.id() as i32;
    let st = warden_sys::process::start_time(pid).unwrap();
    Event::new("security.web_spawn", Severity::Critical, "shell")
        .subject(Subject::Process(ProcessRef {
            pid,
            start_time: st,
            comm: "sleep".into(),
            exe: None,
            cmdline: Some("sleep 30".into()),
            uid: None,
            user: None,
            ppid: None,
            cgroup: None,
            container: None,
        }))
        .actions(vec![ActionSpec::Kill { tree: false, grace: Some(Duration::from_millis(200)) }])
}

#[test]
fn blocks_have_a_budget_of_their_own_and_containment_a_reserve() {
    let mut cfg = Config::default();
    cfg.actions.cooldown = Duration::ZERO;
    cfg.actions.max_actions_per_hour = 4;
    cfg.actions.containment_reserve = 1;
    cfg.actions.firewall.max_blocks_per_hour = 3;
    // an nft table name nft rejects: every block is attempted and fails,
    // nothing touches the firewall of the machine running the test
    cfg.actions.firewall.table = "no such table!".into();
    let mut r = Responder::new(&cfg);
    let run = |r: &mut Responder, e: &Event| r.execute(e, false, &Default::default()).remove(0);

    // an attacker rotating addresses: blocks run until their own budget is used up...
    for i in 0..3 {
        let res = run(&mut r, &block(&format!("203.0.113.{}", i + 10)));
        assert_eq!(res.status, Status::Failed, "attempted: {}", res.message);
    }
    let res = run(&mut r, &block("203.0.113.99"));
    assert_eq!(res.status, Status::Refused);
    assert!(res.message.contains("max_blocks_per_hour"), "{}", res.message);

    // ...which leaves the shared budget alone; hooks get all of it but the reserve
    for i in 0..3 {
        let res = run(&mut r, &hook(&format!("h{i}")));
        assert_eq!(res.status, Status::Done, "{}", res.message);
    }
    let res = run(&mut r, &hook("one too many"));
    assert_eq!(res.status, Status::Refused);
    assert!(res.message.contains("containment_reserve"), "{}", res.message);

    // and the compromise is still contained
    let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
    let res = run(&mut r, &kill(&child));
    assert_eq!(res.status, Status::Done, "{}", res.message);
    let _ = child.wait();
    // now the hour is used up for everyone
    let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
    let res = run(&mut r, &kill(&child));
    assert_eq!(res.status, Status::Refused, "{}", res.message);
    assert!(res.message.contains("max_actions_per_hour ("), "{}", res.message);
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn the_reserve_is_at_most_a_quarter_of_the_budget() {
    let mut cfg = Config::default();
    cfg.actions.cooldown = Duration::ZERO;
    cfg.actions.max_actions_per_hour = 2; // reserve 20 configured, none applied
    let mut r = Responder::new(&cfg);
    for tag in ["a", "b"] {
        assert_eq!(r.execute(&hook(tag), false, &Default::default())[0].status, Status::Done);
    }
}

/// N5: a forged web-log line must not lock the administrator out. An
/// address with an established SSH session is not blocked on web evidence;
/// SSH evidence from the journal (a brute force that got in) still blocks.
#[test]
fn an_address_with_a_live_ssh_session_is_not_blocked_on_web_evidence() {
    use std::net::{TcpListener, TcpStream};
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let _client = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let (_server, _) = listener.accept().unwrap();

    let mut cfg = Config::default();
    cfg.actions.cooldown = Duration::ZERO;
    cfg.actions.firewall.ssh_ports = vec![port]; // the test's "sshd"
    cfg.actions.firewall.allowlist = vec![]; // 127.0.0.1 is the peer here
    cfg.actions.firewall.table = "no such table!".into(); // nothing reaches nft
    let mut r = Responder::new(&cfg);
    let mut web = block("127.0.0.1");
    web.source = "waf".into();
    let res = r.execute(&web, false, &Default::default()).remove(0);
    assert_eq!(res.status, Status::Refused, "{}", res.message);
    assert!(res.message.contains("protect_ssh_sessions"), "{}", res.message);

    let mut ssh = block("127.0.0.1").detail("log_source", "journal");
    ssh.source = "auth".into();
    let res = r.execute(&ssh, false, &Default::default()).remove(0);
    assert_ne!(res.status, Status::Refused, "journal SSH evidence is not held back: {}", res.message);

    cfg.actions.firewall.protect_ssh_sessions = false;
    r.reconfigure(&cfg);
    let res = r.execute(&web, false, &Default::default()).remove(0);
    assert_ne!(res.status, Status::Refused, "{}", res.message);
}
