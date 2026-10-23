//! The systemd D-Bus sensor against a real `dbus-daemon` and a fake
//! `org.freedesktop.systemd1` built on the same client.
#![allow(clippy::unwrap_used)]

use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use warden_core::Event;
use warden_detect::runtime::{Shared, Sink};
use warden_sys::dbus::{Connection, Message, MsgType, Value, escape_path_component};

struct Bus {
    child: Child,
    address: String,
    _dir: tempfile::TempDir,
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_bus() -> Option<Bus> {
    let dir = tempfile::tempdir().unwrap();
    let sock = dir.path().join("bus");
    let conf = dir.path().join("bus.conf");
    std::fs::write(
        &conf,
        format!(
            r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>custom</type>
  <listen>unix:path={}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow user="*"/>
    <allow own="*"/>
    <allow send_destination="*"/>
    <allow receive_sender="*"/>
  </policy>
</busconfig>
"#,
            sock.display()
        ),
    )
    .unwrap();
    let child = Command::new("dbus-daemon")
        .arg(format!("--config-file={}", conf.display()))
        .arg("--nofork")
        .arg("--nopidfile")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let t = Instant::now();
    while !sock.exists() {
        if t.elapsed() > Duration::from_secs(5) {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    Some(Bus { child, address: format!("unix:path={}", sock.display()), _dir: dir })
}

fn unit_record(name: &str, active: &str) -> Value {
    Value::Struct(vec![
        Value::str(name),
        Value::str("test unit"),
        Value::str("loaded"),
        Value::str(active),
        Value::str(active),
        Value::str(""),
        Value::Path(format!("/org/freedesktop/systemd1/unit/{}", escape_path_component(name))),
        Value::U32(0),
        Value::str(""),
        Value::Path("/".into()),
    ])
}

fn properties_changed(unit: &str, state: &str) -> Message {
    Message::signal(
        &format!("/org/freedesktop/systemd1/unit/{}", escape_path_component(unit)),
        "org.freedesktop.DBus.Properties",
        "PropertiesChanged",
    )
    .with_body(
        "sa{sv}as",
        &[
            Value::str("org.freedesktop.systemd1.Unit"),
            Value::Array(
                "{sv}".into(),
                vec![
                    Value::Entry(
                        Box::new(Value::str("ActiveState")),
                        Box::new(Value::Variant(Box::new(Value::str(state)))),
                    ),
                    Value::Entry(
                        Box::new(Value::str("SubState")),
                        Box::new(Value::Variant(Box::new(Value::str(state)))),
                    ),
                ],
            ),
            Value::strings::<&str>(&[]),
        ],
    )
    .unwrap()
}

/// A fake systemd: owns the name, answers Subscribe/ListUnitsFiltered and
/// emits the signals the test asks for.
fn fake_systemd(
    address: String,
    units: Vec<(String, &'static str)>,
    signals: mpsc::Receiver<(String, String)>,
    ready: mpsc::Sender<()>,
) {
    let mut c = Connection::connect(&address).unwrap();
    c.hello().unwrap();
    let rn =
        Message::method_call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "RequestName")
            .with_body("su", &[Value::str("org.freedesktop.systemd1"), Value::U32(4)])
            .unwrap();
    let r = c.call(rn, Duration::from_secs(5)).unwrap();
    assert_eq!(r.args().unwrap(), vec![Value::U32(1)], "primary owner");
    ready.send(()).unwrap();
    loop {
        match signals.try_recv() {
            Ok((unit, state)) => {
                c.send(&properties_changed(&unit, &state)).unwrap();
            }
            Err(mpsc::TryRecvError::Disconnected) => return,
            Err(mpsc::TryRecvError::Empty) => {}
        }
        let Ok(Some(m)) = c.recv(Duration::from_millis(20)) else { continue };
        if m.kind != MsgType::MethodCall {
            continue;
        }
        let reply = match m.member.as_deref() {
            Some("Subscribe") => Message::method_return(&m),
            Some("ListUnitsFiltered") => {
                let args = m.args().unwrap();
                let wanted: Vec<&str> = args[0].items().iter().filter_map(Value::as_str).collect();
                let records =
                    units.iter().filter(|(_, s)| wanted.contains(s)).map(|(u, s)| unit_record(u, s)).collect();
                Message::method_return(&m)
                    .with_body("a(ssssssouso)", &[Value::Array("(ssssssouso)".into(), records)])
                    .unwrap()
            }
            _ => Message::error(&m, "org.freedesktop.DBus.Error.UnknownMethod", "not in the fake"),
        };
        c.send(&reply).unwrap();
    }
}

fn wait_for(events: &Arc<Mutex<Vec<Event>>>, title: &str) -> Event {
    let t = Instant::now();
    loop {
        if let Some(e) = events.lock().unwrap().iter().find(|e| e.title == title) {
            return e.clone();
        }
        assert!(t.elapsed() < Duration::from_secs(10), "no event {title:?}; got {:?}", titles(events));
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn titles(events: &Arc<Mutex<Vec<Event>>>) -> Vec<String> {
    events.lock().unwrap().iter().map(|e| e.title.clone()).collect()
}

#[test]
fn unit_failures_arrive_over_dbus() {
    let Some(bus) = start_bus() else {
        eprintln!("dbus-daemon not available; skipping");
        return;
    };
    let (sig_tx, sig_rx) = mpsc::channel();
    let (ready_tx, ready_rx) = mpsc::channel();
    let addr = bus.address.clone();
    let fake = std::thread::spawn(move || {
        fake_systemd(
            addr,
            vec![("cron.service".into(), "failed"), ("apt-daily.service".into(), "activating")],
            sig_rx,
            ready_tx,
        )
    });
    ready_rx.recv_timeout(Duration::from_secs(5)).unwrap();

    // libdbus reads what our marshaller wrote.
    if let Ok(o) = Command::new("dbus-send")
        .args([&format!("--bus={}", bus.address), "--print-reply", "--dest=org.freedesktop.systemd1"])
        .args([
            "/org/freedesktop/systemd1",
            "org.freedesktop.systemd1.Manager.ListUnitsFiltered",
            "array:string:failed",
        ])
        .output()
    {
        let out = String::from_utf8_lossy(&o.stdout);
        assert!(o.status.success() && out.contains("\"cron.service\"") && out.contains("cron_2eservice"), "{out}");
    }

    let mut cfg = warden_core::Config::default();
    cfg.systemd.ignore = vec!["ignored-*.service".into()];
    let shared = Shared::new(cfg);
    let (sink, events) = Sink::collector();
    let (sh, addr) = (shared.clone(), bus.address.clone());
    let sensor = std::thread::spawn(move || warden_detect::systemd::watch_units(&sh, &sink, &addr));

    let start = wait_for(&events, "unit cron.service failed");
    assert_eq!(start.details["already_failed_at_start"], true);
    // the reconciliation also lists units that are starting; they are not failed
    assert!(!titles(&events).iter().any(|t| t.contains("apt-daily")), "{:?}", titles(&events));
    assert_eq!(start.details["detected_by"], "dbus");
    let t = Instant::now();
    while !shared.sensor_running("systemd_dbus") {
        assert!(t.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(5));
    }

    // A unit fails: reported at once, not at the next poll.
    let t = Instant::now();
    sig_tx.send(("nginx.service".into(), "failed".into())).unwrap();
    let ev = wait_for(&events, "unit nginx.service failed");
    eprintln!("unit failure reported after {:?}", t.elapsed());
    assert!(t.elapsed() < Duration::from_secs(3), "took {:?}", t.elapsed());
    assert_eq!(ev.details["already_failed_at_start"], false);
    sig_tx.send(("ignored-x.service".into(), "failed".into())).unwrap();
    sig_tx.send(("nginx.service".into(), "activating".into())).unwrap();
    sig_tx.send(("nginx.service".into(), "active".into())).unwrap();
    wait_for(&events, "unit nginx.service recovered");

    // Anyone can emit a PropertiesChanged signal; only systemd's are routed.
    let mut evil = Connection::connect(&bus.address).unwrap();
    evil.hello().unwrap();
    evil.send(&properties_changed("sshd.service", "failed")).unwrap();
    // ... and a signal addressed straight to us skips the match rules, so the
    // sender is checked as well: try every connection on the bus.
    let names = evil
        .call(
            Message::method_call("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "ListNames"),
            Duration::from_secs(5),
        )
        .unwrap();
    let mut aimed = 0;
    for n in names.args().unwrap()[0].items().iter().filter_map(Value::as_str).filter(|n| n.starts_with(':')) {
        let mut m = properties_changed("sshd.service", "failed");
        m.destination = Some(n.to_owned());
        evil.send(&m).unwrap();
        aimed += 1;
    }
    assert!(aimed >= 3, "expected the sensor, the fake systemd and ourselves on the bus");
    sig_tx.send(("php8.3-fpm.service".into(), "failed".into())).unwrap();
    wait_for(&events, "unit php8.3-fpm.service failed");
    let all = titles(&events);
    assert!(!all.iter().any(|t| t.contains("sshd") || t.contains("ignored")), "{all:?}");

    shared.begin_shutdown();
    let r = sensor.join().unwrap();
    assert!(r.is_err(), "the watcher returns when the daemon stops");
    drop(sig_tx);
    fake.join().unwrap();
}

#[test]
fn a_dead_bus_is_an_error_not_a_hang() {
    let shared = Shared::new(warden_core::Config::default());
    let (sink, _events) = Sink::collector();
    let r = warden_detect::systemd::watch_units(&shared, &sink, "unix:path=/nonexistent/bus");
    assert!(r.unwrap_err().contains("D-Bus"));
}
