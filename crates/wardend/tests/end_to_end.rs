//! End-to-end test: start the real `wardend` binary against a sandboxed
//! configuration, trigger incidents, and assert the daemon detects and
//! remediates them. Requires root (CI runs the test suite with sudo); it
//! skips itself cleanly otherwise.
#![allow(clippy::unwrap_used)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use warden_sys::sched::is_root;

fn bin(name: &str) -> PathBuf {
    // target/debug/deps/<test> → target/debug/<bin>
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    if p.ends_with("deps") {
        p.pop();
    }
    p.join(name)
}

struct Daemon {
    child: Child,
    socket: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn request(socket: &Path, req: &str) -> serde_json::Value {
    let mut s = UnixStream::connect(socket).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    s.write_all(format!("{req}\n").as_bytes()).unwrap();
    let mut line = String::new();
    BufReader::new(s).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

/// fanotify filesystem marks in file-handle mode (Linux 5.9+).
fn realtime_suid_supported() -> bool {
    warden_sys::fanotify_fid::FidWatcher::new()
        .and_then(|mut w| w.watch_filesystem(Path::new("/tmp"), libc::FAN_ATTRIB))
        .is_ok()
}

fn wait_for<F: FnMut() -> bool>(timeout: Duration, mut f: F) -> bool {
    let end = Instant::now() + timeout;
    while Instant::now() < end {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

#[test]
fn daemon_detects_and_remediates() {
    if !is_root() {
        eprintln!("skipping end-to-end test: not running as root");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    for sub in ["www/uploads", "oldlogs", "state", "run", "suidroot", "out"] {
        std::fs::create_dir_all(d.join(sub)).unwrap();
    }
    {
        // hooks and notification commands run as `nobody` (daemon.command_user):
        // they may traverse the test directory and write into out/
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o711)).unwrap();
        std::fs::set_permissions(d.join("out"), std::fs::Permissions::from_mode(0o777)).unwrap();
    }
    std::fs::write(d.join("www/index.php"), "<?php echo 'home';").unwrap();
    std::fs::write(d.join("auth.log"), "").unwrap();
    std::fs::write(d.join("modsec_error.log"), "").unwrap();
    // a port nobody listens on, for the failing health check
    let dead_port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    for i in 0..3 {
        let f = d.join(format!("oldlogs/app.{i}.gz"));
        std::fs::write(&f, vec![0u8; 4096]).unwrap();
        let old = std::time::SystemTime::now() - Duration::from_secs(3 * 86400);
        std::fs::File::options().write(true).open(&f).unwrap().set_modified(old).unwrap();
    }

    let socket = d.join("run/control.sock");
    let cfg = d.join("warden.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"
[daemon]
dry_run = false
state_dir = "{d}/state"
runtime_dir = "{d}/run"
control_socket = "{sock}"
mlock = false
log_level = "warn"
command_user = "nobody"

[metrics]
enabled = false

[[notify.command]]
program = "sh"
args = ["-c", "id -u >> {d}/out/notify.log; printenv WARDEN_EVENT_JSON >> {d}/out/notify.log"]

[events]
path = "{d}/events.jsonl"

[actions]
quarantine_dir = "{d}/state/quarantine"
snapshot_dir = "{d}/state/snapshots"

[memory]
enabled = false
[cpu]
enabled = false
[io]
enabled = false
[network]
enabled = false
[hardware]
enabled = false
[limits]
enabled = false
[systemd]
enabled = false
[integrity]
enabled = true
files = []
listeners = false
suid_paths = ["{d}/suidroot"]
suid_exclude = []
suid_delay = "1s"
interval = "1h"

[waf]
block_after = 2
block = false

[[waf.log]]
path = "{d}/modsec_error.log"
site = "demo"

[[health.check]]
name = "backend"
type = "tcp"
address = "127.0.0.1:{dead_port}"
interval = "1s"
timeout = "300ms"
failures = 2
actions = ["snapshot", {{ do = "exec", program = "sh", args = ["-c", "id -u > {d}/out/hook.uid"] }}]

[[process.limit]]
name = "long sleeper"
comm = ["sleep"]
max_runtime = "1s"
actions = ["throttle"]

[disk]
enabled = true
interval = "2s"
warning_percent = 0.1
cleanup_at = "warning"
cleanup_target_percent = 0.0
cleanup = [ {{ do = "delete_old", paths = ["{d}/oldlogs/*.gz"], older_than = "1d" }} ]

[auth]
enabled = true
source = "file"
auth_log = "{d}/auth.log"
ssh_max_failures = 3
ssh_block = false

[process]
enabled = true
scan_interval = "2s"

[fim]
enabled = true
scan_on_start = true
block_attackers = false
kill_writer = false

[[fim.site]]
name = "demo"
root = "{d}/www"
"#,
            d = d.display(),
            sock = socket.display(),
            dead_port = dead_port,
        ),
    )
    .unwrap();

    let wardend = bin("wardend");
    assert!(wardend.exists(), "wardend binary not found at {}", wardend.display());
    let child = Command::new(&wardend).arg("--config").arg(&cfg).env("WARDEN_LOG", "warn").spawn().unwrap();
    let daemon = Daemon { child, socket: socket.clone() };

    assert!(wait_for(Duration::from_secs(15), || UnixStream::connect(&daemon.socket).is_ok()), "daemon never came up");
    let pong = request(&daemon.socket, r#"{"cmd":"ping"}"#);
    assert_eq!(pong["data"], "pong");

    // (1) disk cleanup deletes the old gzip logs
    assert!(
        wait_for(Duration::from_secs(10), || std::fs::read_dir(d.join("oldlogs")).unwrap().count() == 0),
        "disk cleanup did not remove old logs"
    );

    // (2) SSH brute force raises an event
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(d.join("auth.log")).unwrap();
        for i in 0..3 {
            writeln!(
                f,
                "Oct 20 12:00:0{i} host sshd[9]: Failed password for invalid user bob from 192.0.2.99 port 2{i} ssh2"
            )
            .unwrap();
        }
    }

    // (2b) ModSecurity blocks the same client twice (nginx error-log format)
    {
        let mut f = std::fs::OpenOptions::new().append(true).open(d.join("modsec_error.log")).unwrap();
        for i in 0..2 {
            writeln!(
                f,
                "2026/10/20 12:00:0{i} [error] 1#1: *{i} [client 198.51.100.4] ModSecurity: Access denied with code 403 (phase 2). [id \"942100\"] [msg \"SQL Injection Attack Detected via libinjection\"] [severity \"2\"] [uri \"/\"] [unique_id \"u{i}\"], client: 198.51.100.4, server: x"
            )
            .unwrap();
        }
    }

    // (2c) a process exceeds a [[process.limit]] rule and gets throttled
    //      (its command line carries a password: notifications must not)
    let mut sleeper = {
        use std::os::unix::process::CommandExt;
        Command::new("sleep").arg0("mysql -pTOPSECRET").arg("60").spawn().unwrap()
    };

    // (2d) real-time SUID: once the baseline exists, `chmod u+s` is reported
    //      without waiting for a walk
    assert!(
        wait_for(Duration::from_secs(15), || {
            let r = request(&daemon.socket, r#"{"cmd":"events","limit":500}"#);
            r["data"].as_array().unwrap().iter().any(|e| e["kind"] == "integrity.suid_baseline")
        }),
        "SUID baseline was not created"
    );
    let rootme = d.join("suidroot/rootme");
    std::fs::write(&rootme, "#!/bin/sh\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&rootme, std::fs::Permissions::from_mode(0o4755)).unwrap();
    }

    // (3) a webshell appears in the uploads directory
    std::fs::write(d.join("www/uploads/x.php"), "<?php @eval(base64_decode($_POST['c'])); ?>").unwrap();

    let found = wait_for(Duration::from_secs(30), || {
        let r = request(&daemon.socket, r#"{"cmd":"events","limit":500}"#);
        let kinds: Vec<&str> = r["data"].as_array().unwrap().iter().filter_map(|e| e["kind"].as_str()).collect();
        kinds.contains(&"security.ssh_bruteforce")
            && kinds.contains(&"security.webshell")
            && kinds.contains(&"security.waf_attack")
            && kinds.contains(&"health.down")
            && kinds.contains(&"action.throttle")
            && (kinds.contains(&"security.new_suid") || !realtime_suid_supported())
            && kinds.iter().any(|k| k.starts_with("action."))
    });
    let events = request(&daemon.socket, r#"{"cmd":"events","limit":500}"#);
    let kinds: Vec<String> =
        events["data"].as_array().unwrap().iter().filter_map(|e| e["kind"].as_str().map(str::to_owned)).collect();
    assert!(found, "expected events not seen; got: {kinds:?}");
    // the throttle really lowered the sleeper's priority (the scanner runs
    // every 2 s; other `sleep` processes on the host may be throttled first)
    let pid = sleeper.id();
    let niced = wait_for(Duration::from_secs(15), || {
        let st = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        st.rsplit(')').next().and_then(|r| r.split_whitespace().nth(16)).and_then(|n| n.parse::<i64>().ok()) == Some(19)
    });
    assert!(niced, "process.limit throttle did not renice the process");
    let _ = sleeper.kill();
    let _ = sleeper.wait();

    if realtime_suid_supported() {
        let ev = events["data"].as_array().unwrap().iter().find(|e| e["kind"] == "security.new_suid").cloned();
        let ev = ev.expect("new SUID file not reported");
        assert_eq!(ev["details"]["detected_by"], "real time (fanotify)", "{ev}");
        assert_eq!(ev["severity"], "critical", "SUID file under /tmp");
    }

    // the webshell was quarantined (default quarantine_score reached)
    assert!(wait_for(Duration::from_secs(5), || !d.join("www/uploads/x.php").exists()), "webshell was not quarantined");
    let q = request(&daemon.socket, r#"{"cmd":"quarantine_list"}"#);
    assert_eq!(q["data"].as_array().unwrap().len(), 1);

    // hooks and notification commands ran as nobody; the password stayed home
    let nobody = warden_sys::cmd::Credentials::lookup("nobody").unwrap().uid.to_string();
    assert!(
        wait_for(Duration::from_secs(10), || std::fs::read_to_string(d.join("out/hook.uid"))
            .is_ok_and(|s| s.trim() == nobody)),
        "the health.down exec hook did not run as nobody"
    );
    let notified = std::fs::read_to_string(d.join("out/notify.log")).unwrap_or_default();
    assert!(notified.lines().any(|l| l == nobody), "notification command not run as nobody: {notified}");
    assert!(!notified.contains("TOPSECRET"), "a secret left the host: {notified}");
    let journal = std::fs::read_to_string(d.join("events.jsonl")).unwrap_or_default();
    let with_secret: Vec<&str> = journal.lines().filter(|l| l.contains("TOPSECRET")).collect();
    assert!(
        with_secret.is_empty() || notified.contains("mysql -p***"),
        "journal: {with_secret:#?}\nnotified: {notified}"
    );

    // status and persisted journal
    let status = request(&daemon.socket, r#"{"cmd":"status"}"#);
    assert_eq!(status["data"]["version"], env!("CARGO_PKG_VERSION"));
    assert!(d.join("events.jsonl").exists());

    // self-profile: modules disabled in the configuration have no thread
    let p = request(&daemon.socket, r#"{"cmd":"profile"}"#);
    assert_eq!(p["ok"], true, "{p}");
    let threads: Vec<&str> =
        p["data"]["threads"].as_array().unwrap().iter().filter_map(|t| t["name"].as_str()).collect();
    for absent in ["w-psi_trigger", "w-access_log"] {
        assert!(!threads.contains(&absent), "{absent} runs although disabled: {threads:?}");
    }
    for present in ["w-sched-fast", "w-sched-slow", "w-fim", "w-auth", "w-waf"] {
        assert!(threads.contains(&present), "{present} missing: {threads:?}");
    }
    assert_eq!(p["data"]["heap_tracking"], true);
    let modules = p["data"]["modules"].as_object().unwrap();
    assert!(modules.contains_key("disk") && modules.contains_key("process"), "{modules:?}");
    let heap: Vec<&str> = p["data"]["heap"].as_array().unwrap().iter().filter_map(|h| h["scope"].as_str()).collect();
    assert!(heap.contains(&"fim") && heap.contains(&"engine"), "{heap:?}");

    // a reload that disables a module stops its thread
    let cfg_text = std::fs::read_to_string(&cfg).unwrap().replace("[waf]\n", "[waf]\nenabled = false\n");
    std::fs::write(&cfg, cfg_text).unwrap();
    request(&daemon.socket, r#"{"cmd":"reload"}"#);
    assert!(
        wait_for(Duration::from_secs(10), || {
            let p = request(&daemon.socket, r#"{"cmd":"profile"}"#);
            !p["data"]["threads"].as_array().unwrap().iter().any(|t| t["name"] == "w-waf")
        }),
        "waf thread still running after it was disabled"
    );

    // a runtime dry-run override survives a reload (0.13.3 put the
    // configuration's value back on every SIGHUP, without an event)
    let reloads = || {
        let ev = request(&daemon.socket, r#"{"cmd":"events","limit":5000}"#);
        ev["data"].as_array().unwrap().iter().filter(|e| e["kind"] == "warden.reloaded").count()
    };
    let before = reloads();
    let r = request(&daemon.socket, r#"{"cmd":"set_dry_run","enabled":true}"#);
    assert_eq!((r["data"]["dry_run"].as_bool(), r["data"]["source"].as_str()), (Some(true), Some("override")), "{r}");
    assert!(d.join("state/dry-run.json").exists());
    request(&daemon.socket, r#"{"cmd":"reload"}"#);
    assert!(wait_for(Duration::from_secs(10), || reloads() > before), "reload not done");
    let st = request(&daemon.socket, r#"{"cmd":"status"}"#);
    assert_eq!(st["data"]["dry_run"], true, "the override was lost on reload");
    assert_eq!(st["data"]["dry_run_source"], "override");
    let ev = request(&daemon.socket, r#"{"cmd":"events","limit":5000}"#);
    let changes: Vec<&serde_json::Value> =
        ev["data"].as_array().unwrap().iter().filter(|e| e["kind"] == "warden.dry_run").collect();
    assert_eq!(changes.len(), 1, "{changes:?}");
    assert_eq!(changes[0]["details"]["source"], "override");
    // reset: back to the configuration (dry_run = false)
    let r = request(&daemon.socket, r#"{"cmd":"set_dry_run"}"#);
    assert_eq!((r["data"]["dry_run"].as_bool(), r["data"]["source"].as_str()), (Some(false), Some("config")), "{r}");
    assert!(!d.join("state/dry-run.json").exists());
}

fn http_get(port: u16, path: &str) -> std::io::Result<String> {
    use std::io::Read;
    let mut s = std::net::TcpStream::connect(("127.0.0.1", port))?;
    s.set_read_timeout(Some(Duration::from_secs(10)))?;
    write!(s, "GET {path} HTTP/1.1\r\nHost: x\r\n\r\n")?;
    let mut out = String::new();
    s.read_to_string(&mut out)?;
    Ok(out)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// While the action executor is busy with a long action, the control
/// socket, the health endpoint and the daemon's own shutdown must not wait
/// for it. (They used to: operator commands took the executor's lock on the
/// daemon's only async thread, which stopped `/health` and the watchdog
/// pings with it.)
#[test]
fn a_busy_executor_does_not_stall_control_health_or_shutdown() {
    if !is_root() {
        eprintln!("skipping end-to-end test: not running as root");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();
    std::fs::create_dir_all(d.join("run")).unwrap();
    let (dead_port, metrics_port) = (free_port(), free_port());
    let socket = d.join("run/control.sock");
    let cfg = d.join("warden.toml");
    std::fs::write(
        &cfg,
        format!(
            r#"
[daemon]
dry_run = false
state_dir = "{d}/state"
runtime_dir = "{d}/run"
control_socket = "{sock}"
mlock = false
log_level = "warn"

[metrics]
listen = "127.0.0.1:{metrics_port}"

[events]
path = "{d}/events.jsonl"

[actions]
quarantine_dir = "{d}/state/quarantine"
snapshot_dir = "{d}/state/snapshots"

[memory]
enabled = false
[cpu]
enabled = false
[io]
enabled = false
[network]
enabled = false
[hardware]
enabled = false
[limits]
enabled = false
[systemd]
enabled = false
[disk]
enabled = false
[integrity]
enabled = false
[auth]
enabled = false
[process]
enabled = false
[fim]
enabled = false

# a failing check whose remedy is a 20-second hook: the executor is busy
[[health.check]]
name = "backend"
type = "tcp"
address = "127.0.0.1:{dead_port}"
interval = "1s"
timeout = "300ms"
failures = 1
actions = [ {{ do = "exec", program = "sleep", args = ["20"], timeout = "30s" }} ]
"#,
            d = d.display(),
            sock = socket.display(),
        ),
    )
    .unwrap();

    let child = Command::new(bin("wardend")).arg("--config").arg(&cfg).env("WARDEN_LOG", "warn").spawn().unwrap();
    let mut daemon = Daemon { child, socket: socket.clone() };
    assert!(wait_for(Duration::from_secs(15), || UnixStream::connect(&daemon.socket).is_ok()), "daemon never came up");
    assert!(
        wait_for(Duration::from_secs(15), || {
            let r = request(&daemon.socket, r#"{"cmd":"events","limit":500}"#);
            r["data"].as_array().unwrap().iter().any(|e| e["kind"] == "health.down")
        }),
        "the failing check did not raise health.down"
    );
    std::thread::sleep(Duration::from_millis(1500)); // the hook is running now

    // every operator command answers promptly although the executor is busy
    for cmd in [r#"{"cmd":"quarantine_list"}"#, r#"{"cmd":"tuning"}"#, r#"{"cmd":"status"}"#, r#"{"cmd":"ping"}"#] {
        let t = Instant::now();
        let r = request(&daemon.socket, cmd);
        assert_eq!(r["ok"], true, "{cmd}: {r}");
        assert!(t.elapsed() < Duration::from_secs(2), "{cmd} took {:?} while the executor was busy", t.elapsed());
    }
    let t = Instant::now();
    let health = http_get(metrics_port, "/health").unwrap();
    assert!(health.starts_with("HTTP/1.1 200"), "{health}");
    assert!(t.elapsed() < Duration::from_secs(2), "/health took {:?}", t.elapsed());

    // a pile of idle connections cannot take the endpoint down
    let idle: Vec<_> =
        (0..200).filter_map(|_| std::net::TcpStream::connect(("127.0.0.1", metrics_port)).ok()).collect();
    drop(idle);
    assert!(
        wait_for(Duration::from_secs(15), || http_get(metrics_port, "/health")
            .is_ok_and(|r| r.starts_with("HTTP/1.1 200"))),
        "/health did not recover after a connection flood"
    );

    // SIGTERM: the daemon does not wait for the 20-second hook. It waits up
    // to its 5 s grace for the busy executor, then exits. An instrumented
    // build (cargo llvm-cov sets LLVM_PROFILE_FILE, which the daemon
    // inherits) also writes its profile on exit, which took seconds more under
    // load: allow for it there, not in a normal run.
    let slack = if std::env::var_os("LLVM_PROFILE_FILE").is_some() { 15 } else { 0 };
    // SAFETY: plain signal to our own child.
    unsafe { libc::kill(daemon.child.id() as i32, libc::SIGTERM) };
    let t = Instant::now();
    let exited = wait_for(Duration::from_secs(12 + slack), || daemon.child.try_wait().ok().flatten().is_some());
    assert!(exited, "the daemon did not stop within {} s of SIGTERM", 12 + slack);
    assert!(t.elapsed() < Duration::from_secs(10 + slack), "stop took {:?}", t.elapsed());
}
