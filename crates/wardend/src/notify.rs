//! Outbound notifications: webhooks (JSON / Slack-compatible), Telegram and
//! arbitrary commands (mail, PagerDuty CLIs...). Runs in its own thread so
//! a slow endpoint never delays detection or remediation.

use std::collections::HashMap;
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};
use warden_core::config::{NotifyConfig, WebhookFormat};
use warden_core::ratelimit::SlidingWindow;
use warden_core::{Event, Severity};
use warden_detect::Shared;

/// Render an event as plain text for chat channels.
pub fn render_text(ev: &Event, host: &str) -> String {
    let mut s = format!(
        "{} [{host}] {}{} {}\n{}\nSubject: {}",
        ev.severity.emoji(),
        ev.severity.as_str().to_uppercase(),
        if ev.resolved { " (resolved)" } else { "" },
        ev.kind,
        ev.title,
        ev.subject
    );
    for (k, v) in ev.details.iter().take(8) {
        let val = match v {
            serde_json::Value::String(x) => x.clone(),
            other => other.to_string(),
        };
        let val: String = val.chars().take(300).collect();
        s.push_str(&format!("\n• {k}: {val}"));
    }
    if !ev.actions.is_empty() {
        let a: Vec<&str> = ev.actions.iter().map(|a| a.name()).collect();
        s.push_str(&format!("\nActions: {}", a.join(", ")));
    }
    s.push_str(&format!("\n{}", ev.time()));
    s
}

struct Notifier {
    agent: ureq::Agent,
    last: HashMap<String, (Instant, Severity)>,
    window: SlidingWindow,
    suppressed: u64,
    /// Conditions that were notified and not yet resolved, per channel
    /// ("" = passed the global filters): a resolution goes only where its
    /// condition went. (0.13.3 sent every resolution: a workstation with
    /// `min_severity = "critical"` got "cpu.pressure resolved" for warnings
    /// it never saw.)
    notified: HashMap<String, Notified>,
}

/// Fingerprints notified on one channel, with when (for the GC).
#[derive(Default)]
struct Notified(HashMap<String, Instant>);

/// Notified conditions older than this are forgotten (a resolution after a
/// week is not worth a message either way).
const NOTIFIED_TTL: Duration = Duration::from_secs(7 * 24 * 3600);

impl Notified {
    /// Should `ev` go to this channel (whose own minimum is `min`)? A
    /// condition is remembered; a resolution passes only if it closes
    /// something remembered, and forgets it.
    fn pass(&mut self, min: Option<Severity>, ev: &Event, now: Instant) -> bool {
        if let Some(cond) = ev.fingerprint.strip_suffix(":resolved") {
            let before = self.0.len();
            self.0.retain(|k, _| !(k == cond || k.strip_prefix(cond).is_some_and(|r| r.starts_with(':'))));
            return self.0.len() < before;
        }
        if min.is_some_and(|m| ev.severity < m) {
            return false;
        }
        self.0.insert(ev.fingerprint.clone(), now);
        if self.0.len() > 10_000 {
            self.0.retain(|_, t| now.saturating_duration_since(*t) < NOTIFIED_TTL);
        }
        true
    }
}

impl Notifier {
    fn new(cfg: &NotifyConfig) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(15)))
            .user_agent(concat!("warden/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Self {
            agent,
            last: HashMap::new(),
            window: SlidingWindow::new(Duration::from_secs(3600), cfg.max_per_hour),
            suppressed: 0,
            notified: HashMap::new(),
        }
    }

    /// The per-channel filter (see [`Notified`]).
    fn channel(&mut self, name: &str, min: Option<Severity>, ev: &Event) -> bool {
        let now = warden_sys::clock::now();
        self.notified.entry(name.to_owned()).or_default().pass(min, ev, now)
    }

    fn wanted(&mut self, cfg: &NotifyConfig, ev: &Event) -> bool {
        if ev.resolved && !cfg.include_resolved {
            return false;
        }
        if !ev.resolved && ev.severity < cfg.min_severity {
            return false;
        }
        // windows and the hourly budget in real time (see `warden_sys::clock`)
        let now = warden_sys::clock::now();
        if let Some((t, sev)) = self.last.get(&ev.fingerprint)
            && now.saturating_duration_since(*t) < cfg.dedup_window
            && ev.severity <= *sev
        {
            return false;
        }
        // A resolution only for a condition that was notified.
        if ev.resolved && !self.would_resolve("", ev) {
            return false;
        }
        // Emergencies always go out; everything else is rate limited.
        if ev.severity < Severity::Emergency && !self.window.allow(now) {
            self.suppressed += 1;
            return false;
        }
        self.channel("", None, ev);
        self.last.insert(ev.fingerprint.clone(), (now, ev.severity));
        // the condition came back after its resolution (or cleared again):
        // a new episode, not a repeat
        warden_core::event::end_episodes(&mut self.last, &ev.fingerprint);
        if self.last.len() > 10_000 {
            let w = cfg.dedup_window;
            self.last.retain(|_, (t, _)| now.saturating_duration_since(*t) < w);
        }
        true
    }

    /// Would `ev`, a resolution, close something notified on `channel`?
    fn would_resolve(&self, channel: &str, ev: &Event) -> bool {
        let Some(cond) = ev.fingerprint.strip_suffix(":resolved") else { return true };
        self.notified
            .get(channel)
            .is_some_and(|n| n.0.keys().any(|k| k == cond || k.strip_prefix(cond).is_some_and(|r| r.starts_with(':'))))
    }

    fn send(&mut self, cfg: &NotifyConfig, original: &Event, shared: &Shared) {
        let host = &shared.hostname;
        // channel filters decide on the event as recorded; what is sent is
        // the event as `notify.details` allows (secrets masked by default)
        let ev = original;
        let out = warden_core::redact::event(original, cfg.details);
        let mut text = render_text(&out, host);
        if self.suppressed > 0 {
            text.push_str(&format!("\n({} notifications suppressed by rate limit)", self.suppressed));
            self.suppressed = 0;
        }
        for w in &cfg.webhook {
            if !self.channel(&format!("webhook:{}", w.name), w.min_severity, ev) {
                continue;
            }
            let body = match w.format {
                WebhookFormat::Json => {
                    let mut v = serde_json::to_value(&*out).unwrap_or_default();
                    if let Some(o) = v.as_object_mut() {
                        o.insert("host".into(), host.clone().into());
                        o.insert("time".into(), ev.time().into());
                        o.insert("text".into(), text.clone().into());
                    }
                    v
                }
                WebhookFormat::Slack => serde_json::json!({ "text": text }),
            };
            let mut req = self.agent.post(&w.url).config().timeout_global(Some(w.timeout)).build();
            for (k, v) in &w.headers {
                req = req.header(k, v);
            }
            let r = req.send_json(&body);
            record(shared, &format!("webhook:{}", w.name), r.map(|_| ()).map_err(|e| e.to_string()));
        }
        if let Some(t) = &cfg.telegram
            && self.channel("telegram", t.min_severity, ev)
        {
            let url = format!("{}/bot{}/sendMessage", t.api_url.trim_end_matches('/'), t.bot_token);
            let body = serde_json::json!({"chat_id": t.chat_id, "text": text.chars().take(4000).collect::<String>(), "disable_web_page_preview": true});
            let r = self.agent.post(&url).send_json(&body);
            record(shared, "telegram", r.map(|_| ()).map_err(|e| e.to_string().replace(&t.bot_token, "***")));
        }
        for c in &cfg.command {
            if !self.channel(&format!("command:{}", c.program), c.min_severity, ev) {
                continue;
            }
            let user = c.user.as_deref().or(shared.config().daemon.command_user.as_deref()).map(str::to_owned);
            let r = run_command(&c.program, &c.args, &text, &out, c.timeout, user.as_deref());
            record(shared, &format!("command:{}", c.program), r);
        }
    }
}

/// Run a notification command: the rendered text on stdin, the event in the
/// `WARDEN_*` environment ([`Event::hook_env`]).
fn run_command(
    program: &str,
    args: &[String],
    text: &str,
    ev: &Event,
    timeout: Duration,
    user: Option<&str>,
) -> Result<(), String> {
    let creds = user.map(warden_sys::cmd::Credentials::lookup).transpose().map_err(|e| format!("user: {e}"))?;
    let mut run = warden_sys::cmd::Run::new(program, timeout)
        .args(args)
        .input(text.as_bytes())
        .max_output(4096)
        .user(creds.as_ref());
    for (k, v) in ev.hook_env() {
        run = run.env(k, v);
    }
    match run.run() {
        Ok(o) if o.status.success() => Ok(()),
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            let err = err.trim();
            Err(if err.is_empty() {
                format!("exit status {}", o.status)
            } else {
                format!("exit status {}: {err}", o.status)
            })
        }
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Err("timeout".into()),
        Err(e) => Err(e.to_string()),
    }
}

fn record(shared: &Shared, channel: &str, r: Result<(), String>) {
    match r {
        Ok(()) => shared.metrics.inc("warden_notifications_total", &[("channel", channel), ("result", "ok")], 1.0),
        Err(e) => {
            shared.metrics.inc("warden_notifications_total", &[("channel", channel), ("result", "error")], 1.0);
            tracing::warn!(channel, error = %e, "notification failed");
        }
    }
}

/// Notification thread body. Returns when the queue closes or the daemon
/// shuts down.
pub fn run(shared: &Shared, rx: &Receiver<Event>) {
    let mut cfg = shared.config().notify.clone();
    let mut generation = shared.generation();
    let mut n = Notifier::new(&cfg);
    loop {
        let ev = match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(ev) => ev,
            Err(RecvTimeoutError::Timeout) if shared.is_shutting_down() => return,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => return,
        };
        if shared.generation() != generation {
            generation = shared.generation();
            cfg = shared.config().notify.clone();
            n.window.set_max(cfg.max_per_hour);
        }
        if cfg.webhook.is_empty() && cfg.telegram.is_none() && cfg.command.is_empty() {
            continue;
        }
        if n.wanted(&cfg, &ev) {
            n.send(&cfg, &ev, shared);
        } else {
            shared.metrics.inc("warden_notifications_suppressed_total", &[], 1.0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warden_core::{Config, Subject};

    #[test]
    fn dedup_and_escalation() {
        let cfg = NotifyConfig::default();
        let mut n = Notifier::new(&cfg);
        let w = Event::new("disk.space", Severity::Warning, "x").fingerprint("f");
        assert!(n.wanted(&cfg, &w));
        assert!(!n.wanted(&cfg, &w));
        let c = Event::new("disk.space", Severity::Critical, "x").fingerprint("f");
        assert!(n.wanted(&cfg, &c), "escalation must pass dedup");
        let info = Event::new("disk.space", Severity::Info, "x").fingerprint("g");
        assert!(!n.wanted(&cfg, &info));
        let resolved = Event::new("disk.space", Severity::Info, "x").fingerprint("f:resolved").resolved();
        assert!(n.wanted(&cfg, &resolved));
        let unknown = Event::new("disk.space", Severity::Info, "x").fingerprint("h:resolved").resolved();
        assert!(!n.wanted(&cfg, &unknown), "nothing was notified about h");
    }

    /// The workstation profile notifies critical events only: the
    /// resolution of a warning it never sent stays home too.
    #[test]
    fn a_resolution_goes_only_where_its_condition_went() {
        let cfg = NotifyConfig { min_severity: Severity::Critical, ..Default::default() };
        let mut n = Notifier::new(&cfg);
        let warn = Event::new("cpu.pressure", Severity::Warning, "w").fingerprint("cpu.pressure:warning");
        let ok = || Event::new("cpu.pressure", Severity::Info, "ok").fingerprint("cpu.pressure:resolved").resolved();
        assert!(!n.wanted(&cfg, &warn));
        assert!(!n.wanted(&cfg, &ok()), "(0.13.3 sent it)");
        let crit = Event::new("cpu.pressure", Severity::Critical, "c").fingerprint("cpu.pressure:critical");
        assert!(n.wanted(&cfg, &crit));
        assert!(n.wanted(&cfg, &ok()));
        assert!(!n.wanted(&cfg, &ok()), "once");
        // per channel: a channel with its own minimum gets what it got the condition of
        let mut c = Notified::default();
        let now = Instant::now();
        let disk_w = Event::new("disk.space", Severity::Warning, "w").fingerprint("disk.space:/:warning");
        let disk_ok = Event::new("disk.space", Severity::Info, "ok").fingerprint("disk.space:/:resolved").resolved();
        assert!(!c.pass(Some(Severity::Critical), &disk_w, now));
        assert!(!c.pass(Some(Severity::Critical), &disk_ok, now));
        assert!(c.pass(None, &disk_w, now));
        assert!(c.pass(None, &disk_ok, now));
    }

    #[test]
    fn a_flap_is_notified_in_full() {
        let cfg = NotifyConfig::default(); // 15 min dedup
        let mut n = Notifier::new(&cfg);
        let down = Event::new("network.link_down", Severity::Warning, "down").fingerprint("network.link:eth0");
        let up =
            Event::new("network.link_up", Severity::Info, "up").fingerprint("network.link:eth0:resolved").resolved();
        assert!(n.wanted(&cfg, &down));
        assert!(n.wanted(&cfg, &up));
        assert!(n.wanted(&cfg, &down), "down again after up: the chat must not keep showing \"up\"");
        assert!(!n.wanted(&cfg, &down), "but a plain repeat is still suppressed");
        // CPU, I/O, memory, limits and disks put the severity into the fingerprint
        let warn = Event::new("cpu.pressure", Severity::Warning, "w").fingerprint("cpu.pressure:warning");
        let ok = Event::new("cpu.pressure", Severity::Info, "ok").fingerprint("cpu.pressure:resolved").resolved();
        assert!(n.wanted(&cfg, &warn));
        assert!(n.wanted(&cfg, &ok));
        assert!(n.wanted(&cfg, &warn), "pressure is back: must not be taken for the warning of 5 minutes ago");
        assert!(n.wanted(&cfg, &ok), "and so is its resolution");
    }

    /// What reaches a webhook and a notification command under each
    /// `notify.details` setting.
    #[test]
    fn secrets_do_not_leave_the_host() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let bodies = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let sink = bodies.clone();
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                let Ok(mut c) = conn else { return };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // headers, then Content-Length bytes of body
                loop {
                    let n = c.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    let text = String::from_utf8_lossy(&buf).into_owned();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let len = head
                            .lines()
                            .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(str::to_owned))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if body.len() >= len {
                            sink.lock().unwrap().push(body.to_owned());
                            break;
                        }
                    }
                }
                let _ = c.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            }
        });
        let d = tempfile::tempdir().unwrap();
        let ev = Event::new("systemd.unit_failed", Severity::Critical, "app.service failed")
            .subject(Subject::Process(warden_core::ProcessRef {
                pid: 7,
                comm: "mysql".into(),
                cmdline: Some("mysql -uroot -pTOPSECRET app".into()),
                ..Default::default()
            }))
            .detail("journal_tail", serde_json::json!(["DB_PASSWORD=TOPSECRET rejected"]));
        for (level, leaks, keeps_details) in [
            (warden_core::redact::Details::Safe, false, true),
            (warden_core::redact::Details::None, false, false),
            (warden_core::redact::Details::All, true, true),
        ] {
            bodies.lock().unwrap().clear();
            let out = d.path().join("cmd.txt");
            let mut cfg = Config::default();
            cfg.notify.details = level;
            cfg.notify.webhook.push(toml::from_str(&format!("name = 'w'\nurl = 'http://{addr}/hook'")).unwrap());
            cfg.notify.command.push(
                toml::from_str(&format!(
                    "program = 'sh'\nargs = ['-c', 'cat > {0}; printenv WARDEN_EVENT_JSON >> {0}']",
                    out.display()
                ))
                .unwrap(),
            );
            let shared = Shared::new(cfg.clone());
            let mut n = Notifier::new(&cfg.notify);
            n.send(&cfg.notify, &ev, &shared);
            let body = bodies.lock().unwrap().join("\n");
            let cmd = std::fs::read_to_string(&out).unwrap();
            for (what, sent) in [("webhook", &body), ("command", &cmd)] {
                assert!(!sent.is_empty(), "{what}: nothing sent");
                assert_eq!(sent.contains("TOPSECRET"), leaks, "{level:?} {what}: {sent}");
                assert_eq!(sent.contains("journal_tail"), keeps_details, "{level:?} {what}: {sent}");
            }
            if level == warden_core::redact::Details::Safe {
                assert!(body.contains("-p***") && body.contains("DB_PASSWORD=***"), "{body}");
            }
        }
        // the event itself (what the journal records) is unchanged
        assert!(serde_json::to_string(&ev).unwrap().contains("TOPSECRET"));
    }

    #[test]
    fn text_rendering() {
        let ev = Event::new("security.webshell", Severity::Critical, "malicious code")
            .subject(Subject::File { path: "/var/www/x.php".into(), site: Some("main".into()) })
            .detail("score", 130);
        let t = render_text(&ev, "web-01");
        assert!(t.contains("[web-01] CRITICAL security.webshell"));
        assert!(t.contains("score: 130"));
    }

    #[test]
    fn command_notifier_gets_stdin() {
        let d = tempfile::tempdir().unwrap();
        let out = d.path().join("o.txt");
        let ev = Event::new("t", Severity::Critical, "hello");
        run_command(
            "sh",
            &["-c".into(), format!("cat > {}", out.display())],
            "payload",
            &ev,
            Duration::from_secs(5),
            None,
        )
        .unwrap();
        assert_eq!(std::fs::read_to_string(out).unwrap(), "payload");
    }

    #[test]
    fn command_notifier_gets_the_event_and_reports_failures() {
        let d = tempfile::tempdir().unwrap();
        let out = d.path().join("env.txt");
        let ev = Event::new("disk.space", Severity::Critical, "hello");
        let script = format!("echo \"$WARDEN_EVENT_KIND/$WARDEN_SEVERITY\" > {}", out.display());
        run_command("sh", &["-c".into(), script], "text", &ev, Duration::from_secs(5), None).unwrap();
        assert_eq!(std::fs::read_to_string(&out).unwrap().trim(), "disk.space/critical");
        let e =
            run_command("sh", &["-c".into(), "echo boom >&2; exit 2".into()], "x", &ev, Duration::from_secs(5), None)
                .unwrap_err();
        assert!(e.contains("boom"), "{e}");
        let e = run_command("sleep", &["30".into()], "x", &ev, Duration::from_millis(100), None).unwrap_err();
        assert_eq!(e, "timeout");
        let e = run_command("true", &[], "x", &ev, Duration::from_secs(5), Some("no-such-user-warden")).unwrap_err();
        assert!(e.contains("no such user"), "{e}");
        if warden_sys::sched::is_root() {
            // the text still arrives on stdin after the switch to an unprivileged user
            let script = "read line; echo \"$(id -un) $line\" >&2; exit 3".to_owned();
            let e = run_command("sh", &["-c".into(), script], "payload", &ev, Duration::from_secs(5), Some("nobody"))
                .unwrap_err();
            assert!(e.ends_with("nobody payload"), "{e}");
        }
    }
}
