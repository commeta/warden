//! Active health checks: HTTP, TCP and command probes.
//!
//! A process can be alive yet hung — deadlocked, stuck on a dead upstream,
//! leaking until it no longer answers. systemd only sees "running". These
//! probes see what users see, and after `failures` consecutive misses raise
//! `health.down` with the configured actions (by default: restart the unit),
//! then wait `grace` for the service to come back before judging again.
//!
//! Typical checks: microservice `/health` endpoints, `pg_isready`,
//! `mysqladmin ping`, `redis-cli ping`, a TCP connect to a backend port.

use crate::runtime::{Cx, Detector};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};
use warden_core::config::{HealthCheck, HealthKind, parse_status_ranges};
use warden_core::{ActionSpec, Event, Severity, Subject};

/// Result of one probe: Ok(detail) or Err(reason).
pub type Probe = Result<String, String>;

fn agent(timeout: Duration, tls_verify: bool) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .http_status_as_error(false)
        .max_redirects(0)
        .user_agent(concat!("warden-health/", env!("CARGO_PKG_VERSION")))
        .tls_config(ureq::tls::TlsConfig::builder().disable_verification(!tls_verify).build())
        .build()
        .into()
}

pub fn probe_http(c: &HealthCheck) -> Probe {
    let url = c.url.as_deref().ok_or("no url")?;
    let ranges = parse_status_ranges(&c.expect_status).unwrap_or_else(|| vec![(200, 399)]);
    let started = Instant::now();
    let mut resp = agent(c.timeout, c.tls_verify).get(url).call().map_err(|e| format!("request failed: {e}"))?;
    let code = resp.status().as_u16();
    if !ranges.iter().any(|(a, b)| (*a..=*b).contains(&code)) {
        return Err(format!("HTTP {code} (expected {})", c.expect_status));
    }
    if let Some(want) = &c.expect_body {
        let body =
            resp.body_mut().with_config().limit(1 << 20).read_to_string().map_err(|e| format!("reading body: {e}"))?;
        if !body.contains(want.as_str()) {
            return Err(format!("HTTP {code} but body does not contain {want:?}"));
        }
    }
    Ok(format!("HTTP {code} in {} ms", started.elapsed().as_millis()))
}

pub fn probe_tcp(c: &HealthCheck) -> Probe {
    let addr = c.address.as_deref().ok_or("no address")?;
    let started = Instant::now();
    let addrs: Vec<_> = addr.to_socket_addrs().map_err(|e| format!("resolve {addr}: {e}"))?.collect();
    let mut last = String::from("no addresses");
    for a in addrs {
        match TcpStream::connect_timeout(&a, c.timeout) {
            Ok(_) => return Ok(format!("connected to {a} in {} ms", started.elapsed().as_millis())),
            Err(e) => last = format!("{a}: {e}"),
        }
    }
    Err(last)
}

pub fn probe_command(c: &HealthCheck) -> Probe {
    let prog = c.program.as_deref().ok_or("no program")?;
    let creds = c
        .user
        .as_deref()
        .map(warden_sys::cmd::Credentials::lookup)
        .transpose()
        .map_err(|e| format!("{prog}: user {}: {e}", c.user.as_deref().unwrap_or("")))?;
    let run = warden_sys::cmd::Run::new(prog, c.timeout).args(&c.args).max_output(64 * 1024).user(creds.as_ref());
    let o = run.run().map_err(|e| {
        if e.kind() == std::io::ErrorKind::TimedOut {
            format!("{prog} timed out after {:?} (service hung?)", c.timeout)
        } else {
            format!("{prog}: {e}")
        }
    })?;
    let status = o.status;
    let out = String::from_utf8_lossy(&o.stdout);
    let err = String::from_utf8_lossy(&o.stderr[..o.stderr.len().min(4096)]);
    if !status.success() {
        let msg = if err.trim().is_empty() { out.trim() } else { err.trim() };
        return Err(format!("{prog} exited with {status}: {}", msg.chars().take(200).collect::<String>()));
    }
    if let Some(want) = &c.expect_output
        && !out.contains(want.as_str())
    {
        return Err(format!("{prog} output does not contain {want:?}"));
    }
    Ok(out.trim().chars().take(120).collect())
}

pub fn probe(c: &HealthCheck) -> Probe {
    match c.kind {
        HealthKind::Http => probe_http(c),
        HealthKind::Tcp => probe_tcp(c),
        HealthKind::Command => probe_command(c),
    }
}

/// One check as a scheduled detector, with hysteresis and grace handling.
pub struct HealthDetector {
    c: HealthCheck,
    name: &'static str,
    fails: u32,
    down: bool,
    down_since: Option<Instant>,
    grace_until: Option<Instant>,
}

impl HealthDetector {
    /// `command_user`: `daemon.command_user`, for a command check without
    /// a `user` of its own.
    pub fn new(c: &HealthCheck, command_user: Option<&str>) -> Self {
        // Detector names are 'static: interned once per distinct check name,
        // so reloads do not leak.
        let name = crate::runtime::intern(&format!("health:{}", c.name));
        Self { c: with_user(c, command_user), name, fails: 0, down: false, down_since: None, grace_until: None }
    }

    fn actions(&self) -> Vec<ActionSpec> {
        if !self.c.actions.is_empty() {
            return self.c.actions.clone();
        }
        if self.c.unit.is_some() { vec![ActionSpec::Snapshot, ActionSpec::RestartUnit { unit: None }] } else { vec![] }
    }

    /// Feed one probe result; returns events to emit.
    pub fn observe(&mut self, now: Instant, res: Probe) -> Vec<Event> {
        let subject = match &self.c.unit {
            Some(u) => Subject::Unit { name: u.clone() },
            None => Subject::System,
        };
        let mut out = Vec::new();
        match res {
            Ok(detail) => {
                if self.down {
                    let secs = self.down_since.map(|t| now.saturating_duration_since(t).as_secs()).unwrap_or(0);
                    out.push(
                        Event::new(
                            "health.down",
                            Severity::Info,
                            format!("{} is healthy again after {secs}s ({detail})", self.c.name),
                        )
                        .subject(subject)
                        .fingerprint(format!("health.down:{}:resolved", self.c.name))
                        .detail("check", self.c.name.clone())
                        .resolved(),
                    );
                }
                self.fails = 0;
                self.down = false;
                self.down_since = None;
            }
            Err(reason) => {
                if self.grace_until.is_some_and(|t| now < t) {
                    return out; // service is (re)starting
                }
                self.fails += 1;
                if self.fails >= self.c.failures {
                    if !self.down {
                        self.down = true;
                        self.down_since = Some(now);
                    }
                    let actions = self.actions();
                    if !actions.is_empty() {
                        self.grace_until = Some(now + self.c.grace);
                    }
                    out.push(
                        Event::new(
                            "health.down",
                            Severity::Critical,
                            format!("{} failed {} consecutive health checks: {reason}", self.c.name, self.fails),
                        )
                        .subject(subject)
                        .fingerprint(format!("health.down:{}", self.c.name))
                        .detail("check", self.c.name.clone())
                        .detail("type", format!("{:?}", self.c.kind).to_lowercase())
                        .detail("reason", reason)
                        .detail("consecutive_failures", self.fails)
                        .actions(actions),
                    );
                    self.fails = 0; // count afresh after acting
                }
            }
        }
        out
    }
}

impl Detector for HealthDetector {
    fn name(&self) -> &'static str {
        self.name
    }

    fn module(&self) -> &'static str {
        "health"
    }

    fn interval(&self) -> Duration {
        self.c.interval
    }

    fn sections(&self) -> &'static [&'static str] {
        &["/health", "/daemon/command_user"]
    }

    fn reconfigure(&mut self, cfg: &warden_core::Config) -> bool {
        // the same check (by name) with new parameters: its failure count
        // and "down" state stay
        match cfg.health.checks.iter().find(|c| c.name == self.c.name) {
            Some(c) => {
                self.c = with_user(c, cfg.daemon.command_user.as_deref());
                true
            }
            None => false,
        }
    }

    fn close(&mut self) -> Vec<Event> {
        if !self.down {
            return Vec::new();
        }
        vec![
            Event::new(
                "health.down",
                Severity::Info,
                format!("{}: {}", self.c.name, crate::runtime::NO_LONGER_WATCHED),
            )
            .fingerprint(format!("health.down:{}:resolved", self.c.name))
            .detail("check", self.c.name.clone())
            .resolved(),
        ]
    }

    fn tick(&mut self, cx: &mut Cx<'_>) {
        let started = Instant::now();
        let res = probe(&self.c);
        let ok = res.is_ok();
        cx.metric("warden_health_up", &[("check", &self.c.name)], if ok { 1.0 } else { 0.0 });
        cx.metric("warden_health_probe_seconds", &[("check", &self.c.name)], started.elapsed().as_secs_f64());
        cx.shared.set_level(
            self.name,
            if ok {
                "ok"
            } else if self.down {
                "critical"
            } else {
                "warning"
            },
        );
        for ev in self.observe(cx.now, res) {
            cx.emit(ev);
        }
    }
}

/// The check with the default user filled in.
fn with_user(c: &HealthCheck, command_user: Option<&str>) -> HealthCheck {
    let mut c = c.clone();
    if c.user.is_none() {
        c.user = command_user.map(str::to_owned);
    }
    c
}

pub fn detectors(cfg: &warden_core::Config) -> Vec<Box<dyn Detector>> {
    if !cfg.health.enabled {
        return Vec::new();
    }
    let user = cfg.daemon.command_user.as_deref();
    cfg.health.checks.iter().map(|c| Box::new(HealthDetector::new(c, user)) as Box<dyn Detector>).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    fn check(toml_src: &str) -> HealthCheck {
        toml::from_str(toml_src).unwrap()
    }

    /// Minimal HTTP server answering `n` requests with `status` and `body`.
    fn serve(status: u16, body: &'static str, n: usize) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap().to_string();
        std::thread::spawn(move || {
            for s in l.incoming().take(n) {
                let mut s = s.unwrap();
                let mut buf = [0u8; 1024];
                let _ = s.read(&mut buf);
                let _ = write!(
                    s,
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        addr
    }

    #[test]
    fn http_probe_status_and_body() {
        let a = serve(200, "{\"status\":\"ok\"}", 2);
        let c = check(&format!("name='a'\ntype='http'\nurl='http://{a}/health'\nexpect_body='ok'"));
        assert!(probe(&c).is_ok(), "{:?}", probe(&c));
        let b = serve(503, "down", 1);
        let c = check(&format!("name='b'\ntype='http'\nurl='http://{b}/health'"));
        assert!(probe(&c).unwrap_err().contains("HTTP 503"));
    }

    #[test]
    fn tcp_and_command_probes() {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let a = l.local_addr().unwrap();
        assert!(probe(&check(&format!("name='t'\ntype='tcp'\naddress='{a}'"))).is_ok());
        drop(l);
        assert!(probe(&check(&format!("name='t'\ntype='tcp'\naddress='{a}'\ntimeout='300ms'"))).is_err());
        let c = check("name='c'\ntype='command'\nprogram='sh'\nargs=['-c','echo PONG']\nexpect_output='PONG'");
        assert!(probe(&c).is_ok());
        let c = check("name='c'\ntype='command'\nprogram='sleep'\nargs=['5']\ntimeout='200ms'");
        assert!(probe(&c).unwrap_err().contains("timed out"));
        let c = check("name='c'\ntype='command'\nprogram='false'");
        assert!(probe(&c).is_err());
        // as another user: the default from daemon.command_user, unless the check names one
        if warden_sys::sched::is_root() {
            let nobody = warden_sys::cmd::Credentials::lookup("nobody").unwrap();
            let c = check("name='c'\ntype='command'\nprogram='id'\nargs=['-u']");
            let d = HealthDetector::new(&c, Some("nobody"));
            assert_eq!(probe(&d.c).unwrap(), nobody.uid.to_string());
            let c = check("name='c'\ntype='command'\nprogram='id'\nargs=['-u']\nuser='root'");
            assert_eq!(probe(&HealthDetector::new(&c, Some("nobody")).c).unwrap(), "0");
            let c = check("name='c'\ntype='command'\nprogram='id'\nuser='no-such-user-warden'");
            assert!(probe(&c).unwrap_err().contains("no such user"));
        }
    }

    #[test]
    fn hysteresis_grace_and_recovery() {
        let c = check("name='api'\ntype='tcp'\naddress='127.0.0.1:1'\nunit='api.service'\nfailures=2\ngrace='60s'");
        let mut d = HealthDetector::new(&c, None);
        let t = Instant::now();
        assert!(d.observe(t, Err("x".into())).is_empty());
        let ev = d.observe(t, Err("x".into()));
        assert_eq!(ev[0].kind, "health.down");
        assert!(ev[0].actions.iter().any(|a| matches!(a, ActionSpec::RestartUnit { .. })));
        // inside grace: failures are ignored while the unit restarts
        assert!(d.observe(t + Duration::from_secs(10), Err("x".into())).is_empty());
        assert!(d.observe(t + Duration::from_secs(20), Err("x".into())).is_empty());
        // recovery
        let ev = d.observe(t + Duration::from_secs(30), Ok("up".into()));
        assert!(ev[0].resolved);
    }
}
