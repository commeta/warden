//! ModSecurity integration (v2 `mod_security2` for Apache, v3 libmodsecurity
//! with the nginx/Apache connectors).
//!
//! ModSecurity decides per request; it has no memory of the attacker. Warden
//! adds the missing dimension: it follows the audit/error logs, counts
//! intercepted transactions per client IP, blocks persistent attackers in
//! nftables (fail2ban-style, but without regex-per-distro tuning), feeds the
//! heuristic IP score, and lets the FIM correlate "who planted this file"
//! with "who was hammering the WAF".
//!
//! Formats understood (auto-detected per line):
//! * JSON audit log — `SecAuditLogFormat JSON` (2.9+) and libmodsecurity 3;
//! * native serial audit log — `--xxxx-A--` sections (v2) / `---xxxx---A--` (v3);
//! * error log lines — Apache `[security2:error] ... ModSecurity: ...` and
//!   nginx `... [client 1.2.3.4] ModSecurity: ... client: 1.2.3.4, ...`.

use crate::runtime::{SensorState, Shared, Sink, lock};
use crate::util::FileTail;
use regex::Regex;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use warden_core::config::{WafConfig, WafFormat};
use warden_core::net::{IpSet, canonical};
use warden_core::ratelimit::{Cooldown, KeyedWindow};
use warden_core::{ActionSpec, Event, Severity, Subject};

/// One WAF transaction (a request that matched at least one rule).
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct WafHit {
    pub ip: Option<IpAddr>,
    pub unique_id: Option<String>,
    pub rule_ids: Vec<String>,
    pub messages: Vec<String>,
    /// Most severe rule severity (0 = emergency … 7 = debug).
    pub severity: Option<u8>,
    pub uri: Option<String>,
    pub host: Option<String>,
    pub status: Option<u16>,
    pub intercepted: bool,
}

struct Patterns {
    id: Regex,
    msg: Regex,
    sev: Regex,
    uri: Regex,
    uid: Regex,
    host: Regex,
    client_bracket: Regex,
    client_nginx: Regex,
    request_nginx: Regex,
    boundary: Regex,
}

fn pats() -> &'static Patterns {
    static P: OnceLock<Patterns> = OnceLock::new();
    P.get_or_init(|| {
        let r = |s: &str| Regex::new(s).expect("static regex");
        Patterns {
            id: r(r#"\[id "(\d+)"\]"#),
            msg: r(r#"\[msg "((?:[^"\\]|\\.)*)"\]"#),
            sev: r(r#"\[severity "([A-Za-z0-9]+)"\]"#),
            uri: r(r#"\[uri "((?:[^"\\]|\\.)*)"\]"#),
            uid: r(r#"\[unique_id "([^"]+)"\]"#),
            host: r(r#"\[hostname "([^"]+)"\]"#),
            client_bracket: r(r"\[client ([0-9a-fA-F.:\[\]]+)\]"),
            client_nginx: r(r"client: ([0-9a-fA-F.:]+),"),
            request_nginx: r(r#"request: "[A-Z]+ ([^ "]+)"#),
            boundary: r(r"^-{2,3}([A-Za-z0-9]+)-{1,3}([A-Z])--\s*$"),
        }
    })
}

/// ModSecurity severity name or number → 0..=7.
pub fn severity_level(s: &str) -> Option<u8> {
    if let Ok(n) = s.trim().parse::<u8>() {
        return (n <= 7).then_some(n);
    }
    Some(match s.trim().to_ascii_uppercase().as_str() {
        "EMERGENCY" => 0,
        "ALERT" => 1,
        "CRITICAL" => 2,
        "ERROR" => 3,
        "WARNING" => 4,
        "NOTICE" => 5,
        "INFO" => 6,
        "DEBUG" => 7,
        _ => return None,
    })
}

/// `1.2.3.4`, `1.2.3.4:5678`, `2001:db8::1`, `[2001:db8::1]:443`.
pub fn parse_client(s: &str) -> Option<IpAddr> {
    let s = s.trim().trim_matches(['[', ']']);
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some(canonical(ip));
    }
    let (host, _port) = s.rsplit_once(':')?;
    host.trim_matches(['[', ']']).parse::<IpAddr>().ok().map(canonical)
}

/// Extract rule ids / messages / severity from ModSecurity message text
/// (error-log lines, v2 JSON messages, native section H).
fn absorb_messages(hit: &mut WafHit, text: &str) {
    let p = pats();
    for c in p.id.captures_iter(text) {
        let id = c[1].to_owned();
        if !hit.rule_ids.contains(&id) {
            hit.rule_ids.push(id);
        }
    }
    for c in p.msg.captures_iter(text) {
        let m = c[1].replace("\\\"", "\"");
        if !m.is_empty() && !hit.messages.contains(&m) && hit.messages.len() < 10 {
            hit.messages.push(m);
        }
    }
    for c in p.sev.captures_iter(text) {
        if let Some(l) = severity_level(&c[1]) {
            hit.severity = Some(hit.severity.map_or(l, |s| s.min(l)));
        }
    }
    if hit.uri.is_none() {
        hit.uri = p.uri.captures(text).map(|c| c[1].to_owned());
    }
    if hit.unique_id.is_none() {
        hit.unique_id = p.uid.captures(text).map(|c| c[1].to_owned());
    }
    if hit.host.is_none() {
        hit.host = p.host.captures(text).map(|c| c[1].to_owned());
    }
    if text.contains("Access denied") || text.contains("Action: Intercepted") {
        hit.intercepted = true;
    }
}

/// Apache (`[security2:error]`) or nginx error-log line.
pub fn parse_error_line(line: &str) -> Option<WafHit> {
    if !line.contains("ModSecurity:") {
        return None;
    }
    let p = pats();
    let ip = p
        .client_bracket
        .captures(line)
        .and_then(|c| parse_client(&c[1]))
        .or_else(|| p.client_nginx.captures(line).and_then(|c| parse_client(&c[1])));
    let mut hit = WafHit { ip, ..Default::default() };
    absorb_messages(&mut hit, line);
    if hit.uri.is_none() {
        hit.uri = p.request_nginx.captures(line).map(|c| c[1].to_owned());
    }
    if let Some(pos) = line.find("Access denied with code ") {
        hit.status = line[pos + 24..].split(|c: char| !c.is_ascii_digit()).next().and_then(|n| n.parse().ok());
    }
    Some(hit)
}

/// One line of a JSON audit log (v2.9 or v3 layout).
pub fn parse_json_line(line: &str) -> Option<WafHit> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    let t = v.get("transaction")?;
    // v3: transaction.client_ip ; v2: transaction.remote_address
    let ip = t.get("client_ip").or_else(|| t.get("remote_address")).and_then(|x| x.as_str()).and_then(parse_client);
    let mut hit = WafHit { ip, ..Default::default() };
    hit.unique_id = t
        .get("unique_id")
        .or_else(|| t.get("transaction_id"))
        .and_then(|x| x.as_str().map(str::to_owned).or_else(|| Some(x.to_string())));
    // v3: transaction.request.uri, transaction.response.http_code, transaction.messages[]
    if let Some(req) = t.get("request") {
        hit.uri = req.get("uri").and_then(|x| x.as_str()).map(str::to_owned);
        hit.host = req
            .get("headers")
            .and_then(|h| h.get("Host").or_else(|| h.get("host")))
            .and_then(|x| x.as_str())
            .map(str::to_owned);
    }
    if let Some(code) = t.get("response").and_then(|r| r.get("http_code")).and_then(|x| x.as_u64()) {
        hit.status = Some(code as u16);
    }
    if let Some(msgs) = t.get("messages").and_then(|m| m.as_array()) {
        for m in msgs {
            if let Some(text) = m.get("message").and_then(|x| x.as_str())
                && !text.is_empty()
                && hit.messages.len() < 10
            {
                hit.messages.push(text.to_owned());
            }
            if let Some(d) = m.get("details") {
                if let Some(id) = d.get("ruleId").and_then(|x| x.as_str())
                    && !hit.rule_ids.iter().any(|r| r == id)
                {
                    hit.rule_ids.push(id.to_owned());
                }
                if let Some(l) = d.get("severity").and_then(|x| x.as_str()).and_then(severity_level) {
                    hit.severity = Some(hit.severity.map_or(l, |s| s.min(l)));
                }
            }
        }
    }
    // v2: top-level request/response/audit_data
    if hit.uri.is_none()
        && let Some(rl) = v.get("request").and_then(|r| r.get("request_line")).and_then(|x| x.as_str())
    {
        hit.uri = rl.split_whitespace().nth(1).map(str::to_owned);
    }
    if hit.status.is_none() {
        hit.status = v.get("response").and_then(|r| r.get("status")).and_then(|x| x.as_u64()).map(|c| c as u16);
    }
    if let Some(ad) = v.get("audit_data") {
        for m in ad.get("messages").and_then(|x| x.as_array()).into_iter().flatten() {
            if let Some(s) = m.as_str() {
                absorb_messages(&mut hit, s);
            }
        }
        if ad.get("action").and_then(|a| a.get("intercepted")).and_then(|x| x.as_bool()) == Some(true) {
            hit.intercepted = true;
        }
    }
    if matches!(hit.status, Some(403 | 406 | 429 | 451)) && !hit.rule_ids.is_empty() {
        hit.intercepted = true;
    }
    (hit.ip.is_some() || !hit.rule_ids.is_empty()).then_some(hit)
}

/// Incremental parser for the native serial audit log (multi-line).
#[derive(Debug, Default)]
pub struct NativeParser {
    cur: Option<(String, WafHit)>,
    section: char,
    first_in_section: bool,
}

impl NativeParser {
    /// Feed one line; returns a finished transaction at its `Z` section.
    pub fn feed(&mut self, line: &str) -> Option<WafHit> {
        let p = pats();
        if let Some(c) = p.boundary.captures(line) {
            let id = c[1].to_owned();
            let sec = c[2].chars().next().unwrap_or('?');
            let mut done = None;
            if sec == 'A' {
                done = self.cur.take().map(|(_, h)| h); // previous one never closed
                self.cur = Some((id, WafHit::default()));
            } else if sec == 'Z' {
                done = self.cur.take().map(|(_, h)| h);
            }
            self.section = sec;
            self.first_in_section = true;
            return done;
        }
        let (_, hit) = self.cur.as_mut()?;
        let first = std::mem::replace(&mut self.first_in_section, false);
        match self.section {
            'A' if first => {
                // [20/Oct/2026:12:00:00 +0300] UNIQUE_ID CLIENT_IP CLIENT_PORT SERVER_IP SERVER_PORT
                if let Some((_, rest)) = line.split_once("] ") {
                    let f: Vec<&str> = rest.split_whitespace().collect();
                    hit.unique_id = f.first().map(|s| (*s).to_owned());
                    hit.ip = f.get(1).and_then(|s| parse_client(s));
                }
            }
            'B' if first => hit.uri = line.split_whitespace().nth(1).map(str::to_owned),
            'F' if first => hit.status = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()),
            'H' => absorb_messages(hit, line),
            _ => {}
        }
        None
    }
}

/// Recent WAF activity per IP, shared with the FIM correlator.
/// count, last seen, rule ids
type RecentEntry = (u32, Instant, BTreeSet<String>);

#[derive(Debug, Default)]
pub struct WafRecent {
    map: Mutex<HashMap<IpAddr, RecentEntry>>,
}

impl WafRecent {
    pub fn record(&self, ip: IpAddr, rules: &[String]) {
        let mut m = lock(&self.map);
        if m.len() >= 50_000 && !m.contains_key(&ip) {
            m.retain(|_, v| v.1.elapsed() < Duration::from_secs(3600));
            if m.len() >= 50_000 {
                return; // distributed flood: the blocklist handles it; keep memory bounded
            }
        }
        let e = m.entry(ip).or_insert((0, Instant::now(), BTreeSet::new()));
        e.0 += 1;
        e.1 = Instant::now();
        if e.2.len() < 20 {
            for r in rules.iter().take(20) {
                e.2.insert(r.clone());
            }
        }
    }

    /// WAF hits for an IP within the last hour.
    pub fn hits(&self, ip: &str) -> Option<(u32, Vec<String>)> {
        let ip: IpAddr = canonical(ip.parse().ok()?);
        let m = lock(&self.map);
        m.get(&ip).filter(|v| v.1.elapsed() < Duration::from_secs(3600)).map(|v| (v.0, v.2.iter().cloned().collect()))
    }
}

/// Counting and decision logic (pure, testable).
pub struct WafTracker {
    cfg: WafConfig,
    min_sev: u8,
    ignore: HashSet<String>,
    allow: IpSet,
    window: KeyedWindow<IpAddr>,
    seen: Cooldown<String>,
    noted: Cooldown<IpAddr>,
    blocked: Cooldown<IpAddr>,
}

impl WafTracker {
    pub fn new(cfg: &WafConfig, allowlist: &[String]) -> Self {
        Self {
            min_sev: severity_level(&cfg.min_rule_severity).unwrap_or(2),
            ignore: cfg.ignore_rules.iter().cloned().collect(),
            allow: IpSet::new(allowlist),
            window: KeyedWindow::new(cfg.window),
            seen: Cooldown::new(Duration::from_secs(120)),
            noted: Cooldown::new(Duration::from_secs(60)),
            blocked: Cooldown::new(cfg.block_ttl.max(Duration::from_secs(60))),
            cfg: cfg.clone(),
        }
    }

    pub fn on_hit(&mut self, mut hit: WafHit, site: Option<&str>, recent: &WafRecent, now: Instant) -> Vec<Event> {
        let Some(ip) = hit.ip else { return Vec::new() };
        // One transaction can produce many error-log lines; count it once.
        if let Some(uid) = &hit.unique_id
            && !self.seen.ready(&format!("{ip}:{uid}"), now)
        {
            return Vec::new();
        }
        hit.rule_ids.retain(|r| !self.ignore.contains(r));
        if hit.rule_ids.is_empty() {
            return Vec::new();
        }
        if hit.severity.is_some_and(|s| s > self.min_sev) && !hit.intercepted {
            return Vec::new();
        }
        if !hit.intercepted && !self.cfg.count_detection_only {
            return Vec::new();
        }
        recent.record(ip, &hit.rule_ids);
        let n = self.window.add(ip, now);
        let mut out = Vec::new();
        let summary = hit.messages.first().cloned().unwrap_or_else(|| format!("rules {}", hit.rule_ids.join(",")));
        if self.noted.ready(&ip, now) {
            let mut ev = Event::new(
                "waf.hit",
                Severity::Info,
                format!(
                    "ModSecurity {} {ip}: {summary}{}",
                    if hit.intercepted { "blocked" } else { "flagged" },
                    hit.uri.as_deref().map(|u| format!(" ({u})")).unwrap_or_default()
                ),
            )
            .subject(Subject::Ip { addr: ip })
            .fingerprint(format!("waf.hit:{ip}"))
            .detail("ip", ip.to_string())
            .detail("rules", hit.rule_ids.clone())
            .detail("count_in_window", n);
            if let Some(s) = site {
                ev = ev.detail("site", s);
            }
            out.push(ev);
        }
        if n >= self.cfg.block_after && self.blocked.ready(&ip, now) {
            self.window.reset(&ip);
            let allowlisted = self.allow.contains(&ip);
            let mut ev = Event::new(
                "security.waf_attack",
                Severity::Warning,
                format!(
                    "{ip}: {n} requests blocked by ModSecurity within {}s — persistent attacker",
                    self.cfg.window.as_secs()
                ),
            )
            .subject(Subject::Ip { addr: ip })
            .fingerprint(format!("security.waf_attack:{ip}"))
            .detail("ip", ip.to_string())
            .detail("blocked_requests", n)
            .detail("last_rules", hit.rule_ids.clone())
            .detail("last_messages", hit.messages.clone())
            .detail("last_uri", hit.uri.clone().unwrap_or_default());
            if let Some(s) = site {
                ev = ev.detail("site", s);
            }
            if allowlisted {
                ev = ev.detail("allowlisted", true);
            } else if self.cfg.block {
                ev = ev.actions(vec![ActionSpec::BlockIp { ttl: Some(self.cfg.block_ttl) }]);
            } else {
                ev = ev.detail(warden_core::event::IP_BLOCK_OFF, "waf.block = false");
            }
            out.push(ev);
        }
        out
    }
}

/// Sensor: tail all configured WAF logs.
pub fn run_waf(shared: &Arc<Shared>, sink: &Sink) -> Result<(), String> {
    let cfg = shared.config();
    if !cfg.waf.enabled || cfg.waf.logs.is_empty() {
        return Ok(());
    }
    let generation = shared.generation();
    let allow: Vec<String> = cfg.actions.firewall.allowlist.iter().chain(&cfg.auth.allowlist).cloned().collect();
    let mut tracker = WafTracker::new(&cfg.waf, &allow);
    let mut tails: Vec<(FileTail, WafFormat, Option<String>, NativeParser)> = cfg
        .waf
        .logs
        .iter()
        .map(|l| (FileTail::new(&l.path), l.format, l.site.clone(), NativeParser::default()))
        .collect();
    let missing: Vec<String> =
        cfg.waf.logs.iter().filter(|l| !l.path.exists()).map(|l| l.path.display().to_string()).collect();
    if missing.len() == cfg.waf.logs.len() {
        return Err(format!("no WAF log exists yet: {}", missing.join(", ")));
    }
    shared.set_sensor("waf", SensorState::Running);
    loop {
        if shared.generation() != generation {
            return Err("configuration reloaded".into());
        }
        if shared.is_shutting_down() {
            return Ok(());
        }
        for (tail, fmt, site, native) in tails.iter_mut() {
            for line in tail.poll(20_000) {
                let hit = match fmt {
                    WafFormat::Json => parse_json_line(&line),
                    WafFormat::ErrorLog => parse_error_line(&line),
                    WafFormat::Native => native.feed(&line),
                    WafFormat::Auto => {
                        let t = line.trim_start();
                        if t.starts_with('{') {
                            parse_json_line(t)
                        } else if t.contains("ModSecurity:") && !t.starts_with("Message:") {
                            parse_error_line(t)
                        } else {
                            native.feed(&line)
                        }
                    }
                };
                if let Some(h) = hit {
                    shared.metrics.inc(
                        "warden_waf_transactions_total",
                        &[("intercepted", if h.intercepted { "yes" } else { "no" })],
                        1.0,
                    );
                    for mut ev in tracker.on_hit(h, site.as_deref(), &shared.waf, Instant::now()) {
                        ev.source = "waf".into();
                        sink.emit(ev);
                    }
                }
            }
        }
        // Poll once a second; a reload or shutdown wakes us at once.
        shared.wait_reload(generation, Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const APACHE: &str = r#"[Tue Oct 20 12:00:00.123456 2026] [security2:error] [pid 1234:tid 5678] [client 203.0.113.5:51234] [client 203.0.113.5] ModSecurity: Access denied with code 403 (phase 2). Operator GE matched 5 at TX:anomaly_score. [file "/usr/share/modsecurity-crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "81"] [id "949110"] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [severity "CRITICAL"] [ver "OWASP_CRS/4.0.0"] [tag "anomaly-evaluation"] [hostname "example.com"] [uri "/index.php"] [unique_id "ZxyzAbC1"]"#;
    const NGINX: &str = r#"2026/10/20 12:00:00 [error] 1234#1234: *5 [client 198.51.100.9] ModSecurity: Access denied with code 403 (phase 2). Matched "Operator `Ge' with parameter `5' against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE' (Value: `5' ) [file "/etc/nginx/crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "222"] [id "949110"] [rev ""] [msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [data ""] [severity "0"] [ver "OWASP_CRS/4.0.0"] [hostname "10.0.0.1"] [uri "/"] [unique_id "1729425600"] [ref ""], client: 198.51.100.9, server: example.com, request: "GET /?id=1%27%20OR%201=1 HTTP/1.1", host: "example.com""#;
    const V3_JSON: &str = r#"{"transaction":{"client_ip":"192.0.2.10","time_stamp":"Tue Oct 20 12:00:00 2026","server_id":"x","client_port":40000,"host_ip":"10.0.0.1","host_port":443,"unique_id":"172942560012.345","request":{"method":"GET","http_version":1.1,"uri":"/?q=<script>alert(1)</script>","headers":{"Host":"example.com"}},"response":{"http_code":403,"headers":{}},"producer":{"modsecurity":"ModSecurity v3.0.12 (Linux)"},"messages":[{"message":"XSS Attack Detected via libinjection","details":{"match":"detected XSS using libinjection.","reference":"v8,25","ruleId":"941100","file":"/crs/REQUEST-941.conf","lineNumber":"55","data":"","severity":"2","ver":"OWASP_CRS/4.0.0","rev":"","tags":[],"maturity":"0","accuracy":"0"}},{"message":"Inbound Anomaly Score Exceeded (Total Score: 5)","details":{"ruleId":"949110","severity":"0"}}]}}"#;
    const V2_JSON: &str = r#"{"transaction":{"time":"20/Oct/2026:12:00:00 +0300","transaction_id":"ZxYz","remote_address":"192.0.2.20","remote_port":5555,"local_address":"10.0.0.1","local_port":80},"request":{"request_line":"POST /wp-login.php HTTP/1.1","headers":{}},"response":{"protocol":"HTTP/1.1","status":403},"audit_data":{"messages":["Warning. detected SQLi using libinjection [file \"/crs/REQUEST-942.conf\"] [line \"46\"] [id \"942100\"] [msg \"SQL Injection Attack Detected via libinjection\"] [severity \"CRITICAL\"]"],"action":{"intercepted":true,"phase":2,"message":"Access denied"}}}"#;
    const NATIVE: &str = "--a1b2c3d4-A--\n[20/Oct/2026:12:00:00 +0300] ZxYzAbC 203.0.113.77 51234 10.0.0.1 443\n--a1b2c3d4-B--\nGET /shell.php?cmd=id HTTP/1.1\nHost: example.com\n\n--a1b2c3d4-F--\nHTTP/1.1 403 Forbidden\n\n--a1b2c3d4-H--\nMessage: Warning. Matched phrase \"cmd=\" [file \"/crs/REQUEST-932.conf\"] [id \"932160\"] [msg \"Remote Command Execution: Unix Shell Code Found\"] [severity \"CRITICAL\"]\nAction: Intercepted (phase 2)\n\n--a1b2c3d4-Z--\n";

    #[test]
    fn apache_error_log() {
        let h = parse_error_line(APACHE).unwrap();
        assert_eq!(h.ip, Some("203.0.113.5".parse().unwrap()));
        assert_eq!(h.rule_ids, vec!["949110"]);
        assert_eq!(h.severity, Some(2));
        assert_eq!(h.uri.as_deref(), Some("/index.php"));
        assert_eq!(h.status, Some(403));
        assert!(h.intercepted);
        assert!(parse_error_line("[error] something else").is_none());
    }

    #[test]
    fn nginx_error_log() {
        let h = parse_error_line(NGINX).unwrap();
        assert_eq!(h.ip, Some("198.51.100.9".parse().unwrap()));
        assert_eq!(h.severity, Some(0));
        assert_eq!(h.uri.as_deref(), Some("/"));
        assert!(h.intercepted);
    }

    #[test]
    fn json_v3_and_v2() {
        let h = parse_json_line(V3_JSON).unwrap();
        assert_eq!(h.ip, Some("192.0.2.10".parse().unwrap()));
        assert_eq!(h.rule_ids, vec!["941100", "949110"]);
        assert_eq!(h.severity, Some(0));
        assert!(h.intercepted);
        assert_eq!(h.host.as_deref(), Some("example.com"));
        let h = parse_json_line(V2_JSON).unwrap();
        assert_eq!(h.ip, Some("192.0.2.20".parse().unwrap()));
        assert_eq!(h.rule_ids, vec!["942100"]);
        assert_eq!(h.uri.as_deref(), Some("/wp-login.php"));
        assert!(h.intercepted);
    }

    #[test]
    fn native_serial() {
        let mut p = NativeParser::default();
        let mut out = Vec::new();
        for l in NATIVE.lines() {
            out.extend(p.feed(l));
        }
        assert_eq!(out.len(), 1);
        let h = &out[0];
        assert_eq!(h.ip, Some("203.0.113.77".parse().unwrap()));
        assert_eq!(h.uri.as_deref(), Some("/shell.php?cmd=id"));
        assert_eq!(h.status, Some(403));
        assert_eq!(h.rule_ids, vec!["932160"]);
        assert!(h.intercepted);
        // v3 boundaries
        let mut p = NativeParser::default();
        let v3 = NATIVE.replace("--a1b2c3d4-", "---ZBMFNTsF---");
        assert_eq!(v3.lines().filter_map(|l| p.feed(l)).count(), 1);
    }

    #[test]
    fn ipv6_and_ports() {
        assert_eq!(parse_client("2001:db8::1"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(parse_client("[2001:db8::1]:443"), Some("2001:db8::1".parse().unwrap()));
        assert_eq!(parse_client("1.2.3.4:80"), Some("1.2.3.4".parse().unwrap()));
        assert_eq!(parse_client("::ffff:1.2.3.4"), Some("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn tracker_blocks_persistent_attacker_once() {
        let cfg = WafConfig { block_after: 3, ..Default::default() };
        let mut t = WafTracker::new(&cfg, &["10.0.0.0/8".to_string()]);
        let recent = WafRecent::default();
        let now = Instant::now();
        let mut kinds = Vec::new();
        for i in 0..5 {
            let mut h = parse_error_line(APACHE).unwrap();
            h.unique_id = Some(format!("u{i}"));
            for e in t.on_hit(h, Some("main"), &recent, now + Duration::from_secs(i)) {
                kinds.push((e.kind.clone(), e.actions.len()));
            }
        }
        assert_eq!(kinds.iter().filter(|k| k.0 == "security.waf_attack").count(), 1);
        assert!(kinds.iter().any(|k| k.0 == "security.waf_attack" && k.1 == 1));
        assert_eq!(recent.hits("203.0.113.5").unwrap().0, 5);
        // the same transaction logged twice counts once
        let mut t = WafTracker::new(&cfg, &[]);
        let h = parse_error_line(APACHE).unwrap();
        t.on_hit(h.clone(), None, &recent, now);
        assert!(t.on_hit(h, None, &recent, now).is_empty());
    }

    #[test]
    fn detection_only_and_ignored_rules() {
        let cfg = WafConfig { ignore_rules: vec!["949110".into()], ..Default::default() };
        let mut t = WafTracker::new(&cfg, &[]);
        let recent = WafRecent::default();
        assert!(t.on_hit(parse_error_line(APACHE).unwrap(), None, &recent, Instant::now()).is_empty());
        let warn = APACHE.replace("Access denied with code 403 (phase 2).", "Warning.");
        let mut t = WafTracker::new(&WafConfig::default(), &[]);
        assert!(t.on_hit(parse_error_line(&warn).unwrap(), None, &recent, Instant::now()).is_empty());
    }
}
