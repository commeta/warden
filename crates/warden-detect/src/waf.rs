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
use regex::Regex;
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::hash::BuildHasher;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use warden_core::config::WafConfig;
use warden_core::net::{IpSet, canonical};
use warden_core::ratelimit::{Cooldown, KeyedWindow, evict_lowest};
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
    /// The message that best says what the attack was: the most severe
    /// rule that is not an anomaly-score evaluation (CRS 949/959/980) —
    /// not "Host header is a numeric IP address" when an XSS rule matched
    /// too. Rank: (evaluation rule?, severity), lower is better.
    #[serde(skip)]
    pub headline: Option<((bool, u8), String)>,
}

/// CRS rules that sum up a transaction rather than recognise an attack.
fn is_evaluation_rule(id: &str) -> bool {
    id.parse::<u32>().is_ok_and(|n| matches!(n / 1000, 949 | 959 | 980))
}

impl WafHit {
    /// Offer a message as the headline (kept when it outranks the current one).
    fn offer_headline(&mut self, id: Option<&str>, severity: Option<u8>, msg: &str) {
        if msg.is_empty() {
            return;
        }
        let rank = (id.is_some_and(is_evaluation_rule), severity.unwrap_or(8));
        if self.headline.as_ref().is_none_or(|(r, _)| rank < *r) {
            self.headline = Some((rank, msg.to_owned()));
        }
    }

    /// The headline, or the first message.
    pub fn summary(&self) -> Option<&str> {
        self.headline.as_ref().map(|(_, m)| m.as_str()).or(self.messages.first().map(String::as_str))
    }
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
    // one message per error-log line / section-H line / v2 JSON message
    if let Some(m) = p.msg.captures(text) {
        let id = p.id.captures(text).map(|c| c[1].to_owned());
        let sev = p.sev.captures(text).and_then(|c| severity_level(&c[1]));
        hit.offer_headline(id.as_deref(), sev, &m[1].replace("\\\"", "\""));
    }
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
            let text = m.get("message").and_then(|x| x.as_str()).unwrap_or("");
            if !text.is_empty() && hit.messages.len() < 10 {
                hit.messages.push(text.to_owned());
            }
            let d = m.get("details");
            let id = d.and_then(|d| d.get("ruleId")).and_then(|x| x.as_str());
            let sev = d.and_then(|d| d.get("severity")).and_then(|x| x.as_str()).and_then(severity_level);
            hit.offer_headline(id, sev, text);
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
    if hit.host.is_none() {
        hit.host = v
            .get("request")
            .and_then(|r| r.get("headers"))
            .and_then(|h| h.get("Host").or_else(|| h.get("host")))
            .and_then(|x| x.as_str())
            .map(|s| s.chars().take(255).collect());
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

/// A JSON audit record that does not parse — cut in the middle (an
/// overlong line keeps only its head and tail), or with invalid escapes:
/// the client address, unique id and URI from wherever they appear, the
/// rule ids and messages from the escaped message strings. An attacker
/// must not be able to hide a transaction by padding it with a large body
/// (the 2.9 layout writes the messages after the request).
pub fn salvage_json_line(line: &str) -> Option<WafHit> {
    static P: OnceLock<[Regex; 7]> = OnceLock::new();
    let [ip, uid, uri, rule, sev, code, rline] = P.get_or_init(|| {
        let r = |s: &str| Regex::new(s).expect("static regex");
        [
            r(r#""(?:client_ip|remote_address)"\s*:\s*"([^"]{1,64})""#),
            r(r#""(?:unique_id|transaction_id)"\s*:\s*"([^"]{1,128})""#),
            r(r#""uri"\s*:\s*"((?:[^"\\]|\\.){0,4096})""#),
            r(r#""ruleId"\s*:\s*"(\d{1,10})""#),
            r(r#""severity"\s*:\s*"([A-Za-z0-9]{1,16})""#),
            r(r#""(?:http_code|status)"\s*:\s*(\d{3})"#),
            r(r#""request_line"\s*:\s*"[A-Z]{1,16} ((?:[^" \\]|\\.){0,4096})"#),
        ]
    });
    let t = line.trim_start();
    if !t.starts_with('{') || !t.contains("\"transaction\"") {
        return None;
    }
    let mut hit = WafHit {
        ip: ip.captures(t).and_then(|c| parse_client(&c[1])),
        unique_id: uid.captures(t).map(|c| c[1].to_owned()),
        uri: uri.captures(t).or_else(|| rline.captures(t)).map(|c| c[1].replace("\\/", "/")),
        status: code.captures(t).and_then(|c| c[1].parse().ok()),
        ..Default::default()
    };
    // v3: structured message details
    for c in rule.captures_iter(t) {
        let id = c[1].to_owned();
        if !hit.rule_ids.contains(&id) && hit.rule_ids.len() < 64 {
            hit.rule_ids.push(id);
        }
    }
    for c in sev.captures_iter(t) {
        if let Some(l) = severity_level(&c[1]) {
            hit.severity = Some(hit.severity.map_or(l, |s| s.min(l)));
        }
    }
    // v2: messages are strings with `[id \"942100\"]` inside
    absorb_messages(&mut hit, &t.replace("\\\"", "\""));
    if t.contains("\"intercepted\":true") || t.contains("\"intercepted\": true") {
        hit.intercepted = true;
    }
    if matches!(hit.status, Some(403 | 406 | 429 | 451)) && !hit.rule_ids.is_empty() {
        hit.intercepted = true;
    }
    (hit.ip.is_some() && !hit.rule_ids.is_empty()).then_some(hit)
}

/// One line of the index of a concurrent audit log (`SecAuditLog` with
/// `SecAuditLogType Concurrent`): an access-log-like prefix and, at the
/// end, where the transaction was written:
/// `host 203.0.113.5 - - [27/Oct/2026:12:00:00 +0300] "GET / HTTP/1.1" 403 199 "-" "ua" UNIQUEID "-" /20261027/20261027-1200/20261027-120000-UNIQUEID 0 1234 md5:…`
/// (ModSecurity 2.9.6+ adds a user directory: `/www-data/20261027/…`).
/// libmodsecurity 3 writes one `-` less, the absolute path and the length
/// as a float: `host 203.0.113.5 - [time] "GET / HTTP/1.1" 403 162 - "ua"
/// 1793….2005 - /var/log/nginx/audit/20261027/…/20261027-202500-1793….2005 0 3750.000000 md5:…`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    pub host: String,
    pub ip: Option<IpAddr>,
    /// Path relative to `SecAuditLogStorageDir` (starts with `/`), or
    /// absolute (libmodsecurity 3) — see `Storage::relative`.
    pub file: String,
    pub size: u64,
    /// MD5 of the entry file as ModSecurity wrote it (hex), if given.
    pub md5: Option<String>,
}

pub fn parse_index_line(line: &str) -> Option<IndexEntry> {
    static P: OnceLock<Regex> = OnceLock::new();
    let tail = P.get_or_init(|| {
        Regex::new(r"\s(/[^\s]{1,1024})\s+(\d{1,20})\s+(\d{1,20})(?:\.\d{1,9})?\s+md5:([0-9a-fA-F-]{1,64})\s*$")
            .expect("static regex")
    });
    let c = tail.captures(line)?;
    let mut head = line.split_whitespace();
    let host = head.next()?.to_owned();
    let ip = head.next().and_then(parse_client);
    let md5 = Some(c[4].to_ascii_lowercase()).filter(|h| h.len() == 32 && h.bytes().all(|b| b.is_ascii_hexdigit()));
    Some(IndexEntry { host, ip, file: c[1].to_owned(), size: c[3].parse().ok()?, md5 })
}

/// One transaction file of a concurrent audit log: a JSON record or a
/// native one (`--xxxx-A--` … `--xxxx-Z--`).
pub fn parse_entry(content: &str) -> Option<WafHit> {
    let t = content.trim_start();
    if t.starts_with('{') {
        let one_line: String = t.lines().map(str::trim).collect::<Vec<_>>().join("");
        return parse_json_line(&one_line).or_else(|| salvage_json_line(&one_line));
    }
    let mut p = NativeParser::default();
    for line in t.lines() {
        if let Some(h) = p.feed(line) {
            return Some(h);
        }
    }
    p.finish()
}

/// Incremental parser for the native serial audit log (multi-line).
#[derive(Debug, Default)]
pub struct NativeParser {
    cur: Option<(String, WafHit)>,
    section: char,
    first_in_section: bool,
    /// When the transaction in progress began (see [`Self::expire`]).
    opened: Option<std::time::Instant>,
}

/// A serial log gets each record in one write; one still open after this
/// was cut (a crash, a full disk, a truncating rotation) and will not end.
const NATIVE_STALE: std::time::Duration = std::time::Duration::from_secs(30);

impl NativeParser {
    /// The transaction in progress, if the record ends without its `Z`
    /// section (a cut entry file).
    pub fn finish(&mut self) -> Option<WafHit> {
        self.opened = None;
        self.cur.take().map(|(_, h)| h).filter(|h| h.ip.is_some())
    }

    /// Inside a record: every line belongs to it, whatever it looks like.
    pub fn in_transaction(&self) -> bool {
        self.cur.is_some()
    }

    /// Give up a record that has been open for too long (it was cut), so
    /// that the next one is recognised.
    pub fn expire(&mut self, now: std::time::Instant) {
        if self.opened.is_some_and(|t| now.saturating_duration_since(t) > NATIVE_STALE) {
            self.cur = None;
            self.opened = None;
        }
    }

    /// Feed one line; returns a finished transaction at its `Z` section.
    ///
    /// Inside a record only boundaries with its own id count: the request
    /// and response bodies (parts C, I, E) are logged verbatim, and a body
    /// line `--x-Z--` followed by a made-up `--y-A--` record with someone
    /// else's address must stay body. The id is random per transaction.
    pub fn feed(&mut self, line: &str) -> Option<WafHit> {
        let p = pats();
        if let Some(c) = p.boundary.captures(line) {
            let sec = c[2].chars().next().unwrap_or('?');
            let ours = match &self.cur {
                None => sec == 'A',
                Some((id, _)) => *id == c[1],
            };
            if ours {
                let mut done = None;
                if sec == 'A' {
                    // the previous record had no Z: give what it had
                    done = self.cur.take().map(|(_, h)| h).filter(|h| h.ip.is_some());
                    self.cur = Some((c[1].to_owned(), WafHit::default()));
                    self.opened = Some(std::time::Instant::now());
                } else if sec == 'Z' {
                    done = self.cur.take().map(|(_, h)| h);
                    self.opened = None;
                }
                self.section = sec;
                self.first_in_section = true;
                return done;
            }
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
            'B' if hit.host.is_none() && line.get(..5).is_some_and(|h| h.eq_ignore_ascii_case("host:")) => {
                hit.host = Some(line[5..].trim().chars().take(255).collect());
            }
            'F' if first => hit.status = line.split_whitespace().nth(1).and_then(|s| s.parse().ok()),
            'H' => absorb_messages(hit, line),
            _ => {}
        }
        None
    }
}

/// Recent WAF activity per IP, shared with the FIM correlator.
#[derive(Debug, Clone, Copy)]
struct RecentEntry {
    count: u32,
    last: Instant,
    /// Rule ids (numeric, as ModSecurity requires), first [`RECENT_RULES`].
    rules: [u32; RECENT_RULES],
    n_rules: u8,
}

/// Rule ids remembered per address.
const RECENT_RULES: usize = 8;
/// Addresses remembered; past it the quietest are forgotten.
const RECENT_CAP: usize = 20_000;
/// How long an address counts as recent.
const RECENT_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug)]
struct RecentMap {
    map: HashMap<IpAddr, RecentEntry>,
    gc_at: usize,
    evicted: u64,
}

impl Default for RecentMap {
    fn default() -> Self {
        Self { map: HashMap::new(), gc_at: 4096, evicted: 0 }
    }
}

/// Fixed-size entries, one clock reading per call, expiry amortised and a
/// hard cap with eviction of the quietest addresses: a flood of distinct
/// addresses used to trigger a full scan — with a clock read per entry — on
/// every new address once 50 000 were known (N2), and to stop recording
/// altogether when all of them were recent.
#[derive(Debug, Default)]
pub struct WafRecent {
    inner: Mutex<RecentMap>,
}

impl WafRecent {
    pub fn record(&self, ip: IpAddr, rules: &[String]) {
        self.record_at(ip, rules, Instant::now());
    }

    pub fn record_at(&self, ip: IpAddr, rules: &[String], now: Instant) {
        let mut r = lock(&self.inner);
        let e = r.map.entry(ip).or_insert(RecentEntry { count: 0, last: now, rules: [0; RECENT_RULES], n_rules: 0 });
        e.count = e.count.saturating_add(1);
        e.last = now;
        for id in rules.iter().filter_map(|r| r.parse::<u32>().ok()) {
            let n = usize::from(e.n_rules);
            if n < RECENT_RULES && !e.rules[..n].contains(&id) {
                e.rules[n] = id;
                e.n_rules += 1;
            }
        }
        if r.map.len() > r.gc_at {
            r.map.retain(|_, v| now.saturating_duration_since(v.last) < RECENT_TTL);
            r.gc_at = (r.map.len() * 2).clamp(4096, RECENT_CAP);
        }
        if r.map.len() > RECENT_CAP {
            let n = evict_lowest(&mut r.map, RECENT_CAP - RECENT_CAP / 10, |v| (v.count, v.last));
            r.evicted += n as u64;
        }
    }

    /// WAF hits for an IP within the last hour.
    pub fn hits(&self, ip: &str) -> Option<(u32, Vec<String>)> {
        let ip: IpAddr = canonical(ip.parse().ok()?);
        let r = lock(&self.inner);
        r.map
            .get(&ip)
            .filter(|v| v.last.elapsed() < RECENT_TTL)
            .map(|v| (v.count, v.rules[..usize::from(v.n_rules)].iter().map(u32::to_string).collect()))
    }

    /// (addresses remembered, addresses evicted by the cap)
    pub fn stats(&self) -> (usize, u64) {
        let r = lock(&self.inner);
        (r.map.len(), r.evicted)
    }
}

/// Counting and decision logic (pure, testable).
pub struct WafTracker {
    cfg: WafConfig,
    min_sev: u8,
    ignore: HashSet<String>,
    allow: IpSet,
    window: KeyedWindow<IpAddr>,
    /// Transactions already counted, by a keyed hash of address and
    /// unique id (8 bytes instead of a formatted string per transaction).
    seen: Cooldown<u64>,
    seen_hasher: std::collections::hash_map::RandomState,
    noted: Cooldown<IpAddr>,
    blocked: Cooldown<IpAddr>,
}

/// One transaction yields several error-log lines (one per matched rule),
/// written within the same request, and may appear in an audit log and an
/// error log both: this is how long its unique id is remembered.
const SEEN_PERIOD: Duration = Duration::from_secs(30);
const SEEN_CAP: usize = 20_000;
/// Addresses counted towards `block_after` at most. Under a flood of one-off
/// addresses the ones with the fewest hits go first: an address that keeps
/// coming back stays counted.
const WINDOW_CAP: usize = 20_000;
/// Addresses whose `waf.hit` was reported within the last minute at most
/// (forgetting one costs only an extra informational event).
const NOTED_CAP: usize = 10_000;

impl WafTracker {
    pub fn new(cfg: &WafConfig, allowlist: &[String]) -> Self {
        Self {
            min_sev: severity_level(&cfg.min_rule_severity).unwrap_or(2),
            ignore: cfg.ignore_rules.iter().cloned().collect(),
            allow: IpSet::new(allowlist),
            window: KeyedWindow::with_capacity(cfg.window, WINDOW_CAP),
            seen: Cooldown::with_capacity(SEEN_PERIOD, SEEN_CAP),
            seen_hasher: std::collections::hash_map::RandomState::new(),
            noted: Cooldown::with_capacity(Duration::from_secs(60), NOTED_CAP),
            blocked: Cooldown::new(cfg.block_ttl.max(Duration::from_secs(60))),
            cfg: cfg.clone(),
        }
    }

    /// Entries forgotten because a table was full: (dedup, counting window).
    pub fn evicted(&self) -> (u64, u64) {
        (self.seen.evicted(), self.window.evicted())
    }

    /// Account one transaction. `writable` says why a web account can
    /// write the log it came from, if it can.
    pub fn on_hit(
        &mut self,
        mut hit: WafHit,
        site: Option<&str>,
        writable: Option<&str>,
        recent: &WafRecent,
        now: Instant,
    ) -> Vec<Event> {
        let Some(ip) = hit.ip else { return Vec::new() };
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
        // One transaction can produce many error-log lines, and reach Warden
        // through two logs (error log and audit log); count it once. Only
        // counted hits take the slot: a warning line of a transaction must
        // not hide its "Access denied" line or its audit record.
        if let Some(uid) = &hit.unique_id
            && !self.seen.ready(&self.seen_hasher.hash_one((ip, uid.as_str())), now)
        {
            return Vec::new();
        }
        recent.record_at(ip, &hit.rule_ids, now);
        let n = self.window.add(ip, now);
        let mut out = Vec::new();
        let summary = hit.summary().map(str::to_owned).unwrap_or_else(|| format!("rules {}", hit.rule_ids.join(",")));
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
            if let Some(h) = &hit.host {
                ev = ev.detail("host", h.chars().take(255).collect::<String>());
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
            if let Some(h) = &hit.host {
                ev = ev.detail("host", h.chars().take(255).collect::<String>());
            }
            if let Some(w) = writable {
                ev = ev.detail("log_trust", format!("writable by a web user: {w}"));
            }
            if allowlisted {
                ev = ev.detail("allowlisted", true);
            } else if !self.cfg.block {
                ev = ev.detail(warden_core::event::IP_BLOCK_OFF, "waf.block = false");
            } else if writable.is_some() && !self.cfg.trust_writable_logs {
                ev = ev.detail(
                    warden_core::event::IP_BLOCK_OFF,
                    "the WAF log can be written by a web user (waf.trust_writable_logs = false)",
                );
            } else {
                ev = ev.actions(vec![ActionSpec::BlockIp { ttl: Some(self.cfg.block_ttl) }]);
            }
            out.push(ev);
        }
        out
    }
}

/// Sensor: follow every WAF log — configured, matched by a glob, or found
/// in the web servers' configuration (`waf.discover`).
pub fn run_waf(shared: &Arc<Shared>, sink: &Sink) -> Result<(), String> {
    use crate::waf_sources::{PollStats, Sources};
    let cfg = shared.config();
    if !cfg.waf.enabled || (cfg.waf.logs.is_empty() && !cfg.waf.discover) {
        return Ok(());
    }
    let generation = shared.generation();
    let allow: Vec<String> = cfg.actions.firewall.allowlist.iter().chain(&cfg.auth.allowlist).cloned().collect();
    let mut tracker = WafTracker::new(&cfg.waf, &allow);
    let web = crate::util::WebPrincipals::load(&cfg.process.web_users);
    let mut sources = Sources::new();
    let mut discovered: Vec<warden_core::config::WafLog> = Vec::new();
    let mut last_discovery: Option<Instant> = None;
    let mut reported_problems: HashSet<String> = HashSet::new();
    let mut tampered = Cooldown::<std::path::PathBuf>::new(TAMPERED_PERIOD);
    // The configured logs first, before reading the web servers'
    // configuration: what is written to them from now on is read.
    sources.refresh(&cfg.waf, &discovered, &web, Instant::now());
    *lock(&shared.waf_sources) = sources.status();
    shared.set_sensor("waf", SensorState::Running);
    loop {
        if shared.generation() != generation {
            return Err("configuration reloaded".into());
        }
        if shared.is_shutting_down() {
            return Ok(());
        }
        let now = Instant::now();
        if cfg.waf.discover && last_discovery.is_none_or(|t| now.saturating_duration_since(t) >= DISCOVER_EVERY) {
            last_discovery = Some(now);
            let d = crate::waf_discover::discover();
            for n in &d.notes {
                if reported_problems.insert(n.clone()) {
                    tracing::warn!(note = %n, "waf discovery");
                }
            }
            let logs = d.logs();
            if logs != discovered {
                discovered = logs;
                sources.rescan_soon();
            }
        }
        if sources.refresh(&cfg.waf, &discovered, &web, now) {
            let status = sources.status();
            if *lock(&shared.waf_sources) != status {
                tracing::info!(sources = %status, "waf sources");
                *lock(&shared.waf_sources) = status;
            }
        }
        for (path, why) in &sources.problems {
            if reported_problems.insert(format!("{}: {why}", path.display())) {
                tracing::warn!(path = %path.display(), error = %why, "waf source cannot be opened");
            }
        }
        let mut stats = PollStats::default();
        for src in sources.list.iter_mut() {
            let mismatched = stats.entries_mismatch;
            let hits = src.poll(20_000, &mut stats);
            if stats.entries_mismatch > mismatched && tampered.ready(&src.path, now) {
                sink.emit(tampered_event(&src.path, stats.entries_mismatch - mismatched, src.writable.as_deref()));
            }
            for h in hits {
                shared.metrics.inc(
                    "warden_waf_transactions_total",
                    &[("intercepted", if h.intercepted { "yes" } else { "no" })],
                    1.0,
                );
                for mut ev in tracker.on_hit(h, src.site.as_deref(), src.writable.as_deref(), &shared.waf, now) {
                    ev.source = "waf".into();
                    sink.emit(ev);
                }
            }
        }
        if stats != PollStats::default() {
            shared.metrics.inc("warden_waf_entries_total", &[("result", "mismatch")], stats.entries_mismatch as f64);
            shared.metrics.inc("warden_waf_entries_total", &[("result", "read")], stats.entries_read as f64);
            shared.metrics.inc("warden_waf_entries_total", &[("result", "missing")], stats.entries_missing as f64);
        }
        let (recent, recent_evicted) = shared.waf.stats();
        let (seen_evicted, window_evicted) = tracker.evicted();
        shared.metrics.set("warden_waf_sources", &[], sources.list.len() as f64);
        shared.metrics.set("warden_waf_recent_addresses", &[], recent as f64);
        shared.metrics.set("warden_state_evicted_total", &[("table", "waf_recent")], recent_evicted as f64);
        shared.metrics.set("warden_state_evicted_total", &[("table", "waf_dedup")], seen_evicted as f64);
        shared.metrics.set("warden_state_evicted_total", &[("table", "waf_window")], window_evicted as f64);
        // Poll once a second; a reload or shutdown wakes us at once.
        // A backlog (a flood, or a log found late) is read without pause.
        if !stats.saturated {
            shared.wait_reload(generation, Duration::from_secs(1));
        }
    }
}

/// How often the web servers' configuration is read again.
const DISCOVER_EVERY: Duration = Duration::from_secs(300);
/// One report per log in this time about entries changed after the fact.
const TAMPERED_PERIOD: Duration = Duration::from_secs(600);

/// Entries of a concurrent log no longer match the MD5 ModSecurity wrote
/// for them into the index: someone who can write the storage directory —
/// the web server's user, so possibly a webshell — rewrote them. They are
/// ignored; the event says where to look.
fn tampered_event(index: &std::path::Path, n: u64, writable: Option<&str>) -> Event {
    let mut ev = Event::new(
        "security.waf_log_tampered",
        Severity::Warning,
        format!(
            "{n} ModSecurity entr{} of {} changed after being written (MD5 differs from the index) — ignored",
            if n == 1 { "y" } else { "ies" },
            index.display()
        ),
    )
    // the subject is not the file: a policy acting on file subjects
    // (quarantine) must not take the index away
    .subject(Subject::System)
    .fingerprint(format!("security.waf_log_tampered:{}", index.display()))
    .detail("log", index.display().to_string())
    .detail("entries", n);
    if let Some(w) = writable {
        ev = ev.detail("log_trust", format!("writable by a web user: {w}"));
    }
    ev.source = "waf".into();
    ev
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
            for e in t.on_hit(h, Some("main"), None, &recent, now + Duration::from_secs(i)) {
                kinds.push((e.kind.clone(), e.actions.len()));
            }
        }
        assert_eq!(kinds.iter().filter(|k| k.0 == "security.waf_attack").count(), 1);
        assert!(kinds.iter().any(|k| k.0 == "security.waf_attack" && k.1 == 1));
        assert_eq!(recent.hits("203.0.113.5").unwrap().0, 5);
        // the same transaction logged twice counts once
        let mut t = WafTracker::new(&cfg, &[]);
        let h = parse_error_line(APACHE).unwrap();
        t.on_hit(h.clone(), None, None, &recent, now);
        assert!(t.on_hit(h, None, None, &recent, now).is_empty());
    }

    #[test]
    fn detection_only_and_ignored_rules() {
        let cfg = WafConfig { ignore_rules: vec!["949110".into()], ..Default::default() };
        let mut t = WafTracker::new(&cfg, &[]);
        let recent = WafRecent::default();
        assert!(t.on_hit(parse_error_line(APACHE).unwrap(), None, None, &recent, Instant::now()).is_empty());
        let warn = APACHE.replace("Access denied with code 403 (phase 2).", "Warning.");
        let mut t = WafTracker::new(&WafConfig::default(), &[]);
        assert!(t.on_hit(parse_error_line(&warn).unwrap(), None, None, &recent, Instant::now()).is_empty());
    }

    /// The 0.14.1 lab: an XSS request with a numeric Host header was
    /// reported as "Host header is a numeric IP address".
    #[test]
    fn the_headline_is_the_most_severe_attack_rule() {
        let v2 = r#"{"transaction":{"remote_address":"127.0.0.2","unique_id":"u1"},"request":{"request_line":"GET /xss.php?q=%3Cscript%3E HTTP/1.1"},"response":{"status":403},"audit_data":{"messages":["Warning. Host header is a numeric IP address [id \"920350\"] [msg \"Host header is a numeric IP address\"] [severity \"WARNING\"]","Warning. detected XSS [id \"941100\"] [msg \"XSS Attack Detected via libinjection\"] [severity \"CRITICAL\"]","Access denied [id \"949110\"] [msg \"Inbound Anomaly Score Exceeded (Total Score: 23)\"] [severity \"CRITICAL\"]"],"action":{"intercepted":true}}}"#;
        let h = parse_json_line(v2).unwrap();
        assert_eq!(h.summary(), Some("XSS Attack Detected via libinjection"));
        let v3 = r#"{"transaction":{"client_ip":"203.0.113.7","request":{"uri":"/x"},"response":{"http_code":403},"messages":[{"message":"Host header is a numeric IP address","details":{"ruleId":"920350","severity":"4"}},{"message":"Inbound Anomaly Score Exceeded","details":{"ruleId":"949110","severity":"2"}},{"message":"SQL Injection Attack Detected via libinjection","details":{"ruleId":"942100","severity":"2"}}]}}"#;
        assert_eq!(parse_json_line(v3).unwrap().summary(), Some("SQL Injection Attack Detected via libinjection"));
        // an evaluation rule alone still makes a headline
        assert_eq!(
            parse_error_line(APACHE).unwrap().summary(),
            Some("Inbound Anomaly Score Exceeded (Total Score: 5)")
        );
    }

    /// N15: a record padded with a large body is cut by the reader; it must
    /// still be counted.
    #[test]
    fn a_cut_json_record_is_salvaged() {
        let body = "A".repeat(2_000_000);
        let full = format!(
            r#"{{"transaction":{{"remote_address":"203.0.113.9","unique_id":"u9"}},"request":{{"request_line":"POST /login HTTP/1.1","body":["{body}"]}},"response":{{"status":403}},"audit_data":{{"messages":["Access denied [id \"942100\"] [msg \"SQL Injection Attack Detected via libinjection\"] [severity \"CRITICAL\"]"],"action":{{"intercepted":true}}}}}}"#
        );
        let cut = format!(
            "{}{}{}",
            &full[..crate::util::LINE_HEAD],
            crate::util::ELIDED,
            &full[full.len() - crate::util::LINE_TAIL..]
        );
        // cut inside the body string the record is still JSON
        assert_eq!(parse_json_line(&cut).unwrap().rule_ids, ["942100"]);
        // cut across the structure it is not, and is salvaged
        let broken = cut.replacen("\"request\":{", "\"request\":{{", 1);
        assert!(parse_json_line(&broken).is_none());
        let h = salvage_json_line(&broken).unwrap();
        assert_eq!(h.ip, Some("203.0.113.9".parse().unwrap()));
        assert_eq!(h.rule_ids, ["942100"]);
        assert!(h.intercepted);
        assert_eq!(h.uri.as_deref(), Some("/login"));
        // the line reader replaced an invalid byte: the record still parses
        let lossy = r#"{"transaction":{"client_ip":"203.0.113.8","request":{"uri":"/","headers":{"User-Agent":"\u{fffd}"}},"response":{"http_code":403},"messages":[{"message":"m","details":{"ruleId":"942100","severity":"2"}}]}}"#.replace("\\u{fffd}", "\u{fffd}");
        assert_eq!(parse_json_line(&lossy).unwrap().ip, Some("203.0.113.8".parse().unwrap()));
    }

    #[test]
    fn concurrent_index_lines() {
        let l = r#"www.example.com 203.0.113.5 - - [27/Oct/2026:12:00:00 +0300] "GET /?a=\"b c\" HTTP/1.1" 403 199 "-" "Mozilla/5.0 (X11; Linux)" YdEaYn8AAQEAAAABcdcAAAAA "-" /20261027/20261027-1200/20261027-120000-YdEaYn8AAQEAAAABcdcAAAAA 0 2345 md5:0123456789abcdef0123456789abcdef"#;
        let e = parse_index_line(l).unwrap();
        assert_eq!(e.host, "www.example.com");
        assert_eq!(e.ip, Some("203.0.113.5".parse().unwrap()));
        assert_eq!(e.file, "/20261027/20261027-1200/20261027-120000-YdEaYn8AAQEAAAABcdcAAAAA");
        assert_eq!(e.size, 2345);
        assert!(parse_index_line("not an index line").is_none());
        // ModSecurity 2.9.7 (Apache, Ubuntu 24.04): a user directory
        let l = r#"127.0.0.1 127.0.0.1 - - [27/Oct/2026:20:21:09.782516 +0000] "GET /?q=<script>alert(1)</script> HTTP/1.1" 403 276 "-" "-" auEHtULFnzBHB-1EbTje9QAAAAY "-" /www-data/20261027/20261027-2021/20261027-202109-auEHtULFnzBHB-1EbTje9QAAAAY 0 8048 md5:35875f66e22207b443c917c780c4006e"#;
        let e = parse_index_line(l).unwrap();
        assert_eq!(e.file, "/www-data/20261027/20261027-2021/20261027-202109-auEHtULFnzBHB-1EbTje9QAAAAY");
        assert_eq!(e.size, 8048);
        // libmodsecurity 3.0.12 (nginx connector 1.0.3)
        let l = r#"x.test 127.0.0.1 - [27/Oct/2026:20:25:00 +0000] "GET /?q=<script>alert(1)</script> HTTP/1.1" 403 162 - "curl/8.5.0" 17931327005.200553 - /var/log/nginx/eps/20261027/20261027-2025/20261027-202500-17931327005.200553 0 3750.000000 md5:2044f72e2b10ef7bb1f82d15ef4adbcb"#;
        let e = parse_index_line(l).unwrap();
        assert_eq!(e.host, "x.test");
        assert_eq!(e.ip, Some("127.0.0.1".parse().unwrap()));
        assert_eq!(e.file, "/var/log/nginx/eps/20261027/20261027-2025/20261027-202500-17931327005.200553");
        assert_eq!(e.size, 3750);
    }

    /// N5 for the WAF: a log a web account can write is flagged in the
    /// event; with `trust_writable_logs = false` it does not block.
    #[test]
    fn waf_evidence_from_a_web_writable_log() {
        let run = |trust: bool| {
            let cfg = WafConfig { block_after: 1, trust_writable_logs: trust, ..Default::default() };
            let mut t = WafTracker::new(&cfg, &[]);
            t.on_hit(
                parse_error_line(APACHE).unwrap(),
                None,
                Some("x.log is owned by www-data"),
                &WafRecent::default(),
                Instant::now(),
            )
            .into_iter()
            .find(|e| e.kind == "security.waf_attack")
            .unwrap()
        };
        let trusted = run(true);
        assert!(matches!(trusted.actions[..], [ActionSpec::BlockIp { .. }]));
        assert!(trusted.details["log_trust"].as_str().unwrap().contains("www-data"));
        let held = run(false);
        assert!(held.actions.is_empty());
        assert!(held.details.contains_key(warden_core::event::IP_BLOCK_OFF));
    }

    /// N2/N3: 120 000 distinct attackers. The recent table stays bounded
    /// and recording stays cheap (0.14.1 scanned the whole table, with a
    /// clock read per entry, for every new address past 50 000).
    #[test]
    fn a_flood_of_distinct_addresses_stays_bounded_and_cheap() {
        let r = WafRecent::default();
        let t0 = Instant::now();
        let rules = vec!["942100".to_owned(), "949110".to_owned()];
        let started = std::time::Instant::now();
        for i in 0..120_000u32 {
            let ip = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, (i >> 16) as u16, i as u16));
            r.record_at(ip, &rules, t0 + Duration::from_micros(u64::from(i)));
        }
        let (n, evicted) = r.stats();
        assert!(n <= RECENT_CAP, "{n}");
        assert!(evicted >= 70_000);
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        let last = IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 1, (119_999u32 & 0xffff) as u16));
        assert!(r.hits(&last.to_string()).is_some(), "the newest are kept");
    }
}
