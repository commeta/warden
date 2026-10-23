//! Web access-log correlation ("patient zero" search).
//!
//! When a script appears or changes, the request that caused it is almost
//! always in the access log a few seconds earlier: usually a POST to a
//! rarely requested script (the vulnerable plugin or an already planted
//! dropper). Requests that later hit a flagged file are the attacker using
//! the webshell — those IPs get blocked.

use crate::runtime::{SensorState, Shared, lock};
use crate::util::FileTail;
use serde::Serialize;
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// HTTP method, one byte instead of a heap string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
    Other,
}

impl Method {
    pub fn parse(s: &str) -> Self {
        match s {
            "GET" => Self::Get,
            "HEAD" => Self::Head,
            "POST" => Self::Post,
            "PUT" => Self::Put,
            "PATCH" => Self::Patch,
            "DELETE" => Self::Delete,
            "OPTIONS" => Self::Options,
            _ => Self::Other,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
            Self::Other => "OTHER",
        }
    }

    pub fn writes(&self) -> bool {
        matches!(self, Self::Post | Self::Put | Self::Patch)
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One access-log request, compact: ~56 bytes plus a shared path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub seq: u64,
    /// Unix seconds (from the log line).
    pub ts: i64,
    pub ip: IpAddr,
    pub method: Method,
    /// Shared with every other request for the same path.
    pub path: Arc<str>,
    pub status: u16,
}

fn month(m: &str) -> Option<u32> {
    Some(match m {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    })
}

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let m = m as i64;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Parse `10/Oct/2026:13:55:36 +0300` to Unix seconds.
pub fn parse_clf_time(s: &str) -> Option<i64> {
    let (dt, tz) = s.split_once(' ').unwrap_or((s, "+0000"));
    let mut p = dt.splitn(4, [':', '/']);
    let day: u32 = p.next()?.parse().ok()?;
    let mon = month(p.next()?)?;
    let year: i64 = p.next()?.parse().ok()?;
    let hms: Vec<i64> = p.next()?.split(':').filter_map(|x| x.parse().ok()).collect();
    // Out-of-range fields are not a time: unchecked, a forged
    // `[01/Oct/2026:9999999999999:…]` overflowed the arithmetic below
    // (a panic in a debug build, a wrapped, arbitrary time in a release one;
    // found by the access_log fuzz target).
    if hms.len() != 3
        || !(1..=31).contains(&day)
        || !(1970..=9999).contains(&year)
        || !(0..24).contains(&hms[0])
        || !(0..60).contains(&hms[1])
        || !(0..=60).contains(&hms[2])
    {
        return None;
    }
    let sign = if tz.starts_with('-') { -1 } else { 1 };
    let tzd = tz.trim_start_matches(['+', '-']);
    // `get`, not slicing: a non-ASCII zone (servers that do not escape)
    // must not panic the sensor (0.13.3: restarted with backoff, for up to
    // ten minutes without correlation)
    let off = match (tzd.len(), tzd.get(..2), tzd.get(2..)) {
        (4, Some(h), Some(m)) => {
            let (h, m) = (h.parse::<i64>().ok()?, m.parse::<i64>().ok()?);
            if h > 14 || m > 59 {
                return None;
            }
            h * 3600 + m * 60
        }
        _ => 0,
    };
    Some(days_from_civil(year, mon, day) * 86400 + hms[0] * 3600 + hms[1] * 60 + hms[2] - sign * off)
}

/// Parse a combined/common log format line (nginx & Apache defaults).
///
/// `ip ident user [time] "request" status size …`: the user comes from the
/// client's `Authorization` header and may contain `[` and `]` (servers
/// escape quotes, not brackets), so the time is the **last** bracketed
/// field before the request's opening quote. (0.13.3 took the first `[`:
/// one request with `[01/Jan/2099:…]` as its user pushed every other
/// request out of the ring.)
pub fn parse_line(line: &str) -> Option<Request> {
    let (ip, rest) = line.split_once(' ')?;
    let q0 = rest.find('"')?;
    let head = &rest[..q0];
    let lb = head.rfind('[')?;
    let rb = head[lb..].find(']')? + lb;
    let ts = parse_clf_time(&head[lb + 1..rb])?;
    let after = &rest[rb + 1..];
    let q1 = after.find('"')?;
    let q2 = after[q1 + 1..].find('"')? + q1 + 1;
    let req = &after[q1 + 1..q2];
    let mut parts = req.split_whitespace();
    let method = Method::parse(parts.next()?);
    let target = parts.next().unwrap_or("");
    let path: Arc<str> = target.split(['?', '#']).next().unwrap_or("").into();
    let status = after[q2 + 1..].split_whitespace().next()?.parse().ok()?;
    let ip = warden_core::net::canonical(ip.parse().ok()?);
    Some(Request { seq: 0, ts, ip, method, path, status })
}

#[derive(Debug, Default)]
pub struct AccessRing {
    reqs: VecDeque<Request>,
    /// When each request was read (Unix seconds), parallel to `reqs`: the
    /// ring is bounded by when requests arrived, not by the time written in
    /// the line — a line from a skewed or forged clock cannot empty it.
    received: VecDeque<i64>,
    /// Requests per path in the ring; its keys are the shared paths.
    counts: HashMap<Arc<str>, u32>,
    next_seq: u64,
}

/// Bounds of the per-site ring: the correlation looks seconds to minutes
/// back from a file write, so keeping more than 15 minutes (or 50 000
/// requests) only costs memory on busy sites.
const RING_CAP: usize = 50_000;
const RING_AGE_SECS: i64 = 15 * 60;

impl AccessRing {
    pub fn push(&mut self, r: Request) {
        let now =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        self.push_at(r, now);
    }

    /// [`AccessRing::push`] of a request read at `received`.
    pub fn push_at(&mut self, mut r: Request, received: i64) {
        self.next_seq += 1;
        r.seq = self.next_seq;
        match self.counts.get_key_value(&*r.path) {
            Some((k, _)) => r.path = k.clone(),
            None => {
                self.counts.insert(r.path.clone(), 0);
            }
        }
        if let Some(c) = self.counts.get_mut(&*r.path) {
            *c += 1;
        }
        self.reqs.push_back(r);
        self.received.push_back(received);
        while self.reqs.len() > RING_CAP || self.received.front().is_some_and(|t| received - t > RING_AGE_SECS) {
            self.received.pop_front();
            let Some(old) = self.reqs.pop_front() else { break };
            if let Some(c) = self.counts.get_mut(&*old.path) {
                *c -= 1;
                if *c == 0 {
                    self.counts.remove(&*old.path);
                }
            }
        }
    }

    pub fn len(&self) -> usize {
        self.reqs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.reqs.is_empty()
    }

    pub fn since(&self, seq: u64) -> Vec<Request> {
        self.reqs.iter().filter(|r| r.seq > seq).cloned().collect()
    }

    pub fn last_seq(&self) -> u64 {
        self.next_seq
    }

    /// Requests around `ts` that could have produced a file write, ranked:
    /// POSTs first, then rarely requested script endpoints.
    pub fn suspects(&self, ts: i64, window: i64, limit: usize) -> Vec<serde_json::Value> {
        let script_ext = [".php", ".phtml", ".php5", ".php7", ".phar", ".asp", ".aspx", ".jsp", ".cgi", ".pl", ".py"];
        let mut v: Vec<(i64, &Request)> = self
            .reqs
            .iter()
            .filter(|r| (r.ts - ts).abs() <= window && r.ts <= ts + 2)
            .filter(|r| {
                r.method != Method::Get
                    || script_ext.iter().any(|e| ends_with_ignore_case(&r.path, e))
                    || r.path.contains("/api/")
            })
            .map(|r| {
                let mut rank = 0i64;
                if r.method.writes() {
                    rank += 100;
                }
                let n = self.counts.get(&*r.path).copied().unwrap_or(0) as i64;
                rank += (50 - n.min(50)).max(0);
                if (200..300).contains(&r.status) {
                    rank += 10;
                }
                rank -= (r.ts - ts).abs();
                (rank, r)
            })
            .collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.0));
        v.into_iter()
            .take(limit)
            .map(|(rank, r)| {
                serde_json::json!({
                    "ip": r.ip.to_string(), "method": r.method.as_str(), "path": &*r.path, "status": r.status,
                    "offset_seconds": r.ts - ts, "path_hits": self.counts.get(&*r.path).copied().unwrap_or(0), "rank": rank,
                })
            })
            .collect()
    }
}

fn ends_with_ignore_case(s: &str, suffix: &str) -> bool {
    s.len() >= suffix.len() && s.as_bytes()[s.len() - suffix.len()..].eq_ignore_ascii_case(suffix.as_bytes())
}

/// Per-site rings, shared between the tailer and the FIM worker.
#[derive(Debug, Default)]
pub struct AccessLogs {
    sites: Mutex<HashMap<String, AccessRing>>,
}

impl AccessLogs {
    pub fn push(&self, site: &str, r: Request) {
        lock(&self.sites).entry(site.to_owned()).or_default().push(r);
    }

    pub fn with<R>(&self, site: &str, f: impl FnOnce(&AccessRing) -> R) -> Option<R> {
        lock(&self.sites).get(site).map(f)
    }
}

/// Sensor: tail every configured access log into the rings.
pub fn run_access_tail(shared: &Arc<Shared>) -> Result<(), String> {
    let cfg = shared.config();
    let logs: Vec<(String, std::path::PathBuf)> =
        cfg.fim.sites.iter().filter_map(|s| s.access_log.clone().map(|p| (s.name.clone(), p))).collect();
    if !cfg.fim.enabled || logs.is_empty() {
        return Ok(());
    }
    let generation = shared.generation();
    let mut tails: Vec<(String, FileTail)> = logs.into_iter().map(|(n, p)| (n, FileTail::new(p))).collect();
    shared.set_sensor("access_log", SensorState::Running);
    loop {
        if shared.generation() != generation {
            return Err("configuration reloaded".into());
        }
        if shared.is_shutting_down() {
            return Ok(());
        }
        for (site, t) in tails.iter_mut() {
            for line in t.poll(20_000) {
                if let Some(r) = parse_line(&line) {
                    shared.access.push(site, r);
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

    /// Found by the access_log fuzz target: out-of-range fields overflowed
    /// the arithmetic (a panic in debug builds, a wrapped time in release).
    #[test]
    fn out_of_range_times_are_rejected() {
        for bad in [
            "20/Oct/2026:9999999999999:00:00 +0000",
            "20/Oct/99999999999999:12:00:00 +0000",
            "99/Oct/2026:12:00:00 +0000",
            "20/Oct/2026:12:61:00 +0000",
            "20/Oct/2026:12:00:00 +9959",
        ] {
            assert_eq!(parse_clf_time(bad), None, "{bad}");
        }
        assert_eq!(parse_clf_time("01/Jan/1970:00:00:00 +0000"), Some(0));
        assert_eq!(parse_clf_time("31/Dec/2026:23:59:60 -1400"), Some(1_798_761_600 + 14 * 3600));
    }

    #[test]
    fn clf_time() {
        assert_eq!(parse_clf_time("01/Jan/1970:00:00:00 +0000"), Some(0));
        assert_eq!(parse_clf_time("20/Oct/2026:12:00:00 +0300"), Some(1792486800));
        assert_eq!(parse_clf_time("29/Feb/2024:23:59:59 -0100"), Some(1709254799));
        assert!(parse_clf_time("bogus").is_none());
    }

    #[test]
    fn combined_log_line() {
        let r = parse_line(r#"203.0.113.5 - - [20/Oct/2026:12:00:00 +0300] "POST /wp-content/plugins/x/up.php?a=1 HTTP/1.1" 200 12 "-" "curl/8""#).unwrap();
        assert_eq!(r.ip.to_string(), "203.0.113.5");
        assert_eq!(r.method, Method::Post);
        assert_eq!(&*r.path, "/wp-content/plugins/x/up.php");
        assert_eq!(r.status, 200);
        assert!(parse_line("garbage").is_none());
    }

    #[test]
    fn suspects_rank_rare_posts_first() {
        let mut ring = AccessRing::default();
        let t = 1_000_000;
        for i in 0..100 {
            ring.push(Request {
                seq: 0,
                ts: t - 100 + i,
                ip: "198.51.100.1".parse().unwrap(),
                method: Method::Get,
                path: "/index.php".into(),
                status: 200,
            });
        }
        ring.push(Request {
            seq: 0,
            ts: t - 3,
            ip: "203.0.113.66".parse().unwrap(),
            method: Method::Post,
            path: "/wp-content/plugins/vuln/upload.php".into(),
            status: 200,
        });
        ring.push(Request {
            seq: 0,
            ts: t - 1,
            ip: "198.51.100.1".parse().unwrap(),
            method: Method::Get,
            path: "/style.css".into(),
            status: 200,
        });
        let s = ring.suspects(t, 30, 5);
        assert_eq!(s[0]["ip"], "203.0.113.66");
        assert!(s.iter().all(|x| x["path"] != "/style.css"));
        assert_eq!(ring.since(100).len(), 2);
        // paths are shared, not copied per request
        let a = ring.reqs.front().unwrap().path.clone();
        assert!(Arc::ptr_eq(&a, &ring.reqs[1].path));
    }

    fn req(ts: i64) -> Request {
        Request { seq: 0, ts, ip: "192.0.2.1".parse().unwrap(), method: Method::Get, path: "/".into(), status: 200 }
    }

    #[test]
    fn ring_is_bounded_by_age() {
        let mut ring = AccessRing::default();
        for i in 0..1000 {
            ring.push_at(req(i * 10), i * 10);
        }
        assert!(ring.len() <= (RING_AGE_SECS / 10 + 1) as usize, "{}", ring.len());
    }

    /// A line whose time is in 2099 — a skewed clock, or (0.13.3) a forged
    /// user name — does not evict the requests that came before it.
    #[test]
    fn a_line_from_the_future_does_not_empty_the_ring() {
        let mut ring = AccessRing::default();
        let now = 1_792_486_800;
        for i in 0..100 {
            ring.push_at(req(now - 100 + i), now - 100 + i);
        }
        ring.push_at(req(4_070_908_800), now); // 2099
        assert_eq!(ring.len(), 101);
    }

    /// The user field comes from the client and may carry brackets.
    #[test]
    fn a_forged_time_in_the_user_field_is_not_taken() {
        let line = r#"203.0.113.9 - [01/Jan/2099:00:00:00 +0000] [20/Oct/2026:12:00:00 +0300] "POST /x.php HTTP/1.1" 200 1 "-" "-""#;
        let r = parse_line(line).unwrap();
        assert_eq!(r.ts, 1792486800);
        assert_eq!(&*r.path, "/x.php");
        let tricky = r#"203.0.113.9 - a]b[c [20/Oct/2026:12:00:00 +0300] "GET / HTTP/1.1" 404 1"#;
        assert_eq!(parse_line(tricky).unwrap().status, 404);
    }

    #[test]
    fn a_non_ascii_zone_does_not_panic() {
        assert_eq!(parse_clf_time("20/Oct/2026:12:00:00 +ж0"), Some(1792497600));
        // four bytes, the second boundary inside a letter: 0.13.3 panicked here
        assert_eq!(parse_clf_time("20/Oct/2026:12:00:00 +aжb"), Some(1792497600));
        // (0.13.3 panicked slicing the two-byte letter in half)
        assert!(parse_line("203.0.113.9 - - [20/Oct/2026:12:00:00 +жж] \"GET / HTTP/1.1\" 200 1").is_none());
    }
}
