//! Kernel resource limits (file handles, PIDs, conntrack) and network health.

use crate::runtime::{Cx, Detector};
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use warden_core::config::{LimitsConfig, NetworkConfig};
use warden_core::ratelimit::CounterRate;
use warden_core::{Event, GlobList, Level, LevelTracker, Severity, Transition};
use warden_sys::{net, system};

/// A bag of named threshold trackers.
#[derive(Debug, Default)]
pub struct Thresholds {
    trackers: HashMap<String, LevelTracker>,
    sustain: Duration,
    clear_after: Duration,
    repeat: Duration,
}

impl Thresholds {
    pub fn new(sustain: Duration, clear_after: Duration, repeat: Duration) -> Self {
        Self { trackers: HashMap::new(), sustain, clear_after, repeat }
    }

    pub fn update(&mut self, key: &str, now: std::time::Instant, value: f64, warn: f64, crit: f64) -> Transition {
        let raw = if value >= crit {
            Level::Critical
        } else if value >= warn {
            Level::Warning
        } else {
            Level::Ok
        };
        let (s, c, r) = (self.sustain, self.clear_after, self.repeat);
        self.trackers.entry(key.to_owned()).or_insert_with(|| LevelTracker::new(s, s, c, r)).update(now, raw)
    }

    pub fn worst(&self) -> Level {
        self.trackers.values().map(|t| t.level()).max().unwrap_or_default()
    }

    /// New timings from a reload; levels are kept.
    pub fn retune(&mut self, sustain: Duration, clear_after: Duration, repeat: Duration) {
        (self.sustain, self.clear_after, self.repeat) = (sustain, clear_after, repeat);
        for t in self.trackers.values_mut() {
            t.retune(sustain, sustain, clear_after, repeat);
        }
    }

    /// The trackers that are not OK, by key.
    pub fn open(&self) -> impl Iterator<Item = (&str, &LevelTracker)> {
        self.trackers.iter().filter(|(_, t)| t.level() > Level::Ok).map(|(k, t)| (k.as_str(), t))
    }

    /// Forget the trackers `keep` rejects (an interface that is gone),
    /// returning those that were not OK so that they can be resolved.
    pub fn retain(&mut self, keep: impl Fn(&str) -> bool) -> Vec<String> {
        let mut open = Vec::new();
        self.trackers.retain(|k, t| {
            let keep = keep(k);
            if !keep && t.level() > Level::Ok {
                open.push(k.clone());
            }
            keep
        });
        open
    }
}

fn sev_of(l: Level) -> Severity {
    if l == Level::Critical { Severity::Critical } else { Severity::Warning }
}

pub struct LimitsDetector {
    cfg: LimitsConfig,
    th: Thresholds,
}

/// What the limits detector reads on one tick.
#[derive(Debug, Clone, Copy, Default)]
pub struct LimitsSample {
    /// Open file handles and `fs.file-max`.
    pub files: Option<(u64, u64)>,
    /// Tasks (processes + threads), from loadavg.
    pub tasks: Option<u64>,
    pub pid_max: u64,
    pub threads_max: Option<u64>,
    /// Conntrack entries and `nf_conntrack_max`.
    pub conntrack: Option<(u64, u64)>,
}

impl LimitsSample {
    pub fn read() -> Self {
        Self {
            files: system::file_nr(),
            tasks: system::loadavg().ok().map(|l| l.total_tasks),
            pid_max: system::pid_max().unwrap_or(32768),
            threads_max: system::threads_max(),
            conntrack: net::conntrack(),
        }
    }
}

impl LimitsDetector {
    pub fn new(cfg: &LimitsConfig) -> Self {
        Self {
            cfg: cfg.clone(),
            th: Thresholds::new(Duration::from_secs(30), Duration::from_secs(120), Duration::from_secs(1800)),
        }
    }

    #[allow(clippy::too_many_arguments)] // one call site per limit; a builder would only add noise
    fn check(
        &mut self,
        cx: &Cx<'_>,
        kind: &str,
        what: &str,
        pct: f64,
        (warn, crit): (f64, f64),
        grow: Option<(&str, u64)>,
        extra: &[(&str, serde_json::Value)],
    ) {
        cx.metric("warden_limit_used_percent", &[("limit", kind)], (pct * 10.0).round() / 10.0);
        match self.th.update(kind, cx.now, pct, warn, crit) {
            Transition::Raised(l) | Transition::Repeated(l) if l > Level::Ok => {
                let mut ev =
                    Event::new(format!("limits.{kind}"), sev_of(l), format!("{what} at {pct:.1}% of the limit"))
                        .fingerprint(format!("limits.{kind}:{}", sev_of(l)))
                        .detail("used_percent", (pct * 10.0).round() / 10.0);
                for (k, v) in extra {
                    ev = ev.detail(*k, v.clone());
                }
                // Capacity limit about to be exhausted: grow it within RAM-derived
                // bounds (tuning.auto_grow) or say what would be done.
                if let Some((key, current)) = grow {
                    let ram = warden_sys::mem::meminfo().map(|m| m.total).unwrap_or(0);
                    match warden_core::tuning::grow(key, current, ram) {
                        Some(next) if cx.cfg.tuning.auto_grow => {
                            ev = ev.detail("auto_grow", format!("{key}: {current} → {next}")).actions(vec![
                                warden_core::ActionSpec::Sysctl { key: key.to_owned(), value: next.to_string() },
                            ]);
                        }
                        Some(next) => {
                            ev = ev.detail(
                                "suggestion",
                                format!("sysctl -w {key}={next}  (or enable [tuning] auto_grow = true)"),
                            );
                        }
                        None => {
                            ev = ev.detail("note", format!("{key} is already at the safe maximum for this RAM size"));
                        }
                    }
                }
                cx.emit(ev);
            }
            Transition::Cleared => cx.emit(
                Event::new(format!("limits.{kind}"), Severity::Info, format!("{what} back to normal ({pct:.1}%)"))
                    .fingerprint(format!("limits.{kind}:resolved"))
                    .resolved(),
            ),
            _ => {}
        }
    }
}

impl Detector for LimitsDetector {
    fn name(&self) -> &'static str {
        "limits"
    }

    fn interval(&self) -> Duration {
        self.cfg.interval
    }

    fn sections(&self) -> &'static [&'static str] {
        &["/limits"]
    }

    fn reconfigure(&mut self, cfg: &warden_core::Config) -> bool {
        self.cfg = cfg.limits.clone();
        true
    }

    fn close(&mut self) -> Vec<Event> {
        self.th
            .open()
            .filter_map(|(k, t)| crate::runtime::close_level(&format!("limits.{k}"), &format!("limits.{k}"), t))
            .collect()
    }

    fn tick(&mut self, cx: &mut Cx<'_>) {
        self.evaluate(cx, LimitsSample::read());
    }
}

impl LimitsDetector {
    pub fn evaluate(&mut self, cx: &Cx<'_>, s: LimitsSample) {
        let c = self.cfg.clone();
        if let Some((used, max)) = s.files
            && max > 0
        {
            let pct = used as f64 * 100.0 / max as f64;
            self.check(
                cx,
                "file_handles",
                "system-wide open files",
                pct,
                (c.file_warning_percent, c.file_critical_percent),
                Some(("fs.file-max", max)),
                &[
                    ("used", used.into()),
                    ("max", max.into()),
                    ("hint", "fs.file-max / per-service LimitNOFILE; look for descriptor leaks".into()),
                ],
            );
        }
        if let Some(tasks) = s.tasks {
            let pid_max = s.pid_max;
            let max = pid_max.min(s.threads_max.unwrap_or(u64::MAX));
            if max > 0 {
                let pct = tasks as f64 * 100.0 / max as f64;
                // Growing pid_max only helps when pid_max (not threads-max) binds.
                let grow = (max == pid_max).then_some(("kernel.pid_max", pid_max));
                self.check(
                    cx,
                    "pids",
                    "tasks (processes + threads)",
                    pct,
                    (c.pid_warning_percent, c.pid_critical_percent),
                    grow,
                    &[("tasks", tasks.into()), ("max", max.into())],
                );
            }
        }
        if let Some((count, max)) = s.conntrack
            && max > 0
        {
            let pct = count as f64 * 100.0 / max as f64;
            self.check(
                cx,
                "conntrack",
                "netfilter conntrack table",
                pct,
                (c.conntrack_warning_percent, c.conntrack_critical_percent),
                Some(("net.netfilter.nf_conntrack_max", max)),
                &[
                ("entries", count.into()),
                ("max", max.into()),
                ("hint", "when full, new connections are dropped: raise net.netfilter.nf_conntrack_max or check for a flood".into()),
            ]);
        }
        cx.shared.set_level("limits", &format!("{:?}", self.th.worst()).to_lowercase());
    }
}

// ---------------------------------------------------------------------------

pub struct NetworkDetector {
    cfg: NetworkConfig,
    ignore: GlobList,
    rates: HashMap<String, CounterRate>,
    th: Thresholds,
}

impl NetworkDetector {
    pub fn new(cfg: &NetworkConfig) -> Self {
        Self {
            ignore: GlobList::new(&cfg.ignore_interfaces),
            th: Thresholds::new(cfg.sustain, Duration::from_secs(120), Duration::from_secs(3600)),
            cfg: cfg.clone(),
            rates: HashMap::new(),
        }
    }

    fn rate(&mut self, key: &str, now: std::time::Instant, v: i64) -> f64 {
        self.rates.entry(key.to_owned()).or_default().update(now, v.max(0) as u64).unwrap_or(0.0)
    }

    /// Listening sockets whose accept queue is (nearly) full.
    fn saturated_listeners() -> Vec<serde_json::Value> {
        let socks: Vec<net::Socket> = net::tcp_sockets()
            .into_iter()
            .filter(|s| s.state == net::TCP_LISTEN && s.tx_queue > 0 && s.rx_queue * 10 >= s.tx_queue * 8)
            .collect();
        let inodes: HashSet<u64> = socks.iter().map(|s| s.inode).collect();
        let owners = net::socket_owners(&inodes);
        socks
            .iter()
            .map(|s| {
                let pid = owners.get(&s.inode).copied();
                let comm = pid.and_then(|p| warden_sys::process::read_stat(p).ok()).map(|s| s.comm);
                serde_json::json!({"listen": s.local.to_string(), "queue": s.rx_queue, "backlog": s.tx_queue, "pid": pid, "comm": comm})
            })
            .collect()
    }
}

/// The event kind and fingerprint base of a network tracker key.
fn net_condition(key: &str) -> (&'static str, String) {
    match key {
        "listen_overflow" => ("network.listen_overflow", "network.listen_overflow".into()),
        "syn_flood" => ("network.syn_flood", "network.syn_flood".into()),
        "retrans" => ("network.retransmits", "network.retransmits".into()),
        k => ("network.iface_errors", format!("network.iface_errors:{}", k.trim_start_matches("if:"))),
    }
}

impl Detector for NetworkDetector {
    fn name(&self) -> &'static str {
        "network"
    }

    fn interval(&self) -> Duration {
        self.cfg.interval
    }

    fn sections(&self) -> &'static [&'static str] {
        &["/network"]
    }

    fn reconfigure(&mut self, cfg: &warden_core::Config) -> bool {
        let c = &cfg.network;
        self.ignore = GlobList::new(&c.ignore_interfaces);
        self.th.retune(c.sustain, Duration::from_secs(120), Duration::from_secs(3600));
        self.cfg = c.clone();
        true
    }

    fn close(&mut self) -> Vec<Event> {
        self.th
            .open()
            .filter_map(|(k, t)| {
                let (kind, fp) = net_condition(k);
                crate::runtime::close_level(kind, &fp, t)
            })
            .collect()
    }

    fn tick(&mut self, cx: &mut Cx<'_>) {
        self.evaluate(cx, net::counters().ok().as_ref(), &net::net_dev().unwrap_or_default());
    }
}

/// `/proc/net/snmp` + `/proc/net/netstat` counters, by protocol.
pub type NetCounters = HashMap<String, HashMap<String, i64>>;

impl NetworkDetector {
    pub fn evaluate(&mut self, cx: &Cx<'_>, counters: Option<&NetCounters>, ifaces: &[net::IfStats]) {
        let now = cx.now;
        let c = self.cfg.clone();
        if let Some(m) = counters {
            let g = |p: &str, k: &str| m.get(p).and_then(|x| x.get(k)).copied().unwrap_or(0);
            let overflows = self.rate("ListenOverflows", now, g("TcpExt", "ListenOverflows"));
            let cookies = self.rate("SyncookiesSent", now, g("TcpExt", "SyncookiesSent"));
            let out = self.rate("OutSegs", now, g("Tcp", "OutSegs"));
            let retr = self.rate("RetransSegs", now, g("Tcp", "RetransSegs"));
            let retr_pct = if out > 100.0 { retr * 100.0 / out } else { 0.0 };
            cx.metric("warden_tcp_listen_overflows_per_second", &[], overflows);
            cx.metric("warden_tcp_syncookies_per_second", &[], cookies);
            cx.metric("warden_tcp_retransmit_percent", &[], retr_pct);
            cx.metric("warden_tcp_established", &[], g("Tcp", "CurrEstab") as f64);

            match self.th.update("listen_overflow", now, overflows, c.listen_overflows_per_sec, f64::INFINITY) {
                Transition::Raised(_) | Transition::Repeated(_) => cx.emit(
                    Event::new(
                        "network.listen_overflow",
                        Severity::Warning,
                        format!("accept queues overflowing: {overflows:.0} connections/s dropped"),
                    )
                    .fingerprint("network.listen_overflow:warning")
                    .detail("overflows_per_sec", overflows.round())
                    .detail("saturated_listeners", Self::saturated_listeners())
                    .detail("hint", "the application accepts connections too slowly (worker pool exhausted?) or backlog is too small"),
                ),
                Transition::Cleared => cx.emit(Self::resolved("listen_overflow", "accept queues no longer overflow")),
                _ => {}
            }
            match self.th.update("syn_flood", now, cookies, c.syncookies_per_sec, f64::INFINITY) {
                Transition::Raised(_) | Transition::Repeated(_) => cx.emit(
                    Event::new(
                        "network.syn_flood",
                        Severity::Warning,
                        format!("SYN flood suspected: {cookies:.0} SYN cookies/s"),
                    )
                    .fingerprint("network.syn_flood:warning")
                    .detail("syncookies_per_sec", cookies.round()),
                ),
                Transition::Cleared => cx.emit(Self::resolved("syn_flood", "SYN cookies back to normal")),
                _ => {}
            }
            match self.th.update("retrans", now, retr_pct, c.tcp_retrans_percent, f64::INFINITY) {
                Transition::Raised(_) => cx.emit(
                    Event::new(
                        "network.retransmits",
                        Severity::Warning,
                        format!("TCP retransmissions at {retr_pct:.1}% of segments"),
                    )
                    .fingerprint("network.retransmits:warning")
                    .detail("retrans_percent", (retr_pct * 10.0).round() / 10.0)
                    .detail("hint", "packet loss on the path, congested uplink or a failing NIC"),
                ),
                Transition::Cleared => cx.emit(Self::resolved("retrans", "TCP retransmissions back to normal")),
                _ => {}
            }
        }
        let mut live = HashSet::new();
        for i in ifaces {
            if self.ignore.is_match(&i.name) {
                continue;
            }
            let key = format!("if:{}", i.name);
            live.insert(key.clone());
            let errs = (i.rx_errs + i.rx_drop + i.tx_errs + i.tx_drop) as i64;
            let r = self.rate(&key, now, errs);
            cx.metric("warden_iface_errors_per_second", &[("iface", &i.name)], r);
            match self.th.update(&key, now, r, c.iface_errors_per_sec, f64::INFINITY) {
                Transition::Raised(_) => cx.emit(
                    Event::new("network.iface_errors", Severity::Warning, format!("{}: {r:.0} errors+drops/s", i.name))
                        .fingerprint(format!("network.iface_errors:{}:warning", i.name))
                        .detail("rx_errs", i.rx_errs)
                        .detail("rx_drop", i.rx_drop)
                        .detail("tx_errs", i.tx_errs)
                        .detail("tx_drop", i.tx_drop),
                ),
                Transition::Cleared => cx.emit(Self::resolved(&key, &format!("{}: errors back to normal", i.name))),
                _ => {}
            }
        }
        // Interfaces that are gone (containers, VMs, VPN tunnels come and
        // go by the thousand on some hosts): forget their counters,
        // trackers and metric series, and resolve what was open for them.
        // (0.13.3 kept them for ever, in locked memory.)
        let is_iface = |k: &str| k.starts_with("if:");
        self.rates.retain(|k, _| !is_iface(k) || live.contains(k));
        for key in self.th.retain(|k| !is_iface(k) || live.contains(k)) {
            cx.emit(Self::resolved(&key, &format!("{}: interface is gone", key.trim_start_matches("if:"))));
        }
        let gone: Vec<String> = cx
            .shared
            .metrics
            .label_values("warden_iface_errors_per_second", "iface")
            .into_iter()
            .filter(|n| !live.contains(&format!("if:{n}")))
            .collect();
        for n in gone {
            cx.shared.metrics.remove_matching("warden_iface_errors_per_second", "iface", &n);
        }
        cx.shared.set_level("network", &format!("{:?}", self.th.worst()).to_lowercase());
    }

    fn resolved(key: &str, title: &str) -> Event {
        let (kind, fp) = net_condition(key);
        Event::new(kind, Severity::Info, title).fingerprint(format!("{fp}:resolved")).resolved()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{Shared, Sink, lock};
    use std::time::Instant;

    /// Feed one sample per `step` seconds; returns (second, event) pairs.
    fn run<D, S: Copy>(
        d: &mut D,
        cfg: &warden_core::Config,
        step: u64,
        series: &[S],
        mut eval: impl FnMut(&mut D, &Cx<'_>, S),
    ) -> (Vec<(u64, Event)>, std::sync::Arc<Shared>) {
        let shared = Shared::new(cfg.clone());
        let (sink, events) = Sink::collector();
        let t0 = Instant::now();
        let mut out = Vec::new();
        for (i, s) in series.iter().enumerate() {
            let mut cx = Cx::new(&shared, cfg, &sink, "test");
            cx.now = t0 + Duration::from_secs(step * i as u64);
            eval(d, &cx, *s);
            out.extend(lock(&events).drain(..).map(|e| (step * i as u64, e)));
        }
        (out, shared)
    }

    fn files(pct: u64) -> LimitsSample {
        LimitsSample { files: Some((pct * 1000, 100_000)), pid_max: 4_194_304, ..Default::default() }
    }

    #[test]
    fn file_handles_warn_go_critical_suggest_growth_and_recover() {
        let cfg = warden_core::Config::default(); // 80 % / 95 %, sustain 30 s, clear after 120 s
        let mut d = LimitsDetector::new(&cfg.limits);
        let mut series = vec![files(50); 2];
        series.extend(vec![files(85); 4]); // 15 s ticks: 45 s over 80 %
        series.extend(vec![files(97); 4]);
        series.extend(vec![files(40); 12]);
        let (ev, shared) = run(&mut d, &cfg, 15, &series, |d, cx, s| d.evaluate(cx, s));
        let got: Vec<(u64, &str, Severity)> =
            ev.iter().map(|(t, e)| (*t, e.fingerprint.as_str(), e.severity)).collect();
        assert_eq!(
            got,
            [
                (60, "limits.file_handles:warning", Severity::Warning),
                (120, "limits.file_handles:critical", Severity::Critical),
                (270, "limits.file_handles:resolved", Severity::Info),
            ]
        );
        // not auto_grow by default: says what it would do
        assert!(ev[0].1.actions.is_empty());
        assert!(
            ev[0].1.details["suggestion"].as_str().unwrap().starts_with("sysctl -w fs.file-max="),
            "{:?}",
            ev[0].1.details
        );
        assert_eq!(lock(&shared.levels)["limits"], "ok");
    }

    #[test]
    fn with_auto_grow_the_limit_is_raised_by_an_action() {
        let mut cfg = warden_core::Config::default();
        cfg.tuning.auto_grow = true;
        let mut d = LimitsDetector::new(&cfg.limits);
        let full = LimitsSample { conntrack: Some((9_700, 10_000)), ..Default::default() };
        let (ev, _) = run(&mut d, &cfg, 15, &[full; 4], |d, cx, s| d.evaluate(cx, s));
        let crit = ev.iter().map(|(_, e)| e).find(|e| e.severity == Severity::Critical).expect("critical");
        assert_eq!(crit.kind, "limits.conntrack");
        match &crit.actions[..] {
            [warden_core::ActionSpec::Sysctl { key, value }] => {
                assert_eq!(key, "net.netfilter.nf_conntrack_max");
                assert!(value.parse::<u64>().unwrap() > 10_000);
            }
            a => panic!("{a:?}"),
        }
    }

    #[test]
    fn pid_usage_is_measured_against_the_binding_limit() {
        let cfg = warden_core::Config::default(); // 75 % / 90 %
        let mut d = LimitsDetector::new(&cfg.limits);
        // threads-max binds (smaller than pid_max): no pid_max growth advice
        let s = LimitsSample { tasks: Some(800), pid_max: 4_194_304, threads_max: Some(1000), ..Default::default() };
        let (ev, _) = run(&mut d, &cfg, 15, &[s; 4], |d, cx, s| d.evaluate(cx, s));
        let e = &ev[0].1;
        assert_eq!(e.fingerprint, "limits.pids:warning");
        assert_eq!(e.details["max"], 1000);
        assert!(!e.details.contains_key("suggestion") && e.actions.is_empty());
    }

    #[test]
    fn network_counters_become_rates_and_need_to_be_sustained() {
        let cfg = warden_core::Config::default(); // 5 overflows/s, 50 cookies/s, 10 errors/s, sustain 30 s
        let mut d = NetworkDetector::new(&cfg.network);
        let shared = Shared::new(cfg.clone());
        let (sink, events) = Sink::collector();
        let t0 = Instant::now();
        let (mut overflows, mut errs) = (0i64, 0u64);
        for i in 0..10u64 {
            let mut cx = Cx::new(&shared, &cfg, &sink, "test");
            cx.now = t0 + Duration::from_secs(10 * i);
            // 20 overflows/s from the second tick on; eth0 errors only for one tick
            if i >= 1 {
                overflows += 200;
            }
            if i == 3 {
                errs += 5000;
            }
            let mut m: NetCounters = HashMap::new();
            m.entry("TcpExt".into()).or_default().insert("ListenOverflows".into(), overflows);
            let ifs = [
                net::IfStats { name: "eth0".into(), rx_errs: errs, ..Default::default() },
                net::IfStats { name: "veth1234".into(), rx_drop: 1_000_000 * i, ..Default::default() },
            ];
            d.evaluate(&cx, Some(&m), &ifs);
        }
        let titles: Vec<String> = lock(&events).iter().map(|e| e.title.clone()).collect();
        assert_eq!(
            titles,
            ["accept queues overflowing: 20 connections/s dropped"],
            "a 10 s error spike and an ignored veth do not count"
        );
    }

    /// Every network condition is resolved, and an interface that goes
    /// away takes its counters, tracker and metric series with it.
    #[test]
    fn network_conditions_resolve_and_vanished_interfaces_are_forgotten() {
        let cfg = warden_core::Config::default(); // sustain 30 s, clear after 120 s
        let mut d = NetworkDetector::new(&cfg.network);
        let shared = Shared::new(cfg.clone());
        let (sink, events) = Sink::collector();
        let t0 = Instant::now();
        let (mut overflows, mut errs) = (0i64, 0u64);
        for i in 0..40u64 {
            let mut cx = Cx::new(&shared, &cfg, &sink, "test");
            cx.now = t0 + Duration::from_secs(10 * i);
            if (1..10).contains(&i) {
                overflows += 200; // 20/s for 90 s
                errs += 500; // 50 errors/s on wg0
            }
            let mut m: NetCounters = HashMap::new();
            m.entry("TcpExt".into()).or_default().insert("ListenOverflows".into(), overflows);
            let mut ifs = vec![net::IfStats { name: "eth0".into(), ..Default::default() }];
            if i < 20 {
                ifs.push(net::IfStats { name: "wg0".into(), rx_errs: errs, ..Default::default() });
            }
            d.evaluate(&cx, Some(&m), &ifs);
        }
        let fps: Vec<String> = lock(&events).iter().map(|e| e.fingerprint.clone()).collect();
        assert!(fps.contains(&"network.listen_overflow:warning".to_owned()), "{fps:?}");
        assert!(fps.contains(&"network.listen_overflow:resolved".to_owned()), "{fps:?}");
        assert!(fps.contains(&"network.iface_errors:wg0:warning".to_owned()), "{fps:?}");
        assert!(fps.contains(&"network.iface_errors:wg0:resolved".to_owned()), "{fps:?}");
        assert!(!d.rates.contains_key("if:wg0") && d.rates.contains_key("if:eth0"));
        let ifaces = shared.metrics.label_values("warden_iface_errors_per_second", "iface");
        assert_eq!(ifaces, ["eth0"]);
        // closing an open condition (the detector disabled by a reload)
        assert!(d.close().is_empty(), "nothing is open any more");
    }

    #[test]
    fn thresholds_track_independently() {
        let mut t = Thresholds::new(Duration::ZERO, Duration::ZERO, Duration::ZERO);
        let now = std::time::Instant::now();
        assert_eq!(t.update("a", now, 90.0, 80.0, 95.0), Transition::Raised(Level::Warning));
        assert_eq!(t.update("b", now, 10.0, 80.0, 95.0), Transition::None);
        assert_eq!(t.update("a", now, 99.0, 80.0, 95.0), Transition::Raised(Level::Critical));
        assert_eq!(t.worst(), Level::Critical);
    }
}
