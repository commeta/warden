//! Kernel log analysis (`/dev/kmsg`) and kernel state (taint, modules, LSM).

use crate::runtime::{Cx, Detector, SensorState, Shared};
use regex::{Regex, RegexSet};
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::{Duration, Instant};
use warden_core::config::{KernelConfig, KmsgPattern};
use warden_core::ratelimit::{Cooldown, KeyedWindow};
use warden_core::units::truncate;
use warden_core::{ActionSpec, Event, Severity, Subject};
use warden_sys::{kernel, kmsg};

/// What a built-in rule turns into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Special {
    None,
    OomKill,
    HungTask,
    Segfault,
    LsmDenial,
    IoError,
    LinkDown,
    LinkUp,
}

#[derive(Debug)]
struct Rule {
    kind: String,
    severity: Severity,
    re: Regex,
    title: Option<String>,
    actions: Vec<ActionSpec>,
    special: Special,
}

/// Built-in kernel message rules: (kind, severity, regex, special handling).
const BUILTIN: &[(&str, Severity, &str, Special)] = &[
    // Printed just before "Killed process": names the cgroup (service /
    // container) whose limit was hit. Same fingerprint, so the later line is
    // deduplicated and this richer one wins.
    (
        "kernel.oom_kill",
        Severity::Warning,
        r"oom-kill:constraint=(?P<constraint>\w+).*?(?:oom_memcg=(?P<memcg>[^,]*),)?task_memcg=(?P<task_memcg>[^,]*),task=(?P<comm>[^,]+),pid=(?P<pid>\d+),uid=(?P<uid>\d+)",
        Special::OomKill,
    ),
    (
        "kernel.oom_kill",
        Severity::Warning,
        r"(?:Memory cgroup out of memory|Out of memory)(?:[^:]*)?: Killed process (?P<pid>\d+) \((?P<comm>[^)]*)\)",
        Special::OomKill,
    ),
    (
        "kernel.hung_task",
        Severity::Warning,
        r"task (?P<comm>.+?):(?P<pid>\d+) blocked for more than (?P<secs>\d+) seconds",
        Special::HungTask,
    ),
    (
        "kernel.soft_lockup",
        Severity::Critical,
        r"(?:watchdog: )?BUG: soft lockup - CPU#(?P<cpu>\d+) stuck for (?P<secs>\d+)s",
        Special::None,
    ),
    ("kernel.hard_lockup", Severity::Critical, r"Watchdog detected hard LOCKUP on cpu (?P<cpu>\d+)", Special::None),
    ("kernel.rcu_stall", Severity::Warning, r"rcu: INFO: rcu_\w+ (?:self-)?detected stalls?", Special::None),
    (
        "kernel.oops",
        Severity::Critical,
        r"(?:BUG: unable to handle|Oops: |kernel BUG at|Kernel panic - not syncing|general protection fault, .*\bKernel\b)",
        Special::None,
    ),
    (
        "kernel.fs_error",
        Severity::Critical,
        r"(?:EXT4-fs error|EXT4-fs \(\S+\): Remounting filesystem read-only|XFS \(\S+\): (?:Corruption|Metadata corruption|log I/O error|Filesystem has been shut down)|BTRFS (?:error|critical)|F2FS-fs \(\S+\) : inconsistent)",
        Special::None,
    ),
    (
        "kernel.io_error",
        Severity::Warning,
        r"(?:I/O error, dev (?P<dev>\w+), sector|Buffer I/O error on dev (?P<dev2>\w+)|critical medium error, dev (?P<dev3>\w+)|nvme\w*: (?:I/O \d+ QID \d+ timeout|controller is down)|ata\d+(?:\.\d+)?: (?:failed command|exception Emask))",
        Special::IoError,
    ),
    (
        "kernel.segfault",
        Severity::Info,
        r"(?P<comm>[^\s\[]+)\[(?P<pid>\d+)\]: (?:segfault at|general protection fault|trap invalid opcode)",
        Special::Segfault,
    ),
    (
        "hardware.mce",
        Severity::Warning,
        r"(?:mce: \[Hardware Error\]|Machine check events logged|EDAC MC\d+: \d+ UE)",
        Special::None,
    ),
    (
        "network.conntrack_full",
        Severity::Critical,
        r"nf_conntrack: (?:nf_conntrack: )?table full, dropping packet",
        Special::None,
    ),
    (
        "network.syn_flood_kernel",
        Severity::Warning,
        r"Possible SYN flooding on port (?P<port>[\d.:\[\]a-f]+)",
        Special::None,
    ),
    ("network.link_down", Severity::Warning, r"(?P<iface>\S+): Link is Down", Special::LinkDown),
    ("network.link_up", Severity::Info, r"(?P<iface>\S+): Link is Up", Special::LinkUp),
    (
        "lsm.apparmor_denied",
        Severity::Info,
        r#"apparmor="DENIED" operation="(?P<op>[^"]+)".*?profile="(?P<profile>[^"]+)"(?:.*?name="(?P<name>[^"]+)")?.*?comm="(?P<comm>[^"]+)""#,
        Special::LsmDenial,
    ),
    (
        "lsm.selinux_denied",
        Severity::Info,
        r#"avc:\s+denied\s+\{ (?P<op>[^}]+) \} for .*?comm="(?P<comm>[^"]+)"(?:.*?name="(?P<name>[^"]+)")?"#,
        Special::LsmDenial,
    ),
    (
        "kernel.unsigned_module",
        Severity::Warning,
        r"module verification failed: signature and/or required key missing",
        Special::None,
    ),
    ("kernel.out_of_tree_module", Severity::Notice, r"loading out-of-tree module taints kernel", Special::None),
    (
        "hardware.thermal_throttle",
        Severity::Warning,
        r"CPU\d+: (?:Core|Package) temperature above threshold, cpu clock throttled",
        Special::None,
    ),
    ("storage.nfs_unresponsive", Severity::Warning, r"nfs: server (?P<server>\S+) not responding", Special::None),
    (
        "security.kernel_lockdown_violation",
        Severity::Warning,
        r"Lockdown: (?P<comm>[^:]+): .* is restricted",
        Special::None,
    ),
];

fn compile(cfg: &KernelConfig) -> Vec<Rule> {
    let mut rules: Vec<Rule> = BUILTIN
        .iter()
        .filter_map(|(k, s, re, sp)| {
            let actions = match sp {
                Special::OomKill => cfg.on_oom_kill.clone(),
                Special::HungTask => cfg.on_hung_task.clone(),
                _ => Vec::new(),
            };
            Some(Rule { kind: (*k).into(), severity: *s, re: Regex::new(re).ok()?, title: None, actions, special: *sp })
        })
        .collect();
    rules.extend(cfg.patterns.iter().filter_map(|p: &KmsgPattern| {
        Some(Rule {
            kind: p.kind.clone(),
            severity: p.severity,
            re: Regex::new(&p.regex).ok()?,
            title: p.title.clone(),
            actions: p.actions.clone(),
            special: Special::None,
        })
    }));
    rules
}

/// Stateful analyzer: matches records, rate-limits floods, aggregates bursts.
pub struct KmsgAnalyzer {
    rules: Vec<Rule>,
    /// All rules in one automaton: a line that matches nothing (almost all
    /// of them) costs one scan instead of one per rule.
    set: RegexSet,
    cooldown: Cooldown<String>,
    bursts: KeyedWindow<String>,
    segfault_burst: usize,
    lsm_burst: usize,
    /// Last reported state of each network link (`true` = up). Link events
    /// are state changes: each one is reported once, however close the next
    /// one follows — a time-based cooldown would swallow the "down" of a
    /// down-up-down flap and leave the link looking up.
    links: HashMap<String, bool>,
}

/// Interfaces whose link state is remembered (a host has a handful; the
/// bound only matters for a flood of invented names).
const MAX_LINKS: usize = 1024;

impl KmsgAnalyzer {
    pub fn new(cfg: &KernelConfig) -> Self {
        let rules = compile(cfg);
        let set = RegexSet::new(rules.iter().map(|r| r.re.as_str())).unwrap_or_else(|_| RegexSet::empty());
        Self {
            rules,
            set,
            cooldown: Cooldown::new(Duration::from_secs(60)),
            bursts: KeyedWindow::new(Duration::from_secs(300)),
            segfault_burst: cfg.segfault_burst.max(1),
            lsm_burst: cfg.lsm_denial_burst.max(1),
            links: HashMap::new(),
        }
    }

    pub fn analyze(&mut self, msg: &str, now: Instant) -> Vec<Event> {
        let mut out = Vec::new();
        let matched = self.set.matches(msg);
        if !matched.matched_any() {
            return out;
        }
        for (i, r) in self.rules.iter().enumerate() {
            if !matched.matched(i) {
                continue;
            }
            let Some(caps) = r.re.captures(msg) else { continue };
            let get = |n: &str| caps.name(n).map(|m| m.as_str().to_owned());
            let mut ev = Event::new(r.kind.clone(), r.severity, r.title.clone().unwrap_or_else(|| truncate(msg, 200)))
                .detail("message", truncate(msg, 1000))
                .actions(r.actions.clone());
            for n in r.re.capture_names().flatten() {
                if let Some(v) = get(n) {
                    ev = ev.detail(n.trim_end_matches(char::is_numeric), v);
                }
            }
            let key = match r.special {
                Special::OomKill => {
                    let pid = get("pid").unwrap_or_default();
                    let comm = get("comm").unwrap_or_default();
                    ev.title = format!("kernel OOM killer killed {comm}[{pid}]");
                    let memcg = get("memcg").filter(|m| !m.is_empty() && m != "/");
                    if get("constraint").as_deref() == Some("CONSTRAINT_MEMCG")
                        && let Some(cg) = memcg.as_deref().or(get("task_memcg").as_deref())
                    {
                        let who = warden_sys::cgroup::container_of(cg)
                            .or_else(|| warden_sys::cgroup::unit_of(cg))
                            .unwrap_or_else(|| cg.to_owned());
                        ev.title = format!("{who} hit its memory limit: OOM killer killed {comm}[{pid}]");
                        ev = ev.detail("limited_cgroup", cg.to_owned()).detail("service", who).detail(
                            "hint",
                            "the service's own MemoryMax/container limit was reached (not host RAM): raise the limit or fix the leak",
                        );
                    }
                    format!("{}:{pid}", r.kind)
                }
                Special::HungTask => {
                    ev.title = format!(
                        "task {} blocked in the kernel for more than {}s",
                        get("comm").unwrap_or_default(),
                        get("secs").unwrap_or_default()
                    );
                    format!("{}:{}", r.kind, get("comm").unwrap_or_default())
                }
                Special::Segfault => {
                    let comm = get("comm").unwrap_or_default();
                    let n = self.bursts.add(format!("segv:{comm}"), now);
                    if n == self.segfault_burst {
                        ev.severity = Severity::Warning;
                        ev.kind = "kernel.segfault_burst".into();
                        ev.title = format!("{comm} crashed {n} times within 5 minutes");
                        ev = ev.detail(
                            "hint",
                            "repeated crashes of a network-facing worker can indicate exploitation attempts",
                        );
                        format!("kernel.segfault_burst:{comm}")
                    } else {
                        // Individual segfaults are recorded (once a minute per
                        // program) but not notified; bursts are.
                        format!("kernel.segfault:{comm}")
                    }
                }
                Special::LsmDenial => {
                    let profile = get("profile").or_else(|| get("comm")).unwrap_or_default();
                    let n = self.bursts.add(format!("lsm:{profile}"), now);
                    if n == self.lsm_burst {
                        ev.severity = Severity::Warning;
                        ev.kind = "lsm.denial_burst".into();
                        ev.title = format!("{n} LSM denials for {profile} within 5 minutes");
                        format!("lsm.denial_burst:{profile}")
                    } else {
                        format!(
                            "{}:{profile}:{}:{}",
                            r.kind,
                            get("op").unwrap_or_default(),
                            get("name").unwrap_or_default()
                        )
                    }
                }
                Special::IoError => {
                    let dev = get("dev").or_else(|| get("dev2")).or_else(|| get("dev3")).unwrap_or_else(|| "?".into());
                    let n = self.bursts.add(format!("io:{dev}"), now);
                    if n >= 20 {
                        ev.severity = Severity::Critical;
                        ev.title = format!("disk {dev}: {n} I/O errors within 5 minutes");
                    }
                    format!("{}:{dev}", r.kind)
                }
                // "Link is Down" opens a condition, "Link is Up" resolves it:
                // the resolution carries the condition's fingerprint plus
                // `:resolved`, like units and health checks do. (Not the same
                // fingerprint: the engine would take the `info` resolution
                // for a repeat of the `warning` and drop it.)
                Special::LinkDown | Special::LinkUp => {
                    let iface = get("iface").unwrap_or_default();
                    let up = r.special == Special::LinkUp;
                    if self.links.get(&iface) == Some(&up) {
                        break; // the same state again: nothing changed
                    }
                    if self.links.len() >= MAX_LINKS {
                        self.links.clear();
                    }
                    self.links.insert(iface.clone(), up);
                    ev.fingerprint = format!("network.link:{iface}");
                    if up {
                        ev = ev.resolved();
                        ev.fingerprint.push_str(":resolved");
                    }
                    out.push(ev);
                    break;
                }
                Special::None => format!("{}:{}", r.kind, caps.get(0).map(|m| m.as_str()).unwrap_or("")),
            };
            ev.fingerprint = key.clone();
            if let Some(pid) = get("pid").and_then(|p| p.parse::<i32>().ok())
                && r.special != Special::OomKill
            {
                ev = ev.detail("pid", pid);
            }
            if let Some(name) = get("name") {
                ev.subject = Subject::File { path: name, site: None };
            }
            if self.cooldown.ready(&key, now) {
                out.push(ev);
            }
            break; // first matching rule wins
        }
        out
    }
}

/// Blocking sensor body: follow `/dev/kmsg`.
pub fn run_kmsg(shared: &Arc<Shared>, sink: &crate::runtime::Sink) -> Result<(), String> {
    let cfg = shared.config();
    if !cfg.kernel.enabled || !cfg.kernel.kmsg {
        return Ok(());
    }
    let generation = shared.generation();
    let mut reader = kmsg::Reader::open(true)
        .map_err(|e| format!("/dev/kmsg: {e}{}", warden_sys::sched::permission_hint(&e, "CAP_SYSLOG")))?;
    let mut an = KmsgAnalyzer::new(&cfg.kernel);
    shared.set_sensor("kmsg", SensorState::Running);
    loop {
        let rec = reader.next_record_timeout(Duration::from_secs(2)).map_err(|e| e.to_string())?;
        if shared.generation() != generation || shared.is_shutting_down() {
            return Err("configuration reloaded".into());
        }
        let Some(rec) = rec else { continue };
        shared.push_kmsg(format!("[{:>12.6}] <{}> {}", rec.ts_us as f64 / 1e6, rec.level, rec.message));
        for mut ev in an.analyze(&rec.message, Instant::now()) {
            ev.source = "kmsg".into();
            shared.metrics.inc("warden_kernel_messages_total", &[("kind", &ev.kind)], 1.0);
            sink.emit(ev);
        }
    }
}

// ---------------------------------------------------------------------------

/// Kernel state that can change at runtime: taint, modules, LSM.
pub struct KernelStateDetector {
    cfg: KernelConfig,
    taint: Option<u64>,
    modules: Option<BTreeSet<String>>,
    lsm: Option<kernel::LsmState>,
    module_alerts: HashMap<String, Instant>,
}

impl KernelStateDetector {
    pub fn new(cfg: &KernelConfig) -> Self {
        Self { cfg: cfg.clone(), taint: None, modules: None, lsm: None, module_alerts: HashMap::new() }
    }
}

impl Detector for KernelStateDetector {
    fn name(&self) -> &'static str {
        "kernel_state"
    }

    fn interval(&self) -> Duration {
        self.cfg.interval
    }

    fn sections(&self) -> &'static [&'static str] {
        &["/kernel"]
    }

    fn reconfigure(&mut self, cfg: &warden_core::Config) -> bool {
        // what was learned (taint, modules, LSM state) stays: a change
        // made around a reload is still reported
        self.cfg = cfg.kernel.clone();
        true
    }

    fn tick(&mut self, cx: &mut Cx<'_>) {
        if self.cfg.taint
            && let Some(t) = kernel::tainted()
        {
            cx.metric("warden_kernel_tainted", &[], t as f64);
            if let Some(prev) = self.taint.replace(t) {
                let new = kernel::new_taints(prev, t);
                if !new.is_empty() {
                    let letters: String = new.iter().map(|x| x.0).collect();
                    let sev = if new.iter().any(|x| matches!(x.0, 'D' | 'M' | 'B' | 'L' | 'E' | 'F')) {
                        Severity::Critical
                    } else {
                        Severity::Warning
                    };
                    cx.emit(
                        Event::new("kernel.taint", sev, format!("kernel became tainted: {letters}"))
                            .fingerprint(format!("kernel.taint:{t}"))
                            .detail("flags", new.iter().map(|x| format!("{}: {}", x.0, x.1)).collect::<Vec<_>>())
                            .detail("value", t),
                    );
                }
            }
        }
        if self.cfg.modules {
            let now = kernel::modules();
            if let Some(prev) = &self.modules {
                for m in now.difference(prev) {
                    if self.module_alerts.get(m).is_some_and(|t| t.elapsed() < Duration::from_secs(3600)) {
                        continue;
                    }
                    self.module_alerts.insert(m.clone(), Instant::now());
                    cx.emit(
                        Event::new(
                            "security.kernel_module_loaded",
                            Severity::Notice,
                            format!("kernel module loaded: {m}"),
                        )
                        .fingerprint(format!("security.kernel_module_loaded:{m}"))
                        .detail("module", m.clone())
                        .detail("hint", "unexpected modules on a server can be rootkits; verify with `modinfo`"),
                    );
                }
            }
            self.modules = Some(now);
        }
        if self.cfg.lsm_state {
            let now = kernel::lsm_state();
            if let Some(prev) = &self.lsm {
                if prev.apparmor_enabled == Some(true) && now.apparmor_enabled == Some(false) {
                    cx.emit(
                        Event::new("security.lsm_disabled", Severity::Critical, "AppArmor was disabled at runtime")
                            .fingerprint("security.lsm_disabled:apparmor"),
                    );
                }
                if let (Some(a), Some(b)) = (prev.apparmor_enforced_profiles, now.apparmor_enforced_profiles)
                    && a >= 4
                    && b * 2 < a
                {
                    cx.emit(
                        Event::new(
                            "security.lsm_profiles_unloaded",
                            Severity::Warning,
                            format!("AppArmor enforced profiles dropped from {a} to {b}"),
                        )
                        .fingerprint("security.lsm_profiles_unloaded:apparmor"),
                    );
                }
                if prev.selinux_enforcing == Some(true) && now.selinux_enforcing == Some(false) {
                    cx.emit(
                        Event::new("security.lsm_disabled", Severity::Critical, "SELinux switched to permissive mode")
                            .fingerprint("security.lsm_disabled:selinux"),
                    );
                }
            }
            if let Some(n) = now.apparmor_enforced_profiles {
                cx.metric("warden_apparmor_enforced_profiles", &[], n as f64);
            }
            self.lsm = Some(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn an() -> KmsgAnalyzer {
        KmsgAnalyzer::new(&KernelConfig::default())
    }

    #[test]
    fn oom_kill_message() {
        let mut a = an();
        let v = a.analyze(
            "Out of memory: Killed process 4242 (php-fpm8.3) total-vm:1234kB, anon-rss:999kB, file-rss:0kB, shmem-rss:0kB, UID:33",
            Instant::now(),
        );
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, "kernel.oom_kill");
        assert!(v[0].title.contains("php-fpm8.3[4242]"));
        assert_eq!(v[0].actions, vec![ActionSpec::Snapshot]);
        let v = a.analyze("Memory cgroup out of memory: Killed process 77 (node) total-vm:1kB", Instant::now());
        assert_eq!(v[0].kind, "kernel.oom_kill");
        // cgroup-limited OOM: the oom-kill line names the service; the follow-up line is deduplicated
        let mut a = an();
        let now = Instant::now();
        let v = a.analyze(
            "oom-kill:constraint=CONSTRAINT_MEMCG,nodemask=(null),cpuset=/,mems_allowed=0,oom_memcg=/system.slice/api.service,task_memcg=/system.slice/api.service,task=node,pid=99,uid=1000",
            now,
        );
        assert_eq!(v[0].kind, "kernel.oom_kill");
        assert!(v[0].title.contains("api.service hit its memory limit"), "{}", v[0].title);
        assert!(a.analyze("Memory cgroup out of memory: Killed process 99 (node) total-vm:1kB", now).is_empty());
    }

    #[test]
    fn fs_and_io_errors() {
        let mut a = an();
        let v = a.analyze(
            "EXT4-fs error (device sda1): ext4_find_entry:1455: inode #2: comm ls: reading directory lblock 0",
            Instant::now(),
        );
        assert_eq!(v[0].kind, "kernel.fs_error");
        assert_eq!(v[0].severity, Severity::Critical);
        let v = a.analyze("blk_update_request: I/O error, dev sdb, sector 123456 op 0x0:(READ)", Instant::now());
        assert_eq!(v[0].kind, "kernel.io_error");
        assert_eq!(v[0].details["dev"], "sdb");
    }

    #[test]
    fn floods_are_rate_limited_and_bursts_escalate() {
        let mut a = an();
        let now = Instant::now();
        let msg = "php-fpm8.3[100]: segfault at 0 ip 00007f sp 00007ff error 4 in libc.so.6";
        let mut kinds = Vec::new();
        for i in 0..25 {
            for e in a.analyze(msg, now + Duration::from_millis(i)) {
                kinds.push(e.kind);
            }
        }
        assert!(kinds.iter().any(|k| k == "kernel.segfault_burst"));
        assert!(kinds.iter().filter(|k| *k == "kernel.segfault_burst").count() == 1);
    }

    #[test]
    fn apparmor_denial() {
        let mut a = an();
        let v = a.analyze(
            r#"audit: type=1400 audit(1700000000.123:42): apparmor="DENIED" operation="open" class="file" profile="php-fpm" name="/etc/shadow" pid=123 comm="php-fpm8.3" requested_mask="r" denied_mask="r" fsuid=33 ouid=0"#,
            Instant::now(),
        );
        assert_eq!(v[0].kind, "lsm.apparmor_denied");
        assert_eq!(v[0].details["profile"], "php-fpm");
        assert!(matches!(&v[0].subject, Subject::File { path, .. } if path == "/etc/shadow"));
    }

    #[test]
    fn user_patterns_and_no_match() {
        let mut cfg = KernelConfig::default();
        cfg.patterns.push(KmsgPattern {
            kind: "custom.raid".into(),
            regex: r"md/raid\d+:md\d+: Disk failure".into(),
            severity: Severity::Critical,
            title: Some("RAID disk failure".into()),
            actions: vec![],
        });
        let mut a = KmsgAnalyzer::new(&cfg);
        assert_eq!(
            a.analyze("md/raid1:md0: Disk failure on sdb1, disabling device.", Instant::now())[0].kind,
            "custom.raid"
        );
        assert!(a.analyze("NET: Registered PF_INET6 protocol family", Instant::now()).is_empty());
    }
}
