//! Kernel tuning advisor.
//!
//! Compares sysctls and kernel features with the hardware and the workload
//! actually running (databases, web servers, Elasticsearch…) and produces
//! recommendations with a reason. It never changes anything: capacity limits
//! are grown reactively by the limits detector (`tuning.auto_grow`), and
//! behaviour-shaping knobs are left to the operator on purpose — they trade
//! latency against throughput in ways only the operator can judge.

use crate::runtime::{Cx, Detector, lock};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use warden_core::config::TuningConfig;
use warden_core::{Event, Severity};

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Advice {
    pub key: String,
    pub current: String,
    pub recommended: String,
    pub reason: String,
    pub category: &'static str,
}

/// Facts the rules look at (gathered from the live system, or built by tests).
#[derive(Debug, Clone, Default)]
pub struct Env {
    pub ram: u64,
    pub swap_total: u64,
    pub sysctl: HashMap<String, String>,
    pub thp: Option<String>,
    pub workloads: HashSet<&'static str>,
    pub psi: bool,
}

const GIB: u64 = 1 << 30;

impl Env {
    fn num(&self, k: &str) -> Option<i64> {
        self.sysctl.get(k)?.split_whitespace().next()?.parse().ok()
    }
    fn has(&self, w: &str) -> bool {
        self.workloads.contains(w)
    }
}

pub const SYSCTLS: &[&str] = &[
    "vm.dirty_ratio",
    "vm.dirty_background_ratio",
    "vm.dirty_bytes",
    "vm.swappiness",
    "vm.max_map_count",
    "vm.overcommit_memory",
    "net.core.somaxconn",
    "net.ipv4.tcp_syncookies",
    "fs.inotify.max_user_watches",
    "kernel.randomize_va_space",
    "fs.protected_symlinks",
    "fs.protected_hardlinks",
    "fs.suid_dumpable",
    "kernel.core_pattern",
    "kernel.kptr_restrict",
    "kernel.unprivileged_bpf_disabled",
    "kernel.yama.ptrace_scope",
];

/// Detect workloads from process names / command lines.
pub fn detect_workloads() -> HashSet<&'static str> {
    let mut w = HashSet::new();
    for pid in warden_sys::process::pids() {
        let Ok(st) = warden_sys::process::read_stat(pid) else { continue };
        let c = st.comm.as_str();
        let tag = match c {
            "mysqld" | "mariadbd" => Some("mysql"),
            "postgres" | "postmaster" => Some("postgres"),
            "redis-server" | "valkey-server" | "keydb-server" => Some("redis"),
            "mongod" => Some("mongodb"),
            "nginx" => Some("nginx"),
            "apache2" | "httpd" => Some("apache"),
            "dockerd" | "containerd" => Some("containers"),
            "kubelet" => Some("kubernetes"),
            "node" | "nodejs" => Some("node"),
            _ if c.starts_with("clickhouse") => Some("clickhouse"),
            _ if c.starts_with("php-fpm") => Some("php-fpm"),
            "java" => {
                let cmd = warden_sys::process::cmdline(pid, 4096).unwrap_or_default();
                if cmd.contains("elasticsearch") || cmd.contains("opensearch") { Some("elasticsearch") } else { None }
            }
            _ => None,
        };
        if let Some(t) = tag {
            w.insert(t);
        }
    }
    w
}

pub fn gather() -> Env {
    let mi = warden_sys::mem::meminfo().unwrap_or_default();
    let sysctl =
        SYSCTLS.iter().filter_map(|k| warden_sys::sysctl::read(k).ok().map(|v| ((*k).to_owned(), v))).collect();
    let thp = std::fs::read_to_string("/sys/kernel/mm/transparent_hugepage/enabled").ok().and_then(|s| {
        let a = s.find('[')?;
        let b = s.find(']')?;
        Some(s[a + 1..b].to_owned())
    });
    Env {
        ram: mi.total,
        swap_total: mi.swap_total,
        sysctl,
        thp,
        workloads: detect_workloads(),
        psi: warden_sys::psi::available(),
    }
}

/// The rules. Pure function of `Env`.
pub fn advise(env: &Env) -> Vec<Advice> {
    let mut out = Vec::new();
    let mut add = |key: &str, cur: String, rec: &str, cat: &'static str, reason: &str| {
        out.push(Advice {
            key: key.into(),
            current: cur,
            recommended: rec.into(),
            reason: reason.into(),
            category: cat,
        });
    };
    let dbs = ["mysql", "postgres", "mongodb", "redis", "clickhouse", "elasticsearch"];
    let has_db = dbs.iter().any(|d| env.has(d));

    // --- stability ---------------------------------------------------------
    if let (Some(ratio), Some(0)) = (env.num("vm.dirty_ratio"), env.num("vm.dirty_bytes")) {
        let dirty = env.ram / 100 * ratio.max(0) as u64;
        if dirty > 4 * GIB {
            add(
                "vm.dirty_bytes",
                format!("dirty_ratio={ratio}% (≈{} GiB)", dirty / GIB),
                "1073741824 (and vm.dirty_background_bytes=268435456)",
                "stability",
                "with lots of RAM a percentage-based dirty limit lets gigabytes of unwritten data pile up; the \
                 flush then stalls all writers for seconds (visible as I/O PSI spikes). Absolute byte limits keep \
                 writeback smooth.",
            );
        }
    }
    if env.swap_total == 0 && env.ram <= 16 * GIB {
        add(
            "swap",
            "none".into(),
            "1–2 GiB swap file or zram",
            "stability",
            "without any swap, cold anonymous pages can never be moved out and memory pressure turns straight into \
             OOM kills; a small swap gives Warden's PSI detector time to act before the kernel OOM killer does.",
        );
    }
    if has_db && env.swap_total > 0 && env.num("vm.swappiness").is_some_and(|s| s > 10) {
        add(
            "vm.swappiness",
            env.num("vm.swappiness").unwrap_or(60).to_string(),
            "10",
            "databases",
            "a database server keeps its hot data in its own buffer pool; aggressive swapping of that memory causes \
             latency spikes. Keep swap as an emergency buffer only.",
        );
    }
    if env.thp.as_deref() == Some("always") && (env.has("redis") || env.has("mongodb") || env.has("clickhouse")) {
        add(
            "transparent_hugepage",
            "always".into(),
            "madvise",
            "databases",
            "Redis/MongoDB recommend disabling THP=always: page-merging (khugepaged) and copy-on-write of 2 MiB pages \
             during fork/snapshot cause latency spikes and memory bloat.",
        );
    }
    if env.has("elasticsearch") && env.num("vm.max_map_count").is_some_and(|v| v < 262_144) {
        add(
            "vm.max_map_count",
            env.num("vm.max_map_count").unwrap_or(0).to_string(),
            "262144",
            "databases",
            "Elasticsearch/OpenSearch require at least 262144 memory-map areas (bootstrap check).",
        );
    }
    if (env.has("nginx") || env.has("apache")) && env.num("net.core.somaxconn").is_some_and(|v| v < 4096) {
        add(
            "net.core.somaxconn",
            env.num("net.core.somaxconn").unwrap_or(0).to_string(),
            "4096 (and raise the server's listen backlog)",
            "network",
            "a small accept queue drops connections during bursts (see network.listen_overflow events).",
        );
    }
    if (env.has("node") || env.has("containers")) && env.num("fs.inotify.max_user_watches").is_some_and(|v| v < 65_536)
    {
        add(
            "fs.inotify.max_user_watches",
            env.num("fs.inotify.max_user_watches").unwrap_or(0).to_string(),
            "524288",
            "capacity",
            "file watchers (Node tooling, container runtimes, IDEs) fail with ENOSPC when the watch limit is low.",
        );
    }
    if !env.psi {
        add(
            "kernel cmdline",
            "PSI disabled".into(),
            "psi=1",
            "stability",
            "Pressure Stall Information is Warden's primary early-warning signal; enable it on the kernel command line.",
        );
    }
    // --- security hardening -------------------------------------------------
    let hard: &[(&str, i64, bool, &str)] = &[
        ("net.ipv4.tcp_syncookies", 1, true, "SYN-flood protection"),
        ("kernel.randomize_va_space", 2, true, "full ASLR makes memory-corruption exploits much harder"),
        ("fs.protected_symlinks", 1, true, "blocks /tmp symlink races used for privilege escalation"),
        ("fs.protected_hardlinks", 1, true, "blocks hardlink tricks against SUID binaries"),
        ("fs.suid_dumpable", 0, false, "SUID programs must not write core dumps (secrets leak)"),
        ("kernel.kptr_restrict", 1, true, "hides kernel addresses from unprivileged users (KASLR bypass)"),
        ("kernel.unprivileged_bpf_disabled", 1, true, "unprivileged eBPF has a long history of kernel exploits"),
        (
            "kernel.yama.ptrace_scope",
            1,
            true,
            "only parents may ptrace their children (blocks credential theft from other processes)",
        ),
    ];
    // `fs.suid_dumpable = 2` with dumps going to a pipe handler (apport,
    // systemd-coredump: the Ubuntu/Fedora default) is the intended setting:
    // the kernel then hands the dump to the root-owned handler instead of
    // writing a root-readable file into the process's directory.
    let core_pipe = env.sysctl.get("kernel.core_pattern").is_some_and(|p| p.trim_start().starts_with('|'));
    for (key, want, at_least, why) in hard {
        if let Some(v) = env.num(key) {
            if *key == "fs.suid_dumpable" && v == 2 && core_pipe {
                continue;
            }
            let bad = if *at_least { v < *want } else { v != *want };
            if bad {
                add(key, v.to_string(), &want.to_string(), "security", why);
            }
        }
    }
    out
}

pub struct TuningDetector {
    cfg: TuningConfig,
    reported: HashSet<(String, String)>,
}

impl TuningDetector {
    pub fn new(cfg: &TuningConfig) -> Self {
        Self { cfg: cfg.clone(), reported: HashSet::new() }
    }
}

impl Detector for TuningDetector {
    fn name(&self) -> &'static str {
        "tuning"
    }

    fn interval(&self) -> Duration {
        self.cfg.interval
    }

    fn sections(&self) -> &'static [&'static str] {
        &["/tuning"]
    }

    fn reconfigure(&mut self, cfg: &warden_core::Config) -> bool {
        // what was already advised is not advised again
        self.cfg = cfg.tuning.clone();
        true
    }

    fn tick(&mut self, cx: &mut Cx<'_>) {
        let list: Vec<Advice> = advise(&gather()).into_iter().filter(|a| !self.cfg.ignore.contains(&a.key)).collect();
        cx.metric("warden_tuning_recommendations", &[], list.len() as f64);
        for a in &list {
            if self.reported.insert((a.key.clone(), a.current.clone())) {
                cx.emit(
                    Event::new(
                        "tuning.advice",
                        Severity::Notice,
                        format!("tuning [{}]: {} = {} → recommended {}", a.category, a.key, a.current, a.recommended),
                    )
                    .fingerprint(format!("tuning.advice:{}:{}", a.key, a.current))
                    .detail("key", a.key.clone())
                    .detail("current", a.current.clone())
                    .detail("recommended", a.recommended.clone())
                    .detail("reason", a.reason.clone()),
                );
            }
        }
        *lock(&cx.shared.advice) = serde_json::to_value(&list).unwrap_or_default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, &str)], ram_gib: u64, swap: bool, w: &[&'static str]) -> Env {
        Env {
            ram: ram_gib * GIB,
            swap_total: if swap { GIB } else { 0 },
            sysctl: pairs.iter().map(|(k, v)| ((*k).to_owned(), (*v).to_owned())).collect(),
            thp: Some("always".into()),
            workloads: w.iter().copied().collect(),
            psi: true,
        }
    }

    fn keys(v: &[Advice]) -> Vec<&str> {
        v.iter().map(|a| a.key.as_str()).collect()
    }

    #[test]
    fn database_server_on_big_box() {
        let e = env(
            &[("vm.dirty_ratio", "20"), ("vm.dirty_bytes", "0"), ("vm.swappiness", "60")],
            128,
            true,
            &["mysql", "redis"],
        );
        let k = keys(&advise(&e)).join(",");
        assert!(k.contains("vm.dirty_bytes"), "{k}");
        assert!(k.contains("vm.swappiness"));
        assert!(k.contains("transparent_hugepage"));
        assert!(!k.contains("swap,"));
    }

    #[test]
    fn small_vps_without_swap_and_weak_hardening() {
        let e = env(
            &[("kernel.randomize_va_space", "0"), ("fs.suid_dumpable", "2"), ("kernel.kptr_restrict", "1")],
            1,
            false,
            &[],
        );
        let adv = advise(&e);
        let k = keys(&adv);
        assert!(k.contains(&"swap"));
        assert!(k.contains(&"kernel.randomize_va_space"));
        assert!(k.contains(&"fs.suid_dumpable"));
        assert!(!k.contains(&"kernel.kptr_restrict"));
    }

    #[test]
    fn suid_dumpable_depends_on_where_core_dumps_go() {
        let flagged = |pairs: &[(&str, &str)]| keys(&advise(&env(pairs, 8, true, &[]))).contains(&"fs.suid_dumpable");
        let pipe = ("kernel.core_pattern", "|/lib/systemd/systemd-coredump %P %u %g %s %t 9223372036854775808 %h");
        assert!(!flagged(&[("fs.suid_dumpable", "2"), pipe]), "2 with a pipe handler is the safe setting");
        assert!(flagged(&[("fs.suid_dumpable", "1"), pipe]), "1 dumps as the file owner even with a pipe");
        assert!(flagged(&[("fs.suid_dumpable", "2"), ("kernel.core_pattern", "core")]), "2 writing a file is not");
        assert!(!flagged(&[("fs.suid_dumpable", "0"), ("kernel.core_pattern", "core")]));
    }

    #[test]
    fn well_tuned_host_is_quiet() {
        let mut e = env(
            &[("vm.dirty_ratio", "20"), ("vm.dirty_bytes", "0"), ("net.core.somaxconn", "4096")],
            8,
            true,
            &["nginx"],
        );
        e.thp = Some("madvise".into());
        assert!(advise(&e).is_empty(), "{:?}", advise(&e));
    }

    #[test]
    fn live_gather_does_not_panic() {
        let e = gather();
        assert!(e.ram > 0);
        let _ = advise(&e);
    }
}
