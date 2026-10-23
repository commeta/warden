//! Diagnostic snapshots: everything an engineer wants to see *after* an
//! incident, captured *during* it (when `top` would not even start).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use warden_core::Event;
use warden_core::units::human_bytes;
use warden_sys::{cgroup, mem, mounts, process, psi, system};

/// Data only the daemon has (kernel log ring, metrics, culprit ranking).
#[derive(Debug, Default, Clone)]
pub struct Extras {
    pub kmsg_tail: Vec<String>,
    pub metrics: String,
    pub culprits: serde_json::Value,
    pub hostname: String,
}

fn proc_table() -> (String, serde_json::Value) {
    let tck = warden_sys::util::clk_tck();
    let users = warden_sys::users::Users::load();
    let mut ps: Vec<process::ProcInfo> = process::snapshot().into_values().filter(|p| !p.kernel_thread).collect();
    ps.sort_by_key(|b| std::cmp::Reverse(b.rss + b.swap));
    let mut txt = format!(
        "{:>8} {:>8} {:<12} {:>10} {:>10} {:>10} {:>9} {:>3} {:>5}  {}\n",
        "PID", "PPID", "USER", "RSS", "SWAP", "PEAK", "CPU(s)", "ST", "THR", "COMMAND"
    );
    let mut json = Vec::new();
    for p in &ps {
        let cmd = process::cmdline(p.pid, 300).filter(|c| !c.is_empty()).unwrap_or_else(|| format!("[{}]", p.comm));
        let user = users.display(p.ruid);
        let _ = writeln!(
            txt,
            "{:>8} {:>8} {:<12} {:>10} {:>10} {:>10} {:>9} {:>3} {:>5}  {}",
            p.pid,
            p.ppid,
            user.chars().take(12).collect::<String>(),
            human_bytes(p.rss),
            human_bytes(p.swap),
            human_bytes(p.hwm),
            p.cpu_ticks / tck.max(1),
            p.state,
            p.threads,
            cmd
        );
        json.push(serde_json::json!({
            "pid": p.pid, "ppid": p.ppid, "user": user, "comm": p.comm, "state": p.state.to_string(),
            "rss": p.rss, "swap": p.swap, "threads": p.threads, "majflt": p.majflt, "cmdline": cmd,
        }));
    }
    (txt, serde_json::Value::Array(json))
}

fn slab_top(n: usize) -> String {
    let Ok(s) = std::fs::read_to_string("/proc/slabinfo") else { return "unavailable\n".into() };
    let mut v: Vec<(u64, String)> = s
        .lines()
        .skip(2)
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let objs: u64 = f.get(2)?.parse().ok()?;
            let size: u64 = f.get(3)?.parse().ok()?;
            Some((objs * size, f[0].to_owned()))
        })
        .collect();
    v.sort_by_key(|b| std::cmp::Reverse(b.0));
    v.into_iter().take(n).map(|(b, name)| format!("{:>12}  {name}\n", human_bytes(b))).collect()
}

fn d_state() -> String {
    let mut out = String::new();
    for pid in process::pids() {
        if let Ok(st) = process::read_stat(pid)
            && st.state == 'D'
        {
            let wchan = std::fs::read_to_string(format!("/proc/{pid}/wchan")).unwrap_or_default();
            let stack = std::fs::read_to_string(format!("/proc/{pid}/stack")).unwrap_or_default();
            let _ = writeln!(out, "== {}[{pid}] wchan={}\n{stack}", st.comm, wchan.trim());
        }
    }
    if out.is_empty() { "none\n".into() } else { out }
}

/// Write a snapshot directory and apply retention. Returns its path.
pub fn take(dir: &Path, keep: usize, reason: &str, ev: &Event, extras: &Extras) -> std::io::Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let ts = humantime::format_rfc3339_seconds(std::time::SystemTime::now()).to_string().replace(':', "");
    let safe: String = reason
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .take(60)
        .collect();
    let out = dir.join(format!("{ts}_{safe}"));
    std::fs::create_dir_all(&out)?;
    let w = |name: &str, data: &str| std::fs::write(out.join(name), data);

    w("event.json", &serde_json::to_string_pretty(ev).unwrap_or_default())?;
    let mut summary = String::new();
    let _ = writeln!(summary, "host: {}  kernel: {}", extras.hostname, system::kernel_release());
    let _ = writeln!(summary, "reason: {reason}\nevent: {}", ev.summary());
    if let Some(u) = system::uptime_secs() {
        let _ = writeln!(summary, "uptime: {:.0}s", u);
    }
    if let Ok(l) = system::loadavg() {
        let _ = writeln!(
            summary,
            "load: {} {} {} tasks={} cpus={}",
            l.one,
            l.five,
            l.fifteen,
            l.total_tasks,
            warden_sys::util::nproc()
        );
    }
    if let Ok(m) = mem::meminfo() {
        let _ = writeln!(
            summary,
            "memory: total {} available {} ({:.1}%) swap {}/{} dirty {} writeback {} shmem {} slab_unreclaim {}",
            human_bytes(m.total),
            human_bytes(m.available),
            m.available_percent(),
            human_bytes(m.swap_used()),
            human_bytes(m.swap_total),
            human_bytes(m.dirty),
            human_bytes(m.writeback),
            human_bytes(m.shmem),
            human_bytes(m.slab_unreclaim)
        );
    }
    let mut pressure = String::new();
    for r in [psi::Resource::Cpu, psi::Resource::Memory, psi::Resource::Io, psi::Resource::Irq] {
        if let Ok(s) = std::fs::read_to_string(r.path()) {
            let _ = writeln!(pressure, "== {}\n{s}", r.path());
        }
    }
    summary.push_str(&pressure);
    w("summary.txt", &summary)?;

    let (ptxt, pjson) = proc_table();
    w("processes.txt", &ptxt)?;
    w("processes.json", &serde_json::to_string(&pjson).unwrap_or_default())?;
    w("culprits.json", &serde_json::to_string_pretty(&extras.culprits).unwrap_or_default())?;
    for (name, src) in [
        ("meminfo.txt", "/proc/meminfo"),
        ("vmstat.txt", "/proc/vmstat"),
        ("sockstat.txt", "/proc/net/sockstat"),
        ("snmp.txt", "/proc/net/snmp"),
    ] {
        if let Ok(s) = std::fs::read_to_string(src) {
            w(name, &s)?;
        }
    }
    w("slabinfo_top.txt", &slab_top(25))?;
    w("d_state.txt", &d_state())?;
    if cgroup::is_v2() {
        let cg: String = cgroup::top_memory(4, 30)
            .into_iter()
            .map(|(p, m)| {
                format!(
                    "{:>12} pinned {:>12} total (cache {}, kernel {})  {p}\n",
                    human_bytes(m.pinned()),
                    human_bytes(m.current),
                    human_bytes(m.file),
                    human_bytes(m.kernel)
                )
            })
            .collect();
        w("cgroups_memory.txt", &cg)?;
    }
    let mut df = String::new();
    if let Ok(ms) = mounts::mounts() {
        for m in ms
            .iter()
            .filter(|m| m.source.starts_with('/') || ["tmpfs", "overlay", "zfs", "btrfs"].contains(&m.fstype.as_str()))
        {
            if let Ok(u) = mounts::statvfs(&m.mount_point) {
                let _ = writeln!(
                    df,
                    "{:>6.1}% {:>10} free  inodes {:>5.1}%  {} ({}, {})",
                    u.used_percent(),
                    human_bytes(u.avail),
                    u.inode_percent(),
                    m.mount_point,
                    m.fstype,
                    m.source
                );
            }
        }
    }
    w("filesystems.txt", &df)?;
    w("kmsg_tail.txt", &extras.kmsg_tail.join("\n"))?;
    w("metrics.prom", &extras.metrics)?;

    // retention
    if let Ok(rd) = std::fs::read_dir(dir) {
        let mut dirs: Vec<PathBuf> = rd.filter_map(Result::ok).map(|e| e.path()).filter(|p| p.is_dir()).collect();
        dirs.sort();
        while dirs.len() > keep.max(1) {
            let d = dirs.remove(0);
            let _ = std::fs::remove_dir_all(d);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_and_retention() {
        let d = tempfile::tempdir().unwrap();
        let ev = Event::new("memory.pressure", warden_core::Severity::Critical, "test");
        let ex = Extras { hostname: "h".into(), kmsg_tail: vec!["line".into()], ..Default::default() };
        let p = take(d.path(), 2, "memory.pressure", &ev, &ex).unwrap();
        assert!(p.join("summary.txt").exists());
        assert!(std::fs::read_to_string(p.join("processes.txt")).unwrap().contains("PID"));
        std::thread::sleep(std::time::Duration::from_millis(1100));
        take(d.path(), 2, "b", &ev, &ex).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(1100));
        take(d.path(), 2, "c", &ev, &ex).unwrap();
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 2);
    }
}
