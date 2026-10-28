//! System-wide counters: `/proc/stat`, `/proc/loadavg`, `/proc/uptime`,
//! file handles, PID limits.

use crate::util::{read_string, read_u64};
use std::io;

#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct CpuTimes {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
    pub irq: u64,
    pub softirq: u64,
    pub steal: u64,
}

impl CpuTimes {
    pub fn total(&self) -> u64 {
        self.user + self.nice + self.system + self.idle + self.iowait + self.irq + self.softirq + self.steal
    }

    pub fn busy(&self) -> u64 {
        self.total() - self.idle - self.iowait
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct Stat {
    pub cpu: CpuTimes,
    pub ctxt: u64,
    pub btime: u64,
    /// Forks since boot.
    pub processes: u64,
    pub procs_running: u64,
    /// Tasks blocked on I/O (D state).
    pub procs_blocked: u64,
}

pub fn parse_stat(content: &str) -> Stat {
    let mut s = Stat::default();
    for line in content.lines() {
        let mut it = line.split_whitespace();
        match it.next() {
            Some("cpu") => {
                let v: Vec<u64> = it.take(8).filter_map(|x| x.parse().ok()).collect();
                if v.len() >= 4 {
                    let g = |i: usize| v.get(i).copied().unwrap_or(0);
                    s.cpu = CpuTimes {
                        user: g(0),
                        nice: g(1),
                        system: g(2),
                        idle: g(3),
                        iowait: g(4),
                        irq: g(5),
                        softirq: g(6),
                        steal: g(7),
                    };
                }
            }
            Some("ctxt") => s.ctxt = it.next().and_then(|x| x.parse().ok()).unwrap_or(0),
            Some("btime") => s.btime = it.next().and_then(|x| x.parse().ok()).unwrap_or(0),
            Some("processes") => s.processes = it.next().and_then(|x| x.parse().ok()).unwrap_or(0),
            Some("procs_running") => s.procs_running = it.next().and_then(|x| x.parse().ok()).unwrap_or(0),
            Some("procs_blocked") => s.procs_blocked = it.next().and_then(|x| x.parse().ok()).unwrap_or(0),
            _ => {}
        }
    }
    s
}

pub fn stat() -> io::Result<Stat> {
    Ok(parse_stat(&read_string("/proc/stat")?))
}

/// CPU time the hypervisor gave to others while this machine's vCPUs were
/// runnable (`steal` of the `cpu` line of `/proc/stat`), in clock ticks
/// summed over all CPUs. Only the first line is parsed.
pub fn steal_ticks() -> Option<u64> {
    use std::io::Read;
    let mut buf = [0u8; 512];
    let n = std::fs::File::open("/proc/stat").and_then(|mut f| f.read(&mut buf)).ok()?;
    let text = std::str::from_utf8(&buf[..n]).ok()?;
    let line = text.lines().next()?;
    let mut it = line.split_whitespace();
    (it.next()? == "cpu").then_some(())?;
    it.nth(7)?.parse().ok()
}

/// Is this a virtual machine? The `hypervisor` CPU flag (x86), a Xen
/// `/sys/hypervisor`, or a DMI vendor of the usual hypervisors.
pub fn is_virtualized() -> bool {
    static V: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *V.get_or_init(|| {
        let flag = read_string("/proc/cpuinfo")
            .map(|c| c.lines().any(|l| l.starts_with("flags") && l.split_whitespace().any(|f| f == "hypervisor")))
            .unwrap_or(false);
        let xen = std::path::Path::new("/sys/hypervisor/type").exists();
        let dmi = ["/sys/class/dmi/id/sys_vendor", "/sys/class/dmi/id/product_name"].iter().any(|p| {
            read_string(p).is_ok_and(|v| {
                let v = v.to_ascii_lowercase();
                [
                    "qemu",
                    "kvm",
                    "vmware",
                    "virtualbox",
                    "innotek",
                    "xen",
                    "microsoft corporation",
                    "parallels",
                    "bochs",
                    "amazon ec2",
                    "google compute",
                ]
                .iter()
                .any(|h| v.contains(h))
            })
        });
        flag || xen || dmi
    })
}

#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct LoadAvg {
    pub one: f64,
    pub five: f64,
    pub fifteen: f64,
    pub running: u64,
    pub total_tasks: u64,
}

pub fn parse_loadavg(content: &str) -> Option<LoadAvg> {
    let mut it = content.split_whitespace();
    let one = it.next()?.parse().ok()?;
    let five = it.next()?.parse().ok()?;
    let fifteen = it.next()?.parse().ok()?;
    let (r, t) = it.next()?.split_once('/')?;
    Some(LoadAvg { one, five, fifteen, running: r.parse().ok()?, total_tasks: t.parse().ok()? })
}

pub fn loadavg() -> io::Result<LoadAvg> {
    parse_loadavg(&read_string("/proc/loadavg")?).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "loadavg"))
}

pub fn uptime_secs() -> Option<f64> {
    read_string("/proc/uptime").ok()?.split_whitespace().next()?.parse().ok()
}

/// `(allocated, max)` system-wide file handles.
pub fn file_nr() -> Option<(u64, u64)> {
    let s = read_string("/proc/sys/fs/file-nr").ok()?;
    let v: Vec<u64> = s.split_whitespace().filter_map(|x| x.parse().ok()).collect();
    Some((*v.first()?, *v.get(2)?))
}

pub fn pid_max() -> Option<u64> {
    read_u64("/proc/sys/kernel/pid_max")
}

pub fn threads_max() -> Option<u64> {
    read_u64("/proc/sys/kernel/threads-max")
}

pub fn hostname() -> String {
    read_string("/proc/sys/kernel/hostname").map(|s| s.trim().to_owned()).unwrap_or_else(|_| "localhost".into())
}

pub fn kernel_release() -> String {
    read_string("/proc/sys/kernel/osrelease").map(|s| s.trim().to_owned()).unwrap_or_default()
}

/// `(major, minor)` of a release string such as `6.8.0-45-generic`.
pub fn parse_kernel_version(release: &str) -> Option<(u32, u32)> {
    let mut it = release.split(|c: char| !c.is_ascii_digit());
    Some((it.next()?.parse().ok()?, it.next()?.parse().ok()?))
}

/// Is the running kernel at least `major.minor`?
pub fn kernel_at_least(major: u32, minor: u32) -> bool {
    parse_kernel_version(&kernel_release()).is_some_and(|v| v >= (major, minor))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_parsing() {
        let s = parse_stat(
            "cpu  100 5 50 1000 20 1 2 3 0 0\ncpu0 1 2 3 4\nctxt 999\nbtime 1700000000\nprocesses 4242\nprocs_running 3\nprocs_blocked 1\n",
        );
        assert_eq!(s.cpu.user, 100);
        assert_eq!(s.cpu.iowait, 20);
        assert_eq!(s.cpu.total(), 1181);
        assert_eq!(s.processes, 4242);
        assert_eq!(s.procs_blocked, 1);
    }

    #[test]
    fn loadavg_parsing() {
        let l = parse_loadavg("0.50 1.25 2.00 3/456 7890\n").unwrap();
        assert_eq!(l.five, 1.25);
        assert_eq!(l.total_tasks, 456);
    }

    #[test]
    fn kernel_versions() {
        assert_eq!(parse_kernel_version("6.8.0-45-generic"), Some((6, 8)));
        assert_eq!(parse_kernel_version("5.15.167.4-microsoft-standard-WSL2"), Some((5, 15)));
        assert_eq!(parse_kernel_version("6.6"), Some((6, 6)));
        assert_eq!(parse_kernel_version("garbage"), None);
        assert!((6, 18) >= (6, 6) && (5, 19) < (6, 6));
    }

    #[test]
    fn steal_is_read_from_the_first_line() {
        assert!(steal_ticks().is_some(), "/proc/stat has a cpu line with a steal column");
        let _ = is_virtualized();
    }
}
