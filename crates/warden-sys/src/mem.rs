//! `/proc/meminfo` and `/proc/vmstat`.

use crate::util::{parse_kb_value, parse_kv_line, read_string};
use std::collections::HashMap;
use std::io;

#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct MemInfo {
    pub total: u64,
    pub free: u64,
    pub available: u64,
    pub buffers: u64,
    pub cached: u64,
    pub swap_total: u64,
    pub swap_free: u64,
    pub dirty: u64,
    pub writeback: u64,
    pub shmem: u64,
    pub slab_reclaimable: u64,
    pub slab_unreclaim: u64,
    pub committed_as: u64,
    pub commit_limit: u64,
    pub anon_pages: u64,
    pub hugepages_total: u64,
}

impl MemInfo {
    pub fn available_percent(&self) -> f64 {
        if self.total == 0 { 100.0 } else { self.available as f64 * 100.0 / self.total as f64 }
    }

    pub fn swap_used(&self) -> u64 {
        self.swap_total.saturating_sub(self.swap_free)
    }

    pub fn swap_used_percent(&self) -> f64 {
        if self.swap_total == 0 { 0.0 } else { self.swap_used() as f64 * 100.0 / self.swap_total as f64 }
    }
}

pub fn parse_meminfo(content: &str) -> MemInfo {
    let mut m = MemInfo::default();
    for line in content.lines() {
        let Some((k, v)) = parse_kv_line(line) else { continue };
        let Some(v) = parse_kb_value(v) else { continue };
        match k {
            "MemTotal" => m.total = v,
            "MemFree" => m.free = v,
            "MemAvailable" => m.available = v,
            "Buffers" => m.buffers = v,
            "Cached" => m.cached = v,
            "SwapTotal" => m.swap_total = v,
            "SwapFree" => m.swap_free = v,
            "Dirty" => m.dirty = v,
            "Writeback" => m.writeback = v,
            "Shmem" => m.shmem = v,
            "SReclaimable" => m.slab_reclaimable = v,
            "SUnreclaim" => m.slab_unreclaim = v,
            "Committed_AS" => m.committed_as = v,
            "CommitLimit" => m.commit_limit = v,
            "AnonPages" => m.anon_pages = v,
            "HugePages_Total" => m.hugepages_total = v,
            _ => {}
        }
    }
    m
}

pub fn meminfo() -> io::Result<MemInfo> {
    Ok(parse_meminfo(&read_string("/proc/meminfo")?))
}

/// `/proc/vmstat` counters (pswpin, pswpout, pgmajfault, oom_kill, ...).
pub fn parse_vmstat(content: &str) -> HashMap<String, u64> {
    content
        .lines()
        .filter_map(|l| {
            let (k, v) = l.split_once(' ')?;
            Some((k.to_owned(), v.trim().parse().ok()?))
        })
        .collect()
}

pub fn vmstat() -> io::Result<HashMap<String, u64>> {
    Ok(parse_vmstat(&read_string("/proc/vmstat")?))
}

/// The subset of vmstat that Warden turns into rates.
#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct VmCounters {
    pub pswpin: u64,
    pub pswpout: u64,
    pub pgmajfault: u64,
    pub oom_kill: u64,
    /// Direct reclaim scans: allocations that had to reclaim synchronously.
    pub pgscan_direct: u64,
    pub allocstall: u64,
}

pub fn vm_counters() -> io::Result<VmCounters> {
    let m = vmstat()?;
    let g = |k: &str| m.get(k).copied().unwrap_or(0);
    // allocstall is split per zone on modern kernels.
    let allocstall = m.iter().filter(|(k, _)| k.starts_with("allocstall")).map(|(_, v)| *v).sum();
    Ok(VmCounters {
        pswpin: g("pswpin"),
        pswpout: g("pswpout"),
        pgmajfault: g("pgmajfault"),
        oom_kill: g("oom_kill"),
        pgscan_direct: g("pgscan_direct"),
        allocstall,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meminfo_parsing() {
        let m = parse_meminfo(
            "MemTotal:        8000000 kB\nMemFree:  100 kB\nMemAvailable:    2000000 kB\nSwapTotal: 1000 kB\nSwapFree: 250 kB\nHugePages_Total:       0\n",
        );
        assert_eq!(m.total, 8_000_000 * 1024);
        assert!((m.available_percent() - 25.0).abs() < 1e-9);
        assert!((m.swap_used_percent() - 75.0).abs() < 1e-9);
    }

    #[test]
    fn vmstat_parsing() {
        let v = parse_vmstat("pswpin 10\npswpout 20\noom_kill 3\nbogus\n");
        assert_eq!(v["pswpout"], 20);
        assert_eq!(v.len(), 3);
    }
}
