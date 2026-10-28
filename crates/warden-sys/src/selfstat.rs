//! Resource usage of the daemon itself: per-thread CPU and I/O, memory
//! breakdown, allocator state. Used by the self-profiler (`wardenctl profile`).

use crate::util::read_string;
use serde::Serialize;
use std::cell::RefCell;
use std::fs::File;
use std::os::unix::fs::FileExt;

/// CPU and I/O counters of one thread (or a sum of them).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Usage {
    pub user_us: u64,
    pub sys_us: u64,
    /// Bytes read/written through syscalls (including page-cache hits).
    pub rchar: u64,
    pub wchar: u64,
    pub syscr: u64,
    pub syscw: u64,
    /// Bytes that actually hit the block layer.
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub majflt: u64,
}

impl Usage {
    pub fn cpu_us(&self) -> u64 {
        self.user_us + self.sys_us
    }

    pub fn saturating_sub(&self, o: &Usage) -> Usage {
        Usage {
            user_us: self.user_us.saturating_sub(o.user_us),
            sys_us: self.sys_us.saturating_sub(o.sys_us),
            rchar: self.rchar.saturating_sub(o.rchar),
            wchar: self.wchar.saturating_sub(o.wchar),
            syscr: self.syscr.saturating_sub(o.syscr),
            syscw: self.syscw.saturating_sub(o.syscw),
            read_bytes: self.read_bytes.saturating_sub(o.read_bytes),
            write_bytes: self.write_bytes.saturating_sub(o.write_bytes),
            majflt: self.majflt.saturating_sub(o.majflt),
        }
    }

    pub fn add(&mut self, o: &Usage) {
        self.user_us += o.user_us;
        self.sys_us += o.sys_us;
        self.rchar += o.rchar;
        self.wchar += o.wchar;
        self.syscr += o.syscr;
        self.syscw += o.syscw;
        self.read_bytes += o.read_bytes;
        self.write_bytes += o.write_bytes;
        self.majflt += o.majflt;
    }
}

/// Parse `/proc/.../io`.
pub fn parse_io(s: &str, u: &mut Usage) {
    for l in s.lines() {
        let Some((k, v)) = l.split_once(':') else { continue };
        let v: u64 = v.trim().parse().unwrap_or(0);
        match k {
            "rchar" => u.rchar = v,
            "wchar" => u.wchar = v,
            "syscr" => u.syscr = v,
            "syscw" => u.syscw = v,
            "read_bytes" => u.read_bytes = v,
            "write_bytes" => u.write_bytes = v,
            _ => {}
        }
    }
}

thread_local! {
    /// `/proc/thread-self/io`, opened once per thread and re-read with
    /// `pread` (one syscall per sample).
    static THREAD_IO: RefCell<Option<File>> = const { RefCell::new(None) };
}

/// Usage of the calling thread: `getrusage(RUSAGE_THREAD)` plus
/// `/proc/thread-self/io`. Costs two syscalls.
pub fn thread_usage() -> Usage {
    let mut u = Usage::default();
    // SAFETY: getrusage writes into the zeroed struct we own.
    unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        if libc::getrusage(libc::RUSAGE_THREAD, &mut ru) == 0 {
            u.user_us = ru.ru_utime.tv_sec as u64 * 1_000_000 + ru.ru_utime.tv_usec as u64;
            u.sys_us = ru.ru_stime.tv_sec as u64 * 1_000_000 + ru.ru_stime.tv_usec as u64;
            u.majflt = ru.ru_majflt as u64;
        }
    }
    let _ = THREAD_IO.try_with(|cell| {
        let mut slot = cell.borrow_mut();
        if slot.is_none() {
            *slot = File::open("/proc/thread-self/io").ok();
        }
        if let Some(f) = slot.as_ref() {
            let mut buf = [0u8; 512];
            if let Ok(n) = f.read_at(&mut buf, 0) {
                parse_io(&String::from_utf8_lossy(&buf[..n]), &mut u);
            }
        }
    });
    u
}

/// One thread of this process as seen in `/proc/self/task`.
#[derive(Debug, Clone, Serialize)]
pub struct ThreadInfo {
    pub tid: i32,
    pub name: String,
    pub usage: Usage,
    /// Voluntary + involuntary context switches (≈ wake-ups).
    pub ctx_switches: u64,
}

pub fn threads() -> Vec<ThreadInfo> {
    let tck = crate::util::clk_tck();
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/proc/self/task") else { return out };
    for e in rd.filter_map(Result::ok) {
        let Some(tid) = e.file_name().to_str().and_then(|s| s.parse::<i32>().ok()) else { continue };
        let base = e.path();
        let Ok(stat) = read_string(base.join("stat")) else { continue };
        let (Some(l), Some(r)) = (stat.find('('), stat.rfind(')')) else { continue };
        let name = stat[l + 1..r].to_owned();
        let f: Vec<&str> = stat[r + 2..].split_whitespace().collect();
        let ticks = |i: usize| f.get(i).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        let mut u = Usage {
            user_us: ticks(11) * 1_000_000 / tck,
            sys_us: ticks(12) * 1_000_000 / tck,
            majflt: ticks(9),
            ..Default::default()
        };
        if let Ok(io) = read_string(base.join("io")) {
            parse_io(&io, &mut u);
        }
        let mut csw = 0;
        if let Ok(st) = read_string(base.join("status")) {
            for line in st.lines() {
                if let Some(v) = line
                    .strip_prefix("voluntary_ctxt_switches:")
                    .or_else(|| line.strip_prefix("nonvoluntary_ctxt_switches:"))
                {
                    csw += v.trim().parse::<u64>().unwrap_or(0);
                }
            }
        }
        out.push(ThreadInfo { tid, name, usage: u, ctx_switches: csw });
    }
    out.sort_by_key(|t| t.tid);
    out
}

/// Whole-process counters (includes exited threads) and reaped children.
#[derive(Debug, Default, Clone, Serialize)]
pub struct ProcessUsage {
    pub usage: Usage,
    pub children_cpu_us: u64,
    pub rss: u64,
    pub rss_anon: u64,
    pub rss_file: u64,
    pub rss_peak: u64,
    pub locked: u64,
    pub threads: u64,
}

pub fn process_usage() -> ProcessUsage {
    let tck = crate::util::clk_tck();
    let mut p = ProcessUsage::default();
    if let Ok(stat) = read_string("/proc/self/stat")
        && let Some(r) = stat.rfind(')')
    {
        let f: Vec<&str> = stat[r + 2..].split_whitespace().collect();
        let ticks = |i: usize| f.get(i).and_then(|v| v.parse::<u64>().ok()).unwrap_or(0);
        p.usage.user_us = ticks(11) * 1_000_000 / tck;
        p.usage.sys_us = ticks(12) * 1_000_000 / tck;
        p.children_cpu_us = (ticks(13) + ticks(14)) * 1_000_000 / tck;
        p.usage.majflt = ticks(9);
    }
    if let Ok(io) = read_string("/proc/self/io") {
        parse_io(&io, &mut p.usage);
    }
    if let Ok(st) = read_string("/proc/self/status") {
        for line in st.lines() {
            let Some((k, v)) = line.split_once(':') else { continue };
            let kb = || crate::util::parse_kb_value(v.trim()).unwrap_or(0);
            match k {
                "VmRSS" => p.rss = kb(),
                "RssAnon" => p.rss_anon = kb(),
                "RssFile" => p.rss_file = kb(),
                "VmHWM" => p.rss_peak = kb(),
                "VmLck" => p.locked = kb(),
                "Threads" => p.threads = v.trim().parse().unwrap_or(0),
                _ => {}
            }
        }
    }
    p
}

/// glibc allocator state: memory the allocator holds from the OS versus
/// what is in use (the difference is fragmentation / cached free chunks).
#[derive(Debug, Default, Clone, Serialize)]
pub struct MallocInfo {
    /// Bytes obtained from the OS (brk arenas + mmapped chunks).
    pub system: u64,
    pub in_use: u64,
    pub free: u64,
    pub mmapped: u64,
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
pub fn malloc_info() -> Option<MallocInfo> {
    // `mallinfo` (not `mallinfo2`, which needs glibc ≥ 2.33) keeps the binary
    // loadable on older distributions; its int fields wrap above 2 GiB, which
    // the daemon never approaches.
    #[allow(deprecated)]
    // SAFETY: mallinfo has no preconditions.
    let m = unsafe { libc::mallinfo() };
    let u = |v: libc::c_int| v as u32 as u64;
    Some(MallocInfo {
        system: u(m.arena) + u(m.hblkhd),
        in_use: u(m.uordblks) + u(m.hblkhd),
        free: u(m.fordblks),
        mmapped: u(m.hblkhd),
    })
}

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
pub fn malloc_info() -> Option<MallocInfo> {
    None
}

/// Resident set of this process, bytes.
fn rss_bytes() -> Option<u64> {
    let statm = crate::util::read_string("/proc/self/statm").ok()?;
    let pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages.saturating_mul(crate::util::page_size()))
}

/// Return free heap memory to the OS (after a large scan). Returns how many
/// bytes of resident memory that released.
///
/// Under `mlockall` the C library cannot do this on its own: `malloc_trim`
/// gives arena pages back with `madvise(MADV_DONTNEED)`, which the kernel
/// refuses for locked pages, so a one-off peak (first baseline, a walk of the
/// whole disk) would stay resident until the next restart. When the host has
/// memory to spare, the lock is therefore lifted for the few milliseconds the
/// trim takes. Under memory pressure nothing is released and nothing is
/// unlocked: the guard must not become evictable exactly when the host is
/// thrashing — the peak is simply kept until a calmer moment.
pub fn release_memory() -> u64 {
    let before = rss_bytes().unwrap_or(0);
    let relock = crate::sched::is_mlocked();
    if relock {
        let calm = crate::psi::read(crate::psi::Resource::Memory)
            .is_ok_and(|p| p.some.avg10 < 1.0 && p.full.is_none_or(|f| f.avg10 < 0.1));
        if !calm || crate::sched::munlock_all().is_err() {
            return 0;
        }
    }
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: malloc_trim has no preconditions.
    unsafe {
        libc::malloc_trim(0);
    }
    if relock && let Err(e) = crate::sched::mlock_all() {
        // Should not happen (the same call succeeded at start-up); say so.
        eprintln!("warden: cannot re-lock memory after trimming: {e}");
    }
    before.saturating_sub(rss_bytes().unwrap_or(before))
}

/// Bound the number of glibc malloc arenas and make large buffers come from
/// (and go back to) `mmap`, so memory freed after a scan is returned to the
/// OS instead of staying resident — and mlocked — in per-thread arenas.
pub fn tune_malloc(arenas: u32) {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    // SAFETY: mallopt has no preconditions; invalid values are rejected.
    unsafe {
        if arenas > 0 {
            libc::mallopt(libc::M_ARENA_MAX, arenas as libc::c_int);
        }
        libc::mallopt(libc::M_MMAP_THRESHOLD, 256 * 1024);
        libc::mallopt(libc::M_TRIM_THRESHOLD, 1024 * 1024);
    }
    #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
    let _ = arenas;
}

/// The daemon's own cgroup path (for its memory accounting).
pub fn self_cgroup() -> Option<String> {
    crate::process::cgroup(std::process::id() as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scan-sized burst of small allocations, of which every 64th survives
    /// (what a scan leaves behind: a little state in the middle of free memory).
    fn burst() -> Vec<Vec<u8>> {
        let mut keep = Vec::new();
        let junk: Vec<Vec<u8>> = (0..400_000).map(|i| vec![(i % 251) as u8; 96]).collect();
        for (i, v) in junk.into_iter().enumerate() {
            if i % 64 == 0 {
                keep.push(v);
            }
        }
        keep
    }

    #[test]
    fn a_peak_is_returned_even_under_mlockall() {
        // `release_memory` consults `sched::is_mlocked`, which is process-wide;
        // this is the only test that touches it.
        if crate::sched::mlock_all().is_err() {
            eprintln!("mlockall not permitted here; skipping");
            return;
        }
        let rss0 = rss_bytes().unwrap();
        let keep = burst();
        let peak = rss_bytes().unwrap();
        assert!(peak > rss0 + (20 << 20), "the burst should be resident: {rss0} → {peak}");
        // what the plain C library manages while the pages are locked
        // SAFETY: no preconditions.
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        unsafe {
            libc::malloc_trim(0);
        }
        let after_plain_trim = rss_bytes().unwrap();
        let released = release_memory();
        let after = rss_bytes().unwrap();
        assert!(crate::sched::is_mlocked(), "locked again afterwards");
        eprintln!(
            "rss: start {rss0}, peak {peak}, plain trim {after_plain_trim}, release_memory {after} (released {released})"
        );
        assert!(after_plain_trim + (2 << 20) > peak, "premise: under mlockall the plain trim gives nothing back");
        assert!(after + (10 << 20) < peak, "release_memory must give the peak back");
        drop(keep);
        crate::sched::munlock_all().unwrap();
    }

    #[test]
    fn thread_usage_moves() {
        let a = thread_usage();
        let mut x = 0u64;
        for i in 0..3_000_000u64 {
            x = x.wrapping_mul(31).wrapping_add(i);
        }
        std::hint::black_box(x);
        let _ = std::fs::read("/proc/self/status");
        let b = thread_usage();
        let d = b.saturating_sub(&a);
        assert!(d.syscr >= 1, "{d:?}");
        assert!(b.cpu_us() >= a.cpu_us());
    }

    #[test]
    fn threads_and_process() {
        let t = threads();
        assert!(!t.is_empty());
        let p = process_usage();
        assert!(p.rss > 0 && p.threads >= 1);
        let mut io = Usage::default();
        parse_io("rchar: 10\nwchar: 2\nsyscr: 3\nsyscw: 4\nread_bytes: 5\nwrite_bytes: 6\n", &mut io);
        assert_eq!((io.rchar, io.syscw, io.write_bytes), (10, 4, 6));
    }
}
