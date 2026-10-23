//! Self-protection and scheduling knobs for the daemon's own threads.

use crate::util::cvt;
use std::io;

const IOPRIO_WHO_PROCESS: libc::c_int = 1;
const IOPRIO_CLASS_BE: libc::c_int = 2;
const IOPRIO_CLASS_IDLE: libc::c_int = 3;
const IOPRIO_CLASS_SHIFT: libc::c_int = 13;

pub fn gettid() -> i32 {
    // SAFETY: gettid has no preconditions.
    unsafe { libc::syscall(libc::SYS_gettid) as i32 }
}

/// Put the *calling thread* into the idle I/O class and nice 19 — used by
/// background scanners (FIM, SUID scan) so they never compete with
/// production I/O.
pub fn background_thread() -> io::Result<()> {
    let tid = gettid();
    let prio = IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT;
    // SAFETY: plain syscalls on our own thread.
    unsafe {
        if libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, tid, prio) == -1 {
            return Err(io::Error::last_os_error());
        }
        cvt(libc::setpriority(libc::PRIO_PROCESS, tid as libc::id_t, 19))?;
    }
    Ok(())
}

/// Move the *calling thread* between the idle I/O class and the lowest
/// best-effort level (7) — see [`crate::pace`].
pub fn set_thread_io_class(idle: bool) -> io::Result<()> {
    let prio = if idle { IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT } else { (IOPRIO_CLASS_BE << IOPRIO_CLASS_SHIFT) | 7 };
    // SAFETY: plain syscall on our own thread.
    let r = unsafe { libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, gettid(), prio) };
    if r == -1 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Thread IDs of a process (`/proc/<pid>/task`).
pub fn threads(pid: i32) -> Vec<i32> {
    std::fs::read_dir(format!("/proc/{pid}/task"))
        .map(|rd| rd.filter_map(Result::ok).filter_map(|e| e.file_name().to_str()?.parse().ok()).collect())
        .unwrap_or_default()
}

/// Lower the CPU (nice) and optionally I/O (idle class) priority of every
/// thread of `pid`. Returns the number of threads changed.
pub fn throttle_process(pid: i32, nice: i32, io_idle: bool) -> io::Result<usize> {
    let tids = threads(pid);
    if tids.is_empty() {
        return Err(io::Error::new(io::ErrorKind::NotFound, "process has no threads (exited?)"));
    }
    let mut n = 0;
    let mut last_err = None;
    for tid in tids {
        // SAFETY: plain syscalls with integer arguments.
        let r = unsafe { libc::setpriority(libc::PRIO_PROCESS, tid as libc::id_t, nice.clamp(-20, 19)) };
        if r == -1 {
            last_err = Some(io::Error::last_os_error());
            continue;
        }
        if io_idle {
            let prio = IOPRIO_CLASS_IDLE << IOPRIO_CLASS_SHIFT;
            // SAFETY: plain syscall.
            unsafe { libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, tid, prio) };
        }
        n += 1;
    }
    match (n, last_err) {
        (0, Some(e)) => Err(e),
        _ => Ok(n),
    }
}

/// Is the process under `mlockall` (see [`mlock_all`])?
static LOCKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

pub fn is_mlocked() -> bool {
    LOCKED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Lock current and future pages in RAM, faulting them in lazily
/// (`MCL_ONFAULT`, Linux 4.4+) so idle stacks do not consume memory.
pub fn mlock_all() -> io::Result<()> {
    // SAFETY: plain syscall.
    let mut r = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE | libc::MCL_ONFAULT) };
    if r != 0 {
        // Older kernels: retry without ONFAULT.
        // SAFETY: plain syscall.
        r = unsafe { libc::mlockall(libc::MCL_CURRENT | libc::MCL_FUTURE) };
    }
    cvt(r)?;
    LOCKED.store(true, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// Undo [`mlock_all`].
pub fn munlock_all() -> io::Result<()> {
    // SAFETY: plain syscall.
    cvt(unsafe { libc::munlockall() })?;
    LOCKED.store(false, std::sync::atomic::Ordering::Relaxed);
    Ok(())
}

pub fn set_oom_score_adj(v: i32) -> io::Result<()> {
    std::fs::write("/proc/self/oom_score_adj", v.to_string())
}

/// Seccomp mode of this process (`0` none, `1` strict, `2` filter).
pub fn seccomp_mode() -> Option<u8> {
    let s = std::fs::read_to_string("/proc/self/status").ok()?;
    s.lines().find_map(|l| l.strip_prefix("Seccomp:")).and_then(|v| v.trim().parse().ok())
}

/// Explain a permission failure: missing capability, or a syscall blocked
/// by the service's seccomp filter (`SystemCallErrorNumber=EPERM`).
pub fn permission_hint(e: &std::io::Error, cap: &str) -> String {
    if e.raw_os_error() != Some(libc::EPERM) && e.raw_os_error() != Some(libc::EACCES) {
        return String::new();
    }
    if seccomp_mode() == Some(2) {
        format!(" (missing {cap}, or the call is blocked by the unit's SystemCallFilter — run `wardenctl doctor`)")
    } else {
        format!(" (needs {cap})")
    }
}

pub fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() == 0 }
}
