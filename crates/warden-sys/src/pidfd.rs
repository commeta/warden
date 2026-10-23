//! Race-free process signalling.
//!
//! `kill(pid)` is racy: between choosing a victim and signalling it the PID
//! can be recycled by an unrelated process. A pidfd (Linux 5.3+) pins the
//! identity: we open it, then verify the start time still matches the one we
//! observed; every later signal goes to exactly that process or fails.

use crate::process;
use crate::util::cvt_long;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum Handle {
    PidFd(OwnedFd),
    /// Fallback for kernels without pidfd (start time re-checked per signal).
    Legacy,
}

#[derive(Debug)]
pub struct Target {
    pub pid: i32,
    pub start_time: u64,
    handle: Handle,
}

#[derive(Debug, thiserror::Error)]
pub enum TargetError {
    #[error("process {0} no longer exists")]
    Gone(i32),
    #[error("PID {0} was reused by another process")]
    Reused(i32),
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl Target {
    pub fn open(pid: i32, start_time: u64) -> Result<Self, TargetError> {
        if pid <= 1 {
            return Err(TargetError::Io(io::Error::new(io::ErrorKind::PermissionDenied, "refusing PID <= 1")));
        }
        // SAFETY: plain syscall with integer arguments.
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        let handle = match cvt_long(fd) {
            Ok(fd) => {
                // SAFETY: the kernel returned a fresh descriptor we now own.
                Handle::PidFd(unsafe { OwnedFd::from_raw_fd(fd as i32) })
            }
            Err(e) if e.raw_os_error() == Some(libc::ESRCH) => return Err(TargetError::Gone(pid)),
            Err(e) if e.raw_os_error() == Some(libc::ENOSYS) => Handle::Legacy,
            Err(e) => return Err(e.into()),
        };
        // Verify identity *after* pinning it.
        match process::start_time(pid) {
            None => Err(TargetError::Gone(pid)),
            Some(st) if st != start_time => Err(TargetError::Reused(pid)),
            Some(_) => Ok(Self { pid, start_time, handle }),
        }
    }

    pub fn signal(&self, sig: libc::c_int) -> Result<(), TargetError> {
        match &self.handle {
            Handle::PidFd(fd) => {
                // SAFETY: valid pidfd; null siginfo is allowed.
                let r = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        fd.as_raw_fd(),
                        sig,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                };
                match cvt_long(r) {
                    Ok(_) => Ok(()),
                    Err(e) if e.raw_os_error() == Some(libc::ESRCH) => Err(TargetError::Gone(self.pid)),
                    Err(e) => Err(e.into()),
                }
            }
            Handle::Legacy => {
                match process::start_time(self.pid) {
                    None => return Err(TargetError::Gone(self.pid)),
                    Some(st) if st != self.start_time => return Err(TargetError::Reused(self.pid)),
                    _ => {}
                }
                // SAFETY: plain syscall.
                if unsafe { libc::kill(self.pid, sig) } == -1 {
                    let e = io::Error::last_os_error();
                    if e.raw_os_error() == Some(libc::ESRCH) {
                        return Err(TargetError::Gone(self.pid));
                    }
                    return Err(e.into());
                }
                Ok(())
            }
        }
    }

    /// Wait until the process exits. Returns `true` if it did within `timeout`.
    pub fn wait_exit(&self, timeout: Duration) -> bool {
        match &self.handle {
            Handle::PidFd(fd) => {
                let deadline = Instant::now() + timeout;
                loop {
                    let left = deadline.saturating_duration_since(Instant::now());
                    let mut pfd = libc::pollfd { fd: fd.as_raw_fd(), events: libc::POLLIN, revents: 0 };
                    // SAFETY: valid pollfd.
                    let n = unsafe { libc::poll(&mut pfd, 1, left.as_millis().min(i32::MAX as u128) as i32) };
                    if n > 0 {
                        return true;
                    }
                    if n == 0 {
                        return false;
                    }
                    if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                        return false;
                    }
                }
            }
            Handle::Legacy => {
                let deadline = Instant::now() + timeout;
                while Instant::now() < deadline {
                    if process::start_time(self.pid) != Some(self.start_time) {
                        return true;
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                false
            }
        }
    }
}

/// Outcome of a graceful termination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KillOutcome {
    /// Exited after SIGTERM.
    Terminated,
    /// Needed SIGKILL.
    Killed,
    /// Already gone before we could signal it.
    AlreadyGone,
    /// Did not die even after SIGKILL (D state / zombie parent).
    Stuck,
}

/// SIGTERM → wait `grace` → SIGKILL → wait.
pub fn terminate(pid: i32, start_time: u64, grace: Duration) -> Result<KillOutcome, TargetError> {
    let t = match Target::open(pid, start_time) {
        Ok(t) => t,
        Err(TargetError::Gone(_)) => return Ok(KillOutcome::AlreadyGone),
        Err(e) => return Err(e),
    };
    // A stopped process cannot handle SIGTERM: continue it first.
    let _ = t.signal(libc::SIGCONT);
    match t.signal(libc::SIGTERM) {
        Err(TargetError::Gone(_)) => return Ok(KillOutcome::AlreadyGone),
        Err(e) => return Err(e),
        Ok(()) => {}
    }
    if !grace.is_zero() && t.wait_exit(grace) {
        return Ok(KillOutcome::Terminated);
    }
    match t.signal(libc::SIGKILL) {
        Err(TargetError::Gone(_)) => return Ok(KillOutcome::Terminated),
        Err(e) => return Err(e),
        Ok(()) => {}
    }
    Ok(if t.wait_exit(Duration::from_secs(5)) { KillOutcome::Killed } else { KillOutcome::Stuck })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn terminates_child_and_detects_reuse() {
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let st = process::start_time(pid).unwrap();
        assert!(matches!(Target::open(pid, st + 1), Err(TargetError::Reused(_))));
        // Reap concurrently so the child does not linger as a zombie.
        let waiter = std::thread::spawn(move || child.wait());
        let out = terminate(pid, st, Duration::from_secs(2)).unwrap();
        assert_eq!(out, KillOutcome::Terminated);
        waiter.join().unwrap().unwrap();
        assert_eq!(terminate(pid, st, Duration::from_millis(10)).unwrap(), KillOutcome::AlreadyGone);
    }

    #[test]
    fn refuses_init() {
        assert!(Target::open(1, 0).is_err());
    }
}
