//! fanotify (Linux 2.6.37+, `CAP_SYS_ADMIN`): filesystem-wide change
//! notification that, unlike inotify, reports **which process** wrote the
//! file. That PID is what lets Warden name the PHP/Node worker that is
//! infecting a site.

use crate::util::cvt;
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

const METADATA_LEN: usize = 24;

pub const FAN_CLOSE_WRITE: u64 = 0x0000_0008;
pub const FAN_Q_OVERFLOW: u64 = 0x0000_4000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event {
    pub mask: u64,
    /// PID of the process that caused the event.
    pub pid: i32,
    /// Path of the affected file (resolved from the event descriptor).
    pub path: Option<PathBuf>,
}

impl Event {
    pub fn overflow(&self) -> bool {
        self.mask & FAN_Q_OVERFLOW != 0
    }
}

/// `(mask, fd, pid)` triples from a raw read buffer.
pub fn parse_metadata(buf: &[u8]) -> Vec<(u64, i32, i32)> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + METADATA_LEN <= buf.len() {
        let b = &buf[off..];
        let event_len = u32::from_ne_bytes([b[0], b[1], b[2], b[3]]) as usize;
        if event_len < METADATA_LEN || off + event_len > buf.len() {
            break;
        }
        let mask = u64::from_ne_bytes(b[8..16].try_into().unwrap_or([0; 8]));
        let fd = i32::from_ne_bytes(b[16..20].try_into().unwrap_or([0; 4]));
        let pid = i32::from_ne_bytes(b[20..24].try_into().unwrap_or([0; 4]));
        out.push((mask, fd, pid));
        off += event_len;
    }
    out
}

#[derive(Debug)]
pub struct Fanotify {
    fd: OwnedFd,
    buf: Vec<u8>,
}

impl Fanotify {
    pub fn new() -> io::Result<Self> {
        // SAFETY: plain syscall wrapper.
        let raw = cvt(unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC,
                (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as libc::c_uint,
            )
        })?;
        // SAFETY: fresh descriptor owned by us.
        Ok(Self { fd: unsafe { OwnedFd::from_raw_fd(raw) }, buf: vec![0u8; 64 * 1024] })
    }

    /// Watch close-after-write on the whole mount containing `path`.
    pub fn watch_mount(&self, path: &Path) -> io::Result<()> {
        let c = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
        // SAFETY: valid fd and NUL-terminated path.
        cvt(unsafe {
            libc::fanotify_mark(
                self.fd.as_raw_fd(),
                libc::FAN_MARK_ADD | libc::FAN_MARK_MOUNT,
                FAN_CLOSE_WRITE,
                libc::AT_FDCWD,
                c.as_ptr(),
            )
        })?;
        Ok(())
    }

    /// Stop receiving close-after-write events for files directly inside
    /// `dir` (a busy directory outside every watched site: PHP sessions,
    /// caches, spool files). Needs Linux 6.0 (`FAN_MARK_IGNORE`); older
    /// kernels return `EINVAL` and the events keep coming (only costlier).
    pub fn ignore_dir(&self, dir: &Path) -> io::Result<()> {
        let c = CString::new(dir.as_os_str().as_bytes()).map_err(io::Error::other)?;
        // SAFETY: valid fd and NUL-terminated path.
        cvt(unsafe {
            libc::fanotify_mark(
                self.fd.as_raw_fd(),
                libc::FAN_MARK_ADD | libc::FAN_MARK_IGNORE_SURV,
                FAN_CLOSE_WRITE | libc::FAN_EVENT_ON_CHILD,
                libc::AT_FDCWD,
                c.as_ptr(),
            )
        })?;
        Ok(())
    }

    /// Wait up to `timeout` for events (empty vector on timeout).
    pub fn read_timeout(&mut self, timeout: std::time::Duration) -> io::Result<Vec<Event>> {
        if !crate::util::wait_readable(self.fd.as_raw_fd(), timeout)? {
            return Ok(Vec::new());
        }
        self.read()
    }

    /// Block until events arrive.
    pub fn read(&mut self) -> io::Result<Vec<Event>> {
        let n = loop {
            // SAFETY: buf valid for writes.
            let n =
                unsafe { libc::read(self.fd.as_raw_fd(), self.buf.as_mut_ptr() as *mut libc::c_void, self.buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            break n as usize;
        };
        let mut out = Vec::new();
        for (mask, fd, pid) in parse_metadata(&self.buf[..n]) {
            let path = if fd >= 0 {
                let p = std::fs::read_link(format!("/proc/self/fd/{fd}")).ok();
                // SAFETY: the kernel handed us this descriptor; we must close it.
                unsafe { libc::close(fd) };
                p
            } else {
                None
            };
            out.push(Event { mask, pid, path });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_metadata_records() {
        let mut buf = Vec::new();
        for (fd, pid) in [(5i32, 100i32), (-1, 200)] {
            buf.extend_from_slice(&(METADATA_LEN as u32).to_ne_bytes());
            buf.push(3);
            buf.push(0);
            buf.extend_from_slice(&(METADATA_LEN as u16).to_ne_bytes());
            buf.extend_from_slice(&FAN_CLOSE_WRITE.to_ne_bytes());
            buf.extend_from_slice(&fd.to_ne_bytes());
            buf.extend_from_slice(&pid.to_ne_bytes());
        }
        let v = parse_metadata(&buf);
        assert_eq!(v, vec![(FAN_CLOSE_WRITE, 5, 100), (FAN_CLOSE_WRITE, -1, 200)]);
        assert!(parse_metadata(&buf[..10]).is_empty());
    }
}
