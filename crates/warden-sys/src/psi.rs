//! Pressure Stall Information (Linux 4.20+, `CONFIG_PSI=y`).
//!
//! * `some` — share of time at least one task was stalled on the resource;
//! * `full` — share of time *all* non-idle tasks were stalled simultaneously
//!   (the host does no useful work at all).
//!
//! Besides polling the averages, a process can register a *trigger*
//! (`"some 150000 1000000"` = 150 ms of stall within any 1 s window) and
//! `poll(POLLPRI)` on the file: the kernel wakes it up immediately when the
//! budget is exceeded. Warden uses both.

use crate::util::{cvt, read_string};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct PsiLine {
    pub avg10: f64,
    pub avg60: f64,
    pub avg300: f64,
    /// Total stall time, microseconds.
    pub total_us: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct Psi {
    pub some: PsiLine,
    /// Absent for system-wide CPU on kernels < 5.13.
    pub full: Option<PsiLine>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    Cpu,
    Memory,
    Io,
    Irq,
}

impl Resource {
    pub fn path(self) -> &'static str {
        match self {
            Resource::Cpu => "/proc/pressure/cpu",
            Resource::Memory => "/proc/pressure/memory",
            Resource::Io => "/proc/pressure/io",
            Resource::Irq => "/proc/pressure/irq",
        }
    }
}

pub fn parse(content: &str) -> Option<Psi> {
    let mut psi = Psi::default();
    let mut have_some = false;
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        let kind = parts.next()?;
        let mut l = PsiLine::default();
        for kv in parts {
            let (k, v) = kv.split_once('=')?;
            match k {
                "avg10" => l.avg10 = v.parse().ok()?,
                "avg60" => l.avg60 = v.parse().ok()?,
                "avg300" => l.avg300 = v.parse().ok()?,
                "total" => l.total_us = v.parse().ok()?,
                _ => {}
            }
        }
        match kind {
            "some" => {
                psi.some = l;
                have_some = true;
            }
            "full" => psi.full = Some(l),
            _ => {}
        }
    }
    have_some.then_some(psi)
}

pub fn read(res: Resource) -> io::Result<Psi> {
    read_path(res.path())
}

/// Read a PSI file (system-wide or a cgroup's `memory.pressure`).
pub fn read_path(path: impl AsRef<Path>) -> io::Result<Psi> {
    let s = read_string(path)?;
    parse(&s).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed PSI data"))
}

pub fn available() -> bool {
    read(Resource::Memory).is_ok()
}

/// A registered kernel PSI trigger.
#[derive(Debug)]
pub struct Trigger {
    file: File,
}

impl Trigger {
    /// Register `"<some|full> <stall_us> <window_us>"` on a PSI file.
    /// Requires root (or CAP_SYS_RESOURCE) for system-wide files.
    pub fn new(path: impl AsRef<Path>, kind: &str, stall: Duration, window: Duration) -> io::Result<Self> {
        let mut file =
            OpenOptions::new().read(true).write(true).custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC).open(path)?;
        let spec = format!("{kind} {} {}\0", stall.as_micros(), window.as_micros());
        file.write_all(spec.as_bytes())?;
        Ok(Self { file })
    }

    /// Block until the trigger fires or `timeout` elapses. Returns `true`
    /// when the kernel signalled pressure.
    pub fn wait(&self, timeout: Duration) -> io::Result<bool> {
        let mut pfd = libc::pollfd { fd: self.file.as_raw_fd(), events: libc::POLLPRI, revents: 0 };
        let ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
        // SAFETY: pfd is a valid pollfd for the duration of the call.
        let n = loop {
            match cvt(unsafe { libc::poll(&mut pfd, 1, ms) }) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                other => break other?,
            }
        };
        if n == 0 {
            return Ok(false);
        }
        if pfd.revents & libc::POLLERR != 0 {
            return Err(io::Error::other("PSI trigger: POLLERR (file went away)"));
        }
        Ok(pfd.revents & libc::POLLPRI != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "some avg10=12.50 avg60=3.10 avg300=0.80 total=123456789\nfull avg10=4.00 avg60=1.00 avg300=0.20 total=23456789\n";

    #[test]
    fn parses_some_and_full() {
        let p = parse(SAMPLE).unwrap();
        assert_eq!(p.some.avg10, 12.5);
        assert_eq!(p.some.total_us, 123456789);
        assert_eq!(p.full.unwrap().avg60, 1.0);
    }

    #[test]
    fn cpu_without_full() {
        let p = parse("some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n").unwrap();
        assert!(p.full.is_none());
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("").is_none());
        assert!(parse("some avg10=abc").is_none());
    }
}
