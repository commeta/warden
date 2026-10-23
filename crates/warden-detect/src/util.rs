//! Helpers shared by detectors.

use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use warden_core::ProcessRef;
use warden_sys::process;

pub use warden_sys::cmd::{run_cmd, which};
pub use warden_sys::process::exe_basename;

/// Build a [`ProcessRef`] for a live PID (None if it vanished).
pub fn process_ref(pid: i32, users: &dyn Fn(u32) -> String) -> Option<ProcessRef> {
    let st = process::read_stat(pid).ok()?;
    let ss = process::read_status(pid).ok();
    let uid = ss.as_ref().map(|s| s.uid[0]);
    let cgroup = process::cgroup(pid);
    Some(ProcessRef {
        pid,
        start_time: st.starttime,
        comm: st.comm,
        exe: process::exe(pid),
        cmdline: process::cmdline(pid, 1024),
        uid,
        user: uid.map(users),
        ppid: Some(st.ppid),
        container: cgroup.as_deref().and_then(warden_sys::cgroup::container_of),
        cgroup,
    })
}

/// Follows a growing text file across rotation (rename + create) and
/// truncation (copytruncate). Starts at the end of the file.
#[derive(Debug)]
pub struct FileTail {
    path: PathBuf,
    reader: Option<BufReader<std::fs::File>>,
    ino: u64,
    pos: u64,
    partial: String,
}

impl FileTail {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let mut t = Self { path: path.into(), reader: None, ino: 0, pos: 0, partial: String::new() };
        t.open(true);
        t
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn open(&mut self, at_end: bool) {
        self.reader = None;
        if let Ok(mut f) = std::fs::File::open(&self.path) {
            let md = f.metadata().ok();
            self.ino = md.as_ref().map(|m| m.ino()).unwrap_or(0);
            self.pos = if at_end { md.map(|m| m.len()).unwrap_or(0) } else { 0 };
            if f.seek(SeekFrom::Start(self.pos)).is_ok() {
                self.reader = Some(BufReader::new(f));
            }
        }
    }

    /// Return complete new lines (at most `max`).
    pub fn poll(&mut self, max: usize) -> Vec<String> {
        // Rotation / truncation checks.
        match std::fs::metadata(&self.path) {
            Ok(md) if self.reader.is_none() => {
                let _ = md;
                self.open(false);
            }
            Ok(md) if md.ino() != self.ino => {
                // Drain the old file first, then switch.
                let mut lines = self.read_lines(max);
                self.open(false);
                lines.extend(self.read_lines(max.saturating_sub(lines.len())));
                return lines;
            }
            Ok(md) if md.len() < self.pos => self.open(false),
            Err(_) => return Vec::new(),
            _ => {}
        }
        self.read_lines(max)
    }

    fn read_lines(&mut self, max: usize) -> Vec<String> {
        let mut out = Vec::new();
        let Some(r) = self.reader.as_mut() else { return out };
        let mut buf = String::new();
        while out.len() < max {
            buf.clear();
            match r.read_line(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    self.pos += n as u64;
                    if buf.ends_with('\n') {
                        let mut line = std::mem::take(&mut self.partial);
                        line.push_str(buf.trim_end_matches(['\n', '\r']));
                        out.push(line);
                    } else {
                        self.partial.push_str(&buf);
                    }
                }
                Err(_) => break,
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn tail_follows_rotation_and_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.log");
        std::fs::write(&p, "old line\n").unwrap();
        let mut t = FileTail::new(&p);
        assert!(t.poll(100).is_empty());
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        write!(f, "one\ntw").unwrap();
        assert_eq!(t.poll(100), vec!["one"]);
        writeln!(f, "o").unwrap();
        assert_eq!(t.poll(100), vec!["two"]);
        // rotation
        std::fs::rename(&p, dir.path().join("a.log.1")).unwrap();
        writeln!(f, "late").unwrap();
        std::fs::write(&p, "fresh\n").unwrap();
        assert_eq!(t.poll(100), vec!["late", "fresh"]);
        // truncation
        std::fs::write(&p, "x\n").unwrap();
        assert_eq!(t.poll(100), vec!["x"]);
    }
}
