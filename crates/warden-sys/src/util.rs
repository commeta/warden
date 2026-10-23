//! Small file helpers: reading kernel pseudo files, atomic replacement.

use std::io;
use std::path::Path;

/// Read a pseudo file (`/proc`, `/sys`) completely.
///
/// `std::fs::read` asks for the size first (`statx`: always 0 for kernel
/// files) and then probes with small, growing reads — about six `read`
/// calls for one `/proc/<pid>/status`. Kernel files fit an 8 KiB chunk: one
/// `read` for the data and one for EOF. This runs for every `exec` on the
/// host (process sensor), so the difference is real.
pub fn read_bytes(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut chunk = [0u8; 8192];
    let mut out = Vec::new();
    loop {
        match f.read(&mut chunk) {
            Ok(0) => return Ok(out),
            Ok(n) => out.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

/// Read a single-record `/proc/<pid>` file (`stat`, `status`, `cmdline`,
/// `environ`, `cgroup`): these return everything they have in one `read`,
/// so a short read is the end and the EOF probe is skipped — one system
/// call less per file, and for `cmdline`/`environ` one less walk of the
/// target's memory. Multi-record files (`/proc/net/*`) must use
/// [`read_bytes`]: they may return less than asked before the end.
pub fn read_record(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(path)?;
    let mut out = vec![0u8; 8192];
    let mut len = 0;
    loop {
        match f.read(&mut out[len..]) {
            Ok(0) => break,
            Ok(n) => {
                len += n;
                if len < out.len() {
                    break;
                }
                out.resize(out.len() * 2, 0);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    out.truncate(len);
    Ok(out)
}

fn lossy(v: Vec<u8>) -> String {
    match String::from_utf8(v) {
        Ok(s) => s,
        Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
    }
}

/// [`read_record`] as a string (invalid UTF-8 replaced).
pub fn read_record_lossy(path: impl AsRef<Path>) -> io::Result<String> {
    Ok(lossy(read_record(path)?))
}

/// Read a pseudo file into a string (see [`read_bytes`]).
pub fn read_string(path: impl AsRef<Path>) -> io::Result<String> {
    String::from_utf8(read_bytes(path)?).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Native-endian `u32` at `off` (kernel structures: netlink, fanotify).
pub(crate) fn u32_ne(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_ne_bytes(b.get(off..off.checked_add(4)?)?.try_into().ok()?))
}

pub fn read_u64(path: impl AsRef<Path>) -> Option<u64> {
    read_string(path).ok()?.trim().parse().ok()
}

pub fn read_trimmed(path: impl AsRef<Path>) -> Option<String> {
    Some(read_string(path).ok()?.trim().to_owned())
}

/// Replace `path` with `data` atomically: a reader (or a crash) sees the old
/// file or the new one, never half of it. Creates the parent directory.
pub fn write_atomic(path: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write;
    if let Some(d) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    let written = std::fs::File::create(&tmp).and_then(|mut f| {
        f.write_all(data)?;
        f.sync_all()
    });
    match written.and_then(|()| std::fs::rename(&tmp, path)) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Parse `Key:   value [kB]` lines (meminfo, status) into (key, value-in-units).
pub fn parse_kv_line(line: &str) -> Option<(&str, &str)> {
    let (k, v) = line.split_once(':')?;
    Some((k.trim(), v.trim()))
}

/// Parse the first number of a `"123 kB"` style value; kB are converted to bytes.
pub fn parse_kb_value(v: &str) -> Option<u64> {
    let mut it = v.split_whitespace();
    let n: u64 = it.next()?.parse().ok()?;
    match it.next() {
        Some("kB") => Some(n * 1024),
        _ => Some(n),
    }
}

pub fn clk_tck() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if v > 0 { v as u64 } else { 100 }
}

pub fn page_size() -> u64 {
    // SAFETY: sysconf has no preconditions.
    let v = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if v > 0 { v as u64 } else { 4096 }
}

pub fn nproc() -> usize {
    // SAFETY: sysconf has no preconditions.
    let v = unsafe { libc::sysconf(libc::_SC_NPROCESSORS_ONLN) };
    if v > 0 { v as usize } else { 1 }
}

pub fn last_os_error() -> io::Error {
    io::Error::last_os_error()
}

/// Check a libc return value (-1 → errno).
pub fn cvt(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret == -1 { Err(last_os_error()) } else { Ok(ret) }
}

pub fn cvt_long(ret: libc::c_long) -> io::Result<libc::c_long> {
    if ret == -1 { Err(last_os_error()) } else { Ok(ret) }
}

/// Wait until `fd` is readable. `Ok(false)` on timeout. Lets blocking
/// sensors (kmsg, netlink, fanotify, pipes) notice reloads and shutdown
/// instead of sleeping in `read()` until the next event — which on a quiet
/// host may be hours away.
pub fn wait_readable(fd: std::os::fd::RawFd, timeout: std::time::Duration) -> io::Result<bool> {
    let mut pfd = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    let ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
    loop {
        // SAFETY: pfd is a valid pollfd for the duration of the call.
        match cvt(unsafe { libc::poll(&mut pfd, 1, ms) }) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
            Ok(0) => return Ok(false),
            Ok(_) => return Ok(pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0),
        }
    }
}

/// Line reader over a pipe/socket with a timeout per call (for child
/// processes such as `journalctl -f`).
#[derive(Debug)]
pub struct LineReader<R> {
    inner: R,
    buf: Vec<u8>,
    eof: bool,
}

impl<R: std::io::Read + std::os::fd::AsRawFd> LineReader<R> {
    pub fn new(inner: R) -> Self {
        Self { inner, buf: Vec::with_capacity(8192), eof: false }
    }

    /// Next complete line (without `\n`), `Ok(None)` on timeout,
    /// `Err(UnexpectedEof)` once the writer closed the pipe.
    pub fn next_line(&mut self, timeout: std::time::Duration) -> io::Result<Option<String>> {
        let deadline = std::time::Instant::now() + timeout;
        loop {
            if let Some(i) = self.buf.iter().position(|b| *b == b'\n') {
                let rest = self.buf.split_off(i + 1);
                let mut line = std::mem::replace(&mut self.buf, rest);
                line.pop();
                return Ok(Some(String::from_utf8_lossy(&line).into_owned()));
            }
            if self.eof {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "pipe closed"));
            }
            let left = deadline.saturating_duration_since(std::time::Instant::now());
            if left.is_zero() || !wait_readable(self.inner.as_raw_fd(), left)? {
                return Ok(None);
            }
            let mut chunk = [0u8; 8192];
            match self.inner.read(&mut chunk) {
                Ok(0) => self.eof = true,
                Ok(n) => {
                    // A runaway line must not grow the buffer without bound.
                    if self.buf.len() + n > 1 << 20 {
                        self.buf.clear();
                    }
                    self.buf.extend_from_slice(&chunk[..n]);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    pub fn get_mut(&mut self) -> &mut R {
        &mut self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_replaces_whole_files_and_leaves_nothing_behind() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("a/b/state.json");
        write_atomic(&p, b"one").unwrap();
        write_atomic(&p, b"two").unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        let names: Vec<_> = std::fs::read_dir(p.parent().unwrap()).unwrap().map(|e| e.unwrap().file_name()).collect();
        assert_eq!(names.len(), 1, "no temp files left: {names:?}");
        // a failure (the target is a directory) cleans its temp file up too
        let dir_target = d.path().join("dir");
        std::fs::create_dir(&dir_target).unwrap();
        assert!(write_atomic(&dir_target, b"x").is_err());
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 2);
    }

    #[test]
    fn kv_and_kb() {
        let (k, v) = parse_kv_line("VmRSS:\t   1234 kB").unwrap();
        assert_eq!(k, "VmRSS");
        assert_eq!(parse_kb_value(v), Some(1234 * 1024));
        assert_eq!(parse_kb_value("17"), Some(17));
        assert!(clk_tck() > 0 && page_size() >= 4096 && nproc() >= 1);
    }

    #[test]
    fn read_record_handles_short_and_long_files() {
        let st = read_record("/proc/self/status").unwrap();
        assert!(st.starts_with(b"Name:") && st.ends_with(b"\n"));
        let d = tempfile::tempdir().unwrap();
        let big: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        std::fs::write(d.path().join("big"), &big).unwrap();
        assert_eq!(read_record(d.path().join("big")).unwrap(), big);
        std::fs::write(d.path().join("exact"), vec![7u8; 8192]).unwrap();
        assert_eq!(read_record(d.path().join("exact")).unwrap().len(), 8192);
        std::fs::write(d.path().join("empty"), b"").unwrap();
        assert!(read_record(d.path().join("empty")).unwrap().is_empty());
    }
}
