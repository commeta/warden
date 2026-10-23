//! Structured kernel log reader (`/dev/kmsg`).
//!
//! Each `read(2)` returns exactly one record:
//! `"<prio>,<seq>,<usec>,<flags>[,...];<message>\n[ KEY=VALUE\n...]"`.
//! `EPIPE` means the ring buffer overwrote records we had not read yet; we
//! just continue with the next one.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Record {
    /// syslog level 0 (emerg) .. 7 (debug)
    pub level: u8,
    pub facility: u8,
    pub seq: u64,
    /// Monotonic microseconds since boot.
    pub ts_us: u64,
    pub message: String,
}

pub fn parse_record(raw: &str) -> Option<Record> {
    let (header, rest) = raw.split_once(';')?;
    let mut h = header.split(',');
    let prio: u32 = h.next()?.parse().ok()?;
    let seq = h.next()?.parse().ok()?;
    let ts_us = h.next()?.parse().ok()?;
    // Continuation (dictionary) lines start with a space.
    let message = rest.split('\n').next().unwrap_or("").to_owned();
    Some(Record { level: (prio & 7) as u8, facility: (prio >> 3) as u8, seq, ts_us, message: unescape(&message) })
}

/// kmsg escapes non-printable bytes as `\xNN`.
fn unescape(s: &str) -> String {
    if !s.contains("\\x") {
        return s.to_owned();
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && b.get(i + 1) == Some(&b'x') && i + 4 <= b.len() {
            let hex = std::str::from_utf8(&b[i + 2..i + 4]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
            if let Some(v) = hex {
                out.push(v);
                i += 4;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[derive(Debug)]
pub struct Reader {
    file: File,
    buf: Vec<u8>,
}

impl Reader {
    /// Open `/dev/kmsg`. With `from_end`, existing history is skipped and only
    /// new records are returned.
    pub fn open(from_end: bool) -> io::Result<Self> {
        let mut file = File::open("/dev/kmsg")?;
        if from_end {
            file.seek(SeekFrom::End(0))?;
        }
        Ok(Self { file, buf: vec![0u8; 8192] })
    }

    /// Wait up to `timeout` for the next record (`Ok(None)` on timeout).
    pub fn next_record_timeout(&mut self, timeout: std::time::Duration) -> io::Result<Option<Record>> {
        use std::os::fd::AsRawFd;
        if !crate::util::wait_readable(self.file.as_raw_fd(), timeout)? {
            return Ok(None);
        }
        self.next_record().map(Some)
    }

    /// Block until the next record arrives.
    pub fn next_record(&mut self) -> io::Result<Record> {
        loop {
            match self.file.read(&mut self.buf) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "kmsg closed")),
                Ok(n) => {
                    let s = String::from_utf8_lossy(&self.buf[..n]);
                    if let Some(r) = parse_record(&s) {
                        return Ok(r);
                    }
                }
                Err(e) if e.raw_os_error() == Some(libc::EPIPE) => continue,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_records() {
        let r = parse_record("6,339,5140900,-;NET: Registered protocol family 10\n SUBSYSTEM=net\n").unwrap();
        assert_eq!(r.level, 6);
        assert_eq!(r.facility, 0);
        assert_eq!(r.seq, 339);
        assert_eq!(r.ts_us, 5140900);
        assert_eq!(r.message, "NET: Registered protocol family 10");

        let r = parse_record("3,1,2,-,caller=T1;Out of memory: Killed process 4242 (php-fpm8.3)").unwrap();
        assert_eq!(r.level, 3);
        assert!(r.message.starts_with("Out of memory"));

        let r = parse_record("4,5,6,c;a\\x20b").unwrap();
        assert_eq!(r.message, "a b");
        assert!(parse_record("garbage").is_none());
    }
}
