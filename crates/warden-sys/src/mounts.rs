//! Mount table (`/proc/self/mountinfo`) and filesystem usage (`statvfs`).

use crate::util::read_string;
use std::ffi::CString;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Mount {
    pub mount_id: u32,
    pub parent_id: u32,
    /// `major:minor`
    pub device: String,
    pub root: String,
    pub mount_point: String,
    pub options: String,
    pub fstype: String,
    pub source: String,
    pub super_options: String,
}

impl Mount {
    pub fn is_readonly(&self) -> bool {
        self.options.split(',').any(|o| o == "ro")
    }

    /// `dev_t` encoded like `stat.st_dev` (for matching file metadata).
    pub fn dev(&self) -> Option<u64> {
        let (ma, mi) = self.device.split_once(':')?;
        let (ma, mi): (u32, u32) = (ma.parse().ok()?, mi.parse().ok()?);
        Some(libc::makedev(ma, mi))
    }
}

/// Decode the `\040`-style octal escapes used in mountinfo.
pub fn unescape(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        let octal = (i + 3 < b.len() && b[i] == b'\\')
            .then(|| &b[i + 1..i + 4])
            .filter(|d| d.iter().all(|c| (b'0'..=b'7').contains(c)))
            .map(|d| u32::from(d[0] - b'0') * 64 + u32::from(d[1] - b'0') * 8 + u32::from(d[2] - b'0'))
            .and_then(|v| u8::try_from(v).ok());
        // `\545` is not a byte (the kernel writes `\134` for a backslash):
        // kept as text, not an overflow (found by the procfs fuzz target)
        if let Some(v) = octal {
            out.push(v);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

pub fn parse_mountinfo(content: &str) -> Vec<Mount> {
    content
        .lines()
        .filter_map(|line| {
            let (pre, post) = line.split_once(" - ")?;
            let pre: Vec<&str> = pre.split(' ').collect();
            let post: Vec<&str> = post.split(' ').collect();
            if pre.len() < 6 || post.len() < 2 {
                return None;
            }
            Some(Mount {
                mount_id: pre[0].parse().ok()?,
                parent_id: pre[1].parse().ok()?,
                device: pre[2].to_owned(),
                root: unescape(pre[3]),
                mount_point: unescape(pre[4]),
                options: pre[5].to_owned(),
                fstype: post[0].to_owned(),
                source: unescape(post[1]),
                super_options: post.get(2).copied().unwrap_or("").to_owned(),
            })
        })
        .collect()
}

pub fn mounts() -> io::Result<Vec<Mount>> {
    Ok(parse_mountinfo(&read_string("/proc/self/mountinfo")?))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, serde::Serialize)]
pub struct FsUsage {
    pub total: u64,
    pub used: u64,
    /// Available to unprivileged users (what `df` shows).
    pub avail: u64,
    pub inodes: u64,
    pub inodes_free: u64,
    pub readonly: bool,
}

impl FsUsage {
    /// Usage percent the way `df` computes it: used / (used + avail).
    pub fn used_percent(&self) -> f64 {
        let denom = self.used + self.avail;
        if denom == 0 { 0.0 } else { self.used as f64 * 100.0 / denom as f64 }
    }

    pub fn inode_percent(&self) -> f64 {
        if self.inodes == 0 {
            0.0
        } else {
            (self.inodes - self.inodes_free.min(self.inodes)) as f64 * 100.0 / self.inodes as f64
        }
    }
}

pub fn statvfs(path: impl AsRef<Path>) -> io::Result<FsUsage> {
    let c = CString::new(path.as_ref().as_os_str().as_bytes()).map_err(io::Error::other)?;
    // SAFETY: zeroed statvfs is a valid out-parameter; c is NUL-terminated.
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    crate::util::cvt(unsafe { libc::statvfs(c.as_ptr(), &mut s) })?;
    let frsize = if s.f_frsize > 0 { s.f_frsize } else { s.f_bsize };
    let total = s.f_blocks as u64 * frsize as u64;
    let free = s.f_bfree as u64 * frsize as u64;
    let avail = s.f_bavail as u64 * frsize as u64;
    Ok(FsUsage {
        total,
        used: total.saturating_sub(free),
        avail,
        inodes: s.f_files as u64,
        inodes_free: s.f_ffree as u64,
        readonly: (s.f_flag & libc::ST_RDONLY) != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Found by the procfs fuzz target: `\545` overflowed the byte.
    #[test]
    fn an_escape_above_255_is_text_not_an_overflow() {
        assert_eq!(unescape("a\\545b"), "a\\545b");
        assert_eq!(unescape("a\\040b\\134"), "a b\\");
        assert_eq!(unescape("\\04"), "\\04");
    }

    const SAMPLE: &str = "\
22 1 252:1 / / rw,relatime shared:1 - ext4 /dev/vda1 rw,errors=remount-ro
23 22 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:12 - proc proc rw
40 22 252:2 / /mnt/my\\040disk ro,relatime - xfs /dev/vdb rw,attr2
";

    #[test]
    fn parses_mountinfo() {
        let m = parse_mountinfo(SAMPLE);
        assert_eq!(m.len(), 3);
        assert_eq!(m[0].mount_point, "/");
        assert_eq!(m[0].fstype, "ext4");
        assert_eq!(m[2].mount_point, "/mnt/my disk");
        assert!(m[2].is_readonly());
        assert!(!m[0].is_readonly());
        assert_eq!(m[0].dev(), Some(libc::makedev(252, 1)));
    }

    #[test]
    fn statvfs_root() {
        let u = statvfs("/").unwrap();
        assert!(u.total > 0);
        assert!(u.used_percent() >= 0.0 && u.used_percent() <= 100.0);
    }
}
