//! Inode attribute flags (`chattr`/`lsattr`). Attackers mark webshells and
//! `.htaccess` immutable (`chattr +i`) so that cleanup scripts — and naive
//! remediation — fail with EPERM. Clearing the flag needs CAP_LINUX_IMMUTABLE.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd};
use std::path::Path;

pub const FS_IMMUTABLE_FL: libc::c_long = 0x0000_0010;
pub const FS_APPEND_FL: libc::c_long = 0x0000_0020;

fn open(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    // O_NOFOLLOW: never act on a symlink's target; O_NONBLOCK: never block on FIFOs.
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
}

pub fn get(path: &Path) -> io::Result<libc::c_long> {
    get_fd(open(path)?.as_fd())
}

/// The flags of an open file or directory.
pub fn get_fd(fd: BorrowedFd<'_>) -> io::Result<libc::c_long> {
    let mut flags: libc::c_long = 0;
    // SAFETY: valid fd and out pointer of the size the ioctl expects.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) };
    if r == -1 { Err(io::Error::last_os_error()) } else { Ok(flags) }
}

#[cfg(test)]
fn set(path: &Path, flags: libc::c_long) -> io::Result<()> {
    set_fd(open(path)?.as_fd(), flags)
}

fn set_fd(fd: BorrowedFd<'_>, flags: libc::c_long) -> io::Result<()> {
    // SAFETY: valid fd and pointer.
    let r = unsafe { libc::ioctl(fd.as_raw_fd(), libc::FS_IOC_SETFLAGS, &flags) };
    if r == -1 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// Clear the immutable and append-only flags of an open file or directory
/// (what the descriptor refers to, whatever its name points at by now).
/// Returns the flags that were cleared (0 if none).
pub fn clear_protection_fd(fd: BorrowedFd<'_>) -> io::Result<libc::c_long> {
    let flags = get_fd(fd)?;
    let prot = flags & (FS_IMMUTABLE_FL | FS_APPEND_FL);
    if prot != 0 {
        set_fd(fd, flags & !prot)?;
    }
    Ok(prot)
}

/// Re-apply previously cleared flags (used to restore a directory).
pub fn restore_fd(fd: BorrowedFd<'_>, cleared: libc::c_long) -> io::Result<()> {
    if cleared == 0 {
        return Ok(());
    }
    let flags = get_fd(fd)?;
    set_fd(fd, flags | cleared)
}

pub fn describe(cleared: libc::c_long) -> &'static str {
    match (cleared & FS_IMMUTABLE_FL != 0, cleared & FS_APPEND_FL != 0) {
        (true, true) => "immutable+append-only",
        (true, false) => "immutable",
        (false, true) => "append-only",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immutable_roundtrip_when_supported() {
        let d = tempfile::tempdir_in("/var/tmp").unwrap();
        let f = d.path().join("x");
        std::fs::write(&f, "x").unwrap();
        let Ok(flags) = get(&f) else { return }; // fs without attribute support (tmpfs/overlay)
        if set(&f, flags | FS_IMMUTABLE_FL).is_err() {
            return; // no CAP_LINUX_IMMUTABLE in this environment
        }
        assert!(std::fs::remove_file(&f).is_err());
        assert_eq!(clear_protection_fd(open(&f).unwrap().as_fd()).unwrap(), FS_IMMUTABLE_FL);
        assert_eq!(describe(FS_IMMUTABLE_FL), "immutable");
        std::fs::remove_file(&f).unwrap();
    }
}
