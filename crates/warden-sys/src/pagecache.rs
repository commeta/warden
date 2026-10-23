//! Keep scans from polluting the page cache.
//!
//! Reading a file to hash it pulls it into the page cache, and that cache is
//! charged to Warden's cgroup (`systemctl status wardend` → "Memory:"). Files
//! that were *already* cached (hot web files, running binaries) must stay
//! there; files Warden alone brought in can be dropped right away.
//!
//! [`ColdRead`] asks the kernel how much of the file was resident before the
//! read (`cachestat(2)`, Linux 6.5+) and, if nothing was, drops the pages
//! afterwards with `posix_fadvise(DONTNEED)`. Without `cachestat` (older
//! kernels, or a seccomp filter that does not allow it) nothing is dropped:
//! never evicting someone else's hot data is more important than our
//! accounting.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::sync::atomic::{AtomicU8, Ordering};

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64"))]
const SYS_CACHESTAT: libc::c_long = 451;

#[repr(C)]
struct CachestatRange {
    off: u64,
    len: u64,
}

#[repr(C)]
#[derive(Default)]
struct Cachestat {
    nr_cache: u64,
    nr_dirty: u64,
    nr_writeback: u64,
    nr_evicted: u64,
    nr_recently_evicted: u64,
}

/// 0 = unknown, 1 = available, 2 = unavailable.
static AVAILABLE: AtomicU8 = AtomicU8::new(0);

/// Pages of `f` currently in the page cache, `None` if the kernel cannot
/// tell us.
pub fn resident_pages(f: &File) -> Option<u64> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64"))]
    {
        if AVAILABLE.load(Ordering::Relaxed) == 2 {
            return None;
        }
        let range = CachestatRange { off: 0, len: 0 };
        let mut st = Cachestat::default();
        // SAFETY: both pointers reference live, correctly laid out structs.
        let r = unsafe {
            libc::syscall(
                SYS_CACHESTAT,
                f.as_raw_fd() as libc::c_uint,
                &range as *const CachestatRange,
                &mut st as *mut Cachestat,
                0 as libc::c_uint,
            )
        };
        if r == 0 {
            AVAILABLE.store(1, Ordering::Relaxed);
            return Some(st.nr_cache);
        }
        let e = std::io::Error::last_os_error();
        if matches!(e.raw_os_error(), Some(libc::ENOSYS) | Some(libc::EPERM)) {
            AVAILABLE.store(2, Ordering::Relaxed);
        }
        None
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "riscv64")))]
    {
        let _ = f;
        None
    }
}

/// Drop the file's clean pages from the page cache.
pub fn drop_pages(f: &File) {
    // SAFETY: plain syscall on a descriptor we own.
    unsafe {
        libc::posix_fadvise(f.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED);
    }
}

/// Is `cachestat` usable on this host? (After the first call.)
pub fn available() -> Option<bool> {
    match AVAILABLE.load(Ordering::Relaxed) {
        1 => Some(true),
        2 => Some(false),
        _ => None,
    }
}

/// Wrap a read-only scan of one file: remembers whether the file was cold
/// and, on drop, evicts what the scan brought into the cache.
pub struct ColdRead<'a> {
    file: &'a File,
    cold: bool,
}

impl<'a> ColdRead<'a> {
    pub fn new(file: &'a File) -> Self {
        let cold = resident_pages(file) == Some(0);
        Self { file, cold }
    }
}

impl Drop for ColdRead<'_> {
    fn drop(&mut self) {
        if self.cold {
            drop_pages(self.file);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn cold_read_evicts_only_cold_files() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("f");
        let mut f = File::create(&p).unwrap();
        f.write_all(&vec![7u8; 1 << 20]).unwrap();
        f.sync_all().unwrap();
        drop(f);
        let read_all = |f: &File| {
            let mut buf = Vec::new();
            let mut r: &File = f;
            r.read_to_end(&mut buf).unwrap();
            buf.len()
        };
        let f = File::open(&p).unwrap();
        drop_pages(&f);
        let Some(before) = resident_pages(&f) else { return }; // kernel without cachestat
        if before != 0 {
            return; // tmpfs: pages cannot be dropped
        }
        {
            let _g = ColdRead::new(&f);
            assert_eq!(read_all(&f), 1 << 20);
            assert!(resident_pages(&f).unwrap() > 0);
        }
        assert_eq!(resident_pages(&f), Some(0), "cold file evicted after the scan");
        // a hot file stays cached
        assert_eq!(read_all(&File::open(&p).unwrap()), 1 << 20);
        let hot = resident_pages(&f).unwrap();
        assert!(hot > 0);
        {
            let f2 = File::open(&p).unwrap();
            let _g = ColdRead::new(&f2);
            read_all(&f2);
        }
        assert_eq!(resident_pages(&f), Some(hot));
    }
}
