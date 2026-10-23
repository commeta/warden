//! fanotify in file-handle mode (`FAN_REPORT_DFID_NAME`, Linux 5.9+):
//! attribute changes (`chmod`), creations and renames anywhere on a
//! **filesystem**, reported as *(directory handle, name)* instead of an open
//! descriptor.
//!
//! This is what makes real-time SUID detection possible: `chmod u+s` is an
//! `FAN_ATTRIB` event, which the descriptor-based API used for FIM cannot
//! report. Resolving a handle needs `open_by_handle_at(2)`
//! (`CAP_DAC_READ_SEARCH`); marking a filesystem needs `CAP_SYS_ADMIN`.

use crate::util::{cvt, u32_ne};
use std::collections::HashMap;
use std::ffi::{CString, OsStr, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

const METADATA_LEN: usize = 24;
const INFO_HDR_LEN: usize = 4;
pub const FAN_Q_OVERFLOW: u64 = 0x0000_4000;
const FAN_EVENT_INFO_TYPE_FID: u8 = 1;
const FAN_EVENT_INFO_TYPE_DFID_NAME: u8 = 2;
const FAN_EVENT_INFO_TYPE_DFID: u8 = 3;

/// One event: the directory (as a handle on filesystem `fsid`) and the name
/// of the entry inside it that changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FidEvent {
    pub mask: u64,
    pub pid: i32,
    pub fsid: [i32; 2],
    /// `struct file_handle` as the kernel wrote it (header + opaque bytes).
    pub handle: Vec<u8>,
    pub name: Option<OsString>,
}

impl FidEvent {
    pub fn overflow(&self) -> bool {
        self.mask & FAN_Q_OVERFLOW != 0
    }
}

/// Parse a read buffer of events with FID/DFID_NAME info records.
pub fn parse_events(buf: &[u8]) -> Vec<FidEvent> {
    let mut out = Vec::new();
    let mut off = 0;
    while off + METADATA_LEN <= buf.len() {
        let b = &buf[off..];
        let Some(event_len) = u32_ne(b, 0).map(|v| v as usize) else { break };
        if event_len < METADATA_LEN || off + event_len > buf.len() {
            break;
        }
        let meta_len = u16::from_ne_bytes([b[6], b[7]]) as usize;
        let mask = u64::from_ne_bytes(b[8..16].try_into().unwrap_or([0; 8]));
        let pid = i32::from_ne_bytes(b[20..24].try_into().unwrap_or([0; 4]));
        let mut ev = FidEvent { mask, pid, fsid: [0, 0], handle: Vec::new(), name: None };
        // info records follow the metadata
        let mut i = meta_len.max(METADATA_LEN);
        while i + INFO_HDR_LEN <= event_len {
            let typ = b[i];
            let len = u16::from_ne_bytes([b[i + 2], b[i + 3]]) as usize;
            if len < INFO_HDR_LEN || i + len > event_len {
                break;
            }
            let rec = &b[i + INFO_HDR_LEN..i + len];
            if matches!(typ, FAN_EVENT_INFO_TYPE_FID | FAN_EVENT_INFO_TYPE_DFID_NAME | FAN_EVENT_INFO_TYPE_DFID)
                && rec.len() >= 16
            {
                let fsid = [
                    i32::from_ne_bytes(rec[0..4].try_into().unwrap_or([0; 4])),
                    i32::from_ne_bytes(rec[4..8].try_into().unwrap_or([0; 4])),
                ];
                let hbytes = u32_ne(rec, 8).unwrap_or(0) as usize;
                let hend = 16 + hbytes;
                if hend <= rec.len() {
                    // keep the first directory/object handle we see
                    if ev.handle.is_empty() {
                        ev.fsid = fsid;
                        ev.handle = rec[8..hend].to_vec();
                    }
                    if typ == FAN_EVENT_INFO_TYPE_DFID_NAME {
                        let name = &rec[hend..];
                        let n = name.iter().position(|c| *c == 0).unwrap_or(name.len());
                        if n > 0 && &name[..n] != b"." {
                            ev.name = Some(OsString::from_vec(name[..n].to_vec()));
                        }
                    }
                }
            }
            i += len;
        }
        out.push(ev);
        off += event_len;
    }
    out
}

fn fsid_of(path: &Path) -> io::Result<[i32; 2]> {
    let c = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
    // SAFETY: zeroed statfs is a valid out-parameter.
    let mut st: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: valid path and buffer.
    cvt(unsafe { libc::statfs(c.as_ptr(), &mut st) })?;
    // SAFETY: fsid_t is two ints on Linux; its fields are private in libc.
    Ok(unsafe { std::mem::transmute::<libc::fsid_t, [i32; 2]>(st.f_fsid) })
}

/// Metadata of a resolved entry (what the SUID check needs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryStat {
    pub mode: u32,
    pub uid: u32,
    pub size: u64,
}

impl EntryStat {
    pub fn is_regular(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFREG
    }

    pub fn setid(&self) -> bool {
        self.mode & 0o6000 != 0
    }
}

#[derive(Debug)]
pub struct FidWatcher {
    fd: OwnedFd,
    buf: Vec<u8>,
    /// One directory descriptor per marked filesystem, for
    /// `open_by_handle_at`.
    mounts: HashMap<[i32; 2], OwnedFd>,
    /// Recently opened directories by handle: a burst of events in one
    /// directory (an archive being unpacked) opens it once.
    dirs: HashMap<([i32; 2], Vec<u8>), OwnedFd>,
}

const DIR_CACHE: usize = 128;

impl FidWatcher {
    /// `EINVAL` on kernels without `FAN_REPORT_DFID_NAME` (< 5.9).
    pub fn new() -> io::Result<Self> {
        // SAFETY: plain syscall wrapper.
        let raw = cvt(unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_REPORT_DFID_NAME,
                (libc::O_RDONLY | libc::O_LARGEFILE | libc::O_CLOEXEC) as libc::c_uint,
            )
        })?;
        Ok(Self {
            // SAFETY: fresh descriptor owned by us.
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
            buf: vec![0u8; 64 * 1024],
            mounts: HashMap::new(),
            dirs: HashMap::new(),
        })
    }

    /// Watch `mask` events on the whole filesystem containing `path`.
    /// Returns `false` if that filesystem is already watched.
    pub fn watch_filesystem(&mut self, path: &Path, mask: u64) -> io::Result<bool> {
        let fsid = fsid_of(path)?;
        if self.mounts.contains_key(&fsid) {
            return Ok(false);
        }
        let c = CString::new(path.as_os_str().as_bytes()).map_err(io::Error::other)?;
        // SAFETY: valid fd and NUL-terminated path.
        cvt(unsafe {
            libc::fanotify_mark(
                self.fd.as_raw_fd(),
                libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
                mask,
                libc::AT_FDCWD,
                c.as_ptr(),
            )
        })?;
        // (open_by_handle_at rejects O_PATH descriptors as mount_fd)
        // SAFETY: valid path.
        let dir = cvt(unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) })?;
        // SAFETY: fresh descriptor owned by us.
        self.mounts.insert(fsid, unsafe { OwnedFd::from_raw_fd(dir) });
        Ok(true)
    }

    pub fn filesystems(&self) -> usize {
        self.mounts.len()
    }

    /// Wait up to `timeout` for events (empty vector on timeout).
    pub fn read_timeout(&mut self, timeout: std::time::Duration) -> io::Result<Vec<FidEvent>> {
        if !crate::util::wait_readable(self.fd.as_raw_fd(), timeout)? {
            return Ok(Vec::new());
        }
        let n = loop {
            // SAFETY: buf valid for writes.
            let n =
                unsafe { libc::read(self.fd.as_raw_fd(), self.buf.as_mut_ptr() as *mut libc::c_void, self.buf.len()) };
            if n < 0 {
                let e = io::Error::last_os_error();
                match e.kind() {
                    io::ErrorKind::Interrupted => continue,
                    io::ErrorKind::WouldBlock => return Ok(Vec::new()),
                    _ => return Err(e),
                }
            }
            break n as usize;
        };
        Ok(parse_events(&self.buf[..n]))
    }

    /// Descriptor of the event's directory (cached).
    fn dir_fd(&mut self, ev: &FidEvent) -> io::Result<libc::c_int> {
        let key = (ev.fsid, ev.handle.clone());
        if let Some(fd) = self.dirs.get(&key) {
            return Ok(fd.as_raw_fd());
        }
        let mount = self.mounts.get(&ev.fsid).ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
        if ev.handle.len() < 8 {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        // The kernel reads the struct with copy_from_user: no alignment needed.
        let mut handle = ev.handle.clone();
        // SAFETY: `handle` holds a complete `struct file_handle`.
        let raw = cvt(unsafe {
            libc::syscall(
                libc::SYS_open_by_handle_at,
                mount.as_raw_fd(),
                handle.as_mut_ptr() as *mut libc::c_void,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            ) as libc::c_int
        })?;
        if self.dirs.len() >= DIR_CACHE {
            self.dirs.clear();
        }
        // SAFETY: fresh descriptor owned by us.
        self.dirs.insert(key, unsafe { OwnedFd::from_raw_fd(raw) });
        Ok(raw)
    }

    /// Drop cached directory descriptors (call periodically).
    pub fn forget_dirs(&mut self) {
        self.dirs.clear();
    }

    /// Metadata of the entry an event refers to (the directory itself when
    /// the event carries no name). One `fstatat` — no path lookup.
    pub fn stat_entry(&mut self, ev: &FidEvent) -> io::Result<EntryStat> {
        let dir = self.dir_fd(ev)?;
        // SAFETY: zeroed stat is a valid out-parameter.
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        match &ev.name {
            Some(name) => {
                let c = CString::new(name.as_bytes()).map_err(io::Error::other)?;
                // SAFETY: valid dirfd, name and buffer.
                cvt(unsafe { libc::fstatat(dir, c.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) })?;
            }
            None => {
                // SAFETY: valid dirfd and buffer.
                cvt(unsafe { libc::fstatat(dir, c"".as_ptr(), &mut st, libc::AT_EMPTY_PATH) })?;
            }
        }
        Ok(EntryStat { mode: st.st_mode, uid: st.st_uid, size: st.st_size as u64 })
    }

    /// Current path of the entry.
    pub fn path_of(&mut self, ev: &FidEvent) -> io::Result<PathBuf> {
        let dir = self.dir_fd(ev)?;
        let dir_path = std::fs::read_link(format!("/proc/self/fd/{dir}"))?;
        Ok(match &ev.name {
            Some(n) => dir_path.join(OsStr::from_bytes(n.as_bytes())),
            None => dir_path,
        })
    }

    pub fn resolve(&mut self, ev: &FidEvent) -> io::Result<(PathBuf, EntryStat)> {
        let st = self.stat_entry(ev)?;
        Ok((self.path_of(ev)?, st))
    }

    /// Stop `mask` events for entries directly inside the event's directory
    /// (`FAN_MARK_IGNORE`, Linux 6.0+).
    pub fn ignore_in_dir(&mut self, ev: &FidEvent, mask: u64) -> io::Result<()> {
        let dir = self.dir_fd(ev)?;
        // SAFETY: valid fanotify fd and directory fd; NULL path = the fd itself.
        cvt(unsafe {
            libc::fanotify_mark(
                self.fd.as_raw_fd(),
                libc::FAN_MARK_ADD | libc::FAN_MARK_IGNORE_SURV,
                mask | libc::FAN_EVENT_ON_CHILD,
                dir,
                std::ptr::null(),
            )
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(mask: u64, pid: i32, handle: &[u8], name: &[u8]) -> Vec<u8> {
        let mut info = Vec::new();
        info.push(FAN_EVENT_INFO_TYPE_DFID_NAME);
        info.push(0);
        info.extend_from_slice(&0u16.to_ne_bytes()); // len, patched below
        info.extend_from_slice(&7i32.to_ne_bytes());
        info.extend_from_slice(&9i32.to_ne_bytes());
        info.extend_from_slice(&(handle.len() as u32).to_ne_bytes());
        info.extend_from_slice(&1i32.to_ne_bytes()); // handle_type
        info.extend_from_slice(handle);
        info.extend_from_slice(name);
        info.push(0);
        while info.len() % 4 != 0 {
            info.push(0);
        }
        let l = info.len() as u16;
        info[2..4].copy_from_slice(&l.to_ne_bytes());
        let mut ev = Vec::new();
        ev.extend_from_slice(&((METADATA_LEN + info.len()) as u32).to_ne_bytes());
        ev.push(3);
        ev.push(0);
        ev.extend_from_slice(&(METADATA_LEN as u16).to_ne_bytes());
        ev.extend_from_slice(&mask.to_ne_bytes());
        ev.extend_from_slice(&(-1i32).to_ne_bytes());
        ev.extend_from_slice(&pid.to_ne_bytes());
        ev.extend_from_slice(&info);
        ev
    }

    #[test]
    fn parses_dfid_name_records() {
        let mut buf = event(libc::FAN_ATTRIB, 42, &[1, 2, 3, 4, 5, 6, 7, 8], b"rootme");
        buf.extend(event(libc::FAN_CREATE, 43, &[9; 12], b"x"));
        let v = parse_events(&buf);
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].mask, libc::FAN_ATTRIB);
        assert_eq!(v[0].pid, 42);
        assert_eq!(v[0].fsid, [7, 9]);
        assert_eq!(v[0].handle.len(), 8 + 8);
        assert_eq!(v[0].name.as_deref(), Some(OsStr::new("rootme")));
        assert_eq!(v[1].name.as_deref(), Some(OsStr::new("x")));
        assert!(parse_events(&buf[..30]).len() <= 1);
    }

    /// Real kernel: `chmod u+s` is reported and resolved to the file.
    #[test]
    fn chmod_setuid_is_reported() {
        // SAFETY: geteuid has no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let Ok(mut w) = FidWatcher::new() else { return }; // kernel < 5.9
        let base = if Path::new("/var/tmp").is_dir() { "/var/tmp" } else { "/tmp" };
        let d = tempfile::tempdir_in(base).unwrap();
        if w.watch_filesystem(d.path(), libc::FAN_ATTRIB | libc::FAN_CREATE | libc::FAN_MOVED_TO).is_err() {
            return; // filesystem without file handles (some overlay/fuse setups)
        }
        let f = d.path().join("rootme");
        std::fs::write(&f, b"#!/bin/sh\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o4755)).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut found = None;
        while found.is_none() && std::time::Instant::now() < deadline {
            for ev in w.read_timeout(std::time::Duration::from_millis(500)).unwrap() {
                if ev.mask & libc::FAN_ATTRIB != 0
                    && let Ok((p, st)) = w.resolve(&ev)
                    && p == f
                {
                    found = Some(st);
                }
            }
        }
        let st = found.expect("FAN_ATTRIB for chmod u+s not received");
        assert!(st.is_regular() && st.setid());

        // muting creations in a busy directory keeps attribute changes. The
        // mark covers the whole filesystem, so events of other processes (and
        // of other tests running in parallel) arrive too: pick our own by name.
        std::fs::write(d.path().join("busy-0"), b"x").unwrap();
        let mut muted = false;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while !muted && std::time::Instant::now() < deadline {
            for ev in w.read_timeout(std::time::Duration::from_millis(500)).unwrap() {
                if ev.mask & libc::FAN_CREATE != 0 && ev.name.as_deref() == Some(OsStr::new("busy-0")) && !muted {
                    w.ignore_in_dir(&ev, libc::FAN_CREATE).unwrap();
                    muted = true;
                }
            }
        }
        assert!(muted);
        std::fs::write(d.path().join("busy-1"), b"x").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o2755)).unwrap();
        let mut evs = Vec::new();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while std::time::Instant::now() < until
            && !evs
                .iter()
                .any(|e: &FidEvent| e.mask & libc::FAN_ATTRIB != 0 && e.name.as_deref() == Some(OsStr::new("rootme")))
        {
            evs.extend(w.read_timeout(std::time::Duration::from_millis(250)).unwrap());
        }
        let names: Vec<_> = evs.iter().filter_map(|e| e.name.clone()).collect();
        assert!(
            !evs.iter().any(|e| e.mask & libc::FAN_CREATE != 0 && e.name.as_deref() == Some(OsStr::new("busy-1"))),
            "{names:?}"
        );
        assert!(
            evs.iter().any(|e| e.mask & libc::FAN_ATTRIB != 0 && e.name.as_deref() == Some(OsStr::new("rootme"))),
            "{names:?}"
        );
    }
}
