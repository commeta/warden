//! Race-free filesystem operations for a root daemon that acts inside
//! directories other users can write to: the cleanup of `/tmp` and log
//! directories, the quarantine of files under a web root.
//!
//! The classic mistake is to look at a path and then act on the same path:
//! between the two, a user who owns a directory on the way can replace it
//! with a symlink and redirect the deletion (or `truncate`, or `chmod`)
//! anywhere root can write. Everything here works on **directory
//! descriptors** instead:
//!
//! * a directory is opened component by component with `O_NOFOLLOW`, so no
//!   symlink is ever followed below a configured root ([`open_dir_nofollow`]),
//!   and on the way to the root only a symlink that can be trusted is
//!   ([`open_root`]);
//! * an entry is examined with `fstatat(AT_SYMLINK_NOFOLLOW)` relative to the
//!   descriptor of its directory, and acted on (`unlinkat`, `openat`)
//!   relative to the same descriptor, after checking that it is still the
//!   inode that was examined ([`unlink_if_same`], [`truncate_if_same`]);
//! * a directory that is renamed or replaced while the walk is inside it
//!   does not matter: the walk keeps the descriptor of the original one.
//!
//! [`walk`] is a depth-first walk over open directory descriptors with the
//! budgets the daemon needs (entries, time, depth, one filesystem).

use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Component, Path, PathBuf};
use std::ptr::NonNull;
use std::time::Instant;

/// What `fstat` says about an inode (the fields Warden decides on).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u64,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    /// Allocated bytes (`st_blocks` × 512).
    pub allocated: u64,
    pub atime: i64,
    pub mtime: i64,
    pub ctime: i64,
}

impl Stat {
    #[allow(clippy::unnecessary_cast)] // field widths differ between architectures
    fn from_raw(st: &libc::stat) -> Self {
        Self {
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
            mode: st.st_mode as u32,
            nlink: st.st_nlink as u64,
            uid: st.st_uid as u32,
            gid: st.st_gid as u32,
            size: st.st_size.max(0) as u64,
            allocated: (st.st_blocks.max(0) as u64).saturating_mul(512),
            atime: st.st_atime as i64,
            mtime: st.st_mtime as i64,
            ctime: st.st_ctime as i64,
        }
    }

    fn kind(&self) -> u32 {
        self.mode & libc::S_IFMT
    }

    pub fn is_dir(&self) -> bool {
        self.kind() == libc::S_IFDIR
    }

    pub fn is_file(&self) -> bool {
        self.kind() == libc::S_IFREG
    }

    pub fn is_symlink(&self) -> bool {
        self.kind() == libc::S_IFLNK
    }

    /// The same inode (device and inode number).
    pub fn same_inode(&self, other: &Stat) -> bool {
        self.dev == other.dev && self.ino == other.ino
    }

    /// The newest of atime, mtime and ctime: how `systemd-tmpfiles` ages a
    /// file. `ctime` cannot be set by a user (`touch -d` moves it to *now*),
    /// so a file cannot be made to look old.
    pub fn newest_time(&self) -> i64 {
        self.atime.max(self.mtime).max(self.ctime)
    }
}

fn cstr(name: &OsStr) -> io::Result<CString> {
    CString::new(name.as_bytes()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in file name"))
}

fn check(r: libc::c_int) -> io::Result<libc::c_int> {
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(r) }
}

/// `fstat` of a descriptor.
pub fn fstat(fd: BorrowedFd<'_>) -> io::Result<Stat> {
    // SAFETY: an all-zero `stat` is a valid value; it is filled by the call.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid descriptor and out pointer.
    check(unsafe { libc::fstat(fd.as_raw_fd(), &mut st) })?;
    Ok(Stat::from_raw(&st))
}

/// `fstatat(dir, name, AT_SYMLINK_NOFOLLOW)`: a symlink is reported as one.
pub fn stat_at(dir: BorrowedFd<'_>, name: &CStr) -> io::Result<Stat> {
    // SAFETY: as in `fstat`.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: valid descriptor, NUL-terminated name, out pointer.
    check(unsafe { libc::fstatat(dir.as_raw_fd(), name.as_ptr(), &mut st, libc::AT_SYMLINK_NOFOLLOW) })?;
    Ok(Stat::from_raw(&st))
}

/// `openat(dir, name, flags | O_NOFOLLOW | O_CLOEXEC | O_NOCTTY)`.
pub fn open_at(dir: BorrowedFd<'_>, name: &CStr, flags: libc::c_int, mode: libc::mode_t) -> io::Result<OwnedFd> {
    let flags = flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NOCTTY;
    // SAFETY: valid descriptor and NUL-terminated name.
    let fd = check(unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags, libc::c_uint::from(mode)) })?;
    // SAFETY: `fd` is a fresh descriptor this function owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open the subdirectory `name` of `dir`, never through a symlink.
pub fn open_dir_at(dir: BorrowedFd<'_>, name: &CStr) -> io::Result<OwnedFd> {
    open_at(dir, name, libc::O_RDONLY | libc::O_DIRECTORY, 0)
}

/// Open an absolute directory path component by component, refusing a
/// symlink anywhere on the way (`ELOOP`/`ENOTDIR`). For paths that must not
/// contain one: a canonical root, the stored location of a quarantined file.
pub fn open_dir_nofollow(path: &Path) -> io::Result<OwnedFd> {
    if !path.is_absolute() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{} is not absolute", path.display())));
    }
    let root = std::fs::File::open("/")?;
    let mut cur: OwnedFd = root.into();
    for c in path.components() {
        match c {
            Component::RootDir => {}
            Component::Normal(n) => cur = open_dir_at(cur.as_fd(), &cstr(n)?)?,
            Component::CurDir => {}
            Component::ParentDir | Component::Prefix(_) => {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{} has `..`", path.display())));
            }
        }
    }
    Ok(cur)
}

/// Most symlinks followed while resolving one path (the kernel's limit).
const MAX_SYMLINKS: usize = 40;

/// Open a directory given by an operator-configured path (`/var/log`, a
/// site root, the parent of a file to quarantine), resolving symlinks only
/// when they can be trusted, and return its real path with the descriptor.
///
/// A symlink is followed only if it is owned by root or by the owner of the
/// directory that holds it (the `fs.protected_symlinks` rule): a symlink a
/// user planted in `/tmp` is refused, the operator's `/var/www -> /srv/www`
/// is followed. Every other component is opened with `O_NOFOLLOW`, so the
/// returned path is exactly what the descriptor refers to; decide policy on
/// that path, act through the descriptor.
pub fn open_root(path: &Path) -> io::Result<(PathBuf, OwnedFd)> {
    resolve(path, true)
}

/// [`open_root`] that follows only symlinks owned by root: for putting a
/// file *back* (quarantine restore), where a link the directory's owner
/// made since — `uploads -> /etc` by the site user — must not be trusted.
pub fn open_root_strict(path: &Path) -> io::Result<(PathBuf, OwnedFd)> {
    resolve(path, false)
}

fn resolve(path: &Path, dir_owner_links: bool) -> io::Result<(PathBuf, OwnedFd)> {
    use std::collections::VecDeque;
    use std::ffi::OsString;
    if !path.is_absolute() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{} is not absolute", path.display())));
    }
    fn parts(p: &Path) -> impl Iterator<Item = OsString> + '_ {
        p.components().filter_map(|c| match c {
            Component::Normal(n) => Some(n.to_os_string()),
            Component::ParentDir => Some(OsString::from("..")),
            _ => None,
        })
    }
    let root: OwnedFd = std::fs::File::open("/")?.into();
    let mut stack: Vec<(OwnedFd, PathBuf)> = vec![(root, PathBuf::from("/"))];
    let mut todo: VecDeque<OsString> = parts(path).collect();
    let mut links = 0;
    while let Some(c) = todo.pop_front() {
        if c == ".." {
            if stack.len() > 1 {
                stack.pop();
            }
            continue;
        }
        let Some((dir, real)) = stack.last() else { break };
        let name = cstr(&c)?;
        let st = stat_at(dir.as_fd(), &name)?;
        if st.is_symlink() {
            let owner = fstat(dir.as_fd())?.uid;
            if st.uid != 0 && !(dir_owner_links && st.uid == owner) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "{} is a symlink owned by uid {} in a directory of uid {owner}",
                        real.join(&c).display(),
                        st.uid
                    ),
                ));
            }
            links += 1;
            if links > MAX_SYMLINKS {
                return Err(io::Error::from_raw_os_error(libc::ELOOP));
            }
            let target = read_link_at(dir.as_fd(), &name)?;
            if target.is_absolute() {
                stack.truncate(1);
            }
            for (i, t) in parts(&target).enumerate() {
                todo.insert(i, t);
            }
            continue;
        }
        let child = open_dir_at(dir.as_fd(), &name)?;
        if !fstat(child.as_fd()).is_ok_and(|c| c.same_inode(&st)) {
            return Err(changed("a directory on the path"));
        }
        let real = real.join(&c);
        stack.push((child, real));
    }
    match stack.pop() {
        Some((fd, real)) => Ok((real, fd)),
        None => Err(io::Error::other("empty path")),
    }
}

/// `readlinkat(dir, name)`.
pub fn read_link_at(dir: BorrowedFd<'_>, name: &CStr) -> io::Result<PathBuf> {
    let mut buf = vec![0u8; libc::PATH_MAX as usize];
    // SAFETY: valid descriptor, NUL-terminated name, buffer of the given size.
    let n = unsafe { libc::readlinkat(dir.as_raw_fd(), name.as_ptr(), buf.as_mut_ptr().cast(), buf.len()) };
    if n < 0 {
        return Err(io::Error::last_os_error());
    }
    buf.truncate(n as usize);
    Ok(PathBuf::from(std::ffi::OsString::from_vec(buf)))
}

/// Open the subdirectory `name` of `dir` that `expect` describes: `None`
/// if it is no longer that directory (replaced between the `fstatat` and
/// the `openat`; a symlink is refused by `O_NOFOLLOW` already).
pub fn open_subdir(dir: BorrowedFd<'_>, name: &CStr, expect: &Stat) -> io::Result<OwnedFd> {
    let child = open_dir_at(dir, name)?;
    if !fstat(child.as_fd()).is_ok_and(|c| c.same_inode(expect)) {
        return Err(changed("the directory"));
    }
    Ok(child)
}

/// `path` split into its parent directory and its last component.
pub fn split(path: &Path) -> io::Result<(&Path, CString)> {
    match (path.parent(), path.file_name()) {
        (Some(p), Some(n)) => Ok((p, cstr(n)?)),
        _ => Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{} has no file name", path.display()))),
    }
}

fn changed(what: &str) -> io::Error {
    io::Error::other(format!("{what} changed while Warden was looking at it (replaced or moved)"))
}

/// Unlink the regular file `name` in `dir` if it is still the inode
/// `expect` describes. A name that now points at something else — a
/// symlink, a directory, another file — is left alone.
pub fn unlink_if_same(dir: BorrowedFd<'_>, name: &CStr, expect: &Stat) -> io::Result<()> {
    let now = stat_at(dir, name)?;
    if !now.is_file() || !now.same_inode(expect) {
        return Err(changed("the file"));
    }
    // SAFETY: valid descriptor and NUL-terminated name.
    check(unsafe { libc::unlinkat(dir.as_raw_fd(), name.as_ptr(), 0) })?;
    Ok(())
}

/// Truncate the regular file `name` in `dir` to zero if it is still the
/// inode `expect` describes and has no other names (a hard link to someone
/// else's file planted in a writable directory is refused). Writers keep
/// their descriptors (copytruncate semantics). Returns the bytes released.
pub fn truncate_if_same(dir: BorrowedFd<'_>, name: &CStr, expect: &Stat) -> io::Result<u64> {
    // O_NONBLOCK: a FIFO swapped in cannot block the responder.
    let fd = open_at(dir, name, libc::O_WRONLY | libc::O_NONBLOCK, 0)?;
    let st = fstat(fd.as_fd())?;
    if !st.is_file() || !st.same_inode(expect) {
        return Err(changed("the file"));
    }
    if st.nlink != 1 {
        return Err(io::Error::other(format!("the file has {} hard links; not truncated", st.nlink)));
    }
    // SAFETY: valid descriptor opened for writing.
    check(unsafe { libc::ftruncate(fd.as_raw_fd(), 0) })?;
    Ok(st.allocated)
}

/// `renameat2(…, RENAME_NOREPLACE)`: fails with `EEXIST` instead of
/// replacing an existing name.
pub fn rename_noreplace(from_dir: BorrowedFd<'_>, from: &CStr, to_dir: BorrowedFd<'_>, to: &CStr) -> io::Result<()> {
    // SAFETY: valid descriptors and NUL-terminated names.
    let r = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            from_dir.as_raw_fd(),
            from.as_ptr(),
            to_dir.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if r < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// `fchmod` of a descriptor (never a path: a path could be a symlink by now).
pub fn fchmod(fd: BorrowedFd<'_>, mode: u32) -> io::Result<()> {
    // SAFETY: valid descriptor.
    check(unsafe { libc::fchmod(fd.as_raw_fd(), mode as libc::mode_t) }).map(drop)
}

/// `fchown` of a descriptor.
pub fn fchown(fd: BorrowedFd<'_>, uid: u32, gid: u32) -> io::Result<()> {
    // SAFETY: valid descriptor.
    check(unsafe { libc::fchown(fd.as_raw_fd(), uid, gid) }).map(drop)
}

// ---------------------------------------------------------------------------
// Directory streams
// ---------------------------------------------------------------------------

/// A directory stream over an owned descriptor (`fdopendir`): the names in
/// one directory, read in place, without building paths.
pub struct DirStream {
    ptr: NonNull<libc::DIR>,
}

impl DirStream {
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        let raw = fd.into_raw_fd();
        // SAFETY: `raw` is an open directory descriptor; on success the
        // stream owns it, on failure we close it.
        let ptr = unsafe { libc::fdopendir(raw) };
        match NonNull::new(ptr) {
            Some(ptr) => Ok(Self { ptr }),
            None => {
                let e = io::Error::last_os_error();
                // SAFETY: the descriptor was not taken over by a stream.
                unsafe { libc::close(raw) };
                Err(e)
            }
        }
    }

    /// The directory's descriptor, for `*at` calls on its entries.
    pub fn fd(&self) -> BorrowedFd<'_> {
        // SAFETY: the stream is open for the lifetime of `self`, and so is
        // its descriptor.
        unsafe { BorrowedFd::borrow_raw(libc::dirfd(self.ptr.as_ptr())) }
    }

    /// The next name, `.` and `..` skipped; `None` at the end (or on an
    /// error, which ends the stream like `readdir` does).
    pub fn next_name(&mut self) -> Option<CString> {
        loop {
            // SAFETY: the stream is open; the returned record stays valid
            // until the next `readdir` on it, and is copied before that.
            let ent = unsafe { libc::readdir(self.ptr.as_ptr()) };
            if ent.is_null() {
                return None;
            }
            // SAFETY: `d_name` of a record returned by `readdir` is NUL-terminated.
            let name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
            let b = name.to_bytes();
            if b == b"." || b == b".." {
                continue;
            }
            return Some(name.to_owned());
        }
    }
}

impl Drop for DirStream {
    fn drop(&mut self) {
        // SAFETY: the stream was opened by `fdopendir` and is closed once.
        unsafe { libc::closedir(self.ptr.as_ptr()) };
    }
}

// ---------------------------------------------------------------------------
// Walk
// ---------------------------------------------------------------------------

/// Budgets and limits of a [`walk`].
#[derive(Debug, Clone)]
pub struct WalkOptions {
    /// Directories below the root that are entered (0 = the root only).
    pub max_depth: usize,
    /// Stay on the root's filesystem.
    pub one_filesystem: bool,
    /// Stop after this many entries.
    pub max_entries: u64,
    /// Stop at this moment.
    pub deadline: Option<Instant>,
}

impl Default for WalkOptions {
    fn default() -> Self {
        Self { max_depth: 10, one_filesystem: true, max_entries: u64::MAX, deadline: None }
    }
}

/// Directory descriptors held open at once; a deeper tree is cut there.
const MAX_OPEN_DIRS: usize = 64;

/// One entry met by [`walk`]. Act on it only through [`WalkEntry::dir`] and
/// [`WalkEntry::name`] (`unlink_if_same(e.dir, e.name, e.stat)`), never
/// through the path: the path is for matching and for messages.
pub struct WalkEntry<'a> {
    /// Descriptor of the directory that holds the entry.
    pub dir: BorrowedFd<'a>,
    pub name: &'a CStr,
    /// Location for matching and reports: the root as the caller gave it,
    /// plus the names below it.
    pub path: &'a Path,
    /// The same entry below the canonical root (where it really is).
    pub real: &'a Path,
    pub stat: &'a Stat,
    /// 1 for an entry directly in the root.
    pub depth: usize,
}

/// What [`walk`] does after visiting an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visit {
    /// Go on (and enter the entry if it is a directory).
    Continue,
    /// Do not enter this directory.
    Skip,
    /// End the walk.
    Stop,
}

/// How a walk ended.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct WalkStats {
    pub entries: u64,
    /// A budget (entries, time, nesting) ended it early.
    pub cut: bool,
    /// Entries that could not be examined or directories not opened.
    pub errors: u64,
}

/// Depth-first walk of `root` over open directory descriptors: no symlink
/// is followed below the (canonicalised) root, memory grows with the depth
/// of the tree and not with its width, and every entry is reported with the
/// descriptor of its directory so that the visitor can act on it safely.
pub fn walk(root: &Path, opt: &WalkOptions, mut visit: impl FnMut(&WalkEntry<'_>) -> Visit) -> io::Result<WalkStats> {
    let (real_root, fd) = match open_root(root) {
        Ok(r) => r,
        // a literal path to a file (`/var/log/app.log`): visit just that
        Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => return visit_file(root, visit),
        Err(e) => return Err(e),
    };
    let root_stat = fstat(fd.as_fd())?;
    let mut stats = WalkStats::default();
    // (stream, logical path, real path, depth of its entries)
    let mut stack: Vec<(DirStream, PathBuf, PathBuf, usize)> =
        vec![(DirStream::new(fd)?, root.to_path_buf(), real_root, 1)];
    let late = |d: &Option<Instant>| d.is_some_and(|t| Instant::now() >= t);
    loop {
        let open = stack.len();
        let Some((dir, logical, real, depth)) = stack.last_mut() else { break };
        let Some(name) = dir.next_name() else {
            stack.pop();
            continue;
        };
        stats.entries += 1;
        // a cold `stat` under writeback can take milliseconds: look at the
        // clock often (it costs nanoseconds)
        if stats.entries > opt.max_entries || (stats.entries.is_multiple_of(32) && late(&opt.deadline)) {
            stats.cut = true;
            break;
        }
        let depth = *depth;
        let Ok(st) = stat_at(dir.fd(), &name) else {
            stats.errors += 1;
            continue;
        };
        if opt.one_filesystem && st.dev != root_stat.dev {
            continue;
        }
        let os = OsStr::from_bytes(name.to_bytes());
        let path = logical.join(os);
        let real_path = real.join(os);
        let entry = WalkEntry { dir: dir.fd(), name: &name, path: &path, real: &real_path, stat: &st, depth };
        let v = visit(&entry);
        if v == Visit::Stop {
            break;
        }
        if v == Visit::Skip || !st.is_dir() || depth > opt.max_depth {
            continue;
        }
        if open >= MAX_OPEN_DIRS {
            stats.cut = true;
            continue;
        }
        match open_subdir(dir.fd(), &name, &st).and_then(DirStream::new) {
            Ok(d) => stack.push((d, path, real_path, depth + 1)),
            Err(_) => stats.errors += 1,
        }
    }
    Ok(stats)
}

/// [`walk`] of a root that is not a directory: one entry, depth 0.
fn visit_file(root: &Path, mut visit: impl FnMut(&WalkEntry<'_>) -> Visit) -> io::Result<WalkStats> {
    let (parent, name) = split(root)?;
    let (real_parent, dir) = open_root(parent)?;
    let st = stat_at(dir.as_fd(), &name)?;
    let real = real_parent.join(OsStr::from_bytes(name.to_bytes()));
    visit(&WalkEntry { dir: dir.as_fd(), name: &name, path: root, real: &real, stat: &st, depth: 0 });
    Ok(WalkStats { entries: 1, ..Default::default() })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn names(root: &Path, opt: &WalkOptions) -> Vec<String> {
        let mut v = Vec::new();
        walk(root, opt, |e| {
            v.push(e.path.strip_prefix(root).unwrap().display().to_string());
            Visit::Continue
        })
        .unwrap();
        v.sort();
        v
    }

    #[test]
    fn walks_without_following_symlinks() {
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::write(outside.path().join("secret"), "x").unwrap();
        std::fs::create_dir_all(d.path().join("a/b")).unwrap();
        std::fs::write(d.path().join("a/b/f"), "x").unwrap();
        symlink(outside.path(), d.path().join("a/link")).unwrap();
        let n = names(d.path(), &WalkOptions::default());
        assert_eq!(n, ["a", "a/b", "a/b/f", "a/link"], "the symlink is reported, never entered");
        // depth limit
        let n = names(d.path(), &WalkOptions { max_depth: 1, ..Default::default() });
        assert_eq!(n, ["a", "a/b", "a/link"]);
    }

    #[test]
    fn a_symlinked_root_is_resolved_but_nothing_below_it() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("real")).unwrap();
        std::fs::write(d.path().join("real/f"), "x").unwrap();
        symlink(d.path().join("real"), d.path().join("alias")).unwrap();
        let mut seen = Vec::new();
        walk(&d.path().join("alias"), &WalkOptions::default(), |e| {
            seen.push((e.path.to_path_buf(), e.real.to_path_buf()));
            Visit::Continue
        })
        .unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, d.path().join("alias/f"), "matching uses the configured path");
        assert_eq!(seen[0].1, std::fs::canonicalize(d.path()).unwrap().join("real/f"), "policy uses the real one");
    }

    #[test]
    fn open_dir_nofollow_refuses_a_symlink_on_the_way() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("real")).unwrap();
        symlink(d.path().join("real"), d.path().join("link")).unwrap();
        let base = std::fs::canonicalize(d.path()).unwrap();
        assert!(open_dir_nofollow(&base.join("real")).is_ok());
        assert!(open_dir_nofollow(&base.join("link")).is_err());
        assert!(open_dir_nofollow(Path::new("relative")).is_err());
        assert!(open_dir_nofollow(&base.join("real/../real")).is_err());
    }

    #[test]
    fn open_root_follows_only_trusted_symlinks() {
        let d = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(d.path()).unwrap();
        std::fs::create_dir_all(base.join("real/sub")).unwrap();
        symlink("real", base.join("rel")).unwrap();
        symlink(base.join("real"), base.join("abs")).unwrap();
        // owned by the test user (root in CI, the directory owner otherwise): trusted
        let (p, _) = open_root(&base.join("rel/sub")).unwrap();
        assert_eq!(p, base.join("real/sub"));
        let (p, _) = open_root(&base.join("abs/sub/..")).unwrap();
        assert_eq!(p, base.join("real"));
        // a file is not a directory
        std::fs::write(base.join("real/f"), "x").unwrap();
        assert_eq!(open_root(&base.join("real/f")).unwrap_err().raw_os_error(), Some(libc::ENOTDIR));
        // a loop
        symlink("loop", base.join("loop")).unwrap();
        assert_eq!(open_root(&base.join("loop")).unwrap_err().raw_os_error(), Some(libc::ELOOP));
    }

    /// A symlink planted by another user in a directory that is not theirs
    /// (`/tmp/x -> /etc`) is not followed. Needs root to create it.
    #[test]
    fn open_root_refuses_a_foreign_symlink() {
        // SAFETY: trivial libc call.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(d.path()).unwrap();
        std::fs::create_dir(base.join("target")).unwrap();
        let link = base.join("planted");
        symlink(base.join("target"), &link).unwrap();
        let c = CString::new(link.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid path; the symlink itself gets the new owner.
        assert_eq!(unsafe { libc::lchown(c.as_ptr(), 65534, 65534) }, 0);
        let e = open_root(&link).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        // the owner of the directory may link inside it
        let own = base.join("own");
        std::fs::create_dir(&own).unwrap();
        let oc = CString::new(own.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid path.
        assert_eq!(unsafe { libc::chown(oc.as_ptr(), 65534, 65534) }, 0);
        let l2 = own.join("l");
        symlink(base.join("target"), &l2).unwrap();
        let c2 = CString::new(l2.as_os_str().as_bytes()).unwrap();
        // SAFETY: valid path.
        assert_eq!(unsafe { libc::lchown(c2.as_ptr(), 65534, 65534) }, 0);
        assert_eq!(open_root(&l2).unwrap().0, base.join("target"));
        // ... but the strict variant trusts root's links only
        assert_eq!(open_root_strict(&l2).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        let rootlink = base.join("rootlink");
        symlink(base.join("target"), &rootlink).unwrap();
        assert_eq!(open_root_strict(&rootlink).unwrap().0, base.join("target"));
    }

    #[test]
    fn a_file_root_is_visited_alone() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("app.log");
        std::fs::write(&f, "x").unwrap();
        let mut seen = Vec::new();
        let st = walk(&f, &WalkOptions::default(), |e| {
            seen.push((e.path.to_path_buf(), e.stat.is_file(), e.depth));
            Visit::Continue
        })
        .unwrap();
        assert_eq!(st.entries, 1);
        assert_eq!(seen, [(f, true, 0)]);
    }

    #[test]
    fn unlink_and_truncate_check_the_inode() {
        let d = tempfile::tempdir().unwrap();
        let dir = open_dir_nofollow(&std::fs::canonicalize(d.path()).unwrap()).unwrap();
        let p = d.path().join("f");
        std::fs::write(&p, vec![1u8; 10_000]).unwrap();
        let name = CString::new("f").unwrap();
        let st = stat_at(dir.as_fd(), &name).unwrap();
        // replaced by another file with the same name: refused (the old one
        // is kept so that its inode number is not reused at once)
        std::fs::rename(&p, d.path().join("old")).unwrap();
        std::fs::write(&p, "other").unwrap();
        assert!(unlink_if_same(dir.as_fd(), &name, &st).is_err());
        assert!(truncate_if_same(dir.as_fd(), &name, &st).is_err());
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "other");
        // replaced by a symlink: refused, the target untouched
        let target = d.path().join("target");
        std::fs::write(&target, "keep").unwrap();
        let st_target = stat_at(dir.as_fd(), &CString::new("target").unwrap()).unwrap();
        std::fs::remove_file(&p).unwrap();
        symlink(&target, &p).unwrap();
        assert!(truncate_if_same(dir.as_fd(), &name, &st_target).is_err());
        assert!(unlink_if_same(dir.as_fd(), &name, &st_target).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        // a second name (hard link): not truncated
        std::fs::remove_file(&p).unwrap();
        std::fs::hard_link(&target, &p).unwrap();
        let st_link = stat_at(dir.as_fd(), &name).unwrap();
        assert!(truncate_if_same(dir.as_fd(), &name, &st_link).is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        // the real thing works
        std::fs::remove_file(&p).unwrap();
        std::fs::write(&p, vec![1u8; 10_000]).unwrap();
        let st = stat_at(dir.as_fd(), &name).unwrap();
        assert!(truncate_if_same(dir.as_fd(), &name, &st).unwrap() > 0);
        assert_eq!(std::fs::metadata(&p).unwrap().len(), 0);
        unlink_if_same(dir.as_fd(), &name, &st).unwrap();
        assert!(!p.exists());
    }

    #[test]
    fn rename_noreplace_never_overwrites() {
        let d = tempfile::tempdir().unwrap();
        let dir = open_dir_nofollow(&std::fs::canonicalize(d.path()).unwrap()).unwrap();
        std::fs::write(d.path().join("a"), "a").unwrap();
        std::fs::write(d.path().join("b"), "b").unwrap();
        let (a, b, c) = (CString::new("a").unwrap(), CString::new("b").unwrap(), CString::new("c").unwrap());
        let e = rename_noreplace(dir.as_fd(), &a, dir.as_fd(), &b).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::EEXIST));
        rename_noreplace(dir.as_fd(), &a, dir.as_fd(), &c).unwrap();
        assert_eq!(std::fs::read_to_string(d.path().join("c")).unwrap(), "a");
        assert_eq!(std::fs::read_to_string(d.path().join("b")).unwrap(), "b");
    }

    /// The attack this module exists for: while a walk deletes files below a
    /// directory the attacker owns, the attacker keeps swapping that
    /// directory for a symlink to a victim directory. Nothing outside the
    /// walked tree may ever be deleted.
    #[test]
    fn a_directory_swapped_for_a_symlink_never_redirects_deletion() {
        let tree = tempfile::tempdir().unwrap();
        let victim = tempfile::tempdir().unwrap();
        for i in 0..200 {
            std::fs::write(victim.path().join(format!("f{i}")), "victim").unwrap();
        }
        let stop = Arc::new(AtomicBool::new(false));
        let (t, s) = (tree.path().to_path_buf(), stop.clone());
        let v = victim.path().to_path_buf();
        let flipper = std::thread::spawn(move || {
            let x = t.join("x");
            let parked = t.join("parked");
            while !s.load(Ordering::Relaxed) {
                let _ = std::fs::create_dir(&x);
                for i in 0..200 {
                    let _ = std::fs::write(x.join(format!("f{i}")), "attacker");
                }
                let _ = std::fs::remove_dir_all(&parked);
                let _ = std::fs::rename(&x, &parked);
                let _ = symlink(&v, &x);
                std::thread::yield_now();
                let _ = std::fs::remove_file(&x);
            }
        });
        let mut deleted = 0;
        let started = Instant::now();
        while deleted < 2_000 && started.elapsed() < std::time::Duration::from_secs(5) {
            walk(tree.path(), &WalkOptions::default(), |e| {
                if e.stat.is_file() && unlink_if_same(e.dir, e.name, e.stat).is_ok() {
                    deleted += 1;
                }
                Visit::Continue
            })
            .unwrap();
        }
        stop.store(true, Ordering::Relaxed);
        flipper.join().unwrap();
        assert!(deleted > 0, "the race was not exercised");
        let left = std::fs::read_dir(victim.path()).unwrap().count();
        assert_eq!(left, 200, "a file outside the walked tree was deleted");
    }
}
