//! File quarantine with full metadata for exact restoration.

use serde::{Deserialize, Serialize};
use std::ffi::{CStr, OsStr};
use std::io::{self, Seek};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use warden_sys::{fsflags, safefs};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub id: String,
    pub original: String,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    pub hash: String,
    pub reason: String,
    pub ts_ms: u64,
    #[serde(default)]
    pub site: Option<String>,
    /// Attribute flags an attacker had set to resist removal (`chattr +i`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleared_attributes: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Quarantine {
    dir: PathBuf,
}

impl Quarantine {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    fn ensure_dir(&self) -> io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        std::fs::set_permissions(&self.dir, std::fs::Permissions::from_mode(0o700))
    }

    /// Move `path` into quarantine. The original disappears atomically when
    /// on the same filesystem (rename), otherwise copy + fsync + unlink.
    ///
    /// Everything happens on descriptors: the directory of the file is
    /// opened without following untrusted symlinks ([`safefs::open_root`]),
    /// `allow` decides on the path that directory really has, the file is
    /// opened `O_NOFOLLOW` and hashed, renamed relative to the directory, and
    /// the inode that arrived in the quarantine is checked to be the one that
    /// was hashed. A site user who swaps the file or a directory on its path
    /// for a symlink can make the action fail, never move it elsewhere.
    pub fn put(
        &self,
        path: &Path,
        reason: &str,
        site: Option<String>,
        allow: impl Fn(&Path) -> Result<(), String>,
    ) -> io::Result<Entry> {
        self.put_inner(path, reason, site, allow, || {})
    }

    /// Internal implementation with a narrow pre-rename seam for deterministic
    /// TOCTOU tests. Production callers pass a no-op closure through the public method.
    fn put_inner(
        &self,
        path: &Path,
        reason: &str,
        site: Option<String>,
        allow: impl Fn(&Path) -> Result<(), String>,
        before_rename: impl FnOnce(),
    ) -> io::Result<Entry> {
        let (parent, name) = safefs::split(path)?;
        let (real_parent, dir) = safefs::open_root(parent)?;
        let real = real_parent.join(OsStr::from_bytes(name.to_bytes()));
        allow(&real).map_err(|e| io::Error::new(io::ErrorKind::PermissionDenied, e))?;
        let st = safefs::stat_at(dir.as_fd(), &name)?;
        if !st.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "not a regular file"));
        }
        let file = std::fs::File::from(safefs::open_at(dir.as_fd(), &name, libc::O_RDONLY | libc::O_NONBLOCK, 0)?);
        let md = safefs::fstat(file.as_fd())?;
        if !md.is_file() || !md.same_inode(&st) {
            return Err(changed());
        }
        self.ensure_dir()?;
        // Streamed: a multi-gigabyte "webshell" must not be read into memory.
        let data_hash = {
            let mut h = blake3::Hasher::new();
            h.update_reader(&file)?;
            h.finalize().to_hex().to_string()
        };
        let ts = warden_core::event::now_ms();
        let id = format!("{ts}-{}", &data_hash[..12]);
        let slot_path = self.dir.join(&id);
        std::fs::create_dir(&slot_path)?;
        let slot = safefs::open_dir_nofollow(&std::fs::canonicalize(&slot_path)?)?;
        let fail = |e: io::Error| {
            let _ = std::fs::remove_dir(&slot_path);
            e
        };
        // Webshells are often made immutable/append-only (on the file or its
        // directory) so that removal fails: clear those flags first.
        let mut cleared = 0;
        let mut dir_cleared = 0;
        // Tests can deterministically replace the directory entry after the
        // original inode has been opened and hashed, but before it is renamed.
        before_rename();
        let mut res = safefs::rename_noreplace(dir.as_fd(), &name, slot.as_fd(), BLOB);
        if matches!(&res, Err(e) if e.raw_os_error() == Some(libc::EPERM)) {
            cleared = fsflags::clear_protection_fd(file.as_fd()).unwrap_or(0);
            dir_cleared = fsflags::clear_protection_fd(dir.as_fd()).unwrap_or(0);
            if cleared != 0 || dir_cleared != 0 {
                res = safefs::rename_noreplace(dir.as_fd(), &name, slot.as_fd(), BLOB);
            }
        }
        let moved = match res {
            Ok(()) => {
                // The name may have been swapped between the `open` and the
                // `rename`: what arrived must be the inode that was hashed.
                if !safefs::stat_at(slot.as_fd(), BLOB).is_ok_and(|b| b.same_inode(&md)) {
                    let _ = fsflags::restore_fd(dir.as_fd(), dir_cleared);
                    return Err(self.give_back(&slot_path, &slot, &dir, &name, &real));
                }
                safefs::fchmod(file.as_fd(), 0o000)
            }
            Err(e) if e.raw_os_error() == Some(libc::EXDEV) => self.copy_out(&file, &md, &dir, &name, &slot),
            Err(e) => Err(e),
        };
        // The directory belongs to the site: put its flags back.
        let _ = fsflags::restore_fd(dir.as_fd(), dir_cleared);
        moved.map_err(fail)?;
        let e = Entry {
            id,
            original: real.to_string_lossy().into_owned(),
            size: md.size,
            mode: md.mode,
            uid: md.uid,
            gid: md.gid,
            mtime: md.mtime,
            hash: data_hash,
            reason: reason.chars().take(500).collect(),
            ts_ms: ts,
            site,
            cleared_attributes: (cleared | dir_cleared != 0).then(|| {
                let mut v = Vec::new();
                if cleared != 0 {
                    v.push(format!("file: {}", fsflags::describe(cleared)));
                }
                if dir_cleared != 0 {
                    v.push(format!("directory: {}", fsflags::describe(dir_cleared)));
                }
                v.join(", ")
            }),
        };
        std::fs::write(slot_path.join("meta.json"), serde_json::to_vec_pretty(&e)?)?;
        Ok(e)
    }

    /// Something else than the hashed file was renamed into the slot (the
    /// name was swapped in between): put it back. If the name is taken again,
    /// a symlink is dropped (removing one never touches its target) and anything
    /// else stays in the slot, listed, for the operator.
    fn give_back(&self, slot_path: &Path, slot: &OwnedFd, dir: &OwnedFd, name: &CStr, real: &Path) -> io::Error {
        if safefs::rename_noreplace(slot.as_fd(), BLOB, dir.as_fd(), name).is_ok() {
            let _ = std::fs::remove_dir(slot_path);
            return changed();
        }
        match safefs::stat_at(slot.as_fd(), BLOB) {
            Ok(st) if st.is_symlink() => {
                // SAFETY: valid descriptor and NUL-terminated name.
                unsafe { libc::unlinkat(slot.as_raw_fd(), BLOB.as_ptr(), 0) };
                let _ = std::fs::remove_dir(slot_path);
            }
            Ok(st) => {
                let id = slot_path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                let e = Entry {
                    id,
                    original: real.to_string_lossy().into_owned(),
                    size: st.size,
                    mode: st.mode,
                    uid: st.uid,
                    gid: st.gid,
                    mtime: st.mtime,
                    hash: String::new(),
                    reason: "displaced: put in place of the file being quarantined, and the name was taken again"
                        .into(),
                    ts_ms: warden_core::event::now_ms(),
                    site: None,
                    cleared_attributes: None,
                };
                if let Ok(j) = serde_json::to_vec_pretty(&e) {
                    let _ = std::fs::write(slot_path.join("meta.json"), j);
                }
            }
            Err(_) => {
                let _ = std::fs::remove_dir(slot_path);
            }
        }
        changed()
    }

    /// The quarantine is on another filesystem: copy from the open file into
    /// a new blob (mode 000 from the start), sync it, then unlink the original
    /// if its name still refers to the copied inode.
    fn copy_out(
        &self,
        file: &std::fs::File,
        md: &safefs::Stat,
        dir: &OwnedFd,
        name: &CStr,
        slot: &OwnedFd,
    ) -> io::Result<()> {
        let mut src = file;
        src.seek(io::SeekFrom::Start(0))?;
        let mut blob = std::fs::File::from(safefs::open_at(
            slot.as_fd(),
            BLOB,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o000,
        )?);
        let done = io::copy(&mut src, &mut blob)
            .and_then(|_| blob.sync_all())
            .and_then(|()| safefs::unlink_if_same(dir.as_fd(), name, md));
        if done.is_err() {
            // the original stays where it was: drop the copy
            // SAFETY: valid descriptor and NUL-terminated name.
            unsafe { libc::unlinkat(slot.as_raw_fd(), BLOB.as_ptr(), 0) };
        }
        done
    }

    pub fn list(&self) -> Vec<Entry> {
        let Ok(rd) = std::fs::read_dir(&self.dir) else { return Vec::new() };
        let mut v: Vec<Entry> = rd
            .filter_map(Result::ok)
            .filter_map(|e| serde_json::from_slice(&std::fs::read(e.path().join("meta.json")).ok()?).ok())
            .collect();
        v.sort_by_key(|b| std::cmp::Reverse(b.ts_ms));
        v
    }

    /// Put a file back with its original mode, owner and mtime. The file is
    /// never written through a symlink someone other than root made: on the
    /// way to its directory only root's symlinks are followed (an operator's
    /// `/var/www -> /srv/www`, as in entries made before 0.13.4, works; a site
    /// user's `uploads -> /etc` does not), the name must be free (it is never
    /// replaced), and the metadata is applied to the restored inode by descriptor.
    pub fn restore(&self, id: &str) -> io::Result<Entry> {
        if id.is_empty() || id.contains('/') || id.contains("..") {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "bad id"));
        }
        let slot_path = self.dir.join(id);
        let e: Entry = serde_json::from_slice(&std::fs::read(slot_path.join("meta.json"))?)?;
        let dest = PathBuf::from(&e.original);
        let (parent, name) = safefs::split(&dest)?;
        let (_, dir) = safefs::open_root_strict(parent).map_err(|e| {
            if e.kind() == io::ErrorKind::PermissionDenied {
                io::Error::new(e.kind(), format!("{e}; not restored to {}", dest.display()))
            } else {
                e
            }
        })?;
        let slot = safefs::open_dir_nofollow(&std::fs::canonicalize(&slot_path)?)?;
        let blob = std::fs::File::from(safefs::open_at(slot.as_fd(), BLOB, libc::O_RDONLY | libc::O_NONBLOCK, 0)?);
        let bst = safefs::fstat(blob.as_fd())?;
        if !bst.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "the quarantined blob is not a regular file"));
        }
        let exists = || io::Error::new(io::ErrorKind::AlreadyExists, format!("{} already exists", dest.display()));
        let restored = match safefs::rename_noreplace(slot.as_fd(), BLOB, dir.as_fd(), &name) {
            Ok(()) => blob,
            Err(err) if err.raw_os_error() == Some(libc::EEXIST) => return Err(exists()),
            Err(err) if err.raw_os_error() == Some(libc::EXDEV) => {
                let mut out =
                    match safefs::open_at(dir.as_fd(), &name, libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o000) {
                        Ok(fd) => std::fs::File::from(fd),
                        Err(err) if err.raw_os_error() == Some(libc::EEXIST) => return Err(exists()),
                        Err(err) => return Err(err),
                    };
                io::copy(&mut &blob, &mut out)?;
                out.sync_all()?;
                safefs::unlink_if_same(slot.as_fd(), BLOB, &bst)?;
                out
            }
            Err(err) => return Err(err),
        };
        // Owner before mode: `chown` clears the set-id bits.
        let _ = safefs::fchown(restored.as_fd(), e.uid, e.gid);
        safefs::fchmod(restored.as_fd(), e.mode & 0o7777)?;
        let t = std::time::UNIX_EPOCH + std::time::Duration::from_secs(e.mtime.max(0) as u64);
        let _ = restored.set_modified(t);
        let _ = std::fs::remove_file(slot_path.join("meta.json"));
        let _ = std::fs::remove_dir(&slot_path);
        Ok(e)
    }
}

/// The name of the quarantined copy inside its slot.
const BLOB: &CStr = c"blob";

fn changed() -> io::Error {
    io::Error::other("the file changed while it was being quarantined (replaced or moved); nothing was done")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn quarantines_immutable_webshell_in_immutable_dir() {
        use warden_sys::fsflags::{FS_IMMUTABLE_FL, get};
        let d = tempfile::tempdir_in("/var/tmp").unwrap();
        let site = d.path().join("uploads");
        std::fs::create_dir(&site).unwrap();
        let f = site.join("shell.php");
        std::fs::write(&f, "<?php system($_GET[1]);").unwrap();
        let chattr = |args: &[&str], p: &Path| std::process::Command::new("chattr").args(args).arg(p).status();
        if !chattr(&["+i"], &f).is_ok_and(|s| s.success()) || !chattr(&["+i"], &site).is_ok_and(|s| s.success()) {
            return; // filesystem or environment without attribute support
        }
        assert!(std::fs::remove_file(&f).is_err(), "precondition: file must be undeletable");
        let q = Quarantine::new(d.path().join("q"));
        let e = q.put(&f, "test", None, any).unwrap();
        assert!(!f.exists());
        let attrs = e.cleared_attributes.unwrap();
        assert!(attrs.contains("file: immutable") && attrs.contains("directory: immutable"), "{attrs}");
        // the site directory gets its flag back
        assert_ne!(get(&site).unwrap() & FS_IMMUTABLE_FL, 0);
        let _ = chattr(&["-i"], &site);
    }

    #[test]
    fn put_list_restore() {
        let d = tempfile::tempdir().unwrap();
        let q = Quarantine::new(d.path().join("q"));
        let f = d.path().join("shell.php");
        std::fs::write(&f, "<?php system($_GET[1]);").unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o640)).unwrap();
        let e = q.put(&f, "test", Some("main".into()), any).unwrap();
        assert!(!f.exists());
        let blob = d.path().join("q").join(&e.id).join("blob");
        assert_eq!(std::fs::metadata(&blob).unwrap().mode() & 0o777, 0);
        assert_eq!(q.list().len(), 1);
        let r = q.restore(&e.id).unwrap();
        assert_eq!(Path::new(&r.original), std::fs::canonicalize(&f).unwrap());
        assert_eq!(std::fs::metadata(&f).unwrap().mode() & 0o777, 0o640);
        assert!(q.list().is_empty());
        assert!(q.restore("../etc").is_err());
        assert!(q.restore("").is_err());
    }

    fn any(_: &Path) -> Result<(), String> {
        Ok(())
    }

    #[test]
    fn put_refuses_a_symlink_and_a_path_outside_the_policy() {
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim");
        std::fs::write(&victim, "data").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        let q = Quarantine::new(d.path().join("q"));
        // the file itself is a symlink
        let link = d.path().join("shell.php");
        std::os::unix::fs::symlink(&victim, &link).unwrap();
        let e = q.put(&link, "t", None, any).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidInput, "{e}");
        // a directory on the way leads out of the site: the policy sees where
        let site = std::fs::canonicalize(d.path()).unwrap();
        std::os::unix::fs::symlink(outside.path(), site.join("uploads")).unwrap();
        let inside_site = |real: &Path| if real.starts_with(&site) { Ok(()) } else { Err(format!("{real:?} outside")) };
        let e = q.put(&site.join("uploads/victim"), "t", None, inside_site).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::PermissionDenied, "{e}");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "data");
        assert_eq!(std::fs::metadata(&victim).unwrap().mode() & 0o777, 0o644);
        assert!(q.list().is_empty());
    }

    /// A replacement in the open-to-rename window must not quarantine a symlink
    /// or change the target of that symlink. The hook makes the TOCTOU window
    /// deterministic instead of depending on thread scheduling.
    #[test]
    fn put_survives_a_file_symlink_swap_race() {
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let victim = outside.path().join("victim");
        std::fs::write(&victim, "data").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();

        let site = d.path().join("site");
        std::fs::create_dir(&site).unwrap();
        let shell = site.join("shell.php");
        std::fs::write(&shell, "<?php eval($_POST[1]);").unwrap();

        let quarantine_dir = d.path().join("q");
        let q = Quarantine::new(&quarantine_dir);
        let err = q
            .put_inner(&shell, "t", None, any, || {
                // The original file has already been opened and hashed. Replace
                // its name exactly before renameat2 moves that directory entry.
                std::fs::remove_file(&shell).unwrap();
                std::os::unix::fs::symlink(&victim, &shell).unwrap();
            })
            .unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::Other, "{err}");
        assert!(err.to_string().contains("file changed while it was being quarantined"), "unexpected error: {err}");

        let shell_meta = std::fs::symlink_metadata(&shell).unwrap();
        assert!(shell_meta.file_type().is_symlink(), "replacement is not a symlink");
        assert_eq!(std::fs::read_link(&shell).unwrap(), victim);

        assert_eq!(std::fs::metadata(&victim).unwrap().mode() & 0o777, 0o644, "the victim's permissions changed");
        assert_eq!(std::fs::read_to_string(&victim).unwrap(), "data", "the victim's contents changed");

        assert!(q.list().is_empty(), "failed put left a listed quarantine entry");
        assert_eq!(std::fs::read_dir(&quarantine_dir).unwrap().count(), 0, "failed put left a partial quarantine slot");

        // Leave the temporary test tree tidy; this only removes the symlink.
        std::fs::remove_file(&shell).unwrap();
    }

    #[test]
    fn restore_never_replaces_and_never_follows() {
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let site = std::fs::canonicalize(d.path()).unwrap().join("site");
        std::fs::create_dir(&site).unwrap();
        let q = Quarantine::new(d.path().join("q"));
        let f = site.join("index.php");
        std::fs::write(&f, "original").unwrap();
        let e = q.put(&f, "t", None, any).unwrap();
        // the name is taken again: not replaced
        std::fs::write(&f, "new").unwrap();
        assert_eq!(q.restore(&e.id).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "new");
        // the directory became a symlink elsewhere, made by someone else
        // than root (the site user): not restored there
        std::fs::remove_file(&f).unwrap();
        std::fs::remove_dir(&site).unwrap();
        std::os::unix::fs::symlink(outside.path(), &site).unwrap();
        // SAFETY: trivial libc call.
        if unsafe { libc::geteuid() } == 0 {
            std::os::unix::fs::lchown(&site, Some(65534), Some(65534)).unwrap();
        }
        let err = q.restore(&e.id).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
        assert!(!outside.path().join("index.php").exists());
        // back in place: restored
        std::fs::remove_file(&site).unwrap();
        std::fs::create_dir(&site).unwrap();
        q.restore(&e.id).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "original");
    }

    /// An entry whose directory is reached through root's own symlink (a
    /// site root configured as `/var/www -> /srv/www`) is restored.
    #[test]
    fn restore_follows_roots_own_symlink() {
        // SAFETY: trivial libc call.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(d.path()).unwrap();
        std::fs::create_dir(base.join("srv")).unwrap();
        std::os::unix::fs::symlink(base.join("srv"), base.join("www")).unwrap();
        let q = Quarantine::new(base.join("q"));
        let f = base.join("srv/index.php");
        std::fs::write(&f, "x").unwrap();
        let mut e = q.put(&f, "t", None, any).unwrap();
        // as 0.13.3 recorded it: the path through the symlink
        e.original = base.join("www/index.php").to_string_lossy().into_owned();
        std::fs::write(base.join("q").join(&e.id).join("meta.json"), serde_json::to_vec(&e).unwrap()).unwrap();
        q.restore(&e.id).unwrap();
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "x");
    }

    /// Owner before mode: `chown` after `chmod` would drop the set-id bits.
    #[test]
    fn restore_keeps_owner_and_setuid_bits() {
        // SAFETY: trivial libc call.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let d = tempfile::tempdir().unwrap();
        let q = Quarantine::new(d.path().join("q"));
        let f = d.path().join("tool");
        std::fs::write(&f, "x").unwrap();
        std::os::unix::fs::chown(&f, Some(65534), Some(65534)).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(0o4755)).unwrap();
        let e = q.put(&f, "t", None, any).unwrap();
        q.restore(&e.id).unwrap();
        let md = std::fs::metadata(&f).unwrap();
        assert_eq!((md.uid(), md.gid()), (65534, 65534));
        assert_eq!(md.mode() & 0o7777, 0o4755);
    }
}
