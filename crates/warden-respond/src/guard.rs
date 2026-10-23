//! Path safety rules for destructive filesystem actions.

use std::path::{Component, Path, PathBuf};

/// Never delete/truncate/quarantine anything under these prefixes.
const DENY: &[&str] = &[
    "/bin",
    "/sbin",
    "/usr",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/etc",
    "/boot",
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/var/lib",
    "/snap",
    "/efi",
    "/root/.ssh",
];
/// ... except these, which are routinely cleaned.
const ALLOW_INSIDE_DENY: &[&str] =
    &["/var/lib/docker/containers", "/dev/shm", "/run/shm", "/var/lib/apt/lists/partial"];

/// Lexically normalise a path (no symlink resolution): drop `.`, fold `..`.
pub fn normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

fn under(p: &Path, prefix: &str) -> bool {
    p == Path::new(prefix) || p.starts_with(prefix)
}

/// May a cleanup action (delete/truncate) touch this path? A pure policy
/// check: `real` must be where the file really is — the path of the entry
/// as the descriptor-based walk reached it ([`warden_sys::safefs::walk`]),
/// never a path that is resolved now and acted on later.
pub fn check_cleanup_path(real: &Path) -> Result<(), String> {
    if !real.is_absolute() {
        return Err(format!("{} is not absolute", real.display()));
    }
    if real.components().count() < 3 {
        return Err(format!("{} is too close to the filesystem root", real.display()));
    }
    if ALLOW_INSIDE_DENY.iter().any(|a| under(real, a)) {
        return Ok(());
    }
    if let Some(d) = DENY.iter().find(|d| under(real, d)) {
        return Err(format!("{} is inside protected location {d}", real.display()));
    }
    if real.components().any(|c| c.as_os_str() == ".ssh" || c.as_os_str() == ".gnupg") {
        return Err(format!("{} is inside a credentials directory", real.display()));
    }
    Ok(())
}

/// May a file be quarantined? It must live under a configured site root or
/// a temporary location, and never in system directories. `real` is where
/// the file really is: the path the quarantine got while opening its
/// directory without following untrusted symlinks
/// ([`warden_sys::safefs::open_root`]), so that a directory swapped for a
/// symlink after the check cannot move the action elsewhere.
pub fn check_quarantine_path(real: &Path, roots: &[PathBuf]) -> Result<(), String> {
    let tmp = ["/tmp", "/var/tmp", "/dev/shm", "/run/shm"];
    let in_root = roots.iter().any(|r| {
        let r = warden_sys::safefs::open_root(r).map(|(p, _)| p).unwrap_or_else(|_| normalize(r));
        real.starts_with(&r)
    });
    if !(in_root || tmp.iter().any(|t| under(real, t))) {
        return Err(format!("{} is outside FIM site roots and temporary directories", real.display()));
    }
    if DENY.iter().filter(|d| !["/dev", "/run"].contains(d)).any(|d| under(real, d)) {
        return Err(format!("{} is inside a system directory", real.display()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization() {
        assert_eq!(normalize(Path::new("/var/log/../../etc/passwd")), PathBuf::from("/etc/passwd"));
        assert_eq!(normalize(Path::new("/var/./log/x")), PathBuf::from("/var/log/x"));
    }

    #[test]
    fn cleanup_rules() {
        let ok = |p: &str| check_cleanup_path(&normalize(Path::new(p))).is_ok();
        assert!(!ok("/etc/passwd"));
        assert!(!ok("/var/log/../../etc/shadow"));
        assert!(!ok("/var/lib/mysql/ibdata1"));
        assert!(ok("/var/log/syslog.1"));
        assert!(ok("/tmp/x"));
        assert!(ok("/var/lib/docker/containers/abc/abc-json.log"));
        assert!(!ok("/var/lib/postgresql/16/main/base/1"));
        assert!(!ok("/home/bob/.ssh/id_rsa"));
        assert!(!ok("relative/x"));
        assert!(!ok("/x"));
    }

    #[test]
    fn quarantine_rules() {
        let d = tempfile::tempdir().unwrap();
        let roots = vec![d.path().to_path_buf()];
        let real = std::fs::canonicalize(d.path()).unwrap().join("shell.php");
        assert!(check_quarantine_path(&real, &roots).is_ok());
        assert!(check_quarantine_path(Path::new("/usr/bin/ls"), &roots).is_err());
        assert!(check_quarantine_path(Path::new("/etc/passwd"), &roots).is_err());
        assert!(check_quarantine_path(Path::new("/var/tmp/x.php"), &[]).is_ok());
        assert!(check_quarantine_path(Path::new("/srv/other/x.php"), &roots).is_err());
    }
}
