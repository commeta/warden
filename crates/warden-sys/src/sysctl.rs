//! Reading and writing kernel parameters through /proc/sys.

use std::io;
use std::path::{Path, PathBuf};

pub const ROOT: &str = "/proc/sys";

fn path_in(root: &Path, key: &str) -> io::Result<PathBuf> {
    if key.is_empty() || key.contains("..") || key.contains('/') || key.starts_with('.') {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("bad sysctl key {key:?}")));
    }
    Ok(root.join(key.replace('.', "/")))
}

pub fn read_in(root: &Path, key: &str) -> io::Result<String> {
    Ok(std::fs::read_to_string(path_in(root, key)?)?.trim().to_owned())
}

pub fn write_in(root: &Path, key: &str, value: &str) -> io::Result<()> {
    std::fs::write(path_in(root, key)?, value)
}

pub fn read(key: &str) -> io::Result<String> {
    read_in(Path::new(ROOT), key)
}

pub fn read_u64(key: &str) -> Option<u64> {
    read(key).ok()?.split_whitespace().next()?.parse().ok()
}

pub fn write(key: &str, value: &str) -> io::Result<()> {
    write_in(Path::new(ROOT), key, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_map_to_paths_and_reject_traversal() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("kernel")).unwrap();
        std::fs::write(d.path().join("kernel/pid_max"), "32768\n").unwrap();
        assert_eq!(read_in(d.path(), "kernel.pid_max").unwrap(), "32768");
        write_in(d.path(), "kernel.pid_max", "65536").unwrap();
        assert_eq!(read_in(d.path(), "kernel.pid_max").unwrap(), "65536");
        assert!(read_in(d.path(), "../etc/passwd").is_err());
        assert!(read_in(d.path(), "kernel/pid_max").is_err());
        assert!(read_u64("kernel.pid_max").is_some());
    }
}
