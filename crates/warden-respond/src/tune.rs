//! Guarded sysctl changes with a journal of original values (for revert)
//! and optional persistence to /etc/sysctl.d.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use warden_core::tuning;

pub const PERSIST_FILE: &str = "/etc/sysctl.d/90-warden.conf";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Change {
    pub key: String,
    /// Value before Warden first touched the key.
    pub original: String,
    pub value: String,
    pub ts_ms: u64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Journal {
    changes: BTreeMap<String, Change>,
}

#[derive(Debug, Clone)]
pub struct Tuner {
    journal_path: PathBuf,
    sys_root: PathBuf,
    persist_path: Option<PathBuf>,
}

impl Tuner {
    pub fn new(state_dir: &Path, persist: bool) -> Self {
        Self {
            journal_path: state_dir.join("sysctl-changes.json"),
            sys_root: PathBuf::from(warden_sys::sysctl::ROOT),
            persist_path: persist.then(|| PathBuf::from(PERSIST_FILE)),
        }
    }

    #[cfg(test)]
    fn with_roots(journal: PathBuf, sys_root: PathBuf, persist: Option<PathBuf>) -> Self {
        Self { journal_path: journal, sys_root, persist_path: persist }
    }

    fn load(&self) -> Journal {
        std::fs::read(&self.journal_path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default()
    }

    fn save(&self, j: &Journal) -> std::io::Result<()> {
        warden_sys::util::write_atomic(&self.journal_path, &serde_json::to_vec_pretty(j)?)?;
        self.write_persist(j)
    }

    fn write_persist(&self, j: &Journal) -> std::io::Result<()> {
        let Some(p) = &self.persist_path else { return Ok(()) };
        if j.changes.is_empty() {
            let _ = std::fs::remove_file(p);
            return Ok(());
        }
        let mut s = String::from("# Managed by Warden (tuning.auto_grow). Revert: wardenctl tuning revert\n");
        for c in j.changes.values() {
            s.push_str(&format!("{} = {}\n", c.key, c.value));
        }
        warden_sys::util::write_atomic(p, s.as_bytes())
    }

    pub fn changes(&self) -> Vec<Change> {
        self.load().changes.into_values().collect()
    }

    /// Validate and apply. Returns a human message.
    pub fn apply(&self, key: &str, value: &str, ram: u64) -> Result<String, String> {
        let v = tuning::check(key, value, ram)?;
        let cur = warden_sys::sysctl::read_in(&self.sys_root, key).map_err(|e| format!("{key}: {e}"))?;
        let cur_n: u64 = cur.split_whitespace().next().and_then(|x| x.parse().ok()).unwrap_or(0);
        if cur_n >= v {
            return Ok(format!("{key} is already {cur} (≥ {v}); nothing to do"));
        }
        warden_sys::sysctl::write_in(&self.sys_root, key, &v.to_string()).map_err(|e| format!("{key}: {e}"))?;
        let mut j = self.load();
        let original = j.changes.get(key).map(|c| c.original.clone()).unwrap_or(cur.clone());
        j.changes.insert(
            key.to_owned(),
            Change { key: key.to_owned(), original, value: v.to_string(), ts_ms: warden_core::event::now_ms() },
        );
        self.save(&j).map_err(|e| format!("journal: {e}"))?;
        Ok(format!(
            "{key}: {cur} → {v}{}",
            if self.persist_path.is_some() { " (persisted)" } else { " (runtime only)" }
        ))
    }

    /// Restore every original value. Returns what was restored.
    pub fn revert(&self) -> Vec<String> {
        let mut j = self.load();
        let mut out = Vec::new();
        for c in j.changes.values() {
            match warden_sys::sysctl::write_in(&self.sys_root, &c.key, &c.original) {
                Ok(()) => out.push(format!("{} restored to {}", c.key, c.original)),
                Err(e) => out.push(format!("{}: cannot restore: {e}", c.key)),
            }
        }
        j.changes.clear();
        let _ = self.save(&j);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_journal_persist_revert() {
        let d = tempfile::tempdir().unwrap();
        let sys = d.path().join("sys");
        std::fs::create_dir_all(sys.join("kernel")).unwrap();
        std::fs::write(sys.join("kernel/pid_max"), "32768\n").unwrap();
        let persist = d.path().join("90-warden.conf");
        let t = Tuner::with_roots(d.path().join("j.json"), sys.clone(), Some(persist.clone()));
        let ram = 8u64 << 30;
        assert!(t.apply("vm.swappiness", "10", ram).is_err());
        assert!(t.apply("kernel.pid_max", "65536", ram).unwrap().contains("32768 → 65536"));
        assert!(t.apply("kernel.pid_max", "131072", ram).is_ok());
        assert!(t.apply("kernel.pid_max", "100000", ram).unwrap().contains("nothing to do"));
        let ch = t.changes();
        assert_eq!(ch[0].original, "32768");
        assert_eq!(ch[0].value, "131072");
        assert!(std::fs::read_to_string(&persist).unwrap().contains("kernel.pid_max = 131072"));
        let r = t.revert();
        assert!(r[0].contains("restored to 32768"));
        assert_eq!(std::fs::read_to_string(sys.join("kernel/pid_max")).unwrap(), "32768");
        assert!(!persist.exists());
    }
}
