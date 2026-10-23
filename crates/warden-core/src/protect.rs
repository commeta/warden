//! Process protection rules shared by detectors (victim selection) and the
//! responder (final enforcement). Pure logic: callers supply attributes.
//!
//! What is trusted here is only what the kernel vouches for: the PID, the
//! executable (`/proc/<pid>/exe`), the cgroup and the UID. The process name
//! (`comm`) is chosen by the process itself, so a name match protects only a
//! process that is verified to be the program of that name (see
//! [`ProcAttrs::genuine`]): a miner calling itself `systemd-udevd` gets no
//! immunity from the name.

use crate::config::ProtectionConfig;
use crate::glob::GlobList;

/// Attributes needed to decide whether a process may be touched.
#[derive(Debug, Clone, Default)]
pub struct ProcAttrs<'a> {
    pub pid: i32,
    pub comm: &'a str,
    pub exe: Option<&'a str>,
    pub cgroup: Option<&'a str>,
    pub uid: Option<u32>,
    pub kernel_thread: bool,
    /// Is the process the program its name claims — a root-owned executable
    /// whose basename explains `comm` (`warden_sys::process::verify_daemon`)?
    /// `Some(false)` withdraws the protection a `comm` match would give;
    /// `None` (could not be verified) keeps it: when in doubt, do not touch.
    pub genuine: Option<bool>,
}

#[derive(Debug, Clone, Default)]
pub struct Protection {
    comm: GlobList,
    exe: GlobList,
    units: GlobList,
    uids: Vec<u32>,
    self_pid: i32,
}

impl Protection {
    pub fn new(cfg: &ProtectionConfig) -> Self {
        Self {
            comm: GlobList::new(&cfg.comm),
            exe: GlobList::new(&cfg.exe),
            units: GlobList::new(&cfg.units),
            uids: cfg.uids.clone(),
            self_pid: std::process::id() as i32,
        }
    }

    /// `Err(reason)` if the process is protected.
    pub fn check(&self, p: &ProcAttrs<'_>) -> Result<(), String> {
        if p.pid <= 1 {
            return Err("PID 1 / invalid PID".into());
        }
        if p.pid == self.self_pid {
            return Err("Warden itself".into());
        }
        if p.kernel_thread {
            return Err("kernel thread".into());
        }
        if self.comm.is_match(p.comm) && p.genuine != Some(false) {
            return Err(format!("protected comm {:?}", p.comm));
        }
        if let Some(exe) = p.exe {
            let clean = exe.trim_end_matches(" (deleted)");
            if self.exe.is_match(clean) {
                return Err(format!("protected executable {clean}"));
            }
        }
        if let Some(cg) = p.cgroup {
            for comp in cg.split('/').filter(|c| !c.is_empty()) {
                if self.units.is_match(comp) {
                    return Err(format!("protected unit {comp}"));
                }
            }
        }
        if let Some(uid) = p.uid
            && self.uids.contains(&uid)
        {
            return Err(format!("protected uid {uid}"));
        }
        Ok(())
    }

    pub fn is_unit_protected(&self, unit: &str) -> bool {
        self.units.is_match(unit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_protection() {
        let p = Protection::new(&ProtectionConfig::default());
        let a = |comm, cg| ProcAttrs {
            pid: 1000,
            comm,
            exe: None,
            cgroup: Some(cg),
            uid: Some(33),
            kernel_thread: false,
            genuine: None,
        };
        assert!(p.check(&a("sshd", "/system.slice/ssh.service")).is_err());
        assert!(p.check(&a("bash", "/system.slice/ssh.service")).is_err());
        assert!(p.check(&a("php-fpm8.3", "/system.slice/php8.3-fpm.service")).is_ok());
        assert!(p.check(&a("systemd-journal", "/system.slice/systemd-journald.service")).is_err());
        assert!(p.check(&ProcAttrs { pid: 1, comm: "x", ..Default::default() }).is_err());
        assert!(
            p.check(&ProcAttrs { pid: 50, comm: "kworker/0:1", kernel_thread: true, ..Default::default() }).is_err()
        );
    }

    #[test]
    fn a_name_alone_does_not_protect_an_impostor() {
        let p = Protection::new(&ProtectionConfig::default());
        let named = |genuine| ProcAttrs { pid: 1000, comm: "systemd-udevd", genuine, ..Default::default() };
        assert!(p.check(&named(Some(true))).is_err(), "the real daemon stays protected");
        assert!(p.check(&named(None)).is_err(), "unverified: do not touch");
        assert!(p.check(&named(Some(false))).is_ok(), "a process that merely carries the name is not immune");
        // what the kernel vouches for protects regardless of the name
        let by_exe =
            ProcAttrs { pid: 1000, comm: "x", exe: Some("/usr/sbin/sshd"), genuine: Some(false), ..Default::default() };
        assert!(p.check(&by_exe).is_err());
        let by_unit = ProcAttrs {
            pid: 1000,
            comm: "x",
            cgroup: Some("/system.slice/ssh.service"),
            genuine: Some(false),
            ..Default::default()
        };
        assert!(p.check(&by_unit).is_err());
    }
}
