//! Kernel state: taint flags, loaded modules, LSM status, clock sync.

use crate::util::{read_string, read_trimmed, read_u64};
use std::collections::BTreeSet;

/// Kernel taint bits → (letter, description). See Documentation/admin-guide/tainted-kernels.rst
pub const TAINT_FLAGS: &[(u32, char, &str)] = &[
    (0, 'P', "proprietary module loaded"),
    (1, 'F', "module force-loaded"),
    (2, 'S', "SMP with non-SMP CPU / out-of-spec"),
    (3, 'R', "module force-unloaded"),
    (4, 'M', "machine check exception"),
    (5, 'B', "bad page referenced"),
    (6, 'U', "taint requested by userspace"),
    (7, 'D', "kernel died recently (OOPS/BUG)"),
    (8, 'A', "ACPI table overridden"),
    (9, 'W', "kernel issued a warning"),
    (10, 'C', "staging driver loaded"),
    (11, 'I', "platform firmware bug workaround"),
    (12, 'O', "out-of-tree module loaded"),
    (13, 'E', "unsigned module loaded"),
    (14, 'L', "soft lockup occurred"),
    (15, 'K', "kernel live-patched"),
    (16, 'X', "auxiliary taint"),
    (17, 'T', "struct randomization plugin"),
    (18, 'N', "in-kernel test"),
];

pub fn tainted() -> Option<u64> {
    read_u64("/proc/sys/kernel/tainted")
}

pub fn taint_letters(v: u64) -> Vec<(char, &'static str)> {
    TAINT_FLAGS.iter().filter(|(b, _, _)| v & (1u64 << b) != 0).map(|(_, c, d)| (*c, *d)).collect()
}

/// Bits newly set in `now` compared to `before`.
pub fn new_taints(before: u64, now: u64) -> Vec<(char, &'static str)> {
    taint_letters(now & !before)
}

pub fn parse_modules(content: &str) -> BTreeSet<String> {
    content.lines().filter_map(|l| l.split_whitespace().next().map(str::to_owned)).collect()
}

pub fn modules() -> BTreeSet<String> {
    read_string("/proc/modules").map(|s| parse_modules(&s)).unwrap_or_default()
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct LsmState {
    /// Active LSM stack (`capability,lockdown,landlock,yama,apparmor`).
    pub stack: Option<String>,
    pub apparmor_enabled: Option<bool>,
    /// `Some(true)` = enforcing, `Some(false)` = permissive, `None` = absent.
    pub selinux_enforcing: Option<bool>,
    /// Number of loaded AppArmor profiles in enforce mode.
    pub apparmor_enforced_profiles: Option<usize>,
    pub lockdown: Option<String>,
}

pub fn lsm_state() -> LsmState {
    let apparmor_enforced_profiles = read_string("/sys/kernel/security/apparmor/profiles")
        .ok()
        .map(|s| s.lines().filter(|l| l.ends_with("(enforce)")).count());
    let lockdown = read_trimmed("/sys/kernel/security/lockdown").and_then(|s| {
        // "none [integrity] confidentiality" → the bracketed one is active.
        let start = s.find('[')?;
        let end = s.find(']')?;
        Some(s[start + 1..end].to_owned())
    });
    LsmState {
        stack: read_trimmed("/sys/kernel/security/lsm"),
        apparmor_enabled: read_trimmed("/sys/module/apparmor/parameters/enabled").map(|s| s == "Y"),
        selinux_enforcing: read_trimmed("/sys/fs/selinux/enforce").map(|s| s == "1"),
        apparmor_enforced_profiles,
        lockdown,
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct ClockStatus {
    pub synced: bool,
    /// Maximum error estimate, microseconds.
    pub max_error_us: i64,
    pub est_error_us: i64,
}

const STA_UNSYNC: i32 = 0x0040;
const TIME_ERROR: i32 = 5;

pub fn clock_status() -> Option<ClockStatus> {
    // SAFETY: zeroed timex with modes = 0 is a read-only query.
    let mut tx: libc::timex = unsafe { std::mem::zeroed() };
    let state = unsafe { libc::adjtimex(&mut tx) };
    if state < 0 {
        return None;
    }
    Some(ClockStatus {
        synced: state != TIME_ERROR && (tx.status & STA_UNSYNC) == 0,
        max_error_us: tx.maxerror as i64,
        est_error_us: tx.esterror as i64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taint_decoding() {
        let l = taint_letters((1 << 12) | (1 << 13));
        assert_eq!(l.iter().map(|x| x.0).collect::<String>(), "OE");
        assert_eq!(new_taints(1 << 12, (1 << 12) | (1 << 7))[0].0, 'D');
        assert!(new_taints(5, 5).is_empty());
    }

    #[test]
    fn modules_parsing() {
        let m = parse_modules("nf_tables 300000 0 - Live 0x0\nxt_conntrack 16384 2 - Live 0x0\n");
        assert!(m.contains("nf_tables"));
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn clock_query_does_not_fail() {
        assert!(clock_status().is_some());
    }
}
