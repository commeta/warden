//! Bounded kernel tuning: which sysctls Warden may change and how far.
//!
//! Only *capacity* limits are adjustable — tables and counters that, when
//! exhausted, make the kernel refuse work (drop connections, fail fork(),
//! fail open()). Raising them within RAM-proportional caps is safe and
//! reversible. Behaviour-shaping knobs (swappiness, dirty ratios,
//! overcommit, THP) are only ever *recommended*, never changed.

/// Keys the `sysctl` action accepts.
pub const GROWABLE: &[&str] = &[
    "net.netfilter.nf_conntrack_max",
    "kernel.pid_max",
    "fs.file-max",
    "fs.inotify.max_user_watches",
    "fs.inotify.max_user_instances",
    "net.core.somaxconn",
    "vm.max_map_count",
];

const GIB: u64 = 1 << 30;

/// Upper bound for a key on a machine with `ram` bytes of memory.
pub fn cap_for(key: &str, ram: u64) -> Option<u64> {
    let ram = ram.max(GIB / 2);
    Some(match key {
        // ~300 bytes of kernel memory per entry: cap at ≈2% of RAM.
        "net.netfilter.nf_conntrack_max" => (ram / 16384).clamp(65_536, 4_194_304),
        // PID_MAX_LIMIT on 64-bit.
        "kernel.pid_max" => 4_194_304,
        // ≈1KiB per open file object.
        "fs.file-max" => (ram / 1024).max(1_048_576),
        // ≈1KiB per watch, only consumed when actually used.
        "fs.inotify.max_user_watches" => (ram / 16384).clamp(65_536, 4_194_304),
        "fs.inotify.max_user_instances" => 8192,
        "net.core.somaxconn" => 65_535,
        "vm.max_map_count" => 1_048_576,
        _ => return None,
    })
}

/// Next value when `key` is close to exhaustion: double, bounded by the cap.
/// `None` when already at (or above) the cap.
pub fn grow(key: &str, current: u64, ram: u64) -> Option<u64> {
    let cap = cap_for(key, ram)?;
    if current >= cap {
        return None;
    }
    Some(current.saturating_mul(2).clamp(current + 1, cap))
}

/// Validate a requested change (used by the responder as the final gate).
pub fn check(key: &str, value: &str, ram: u64) -> Result<u64, String> {
    if !GROWABLE.contains(&key) {
        return Err(format!("{key} is not an adjustable capacity limit (allowed: {})", GROWABLE.join(", ")));
    }
    let v: u64 = value.trim().parse().map_err(|_| format!("{key}: value {value:?} is not an integer"))?;
    let cap = cap_for(key, ram).unwrap_or(0);
    if v == 0 || v > cap {
        return Err(format!("{key}={v} is outside the safe range 1..={cap} for this machine"));
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caps_scale_with_ram() {
        assert_eq!(cap_for("net.netfilter.nf_conntrack_max", 8 * GIB), Some(524_288));
        assert_eq!(cap_for("net.netfilter.nf_conntrack_max", GIB), Some(65_536));
        assert_eq!(cap_for("vm.swappiness", 8 * GIB), None);
    }

    #[test]
    fn growth_is_bounded() {
        assert_eq!(grow("net.netfilter.nf_conntrack_max", 262_144, 8 * GIB), Some(524_288));
        assert_eq!(grow("net.netfilter.nf_conntrack_max", 400_000, 8 * GIB), Some(524_288));
        assert_eq!(grow("net.netfilter.nf_conntrack_max", 524_288, 8 * GIB), None);
        assert_eq!(grow("kernel.pid_max", 32_768, 8 * GIB), Some(65_536));
    }

    #[test]
    fn check_rejects_unsafe() {
        assert!(check("vm.swappiness", "10", 8 * GIB).is_err());
        assert!(check("kernel.pid_max", "99999999", 8 * GIB).is_err());
        assert!(check("kernel.pid_max", "abc", 8 * GIB).is_err());
        assert_eq!(check("kernel.pid_max", "131072", 8 * GIB), Ok(131_072));
    }
}
