//! Remediation actions as they appear in configuration.
//!
//! Each action is either a short name (`"kill"`, `"snapshot"`) or a table
//! with parameters (`{ do = "journal_vacuum", max_size = "500MiB" }`).
//! Actions are *templates*: the responder resolves them against the event
//! subject (which process to kill, which file to quarantine, ...).

use crate::units::ByteSize;
use serde::{Deserialize, Deserializer, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "do", rename_all = "snake_case", deny_unknown_fields)]
pub enum ActionSpec {
    /// Collect a diagnostic snapshot (process table, PSI, meminfo, kmsg tail...).
    Snapshot,
    /// SIGTERM the subject process, wait `grace`, then SIGKILL. With
    /// `tree = true` descendants are terminated first.
    Kill {
        #[serde(default)]
        tree: bool,
        #[serde(default, with = "humantime_serde::option", skip_serializing_if = "Option::is_none")]
        grace: Option<Duration>,
    },
    /// SIGSTOP the subject process (and its descendants): containment that
    /// preserves memory for forensics. Resume with `kill -CONT`.
    Stop,
    /// Freeze the whole cgroup of the subject (`cgroup.freeze`).
    FreezeCgroup,
    /// Kill every process in the subject's cgroup (`cgroup.kill`, Linux 5.14+).
    KillCgroup,
    /// `systemctl restart` the given unit, or the unit owning the subject.
    RestartUnit {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unit: Option<String>,
    },
    /// Move the subject file into quarantine (metadata preserved, mode 000).
    Quarantine,
    /// Block the subject IP (or `details.ip`) in the nftables blocklist.
    BlockIp {
        #[serde(default, with = "humantime_serde::option", skip_serializing_if = "Option::is_none")]
        ttl: Option<Duration>,
    },
    /// `journalctl --vacuum-size/--vacuum-time`.
    JournalVacuum {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_size: Option<ByteSize>,
        #[serde(default, with = "humantime_serde::option", skip_serializing_if = "Option::is_none")]
        max_age: Option<Duration>,
    },
    /// Delete regular files matching globs that are older than `older_than`.
    DeleteOld {
        paths: Vec<String>,
        #[serde(with = "humantime_serde")]
        older_than: Duration,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_files: Option<usize>,
        /// Which timestamp ages a file: `mtime` (logs, the default) or
        /// `newest` — the newest of atime, mtime and ctime, as
        /// `systemd-tmpfiles` does (a file that is still read is kept, and
        /// `touch -d` cannot make a file look old).
        #[serde(default, skip_serializing_if = "AgeFrom::is_default")]
        age_from: AgeFrom,
        /// Globs never touched; a matching directory is not entered
        /// (`/tmp/systemd-private-*`, X server locks).
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        exclude: Vec<String>,
    },
    /// Truncate (copytruncate-style) files matching globs that exceed `larger_than`.
    TruncateLarge { paths: Vec<String>, larger_than: ByteSize },
    /// Truncate deleted-but-still-open files on the subject mount that hold
    /// at least `min_size` (the classic "df says full, du says empty").
    TruncateDeleted {
        #[serde(default = "default_deleted_min")]
        min_size: ByteSize,
    },
    /// `apt-get clean` (package cache).
    AptClean,
    /// Lower the priority of the subject process (all threads): nice 19 and
    /// the idle I/O class. Reversible, nothing is lost — the gentle answer to
    /// a long-running script that must not be killed.
    Throttle {
        #[serde(default = "default_nice")]
        nice: i32,
        #[serde(default = "default_true")]
        io_idle: bool,
    },
    /// Runtime resource limits on a systemd unit (`systemctl set-property
    /// --runtime`): reverts at reboot. Unit defaults to the subject's.
    LimitUnit {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unit: Option<String>,
        /// e.g. "50%" (of one CPU) or "200%".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cpu_quota: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        memory_high: Option<ByteSize>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        memory_max: Option<ByteSize>,
    },
    /// Set a kernel parameter. Only allow-listed capacity keys are accepted
    /// and values are bounded by RAM-derived caps (see the tuning docs).
    Sysctl { key: String, value: String },
    /// Run an external program. The event is passed as JSON in
    /// `WARDEN_EVENT_JSON`, plus `WARDEN_EVENT_KIND`, `WARDEN_SEVERITY`.
    Exec {
        program: String,
        #[serde(default)]
        args: Vec<String>,
        #[serde(default, with = "humantime_serde::option", skip_serializing_if = "Option::is_none")]
        timeout: Option<Duration>,
        /// Account to run as (name or UID); default `daemon.command_user`,
        /// and root when that is unset too.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        user: Option<String>,
    },
}

/// The timestamp `delete_old` ages a file by.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgeFrom {
    #[default]
    Mtime,
    Newest,
}

impl AgeFrom {
    fn is_default(&self) -> bool {
        *self == AgeFrom::Mtime
    }
}

fn default_nice() -> i32 {
    19
}

fn default_true() -> bool {
    true
}

fn default_deleted_min() -> ByteSize {
    ByteSize::mib(100)
}

impl ActionSpec {
    pub fn name(&self) -> &'static str {
        match self {
            ActionSpec::Snapshot => "snapshot",
            ActionSpec::Kill { .. } => "kill",
            ActionSpec::Stop => "stop",
            ActionSpec::FreezeCgroup => "freeze_cgroup",
            ActionSpec::KillCgroup => "kill_cgroup",
            ActionSpec::RestartUnit { .. } => "restart_unit",
            ActionSpec::Quarantine => "quarantine",
            ActionSpec::BlockIp { .. } => "block_ip",
            ActionSpec::JournalVacuum { .. } => "journal_vacuum",
            ActionSpec::DeleteOld { .. } => "delete_old",
            ActionSpec::TruncateLarge { .. } => "truncate_large",
            ActionSpec::TruncateDeleted { .. } => "truncate_deleted",
            ActionSpec::AptClean => "apt_clean",
            ActionSpec::Throttle { .. } => "throttle",
            ActionSpec::LimitUnit { .. } => "limit_unit",
            ActionSpec::Sysctl { .. } => "sysctl",
            ActionSpec::Exec { .. } => "exec",
        }
    }

    /// Destructive actions are subject to stricter rate limits and are the
    /// only ones suppressed by `dry_run` (snapshots still run in dry-run).
    pub fn is_destructive(&self) -> bool {
        !matches!(self, ActionSpec::Snapshot)
    }

    /// Actions that terminate processes count against `max_kills_per_hour`.
    pub fn is_kill(&self) -> bool {
        matches!(self, ActionSpec::Kill { .. } | ActionSpec::KillCgroup)
    }

    /// Containment that must not wait behind a cleanup or a hook: it acts
    /// on a live process, cgroup, file or address, and takes at most the
    /// kill grace. An event with one of these goes to the urgent lane of the
    /// executor (all kills are there, so two kills never race); everything
    /// else (`systemctl restart`, `apt-get clean`, journal vacuum, file
    /// cleanup, `exec` hooks, `limit_unit`, `sysctl`) to the slow lane.
    pub fn is_urgent(&self) -> bool {
        matches!(
            self,
            ActionSpec::Kill { .. }
                | ActionSpec::Stop
                | ActionSpec::FreezeCgroup
                | ActionSpec::KillCgroup
                | ActionSpec::BlockIp { .. }
                | ActionSpec::Quarantine
                | ActionSpec::Throttle { .. }
        )
    }

    /// Identity of this exact action for the per-target cooldown: its kind
    /// *and* parameters. Two `delete_old` steps of one playbook (different
    /// paths and ages) are different actions and must not cool each other
    /// down; the same step repeated on the same target is what the
    /// cooldown exists to suppress.
    pub fn cooldown_key(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| self.name().to_owned())
    }

    /// Cleanup actions reclaim disk space.
    pub fn is_cleanup(&self) -> bool {
        matches!(
            self,
            ActionSpec::JournalVacuum { .. }
                | ActionSpec::DeleteOld { .. }
                | ActionSpec::TruncateLarge { .. }
                | ActionSpec::TruncateDeleted { .. }
                | ActionSpec::AptClean
        )
    }
}

/// Deserialize a single action from either `"name"` or a `{ do = ... }` table.
pub fn parse_action<'de, D: Deserializer<'de>>(d: D) -> Result<ActionSpec, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Short(String),
        Full(serde_json::Value),
    }
    let v = match Repr::deserialize(d)? {
        Repr::Short(name) => serde_json::json!({ "do": name }),
        Repr::Full(v) => v,
    };
    serde_json::from_value(v).map_err(serde::de::Error::custom)
}

/// `deserialize_with` helper for `Vec<ActionSpec>` fields.
pub fn de_actions<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<ActionSpec>, D::Error> {
    #[derive(Deserialize)]
    struct One(#[serde(deserialize_with = "parse_action")] ActionSpec);
    let items: Vec<One> = Vec::deserialize(d)?;
    Ok(items.into_iter().map(|o| o.0).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Holder {
        #[serde(deserialize_with = "de_actions")]
        a: Vec<ActionSpec>,
    }

    #[test]
    fn short_and_full_forms() {
        let h: Holder = toml::from_str(
            r#"a = [
                "snapshot",
                "kill",
                { do = "kill", tree = true, grace = "2s" },
                { do = "journal_vacuum", max_size = "500MiB" },
                { do = "delete_old", paths = ["/var/log/*.gz"], older_than = "7d" },
                { do = "delete_old", paths = ["/tmp/**"], older_than = "10d", age_from = "newest", exclude = ["/tmp/.X*-lock"] },
                "throttle",
                { do = "limit_unit", cpu_quota = "50%", memory_high = "1GiB" },
                { do = "sysctl", key = "net.netfilter.nf_conntrack_max", value = "524288" },
            ]"#,
        )
        .unwrap();
        assert_eq!(h.a[0], ActionSpec::Snapshot);
        assert_eq!(h.a[1], ActionSpec::Kill { tree: false, grace: None });
        assert_eq!(h.a[2], ActionSpec::Kill { tree: true, grace: Some(Duration::from_secs(2)) });
        assert!(matches!(h.a[3], ActionSpec::JournalVacuum { max_size: Some(_), .. }));
        assert!(h.a[4].is_cleanup());
        assert!(
            matches!(&h.a[4], ActionSpec::DeleteOld { age_from: AgeFrom::Mtime, exclude, .. } if exclude.is_empty())
        );
        assert!(
            matches!(&h.a[5], ActionSpec::DeleteOld { age_from: AgeFrom::Newest, exclude, .. } if exclude.len() == 1)
        );
        assert_eq!(h.a[6], ActionSpec::Throttle { nice: 19, io_idle: true });
        assert!(matches!(h.a[7], ActionSpec::LimitUnit { memory_high: Some(_), .. }));
        assert_eq!(h.a[8].name(), "sysctl");
    }

    #[test]
    fn cooldown_key_tells_playbook_steps_apart() {
        let step = |paths: &[&str], days: u64| ActionSpec::DeleteOld {
            paths: paths.iter().map(|s| s.to_string()).collect(),
            older_than: Duration::from_secs(days * 86400),
            max_files: None,
            age_from: AgeFrom::Mtime,
            exclude: vec![],
        };
        let logs = step(&["/var/log/**/*.gz"], 7);
        let tmp = step(&["/tmp/**", "/var/tmp/**"], 2);
        assert_ne!(logs.cooldown_key(), tmp.cooldown_key());
        // the new fields at their defaults do not change the key of an existing step
        assert!(!logs.cooldown_key().contains("age_from") && !logs.cooldown_key().contains("exclude"));
        assert_eq!(logs.cooldown_key(), step(&["/var/log/**/*.gz"], 7).cooldown_key());
        assert_ne!(ActionSpec::Stop.cooldown_key(), ActionSpec::Snapshot.cooldown_key());
        assert_ne!(
            ActionSpec::RestartUnit { unit: Some("a.service".into()) }.cooldown_key(),
            ActionSpec::RestartUnit { unit: Some("b.service".into()) }.cooldown_key()
        );
    }

    #[test]
    fn rejects_unknown_action_and_missing_fields() {
        assert!(toml::from_str::<Holder>(r#"a = ["explode"]"#).is_err());
        assert!(toml::from_str::<Holder>(r#"a = ["delete_old"]"#).is_err());
        assert!(toml::from_str::<Holder>(r#"a = [{ do = "kill", bogus = 1 }]"#).is_err());
    }
}
