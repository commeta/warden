//! The dry-run switch.
//!
//! Three things decide whether destructive actions run:
//!
//! * `daemon.dry_run` in the configuration — the baseline;
//! * `wardend --dry-run` — forces dry-run for the life of the process;
//! * `wardenctl dry-run on|off` — a **runtime override**. 0.13.3 kept it in
//!   memory only: the next `SIGHUP` (logrotate, a CMS deploy hook, an
//!   unrelated config edit) or restart silently put the configuration's
//!   value back — usually `true`, so an operator who had switched protection
//!   on found it off again without any event. The override is now stored in
//!   the state directory and survives reloads and restarts, until
//!   `wardenctl dry-run reset` or until the operator changes `daemon.dry_run`
//!   in the configuration (a deliberate edit wins over an older override).
//!
//! Every change of the effective mode, whatever caused it, is reported as a
//! `warden.dry_run` event that says what decided it.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The file in the state directory that holds the override.
pub const FILE: &str = "dry-run.json";

/// What decided the current mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Config,
    /// `wardend --dry-run`.
    Cli,
    /// `wardenctl dry-run on|off`.
    Override,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Config => "config",
            Source::Cli => "cli",
            Source::Override => "override",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Saved {
    enabled: bool,
    /// `daemon.dry_run` when the override was set: if the configuration
    /// says something else later, it was edited since, and it wins.
    config_value: bool,
    set_ms: u64,
}

/// A change of the effective mode, to be reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub enabled: bool,
    pub source: Source,
    pub reason: String,
}

#[derive(Debug)]
pub struct DryRun {
    path: PathBuf,
    cli: bool,
    config_value: bool,
    saved: Option<Saved>,
}

impl DryRun {
    /// The switch at startup. Returns a note when the stored override was
    /// dropped (the configuration changed since) or is in effect.
    pub fn load(state_dir: &Path, config_value: bool, cli: bool) -> (Self, Option<Change>) {
        let path = state_dir.join(FILE);
        let saved: Option<Saved> = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok());
        let mut d = Self { path, cli, config_value, saved };
        let note = match saved {
            Some(s) if s.config_value != config_value => {
                d.forget();
                Some(Change {
                    enabled: d.effective(),
                    source: d.source(),
                    reason: format!(
                        "daemon.dry_run was changed in the configuration since `wardenctl dry-run {}` ({}); \
                         the configuration wins and the override was dropped",
                        on_off(s.enabled),
                        ago(s.set_ms)
                    ),
                })
            }
            Some(s) if s.enabled != config_value => Some(Change {
                enabled: d.effective(),
                source: d.source(),
                reason: format!(
                    "runtime override `wardenctl dry-run {}` ({}) is in effect; the configuration says dry_run = {config_value} \
                     (`wardenctl dry-run reset` returns to it)",
                    on_off(s.enabled),
                    ago(s.set_ms)
                ),
            }),
            _ => None,
        };
        (d, note)
    }

    pub fn effective(&self) -> bool {
        self.cli || self.saved.map_or(self.config_value, |s| s.enabled)
    }

    pub fn source(&self) -> Source {
        if self.cli {
            Source::Cli
        } else if self.saved.is_some() {
            Source::Override
        } else {
            Source::Config
        }
    }

    /// When the override was set (ms since the epoch).
    pub fn override_since_ms(&self) -> Option<u64> {
        self.saved.map(|s| s.set_ms)
    }

    /// `wardenctl dry-run on|off`. The override is persisted; an error is
    /// returned if it cannot be (then it lasts until the next reload, as
    /// before, and the caller says so).
    pub fn set(&mut self, enabled: bool, now_ms: u64) -> Result<Option<Change>, String> {
        if self.cli && !enabled {
            return Err("wardend was started with --dry-run; restart it without the flag to act".into());
        }
        let was = self.effective();
        let s = Saved { enabled, config_value: self.config_value, set_ms: now_ms };
        self.saved = Some(s);
        let stored = serde_json::to_vec_pretty(&s)
            .map_err(|e| e.to_string())
            .and_then(|b| warden_sys::util::write_atomic(&self.path, &b).map_err(|e| e.to_string()));
        let change = (self.effective() != was).then(|| Change {
            enabled: self.effective(),
            source: self.source(),
            reason: "wardenctl dry-run".into(),
        });
        match stored {
            Ok(()) => Ok(change),
            Err(e) => Err(format!(
                "dry-run {} for now, but the override could not be saved to {} ({e}): a reload or restart will return to the configuration",
                on_off(enabled),
                self.path.display()
            )),
        }
    }

    /// `wardenctl dry-run reset`: back to the configuration.
    pub fn reset(&mut self) -> Option<Change> {
        let was = self.effective();
        self.forget();
        (self.effective() != was).then(|| Change {
            enabled: self.effective(),
            source: self.source(),
            reason: "wardenctl dry-run reset: back to the configuration".into(),
        })
    }

    /// A configuration was (re)loaded. The override is kept unless the
    /// configuration's own value changed.
    pub fn reload(&mut self, config_value: bool) -> Option<Change> {
        let was = self.effective();
        let old = std::mem::replace(&mut self.config_value, config_value);
        let mut reason = format!("configuration reloaded: dry_run = {config_value}");
        if let Some(s) = self.saved
            && s.config_value != config_value
        {
            self.forget();
            reason = format!(
                "daemon.dry_run was changed in the configuration ({old} → {config_value}); \
                 the runtime override `wardenctl dry-run {}` ({}) was dropped",
                on_off(s.enabled),
                ago(s.set_ms)
            );
        }
        (self.effective() != was).then(|| Change { enabled: self.effective(), source: self.source(), reason })
    }

    fn forget(&mut self) {
        self.saved = None;
        match std::fs::remove_file(&self.path) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                tracing::warn!(path = %self.path.display(), error = %e, "cannot remove the dry-run override");
            }
            _ => {}
        }
    }
}

/// The `warden.dry_run` event for a change of the effective mode.
pub fn event(c: &Change) -> warden_core::Event {
    warden_core::Event::new(
        "warden.dry_run",
        warden_core::Severity::Notice,
        format!("dry-run {} ({})", if c.enabled { "enabled" } else { "disabled" }, c.reason),
    )
    .source("daemon")
    .detail("enabled", c.enabled)
    .detail("source", c.source.as_str())
    .detail("reason", c.reason.clone())
    .fingerprint(format!("warden.dry_run:{}:{}", c.enabled, c.source.as_str()))
}

fn on_off(b: bool) -> &'static str {
    if b { "on" } else { "off" }
}

fn ago(ms: u64) -> String {
    let secs = warden_core::event::now_ms().saturating_sub(ms) / 1000;
    format!("{} ago", warden_core::units::human_duration(std::time::Duration::from_secs(secs)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_survives_reload_and_restart() {
        let d = tempfile::tempdir().unwrap();
        // config says dry_run = true (the default); the operator switches protection on
        let (mut dr, note) = DryRun::load(d.path(), true, false);
        assert!(note.is_none());
        assert!(dr.effective());
        let c = dr.set(false, 1).unwrap().unwrap();
        assert!(!c.enabled);
        assert_eq!(c.source, Source::Override);
        // a reload with the same configuration (logrotate's SIGHUP) keeps it
        assert_eq!(dr.reload(true), None);
        assert!(!dr.effective());
        // so does a restart
        let (dr2, note) = DryRun::load(d.path(), true, false);
        assert!(!dr2.effective());
        assert_eq!(dr2.source(), Source::Override);
        assert!(note.unwrap().reason.contains("is in effect"));
        // setting the same value again is not a change
        let (mut dr3, _) = DryRun::load(d.path(), true, false);
        assert_eq!(dr3.set(false, 2).unwrap(), None);
    }

    #[test]
    fn an_edit_of_the_configuration_wins_over_an_older_override() {
        let d = tempfile::tempdir().unwrap();
        let (mut dr, _) = DryRun::load(d.path(), true, false);
        dr.set(false, 1).unwrap();
        // the operator then sets dry_run = false in the file and reloads: no
        // change of mode, but the override is gone
        assert_eq!(dr.reload(false), None);
        assert_eq!(dr.source(), Source::Config);
        assert!(!d.path().join(FILE).exists());
        // later dry_run = true in the file: the configuration decides
        let c = dr.reload(true).unwrap();
        assert!(c.enabled);
        assert_eq!(c.source, Source::Config);
        // an override whose configuration changed while the daemon was down
        dr.set(false, 1).unwrap();
        let (dr2, note) = DryRun::load(d.path(), false, false);
        assert_eq!(dr2.source(), Source::Config);
        assert!(note.unwrap().reason.contains("dropped"));
    }

    #[test]
    fn reset_and_cli() {
        let d = tempfile::tempdir().unwrap();
        let (mut dr, _) = DryRun::load(d.path(), true, false);
        dr.set(false, 1).unwrap();
        let c = dr.reset().unwrap();
        assert!(c.enabled);
        assert_eq!(dr.source(), Source::Config);
        assert!(!d.path().join(FILE).exists());
        // --dry-run cannot be switched off from the socket, and beats an override
        dr.set(false, 1).unwrap();
        let (mut cli, _) = DryRun::load(d.path(), false, true);
        assert!(cli.effective());
        assert_eq!(cli.source(), Source::Cli);
        assert!(cli.set(false, 2).is_err());
    }

    #[test]
    fn an_unwritable_state_dir_is_reported() {
        let (mut dr, _) = DryRun::load(Path::new("/proc/warden-no-such-dir"), true, false);
        let e = dr.set(false, 1).unwrap_err();
        assert!(e.contains("could not be saved"), "{e}");
        assert!(!dr.effective(), "the mode still changes for now");
    }
}
