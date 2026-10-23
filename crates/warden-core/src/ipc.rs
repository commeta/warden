//! Control protocol between `wardenctl` and `wardend`: one JSON object per
//! line over a root-only Unix socket (peer credentials are verified).

use crate::event::Severity;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    Ping,
    Status,
    Events {
        #[serde(default = "default_limit")]
        limit: usize,
        #[serde(default)]
        since_id: Option<u64>,
        #[serde(default)]
        min_severity: Option<Severity>,
    },
    Reload,
    /// `enabled`: the runtime override (kept across reloads and restarts);
    /// absent: drop the override, back to the configuration.
    SetDryRun {
        #[serde(default)]
        enabled: Option<bool>,
    },
    /// Memory culprit ranking as Warden sees it right now.
    Top {
        #[serde(default = "default_top")]
        limit: usize,
    },
    /// Heuristic suspicion scores.
    Scores,
    FimStatus,
    FimScan {
        #[serde(default)]
        site: Option<String>,
    },
    /// Accept the current state of a site (or one file) into the baseline.
    FimAccept {
        site: String,
        #[serde(default)]
        path: Option<String>,
    },
    /// Treat changes as trusted for a while (deployments).
    FimPause {
        site: String,
        seconds: u64,
    },
    Blocklist,
    Block {
        ip: String,
        #[serde(default)]
        ttl_secs: Option<u64>,
    },
    Unblock {
        ip: String,
    },
    QuarantineList,
    QuarantineRestore {
        id: String,
    },
    Snapshot {
        #[serde(default)]
        reason: Option<String>,
    },
    /// Tuning recommendations and sysctl changes Warden applied.
    Tuning,
    /// Restore every sysctl Warden changed to its original value.
    TuningRevert,
    /// Self-profile: CPU, I/O and memory per thread and per module.
    Profile,
}

fn default_limit() -> usize {
    50
}
fn default_top() -> usize {
    15
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default)]
    pub data: serde_json::Value,
}

impl Response {
    pub fn ok(data: impl Serialize) -> Self {
        Self { ok: true, error: None, data: serde_json::to_value(data).unwrap_or(serde_json::Value::Null) }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self { ok: false, error: Some(msg.into()), data: serde_json::Value::Null }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wire_format() {
        let r: Request = serde_json::from_str(r#"{"cmd":"events","limit":5}"#).unwrap();
        assert!(matches!(r, Request::Events { limit: 5, .. }));
        let s = serde_json::to_string(&Request::FimPause { site: "main".into(), seconds: 60 }).unwrap();
        assert_eq!(s, r#"{"cmd":"fim_pause","site":"main","seconds":60}"#);
    }
}
