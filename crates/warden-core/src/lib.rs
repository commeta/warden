//! # warden-core
//!
//! Platform-independent building blocks of the Warden host guardian:
//! configuration ([`config`]), the event model ([`event`]), remediation
//! templates ([`action`]), operator policy ([`policy`]), hysteresis
//! ([`sustain`]), the lifecycle of reported conditions ([`condition`]), rate limiting ([`ratelimit`]), locking ([`sync`]) and the
//! control protocol ([`ipc`]).
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod action;
pub mod condition;
pub mod config;
pub mod event;
pub mod glob;
pub mod ipc;
pub mod load;
pub mod net;
pub mod policy;
pub mod protect;
pub mod ratelimit;
pub mod redact;
pub mod sustain;
pub mod sync;
pub mod tuning;
pub mod units;

pub use action::ActionSpec;
pub use config::Config;
pub use event::{Event, ProcessRef, Severity, Subject};
pub use glob::GlobList;
pub use sustain::{Level, LevelTracker, Transition};
pub use units::ByteSize;

/// Default configuration path.
pub const DEFAULT_CONFIG: &str = "/etc/warden/warden.toml";
/// Version string embedded in notifications and `/metrics`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
