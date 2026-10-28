//! Configuration model. Every section has production-sane defaults so an
//! empty file is a valid configuration; `deny_unknown_fields` turns typos into
//! startup errors instead of silently ignored settings.

use crate::action::{ActionSpec, AgeFrom, de_actions};
use crate::event::Severity;
use crate::policy::PolicyRule;
use crate::units::ByteSize;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}
fn ms(v: u64) -> Duration {
    Duration::from_millis(v)
}
fn strings(v: &[&str]) -> Vec<String> {
    v.iter().map(|s| (*s).to_owned()).collect()
}
fn kill() -> ActionSpec {
    ActionSpec::Kill { tree: false, grace: None }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub daemon: DaemonConfig,
    pub metrics: MetricsConfig,
    pub events: EventLogConfig,
    pub notify: NotifyConfig,
    pub protection: ProtectionConfig,
    pub actions: ActionsConfig,
    pub memory: MemoryConfig,
    pub cpu: CpuConfig,
    pub io: IoConfig,
    pub stall: StallConfig,
    pub disk: DiskConfig,
    pub limits: LimitsConfig,
    pub network: NetworkConfig,
    pub systemd: SystemdConfig,
    pub hardware: HardwareConfig,
    pub kernel: KernelConfig,
    pub process: ProcessConfig,
    pub integrity: IntegrityConfig,
    pub auth: AuthConfig,
    pub fim: FimConfig,
    pub waf: WafConfig,
    pub health: HealthConfig,
    pub tuning: TuningConfig,
    pub heuristics: HeuristicsConfig,
    #[serde(rename = "policy")]
    pub policies: Vec<PolicyRule>,
}

// ---------------------------------------------------------------------------
// daemon / output
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    /// `journal` when started by systemd, `text` otherwise.
    #[default]
    Auto,
    Text,
    Json,
    /// Text without timestamps (journald adds its own).
    Journal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DaemonConfig {
    /// Base resolution of the polling scheduler.
    #[serde(with = "humantime_serde")]
    pub tick: Duration,
    /// Detect and report everything but do not execute destructive actions.
    /// On by default: a fresh install observes first; remediation is switched
    /// on deliberately (`dry_run = false`, or `wardenctl dry-run off`).
    pub dry_run: bool,
    pub state_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub control_socket: PathBuf,
    pub log_level: String,
    pub log_format: LogFormat,
    /// `mlockall(MCL_CURRENT|MCL_FUTURE|MCL_ONFAULT)`: the guard must never be
    /// swapped out while the host is thrashing.
    pub mlock: bool,
    /// Our own `oom_score_adj` (systemd unit sets it too).
    pub oom_score_adj: i32,
    /// glibc malloc arenas (0 = glibc default: 8 per CPU core). Each thread
    /// that allocates may otherwise get its own arena, and memory freed after
    /// a scan stays resident (and mlocked) in it.
    pub malloc_arenas: u32,
    /// Hostname used in notifications (defaults to the kernel hostname).
    pub hostname: Option<String>,
    /// The account that the programs you configure run as — `exec` actions,
    /// notification commands, command health checks — unless one sets its
    /// own `user`. A name or a UID; unset = root, with the daemon's
    /// capabilities (as before 0.14.1). An unprivileged user loses every
    /// capability on the switch.
    pub command_user: Option<String>,
    /// `[daemon.pacing]`: background scans yield to the workload.
    pub pacing: PacingConfig,
}

/// Adaptive pacing of background scans (the disk-usage walk, the SUID/SGID
/// walk, scheduled FIM scans) by I/O pressure — see `docs/performance.md`.
/// Scans started by the operator and cleanup actions are never paced.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PacingConfig {
    pub enabled: bool,
    /// I/O pressure (PSI `some`: % of time some task waited for I/O) the
    /// workload may see before a scan slows down (down to its floor: it
    /// always finishes) and a scheduled scan is postponed.
    pub io_pressure: f64,
    /// `adaptive`: the idle I/O class while the disk is busy, best-effort 7
    /// while it is quiet; `idle`: always the idle class.
    pub io_class: PacingIoClass,
    /// Longest a scheduled scan waits for a quiet disk before it runs anyway
    /// (paced).
    #[serde(with = "humantime_serde")]
    pub max_defer: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PacingIoClass {
    Adaptive,
    Idle,
}

impl Default for PacingConfig {
    fn default() -> Self {
        Self { enabled: true, io_pressure: 10.0, io_class: PacingIoClass::Adaptive, max_defer: secs(3600) }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            tick: secs(1),
            dry_run: true,
            state_dir: "/var/lib/warden".into(),
            runtime_dir: "/run/warden".into(),
            control_socket: "/run/warden/control.sock".into(),
            log_level: "info".into(),
            log_format: LogFormat::Auto,
            mlock: true,
            oom_score_adj: -900,
            malloc_arenas: 2,
            hostname: None,
            command_user: None,
            pacing: PacingConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    pub enabled: bool,
    /// Prometheus endpoint (`/metrics`, `/health`). Keep it on loopback.
    pub listen: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self { enabled: true, listen: "127.0.0.1:9184".into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EventLogConfig {
    /// JSON-lines journal of every event and action result.
    pub path: PathBuf,
    pub max_size: ByteSize,
    pub keep: usize,
    pub min_severity: Severity,
    /// Events kept in memory for `wardenctl events`.
    pub ring_size: usize,
    /// Do not record the same fingerprint more often than this.
    #[serde(with = "humantime_serde")]
    pub dedup_window: Duration,
    /// Informational events of one kind recorded per minute at most. A
    /// flood (`waf.hit` from thousands of addresses) otherwise fills the
    /// journal — 64 MB a minute in the 0.14.2 review — and rotation erases
    /// the history of real incidents (N33). The rest are counted
    /// (`warden_journal_suppressed_total{kind}`) and summed up once a minute
    /// in a `warden.journal_suppressed` event. Resolutions, action results
    /// and `warden.*` events are never held back. 0 = no limit.
    pub max_info_per_minute: usize,
}

impl Default for EventLogConfig {
    fn default() -> Self {
        Self {
            path: "/var/log/warden/events.jsonl".into(),
            max_size: ByteSize::mib(50),
            keep: 5,
            min_severity: Severity::Info,
            ring_size: 2000,
            dedup_window: secs(60),
            max_info_per_minute: 600,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum WebhookFormat {
    /// The full event as JSON.
    #[default]
    Json,
    /// `{"text": "..."}` — Slack, Mattermost, Rocket.Chat, Discord (/slack).
    Slack,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub format: WebhookFormat,
    #[serde(default)]
    pub min_severity: Option<Severity>,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default = "default_notify_timeout", with = "humantime_serde")]
    pub timeout: Duration,
}

fn default_notify_timeout() -> Duration {
    secs(10)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TelegramConfig {
    pub bot_token: String,
    pub chat_id: String,
    #[serde(default)]
    pub min_severity: Option<Severity>,
    #[serde(default = "default_tg_api")]
    pub api_url: String,
}

fn default_tg_api() -> String {
    "https://api.telegram.org".into()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandNotifierConfig {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub min_severity: Option<Severity>,
    /// Account to run as; default `daemon.command_user`.
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default = "default_notify_timeout", with = "humantime_serde")]
    pub timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NotifyConfig {
    pub min_severity: Severity,
    /// Identical notifications (same fingerprint) are suppressed for this long.
    #[serde(with = "humantime_serde")]
    pub dedup_window: Duration,
    pub max_per_hour: usize,
    /// Also notify when a condition clears.
    pub include_resolved: bool,
    /// What of an event's detail leaves the host: `safe` (default) masks
    /// secrets — passwords in command lines, `KEY=value` credentials in
    /// diffs and journal lines, tokens, `Authorization` headers; `none`
    /// sends kind, severity, title, subject and actions only; `all` sends
    /// everything as recorded. The journal always keeps the original.
    pub details: crate::redact::Details,
    pub webhook: Vec<WebhookConfig>,
    pub telegram: Option<TelegramConfig>,
    pub command: Vec<CommandNotifierConfig>,
}

impl Default for NotifyConfig {
    fn default() -> Self {
        Self {
            min_severity: Severity::Warning,
            dedup_window: secs(15 * 60),
            max_per_hour: 60,
            include_resolved: true,
            details: crate::redact::Details::Safe,
            webhook: Vec::new(),
            telegram: None,
            command: Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// safety
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProtectionConfig {
    /// Never signal/stop processes whose `comm` matches (glob).
    pub comm: Vec<String>,
    /// Never touch processes whose executable path matches (glob).
    pub exe: Vec<String>,
    /// Never touch processes living in these systemd units (glob on the
    /// last cgroup path component).
    pub units: Vec<String>,
    /// Never touch processes owned by these UIDs.
    pub uids: Vec<u32>,
}

impl Default for ProtectionConfig {
    fn default() -> Self {
        Self {
            comm: strings(&[
                "systemd",
                "systemd-*",
                "(sd-pam)",
                "init",
                "sshd",
                "sshd-session",
                "sshd-auth",
                "wardend",
                "dbus-daemon",
                "dbus-broker*",
                "agetty",
                "login",
                "auditd",
                "rsyslogd",
                "chronyd",
                "multipathd",
                "kubelet",
                "containerd",
                "dockerd",
            ]),
            exe: strings(&["/usr/lib/systemd/*", "/lib/systemd/*", "/usr/sbin/sshd"]),
            units: strings(&[
                "init.scope",
                "ssh.service",
                "sshd.service",
                "wardend.service",
                "dbus.service",
                "systemd-*.service",
                "getty@*.service",
                "serial-getty@*.service",
            ]),
            uids: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FirewallConfig {
    pub enabled: bool,
    /// nftables table (family `inet`) managed by Warden.
    pub table: String,
    pub set_v4: String,
    pub set_v6: String,
    #[serde(with = "humantime_serde")]
    pub default_ttl: Duration,
    /// Never block these networks (CIDR).
    pub allowlist: Vec<String>,
    pub max_blocked: usize,
    /// IPv6 addresses are counted and blocked by the network of this many
    /// bits that holds them (48..=128): a /64 is one subscriber, and an
    /// attacker with one rotates through it at will (N25). 128 = per
    /// address, as before 0.14.3. IPv4 is always per address.
    pub ipv6_prefix: u8,
    /// Addresses blocked per hour. Blocks have a budget of their own: an
    /// attacker rotating through an IPv6 prefix must not use up the budget
    /// of the actions that contain a compromise (`max_actions_per_hour`).
    pub max_blocks_per_hour: usize,
    /// Never block an address that has an established SSH session to this
    /// host, unless the evidence is about SSH itself and comes from the
    /// journal: a forged web log line must not lock the administrator out.
    pub protect_ssh_sessions: bool,
    /// SSH ports for `protect_ssh_sessions`; empty = the `Port` and
    /// `ListenAddress` lines of `/etc/ssh/sshd_config` (and its
    /// `sshd_config.d`), or 22.
    pub ssh_ports: Vec<u16>,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            table: "warden".into(),
            set_v4: "blocklist4".into(),
            set_v6: "blocklist6".into(),
            default_ttl: secs(3600),
            allowlist: strings(&["127.0.0.0/8", "::1/128"]),
            max_blocked: 50_000,
            ipv6_prefix: crate::net::DEFAULT_IPV6_PREFIX,
            max_blocks_per_hour: 10_000,
            protect_ssh_sessions: true,
            ssh_ports: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ActionsConfig {
    /// Time between SIGTERM and SIGKILL.
    #[serde(with = "humantime_serde")]
    pub kill_grace: Duration,
    /// Global circuit breaker for process kills.
    pub max_kills_per_hour: usize,
    /// Global circuit breaker for destructive actions other than `block_ip`
    /// (which has `firewall.max_blocks_per_hour`).
    pub max_actions_per_hour: usize,
    /// Of `max_actions_per_hour`, the last ones are kept for containment
    /// (`kill`, `kill_cgroup`, `freeze_cgroup`, `stop`, `quarantine`,
    /// `throttle`): hooks, restarts and cleanups cannot use them up. At
    /// most a quarter of `max_actions_per_hour`.
    pub containment_reserve: usize,
    /// The same action on the same subject is not repeated within this period.
    #[serde(with = "humantime_serde")]
    pub cooldown: Duration,
    pub quarantine_dir: PathBuf,
    pub snapshot_dir: PathBuf,
    pub snapshot_keep: usize,
    #[serde(with = "humantime_serde")]
    pub snapshot_min_interval: Duration,
    #[serde(with = "humantime_serde")]
    pub exec_timeout: Duration,
    pub firewall: FirewallConfig,
}

impl Default for ActionsConfig {
    fn default() -> Self {
        Self {
            kill_grace: secs(5),
            max_kills_per_hour: 10,
            max_actions_per_hour: 120,
            containment_reserve: 20,
            cooldown: secs(60),
            quarantine_dir: "/var/lib/warden/quarantine".into(),
            snapshot_dir: "/var/lib/warden/snapshots".into(),
            snapshot_keep: 30,
            snapshot_min_interval: secs(120),
            exec_timeout: secs(30),
            firewall: FirewallConfig::default(),
        }
    }
}

// ---------------------------------------------------------------------------
// resource pressure
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PsiKind {
    #[default]
    Some,
    Full,
}

impl PsiKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PsiKind::Some => "some",
            PsiKind::Full => "full",
        }
    }
}

/// Kernel PSI trigger (`echo "some 150000 1000000" > /proc/pressure/memory`):
/// the kernel wakes us up the moment the stall budget is exceeded instead of
/// waiting for the next poll.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PsiTriggerConfig {
    pub enabled: bool,
    pub kind: PsiKind,
    #[serde(with = "humantime_serde")]
    pub stall: Duration,
    #[serde(with = "humantime_serde")]
    pub window: Duration,
}

impl Default for PsiTriggerConfig {
    fn default() -> Self {
        Self { enabled: true, kind: PsiKind::Some, stall: ms(150), window: secs(1) }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SwapStormConfig {
    pub enabled: bool,
    /// pswpin + pswpout pages per second.
    pub min_swap_pages_per_sec: f64,
    /// Major page faults per second (file-backed thrashing counts too).
    pub min_majfault_per_sec: f64,
    /// PSI memory `full` avg10 that must accompany the paging storm.
    pub psi_full_avg10: f64,
    /// How long the storm must last before acting ("долгий своппинг").
    #[serde(with = "humantime_serde")]
    pub sustain: Duration,
    #[serde(deserialize_with = "de_actions")]
    pub actions: Vec<ActionSpec>,
}

impl Default for SwapStormConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            min_swap_pages_per_sec: 2000.0,
            min_majfault_per_sec: 1000.0,
            psi_full_avg10: 10.0,
            sustain: secs(60),
            actions: vec![ActionSpec::Snapshot, kill()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CulpritConfig {
    /// Ignore processes smaller than this.
    pub min_rss: ByteSize,
    /// `comm` globs that are preferred victims (score × prefer_factor).
    pub prefer: Vec<String>,
    pub prefer_factor: f64,
    /// `comm` globs that are avoided (score × avoid_factor).
    pub avoid: Vec<String>,
    pub avoid_factor: f64,
    /// Respect `oom_score_adj` like the kernel OOM killer.
    pub use_oom_score_adj: bool,
}

impl Default for CulpritConfig {
    fn default() -> Self {
        Self {
            min_rss: ByteSize::mib(32),
            prefer: strings(&["php-fpm*", "php", "node", "java", "python*", "ruby", "chrome*", "firefox*", "electron"]),
            prefer_factor: 1.5,
            avoid: strings(&["postgres", "mysqld", "mariadbd", "redis-server", "Xorg", "gnome-shell", "kwin*"]),
            avoid_factor: 0.2,
            use_oom_score_adj: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MemoryConfig {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    pub psi_some_avg10_warning: f64,
    pub psi_full_avg10_warning: f64,
    pub psi_full_avg10_critical: f64,
    /// Scale the "available memory" thresholds with the machine: the
    /// percentages below are clamped to sane absolute bounds, so 8% means
    /// ~80MiB on a 1GiB VPS (raised to a floor) and not 40GiB on a 512GiB host
    /// (capped). Inside a container the cgroup memory limit is used instead
    /// of the host's MemTotal.
    pub auto_scale: bool,
    /// MemAvailable as a percentage of MemTotal.
    pub available_warning_percent: f64,
    pub available_critical_percent: f64,
    pub swap_used_warning_percent: f64,
    /// How long a critical condition must hold before acting.
    #[serde(with = "humantime_serde")]
    pub sustain: Duration,
    /// How long the condition must be absent before declaring recovery.
    #[serde(with = "humantime_serde")]
    pub clear_after: Duration,
    /// While still critical, re-evaluate (and act on the next culprit) after.
    #[serde(with = "humantime_serde")]
    pub repeat: Duration,
    /// Kills that freed memory, per pressure episode (and per swap storm),
    /// after which further kills are withheld until the episode ends; 0 =
    /// no limit. Independently, a kill that did not raise MemAvailable by
    /// at least half of what the victim held (its anonymous memory and swap)
    /// stops kills for the rest of the episode: the memory is held by
    /// something killing processes does not release (tmpfs, shared memory,
    /// kernel slab), and every further kill would only take down a service.
    pub max_kills_per_episode: u32,
    /// Run the process actions of `on_warning`/`on_critical` (kill, stop,
    /// freeze, throttle) when only PSI is high and MemAvailable is above
    /// the warning threshold. Off: memory is not short then — tasks stall
    /// paging in from a slow disk or swap — and a kill frees nothing that
    /// helps (the 0.14.1 lab killed a compiler with 69 % of RAM free).
    /// Snapshots and hooks still run.
    pub act_on_psi_alone: bool,
    pub trigger: PsiTriggerConfig,
    pub swap_storm: SwapStormConfig,
    pub culprit: CulpritConfig,
    /// Report kernel OOM kills (`oom_kill` in /proc/vmstat).
    pub report_oom_kills: bool,
    #[serde(deserialize_with = "de_actions")]
    pub on_warning: Vec<ActionSpec>,
    #[serde(deserialize_with = "de_actions")]
    pub on_critical: Vec<ActionSpec>,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: secs(2),
            auto_scale: true,
            psi_some_avg10_warning: 30.0,
            psi_full_avg10_warning: 10.0,
            psi_full_avg10_critical: 30.0,
            available_warning_percent: 8.0,
            available_critical_percent: 3.0,
            swap_used_warning_percent: 85.0,
            sustain: secs(20),
            clear_after: secs(60),
            repeat: secs(30),
            max_kills_per_episode: 3,
            act_on_psi_alone: false,
            trigger: PsiTriggerConfig::default(),
            swap_storm: SwapStormConfig::default(),
            culprit: CulpritConfig::default(),
            report_oom_kills: true,
            on_warning: vec![],
            on_critical: vec![ActionSpec::Snapshot, kill()],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CpuConfig {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    pub psi_some_avg60_warning: f64,
    pub psi_some_avg60_critical: f64,
    /// 5-minute load average divided by the number of CPUs.
    pub load_per_cpu_warning: f64,
    pub load_per_cpu_critical: f64,
    pub iowait_warning_percent: f64,
    /// Tasks in uninterruptible sleep (D state) — storage/NFS hangs.
    pub blocked_tasks_warning: u64,
    /// Process creations per second (fork bombs).
    pub fork_rate_warning: f64,
    /// A single process burning ≥ this % of one core for `hog_duration`.
    pub hog_percent: f64,
    #[serde(with = "humantime_serde")]
    pub hog_duration: Duration,
    /// `comm` globs that are allowed to burn CPU.
    pub hog_ignore: Vec<String>,
    #[serde(with = "humantime_serde")]
    pub sustain: Duration,
    #[serde(with = "humantime_serde")]
    pub clear_after: Duration,
    #[serde(deserialize_with = "de_actions")]
    pub on_critical: Vec<ActionSpec>,
}

impl Default for CpuConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: secs(5),
            psi_some_avg60_warning: 60.0,
            psi_some_avg60_critical: 90.0,
            load_per_cpu_warning: 2.0,
            load_per_cpu_critical: 4.0,
            iowait_warning_percent: 40.0,
            blocked_tasks_warning: 16,
            fork_rate_warning: 1500.0,
            hog_percent: 95.0,
            hog_duration: secs(30 * 60),
            hog_ignore: strings(&[
                "ffmpeg",
                "x264",
                "x265",
                "gcc",
                "cc1*",
                "rustc",
                "cargo",
                "clang*",
                "ld*",
                "make",
                "ninja",
                "java",
                "node",
                "python*",
                "postgres",
                "mysqld",
                "mariadbd",
                "clickhouse*",
            ]),
            sustain: secs(120),
            clear_after: secs(120),
            on_critical: vec![ActionSpec::Snapshot],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IoConfig {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    pub psi_full_avg10_warning: f64,
    pub psi_full_avg10_critical: f64,
    #[serde(with = "humantime_serde")]
    pub sustain: Duration,
    #[serde(with = "humantime_serde")]
    pub clear_after: Duration,
    #[serde(deserialize_with = "de_actions")]
    pub on_critical: Vec<ActionSpec>,
}

impl Default for IoConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: secs(5),
            psi_full_avg10_warning: 25.0,
            psi_full_avg10_critical: 60.0,
            sustain: secs(60),
            clear_after: secs(120),
            on_critical: vec![ActionSpec::Snapshot],
        }
    }
}

/// Detects whole-host freezes by measuring how late our own (mlocked,
/// high-priority) scheduler wakes up.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StallConfig {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub threshold: Duration,
    #[serde(with = "humantime_serde")]
    pub critical: Duration,
    #[serde(deserialize_with = "de_actions")]
    pub actions: Vec<ActionSpec>,
}

impl Default for StallConfig {
    fn default() -> Self {
        Self { enabled: true, threshold: secs(5), critical: secs(30), actions: vec![ActionSpec::Snapshot] }
    }
}

// ---------------------------------------------------------------------------
// disks
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DiskConfig {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    pub warning_percent: f64,
    pub critical_percent: f64,
    pub inode_warning_percent: f64,
    pub inode_critical_percent: f64,
    pub fstypes: Vec<String>,
    /// Mount points to ignore (glob).
    pub exclude: Vec<String>,
    /// Predictive alert: warn when the mount will be full within `horizon`
    /// at the current growth rate (linear regression over `window`).
    pub predict: bool,
    #[serde(with = "humantime_serde")]
    pub horizon: Duration,
    #[serde(with = "humantime_serde")]
    pub window: Duration,
    /// Alert when a filesystem that was read-write becomes read-only.
    pub detect_readonly: bool,
    /// Report deleted-but-open files bigger than this on full mounts.
    pub deleted_open_min: ByteSize,
    /// Run the cleanup playbook at this level ("warning" or "critical").
    pub cleanup_at: Severity,
    /// Stop running cleanup steps once usage is below this percentage (it
    /// must be below the level that starts the cleanup; 0 runs every step).
    pub cleanup_target_percent: f64,
    /// Ordered cleanup playbook.
    #[serde(deserialize_with = "de_actions")]
    pub cleanup: Vec<ActionSpec>,
    #[serde(with = "humantime_serde")]
    pub repeat: Duration,
    /// "Who is using the disk": a bounded `du -x` of the mount in the
    /// background when cleanup did not help (or there is nothing to run),
    /// reported as `disk.usage_report`.
    pub usage_report: bool,
    /// At most one report per mount per this period.
    #[serde(with = "humantime_serde")]
    pub usage_report_every: Duration,
    /// Walk budget: directory entries and wall time.
    pub usage_report_max_entries: u64,
    #[serde(with = "humantime_serde")]
    pub usage_report_max_time: Duration,
}

/// What `systemd-tmpfiles` never ages out of `/tmp` and `/var/tmp`: the
/// private temp directories of services (`PrivateTmp=`), snap's, X server
/// locks and socket directories, tmux sockets.
pub const TMP_CLEANUP_EXCLUDE: &[&str] = &[
    "/tmp/systemd-private-*",
    "/var/tmp/systemd-private-*",
    "/tmp/snap-private-tmp",
    "/tmp/.X*-lock",
    "/tmp/.X11-unix",
    "/tmp/.ICE-unix",
    "/tmp/.XIM-unix",
    "/tmp/.font-unix",
    "/tmp/.Test-unix",
    "/tmp/tmux-*",
];

impl Default for DiskConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: secs(30),
            warning_percent: 85.0,
            critical_percent: 95.0,
            inode_warning_percent: 85.0,
            inode_critical_percent: 95.0,
            fstypes: strings(&[
                "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "vfat", "reiserfs", "jfs", "bcachefs",
            ]),
            exclude: strings(&["/snap/*", "/boot/efi", "/var/lib/docker/*/merged"]),
            predict: true,
            horizon: secs(6 * 3600),
            window: secs(30 * 60),
            detect_readonly: true,
            deleted_open_min: ByteSize::mib(50),
            cleanup_at: Severity::Critical,
            cleanup_target_percent: 85.0,
            cleanup: vec![
                ActionSpec::JournalVacuum { max_size: Some(ByteSize::mib(512)), max_age: None },
                ActionSpec::AptClean,
                ActionSpec::DeleteOld {
                    paths: strings(&["/var/log/**/*.gz", "/var/log/**/*.[0-9]", "/var/log/**/*.old", "/var/crash/*"]),
                    older_than: secs(3 * 86400),
                    max_files: Some(5000),
                    age_from: AgeFrom::Mtime,
                    exclude: vec![],
                },
                ActionSpec::DeleteOld {
                    paths: strings(&["/tmp/**", "/var/tmp/**"]),
                    older_than: secs(10 * 86400),
                    max_files: Some(20000),
                    // the systemd-tmpfiles rules for /tmp (tmp.conf, x11.conf)
                    age_from: AgeFrom::Newest,
                    exclude: strings(TMP_CLEANUP_EXCLUDE),
                },
                ActionSpec::TruncateDeleted { min_size: ByteSize::mib(100) },
                ActionSpec::TruncateLarge {
                    paths: strings(&["/var/log/*.log", "/var/log/**/*.log"]),
                    larger_than: ByteSize::gib(2),
                },
            ],
            repeat: secs(15 * 60),
            usage_report: true,
            usage_report_every: secs(24 * 3600),
            usage_report_max_entries: 2_000_000,
            usage_report_max_time: secs(120),
        }
    }
}

// ---------------------------------------------------------------------------
// limits / network / systemd / hardware / kernel
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// System-wide file handles (`/proc/sys/fs/file-nr`).
    pub file_warning_percent: f64,
    pub file_critical_percent: f64,
    /// Tasks vs `kernel.pid_max` / `kernel.threads-max`.
    pub pid_warning_percent: f64,
    pub pid_critical_percent: f64,
    /// netfilter conntrack table fill.
    pub conntrack_warning_percent: f64,
    pub conntrack_critical_percent: f64,
    /// Per-process open files vs RLIMIT_NOFILE.
    pub process_fd_warning_percent: f64,
    /// Zombie processes (usually a broken parent).
    pub zombies_warning: u64,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: secs(15),
            file_warning_percent: 80.0,
            file_critical_percent: 95.0,
            pid_warning_percent: 75.0,
            pid_critical_percent: 90.0,
            conntrack_warning_percent: 80.0,
            conntrack_critical_percent: 95.0,
            process_fd_warning_percent: 90.0,
            zombies_warning: 50,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// Accept-queue overflows per second (`ListenOverflows`).
    pub listen_overflows_per_sec: f64,
    /// SYN cookies sent per second — SYN flood indicator.
    pub syncookies_per_sec: f64,
    /// RX/TX errors + drops per second per interface.
    pub iface_errors_per_sec: f64,
    /// TCP retransmitted segments as % of sent segments.
    pub tcp_retrans_percent: f64,
    /// Interfaces to ignore (glob).
    pub ignore_interfaces: Vec<String>,
    #[serde(with = "humantime_serde")]
    pub sustain: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: secs(10),
            listen_overflows_per_sec: 5.0,
            syncookies_per_sec: 50.0,
            iface_errors_per_sec: 10.0,
            tcp_retrans_percent: 10.0,
            ignore_interfaces: strings(&["lo", "veth*", "docker*", "br-*", "virbr*", "tun*", "tap*"]),
            sustain: secs(30),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SystemdConfig {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// Alert on failed units.
    pub watch_failed: bool,
    /// Units restarted automatically when they enter the failed state.
    pub auto_restart: Vec<String>,
    pub max_restarts_per_hour: usize,
    /// Failed units to ignore (glob).
    pub ignore: Vec<String>,
    /// Follow unit state changes over D-Bus (instant, no `systemctl`
    /// process every `interval`); polling remains the fallback.
    pub dbus: bool,
    /// Full re-read of failed units over D-Bus, in case a signal was missed.
    #[serde(with = "humantime_serde")]
    pub dbus_reconcile: Duration,
}

impl Default for SystemdConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: secs(30),
            watch_failed: true,
            auto_restart: vec![],
            max_restarts_per_hour: 3,
            ignore: vec![],
            dbus: true,
            dbus_reconcile: secs(600),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HardwareConfig {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// ECC memory errors via EDAC.
    pub edac: bool,
    pub thermal: bool,
    pub thermal_warning_c: f64,
    pub thermal_critical_c: f64,
    /// Clock synchronisation (adjtimex).
    pub clock: bool,
    /// Limit for the NTP daemon's estimated error (`esterror`).
    #[serde(with = "humantime_serde")]
    pub clock_max_error: Duration,
}

impl Default for HardwareConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: secs(60),
            edac: true,
            thermal: true,
            thermal_warning_c: 85.0,
            thermal_critical_c: 95.0,
            clock: true,
            clock_max_error: ms(500),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KmsgPattern {
    pub kind: String,
    pub regex: String,
    pub severity: Severity,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default, deserialize_with = "de_actions")]
    pub actions: Vec<ActionSpec>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct KernelConfig {
    pub enabled: bool,
    /// Follow `/dev/kmsg` (OOM, hung tasks, FS/IO errors, LSM denials...).
    pub kmsg: bool,
    /// Extra user patterns (evaluated after the built-in ones).
    pub patterns: Vec<KmsgPattern>,
    /// Segfaults per 5 minutes that raise an alert.
    pub segfault_burst: usize,
    /// AppArmor/SELinux denials per 5 minutes that raise an alert.
    pub lsm_denial_burst: usize,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// Kernel taint changes.
    pub taint: bool,
    /// New kernel modules.
    pub modules: bool,
    /// AppArmor / SELinux disabled or switched to permissive at runtime.
    pub lsm_state: bool,
    #[serde(deserialize_with = "de_actions")]
    pub on_oom_kill: Vec<ActionSpec>,
    #[serde(deserialize_with = "de_actions")]
    pub on_hung_task: Vec<ActionSpec>,
}

impl Default for KernelConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            kmsg: true,
            patterns: vec![],
            segfault_burst: 20,
            lsm_denial_burst: 50,
            interval: secs(60),
            taint: true,
            modules: true,
            lsm_state: true,
            on_oom_kill: vec![ActionSpec::Snapshot],
            on_hung_task: vec![ActionSpec::Snapshot],
        }
    }
}

// ---------------------------------------------------------------------------
// security
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildAllow {
    /// Parent `comm` glob.
    pub parent: String,
    /// Child executable path or `comm` glob.
    pub child: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProcessResponse {
    #[serde(deserialize_with = "de_actions")]
    pub privilege_escalation: Vec<ActionSpec>,
    #[serde(deserialize_with = "de_actions")]
    pub web_spawn: Vec<ActionSpec>,
    #[serde(deserialize_with = "de_actions")]
    pub exec_from_writable: Vec<ActionSpec>,
    #[serde(deserialize_with = "de_actions")]
    pub fileless: Vec<ActionSpec>,
    #[serde(deserialize_with = "de_actions")]
    pub reverse_shell: Vec<ActionSpec>,
    #[serde(deserialize_with = "de_actions")]
    pub miner: Vec<ActionSpec>,
    #[serde(deserialize_with = "de_actions")]
    pub masquerade: Vec<ActionSpec>,
    #[serde(deserialize_with = "de_actions")]
    pub ld_preload: Vec<ActionSpec>,
    #[serde(deserialize_with = "de_actions")]
    pub ptrace: Vec<ActionSpec>,
    #[serde(deserialize_with = "de_actions")]
    pub unknown_suid: Vec<ActionSpec>,
    #[serde(deserialize_with = "de_actions")]
    pub db_spawn: Vec<ActionSpec>,
}

impl Default for ProcessResponse {
    fn default() -> Self {
        Self {
            privilege_escalation: vec![ActionSpec::Stop, ActionSpec::Snapshot],
            web_spawn: vec![],
            exec_from_writable: vec![],
            fileless: vec![ActionSpec::Stop],
            reverse_shell: vec![kill()],
            miner: vec![kill()],
            masquerade: vec![],
            ld_preload: vec![],
            ptrace: vec![],
            unknown_suid: vec![ActionSpec::Stop],
            db_spawn: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProcessConfig {
    pub enabled: bool,
    /// Real-time exec/uid/ptrace events via the netlink proc connector.
    pub proc_connector: bool,
    /// Skip the full `/proc` analysis for a (parent, executable, uids)
    /// combination already analysed clean several times — build servers and
    /// cron/monitoring storms repeat the same few. Shell/interpreter scripts
    /// and LD_PRELOAD of root processes are still checked on every exec.
    pub exec_fast_path: bool,
    /// Every N-th exec of a fast-path combination gets the full analysis
    /// anyway (0 = never).
    pub exec_recheck_every: u32,
    /// Periodic full /proc scan (catches what the connector cannot see).
    #[serde(with = "humantime_serde")]
    pub scan_interval: Duration,
    /// Accounts that run web applications.
    pub web_users: Vec<String>,
    /// `comm` globs of web server / application worker processes.
    pub web_comms: Vec<String>,
    /// Children that are suspicious when spawned by a web worker.
    pub suspicious_children: Vec<String>,
    /// Exceptions: legitimate parent → child pairs.
    pub allowed_children: Vec<ChildAllow>,
    /// Executing binaries from these locations is suspicious.
    pub writable_exec_paths: Vec<String>,
    /// Executables allowed to run as euid 0 for a non-root real uid.
    pub setuid_allowlist: Vec<String>,
    /// Parents (`comm` glob) that legitimately spawn root children for
    /// non-root users (sudo, su, pkexec, login managers...).
    pub root_transition_parents: Vec<String>,
    pub detect_masquerade: bool,
    pub detect_fileless: bool,
    pub detect_reverse_shell: bool,
    pub detect_ld_preload: bool,
    pub detect_ptrace: bool,
    /// Debuggers allowed to ptrace (`comm` glob).
    pub ptrace_allow: Vec<String>,
    /// Known crypto-miner names (`comm`/exe basename glob).
    pub miner_names: Vec<String>,
    /// Typical mining pool ports (outbound connections are scored).
    pub miner_ports: Vec<u16>,
    /// Database / data-store server processes. A shell or tool spawned by one
    /// of them is the classic outcome of SQL-injection-to-RCE (MySQL UDF,
    /// PostgreSQL `COPY ... TO PROGRAM`, Redis module/config abuse).
    pub db_comms: Vec<String>,
    /// Apply response actions to findings about processes that already
    /// existed when Warden started (default: report only — no context).
    pub act_on_existing: bool,
    pub response: ProcessResponse,
    /// Resource limits for long-running / runaway processes (`[[process.limit]]`).
    #[serde(rename = "limit")]
    pub limits: Vec<LimitRule>,
}

/// A resource rule: processes matching `comm`/`users`/`units` that exceed
/// `cpu_percent` for `cpu_duration`, run longer than `max_runtime`, or grow
/// beyond `max_rss` get `actions` (default: report only).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LimitRule {
    pub name: String,
    /// `comm` globs (e.g. `php-fpm*`).
    #[serde(default)]
    pub comm: Vec<String>,
    /// User names.
    #[serde(default)]
    pub users: Vec<String>,
    /// systemd unit / cgroup component globs (e.g. `php*-fpm.service`).
    #[serde(default)]
    pub units: Vec<String>,
    /// Sustained CPU usage, percent of one core.
    #[serde(default)]
    pub cpu_percent: Option<f64>,
    #[serde(default = "default_cpu_duration", with = "humantime_serde")]
    pub cpu_duration: Duration,
    /// Wall-clock lifetime of the process.
    #[serde(default, with = "humantime_serde::option")]
    pub max_runtime: Option<Duration>,
    #[serde(default)]
    pub max_rss: Option<ByteSize>,
    #[serde(default, deserialize_with = "de_actions")]
    pub actions: Vec<ActionSpec>,
}

fn default_cpu_duration() -> Duration {
    secs(300)
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            proc_connector: true,
            exec_fast_path: true,
            exec_recheck_every: 16,
            scan_interval: secs(15),
            web_users: strings(&["www-data", "nginx", "apache", "http", "httpd", "wwwrun", "nobody", "php-fpm"]),
            web_comms: strings(&[
                "php-fpm*",
                "php-cgi*",
                "php",
                "php[0-9]*",
                "apache2",
                "httpd",
                "nginx",
                "lsphp*",
                "node",
                "nodejs",
                "uwsgi",
                "gunicorn*",
                "puma*",
                "unicorn*",
                "passenger*",
                "java",
                "tomcat*",
                "dotnet",
                "fcgiwrap",
                "frankenphp",
                "hhvm",
                "litespeed",
                "lshttpd",
                "uvicorn",
                "hypercorn",
                "daphne",
                "deno",
                "bun",
            ]),
            suspicious_children: strings(&[
                "sh", "bash", "dash", "zsh", "ksh", "csh", "tcsh", "fish", "busybox", "nc", "ncat", "netcat", "socat",
                "telnet", "curl", "wget", "python*", "perl", "ruby", "lua*", "base64", "xxd", "nmap", "masscan",
                "whoami", "id", "uname", "hostname", "ifconfig", "ip", "ss", "netstat", "crontab", "chmod", "chattr",
                "ssh", "scp", "tftp", "ftp", "gcc", "cc", "make", "dd", "mkfifo", "openssl",
            ]),
            allowed_children: vec![
                ChildAllow { parent: "php*".into(), child: "/usr/sbin/sendmail".into() },
                ChildAllow { parent: "php*".into(), child: "/usr/lib/sendmail".into() },
                ChildAllow { parent: "php*".into(), child: "/usr/bin/msmtp".into() },
                ChildAllow { parent: "php*".into(), child: "/usr/sbin/postdrop".into() },
                ChildAllow { parent: "php*".into(), child: "/usr/bin/convert".into() },
                ChildAllow { parent: "php*".into(), child: "/usr/bin/magick".into() },
                ChildAllow { parent: "php*".into(), child: "/usr/bin/gs".into() },
                ChildAllow { parent: "php*".into(), child: "/usr/bin/ffmpeg".into() },
                ChildAllow { parent: "php*".into(), child: "/usr/bin/ffprobe".into() },
                ChildAllow { parent: "php*".into(), child: "/usr/bin/pdftotext".into() },
                ChildAllow { parent: "php*".into(), child: "/usr/bin/wkhtmltopdf".into() },
                ChildAllow { parent: "php*".into(), child: "/usr/bin/git".into() },
                ChildAllow { parent: "node".into(), child: "/usr/bin/git".into() },
                ChildAllow { parent: "sendmail".into(), child: "/usr/sbin/postdrop".into() },
                ChildAllow { parent: "nginx".into(), child: "/usr/sbin/nginx".into() },
                ChildAllow { parent: "apache2".into(), child: "/usr/sbin/apache2".into() },
                // Piped logging (`CustomLog "|/usr/bin/rotatelogs ..."`).
                ChildAllow { parent: "apache2".into(), child: "/usr/bin/rotatelogs".into() },
                ChildAllow { parent: "httpd".into(), child: "/usr/sbin/rotatelogs".into() },
                ChildAllow { parent: "apache2".into(), child: "/usr/bin/logger".into() },
                ChildAllow { parent: "httpd".into(), child: "/usr/bin/logger".into() },
                ChildAllow { parent: "apache2".into(), child: "/usr/sbin/cronolog".into() },
            ],
            writable_exec_paths: strings(&[
                "/tmp/**",
                "/var/tmp/**",
                "/dev/shm/**",
                "/run/shm/**",
                "/var/www/**",
                "/srv/www/**",
                "/home/*/public_html/**",
                "/var/lib/php/sessions/**",
                "/run/user/**",
            ]),
            setuid_allowlist: strings(&[
                "/usr/bin/sudo",
                "/usr/bin/sudoedit",
                "/usr/bin/sudo-rs",
                "/usr/bin/su",
                "/usr/bin/pkexec",
                "/usr/bin/passwd",
                "/usr/bin/newgrp",
                "/usr/bin/chsh",
                "/usr/bin/chfn",
                "/usr/bin/gpasswd",
                "/usr/bin/mount",
                "/usr/bin/umount",
                "/usr/bin/fusermount*",
                "/usr/bin/doas",
                "/usr/bin/at",
                "/usr/bin/crontab",
                "/usr/sbin/unix_chkpwd",
                "/usr/sbin/pppd",
                "/usr/bin/ntfs-3g",
                "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
                "/usr/lib/policykit-1/polkit-agent-helper-1",
                "/usr/lib/polkit-1/polkit-agent-helper-1",
                "/usr/libexec/polkit-agent-helper-1",
                "/usr/lib/openssh/ssh-keysign",
                "/usr/libexec/openssh/ssh-keysign",
                "/usr/lib/snapd/snap-confine",
                "/usr/lib/xorg/Xorg.wrap",
                "/usr/lib/eject/dmcrypt-get-device",
                "/usr/sbin/mount.*",
                "/usr/lib/chromium/chrome-sandbox",
                "/opt/google/chrome/chrome-sandbox",
                "/usr/bin/vmware-user-suid-wrapper",
                "/usr/bin/expiry",
                "/usr/bin/chage",
                "/usr/bin/ssh-agent",
                "/usr/bin/write*",
                "/usr/bin/wall",
            ]),
            root_transition_parents: strings(&[
                "sudo",
                "sudo-rs",
                "su",
                "pkexec",
                "doas",
                "run0",
                "polkitd",
                "polkit-agent-he*",
                "login",
                "sshd",
                "sshd-session",
                "gdm-session-wor*",
                "lightdm",
                "sddm*",
                "systemd",
                "(sd-pam)",
                "cron",
                "crond",
                "atd",
                "snapd",
                "snap-confine",
                "containerd-shim*",
                "runc",
                "crun",
                "conmon",
                "dbus-daemon-lau*",
                "unix_chkpwd",
                "newgrp",
                "mount",
                "fusermount*",
            ]),
            detect_masquerade: true,
            detect_fileless: true,
            detect_reverse_shell: true,
            detect_ld_preload: true,
            detect_ptrace: true,
            ptrace_allow: strings(&[
                "gdb",
                "lldb*",
                "strace",
                "ltrace",
                "perf",
                "valgrind*",
                "rr",
                "dlv",
                "py-spy",
                "rbspy",
                "criu",
                "apport",
                "systemd-coredump",
            ]),
            miner_names: strings(&[
                "xmrig*",
                "xmr-stak*",
                "kdevtmpfsi",
                "kinsing",
                "minerd",
                "cpuminer*",
                "nanominer",
                "t-rex",
                "lolminer",
                "phoenixminer",
                "ethminer",
                "nbminer",
                "gminer",
                "srbminer*",
                "teamredminer",
                "c3pool*",
                "moneroocean*",
                "sysupdate",
                "networkservice",
                "kthreaddi",
                "kworkerds",
                "dbused",
                "solrd",
            ]),
            miner_ports: vec![3333, 3334, 3357, 4444, 5555, 5556, 6666, 7777, 8888, 9999, 14433, 14444, 45560, 45700],
            db_comms: strings(&[
                "mysqld",
                "mariadbd",
                "postgres",
                "postmaster",
                "redis-server",
                "valkey-server",
                "keydb-server",
                "mongod",
                "mongos",
                "clickhouse-serv*",
                "memcached",
                "influxd",
                "etcd",
            ]),
            act_on_existing: false,
            response: ProcessResponse::default(),
            limits: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IntegrityConfig {
    pub enabled: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// Critical system files (globs) whose content is baselined.
    pub files: Vec<String>,
    /// Look for new SUID/SGID files.
    pub suid_scan: bool,
    pub suid_paths: Vec<String>,
    /// Directories not walked by the SUID scan (container image layers,
    /// snap/flatpak stores: SUID binaries there are legitimate and many).
    pub suid_exclude: Vec<String>,
    /// Without real-time detection (or for roots it cannot cover): walk
    /// `suid_paths` this often.
    #[serde(with = "humantime_serde")]
    pub suid_interval: Duration,
    /// Real-time detection of `chmod u+s`, SUID files created or moved in
    /// (fanotify filesystem marks, Linux 5.9+). The full walk then becomes a
    /// rare safety net (`suid_rescan`) and is not repeated on every restart.
    pub suid_realtime: bool,
    /// Full walk interval while real-time detection is active.
    #[serde(with = "humantime_serde")]
    pub suid_rescan: Duration,
    /// Delay of the first walk after start (lets the host settle after boot).
    #[serde(with = "humantime_serde")]
    pub suid_delay: Duration,
    /// New listening sockets.
    pub listeners: bool,
    /// Listening ports to ignore.
    pub listener_ignore_ports: Vec<u16>,
    #[serde(deserialize_with = "de_actions")]
    pub on_change: Vec<ActionSpec>,
}

impl Default for IntegrityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval: secs(300),
            files: strings(&[
                "/etc/passwd",
                "/etc/shadow",
                "/etc/group",
                "/etc/gshadow",
                "/etc/sudoers",
                "/etc/sudoers.d/*",
                "/etc/ssh/sshd_config",
                "/etc/ssh/sshd_config.d/*",
                "/root/.ssh/authorized_keys",
                "/root/.ssh/authorized_keys2",
                "/home/*/.ssh/authorized_keys",
                "/etc/crontab",
                "/etc/cron.d/*",
                "/etc/cron.hourly/*",
                "/etc/cron.daily/*",
                "/var/spool/cron/crontabs/*",
                "/etc/ld.so.preload",
                "/etc/ld.so.conf",
                "/etc/ld.so.conf.d/*",
                "/etc/pam.d/*",
                "/etc/security/*.conf",
                "/etc/systemd/system/*.service",
                "/etc/systemd/system/*.timer",
                "/etc/systemd/system/*/*.service",
                "/etc/systemd/system/*/*.conf",
                "/lib/systemd/system/*.service",
                "/usr/lib/systemd/system/*.service",
                "/etc/rc.local",
                "/etc/profile",
                "/etc/profile.d/*",
                "/etc/bash.bashrc",
                "/etc/environment",
                "/root/.bashrc",
                "/root/.profile",
                "/etc/hosts",
                "/etc/nsswitch.conf",
                "/etc/resolv.conf",
                "/etc/modprobe.d/*",
                "/etc/modules-load.d/*",
                "/etc/udev/rules.d/*",
                "/etc/apt/sources.list",
                "/etc/apt/sources.list.d/*",
                "/usr/bin/sudo",
                "/usr/sbin/sshd",
                "/usr/bin/passwd",
                "/bin/login",
                "/usr/bin/login",
                "/usr/lib/mysql/plugin/*",
            ]),
            suid_scan: true,
            suid_paths: strings(&[
                "/usr", "/bin", "/sbin", "/opt", "/home", "/tmp", "/var", "/srv", "/root", "/dev/shm",
            ]),
            suid_exclude: strings(&[
                "/var/lib/docker",
                "/var/lib/containerd",
                "/var/lib/containers",
                "/var/lib/lxd",
                "/var/lib/snapd",
                "/var/lib/flatpak",
                "/var/lib/lxc/*/rootfs",
                "/var/lib/machines",
                "/home/*/.local/share/containers",
                "/home/*/.local/share/flatpak",
            ]),
            suid_interval: secs(6 * 3600),
            suid_realtime: true,
            suid_rescan: secs(7 * 86400),
            suid_delay: secs(120),
            listeners: true,
            listener_ignore_ports: vec![],
            on_change: vec![],
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AuthSource {
    /// journald if it runs (it records who sent each line), else the auth
    /// log file (which does not: see `auth.trust_file`).
    #[default]
    Auto,
    Journal,
    File,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub enabled: bool,
    pub source: AuthSource,
    pub auth_log: PathBuf,
    /// Failed SSH authentications from one IP within `window` → block.
    pub ssh_max_failures: usize,
    #[serde(with = "humantime_serde")]
    pub ssh_window: Duration,
    pub ssh_block: bool,
    #[serde(with = "humantime_serde")]
    pub ssh_block_ttl: Duration,
    /// Networks that are never blocked (in addition to firewall.allowlist).
    pub allowlist: Vec<String>,
    pub alert_root_login: bool,
    pub alert_sudo_failure: bool,
    pub alert_account_changes: bool,
    /// Block addresses on lines read from the auth log *file*. A syslog
    /// file does not say who sent a line, and any local user can write
    /// `sshd[1]: Failed password for root from <address>` into it with
    /// `logger`: by default such lines are counted and reported, but do not
    /// block. journald records the sender and is used when it runs.
    pub trust_file: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            source: AuthSource::Auto,
            auth_log: "/var/log/auth.log".into(),
            ssh_max_failures: 8,
            ssh_window: secs(600),
            ssh_block: true,
            ssh_block_ttl: secs(3600),
            allowlist: vec![],
            alert_root_login: true,
            alert_sudo_failure: true,
            alert_account_changes: true,
            trust_file: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FimSite {
    pub name: String,
    pub root: PathBuf,
    /// Files to baseline (globs relative to root). Defaults to script-like files.
    #[serde(default = "default_fim_include")]
    pub include: Vec<String>,
    #[serde(default = "default_fim_exclude")]
    pub exclude: Vec<String>,
    /// Directories where scripts must never appear (user uploads, media).
    #[serde(default = "default_no_scripts")]
    pub no_scripts: Vec<String>,
    /// Content signatures are not evaluated for these globs (minified bundles,
    /// vendored code) — hashes still are.
    #[serde(default = "default_signature_exclude")]
    pub signature_exclude: Vec<String>,
    /// Web server access log for "patient zero" correlation.
    #[serde(default)]
    pub access_log: Option<PathBuf>,
    /// Overrides `fim.quarantine` for this site.
    #[serde(default)]
    pub quarantine: Option<bool>,
    /// Unit to restart after an infection is contained (e.g. php8.3-fpm.service).
    #[serde(default)]
    pub restart_unit: Option<String>,
}

pub fn default_fim_include() -> Vec<String> {
    strings(&[
        "**/*.php",
        "**/*.php[0-9]",
        "**/*.phtml",
        "**/*.pht",
        "**/*.phar",
        "**/*.inc",
        "**/*.module",
        "**/*.js",
        "**/*.mjs",
        "**/*.cjs",
        "**/*.jsx",
        "**/*.ts",
        "**/*.py",
        "**/*.pyc",
        "**/*.rb",
        "**/*.pl",
        "**/*.pm",
        "**/*.cgi",
        "**/*.sh",
        "**/*.jsp",
        "**/*.jspx",
        "**/*.asp",
        "**/*.aspx",
        "**/*.cfm",
        "**/*.html",
        "**/*.htm",
        "**/*.shtml",
        "**/*.svg",
        "**/.htaccess",
        "**/.user.ini",
        "**/php.ini",
        "**/web.config",
        "**/*.so",
        "**/*.wasm",
    ])
}

pub fn default_fim_exclude() -> Vec<String> {
    strings(&["**/.git/**", "**/.svn/**", "**/cache/**/*.html", "**/node_modules/.cache/**", "**/.next/cache/**"])
}

pub fn default_no_scripts() -> Vec<String> {
    strings(&[
        "wp-content/uploads/**",
        "uploads/**",
        "upload/**",
        "media/**",
        "files/**",
        "images/**",
        "img/**",
        "storage/app/public/**",
        "public/uploads/**",
        "sites/default/files/**",
        "var/uploads/**",
    ])
}

pub fn default_signature_exclude() -> Vec<String> {
    strings(&["**/*.min.js", "**/*.bundle.js", "**/*.chunk.js", "**/*.map", "**/*.pyc", "**/*.so", "**/*.wasm"])
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FimConfig {
    pub enabled: bool,
    /// Full verification scan period.
    #[serde(with = "humantime_serde")]
    pub schedule: Duration,
    pub scan_on_start: bool,
    /// Real-time change detection with fanotify (reports the writer PID).
    pub realtime: bool,
    /// Scan with idle I/O priority and nice 19.
    pub low_priority: bool,
    /// Throttle full scans (files per second, 0 = unlimited).
    pub max_files_per_sec: u32,
    pub max_file_size: ByteSize,
    /// Extra signature rule files (TOML), e.g. /etc/warden/signatures.d/*.toml
    pub signatures: Vec<String>,
    /// Score ≥ alert_score → alert; ≥ quarantine_score → quarantine.
    pub alert_score: u32,
    pub quarantine_score: u32,
    pub quarantine: bool,
    /// Mass modification detection: ≥ burst_files changes within burst_window.
    pub burst_files: usize,
    #[serde(with = "humantime_serde")]
    pub burst_window: Duration,
    /// Changes written by these processes (`comm` glob) are accepted into
    /// the baseline automatically — unless the content is flagged.
    pub trusted_writers: Vec<String>,
    /// ... and only when the writer runs as one of these users (empty = any).
    pub trusted_users: Vec<String>,
    /// Requests within this window around a change are correlated.
    #[serde(with = "humantime_serde")]
    pub correlate_window: Duration,
    /// Block IPs that sent requests correlated with a confirmed infection.
    pub block_attackers: bool,
    /// Block on a request read from an access log that a non-root user can
    /// write (nginx on Debian writes its logs as `www-data`; a webshell
    /// running as that user can add a line naming any address). Off: such
    /// a request is reported and scored, but does not block by itself.
    pub trust_writable_logs: bool,
    /// Kill the (web worker) process that wrote malicious content. In a
    /// mass change (`burst_files` within `burst_window`) only the writers
    /// whose own writes matched the signatures are killed; a burst of clean
    /// changes (a CMS update) is a warning (`wardenctl fim pause`).
    pub kill_writer: bool,
    #[serde(rename = "site")]
    pub sites: Vec<FimSite>,
}

impl Default for FimConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            schedule: secs(6 * 3600),
            scan_on_start: true,
            realtime: true,
            low_priority: true,
            max_files_per_sec: 2000,
            max_file_size: ByteSize::mib(16),
            signatures: strings(&["/etc/warden/signatures.d/*.toml"]),
            alert_score: 40,
            quarantine_score: 80,
            quarantine: true,
            burst_files: 25,
            burst_window: secs(120),
            trusted_writers: strings(&[
                "git",
                "rsync",
                "composer",
                "npm",
                "yarn",
                "pnpm",
                "dpkg",
                "apt*",
                "unattended-upgr*",
            ]),
            trusted_users: vec![],
            correlate_window: secs(30),
            block_attackers: true,
            trust_writable_logs: false,
            kill_writer: true,
            sites: vec![],
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HeuristicsConfig {
    pub enabled: bool,
    /// Suspicion decays exponentially with this half-life.
    #[serde(with = "humantime_serde")]
    pub half_life: Duration,
    pub alert_score: f64,
    pub contain_score: f64,
    /// Actions applied when a process reaches `contain_score`.
    #[serde(deserialize_with = "de_actions")]
    pub on_contain: Vec<ActionSpec>,
    /// Block a remote IP whose accumulated score reaches this.
    pub ip_block_score: f64,
    /// Points per finding (keys are event kinds without the `security.` prefix).
    pub weights: BTreeMap<String, f64>,
    /// Learn parent→child process lineages for this long, then report new ones.
    pub lineage: bool,
    #[serde(with = "humantime_serde")]
    pub lineage_learning: Duration,
}

impl Default for HeuristicsConfig {
    fn default() -> Self {
        let weights = [
            ("privilege_escalation", 100.0),
            ("reverse_shell", 100.0),
            ("miner", 100.0),
            ("fileless_exec", 80.0),
            ("unknown_suid_exec", 80.0),
            ("ld_preload", 60.0),
            ("masquerade", 50.0),
            ("exec_from_writable", 40.0),
            ("ptrace", 40.0),
            ("web_spawn", 30.0),
            ("miner_port", 40.0),
            ("new_lineage", 15.0),
            ("ssh_bruteforce", 60.0),
            ("bruteforce_success", 100.0),
            ("webshell", 100.0),
            ("webshell_access", 60.0),
            ("malicious_writer", 100.0),
            ("db_spawn", 60.0),
            ("waf_attack", 40.0),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        Self {
            enabled: true,
            half_life: secs(30 * 60),
            alert_score: 60.0,
            contain_score: 120.0,
            on_contain: vec![ActionSpec::Stop, ActionSpec::Snapshot],
            ip_block_score: 60.0,
            weights,
            lineage: true,
            lineage_learning: secs(7 * 86400),
        }
    }
}

// ---------------------------------------------------------------------------
// WAF (ModSecurity) integration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WafFormat {
    /// Detect per line: JSON audit log, native (serial) audit log or error log.
    #[default]
    Auto,
    /// `SecAuditLogFormat JSON` (ModSecurity 2.9+ and libmodsecurity 3).
    Json,
    /// Native serial audit log (`--xxxx-A--` sections), v2 and v3.
    Native,
    /// Apache `error.log` (mod_security2) or nginx `error.log` (ModSecurity-nginx).
    ErrorLog,
    /// `SecAuditLogType Concurrent`: one file per transaction under
    /// `storage_dir` (`SecAuditLogStorageDir`), listed in the index file
    /// `path` (`SecAuditLog`). Without an index (piped to `mlogc`), `path`
    /// is the storage directory itself and new files are found by scanning.
    Concurrent,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct WafLog {
    /// The log file, or a glob for one log per site
    /// (`/var/log/apache2/*/modsec_audit.log`): new matches are picked up
    /// while Warden runs.
    pub path: PathBuf,
    #[serde(default)]
    pub format: WafFormat,
    /// FIM site the log belongs to (enables WAF ↔ file-change correlation).
    /// With a glob, `{1}`, `{2}`… stand for what the 1st, 2nd `*` matched.
    #[serde(default)]
    pub site: Option<String>,
    /// `format = "concurrent"`: `SecAuditLogStorageDir`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_dir: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WafConfig {
    pub enabled: bool,
    #[serde(rename = "log")]
    pub logs: Vec<WafLog>,
    /// Blocked (intercepted) transactions from one IP within `window` before
    /// Warden blocks the address in nftables — ModSecurity blocks single
    /// requests, Warden blocks the attacker.
    pub block_after: usize,
    #[serde(with = "humantime_serde")]
    pub window: Duration,
    pub block: bool,
    #[serde(with = "humantime_serde")]
    pub block_ttl: Duration,
    /// Also count detection-only matches (SecRuleEngine DetectionOnly).
    pub count_detection_only: bool,
    /// Minimum rule severity that counts (CRS: emergency, alert, critical, error, warning, notice).
    pub min_rule_severity: String,
    /// Rule IDs that never count (known false positives on your sites).
    pub ignore_rules: Vec<String>,
    /// Block on transactions read from a log a non-root user can write
    /// (ModSecurity-nginx: the workers write the audit log; nginx on Debian
    /// owns its error log as `www-data`). On by default, because on such
    /// servers there is no other source; events from such a log say so
    /// (`log_trust`), `wardenctl doctor` warns, and an address with a live
    /// SSH session is never blocked on such evidence
    /// (`actions.firewall.protect_ssh_sessions`).
    pub trust_writable_logs: bool,
    /// Also follow the ModSecurity logs that Apache, nginx and Angie are
    /// configured to write (`SecAuditLog`, `SecAuditLogStorageDir`, the
    /// error logs where audit logging is piped away), per virtual host,
    /// re-read every few minutes. `wardenctl waf discover` shows them.
    pub discover: bool,
}

impl Default for WafConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            logs: vec![],
            block_after: 5,
            window: secs(600),
            block: true,
            block_ttl: secs(3600),
            count_detection_only: false,
            min_rule_severity: "critical".into(),
            ignore_rules: vec![],
            trust_writable_logs: true,
            discover: true,
        }
    }
}

// ---------------------------------------------------------------------------
// health checks (hung services, microservices, databases)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthKind {
    Http,
    Tcp,
    Command,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheck {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: HealthKind,
    /// http: URL (`http://127.0.0.1:8080/health`, `https://...`).
    #[serde(default)]
    pub url: Option<String>,
    /// tcp: `host:port`.
    #[serde(default)]
    pub address: Option<String>,
    /// command: program and arguments (`pg_isready`, `redis-cli ping`...).
    #[serde(default)]
    pub program: Option<String>,
    #[serde(default)]
    pub args: Vec<String>,
    /// command: account to run as; default `daemon.command_user`.
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default = "default_health_interval", with = "humantime_serde")]
    pub interval: Duration,
    #[serde(default = "default_health_timeout", with = "humantime_serde")]
    pub timeout: Duration,
    /// Consecutive failures before the check is declared down.
    #[serde(default = "default_health_failures")]
    pub failures: u32,
    /// http: accepted status codes, e.g. "200-399" or "200,204".
    #[serde(default = "default_expect_status")]
    pub expect_status: String,
    /// http: substring the body must contain.
    #[serde(default)]
    pub expect_body: Option<String>,
    /// command: substring stdout must contain (exit status must be 0 too).
    #[serde(default)]
    pub expect_output: Option<String>,
    #[serde(default = "yes")]
    pub tls_verify: bool,
    /// systemd unit the check belongs to; when set and `actions` is empty,
    /// a failing check restarts it.
    #[serde(default)]
    pub unit: Option<String>,
    #[serde(default, deserialize_with = "de_actions")]
    pub actions: Vec<ActionSpec>,
    /// After an action, ignore failures for this long (service start-up).
    #[serde(default = "default_health_grace", with = "humantime_serde")]
    pub grace: Duration,
}

fn yes() -> bool {
    true
}
fn default_health_interval() -> Duration {
    secs(30)
}
fn default_health_timeout() -> Duration {
    secs(5)
}
fn default_health_failures() -> u32 {
    3
}
fn default_expect_status() -> String {
    "200-399".into()
}
fn default_health_grace() -> Duration {
    secs(60)
}

/// Parse "200-399", "200,204", "204" into inclusive ranges.
pub fn parse_status_ranges(s: &str) -> Option<Vec<(u16, u16)>> {
    s.split(',')
        .map(|p| {
            let p = p.trim();
            match p.split_once('-') {
                Some((a, b)) => Some((a.trim().parse().ok()?, b.trim().parse().ok()?)),
                None => {
                    let v = p.parse().ok()?;
                    Some((v, v))
                }
            }
        })
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HealthConfig {
    pub enabled: bool,
    #[serde(rename = "check")]
    pub checks: Vec<HealthCheck>,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self { enabled: true, checks: vec![] }
    }
}

// ---------------------------------------------------------------------------
// kernel tuning advisor
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TuningConfig {
    /// Periodically compare sysctls with the hardware and workload and
    /// report recommendations (`wardenctl tuning`). Never changes anything.
    pub advise: bool,
    #[serde(with = "humantime_serde")]
    pub interval: Duration,
    /// Reactively grow *capacity* limits that are about to be exhausted
    /// (nf_conntrack_max, pid_max, file-max) within RAM-derived caps.
    /// Behaviour-shaping knobs (swappiness, dirty ratios, THP) are never
    /// changed automatically.
    pub auto_grow: bool,
    /// Write applied changes to /etc/sysctl.d/90-warden.conf so they survive reboot.
    pub persist: bool,
    /// Recommendation keys to ignore.
    pub ignore: Vec<String>,
}

impl Default for TuningConfig {
    fn default() -> Self {
        Self { advise: true, interval: secs(6 * 3600), auto_grow: false, persist: false, ignore: vec![] }
    }
}

// ---------------------------------------------------------------------------
// validation
// ---------------------------------------------------------------------------

impl Config {
    /// Semantic validation beyond what serde can express. Returns all
    /// problems at once so an operator can fix them in one go.
    pub fn validate(&self) -> Vec<String> {
        let mut errs = Vec::new();
        let mut order = |name: &str, warn: f64, crit: f64| {
            if warn > crit {
                errs.push(format!("{name}: warning threshold ({warn}) is above critical ({crit})"));
            }
        };
        order("memory.psi_full_avg10", self.memory.psi_full_avg10_warning, self.memory.psi_full_avg10_critical);
        // For "available" lower is worse.
        order(
            "memory.available_percent (critical must be lower)",
            self.memory.available_critical_percent,
            self.memory.available_warning_percent,
        );
        order("cpu.psi_some_avg60", self.cpu.psi_some_avg60_warning, self.cpu.psi_some_avg60_critical);
        order("cpu.load_per_cpu", self.cpu.load_per_cpu_warning, self.cpu.load_per_cpu_critical);
        order("io.psi_full_avg10", self.io.psi_full_avg10_warning, self.io.psi_full_avg10_critical);
        order("disk.percent", self.disk.warning_percent, self.disk.critical_percent);
        order("disk.inode_percent", self.disk.inode_warning_percent, self.disk.inode_critical_percent);
        order("limits.file_percent", self.limits.file_warning_percent, self.limits.file_critical_percent);
        order("limits.pid_percent", self.limits.pid_warning_percent, self.limits.pid_critical_percent);
        order(
            "limits.conntrack_percent",
            self.limits.conntrack_warning_percent,
            self.limits.conntrack_critical_percent,
        );
        order("hardware.thermal_c", self.hardware.thermal_warning_c, self.hardware.thermal_critical_c);
        order("heuristics.score", self.heuristics.alert_score, self.heuristics.contain_score);
        if self.fim.alert_score > self.fim.quarantine_score {
            errs.push("fim: alert_score is above quarantine_score".into());
        }

        if self.daemon.tick.is_zero() {
            errs.push("daemon.tick must be > 0".into());
        }
        let p = self.daemon.pacing.io_pressure;
        if !(p > 0.0 && p <= 100.0) {
            errs.push(format!("daemon.pacing.io_pressure must be within (0, 100] percent, got {p}"));
        }
        let t = &self.memory.trigger;
        if t.enabled {
            if t.window < ms(500) || t.window > secs(10) {
                errs.push("memory.trigger.window must be within 500ms..10s (kernel limit)".into());
            }
            if t.stall.is_zero() || t.stall > t.window {
                errs.push("memory.trigger.stall must be > 0 and <= window".into());
            }
        }
        if self.disk.cleanup_at < Severity::Warning {
            errs.push("disk.cleanup_at must be \"warning\" or \"critical\"".into());
        }
        // The playbook stops once usage is below the target: a target at or
        // above the level that starts it skips every step.
        let start = if self.disk.cleanup_at >= Severity::Critical {
            ("disk.critical_percent", self.disk.critical_percent)
        } else {
            ("disk.warning_percent", self.disk.warning_percent)
        };
        let t = self.disk.cleanup_target_percent;
        if !(t >= 0.0 && t < start.1) {
            errs.push(format!(
                "disk.cleanup_target_percent ({t}) must be below {} ({}), where the cleanup starts \
                 (0 runs every step)",
                start.0, start.1
            ));
        }
        // A zero interval makes a scheduler spin (a locked thread at 100% of a core).
        let intervals: [(&str, Duration); 16] = [
            ("memory.interval", self.memory.interval),
            ("cpu.interval", self.cpu.interval),
            ("io.interval", self.io.interval),
            ("limits.interval", self.limits.interval),
            ("network.interval", self.network.interval),
            ("hardware.interval", self.hardware.interval),
            ("kernel.interval", self.kernel.interval),
            ("disk.interval", self.disk.interval),
            ("process.scan_interval", self.process.scan_interval),
            ("integrity.interval", self.integrity.interval),
            ("integrity.suid_interval", self.integrity.suid_interval),
            ("integrity.suid_rescan", self.integrity.suid_rescan),
            ("systemd.interval", self.systemd.interval),
            ("systemd.dbus_reconcile", self.systemd.dbus_reconcile),
            ("tuning.interval", self.tuning.interval),
            ("fim.schedule", self.fim.schedule),
        ];
        for (name, d) in intervals {
            if d.is_zero() {
                errs.push(format!("{name} must be > 0"));
            }
        }

        // Every glob list: `GlobList` drops a pattern it cannot compile, so
        // an invalid one would silently match nothing (0.13.3 checked only
        // some of the lists).
        let mut globs: Vec<(&str, &[String])> = vec![
            ("protection.comm", &self.protection.comm),
            ("protection.exe", &self.protection.exe),
            ("protection.units", &self.protection.units),
            ("memory.culprit.prefer", &self.memory.culprit.prefer),
            ("memory.culprit.avoid", &self.memory.culprit.avoid),
            ("cpu.hog_ignore", &self.cpu.hog_ignore),
            ("disk.exclude", &self.disk.exclude),
            ("network.ignore_interfaces", &self.network.ignore_interfaces),
            ("systemd.auto_restart", &self.systemd.auto_restart),
            ("systemd.ignore", &self.systemd.ignore),
            ("process.web_comms", &self.process.web_comms),
            ("process.suspicious_children", &self.process.suspicious_children),
            ("process.writable_exec_paths", &self.process.writable_exec_paths),
            ("process.setuid_allowlist", &self.process.setuid_allowlist),
            ("process.root_transition_parents", &self.process.root_transition_parents),
            ("process.ptrace_allow", &self.process.ptrace_allow),
            ("process.miner_names", &self.process.miner_names),
            ("process.db_comms", &self.process.db_comms),
            ("integrity.files", &self.integrity.files),
            ("integrity.suid_exclude", &self.integrity.suid_exclude),
            ("fim.trusted_writers", &self.fim.trusted_writers),
        ];
        for s in &self.fim.sites {
            globs.push(("fim.site.include", &s.include));
            globs.push(("fim.site.exclude", &s.exclude));
            globs.push(("fim.site.no_scripts", &s.no_scripts));
            globs.push(("fim.site.signature_exclude", &s.signature_exclude));
        }
        for a in &self.process.allowed_children {
            globs.push(("process.allowed_children", std::slice::from_ref(&a.parent)));
            globs.push(("process.allowed_children", std::slice::from_ref(&a.child)));
        }
        for a in &self.disk.cleanup {
            let (paths, exclude): (&[String], &[String]) = match a {
                ActionSpec::DeleteOld { paths, exclude, .. } => (paths, exclude),
                ActionSpec::TruncateLarge { paths, .. } => (paths, &[]),
                _ => continue,
            };
            for p in paths.iter().chain(exclude) {
                if !p.starts_with('/') {
                    errs.push(format!("disk.cleanup {}: {p:?} must be an absolute path", a.name()));
                }
            }
            globs.push(("disk.cleanup paths", paths));
            globs.push(("disk.cleanup exclude", exclude));
        }
        for (name, list) in globs {
            for g in list {
                if let Err(e) = globset::Glob::new(g) {
                    errs.push(format!("{name}: invalid glob {g:?}: {e}"));
                }
            }
        }

        let mut names = std::collections::HashSet::new();
        for s in &self.fim.sites {
            if !names.insert(&s.name) {
                errs.push(format!("fim.site: duplicate site name {:?}", s.name));
            }
            if !s.root.is_absolute() {
                errs.push(format!("fim.site {:?}: root must be an absolute path", s.name));
            }
        }
        for p in &self.kernel.patterns {
            if let Err(e) = regex::Regex::new(&p.regex) {
                errs.push(format!("kernel.patterns {:?}: invalid regex: {e}", p.kind));
            }
        }
        for (i, p) in self.policies.iter().enumerate() {
            if let Err(e) = p.compile() {
                errs.push(format!("policy #{i} ({}): {e}", p.name.as_deref().unwrap_or("unnamed")));
            }
        }
        let fw = &self.actions.firewall;
        if !(crate::net::MIN_IPV6_PREFIX..=128).contains(&fw.ipv6_prefix) {
            errs.push(format!(
                "actions.firewall.ipv6_prefix must be within {}..=128, got {}",
                crate::net::MIN_IPV6_PREFIX,
                fw.ipv6_prefix
            ));
        }
        // the names go into nft scripts: plain identifiers only
        for (name, v) in [("table", &fw.table), ("set_v4", &fw.set_v4), ("set_v6", &fw.set_v6)] {
            let ok = v.len() <= 48
                && v.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
            if !ok {
                errs.push(format!("actions.firewall.{name} {v:?}: use letters, digits and '_' (at most 48)"));
            }
        }
        if fw.set_v4 == fw.set_v6 {
            errs.push("actions.firewall.set_v4 and set_v6 must differ".into());
        }
        for cidr in self.actions.firewall.allowlist.iter().chain(&self.auth.allowlist) {
            if crate::net::Cidr::parse(cidr).is_none() {
                errs.push(format!("invalid CIDR in allowlist: {cidr:?}"));
            }
        }
        for w in &self.notify.webhook {
            if !(w.url.starts_with("http://") || w.url.starts_with("https://")) {
                errs.push(format!("notify.webhook {:?}: url must be http(s)", w.name));
            }
        }
        for r in &self.process.limits {
            if r.comm.is_empty() && r.users.is_empty() && r.units.is_empty() {
                errs.push(format!("process.limit {:?}: needs at least one of comm / users / units", r.name));
            }
            if r.cpu_percent.is_none() && r.max_runtime.is_none() && r.max_rss.is_none() {
                errs.push(format!("process.limit {:?}: needs cpu_percent, max_runtime or max_rss", r.name));
            }
            for g in r.comm.iter().chain(&r.units) {
                if globset::Glob::new(g).is_err() {
                    errs.push(format!("process.limit {:?}: invalid glob {g:?}", r.name));
                }
            }
        }
        let mut hnames = std::collections::HashSet::new();
        for c in &self.health.checks {
            if !hnames.insert(&c.name) {
                errs.push(format!("health.check: duplicate name {:?}", c.name));
            }
            let missing = match c.kind {
                HealthKind::Http => {
                    c.url.as_deref().is_none_or(|u| !(u.starts_with("http://") || u.starts_with("https://")))
                }
                HealthKind::Tcp => c.address.as_deref().is_none_or(|a| !a.contains(':')),
                HealthKind::Command => c.program.is_none(),
            };
            if missing {
                errs.push(format!(
                    "health.check {:?}: type {:?} needs {}",
                    c.name,
                    c.kind,
                    match c.kind {
                        HealthKind::Http => "url = \"http(s)://...\"",
                        HealthKind::Tcp => "address = \"host:port\"",
                        HealthKind::Command => "program = \"...\"",
                    }
                ));
            }
            if parse_status_ranges(&c.expect_status).is_none() {
                errs.push(format!("health.check {:?}: invalid expect_status {:?}", c.name, c.expect_status));
            }
            if c.failures == 0 || c.timeout.is_zero() || c.interval.is_zero() {
                errs.push(format!("health.check {:?}: failures, timeout and interval must be > 0", c.name));
            }
        }
        if !["emergency", "alert", "critical", "error", "warning", "notice", "info", "debug"]
            .contains(&self.waf.min_rule_severity.to_ascii_lowercase().as_str())
        {
            errs.push(format!("waf.min_rule_severity {:?} is not a ModSecurity severity", self.waf.min_rule_severity));
        }
        for (i, l) in self.waf.logs.iter().enumerate() {
            if !l.path.is_absolute() {
                errs.push(format!("waf.log[{i}]: path {:?} must be absolute", l.path));
            }
            if let Some(d) = &l.storage_dir {
                if l.format != WafFormat::Concurrent {
                    errs.push(format!("waf.log[{i}]: storage_dir is only for format = \"concurrent\""));
                }
                if !d.is_absolute() {
                    errs.push(format!("waf.log[{i}]: storage_dir {d:?} must be absolute"));
                }
            }
        }
        if self.waf.block_after == 0 {
            errs.push("waf.block_after must be >= 1".into());
        }
        for (place, user) in self.command_users() {
            if !valid_user(&user) {
                errs.push(format!("{place}: user {user:?} is not a user name or UID"));
            }
        }
        errs
    }

    /// Every account a configured program runs as: `(where, user)` for
    /// `daemon.command_user` and each `user` of an `exec` action (in any
    /// action list or policy), a notification command or a health check.
    pub fn command_users(&self) -> Vec<(String, String)> {
        fn walk(v: &serde_json::Value, path: &mut String, out: &mut Vec<(String, String)>) {
            match v {
                serde_json::Value::Object(m) => {
                    if let Some(serde_json::Value::String(u)) = m.get("user") {
                        out.push((path.trim_start_matches('.').to_owned(), u.clone()));
                    }
                    for (k, v) in m {
                        let len = path.len();
                        path.push('.');
                        path.push_str(k);
                        walk(v, path, out);
                        path.truncate(len);
                    }
                }
                serde_json::Value::Array(a) => {
                    for (i, v) in a.iter().enumerate() {
                        let len = path.len();
                        path.push_str(&format!("[{i}]"));
                        walk(v, path, out);
                        path.truncate(len);
                    }
                }
                _ => {}
            }
        }
        let mut out = Vec::new();
        if let Some(u) = &self.daemon.command_user {
            out.push(("daemon.command_user".to_owned(), u.clone()));
        }
        let mut rest = serde_json::to_value(self).unwrap_or_default();
        if let Some(d) = rest.get_mut("daemon").and_then(|d| d.as_object_mut()) {
            d.remove("command_user");
        }
        walk(&rest, &mut String::new(), &mut out);
        out
    }
}

/// A user name as `useradd` accepts it (or a numeric UID).
fn valid_user(u: &str) -> bool {
    let mut chars = u.chars();
    let Some(first) = chars.next() else { return false };
    u.len() <= 64
        && (u.bytes().all(|b| b.is_ascii_digit())
            || ((first.is_ascii_alphabetic() || first == '_')
                && u.trim_end_matches('$').chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_users_are_found_everywhere_and_validated() {
        let c: Config = toml::from_str(
            r#"
            [daemon]
            command_user = "warden-hooks"
            [memory]
            on_critical = [{ do = "exec", program = "/usr/local/bin/page", user = "pager" }]
            [[notify.command]]
            program = "/usr/local/bin/notify"
            user = "1001"
            [[health.check]]
            name = "pg"
            type = "command"
            program = "pg_isready"
            user = "postgres"
            [[policy]]
            name = "p"
            kind = "disk.*"
            effect = "add_actions"
            actions = [{ do = "exec", program = "x", user = "bad user" }]
            "#,
        )
        .unwrap();
        let users = c.command_users();
        let has = |place: &str, user: &str| users.iter().any(|(p, u)| p == place && u == user);
        assert!(has("daemon.command_user", "warden-hooks"), "{users:?}");
        assert!(has("memory.on_critical[0]", "pager"), "{users:?}");
        assert!(has("notify.command[0]", "1001"), "{users:?}");
        assert!(has("health.check[0]", "postgres"), "{users:?}");
        assert!(has("policy[0].actions[0]", "bad user"), "{users:?}");
        assert_eq!(users.len(), 5, "{users:?}");
        let errs = c.validate();
        assert_eq!(errs.len(), 1, "{errs:?}");
        assert!(errs[0].contains("\"bad user\""), "{errs:?}");
        for ok in ["nobody", "_apt", "www-data", "user.name", "machine$", "65534"] {
            assert!(valid_user(ok), "{ok}");
        }
        for bad in ["", "-x", "a b", "a:b", "1x$", "../x"] {
            assert!(!valid_user(bad), "{bad}");
        }
    }

    #[test]
    fn every_glob_list_and_interval_is_validated() {
        let c: Config = toml::from_str(
            r#"[cpu]
hog_ignore = ["[x"]
[memory]
interval = "0s"
[memory.culprit]
avoid = ["{a"]
[systemd]
ignore = ["[y"]
[network]
ignore_interfaces = ["[z"]
[process]
ptrace_allow = ["[p"]
[[process.allowed_children]]
parent = "php-fpm*"
child = "[q"
[integrity]
suid_exclude = ["[s"]
[fim]
schedule = "0s"
[disk]
cleanup_target_percent = 99.0
"#,
        )
        .unwrap();
        let e = c.validate().join("\n");
        for want in [
            "cpu.hog_ignore",
            "memory.culprit.avoid",
            "systemd.ignore",
            "network.ignore_interfaces",
            "process.ptrace_allow",
            "process.allowed_children",
            "integrity.suid_exclude",
            "memory.interval must be > 0",
            "fim.schedule must be > 0",
            "disk.cleanup_target_percent (99)",
        ] {
            assert!(e.contains(want), "{want} missing in:\n{e}");
        }
        assert!(Config::default().validate().is_empty());
    }

    #[test]
    fn cleanup_globs_are_validated() {
        let c: Config = toml::from_str(
            r#"[disk]
cleanup = [
    { do = "delete_old", paths = ["tmp/**"], older_than = "1d" },
    { do = "delete_old", paths = ["/tmp/**"], older_than = "1d", exclude = ["/tmp/[bad"] },
    { do = "truncate_large", paths = ["/var/log/{a"], larger_than = "1GiB" },
]"#,
        )
        .unwrap();
        let e = c.validate().join("\n");
        assert!(e.contains(r#""tmp/**" must be an absolute path"#), "{e}");
        assert!(e.contains(r#"disk.cleanup exclude: invalid glob "/tmp/[bad""#), "{e}");
        assert!(e.contains(r#"disk.cleanup paths: invalid glob "/var/log/{a""#), "{e}");
        let d = Config::default();
        assert!(d.validate().is_empty());
        assert!(matches!(&d.disk.cleanup[3], ActionSpec::DeleteOld { age_from: AgeFrom::Newest, exclude, .. }
            if exclude.iter().any(|e| e == "/tmp/systemd-private-*")));
    }

    #[test]
    fn empty_config_is_valid() {
        let c: Config = toml::from_str("").unwrap();
        assert!(c.validate().is_empty(), "{:?}", c.validate());
        assert!(c.memory.enabled);
        assert_eq!(c.memory.swap_storm.sustain, secs(60));
    }

    #[test]
    fn firewall_names_and_prefix_are_validated() {
        let errs = |t: &str| toml::from_str::<Config>(t).unwrap().validate();
        assert!(errs("[actions.firewall]\nipv6_prefix = 56").is_empty());
        assert!(errs("[actions.firewall]\nipv6_prefix = 128").is_empty());
        assert!(errs("[actions.firewall]\nipv6_prefix = 32").iter().any(|e| e.contains("ipv6_prefix")));
        assert!(errs("[actions.firewall]\nipv6_prefix = 129").iter().any(|e| e.contains("ipv6_prefix")));
        // the names go into nft scripts
        assert!(errs("[actions.firewall]\ntable = 'warden; flush ruleset'").iter().any(|e| e.contains("table")));
        assert!(errs("[actions.firewall]\nset_v6 = 'blocklist4'").iter().any(|e| e.contains("must differ")));
        assert!(errs("[actions.firewall]\ntable = 'my_warden2'").is_empty());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        assert!(toml::from_str::<Config>("[memory]\nsustian = \"10s\"").is_err());
        assert!(toml::from_str::<Config>("[nonsense]\na = 1").is_err());
    }

    #[test]
    fn validation_catches_inverted_thresholds() {
        let c: Config = toml::from_str(
            "[disk]\nwarning_percent = 99.0\ncritical_percent = 90.0\n[[fim.site]]\nname='a'\nroot='rel'",
        )
        .unwrap();
        let errs = c.validate();
        assert!(errs.iter().any(|e| e.contains("disk.percent")));
        assert!(errs.iter().any(|e| e.contains("absolute")));
    }

    #[test]
    fn new_sections_parse_and_validate() {
        let c: Config = toml::from_str(
            r#"
            [[process.limit]]
            name = "stuck php"
            comm = ["php-fpm*"]
            cpu_percent = 90.0
            cpu_duration = "5m"
            actions = ["kill"]
            [[health.check]]
            name = "api"
            type = "http"
            url = "http://127.0.0.1:8080/health"
            unit = "api.service"
            [[health.check]]
            name = "pg"
            type = "command"
            program = "pg_isready"
            [[waf.log]]
            path = "/var/log/apache2/modsec_audit.log"
            [tuning]
            auto_grow = true
            "#,
        )
        .unwrap();
        assert!(c.validate().is_empty(), "{:?}", c.validate());
        assert_eq!(c.health.checks[0].failures, 3);
        assert_eq!(parse_status_ranges("200-399,418"), Some(vec![(200, 399), (418, 418)]));
        let bad: Config =
            toml::from_str("[[health.check]]\nname='x'\ntype='tcp'\n[[process.limit]]\nname='y'\ncomm=['a']\n")
                .unwrap();
        let e = bad.validate();
        assert!(e.iter().any(|m| m.contains("host:port")));
        assert!(e.iter().any(|m| m.contains("needs cpu_percent")));
    }

    #[test]
    fn site_defaults_apply() {
        let c: Config = toml::from_str("[[fim.site]]\nname = 'main'\nroot = '/var/www/html'").unwrap();
        assert!(c.fim.sites[0].include.iter().any(|g| g == "**/*.php"));
        assert!(c.fim.sites[0].no_scripts.iter().any(|g| g.starts_with("wp-content")));
    }
}
