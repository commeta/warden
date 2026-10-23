//! # warden-respond
//!
//! Executes remediation actions under strict safety rules:
//!
//! * **identity pinning** — processes are signalled through pidfds after the
//!   start time is re-verified (no PID-reuse accidents);
//! * **protection lists** — PID 1, kernel threads, Warden itself, sshd,
//!   systemd, journald and anything the operator lists are untouchable;
//! * **circuit breakers** — global budgets for kills and destructive actions
//!   per hour, per-target cooldowns;
//! * **dry-run** — everything is evaluated and logged, nothing destructive
//!   happens;
//! * **path guards** — cleanup and quarantine never touch system locations.
//!
//! The executor ([`Responder`]) is owned by one thread and runs actions one
//! at a time; a second lane ([`Responder::lane`]) on another thread shares
//! its budgets and cooldowns, so containment never waits behind a cleanup.
//! What the control socket also needs (blocklist, quarantine, sysctl
//! journal) lives in [`Handles`] with locks of its own, so an operator
//! command never waits for a long action in progress.
#![cfg_attr(test, allow(clippy::unwrap_used))]

pub mod cleanup;
pub mod firewall;
pub mod guard;
pub mod quarantine;
pub mod snapshot;
pub mod tune;

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use warden_core::config::ActionsConfig;
use warden_core::protect::{ProcAttrs, Protection};
use warden_core::ratelimit::{Cooldown, SlidingWindow};
use warden_core::sync::{lock, read, write};
use warden_core::units::human_bytes;
use warden_core::{ActionSpec, Config, Event, ProcessRef, Subject};
use warden_sys::clock;
use warden_sys::pidfd::{self, KillOutcome, Target};
use warden_sys::{cgroup, mounts, process};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Done,
    DryRun,
    Skipped,
    Refused,
    Failed,
}

#[derive(Debug, Clone, Serialize)]
pub struct ActionResult {
    pub action: String,
    pub target: String,
    pub status: Status,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freed_bytes: Option<u64>,
}

impl ActionResult {
    fn new(spec: &ActionSpec, target: impl Into<String>, status: Status, message: impl Into<String>) -> Self {
        Self { action: spec.name().into(), target: target.into(), status, message: message.into(), freed_bytes: None }
    }
}

/// The responder's state that operators also reach through the control
/// socket. Cheap to clone (shared); every part has its own lock, held only
/// for the one operation.
#[derive(Clone)]
pub struct Handles {
    pub firewall: Arc<Mutex<firewall::Firewall>>,
    pub quarantine: Arc<RwLock<quarantine::Quarantine>>,
    pub tuner: Arc<Mutex<tune::Tuner>>,
}

impl Handles {
    fn new(cfg: &Config) -> Self {
        Self {
            firewall: Arc::new(Mutex::new(firewall::Firewall::new(&cfg.actions.firewall, &cfg.auth.allowlist))),
            quarantine: Arc::new(RwLock::new(quarantine::Quarantine::new(&cfg.actions.quarantine_dir))),
            tuner: Arc::new(Mutex::new(tune::Tuner::new(&cfg.daemon.state_dir, cfg.tuning.persist))),
        }
    }

    /// Apply a new configuration in place (the objects are shared with the
    /// control socket, so they are updated, not replaced).
    fn reconfigure(&self, cfg: &Config) {
        *lock(&self.firewall) = firewall::Firewall::new(&cfg.actions.firewall, &cfg.auth.allowlist);
        *write(&self.quarantine) = quarantine::Quarantine::new(&cfg.actions.quarantine_dir);
        *lock(&self.tuner) = tune::Tuner::new(&cfg.daemon.state_dir, cfg.tuning.persist);
    }
}

/// Circuit breakers shared by every lane of the executor: one hour, one
/// budget, however many threads run actions. Each lock is held for a check
/// or a record, never while an action runs.
struct Limits {
    kills: SlidingWindow,
    budget: SlidingWindow,
    cooldown: Cooldown<String>,
    /// Restarts per unit and hour: the one budget, `systemd.max_restarts_per_hour`.
    unit_restarts: HashMap<String, SlidingWindow>,
    last_snapshot: Option<Instant>,
}

pub struct Responder {
    cfg: ActionsConfig,
    protection: Protection,
    limits: Arc<Mutex<Limits>>,
    max_restarts: usize,
    quarantine_roots: Vec<PathBuf>,
    /// `daemon.command_user`: who `exec` actions run as unless they say.
    command_user: Option<String>,
    handles: Handles,
}

impl std::fmt::Debug for Responder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Responder").finish_non_exhaustive()
    }
}

fn target_key(ev: &Event) -> String {
    match &ev.subject {
        Subject::Process(p) => format!("pid:{}:{}", p.pid, p.start_time),
        other => other.to_string(),
    }
}

/// Did an action really do something (or try to)? Only those count
/// against the budgets and arm the cooldown; a refusal, a skip or a dry run
/// does not.
fn attempted(s: Status) -> bool {
    matches!(s, Status::Done | Status::Failed)
}

/// SIGTERM → `grace` → SIGKILL for one process.
fn kill_one(spec: &ActionSpec, p: &ProcessRef, grace: Duration, rss: u64) -> ActionResult {
    let target = p.to_string();
    match pidfd::terminate(p.pid, p.start_time, grace) {
        Ok(KillOutcome::AlreadyGone) => {
            ActionResult::new(spec, target, Status::Skipped, "process exited before the signal")
        }
        Ok(KillOutcome::Stuck) => {
            ActionResult::new(spec, target, Status::Failed, "process survived SIGKILL (uninterruptible sleep?)")
        }
        Ok(o) => {
            let mut r = ActionResult::new(
                spec,
                target,
                Status::Done,
                format!("{o:?} after {grace:?}, released ~{}", human_bytes(rss)).to_lowercase(),
            );
            r.freed_bytes = Some(rss);
            r
        }
        Err(e) => ActionResult::new(spec, target, Status::Failed, e.to_string()),
    }
}

impl Responder {
    pub fn new(cfg: &Config) -> Self {
        let a = &cfg.actions;
        Self {
            cfg: a.clone(),
            protection: Protection::new(&cfg.protection),
            limits: Arc::new(Mutex::new(Limits {
                kills: SlidingWindow::new(Duration::from_secs(3600), a.max_kills_per_hour),
                budget: SlidingWindow::new(Duration::from_secs(3600), a.max_actions_per_hour),
                cooldown: Cooldown::new(a.cooldown),
                unit_restarts: HashMap::new(),
                last_snapshot: None,
            })),
            max_restarts: cfg.systemd.max_restarts_per_hour,
            quarantine_roots: cfg.fim.sites.iter().map(|s| s.root.clone()).collect(),
            command_user: cfg.daemon.command_user.clone(),
            handles: Handles::new(cfg),
        }
    }

    /// What the control socket may use while this responder is busy.
    pub fn handles(&self) -> Handles {
        self.handles.clone()
    }

    /// Another executor for a second thread, sharing this one's budgets,
    /// cooldowns, snapshot interval and handles. The daemon runs urgent
    /// containment on one lane and slow actions on the other; every kill
    /// goes to the same lane, so two kills still never race.
    pub fn lane(&self) -> Self {
        Self {
            cfg: self.cfg.clone(),
            protection: self.protection.clone(),
            limits: self.limits.clone(),
            max_restarts: self.max_restarts,
            quarantine_roots: self.quarantine_roots.clone(),
            command_user: self.command_user.clone(),
            handles: self.handles.clone(),
        }
    }

    /// Apply a new configuration but keep budgets/cooldowns (a reload must
    /// not reset the circuit breakers).
    pub fn reconfigure(&mut self, cfg: &Config) {
        let a = &cfg.actions;
        self.cfg = a.clone();
        self.protection = Protection::new(&cfg.protection);
        self.max_restarts = cfg.systemd.max_restarts_per_hour;
        {
            let mut l = lock(&self.limits);
            l.kills.set_max(a.max_kills_per_hour);
            l.budget.set_max(a.max_actions_per_hour);
            for w in l.unit_restarts.values_mut() {
                w.set_max(self.max_restarts);
            }
            l.cooldown.set_period(a.cooldown);
        }
        self.quarantine_roots = cfg.fim.sites.iter().map(|s| s.root.clone()).collect();
        self.command_user = cfg.daemon.command_user.clone();
        self.handles.reconfigure(cfg);
    }

    /// Execute all actions attached to an event, in order.
    pub fn execute(&mut self, ev: &Event, dry_run: bool, extras: &snapshot::Extras) -> Vec<ActionResult> {
        let mut out = Vec::new();
        let stop_below = ev.details.get("stop_below_percent").and_then(|v| v.as_f64());
        for spec in &ev.actions {
            // Disk playbooks stop as soon as the target is reached.
            if spec.is_cleanup()
                && let (Some(target), Subject::Mount { path, .. }) = (stop_below, &ev.subject)
                && let Ok(u) = mounts::statvfs(path)
                && u.used_percent() < target
                && !dry_run
            {
                out.push(ActionResult::new(
                    spec,
                    path.clone(),
                    Status::Skipped,
                    format!("usage {:.1}% already below {target}%", u.used_percent()),
                ));
                continue;
            }
            // kind + parameters + target: the steps of a playbook are distinct
            // actions even when they share a kind (two `delete_old` steps)
            let key = format!("{}@{}", spec.cooldown_key(), target_key(ev));
            // Checked here, armed only once the action has really been
            // attempted: what a dry run would have done, or a step the budget
            // refused, must not hold back the next real occurrence.
            if spec.is_destructive() && lock(&self.limits).cooldown.cooling(&key, clock::now()) {
                out.push(ActionResult::new(
                    spec,
                    target_key(ev),
                    Status::Skipped,
                    "cooldown: same action on the same target ran recently",
                ));
                continue;
            }
            if spec.is_destructive() && dry_run {
                out.push(ActionResult::new(
                    spec,
                    target_key(ev),
                    Status::DryRun,
                    format!("dry-run: would {}", describe(spec, ev)),
                ));
                continue;
            }
            // Reserved here (so the other lane sees it), given back unless
            // the action was really attempted: a refused (protected target,
            // another budget), skipped (gone, nothing to do) or dry-run
            // action must not use up the hour. (0.13.3 charged before
            // running, whatever happened.)
            let reserved = if spec.is_destructive() {
                let now = clock::now();
                let mut l = lock(&self.limits);
                if !l.budget.peek(now) {
                    drop(l);
                    out.push(ActionResult::new(
                        spec,
                        target_key(ev),
                        Status::Refused,
                        format!("circuit breaker: max_actions_per_hour ({}) reached", self.cfg.max_actions_per_hour),
                    ));
                    continue;
                }
                l.budget.record(now);
                Some(now)
            } else {
                None
            };
            let r = self.run_one(spec, ev, extras);
            if let Some(at) = reserved {
                let mut l = lock(&self.limits);
                if attempted(r.status) {
                    l.cooldown.arm(&key, clock::now());
                } else {
                    l.budget.unrecord(at);
                }
            }
            tracing::info!(action = %r.action, target = %r.target, status = ?r.status, message = %r.message, event = %ev.kind, "action executed");
            out.push(r);
        }
        out
    }

    fn run_one(&mut self, spec: &ActionSpec, ev: &Event, extras: &snapshot::Extras) -> ActionResult {
        match spec {
            ActionSpec::Snapshot => self.snapshot(spec, ev, extras),
            ActionSpec::Kill { tree, grace } => self.kill(spec, ev, *tree, grace.unwrap_or(self.cfg.kill_grace)),
            ActionSpec::Stop => self.stop(spec, ev),
            ActionSpec::FreezeCgroup | ActionSpec::KillCgroup => self.cgroup_action(spec, ev),
            ActionSpec::RestartUnit { unit } => self.restart_unit(spec, ev, unit.clone()),
            ActionSpec::Quarantine => self.do_quarantine(spec, ev),
            ActionSpec::BlockIp { ttl } => self.block_ip(spec, ev, *ttl),
            ActionSpec::JournalVacuum { max_size, max_age } => {
                cleanup_result(spec, ev, cleanup::journal_vacuum(max_size.map(|s| s.as_u64()), *max_age))
            }
            ActionSpec::DeleteOld { paths, older_than, max_files, age_from, exclude } => cleanup_result(
                spec,
                ev,
                cleanup::delete_old(paths, *older_than, *max_files, mount_dev(ev), *age_from, exclude),
            ),
            ActionSpec::TruncateLarge { paths, larger_than } => {
                cleanup_result(spec, ev, cleanup::truncate_large(paths, larger_than.as_u64(), mount_dev(ev)))
            }
            ActionSpec::TruncateDeleted { min_size } => {
                cleanup_result(spec, ev, cleanup::truncate_deleted(min_size.as_u64(), mount_dev(ev)))
            }
            ActionSpec::AptClean => cleanup_result(spec, ev, cleanup::apt_clean()),
            ActionSpec::Throttle { nice, io_idle } => self.throttle(spec, ev, *nice, *io_idle),
            ActionSpec::LimitUnit { unit, cpu_quota, memory_high, memory_max } => {
                self.limit_unit(spec, ev, unit.clone(), cpu_quota.clone(), *memory_high, *memory_max)
            }
            ActionSpec::Sysctl { key, value } => {
                let ram = warden_sys::mem::meminfo().map(|m| m.total).unwrap_or(0);
                match lock(&self.handles.tuner).apply(key, value, ram) {
                    Ok(m) => ActionResult::new(spec, key.clone(), Status::Done, m),
                    Err(m) if m.contains("not an adjustable") || m.contains("outside the safe") => {
                        ActionResult::new(spec, key.clone(), Status::Refused, m)
                    }
                    Err(m) => ActionResult::new(spec, key.clone(), Status::Failed, m),
                }
            }
            ActionSpec::Exec { program, args, timeout, user } => {
                let user = user.as_deref().or(self.command_user.as_deref());
                self.exec(spec, ev, program, args, timeout.unwrap_or(self.cfg.exec_timeout), user)
            }
        }
    }

    fn snapshot(&mut self, spec: &ActionSpec, ev: &Event, extras: &snapshot::Extras) -> ActionResult {
        {
            let mut l = lock(&self.limits);
            if l.last_snapshot
                .is_some_and(|t| clock::now().saturating_duration_since(t) < self.cfg.snapshot_min_interval)
            {
                return ActionResult::new(spec, "system", Status::Skipped, "a snapshot was taken recently");
            }
            l.last_snapshot = Some(clock::now());
        }
        match snapshot::take(&self.cfg.snapshot_dir, self.cfg.snapshot_keep, &ev.kind, ev, extras) {
            Ok(p) => ActionResult::new(spec, "system", Status::Done, format!("snapshot saved to {}", p.display())),
            Err(e) => ActionResult::new(spec, "system", Status::Failed, e.to_string()),
        }
    }

    /// Validate a process subject: alive, same identity, not protected.
    fn check_process(&self, p: &ProcessRef) -> Result<(), (Status, String)> {
        let st =
            process::read_stat(p.pid).map_err(|_| (Status::Skipped, format!("process {} already exited", p.pid)))?;
        if st.starttime != p.start_time {
            return Err((Status::Skipped, format!("PID {} was reused by another process", p.pid)));
        }
        let exe = process::exe(p.pid);
        let cg = process::cgroup(p.pid);
        let uid = process::read_status(p.pid).ok().map(|s| s.uid[0]);
        // The name is the process's own claim: it protects only a process
        // that really is that program (see `warden_core::protect`).
        let genuine = exe.as_deref().and_then(|e| process::verify_daemon(p.pid, &st.comm, e));
        self.protection
            .check(&ProcAttrs {
                pid: p.pid,
                comm: &st.comm,
                exe: exe.as_deref(),
                cgroup: cg.as_deref(),
                uid,
                kernel_thread: process::is_kernel_thread(&st),
                genuine,
            })
            .map_err(|r| (Status::Refused, format!("protected: {r}")))
    }

    fn kill(&mut self, spec: &ActionSpec, ev: &Event, tree: bool, grace: Duration) -> ActionResult {
        let Some(p) = ev.process() else {
            return ActionResult::new(spec, ev.subject.to_string(), Status::Skipped, "event has no process subject");
        };
        let target = p.to_string();
        if let Err((s, m)) = self.check_process(p) {
            return ActionResult::new(spec, target, s, m);
        }
        if !lock(&self.limits).kills.peek(clock::now()) {
            return ActionResult::new(
                spec,
                target,
                Status::Refused,
                format!("circuit breaker: max_kills_per_hour ({}) reached", self.cfg.max_kills_per_hour),
            );
        }
        let rss = process::read_status(p.pid).map(|s| s.vm_rss + s.vm_swap).unwrap_or(0);
        let r = if tree { self.kill_tree(spec, p, grace, rss) } else { kill_one(spec, p, grace, rss) };
        // a kill that happened counts; one refused or of a process already gone does not
        if attempted(r.status) {
            lock(&self.limits).kills.record(clock::now());
        }
        r
    }

    /// `kill { tree = true }`. 0.13.3 terminated the descendants one at a
    /// time, waiting up to 500 ms for each, while the parent kept running
    /// and forking: a tree of a thousand processes held the responder for
    /// minutes. Now the whole tree is stopped first — the parent first, then
    /// whatever it forked meanwhile, until a pass finds nothing new (a
    /// stopped process cannot fork) — and then every process gets SIGKILL,
    /// all under one deadline (`grace`, at least a second). When the tree is
    /// everything in its unit's cgroup, `cgroup.kill` does it atomically.
    fn kill_tree(&mut self, spec: &ActionSpec, p: &ProcessRef, grace: Duration, rss: u64) -> ActionResult {
        let target = p.to_string();
        let deadline = Instant::now() + grace.max(Duration::from_secs(1));
        let root = match Target::open(p.pid, p.start_time) {
            Ok(t) => t,
            Err(_) => return ActionResult::new(spec, target, Status::Skipped, "process exited before the signal"),
        };
        // The whole unit? (everything in the cgroup belongs to the tree)
        if let Some(cg) = p.cgroup.clone().or_else(|| process::cgroup(p.pid))
            && cgroup::unit_of(&cg).is_some_and(|u| u.ends_with(".service") && !self.protection.is_unit_protected(&u))
        {
            let table = process::snapshot_light();
            let mut tree: HashSet<i32> = process::descendants(&table, p.pid).into_iter().collect();
            tree.insert(p.pid);
            let members = cgroup::procs(&cg);
            let all_ours = !members.is_empty()
                && members.iter().all(|pid| {
                    tree.contains(pid)
                        && process::start_time(*pid).is_some_and(|st| {
                            self.check_process(&ProcessRef { pid: *pid, start_time: st, ..Default::default() }).is_ok()
                        })
                });
            if all_ours && cgroup::kill(&cg).is_ok() {
                let gone = root.wait_exit(deadline.saturating_duration_since(Instant::now()));
                let mut r = ActionResult::new(
                    spec,
                    target,
                    if gone { Status::Done } else { Status::Failed },
                    format!(
                        "killed the whole cgroup {cg} ({} processes) with cgroup.kill{}; released ~{}",
                        members.len(),
                        if gone { "" } else { ", but the process has not exited (uninterruptible sleep?)" },
                        human_bytes(rss)
                    ),
                );
                r.freed_bytes = Some(rss);
                return r;
            }
        }
        // 1. stop: the parent, then its descendants, until nothing new appears
        if root.signal(libc::SIGSTOP).is_err() {
            return ActionResult::new(spec, target, Status::Skipped, "process exited before the signal");
        }
        let mut stopped = vec![root];
        let mut seen: HashSet<(i32, u64)> = HashSet::from([(p.pid, p.start_time)]);
        let mut protected = 0;
        for _ in 0..16 {
            let table = process::snapshot_light();
            let mut new = 0;
            for pid in process::descendants(&table, p.pid) {
                let Some(st) = table.get(&pid).map(|i| i.start_time) else { continue };
                if !seen.insert((pid, st)) {
                    continue;
                }
                new += 1;
                if self.check_process(&ProcessRef { pid, start_time: st, ..Default::default() }).is_err() {
                    protected += 1;
                    continue;
                }
                if let Ok(t) = Target::open(pid, st)
                    && t.signal(libc::SIGSTOP).is_ok()
                {
                    stopped.push(t);
                }
            }
            if new == 0 || Instant::now() >= deadline {
                break;
            }
        }
        // 2. kill everything that was stopped, 3. wait under one deadline
        for t in &stopped {
            let _ = t.signal(libc::SIGKILL);
        }
        let stuck = stopped.iter().filter(|t| !t.wait_exit(deadline.saturating_duration_since(Instant::now()))).count();
        let n = stopped.len();
        let mut msg = format!("stopped and killed {n} process(es) of the tree, released ~{}", human_bytes(rss));
        if protected > 0 {
            msg += &format!("; {protected} protected descendant(s) left running");
        }
        if stuck > 0 {
            msg += &format!("; {stuck} did not exit before the deadline (uninterruptible sleep?)");
        }
        let mut r = ActionResult::new(spec, target, if stuck == 0 { Status::Done } else { Status::Failed }, msg);
        r.freed_bytes = Some(rss);
        r
    }

    fn stop(&mut self, spec: &ActionSpec, ev: &Event) -> ActionResult {
        let Some(p) = ev.process() else {
            return ActionResult::new(spec, ev.subject.to_string(), Status::Skipped, "event has no process subject");
        };
        let target = p.to_string();
        if let Err((s, m)) = self.check_process(p) {
            return ActionResult::new(spec, target, s, m);
        }
        let table = process::snapshot();
        let mut n = 0;
        let mut pids = vec![(p.pid, p.start_time)];
        pids.extend(
            process::descendants(&table, p.pid).into_iter().filter_map(|c| table.get(&c).map(|i| (c, i.start_time))),
        );
        for (pid, st) in pids {
            let cref = ProcessRef { pid, start_time: st, ..Default::default() };
            if self.check_process(&cref).is_ok()
                && let Ok(t) = Target::open(pid, st)
                && t.signal(libc::SIGSTOP).is_ok()
            {
                n += 1;
            }
        }
        if n == 0 {
            return ActionResult::new(spec, target, Status::Failed, "could not stop the process");
        }
        ActionResult::new(
            spec,
            target,
            Status::Done,
            format!("stopped {n} process(es) with SIGSTOP; inspect /proc/{}/ then `kill -CONT` or `kill -9`", p.pid),
        )
    }

    fn cgroup_action(&mut self, spec: &ActionSpec, ev: &Event) -> ActionResult {
        let path = match &ev.subject {
            Subject::Cgroup { path } => Some(path.clone()),
            Subject::Process(p) => p.cgroup.clone().or_else(|| process::cgroup(p.pid)),
            _ => None,
        };
        let Some(path) = path else {
            return ActionResult::new(spec, ev.subject.to_string(), Status::Skipped, "no cgroup for subject");
        };
        if !cgroup::is_v2() {
            return ActionResult::new(spec, path, Status::Failed, "cgroup v2 is not mounted");
        }
        if let Some(unit) = cgroup::unit_of(&path)
            && self.protection.is_unit_protected(&unit)
        {
            return ActionResult::new(spec, path, Status::Refused, format!("unit {unit} is protected"));
        }
        for pid in cgroup::procs(&path) {
            if let Some(st) = process::start_time(pid) {
                let r = ProcessRef { pid, start_time: st, ..Default::default() };
                if let Err((Status::Refused, m)) = self.check_process(&r) {
                    return ActionResult::new(
                        spec,
                        path,
                        Status::Refused,
                        format!("cgroup contains a protected process: {m}"),
                    );
                }
            }
        }
        let is_kill = matches!(spec, ActionSpec::KillCgroup);
        if is_kill && !lock(&self.limits).kills.peek(clock::now()) {
            return ActionResult::new(spec, path, Status::Refused, "circuit breaker: max_kills_per_hour reached");
        }
        let res = if is_kill { cgroup::kill(&path) } else { cgroup::freeze(&path, true) };
        if is_kill && res.is_ok() {
            lock(&self.limits).kills.record(clock::now());
        }
        match res {
            Ok(()) if is_kill => ActionResult::new(spec, path, Status::Done, "all processes in the cgroup were killed"),
            Ok(()) => ActionResult::new(
                spec,
                path.clone(),
                Status::Done,
                format!("cgroup frozen; thaw with: echo 0 > /sys/fs/cgroup{path}/cgroup.freeze"),
            ),
            Err(e) => ActionResult::new(spec, path, Status::Failed, e.to_string()),
        }
    }

    fn throttle(&mut self, spec: &ActionSpec, ev: &Event, nice: i32, io_idle: bool) -> ActionResult {
        let Some(p) = ev.process() else {
            return ActionResult::new(spec, ev.subject.to_string(), Status::Skipped, "event has no process subject");
        };
        let target = p.to_string();
        if let Err((s, m)) = self.check_process(p) {
            return ActionResult::new(spec, target, s, m);
        }
        match warden_sys::sched::throttle_process(p.pid, nice, io_idle) {
            Ok(n) => ActionResult::new(
                spec,
                target,
                Status::Done,
                format!(
                    "{n} thread(s) set to nice {nice}{}; undo with `renice 0 -p {}`",
                    if io_idle { " and idle I/O class" } else { "" },
                    p.pid
                ),
            ),
            Err(e) => ActionResult::new(spec, target, Status::Failed, e.to_string()),
        }
    }

    fn limit_unit(
        &mut self,
        spec: &ActionSpec,
        ev: &Event,
        unit: Option<String>,
        cpu_quota: Option<String>,
        memory_high: Option<warden_core::ByteSize>,
        memory_max: Option<warden_core::ByteSize>,
    ) -> ActionResult {
        let unit = unit.or_else(|| match &ev.subject {
            Subject::Unit { name } => Some(name.clone()),
            Subject::Process(p) => {
                p.cgroup.clone().or_else(|| process::cgroup(p.pid)).as_deref().and_then(cgroup::unit_of)
            }
            _ => None,
        });
        let Some(unit) = unit else {
            return ActionResult::new(spec, ev.subject.to_string(), Status::Skipped, "no systemd unit for subject");
        };
        if self.protection.is_unit_protected(&unit) {
            return ActionResult::new(spec, unit.clone(), Status::Refused, format!("unit {unit} is protected"));
        }
        let mut props = Vec::new();
        if let Some(q) = cpu_quota {
            let ok = q.strip_suffix('%').and_then(|n| n.parse::<u32>().ok()).is_some_and(|n| n > 0);
            if !ok {
                return ActionResult::new(
                    spec,
                    unit,
                    Status::Failed,
                    format!("invalid cpu_quota {q:?} (use e.g. \"50%\")"),
                );
            }
            props.push(format!("CPUQuota={q}"));
        }
        if let Some(m) = memory_high {
            props.push(format!("MemoryHigh={}", m.as_u64()));
        }
        if let Some(m) = memory_max {
            props.push(format!("MemoryMax={}", m.as_u64()));
        }
        if props.is_empty() {
            return ActionResult::new(spec, unit, Status::Skipped, "no limits given");
        }
        let mut args = vec!["set-property", "--runtime", unit.as_str()];
        args.extend(props.iter().map(String::as_str));
        match warden_sys::cmd::run_cmd("systemctl", &args, Duration::from_secs(30)) {
            Ok(o) if o.status.success() => ActionResult::new(
                spec,
                unit.clone(),
                Status::Done,
                format!("{} (runtime only; undo: systemctl revert {unit} or reboot)", props.join(" ")),
            ),
            Ok(o) => {
                ActionResult::new(spec, unit, Status::Failed, String::from_utf8_lossy(&o.stderr).trim().to_owned())
            }
            Err(e) => ActionResult::new(spec, unit, Status::Failed, e.to_string()),
        }
    }

    fn restart_unit(&mut self, spec: &ActionSpec, ev: &Event, unit: Option<String>) -> ActionResult {
        let unit = unit.or_else(|| match &ev.subject {
            Subject::Unit { name } => Some(name.clone()),
            Subject::Process(p) => p.cgroup.as_deref().and_then(cgroup::unit_of).filter(|u| u.ends_with(".service")),
            _ => None,
        });
        let Some(unit) = unit else {
            return ActionResult::new(spec, ev.subject.to_string(), Status::Skipped, "no unit to restart");
        };
        if self.protection.is_unit_protected(&unit) {
            return ActionResult::new(spec, unit.clone(), Status::Refused, format!("unit {unit} is protected"));
        }
        let max = self.max_restarts;
        let allowed = lock(&self.limits)
            .unit_restarts
            .entry(unit.clone())
            .or_insert_with(|| SlidingWindow::new(Duration::from_secs(3600), max))
            .peek(clock::now());
        if !allowed {
            return ActionResult::new(
                spec,
                unit,
                Status::Refused,
                format!("restart budget for this unit exhausted ({max} per hour, systemd.max_restarts_per_hour)"),
            );
        }
        let r = match warden_sys::cmd::run_cmd("systemctl", &["restart", &unit], Duration::from_secs(90)) {
            Ok(o) if o.status.success() => ActionResult::new(spec, unit.clone(), Status::Done, "restarted"),
            Ok(o) => ActionResult::new(
                spec,
                unit.clone(),
                Status::Failed,
                String::from_utf8_lossy(&o.stderr).trim().to_owned(),
            ),
            Err(e) => ActionResult::new(spec, unit.clone(), Status::Failed, e.to_string()),
        };
        if attempted(r.status)
            && let Some(w) = lock(&self.limits).unit_restarts.get_mut(&unit)
        {
            w.record(clock::now());
        }
        r
    }

    fn do_quarantine(&mut self, spec: &ActionSpec, ev: &Event) -> ActionResult {
        let Subject::File { path, site } = &ev.subject else {
            return ActionResult::new(spec, ev.subject.to_string(), Status::Skipped, "event has no file subject");
        };
        let p = guard::normalize(std::path::Path::new(path));
        if !p.is_absolute() {
            return ActionResult::new(spec, path.clone(), Status::Refused, format!("{path} is not absolute"));
        }
        // the policy is checked inside `put`, on the path the file's
        // directory really has once it is open
        let roots = &self.quarantine_roots;
        let put = read(&self.handles.quarantine)
            .put(&p, &ev.title, site.clone(), |real| guard::check_quarantine_path(real, roots));
        match put {
            Ok(e) => ActionResult::new(
                spec,
                path.clone(),
                Status::Done,
                format!(
                    "quarantined as {} (restore: wardenctl quarantine restore {}){}",
                    e.id,
                    e.id,
                    e.cleared_attributes
                        .map(|a| format!("; attacker had set chattr attributes ({a}) — cleared"))
                        .unwrap_or_default()
                ),
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ActionResult::new(spec, path.clone(), Status::Skipped, "file no longer exists")
            }
            // outside the allowed locations, or behind an untrusted symlink
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                ActionResult::new(spec, path.clone(), Status::Refused, e.to_string())
            }
            Err(e) => ActionResult::new(spec, path.clone(), Status::Failed, e.to_string()),
        }
    }

    fn block_ip(&mut self, spec: &ActionSpec, ev: &Event, ttl: Option<Duration>) -> ActionResult {
        let ip: Option<IpAddr> = match &ev.subject {
            Subject::Ip { addr } => Some(*addr),
            _ => ev.details.get("ip").and_then(|v| v.as_str()).and_then(|s| s.parse().ok()),
        };
        let Some(ip) = ip else {
            return ActionResult::new(spec, ev.subject.to_string(), Status::Skipped, "no IP address in event");
        };
        let blocked = lock(&self.handles.firewall).block(ip, ttl);
        match blocked {
            Ok(m) => ActionResult::new(spec, ip.to_string(), Status::Done, m),
            // allowlisted, or `[actions.firewall] enabled = false`: refused by
            // configuration, not a failure
            Err(m) if m.contains("allowlisted") || m.contains("disabled in configuration") => {
                ActionResult::new(spec, ip.to_string(), Status::Refused, m)
            }
            Err(m) => ActionResult::new(spec, ip.to_string(), Status::Failed, m),
        }
    }

    fn exec(
        &self,
        spec: &ActionSpec,
        ev: &Event,
        program: &str,
        args: &[String],
        timeout: Duration,
        user: Option<&str>,
    ) -> ActionResult {
        let creds = match user.map(warden_sys::cmd::Credentials::lookup).transpose() {
            Ok(c) => c,
            Err(e) => {
                return ActionResult::new(spec, program, Status::Failed, format!("user {}: {e}", user.unwrap_or("")));
            }
        };
        let mut run =
            warden_sys::cmd::Run::new(program, timeout).args(args).max_output(HOOK_OUTPUT_LIMIT).user(creds.as_ref());
        for (k, v) in ev.hook_env() {
            run = run.env(k, v);
        }
        let who = creds.as_ref().filter(|c| !c.is_root()).map(|c| format!(" (as {})", c.name)).unwrap_or_default();
        match run.run() {
            Ok(o) => {
                let text: String = String::from_utf8_lossy(&o.stdout).chars().take(500).collect();
                let status = if o.status.success() { Status::Done } else { Status::Failed };
                ActionResult::new(
                    spec,
                    program,
                    status,
                    format!("exit {}{who}: {}", o.status.code().unwrap_or(-1), text.trim()),
                )
            }
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => {
                ActionResult::new(spec, program, Status::Failed, format!("timed out after {timeout:?}"))
            }
            Err(e) => ActionResult::new(spec, program, Status::Failed, e.to_string()),
        }
    }
}

/// How much of a hook's output is kept (only the first 500 characters of
/// stdout are reported).
const HOOK_OUTPUT_LIMIT: usize = 64 * 1024;

fn mount_dev(ev: &Event) -> Option<u64> {
    let Subject::Mount { path, .. } = &ev.subject else { return None };
    let ms = mounts::mounts().ok()?;
    ms.iter().filter(|m| m.mount_point == *path).find_map(|m| m.dev())
}

fn cleanup_result(spec: &ActionSpec, ev: &Event, r: cleanup::Outcome) -> ActionResult {
    let target = ev.subject.to_string();
    match r {
        Ok((freed, _, msg)) => {
            let mut a = ActionResult::new(spec, target, Status::Done, msg);
            // Some(0) as well: "ran, freed nothing" is reported as a notice
            a.freed_bytes = Some(freed);
            a
        }
        Err(e) => ActionResult::new(spec, target, Status::Failed, e),
    }
}

/// Human description used in dry-run results.
pub fn describe(spec: &ActionSpec, ev: &Event) -> String {
    match spec {
        ActionSpec::Kill { tree, .. } => {
            format!("terminate {}{}", ev.subject, if *tree { " and its descendants" } else { "" })
        }
        ActionSpec::Stop => format!("SIGSTOP {}", ev.subject),
        ActionSpec::Quarantine => format!("quarantine {}", ev.subject),
        ActionSpec::BlockIp { ttl } => format!(
            "block {} for {:?}",
            ev.details.get("ip").and_then(|v| v.as_str()).map(str::to_owned).unwrap_or_else(|| ev.subject.to_string()),
            ttl
        ),
        ActionSpec::RestartUnit { unit } => {
            format!("restart {}", unit.clone().unwrap_or_else(|| ev.subject.to_string()))
        }
        ActionSpec::Exec { program, user, .. } => match user {
            Some(u) => format!("run {program} as {u}"),
            None => format!("run {program}"),
        },
        other => format!("{} on {}", other.name(), ev.subject),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warden_core::Severity;

    fn ev_for(pid: i32, st: u64, actions: Vec<ActionSpec>) -> Event {
        Event::new("test", Severity::Critical, "t")
            .subject(Subject::Process(ProcessRef { pid, start_time: st, comm: "sleep".into(), ..Default::default() }))
            .actions(actions)
    }

    #[test]
    fn dry_run_does_nothing() {
        let mut r = Responder::new(&Config::default());
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let st = process::start_time(pid).unwrap();
        let res =
            r.execute(&ev_for(pid, st, vec![ActionSpec::Kill { tree: false, grace: None }]), true, &Default::default());
        assert_eq!(res[0].status, Status::DryRun);
        assert!(process::start_time(pid).is_some());
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn kills_and_respects_cooldown_and_reuse() {
        let mut r = Responder::new(&Config::default());
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let st = process::start_time(pid).unwrap();
        let waiter = std::thread::spawn(move || child.wait());
        // wrong start time → treated as PID reuse
        let res = r.execute(
            &ev_for(pid, st + 5, vec![ActionSpec::Kill { tree: false, grace: Some(Duration::from_millis(500)) }]),
            false,
            &Default::default(),
        );
        assert_eq!(res[0].status, Status::Skipped, "{}", res[0].message);
        let mut r = Responder::new(&Config::default());
        let res = r.execute(
            &ev_for(pid, st, vec![ActionSpec::Kill { tree: false, grace: Some(Duration::from_millis(500)) }]),
            false,
            &Default::default(),
        );
        assert_eq!(res[0].status, Status::Done, "{}", res[0].message);
        waiter.join().unwrap().unwrap();
        let res = r.execute(
            &ev_for(pid, st, vec![ActionSpec::Kill { tree: false, grace: None }]),
            false,
            &Default::default(),
        );
        assert_eq!(res[0].status, Status::Skipped);
    }

    #[test]
    fn refuses_protected_and_self() {
        let mut r = Responder::new(&Config::default());
        let me = std::process::id() as i32;
        let st = process::start_time(me).unwrap();
        let res =
            r.execute(&ev_for(me, st, vec![ActionSpec::Kill { tree: false, grace: None }]), false, &Default::default());
        assert_eq!(res[0].status, Status::Refused);
        let res = r.execute(
            &ev_for(1, process::start_time(1).unwrap_or(0), vec![ActionSpec::Stop]),
            false,
            &Default::default(),
        );
        assert_ne!(res[0].status, Status::Done);
    }

    #[test]
    fn throttle_lowers_priority() {
        let mut r = Responder::new(&Config::default());
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let st = process::start_time(pid).unwrap();
        let res = r.execute(
            &ev_for(pid, st, vec![ActionSpec::Throttle { nice: 19, io_idle: true }]),
            false,
            &Default::default(),
        );
        assert_eq!(res[0].status, Status::Done, "{}", res[0].message);
        assert_eq!(process::read_stat(pid).unwrap().nice, 19);
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn sysctl_action_is_gated() {
        let mut r = Responder::new(&Config::default());
        let ev = Event::new("t", Severity::Warning, "t")
            .actions(vec![ActionSpec::Sysctl { key: "vm.swappiness".into(), value: "1".into() }]);
        assert_eq!(r.execute(&ev, false, &Default::default())[0].status, Status::Refused);
    }

    #[test]
    fn kill_budget_trips() {
        let mut cfg = Config::default();
        cfg.actions.max_kills_per_hour = 1;
        let mut r = Responder::new(&cfg);
        let mut a = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let mut b = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let (pa, pb) = (a.id() as i32, b.id() as i32);
        let (sa, sb) = (process::start_time(pa).unwrap(), process::start_time(pb).unwrap());
        let ra = r.execute(
            &ev_for(pa, sa, vec![ActionSpec::Kill { tree: false, grace: Some(Duration::from_millis(300)) }]),
            false,
            &Default::default(),
        );
        let rb = r.execute(
            &ev_for(pb, sb, vec![ActionSpec::Kill { tree: false, grace: Some(Duration::from_millis(300)) }]),
            false,
            &Default::default(),
        );
        assert_eq!(ra[0].status, Status::Done);
        assert_eq!(rb[0].status, Status::Refused);
        a.wait().unwrap();
        b.kill().unwrap();
        b.wait().unwrap();
    }

    /// Budgets are charged for what was done, not for what was asked: an
    /// action on a process that is already gone, a protected one, or a dry
    /// run leaves the hour's budget alone. (0.13.3 charged before running.)
    #[test]
    fn budgets_are_charged_only_for_attempted_actions() {
        let mut cfg = Config::default();
        cfg.actions.max_kills_per_hour = 1;
        cfg.actions.max_actions_per_hour = 1;
        let mut r = Responder::new(&cfg);
        let kill = || vec![ActionSpec::Kill { tree: false, grace: Some(Duration::from_millis(300)) }];
        // gone before the signal
        let mut gone = std::process::Command::new("true").spawn().unwrap();
        let (pg, sg) = (gone.id() as i32, process::start_time(gone.id() as i32).unwrap_or(1));
        gone.wait().unwrap();
        assert_eq!(r.execute(&ev_for(pg, sg, kill()), false, &Default::default())[0].status, Status::Skipped);
        // protected: Warden itself
        let me = std::process::id() as i32;
        let st = process::start_time(me).unwrap();
        assert_eq!(r.execute(&ev_for(me, st, kill()), false, &Default::default())[0].status, Status::Refused);
        // a dry run
        let mut a = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pa = a.id() as i32;
        let sa = process::start_time(pa).unwrap();
        assert_eq!(r.execute(&ev_for(pa, sa, kill()), true, &Default::default())[0].status, Status::DryRun);
        // ...the one real kill of the hour is still there
        assert_eq!(r.execute(&ev_for(pa, sa, kill()), false, &Default::default())[0].status, Status::Done);
        a.wait().unwrap();
        let mut b = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pb = b.id() as i32;
        let sb = process::start_time(pb).unwrap();
        let rb = r.execute(&ev_for(pb, sb, kill()), false, &Default::default());
        assert_eq!(rb[0].status, Status::Refused, "and now it is used: {}", rb[0].message);
        b.kill().unwrap();
        b.wait().unwrap();
    }

    /// One restart budget per unit, from `systemd.max_restarts_per_hour`
    /// (0.13.3 also had a hard-coded 4/hour in the responder).
    #[test]
    fn unit_restarts_follow_the_configured_budget() {
        let mut cfg = Config::default();
        cfg.systemd.max_restarts_per_hour = 1;
        cfg.actions.cooldown = Duration::ZERO; // the budget, not the cooldown, is under test
        let mut r = Responder::new(&cfg);
        let ev = Event::new("systemd.unit_failed", Severity::Warning, "x")
            .subject(Subject::Unit { name: "warden-test-nonexistent.service".into() })
            .actions(vec![ActionSpec::RestartUnit { unit: None }]);
        let first = r.execute(&ev, false, &Default::default());
        assert!(attempted(first[0].status), "{:?}", first[0]);
        let second = r.execute(&ev, false, &Default::default());
        assert_eq!(second[0].status, Status::Refused);
        assert!(second[0].message.contains("1 per hour"), "{}", second[0].message);
        // a reload with a bigger budget applies to the open window
        let mut c2 = cfg.clone();
        c2.systemd.max_restarts_per_hour = 3;
        r.reconfigure(&c2);
        assert!(attempted(r.execute(&ev, false, &Default::default())[0].status));
    }

    /// A tree that keeps forking is stopped, then killed, quickly: nothing
    /// of it survives, and the responder is not held for long.
    #[test]
    fn a_forking_tree_is_killed_as_a_whole() {
        let marker = "31.4159";
        let mut root = std::process::Command::new("sh")
            .args(["-c", &format!("while :; do sleep {marker} & sleep 0.01; done")])
            .spawn()
            .unwrap();
        std::thread::sleep(Duration::from_millis(300)); // a few dozen children
        let pid = root.id() as i32;
        let st = process::start_time(pid).unwrap();
        let mut r = Responder::new(&Config::default());
        let t = Instant::now();
        let res = r.execute(
            &ev_for(pid, st, vec![ActionSpec::Kill { tree: true, grace: Some(Duration::from_millis(500)) }]),
            false,
            &Default::default(),
        );
        assert_eq!(res[0].status, Status::Done, "{}", res[0].message);
        assert!(t.elapsed() < Duration::from_secs(3), "took {:?}", t.elapsed());
        root.wait().unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let left = process::pids()
            .into_iter()
            .filter(|p| process::cmdline(*p, 64).is_some_and(|c| c.contains(marker)))
            .count();
        assert_eq!(left, 0, "children of the tree survived: {}", res[0].message);
    }

    fn exec_step(args: &[&str]) -> ActionSpec {
        ActionSpec::Exec {
            program: "sh".into(),
            args: args.iter().map(|s| s.to_string()).collect(),
            timeout: Some(Duration::from_secs(5)),
            user: None,
        }
    }

    #[test]
    fn lanes_share_the_budgets_but_not_the_wait() {
        let mut cfg = Config::default();
        cfg.actions.cooldown = Duration::ZERO;
        cfg.actions.max_actions_per_hour = 2;
        let mut slow = Responder::new(&cfg);
        let mut fast = slow.lane();
        let hook = Event::new("disk.space", Severity::Critical, "full").actions(vec![exec_step(&["-c", "sleep 1.5"])]);
        let started = Instant::now();
        let busy = std::thread::spawn(move || slow.execute(&hook, false, &Default::default()));
        std::thread::sleep(Duration::from_millis(100));
        // the urgent lane does not wait for the hook on the slow one
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let st = process::start_time(pid).unwrap();
        let res = fast.execute(
            &ev_for(pid, st, vec![ActionSpec::Kill { tree: false, grace: Some(Duration::from_millis(500)) }]),
            false,
            &Default::default(),
        );
        assert_eq!(res[0].status, Status::Done, "{}", res[0].message);
        assert!(started.elapsed() < Duration::from_millis(1200), "the kill waited {:?}", started.elapsed());
        let _ = child.wait();
        assert_eq!(busy.join().unwrap()[0].status, Status::Done);
        // one hour, one budget: both actions counted, a third is refused on either lane
        let res = fast.execute(
            &Event::new("t", Severity::Warning, "x").actions(vec![exec_step(&["-c", "true"])]),
            false,
            &Default::default(),
        );
        assert_eq!(res[0].status, Status::Refused, "{}", res[0].message);
        assert!(res[0].message.contains("max_actions_per_hour"));
    }

    #[test]
    fn exec_hooks_run_as_the_configured_user() {
        if !warden_sys::sched::is_root() {
            return;
        }
        let nobody = warden_sys::cmd::Credentials::lookup("nobody").unwrap();
        let mut cfg = Config::default();
        cfg.actions.cooldown = Duration::ZERO;
        cfg.daemon.command_user = Some("nobody".into()); // any unprivileged account
        let mut r = Responder::new(&cfg);
        let mut own = exec_step(&["-c", "id -u"]);
        let ev = |a: Vec<ActionSpec>| Event::new("t", Severity::Warning, "x").actions(a);
        // the default user
        let res = r.execute(&ev(vec![own.clone()]), false, &Default::default());
        assert_eq!(res[0].status, Status::Done, "{}", res[0].message);
        assert_eq!(res[0].message, format!("exit 0 (as nobody): {}", nobody.uid));
        // a hook's own user wins: `root` keeps the old behaviour
        if let ActionSpec::Exec { user, .. } = &mut own {
            *user = Some("root".into());
        }
        let res = r.execute(&ev(vec![own.clone()]), false, &Default::default());
        assert_eq!(res[0].message, "exit 0: 0");
        // an unknown user fails the hook, it does not fall back to root
        if let ActionSpec::Exec { user, .. } = &mut own {
            *user = Some("no-such-user-warden".into());
        }
        let res = r.execute(&ev(vec![own]), false, &Default::default());
        assert_eq!(res[0].status, Status::Failed);
        assert!(res[0].message.contains("no such user"), "{}", res[0].message);
        assert_eq!(describe(&exec_step(&[]), &ev(vec![])), "run sh");
    }

    #[test]
    fn steps_of_one_playbook_do_not_cool_each_other_down() {
        // Two steps of the same kind on the same target — like the two
        // `delete_old` steps of the disk playbook, which used to share one
        // cooldown key so the second never ran.
        let mut r = Responder::new(&Config::default());
        let ev = Event::new("disk.space", Severity::Critical, "full")
            .subject(Subject::Mount { path: "/".into(), device: None })
            .actions(vec![exec_step(&["-c", "echo first"]), exec_step(&["-c", "echo second"])]);
        let res = r.execute(&ev, false, &Default::default());
        assert!(res.iter().all(|x| x.status == Status::Done), "{res:?}");
        assert!(res[0].message.contains("first") && res[1].message.contains("second"));
        // the same steps again, at once: that is what the cooldown is for
        let again = r.execute(&ev, false, &Default::default());
        assert!(again.iter().all(|x| x.status == Status::Skipped && x.message.contains("cooldown")), "{again:?}");
    }

    #[test]
    fn a_process_that_only_carries_a_protected_name_can_be_killed() {
        // A binary planted in a writable place and started under the name
        // of a system daemon: the name must not make it immune.
        let d = tempfile::tempdir_in("/var/tmp").unwrap();
        let impostor = d.path().join("systemd-udevd");
        std::os::unix::fs::symlink("/usr/bin/sleep", &impostor).unwrap();
        let mut child = std::process::Command::new(&impostor).arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let st = process::read_stat(pid).unwrap();
        assert_eq!(st.comm, "systemd-udevd");
        let waiter = std::thread::spawn(move || child.wait());
        let ev = Event::new("security.miner", Severity::Critical, "probable crypto-miner")
            .subject(Subject::Process(ProcessRef {
                pid,
                start_time: st.starttime,
                comm: st.comm,
                ..Default::default()
            }))
            .actions(vec![ActionSpec::Kill { tree: false, grace: Some(Duration::from_millis(300)) }]);
        let res = Responder::new(&Config::default()).execute(&ev, false, &Default::default());
        assert_eq!(res[0].status, Status::Done, "{}", res[0].message);
        waiter.join().unwrap().unwrap();
    }

    #[test]
    fn a_genuine_program_keeps_the_protection_its_name_gives() {
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let pid = child.id() as i32;
        let st = process::read_stat(pid).unwrap();
        let exe = process::exe(pid).unwrap();
        let mut cfg = Config::default();
        cfg.protection.comm = vec!["sleep".into()];
        let ev = ev_for(pid, st.starttime, vec![ActionSpec::Stop]);
        let res = Responder::new(&cfg).execute(&ev, false, &Default::default());
        if process::verify_daemon(pid, &st.comm, &exe) == Some(true) {
            // a root-owned `sleep` whose name matches its executable
            assert_eq!(res[0].status, Status::Refused, "{}", res[0].message);
            assert!(res[0].message.contains("protected comm"), "{}", res[0].message);
        }
        // control: the same process without the name on the list is stopped
        cfg.protection.comm.clear();
        let mut r = Responder::new(&cfg);
        let res = r.execute(&ev, false, &Default::default());
        assert_eq!(res[0].status, Status::Done, "{}", res[0].message);
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn exec_hooks_cannot_wedge_the_executor() {
        let mut r = Responder::new(&Config::default());
        let t = Instant::now();
        let ev = Event::new("t", Severity::Warning, "hook").actions(vec![
            // far more output than a pipe holds, and a child that outlives the hook
            exec_step(&["-c", "head -c 5000000 /dev/zero; (sleep 3 &) ; echo $WARDEN_EVENT_KIND"]),
            ActionSpec::Exec {
                program: "sleep".into(),
                args: vec!["30".into()],
                timeout: Some(Duration::from_millis(200)),
                user: None,
            },
        ]);
        let res = r.execute(&ev, false, &Default::default());
        assert_eq!(res[0].status, Status::Done, "{}", res[0].message);
        assert_eq!(res[1].status, Status::Failed);
        assert!(res[1].message.contains("timed out"), "{}", res[1].message);
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    }

    #[test]
    fn handles_are_shared_and_follow_reconfiguration() {
        let mut r = Responder::new(&Config::default());
        let h = r.handles();
        let before = lock(&h.firewall).is_allowlisted(&"203.0.113.7".parse().unwrap());
        assert!(!before);
        let mut cfg = Config::default();
        cfg.actions.firewall.allowlist.push("203.0.113.0/24".into());
        r.reconfigure(&cfg);
        // the control socket's handle sees the new allowlist without being replaced
        assert!(lock(&h.firewall).is_allowlisted(&"203.0.113.7".parse().unwrap()));
        assert!(Arc::ptr_eq(&h.firewall, &r.handles().firewall));
        // a long action holds no handle lock: the executor can be busy while
        // the operator lists the quarantine
        let busy = std::thread::spawn(move || {
            r.execute(
                &Event::new("t", Severity::Warning, "slow").actions(vec![ActionSpec::Exec {
                    program: "sleep".into(),
                    args: vec!["1".into()],
                    timeout: None,
                    user: None,
                }]),
                false,
                &Default::default(),
            )
        });
        std::thread::sleep(Duration::from_millis(200));
        let t = Instant::now();
        let _ = read(&h.quarantine).list();
        let _ = lock(&h.tuner).changes();
        let _ = lock(&h.firewall).is_allowlisted(&"127.0.0.1".parse().unwrap());
        assert!(t.elapsed() < Duration::from_millis(500), "{:?}", t.elapsed());
        busy.join().unwrap();
    }

    #[test]
    fn quarantine_via_event_and_guard() {
        let site = tempfile::tempdir().unwrap();
        let qdir = tempfile::tempdir().unwrap();
        let mut cfg = Config::default();
        cfg.actions.quarantine_dir = qdir.path().to_path_buf();
        cfg.fim.sites.push(warden_core::config::FimSite {
            name: "s".into(),
            root: site.path().to_path_buf(),
            include: vec![],
            exclude: vec![],
            no_scripts: vec![],
            signature_exclude: vec![],
            access_log: None,
            quarantine: None,
            restart_unit: None,
        });
        let mut r = Responder::new(&cfg);
        let f = site.path().join("x.php");
        std::fs::write(&f, "<?php").unwrap();
        let ev = Event::new("security.webshell", Severity::Critical, "shell")
            .subject(Subject::File { path: f.to_string_lossy().into_owned(), site: Some("s".into()) })
            .actions(vec![ActionSpec::Quarantine]);
        let res = r.execute(&ev, false, &Default::default());
        assert_eq!(res[0].status, Status::Done, "{}", res[0].message);
        assert!(!f.exists());
        let ev = Event::new("security.webshell", Severity::Critical, "shell")
            .subject(Subject::File { path: "/etc/hostname".into(), site: None })
            .actions(vec![ActionSpec::Quarantine]);
        assert_eq!(r.execute(&ev, false, &Default::default())[0].status, Status::Refused);
    }
}
