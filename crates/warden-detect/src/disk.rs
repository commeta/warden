//! Filesystem space, inodes, read-only remounts and fill-rate prediction.

use crate::runtime::{Cx, Detector};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use warden_core::config::DiskConfig;
use warden_core::units::{human_bytes, human_duration};
use warden_core::{Event, GlobList, Level, LevelTracker, Severity, Subject, Transition};
use warden_sys::du::{DuOptions, DuReport};
use warden_sys::mounts::{self, Mount};
use warden_sys::process;
use warden_sys::safefs;

/// Least-squares slope (units per second) of `(t, y)` samples.
pub fn slope(samples: &VecDeque<(Instant, u64)>) -> Option<f64> {
    let (t0, _) = *samples.front()?;
    let n = samples.len() as f64;
    if n < 3.0 {
        return None;
    }
    let pts: Vec<(f64, f64)> =
        samples.iter().map(|(t, y)| (t.saturating_duration_since(t0).as_secs_f64(), *y as f64)).collect();
    let mx = pts.iter().map(|p| p.0).sum::<f64>() / n;
    let my = pts.iter().map(|p| p.1).sum::<f64>() / n;
    let sxx: f64 = pts.iter().map(|p| (p.0 - mx).powi(2)).sum();
    if sxx <= 0.0 {
        return None;
    }
    let sxy: f64 = pts.iter().map(|p| (p.0 - mx) * (p.1 - my)).sum();
    Some(sxy / sxx)
}

/// Biggest regular files under `dir` (bounded walk, same filesystem).
pub fn largest_files(dir: &Path, min_size: u64, limit: usize, max_entries: usize) -> Vec<(String, u64)> {
    largest_files_until(dir, min_size, limit, max_entries, None).0
}

/// [`largest_files`] that also stops at `deadline`; the flag says whether a
/// budget cut the walk short.
///
/// It runs in the detector before the `disk.space` event goes out — the
/// alert and its cleanup wait for it — so both budgets stop the *whole*
/// walk: a `/tmp` with 200 000 session directories on a cold cache under
/// writeback took 2.6 s for this one directory before (the entry budget only
/// ended the current directory, and every directory already queued was
/// still listed).
///
/// The walk runs over directory descriptors ([`safefs::walk`]): a directory
/// swapped for a symlink mid-walk cannot make it list (and report the names
/// of) files outside the filesystem being examined.
pub fn largest_files_until(
    dir: &Path,
    min_size: u64,
    limit: usize,
    max_entries: usize,
    deadline: Option<Instant>,
) -> (Vec<(String, u64)>, bool) {
    let opt = safefs::WalkOptions { max_depth: 6, one_filesystem: true, max_entries: max_entries as u64, deadline };
    let mut out = Vec::new();
    let r = safefs::walk(dir, &opt, |e| {
        if e.stat.is_file() && e.stat.size >= min_size {
            out.push((e.path.to_string_lossy().into_owned(), e.stat.size));
        }
        safefs::Visit::Continue
    });
    let cut = r.is_ok_and(|s| s.cut);
    out.sort_by_key(|b| std::cmp::Reverse(b.1));
    out.truncate(limit);
    (out, cut)
}

/// How long the evidence attached to a `disk.space` event may take to gather.
const EVIDENCE_BUDGET: Duration = Duration::from_secs(1);

pub struct DiskDetector {
    cfg: DiskConfig,
    fstypes: HashSet<String>,
    exclude: GlobList,
    space: HashMap<String, LevelTracker>,
    inodes: HashMap<String, LevelTracker>,
    history: HashMap<String, VecDeque<(Instant, u64)>>,
    /// Last read-only state seen per mount, and the mounts reported as
    /// read-only (resolved when they are writable again).
    readonly: HashMap<String, bool>,
    readonly_open: HashSet<String>,
    last_prediction: HashMap<String, Instant>,
    nags: HashMap<String, Nag>,
    cleanups: HashMap<String, CleanupRun>,
    /// Where `cleanups` is kept across restarts (`None`: in memory only).
    state: Option<PathBuf>,
    /// Background "who is using the disk" walk (at most one at a time).
    du_job: Option<DuJob>,
    /// Last report per mount: when, and the biggest directories (attached
    /// to later `disk.space` reminders).
    du_last: HashMap<String, (Instant, Vec<serde_json::Value>)>,
}

struct DuJob {
    mount: String,
    used: u64,
    handle: std::thread::JoinHandle<std::io::Result<DuReport>>,
}

/// Repeat reminders with exponential backoff (15m, 30m, 1h … 24h) unless
/// usage keeps growing: a disk that sits at 98% for days is one problem,
/// not a hundred.
#[derive(Debug, Clone, Copy)]
struct Nag {
    last: Instant,
    n: u32,
    pct: f64,
}

/// The last automatic cleanup requested for a mount, to judge whether it
/// helped before running the playbook again.
#[derive(Debug, Clone, Copy)]
struct CleanupRun {
    at: Instant,
    avail_before: u64,
    /// Consecutive runs that freed (almost) nothing.
    ineffective: u32,
    judged: bool,
    freed: u64,
}

/// A [`CleanupRun`] as stored in `disk-cleanups.json`. An `Instant` means
/// nothing to the next process, so the file keeps wall-clock time.
#[derive(Debug, Serialize, Deserialize)]
struct SavedCleanup {
    at_ms: u64,
    avail_before: u64,
    ineffective: u32,
    judged: bool,
    freed: u64,
}

fn encode_cleanups(runs: &HashMap<String, CleanupRun>, now: Instant, wall_ms: u64) -> serde_json::Result<Vec<u8>> {
    let saved: std::collections::BTreeMap<&String, SavedCleanup> = runs
        .iter()
        .map(|(mp, r)| {
            let age = now.saturating_duration_since(r.at).as_millis() as u64;
            let saved = SavedCleanup {
                at_ms: wall_ms.saturating_sub(age),
                avail_before: r.avail_before,
                ineffective: r.ineffective,
                judged: r.judged,
                freed: r.freed,
            };
            (mp, saved)
        })
        .collect();
    serde_json::to_vec_pretty(&saved)
}

/// Runs older than the longest back-off no longer matter and are dropped.
fn decode_cleanups(bytes: &[u8], now: Instant, wall_ms: u64) -> HashMap<String, CleanupRun> {
    let saved: HashMap<String, SavedCleanup> = serde_json::from_slice(bytes).unwrap_or_default();
    saved
        .into_iter()
        .filter_map(|(mp, r)| {
            let age = Duration::from_millis(wall_ms.saturating_sub(r.at_ms));
            if age > MAX_BACKOFF {
                return None;
            }
            // (just after a reboot the monotonic clock may be younger than the run)
            let at = now.checked_sub(age).unwrap_or(now);
            Some((
                mp,
                CleanupRun {
                    at,
                    avail_before: r.avail_before,
                    ineffective: r.ineffective,
                    judged: r.judged,
                    freed: r.freed,
                },
            ))
        })
        .collect()
}

/// Start the "who is using the space?" walk at once on a critical level, or
/// after a cleanup that did not help. It runs at idle priority within a time
/// and entry budget, and waiting for the second failed cleanup meant the
/// answer came a quarter of an hour after the disk was already full.
fn wants_usage_report(cleanup_was_useless: bool, sev: Severity) -> bool {
    cleanup_was_useless || sev >= Severity::Critical
}

const MAX_BACKOFF: Duration = Duration::from_secs(24 * 3600);

fn backoff(base: Duration, n: u32) -> Duration {
    base.saturating_mul(1 << n.min(10)).min(MAX_BACKOFF)
}

impl DiskDetector {
    pub fn new(cfg: &DiskConfig) -> Self {
        Self {
            fstypes: cfg.fstypes.iter().cloned().collect(),
            exclude: GlobList::new(&cfg.exclude),
            cfg: cfg.clone(),
            space: HashMap::new(),
            inodes: HashMap::new(),
            history: HashMap::new(),
            readonly: HashMap::new(),
            readonly_open: HashSet::new(),
            last_prediction: HashMap::new(),
            nags: HashMap::new(),
            cleanups: HashMap::new(),
            state: None,
            du_job: None,
            du_last: HashMap::new(),
        }
    }

    /// Keep the cleanup history in `path` across restarts. Without it a daemon
    /// that is restarted (or reloaded) forgets that the last cleanup freed
    /// nothing and runs the whole playbook again.
    pub fn persisted(mut self, path: PathBuf) -> Self {
        if let Ok(bytes) = std::fs::read(&path) {
            self.cleanups = decode_cleanups(&bytes, warden_sys::clock::now(), warden_core::event::now_ms());
        }
        self.state = Some(path);
        self
    }

    fn persist(&self) {
        let Some(path) = &self.state else { return };
        let written = if self.cleanups.is_empty() {
            std::fs::remove_file(path)
                .or_else(|e| if e.kind() == std::io::ErrorKind::NotFound { Ok(()) } else { Err(e) })
        } else {
            encode_cleanups(&self.cleanups, warden_sys::clock::now(), warden_core::event::now_ms())
                .map_err(std::io::Error::other)
                .and_then(|b| warden_sys::util::write_atomic(path, &b))
        };
        if let Err(e) = written {
            tracing::warn!("cannot save {}: {e}", path.display());
        }
    }

    /// Start the bounded walk of `mp` unless one is running or the mount was
    /// reported recently.
    fn start_usage_report(&mut self, cx: &Cx<'_>, mp: &str, used: u64) {
        if self.du_job.is_some()
            || self
                .du_last
                .get(mp)
                .is_some_and(|(t, _)| cx.real.saturating_duration_since(*t) < self.cfg.usage_report_every)
        {
            return;
        }
        let opt = DuOptions {
            max_entries: self.cfg.usage_report_max_entries,
            max_time: self.cfg.usage_report_max_time,
            pace: true,
            ..Default::default()
        };
        let root = std::path::PathBuf::from(mp);
        let wake = cx.shared.metrics_handle();
        let spawned = std::thread::Builder::new().name("w-disk-du".into()).spawn(move || {
            crate::prof::set_thread_scope(crate::prof::scope_id("disk"));
            let _ = warden_sys::sched::background_thread();
            let r = warden_sys::du::usage(&root, &opt, None);
            tracing::debug!(bytes = warden_sys::selfstat::release_memory(), "disk walk memory released");
            if let Some(w) = wake {
                w.wake(crate::runtime::Wake::Detector("disk"));
            }
            r
        });
        match spawned {
            Ok(handle) => {
                // Remember the attempt now: a failed or slow walk is not retried every tick.
                self.du_last.insert(mp.to_owned(), (cx.real, Vec::new()));
                self.du_job = Some(DuJob { mount: mp.to_owned(), used, handle });
            }
            Err(e) => tracing::warn!(error = %e, "cannot start the disk usage walk"),
        }
    }

    /// Collect a finished walk and report it.
    fn finish_usage_report(&mut self, cx: &Cx<'_>) {
        if !self.du_job.as_ref().is_some_and(|j| j.handle.is_finished()) {
            return;
        }
        let job = self.du_job.take().expect("checked above");
        let rep = match job.handle.join() {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => {
                tracing::warn!(mount = %job.mount, error = %e, "disk usage walk failed");
                return;
            }
            Err(_) => return,
        };
        cx.metric("warden_disk_usage_walk_seconds", &[("mount", &job.mount)], rep.elapsed.as_secs_f64());
        let ev = usage_event(&job.mount, job.used, &rep);
        let top: Vec<serde_json::Value> = rep
            .levels
            .first()
            .map(|l| {
                l.iter()
                    .take(5)
                    .map(|e| serde_json::json!(format!("{} {}", e.path.display(), human_bytes(e.bytes))))
                    .collect()
            })
            .unwrap_or_default();
        self.du_last.insert(job.mount.clone(), (cx.real, top));
        cx.emit(ev);
    }

    /// Should a `Repeated` transition be reported now?
    fn nag_due(&mut self, mp: &str, now: Instant, pct: f64) -> bool {
        let base = self.cfg.repeat;
        match self.nags.get_mut(mp) {
            None => {
                self.nags.insert(mp.to_owned(), Nag { last: now, n: 0, pct });
                true
            }
            Some(n) => {
                let worse = pct >= n.pct + 1.0;
                if worse || now.saturating_duration_since(n.last) >= backoff(base, n.n) {
                    n.last = now;
                    n.n = if worse { 0 } else { n.n + 1 };
                    n.pct = pct;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Decide whether to attach the cleanup playbook. Returns `None` to run
    /// it, or a note explaining why it is skipped. A run that freed less
    /// than 1% of the filesystem (min. 256 MiB) counts as useless; useless
    /// runs are retried after 30m, 1h, 2h … 24h.
    fn cleanup_gate(&mut self, mp: &str, now: Instant, avail: u64, total: u64) -> Option<String> {
        let verdict = self.judge_cleanup(mp, now, avail, total);
        self.persist();
        verdict
    }

    fn judge_cleanup(&mut self, mp: &str, now: Instant, avail: u64, total: u64) -> Option<String> {
        let enough = (total / 100).max(256 << 20);
        let base = self.cfg.repeat;
        let mut ineffective = 0;
        if let Some(c) = self.cleanups.get_mut(mp) {
            let since = now.saturating_duration_since(c.at);
            if since < base / 2 {
                return Some("cleanup already requested moments ago".into());
            }
            if !c.judged {
                c.judged = true;
                let freed = avail.saturating_sub(c.avail_before);
                c.ineffective = if freed < enough { c.ineffective + 1 } else { 0 };
                c.freed = freed;
            }
            ineffective = c.ineffective;
            let wait = backoff(base, c.ineffective);
            if c.ineffective > 0 && since < wait {
                return Some(format!(
                    "automatic cleanup is paused: the last run freed only {} — the space is used by something the \
                     playbook does not cover (see disk.usage_report, largest_files and deleted_but_open, or run `wardenctl du {mp}`); \
                     next attempt in {}",
                    human_bytes(c.freed),
                    human_duration(wait.saturating_sub(since))
                ));
            }
        }
        self.cleanups
            .insert(mp.to_owned(), CleanupRun { at: now, avail_before: avail, ineffective, judged: false, freed: 0 });
        None
    }

    /// A mount's read-only state on this tick.
    fn readonly_check(&mut self, cx: &Cx<'_>, mp: &str, ro: bool, fstype: &str, source: &str, subject: &Subject) {
        let prev = self.readonly.insert(mp.to_owned(), ro);
        if ro && !self.readonly_open.contains(mp) {
            // Became read-only while watched: the kernel's answer to I/O or
            // filesystem errors. Already read-only when first seen
            // (startup): perhaps on purpose, perhaps not — reported, without
            // the alarm. (0.13.3 said nothing about it.)
            let became = prev == Some(false);
            let (sev, title) = if became {
                (Severity::Critical, format!("filesystem {mp} became read-only"))
            } else {
                (Severity::Notice, format!("filesystem {mp} is mounted read-only"))
            };
            let mut ev = Event::new("disk.readonly", sev, title)
                .subject(subject.clone())
                .fingerprint(format!("disk.readonly:{mp}:{sev}"))
                .detail("fstype", fstype)
                .detail("source", source)
                .detail(
                    "hint",
                    "check `dmesg` for I/O or filesystem errors; the kernel remounts read-only to prevent corruption",
                );
            if became {
                ev = ev.actions(vec![warden_core::ActionSpec::Snapshot]);
            }
            self.readonly_open.insert(mp.to_owned());
            cx.emit(ev);
        } else if !ro && self.readonly_open.remove(mp) {
            cx.emit(
                Event::new("disk.readonly", Severity::Info, format!("filesystem {mp} is writable again"))
                    .subject(subject.clone())
                    .fingerprint(format!("disk.readonly:{mp}:resolved"))
                    .resolved(),
            );
        }
    }

    /// A mount's inode use on this tick: the same lifecycle as space — a
    /// change is reported at once, reminders back off, the episode is
    /// resolved. (0.13.3 never resolved an inode incident nor reported a
    /// step down.) Returns the level.
    fn inode_check(
        &mut self,
        cx: &Cx<'_>,
        mp: &str,
        ipct: f64,
        (inodes, free): (u64, u64),
        subject: &Subject,
    ) -> Level {
        let c = &self.cfg;
        let raw = if ipct >= c.inode_critical_percent {
            Level::Critical
        } else if ipct >= c.inode_warning_percent {
            Level::Warning
        } else {
            Level::Ok
        };
        let tracker = Self::tracker(c);
        let tr = self.inodes.entry(mp.to_owned()).or_insert(tracker).update(cx.now, raw);
        let nag = format!("inodes:{mp}");
        if matches!(tr, Transition::Raised(_) | Transition::Lowered(_)) {
            self.nags.remove(&nag);
        }
        let report = match tr {
            Transition::Repeated(_) => self.nag_due(&nag, cx.real, ipct),
            Transition::Raised(_) | Transition::Lowered(_) => {
                self.nag_due(&nag, cx.real, ipct);
                true
            }
            _ => false,
        };
        match tr {
            Transition::Raised(l) | Transition::Repeated(l) | Transition::Lowered(l) if l > Level::Ok && report => {
                let sev = if l == Level::Critical { Severity::Critical } else { Severity::Warning };
                cx.emit(
                    Event::new("disk.inodes", sev, format!("{mp} inodes {ipct:.1}% used"))
                        .subject(subject.clone())
                        .fingerprint(format!("disk.inodes:{mp}:{sev}"))
                        .detail("inodes", inodes)
                        .detail("inodes_free", free)
                        .detail(
                            "hint",
                            "typical causes: PHP session files, mail queues, cache directories with millions of small files",
                        ),
                );
            }
            Transition::Cleared => {
                self.nags.remove(&nag);
                cx.emit(
                    Event::new("disk.inodes", Severity::Info, format!("{mp} inodes back to {ipct:.1}%"))
                        .subject(subject.clone())
                        .fingerprint(format!("disk.inodes:{mp}:resolved"))
                        .resolved(),
                );
            }
            _ => {}
        }
        self.inodes.get(mp).map(|t| t.level()).unwrap_or_default()
    }

    fn tracker(cfg: &DiskConfig) -> LevelTracker {
        LevelTracker::new(Duration::ZERO, Duration::ZERO, Duration::from_secs(120), cfg.repeat)
    }

    /// Local filesystems to watch, one mount point per device (bind mounts
    /// and btrfs subvolumes would otherwise alert N times).
    pub fn watched(&self) -> Vec<Mount> {
        let Ok(all) = mounts::mounts() else { return Vec::new() };
        let mut by_dev: HashMap<String, Mount> = HashMap::new();
        for m in all {
            if !self.fstypes.contains(&m.fstype) || self.exclude.is_match(&m.mount_point) {
                continue;
            }
            match by_dev.get(&m.device) {
                Some(cur) if cur.mount_point.len() <= m.mount_point.len() => {}
                _ => {
                    by_dev.insert(m.device.clone(), m);
                }
            }
        }
        let mut v: Vec<Mount> = by_dev.into_values().collect();
        v.sort_by(|a, b| a.mount_point.cmp(&b.mount_point));
        v
    }

    /// Deleted-but-open files and the biggest files in the usual places;
    /// `true` when the time or entry budget cut the file walk short.
    fn evidence(&self, m: &Mount) -> (Vec<serde_json::Value>, Vec<serde_json::Value>, bool) {
        let deadline = Instant::now() + EVIDENCE_BUDGET;
        let deleted: Vec<serde_json::Value> = process::deleted_open_files(self.cfg.deleted_open_min.as_u64(), m.dev())
            .into_iter()
            .take(10)
            .map(|(pid, fd, path, size)| {
                let comm = process::read_stat(pid).map(|s| s.comm).unwrap_or_default();
                serde_json::json!({"pid": pid, "comm": comm, "fd": fd, "path": path, "size": human_bytes(size)})
            })
            .collect();
        let mut big = Vec::new();
        let mut partial = false;
        for dir in ["/var/log", "/var/tmp", "/tmp", "/var/crash", "/var/lib/docker/containers"] {
            use std::os::unix::fs::MetadataExt;
            let same_fs = std::fs::metadata(dir).ok().map(|md| md.dev()) == m.dev();
            if same_fs {
                let (found, cut) = largest_files_until(Path::new(dir), 256 << 20, 5, 50_000, Some(deadline));
                big.extend(found);
                partial |= cut;
            }
        }
        big.sort_by_key(|b| std::cmp::Reverse(b.1));
        let big =
            big.into_iter().take(8).map(|(p, s)| serde_json::json!({"path": p, "size": human_bytes(s)})).collect();
        (deleted, big, partial)
    }
}

fn entries(v: &[warden_sys::du::DuEntry]) -> Vec<serde_json::Value> {
    v.iter()
        .map(|e| serde_json::json!({"path": e.path.display().to_string(), "size": human_bytes(e.bytes), "bytes": e.bytes}))
        .collect()
}

/// The `disk.usage_report` event for a finished walk of `mp`.
pub fn usage_event(mp: &str, used: u64, rep: &DuReport) -> Event {
    let top = rep.levels.first().map(Vec::as_slice).unwrap_or_default();
    let summary = if top.is_empty() {
        "no directories found".to_owned()
    } else {
        top.iter()
            .take(3)
            .map(|e| format!("{} {}", e.path.display(), human_bytes(e.bytes)))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let mut ev = Event::new("disk.usage_report", Severity::Notice, format!("{mp}: biggest directories — {summary}"))
        .subject(Subject::Mount { path: mp.to_owned(), device: None })
        .fingerprint(format!("disk.usage_report:{mp}"))
        .detail("directories", entries(top))
        .detail("counted", human_bytes(rep.total))
        .detail("entries_scanned", rep.entries)
        .detail("took_seconds", (rep.elapsed.as_secs_f64() * 10.0).round() / 10.0);
    if rep.paced >= std::time::Duration::from_secs(1) {
        // the disk was busy: the walk yielded to the workload for this long
        ev = ev.detail("paced_seconds", rep.paced.as_secs());
    }
    if let Some(l2) = rep.levels.get(1)
        && !l2.is_empty()
    {
        ev = ev.detail("subdirectories", entries(l2));
    }
    if !rep.largest_files.is_empty() {
        ev = ev.detail("largest_files", entries(&rep.largest_files));
    }
    if rep.root_files > 0 {
        ev = ev.detail("files_in_root", human_bytes(rep.root_files));
    }
    if rep.errors > 0 {
        ev = ev.detail("unreadable_dirs", rep.errors);
    }
    if let Some(why) = rep.partial {
        ev = ev.detail("partial", why);
    } else {
        // What the walk could not see: deleted-but-open files, data hidden
        // under another mount point, snapshots, filesystem metadata.
        let hidden = used.saturating_sub(rep.total);
        if hidden > (used / 10).max(1 << 30) {
            ev = ev.detail("not_found_by_walk", human_bytes(hidden)).detail(
                "hint",
                "space the walk cannot see: files deleted but still open (see deleted_but_open), data under a \
                 mount point (umount or bind-mount / elsewhere to inspect), btrfs/zfs snapshots",
            );
        }
    }
    ev
}

impl Detector for DiskDetector {
    fn name(&self) -> &'static str {
        "disk"
    }

    fn sections(&self) -> &'static [&'static str] {
        &["/disk", "/daemon/state_dir"]
    }

    fn reconfigure(&mut self, cfg: &warden_core::Config) -> bool {
        // levels, reminders, cleanup history, the last usage report and a
        // walk in progress all stay: a reload must not start another `du`
        let c = &cfg.disk;
        for t in self.space.values_mut().chain(self.inodes.values_mut()) {
            t.retune(Duration::ZERO, Duration::ZERO, Duration::from_secs(120), c.repeat);
        }
        self.fstypes = c.fstypes.iter().cloned().collect();
        self.exclude = GlobList::new(&c.exclude);
        self.cfg = c.clone();
        if self.state.is_some() {
            self.state = Some(cfg.daemon.state_dir.join("disk-cleanups.json"));
            self.persist();
        }
        true
    }

    fn close(&mut self) -> Vec<Event> {
        let mut v = Vec::new();
        for (mp, t) in &self.space {
            v.extend(crate::runtime::close_level("disk.space", &format!("disk.space:{mp}"), t));
        }
        for (mp, t) in &self.inodes {
            v.extend(crate::runtime::close_level("disk.inodes", &format!("disk.inodes:{mp}"), t));
        }
        for mp in self.readonly_open.drain() {
            v.push(
                Event::new("disk.readonly", Severity::Info, format!("{mp}: {}", crate::runtime::NO_LONGER_WATCHED))
                    .fingerprint(format!("disk.readonly:{mp}:resolved"))
                    .resolved(),
            );
        }
        v
    }

    fn interval(&self) -> Duration {
        if self.du_job.is_some() { self.cfg.interval.min(Duration::from_secs(5)) } else { self.cfg.interval }
    }

    fn tick(&mut self, cx: &mut Cx<'_>) {
        self.finish_usage_report(cx);
        let watched = self.watched();
        let live: HashSet<String> = watched.iter().map(|m| m.mount_point.clone()).collect();
        let gone: Vec<String> = self.space.keys().filter(|k| !live.contains(*k)).cloned().collect();
        for g in gone {
            self.space.remove(&g);
            self.inodes.remove(&g);
            self.history.remove(&g);
            self.readonly.remove(&g);
            self.readonly_open.remove(&g);
            self.nags.remove(&g);
            self.nags.remove(&format!("inodes:{g}"));
            if self.cleanups.remove(&g).is_some() {
                self.persist();
            }
            for m in [
                "warden_disk_used_percent",
                "warden_disk_inodes_used_percent",
                "warden_disk_avail_bytes",
                "warden_disk_full_eta_seconds",
            ] {
                cx.shared.metrics.remove_matching(m, "mount", &g);
            }
        }

        let mut worst = Level::Ok;
        for m in watched {
            let mp = m.mount_point.clone();
            let Ok(u) = mounts::statvfs(&mp) else { continue };
            let pct = u.used_percent();
            let ipct = u.inode_percent();
            cx.metric("warden_disk_used_percent", &[("mount", &mp)], (pct * 10.0).round() / 10.0);
            cx.metric("warden_disk_avail_bytes", &[("mount", &mp)], u.avail as f64);
            cx.metric("warden_disk_inodes_used_percent", &[("mount", &mp)], (ipct * 10.0).round() / 10.0);
            let subject = Subject::Mount { path: mp.clone(), device: Some(m.source.clone()) };

            // --- read-only remount (filesystem errors) ---
            if self.cfg.detect_readonly {
                self.readonly_check(cx, &mp, m.is_readonly(), &m.fstype, &m.source, &subject);
            }

            // --- space ---
            let snapshot = self.cfg.clone();
            let c = &snapshot;
            let raw = if pct >= c.critical_percent {
                Level::Critical
            } else if pct >= c.warning_percent {
                Level::Warning
            } else {
                Level::Ok
            };
            let tr = self.space.entry(mp.clone()).or_insert_with(|| Self::tracker(c)).update(cx.now, raw);
            if matches!(tr, Transition::Raised(_) | Transition::Lowered(_)) {
                self.nags.remove(&mp);
            }
            let report = match tr {
                Transition::Repeated(_) => self.nag_due(&mp, cx.real, pct),
                Transition::Raised(_) | Transition::Lowered(_) => {
                    self.nag_due(&mp, cx.real, pct);
                    true
                }
                _ => false,
            };
            match tr {
                Transition::Raised(l) | Transition::Repeated(l) | Transition::Lowered(l) if l > Level::Ok && report => {
                    let sev = if l == Level::Critical { Severity::Critical } else { Severity::Warning };
                    let (deleted, big, partial) = self.evidence(&m);
                    let mut cleanup = sev >= c.cleanup_at;
                    let mut skipped = None;
                    if cleanup && let Some(note) = self.cleanup_gate(&mp, cx.real, u.avail, u.total) {
                        cleanup = false;
                        skipped = Some(note);
                    }
                    let mut ev = Event::new(
                        "disk.space",
                        sev,
                        format!("{mp} is {pct:.1}% full ({} free of {})", human_bytes(u.avail), human_bytes(u.total)),
                    )
                    .subject(subject.clone())
                    .fingerprint(format!("disk.space:{mp}:{sev}"))
                    .detail("used_percent", (pct * 10.0).round() / 10.0)
                    .detail("avail", human_bytes(u.avail))
                    .detail("fstype", m.fstype.clone());
                    if !deleted.is_empty() {
                        ev = ev.detail("deleted_but_open", deleted);
                    }
                    if !big.is_empty() {
                        ev = ev.detail("largest_files", big);
                    }
                    if partial {
                        // the alert does not wait for a full walk: `wardenctl du` has it
                        ev = ev.detail("largest_files_partial", true);
                    }
                    if cleanup {
                        ev = ev.detail("stop_below_percent", c.cleanup_target_percent).actions(c.cleanup.clone());
                    }
                    if let Some(n) = skipped {
                        ev = ev.detail("cleanup_skipped", n);
                    }
                    // Find out who is using the space (see `wants_usage_report`).
                    let useless = self.cleanups.get(&mp).is_some_and(|r| r.ineffective > 0);
                    if c.usage_report && wants_usage_report(useless, sev) {
                        self.start_usage_report(cx, &mp, u.used);
                        if self.du_job.as_ref().is_some_and(|j| j.mount == mp) {
                            ev = ev.detail("usage_report", "running: `disk.usage_report` follows");
                        }
                    }
                    if let Some((at, top)) = self.du_last.get(&mp)
                        && !top.is_empty()
                    {
                        ev = ev
                            .detail("biggest_dirs", serde_json::json!(top))
                            .detail("biggest_dirs_age", human_duration(cx.real.saturating_duration_since(*at)));
                    }
                    if let Some(n) = self.nags.get(&mp)
                        && n.n > 0
                    {
                        ev = ev.detail("next_reminder_in", human_duration(backoff(c.repeat, n.n)));
                    }
                    cx.emit(ev);
                }
                Transition::Cleared => {
                    self.nags.remove(&mp);
                    if self.cleanups.remove(&mp).is_some() {
                        self.persist();
                    }
                    cx.emit(
                        Event::new("disk.space", Severity::Info, format!("{mp} usage back to {pct:.1}%"))
                            .subject(subject.clone())
                            .fingerprint(format!("disk.space:{mp}:resolved"))
                            .resolved(),
                    )
                }
                _ => {}
            }
            let lvl = self.space.get(&mp).map(|t| t.level()).unwrap_or_default();
            worst = worst.max(lvl);

            // --- inodes ---
            if u.inodes > 0 {
                worst = worst.max(self.inode_check(cx, &mp, ipct, (u.inodes, u.inodes_free), &subject));
            }

            // --- prediction ---
            if c.predict {
                let h = self.history.entry(mp.clone()).or_default();
                h.push_back((cx.now, u.used));
                while h.front().is_some_and(|(t, _)| cx.now.saturating_duration_since(*t) > c.window) {
                    h.pop_front();
                }
                let span = h.front().map(|(t, _)| cx.now.saturating_duration_since(*t)).unwrap_or_default();
                let rate = if span >= c.window / 3 && pct >= 50.0 && raw < Level::Critical {
                    slope(h).filter(|r| *r > 0.0)
                } else {
                    None
                };
                if rate.is_none() {
                    // no growth to project: no ETA (0.13.3 left the last one
                    // in place for ever — "full in 2 h" on a quiet disk)
                    cx.shared.metrics.remove_matching("warden_disk_full_eta_seconds", "mount", &mp);
                }
                if let Some(rate) = rate {
                    let eta = Duration::from_secs_f64((u.avail as f64 / rate).min(1e9));
                    cx.metric("warden_disk_full_eta_seconds", &[("mount", &mp)], eta.as_secs_f64());
                    if eta < c.horizon
                        && self
                            .last_prediction
                            .get(&mp)
                            .is_none_or(|t| cx.real.saturating_duration_since(*t) > Duration::from_secs(3600))
                    {
                        self.last_prediction.insert(mp.clone(), cx.real);
                        cx.emit(
                            Event::new(
                                "disk.fill_prediction",
                                Severity::Warning,
                                format!(
                                    "{mp} will be full in ~{} at {}/min",
                                    human_duration(eta),
                                    human_bytes((rate * 60.0) as u64)
                                ),
                            )
                            .subject(subject.clone())
                            .fingerprint(format!("disk.fill_prediction:{mp}"))
                            .detail("eta_seconds", eta.as_secs())
                            .detail("growth_bytes_per_min", (rate * 60.0) as u64),
                        );
                    }
                }
            }
        }
        cx.shared.set_level("disk", &format!("{worst:?}").to_lowercase());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::{Shared, Sink, lock};

    fn cx_at<'a>(shared: &'a Shared, cfg: &'a warden_core::Config, sink: &'a Sink, t0: Instant, s: u64) -> Cx<'a> {
        let mut cx = Cx::new(shared, cfg, sink, "disk");
        cx.now = t0 + Duration::from_secs(s);
        cx.real = cx.now;
        cx
    }

    #[test]
    fn readonly_is_reported_at_startup_and_resolved_when_writable() {
        let cfg = warden_core::Config::default();
        let mut d = DiskDetector::new(&cfg.disk);
        let shared = Shared::new(cfg.clone());
        let (sink, events) = Sink::collector();
        let t0 = Instant::now();
        let subj = Subject::Mount { path: "/data".into(), device: None };
        let step = |d: &mut DiskDetector, s: u64, ro: bool| {
            d.readonly_check(&cx_at(&shared, &cfg, &sink, t0, s), "/data", ro, "ext4", "/dev/sdb1", &subj);
            lock(&events).drain(..).map(|e| (e.fingerprint, e.severity, e.actions.len())).collect::<Vec<_>>()
        };
        // read-only when first seen: a notice, without actions; once
        assert_eq!(step(&mut d, 0, true), [("disk.readonly:/data:notice".into(), Severity::Notice, 0)]);
        assert!(step(&mut d, 60, true).is_empty());
        assert_eq!(step(&mut d, 120, false), [("disk.readonly:/data:resolved".into(), Severity::Info, 0)]);
        // becomes read-only while watched: critical, with a snapshot
        assert_eq!(step(&mut d, 180, true), [("disk.readonly:/data:critical".into(), Severity::Critical, 1)]);
        assert!(!d.close().is_empty(), "an open read-only mount is closed when the detector goes");
    }

    #[test]
    fn inode_incidents_step_down_remind_with_backoff_and_resolve() {
        let cfg = warden_core::Config::default(); // 85 % / 95 %, clear after 120 s, repeat 15 min
        let mut d = DiskDetector::new(&cfg.disk);
        let shared = Shared::new(cfg.clone());
        let (sink, events) = Sink::collector();
        let t0 = Instant::now();
        let subj = Subject::Mount { path: "/".into(), device: None };
        let mut series: Vec<(u64, f64)> = Vec::new();
        for m in 0..10 {
            series.push((m * 60, 90.0)); // warning
        }
        for m in 10..15 {
            series.push((m * 60, 97.0)); // critical
        }
        for m in 15..60 {
            series.push((m * 60, 88.0)); // back to warning, held for 45 min
        }
        for m in 60..65 {
            series.push((m * 60, 50.0)); // ok
        }
        let mut got = Vec::new();
        for (s, pct) in series {
            d.inode_check(&cx_at(&shared, &cfg, &sink, t0, s), "/", pct, (1000, 100), &subj);
            got.extend(lock(&events).drain(..).map(|e| (s / 60, e.fingerprint)));
        }
        let want: Vec<(u64, String)> = [
            (0, "disk.inodes:/:warning"),
            (10, "disk.inodes:/:critical"),
            (17, "disk.inodes:/:warning"),  // stepped down after clear_after
            (32, "disk.inodes:/:warning"),  // reminder after 15 min
            (62, "disk.inodes:/:resolved"), // (the next reminder would be at 62 = 32 + 30)
        ]
        .into_iter()
        .map(|(m, f)| (m, f.to_owned()))
        .collect();
        assert_eq!(got, want);
    }

    #[test]
    fn a_reload_keeps_the_disk_detectors_memory() {
        let cfg = warden_core::Config::default();
        let mut d = DiskDetector::new(&cfg.disk);
        let real = warden_sys::clock::now();
        d.du_last.insert("/".into(), (real, vec![serde_json::json!("/var 10 GiB")]));
        d.inodes.insert("/".into(), DiskDetector::tracker(&cfg.disk));
        let mut c2 = cfg.clone();
        c2.disk.warning_percent = 70.0;
        c2.disk.repeat = Duration::from_secs(60);
        assert!(d.reconfigure(&c2));
        assert!(d.du_last.contains_key("/"), "no new walk because of a reload");
        assert_eq!(d.cfg.warning_percent, 70.0);
        assert_eq!(d.inodes["/"].repeat, Duration::from_secs(60));
    }

    #[test]
    fn slope_of_linear_growth() {
        let t0 = Instant::now();
        let s: VecDeque<(Instant, u64)> = (0..10).map(|i| (t0 + Duration::from_secs(i * 10), 1000 + i * 500)).collect();
        let r = slope(&s).unwrap();
        assert!((r - 50.0).abs() < 1e-6, "{r}");
        let flat: VecDeque<(Instant, u64)> = (0..5).map(|i| (t0 + Duration::from_secs(i), 7)).collect();
        assert_eq!(slope(&flat), Some(0.0));
    }

    #[test]
    fn usage_report_runs_once_in_background_and_is_reported() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(d.path().join("db/data")).unwrap();
        std::fs::write(d.path().join("db/data/ibdata1"), vec![1u8; 2 << 20]).unwrap();
        std::fs::create_dir_all(d.path().join("logs")).unwrap();
        std::fs::write(d.path().join("logs/app.log"), vec![1u8; 128 << 10]).unwrap();
        let cfg = warden_core::Config::default();
        let shared = crate::runtime::Shared::new(cfg.clone());
        let (sink, events) = crate::runtime::Sink::collector();
        let cx = Cx::new(&shared, &cfg, &sink, "disk");
        let mut det = DiskDetector::new(&cfg.disk);
        let mp = d.path().to_string_lossy().into_owned();
        det.start_usage_report(&cx, &mp, 100 << 30);
        assert!(det.du_job.is_some());
        assert!(det.interval() <= Duration::from_secs(5), "polls quickly while the walk runs");
        // A second request while running (or within usage_report_every) is ignored.
        det.start_usage_report(&cx, &mp, 100 << 30);
        let t = Instant::now();
        while det.du_job.as_ref().is_some_and(|j| !j.handle.is_finished()) && t.elapsed() < Duration::from_secs(10) {
            std::thread::sleep(Duration::from_millis(10));
        }
        det.finish_usage_report(&cx);
        assert!(det.du_job.is_none());
        let evs = crate::runtime::lock(&events);
        let ev = evs.iter().find(|e| e.kind == "disk.usage_report").expect("report emitted");
        assert!(ev.title.contains("/db "), "{}", ev.title);
        assert_eq!(ev.details["directories"][0]["path"], format!("{mp}/db"));
        assert_eq!(ev.details["subdirectories"][0]["path"], format!("{mp}/db/data"));
        // 100 GiB "used" but only ~2 MiB found: the hidden-space hint appears.
        assert!(ev.details.contains_key("not_found_by_walk"));
        drop(evs);
        assert!(!det.du_last[&mp].1.is_empty(), "biggest dirs remembered for reminders");
        det.start_usage_report(&cx, &mp, 100 << 30);
        assert!(det.du_job.is_none(), "not again within usage_report_every");
    }

    #[test]
    fn reminders_back_off_and_useless_cleanup_pauses() {
        let mut d = DiskDetector::new(&DiskConfig::default()); // repeat = 15m
        let t0 = Instant::now();
        let m = |x: u64| t0 + Duration::from_secs(x * 60);
        assert!(d.nag_due("/", m(0), 98.0));
        assert!(d.nag_due("/", m(15), 98.0)); // 15m
        assert!(!d.nag_due("/", m(30), 98.1)); // backoff: 30m since last
        assert!(d.nag_due("/", m(45), 98.1));
        assert!(!d.nag_due("/", m(60), 98.2));
        assert!(d.nag_due("/", m(61), 99.2), "usage grew ≥1 point: report at once");

        const G: u64 = 1 << 30;
        let total = 224 * G;
        assert_eq!(d.cleanup_gate("/", m(0), 2 * G, total), None, "first run");
        // 15 min later only 4 MiB more free: the playbook did not help
        let note = d.cleanup_gate("/", m(15), 2 * G + (4 << 20), total).unwrap();
        assert!(note.contains("paused") && note.contains("4.0MiB"), "{note}");
        assert!(d.cleanup_gate("/", m(25), 2 * G, total).is_some());
        assert_eq!(d.cleanup_gate("/", m(31), 2 * G, total), None, "retried after 30m");
        assert!(d.cleanup_gate("/", m(46), 2 * G, total).is_some(), "useless again: wait 1h");
        assert_eq!(d.cleanup_gate("/", m(92), 2 * G, total), None);
        // a run that frees space resets the backoff
        assert_eq!(d.cleanup_gate("/", m(120), 12 * G, total), None);
        assert!(d.cleanups["/"].ineffective == 0);
    }

    #[test]
    fn a_useless_cleanup_is_remembered_across_a_restart() {
        const G: u64 = 1 << 30;
        let total = 224 * G;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/disk-cleanups.json");
        let cfg = DiskConfig::default(); // repeat = 15m
        let mut before = DiskDetector::new(&cfg).persisted(path.clone());
        assert_eq!(before.cleanup_gate("/", Instant::now(), 2 * G, total), None, "first run");
        // The daemon is restarted a minute later (the `api` host in the review):
        // the new process must not run the playbook again at once.
        let mut after = DiskDetector::new(&cfg).persisted(path.clone());
        let note = after.cleanup_gate("/", Instant::now() + Duration::from_secs(63), 2 * G, total);
        assert!(note.is_some_and(|n| n.contains("moments ago")), "the run before the restart counts");
        // ... and a run judged useless keeps its back-off through another restart
        let later = Instant::now() + Duration::from_secs(16 * 60);
        let note = after.cleanup_gate("/", later, 2 * G + (4 << 20), total).unwrap();
        assert!(note.contains("paused"), "{note}");
        let mut third = DiskDetector::new(&cfg).persisted(path.clone());
        assert_eq!(third.cleanups["/"].ineffective, 1);
        assert!(third.cleanup_gate("/", later + Duration::from_secs(60), 2 * G, total).is_some());
        // a cleared level forgets the history, and the file goes with it
        third.cleanups.clear();
        third.persist();
        assert!(!path.exists());
    }

    #[test]
    fn cleanup_history_encoding_drops_stale_and_garbage() {
        let now = Instant::now();
        let wall = 10_000_000_000u64;
        let run =
            CleanupRun { at: now - Duration::from_secs(60), avail_before: 7, ineffective: 2, judged: true, freed: 5 };
        let mut runs = HashMap::new();
        runs.insert("/".to_owned(), run);
        let bytes = encode_cleanups(&runs, now, wall).unwrap();
        let back = decode_cleanups(&bytes, now, wall + 30_000);
        let r = back["/"];
        assert_eq!((r.avail_before, r.ineffective, r.judged, r.freed), (7, 2, true, 5));
        assert_eq!(now.saturating_duration_since(r.at).as_secs(), 90, "age = 60 s before + 30 s since");
        assert!(decode_cleanups(&bytes, now, wall + 25 * 3600 * 1000).is_empty(), "older than the longest back-off");
        assert!(decode_cleanups(b"not json", now, wall).is_empty());
    }

    #[test]
    fn who_is_using_the_disk_is_asked_at_once_when_critical() {
        assert!(wants_usage_report(false, Severity::Critical), "no waiting for a second failed cleanup");
        assert!(wants_usage_report(true, Severity::Warning), "a cleanup that freed nothing");
        assert!(!wants_usage_report(false, Severity::Warning));
    }

    #[test]
    fn the_file_walk_stops_as_a_whole_at_its_budgets() {
        let d = tempfile::tempdir().unwrap();
        // 300 directories with one entry each, and a big file at the end
        for i in 0..300 {
            std::fs::create_dir_all(d.path().join(format!("d{i:03}/x"))).unwrap();
        }
        std::fs::write(d.path().join("zz-big"), vec![0u8; 8192]).unwrap();
        let (_, cut) = largest_files_until(d.path(), 4096, 5, 1_000_000, None);
        assert!(!cut);
        // the entry budget ends the walk, not just the directory being read
        let (_, cut) = largest_files_until(d.path(), 4096, 5, 100, None);
        assert!(cut);
        // the deadline too
        let t = Instant::now();
        let (_, cut) = largest_files_until(d.path(), 4096, 5, 1_000_000, Some(t));
        assert!(cut && t.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn largest_files_finds_big_ones() {
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("sub")).unwrap();
        std::fs::write(d.path().join("sub/big"), vec![0u8; 4096]).unwrap();
        std::fs::write(d.path().join("small"), b"x").unwrap();
        let v = largest_files(d.path(), 1000, 5, 1000);
        assert_eq!(v.len(), 1);
        assert!(v[0].0.ends_with("sub/big"));
    }

    #[test]
    fn watches_root_filesystem() {
        let d = DiskDetector::new(&DiskConfig::default());
        let w = d.watched();
        // Containers may have overlay roots; just ensure no duplicates by device.
        let devs: HashSet<&String> = w.iter().map(|m| &m.device).collect();
        assert_eq!(devs.len(), w.len());
    }
}
