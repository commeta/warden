//! System integrity: critical configuration files, persistence locations,
//! privileged binaries (verified against dpkg checksums), new SUID/SGID
//! files and new listening sockets.

use crate::runtime::{Cx, Detector, lock};
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use warden_core::config::IntegrityConfig;
use warden_core::{Event, GlobList, Severity, Subject};
use warden_sys::net;
use warden_sys::util::write_atomic;

/// Files whose content is kept in the baseline so changes can be shown as a
/// line diff (never secrets such as /etc/shadow).
const KEEP_CONTENT: &[&str] = &[
    "/etc/passwd",
    "/etc/group",
    "/etc/sudoers",
    "/etc/sudoers.d/*",
    "/root/.ssh/authorized_keys*",
    "/home/*/.ssh/authorized_keys*",
    "/etc/crontab",
    "/etc/cron.d/*",
    "/var/spool/cron/crontabs/*",
    "/etc/ld.so.preload",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d/*",
    "/etc/rc.local",
    "/etc/environment",
    "/etc/profile.d/*",
    "/etc/systemd/system/*.service",
    "/etc/systemd/system/*/*.service",
    "/etc/apt/sources.list",
    "/etc/apt/sources.list.d/*",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SysRecord {
    pub size: u64,
    pub mtime: i64,
    pub ctime: i64,
    pub ino: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

impl SysRecord {
    /// Cheap change check. Mode and owner are compared too: timestamps have
    /// one-second granularity, so a `chmod` in the same second as the last
    /// check would otherwise go unseen.
    fn same_meta(&self, md: &std::fs::Metadata) -> bool {
        self.size == md.size()
            && self.mtime == md.mtime()
            && self.ctime == md.ctime()
            && self.ino == md.ino()
            && self.mode == md.mode()
            && self.uid == md.uid()
            && self.gid == md.gid()
    }

    /// Same bytes, permissions and owner: what a reader of the file sees did
    /// not change, only its inode or timestamps did (rewritten via
    /// "temp + rename" with the same text, `touch`, a restore from backup).
    fn same_content(&self, other: &SysRecord) -> bool {
        self.hash == other.hash && self.mode == other.mode && self.uid == other.uid && self.gid == other.gid
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct BaselineFile {
    files: BTreeMap<String, SysRecord>,
    #[serde(default)]
    suid: Option<BTreeSet<String>>,
    /// When the last *full* SUID walk finished (Unix ms).
    #[serde(default)]
    suid_scanned_ms: u64,
}

/// State shared between the real-time SUID sensor and the detector.
#[derive(Debug, Default)]
pub struct SuidRealtime {
    /// `suid_paths` roots whose filesystems are marked (empty: not running).
    pub covered: Vec<PathBuf>,
    /// SUID/SGID files seen by the sensor, waiting for the detector.
    pub pending: BTreeSet<String>,
    /// Events were lost (queue overflow, storm): a full walk is needed.
    pub overflow: bool,
}

pub fn hash_file(path: &Path) -> std::io::Result<String> {
    let f = std::fs::File::open(path)?;
    let _cold = warden_sys::pagecache::ColdRead::new(&f);
    let mut h = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = (&f).read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().to_hex().to_string())
}

/// Expand absolute globs into existing regular files.
///
/// Patterns are resolved one path component at a time: literal components
/// are joined without listing anything, and only directories matching a
/// wildcard component are read. `/home/*/.ssh/authorized_keys` lists
/// `/home` and stats one file per user — it does not walk the home
/// directories. `**` walks (bounded).
pub fn expand(patterns: &[String]) -> Vec<PathBuf> {
    let mut out = BTreeSet::new();
    for p in patterns {
        expand_one(p, &mut out);
    }
    out.into_iter().collect()
}

fn has_glob(c: &str) -> bool {
    c.contains(['*', '?', '[', '{'])
}

fn expand_one(pattern: &str, out: &mut BTreeSet<PathBuf>) {
    const MAX_ENTRIES: usize = 20_000;
    if !pattern.starts_with('/') {
        return;
    }
    let comps: Vec<&str> = pattern.split('/').filter(|c| !c.is_empty()).collect();
    let mut frontier = vec![PathBuf::from("/")];
    let mut budget = MAX_ENTRIES;
    for (i, c) in comps.iter().enumerate() {
        let mut next = Vec::new();
        if *c == "**" {
            // Every directory below the frontier (including itself).
            let mut stack: Vec<(PathBuf, usize)> = frontier.into_iter().map(|d| (d, 0)).collect();
            while let Some((d, depth)) = stack.pop() {
                next.push(d.clone());
                if depth >= 8 {
                    continue;
                }
                let Ok(rd) = std::fs::read_dir(&d) else { continue };
                for e in rd.filter_map(Result::ok) {
                    if budget == 0 {
                        break;
                    }
                    budget -= 1;
                    if e.file_type().is_ok_and(|t| t.is_dir()) {
                        stack.push((e.path(), depth + 1));
                    }
                }
            }
        } else if has_glob(c) {
            let m = GlobList::new(&[*c]);
            let last = i + 1 == comps.len();
            for d in &frontier {
                let Ok(rd) = std::fs::read_dir(d) else { continue };
                for e in rd.filter_map(Result::ok) {
                    if budget == 0 {
                        break;
                    }
                    budget -= 1;
                    if !m.is_match(e.file_name()) {
                        continue;
                    }
                    // Intermediate components must be directories.
                    if last || e.file_type().is_ok_and(|t| t.is_dir() || t.is_symlink()) {
                        next.push(e.path());
                    }
                }
            }
        } else {
            next = frontier.iter().map(|d| d.join(c)).collect();
        }
        frontier = next;
        if frontier.is_empty() {
            return;
        }
    }
    for p in frontier {
        if std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_file()) {
            out.insert(p);
        }
    }
}

fn line_diff(old: &str, new: &str) -> (Vec<String>, Vec<String>) {
    let o: HashSet<&str> = old.lines().collect();
    let n: HashSet<&str> = new.lines().collect();
    let added = new.lines().filter(|l| !o.contains(l)).take(20).map(str::to_owned).collect();
    let removed = old.lines().filter(|l| !n.contains(l)).take(20).map(str::to_owned).collect();
    (added, removed)
}

/// uid-0 accounts in a passwd file.
pub fn uid0_accounts(passwd: &str) -> BTreeSet<String> {
    warden_sys::users::parse_passwd(passwd).into_iter().filter(|e| e.uid == 0).map(|e| e.name).collect()
}

/// Classify a change to a watched file: (kind, severity).
pub fn classify(path: &str) -> (&'static str, Severity) {
    let g = |pats: &[&str]| GlobList::new(pats).is_match(path);
    if path == "/etc/ld.so.preload" {
        ("security.ld_so_preload", Severity::Critical)
    } else if g(&["/usr/bin/sudo", "/usr/sbin/sshd", "/usr/bin/passwd", "/bin/login", "/usr/bin/login", "/usr/bin/su"])
    {
        ("security.binary_replaced", Severity::Critical)
    } else if g(&["/etc/sudoers", "/etc/sudoers.d/*"]) {
        ("security.sudoers_changed", Severity::Warning)
    } else if g(&["/root/.ssh/*", "/home/*/.ssh/*"]) {
        ("security.ssh_keys_changed", Severity::Warning)
    } else if g(&["/etc/crontab", "/etc/cron.*/*", "/var/spool/cron/crontabs/*"]) {
        ("security.persistence_cron", Severity::Warning)
    } else if g(&["/etc/systemd/system/**", "/lib/systemd/system/*", "/usr/lib/systemd/system/*"]) {
        ("security.persistence_systemd", Severity::Warning)
    } else if g(&["/etc/pam.d/*", "/etc/security/*"]) {
        ("security.pam_changed", Severity::Warning)
    } else if g(&["/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow"]) {
        ("integrity.accounts_changed", Severity::Notice)
    } else if g(&[
        "/etc/profile",
        "/etc/profile.d/*",
        "/etc/bash.bashrc",
        "/root/.bashrc",
        "/root/.profile",
        "/etc/environment",
        "/etc/rc.local",
    ]) {
        ("security.persistence_shell", Severity::Warning)
    } else if g(&[
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d/*",
        "/etc/modprobe.d/*",
        "/etc/modules-load.d/*",
        "/etc/udev/rules.d/*",
    ]) {
        ("security.persistence_system", Severity::Warning)
    } else {
        ("integrity.file_changed", Severity::Notice)
    }
}

/// Verification of files against dpkg's recorded MD5 checksums.
///
/// All paths of one detector tick are verified in a single pass over
/// `/var/lib/dpkg/info/*.md5sums` (earlier versions re-read every md5sums
/// file once per changed path: an upgrade touching 200 binaries meant 200
/// full passes).
#[derive(Debug, Default)]
pub struct DpkgIndex;

fn dpkg_variants(path: &str) -> Vec<String> {
    let real = std::fs::canonicalize(path).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
    let mut v = vec![path.to_owned(), format!("/usr{path}")];
    if !real.is_empty() {
        if let Some(r) = real.strip_prefix("/usr") {
            v.push(r.to_owned());
        }
        v.push(real);
    }
    v.sort();
    v.dedup();
    v
}

fn md5_file(path: &str) -> Option<String> {
    let f = std::fs::File::open(path).ok()?;
    let _cold = warden_sys::pagecache::ColdRead::new(&f);
    let mut h = Md5::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = (&f).read(&mut buf).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Some(format!("{:x}", h.finalize()))
}

impl DpkgIndex {
    /// `Some(true)`: content matches a package checksum; `Some(false)`:
    /// owned by a package but modified; `None`: not a packaged file.
    pub fn verify_many(&mut self, paths: &[String]) -> HashMap<String, Option<bool>> {
        self.verify_many_in(Path::new("/var/lib/dpkg/info"), paths)
    }

    fn verify_many_in(&mut self, info: &Path, paths: &[String]) -> HashMap<String, Option<bool>> {
        let mut out: HashMap<String, Option<bool>> = paths.iter().map(|p| (p.clone(), None)).collect();
        if paths.is_empty() {
            return out;
        }
        let mut want: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, p) in paths.iter().enumerate() {
            for v in dpkg_variants(p) {
                want.entry(v).or_default().push(i);
            }
        }
        let mut expected: Vec<Vec<String>> = vec![Vec::new(); paths.len()];
        if let Ok(rd) = std::fs::read_dir(info) {
            let mut buf = String::new();
            for e in rd.filter_map(Result::ok) {
                if !e.file_name().to_string_lossy().ends_with(".md5sums") {
                    continue;
                }
                let Ok(f) = std::fs::File::open(e.path()) else { continue };
                let _cold = warden_sys::pagecache::ColdRead::new(&f);
                buf.clear();
                if (&f).read_to_string(&mut buf).is_err() {
                    continue;
                }
                for l in buf.lines() {
                    let Some((sum, rel)) = l.split_once("  ") else { continue };
                    let key = format!("/{rel}");
                    if let Some(idx) = want.get(&key) {
                        for i in idx {
                            expected[*i].push(sum.to_owned());
                        }
                    }
                }
            }
        }
        for (i, p) in paths.iter().enumerate() {
            if expected[i].is_empty() {
                continue;
            }
            let real = std::fs::canonicalize(p).map(|r| r.to_string_lossy().into_owned()).unwrap_or_else(|_| p.clone());
            let actual = md5_file(&real);
            out.insert(p.clone(), actual.map(|a| expected[i].contains(&a)));
        }
        out
    }

    pub fn verify(&mut self, path: &str) -> Option<bool> {
        self.verify_many(&[path.to_owned()]).remove(path).flatten()
    }
}

/// A finished walk: the roots walked, whether it was a full walk, the files.
type SuidResult = Arc<Mutex<Option<(Vec<PathBuf>, bool, BTreeSet<String>)>>>;

pub struct IntegrityDetector {
    cfg: IntegrityConfig,
    path: PathBuf,
    state: Option<BaselineFile>,
    keep: GlobList,
    dpkg: DpkgIndex,
    /// When the next walk is due, on [`warden_sys::clock`] ("every 24 h"
    /// means real hours, sleep included).
    suid_next: Instant,
    suid_job: Option<(std::thread::JoinHandle<()>, SuidResult)>,
    suid_defer: warden_sys::pace::Deferral,
    listeners: Option<HashSet<(String, u32)>>,
    ignore_ports: HashSet<u16>,
    web_users: HashSet<String>,
}

impl IntegrityDetector {
    pub fn new(cfg: &warden_core::Config) -> Self {
        Self {
            cfg: cfg.integrity.clone(),
            path: cfg.daemon.state_dir.join("integrity.json"),
            state: None,
            keep: GlobList::new(KEEP_CONTENT),
            dpkg: DpkgIndex,
            suid_next: warden_sys::clock::now() + cfg.integrity.suid_delay,
            suid_job: None,
            suid_defer: Default::default(),
            listeners: None,
            ignore_ports: cfg.integrity.listener_ignore_ports.iter().copied().collect(),
            web_users: cfg.process.web_users.iter().cloned().collect(),
        }
    }

    fn record(&self, p: &Path, md: &std::fs::Metadata) -> Option<SysRecord> {
        let hash = hash_file(p).ok()?;
        let content =
            if self.keep.is_match(p) && md.size() <= 256 * 1024 { std::fs::read_to_string(p).ok() } else { None };
        Some(SysRecord {
            size: md.size(),
            mtime: md.mtime(),
            ctime: md.ctime(),
            ino: md.ino(),
            mode: md.mode(),
            uid: md.uid(),
            gid: md.gid(),
            hash,
            content,
        })
    }

    fn save(&self) {
        if let Some(st) = &self.state
            && let Ok(s) = serde_json::to_vec(st)
            && let Err(e) = write_atomic(&self.path, &s)
        {
            tracing::warn!(error = %e, "cannot save integrity baseline");
        }
    }

    fn check_files(&mut self, cx: &Cx<'_>) {
        let files = expand(&self.cfg.files);
        let first = self.state.is_none();
        if first {
            self.state =
                Some(std::fs::read(&self.path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default());
        }
        let fresh = self.state.as_ref().is_some_and(|s| s.files.is_empty());
        let mut changed = false;
        let mut seen = HashSet::new();
        let mut reports: Vec<(String, Option<SysRecord>, Option<SysRecord>)> = Vec::new();
        for p in &files {
            let key = p.to_string_lossy().into_owned();
            seen.insert(key.clone());
            let Ok(md) = std::fs::symlink_metadata(p) else { continue };
            let prev = self.state.as_ref().and_then(|s| s.files.get(&key)).cloned();
            if prev.as_ref().is_some_and(|r| r.same_meta(&md)) {
                continue;
            }
            let Some(rec) = self.record(p, &md) else { continue };
            changed = true;
            // Only the inode or the timestamps moved: refresh the baseline
            // quietly — the event would carry empty diffs (Chrome's daily
            // cron rewrites its apt source like that).
            let same = prev.as_ref().is_some_and(|o| o.same_content(&rec));
            if !fresh && !same {
                reports.push((key.clone(), prev, Some(rec.clone())));
            }
            if let Some(st) = self.state.as_mut() {
                st.files.insert(key, rec);
            }
        }
        let gone: Vec<String> = self
            .state
            .as_ref()
            .map(|s| s.files.keys().filter(|k| !seen.contains(*k)).cloned().collect())
            .unwrap_or_default();
        for k in gone {
            let prev = self.state.as_mut().and_then(|s| s.files.remove(&k));
            changed = true;
            if !fresh {
                reports.push((k, prev, None));
            }
        }
        // Package upgrades legitimately replace binaries and unit files:
        // verify all changed packaged paths in one pass.
        let packaged: Vec<String> = reports
            .iter()
            .filter(|(p, _, new)| {
                new.is_some() && (p.starts_with("/usr/") || p.starts_with("/bin/") || p.starts_with("/lib/"))
            })
            .map(|(p, _, _)| p.clone())
            .collect();
        let verified = self.dpkg.verify_many(&packaged);
        for (path, old, new) in reports {
            let dpkg = verified.get(&path).copied().flatten();
            self.report(cx, &path, old.as_ref(), new.as_ref(), dpkg);
        }
        if fresh {
            cx.emit(
                Event::new(
                    "integrity.baseline_created",
                    Severity::Info,
                    format!("system integrity baseline created ({} files)", files.len()),
                )
                .fingerprint("integrity.baseline_created"),
            );
        }
        if changed {
            self.save();
        }
        cx.metric("warden_integrity_files", &[], files.len() as f64);
    }

    fn report(
        &mut self,
        cx: &Cx<'_>,
        path: &str,
        old: Option<&SysRecord>,
        new: Option<&SysRecord>,
        dpkg: Option<bool>,
    ) {
        let (kind, mut sev) = classify(path);
        let what = match (old, new) {
            (None, Some(_)) => "created",
            (Some(_), None) => "deleted",
            (Some(o), Some(n)) if o.hash == n.hash => "metadata changed",
            _ => "modified",
        };
        if what == "deleted" && kind == "security.ld_so_preload" {
            sev = Severity::Notice;
        }
        let mut ev = Event::new(kind, sev, format!("{path} {what}"))
            .subject(Subject::File { path: path.to_owned(), site: None });
        if let (Some(o), Some(n)) = (old, new) {
            if o.mode != n.mode {
                ev = ev.detail("mode", format!("{:o} → {:o}", o.mode & 0o7777, n.mode & 0o7777));
            }
            if o.uid != n.uid || o.gid != n.gid {
                ev = ev.detail("owner", format!("{}:{} → {}:{}", o.uid, o.gid, n.uid, n.gid));
            }
            if let (Some(a), Some(b)) = (&o.content, &n.content) {
                let (added, removed) = line_diff(a, b);
                if path == "/etc/passwd" {
                    let new0: Vec<String> = uid0_accounts(b).difference(&uid0_accounts(a)).cloned().collect();
                    if !new0.is_empty() {
                        ev.severity = Severity::Critical;
                        ev.kind = "security.uid0_account".into();
                        ev.title = format!("new uid 0 account(s) in /etc/passwd: {}", new0.join(", "));
                    }
                }
                if path.contains("authorized_keys") && !added.is_empty() {
                    ev.kind = "security.ssh_key_added".into();
                    ev.title = format!("{} SSH key(s) added to {path}", added.len());
                }
                ev = ev.detail("added_lines", added).detail("removed_lines", removed);
            }
        } else if let Some(n) = new
            && let Some(c) = &n.content
        {
            ev = ev.detail("content_head", c.lines().take(15).collect::<Vec<_>>().join("\n"));
        }
        if new.is_some() {
            match dpkg {
                Some(true) => {
                    ev.severity = Severity::Info;
                    ev.title = format!("{path} {what} (matches dpkg checksum — package upgrade)");
                    ev = ev.detail("dpkg_verified", true);
                }
                Some(false) => {
                    ev.severity = Severity::Critical;
                    ev =
                        ev.detail("dpkg_verified", false).detail("hint", "content does NOT match the package checksum");
                }
                None => {}
            }
        }
        ev.fingerprint = format!("{}:{path}:{}", ev.kind, new.map(|n| n.hash.as_str()).unwrap_or("deleted"));
        ev.actions = if ev.severity >= Severity::Warning { self.cfg.on_change.clone() } else { Vec::new() };
        cx.emit(ev);
    }

    /// Report SUID/SGID files that are not in the baseline.
    fn report_new_suid(&mut self, cx: &Cx<'_>, new: &[String], how: &str) {
        if new.is_empty() {
            return;
        }
        let writable = GlobList::new(&["/tmp/**", "/var/tmp/**", "/dev/shm/**", "/home/**", "/var/www/**", "/srv/**"]);
        let verified = self.dpkg.verify_many(new);
        for p in new {
            let dpkg = verified.get(p).copied().flatten();
            let sev = if writable.is_match(p) {
                Severity::Critical
            } else if dpkg == Some(true) {
                Severity::Info
            } else {
                Severity::Warning
            };
            let mode = std::fs::metadata(p).map(|m| format!("{:o}", m.mode() & 0o7777)).unwrap_or_default();
            cx.emit(
                Event::new("security.new_suid", sev, format!("new SUID/SGID file: {p} (mode {mode})"))
                    .subject(Subject::File { path: p.clone(), site: None })
                    .fingerprint(format!("security.new_suid:{p}"))
                    .detail("dpkg_verified", dpkg)
                    .detail("detected_by", how)
                    .detail("hint", "SUID binaries in user-writable locations are a classic root backdoor"),
            );
        }
    }

    fn apply_walk(&mut self, cx: &Cx<'_>, roots: &[PathBuf], full: bool, found: BTreeSet<String>) {
        let st = self.state.get_or_insert_with(Default::default);
        let new: Vec<String> = match &mut st.suid {
            None => {
                cx.emit(
                    Event::new(
                        "integrity.suid_baseline",
                        Severity::Info,
                        format!("SUID/SGID baseline: {} files", found.len()),
                    )
                    .fingerprint("integrity.suid_baseline"),
                );
                st.suid = Some(found);
                Vec::new()
            }
            Some(prev) => {
                // A partial walk only speaks for its own roots.
                let under = |p: &String| roots.iter().any(|r| Path::new(p).starts_with(r));
                let new: Vec<String> = found.iter().filter(|p| !prev.contains(*p)).cloned().collect();
                prev.retain(|p| !under(p));
                prev.extend(found);
                new
            }
        };
        if full {
            st.suid_scanned_ms = warden_core::event::now_ms();
        }
        let n = st.suid.as_ref().map(BTreeSet::len).unwrap_or(0);
        self.report_new_suid(cx, &new, if full { "full walk" } else { "walk of roots without real-time coverage" });
        cx.metric("warden_suid_files", &[], n as f64);
        self.save();
    }

    /// Candidates from the real-time sensor.
    fn apply_realtime(&mut self, cx: &Cx<'_>, candidates: BTreeSet<String>) {
        let Some(st) = self.state.as_mut() else { return };
        let Some(base) = st.suid.as_mut() else { return }; // the first walk will see them
        let mut new = Vec::new();
        for p in candidates {
            // still there and still SUID/SGID (dpkg's .dpkg-new files are gone by now)
            let ok = std::fs::symlink_metadata(&p).is_ok_and(|m| m.is_file() && m.mode() & 0o6000 != 0);
            if ok && base.insert(p.clone()) {
                new.push(p);
            }
        }
        if new.is_empty() {
            return;
        }
        let n = base.len();
        self.report_new_suid(cx, &new, "real time (fanotify)");
        cx.metric("warden_suid_files", &[], n as f64);
        self.save();
    }

    fn suid_scan(&mut self, cx: &Cx<'_>) {
        let now = cx.real;
        // Collect a finished walk.
        if let Some((h, res)) = &self.suid_job
            && h.is_finished()
        {
            let out = lock(res).take();
            self.suid_job = None;
            if let Some((roots, full, found)) = out {
                self.apply_walk(cx, &roots, full, found);
            }
        }
        // Real-time candidates.
        let realtime = cx.shared.sensor_running("suid_realtime");
        let (covered, pending, overflow) = {
            let mut rt = lock(&cx.shared.suid_rt);
            let overflow = std::mem::take(&mut rt.overflow);
            (rt.covered.clone(), std::mem::take(&mut rt.pending), overflow)
        };
        if !pending.is_empty() {
            self.apply_realtime(cx, pending);
        }
        if overflow {
            tracing::info!("real-time SUID events were lost; scheduling a full walk");
            self.suid_next = now;
        }
        // Schedule walks.
        if self.suid_job.is_some() || now < self.suid_next {
            return;
        }
        // A periodic walk waits for a quiet disk (for a bounded time); the
        // first baseline and a walk after lost real-time events do not.
        let urgent = overflow || self.state.as_ref().is_none_or(|s| s.suid.is_none());
        if !urgent {
            let pressure = warden_sys::pace::io_pressure();
            let first = self.suid_defer.waiting(now).is_none();
            if let Some(wait) = self.suid_defer.check(&warden_sys::pace::params(), "suid", now, pressure) {
                if first {
                    tracing::info!(
                        io_pressure_percent = pressure.unwrap_or_default() * 100.0,
                        "SUID/SGID walk postponed: the disk is busy"
                    );
                }
                self.suid_next = now + wait;
                return;
            }
        }
        self.suid_next = now + self.cfg.suid_interval;
        let all: Vec<PathBuf> = self.cfg.suid_paths.iter().map(PathBuf::from).collect();
        let st = self.state.get_or_insert_with(Default::default);
        let last_full = Duration::from_millis(warden_core::event::now_ms().saturating_sub(st.suid_scanned_ms));
        let active = realtime && !covered.is_empty();
        let full =
            !active || overflow || st.suid.is_none() || st.suid_scanned_ms == 0 || last_full >= self.cfg.suid_rescan;
        let roots: Vec<PathBuf> =
            if full { all } else { all.into_iter().filter(|r| !covered.iter().any(|c| c == r)).collect() };
        if roots.is_empty() {
            return; // everything is watched in real time and the baseline is fresh
        }
        let exclude = GlobList::new(&self.cfg.suid_exclude);
        let res: SuidResult = Arc::new(Mutex::new(None));
        let r2 = res.clone();
        let metrics = cx.shared.metrics_handle();
        if let Ok(h) = std::thread::Builder::new().name("w-suid-scan".into()).spawn(move || {
            crate::prof::set_thread_scope(crate::prof::scope_id("integrity"));
            let _ = warden_sys::sched::background_thread();
            let started = Instant::now();
            // nothing waits for this walk: it may slow down to a tenth
            let mut pace = warden_sys::pace::Pacer::new("suid", 0.1, true);
            let scan = find_suid_with(&roots, &exclude, &mut pace);
            if let Some(m) = metrics {
                m.metrics.set("warden_suid_scan_entries", &[], scan.entries as f64);
                m.metrics.set("warden_suid_scan_seconds", &[], started.elapsed().as_secs_f64());
            }
            tracing::info!(
                files = scan.found.len(),
                entries = scan.entries,
                skipped_mounts = scan.skipped_mounts,
                full,
                seconds = started.elapsed().as_secs_f64(),
                paced_seconds = pace.paced().as_secs_f64(),
                "SUID/SGID scan finished"
            );
            tracing::debug!(bytes = warden_sys::selfstat::release_memory(), "SUID scan memory released");
            *lock(&r2) = Some((roots, full, scan.found));
        }) {
            self.suid_job = Some((h, res));
        }
    }

    fn check_listeners(&mut self, cx: &Cx<'_>) {
        let socks: Vec<net::Socket> = net::tcp_sockets().into_iter().filter(|s| s.state == net::TCP_LISTEN).collect();
        let now: HashSet<(String, u32)> = socks.iter().map(|s| (s.local.to_string(), s.uid)).collect();
        if let Some(prev) = &self.listeners {
            let new: Vec<&net::Socket> = socks
                .iter()
                .filter(|s| {
                    !prev.contains(&(s.local.to_string(), s.uid)) && !self.ignore_ports.contains(&s.local.port())
                })
                .collect();
            if !new.is_empty() {
                let owners = net::socket_owners(&new.iter().map(|s| s.inode).collect());
                for s in new {
                    let pid = owners.get(&s.inode).copied();
                    let user = cx.shared.user_name(s.uid);
                    let comm =
                        pid.and_then(|p| warden_sys::process::read_stat(p).ok()).map(|x| x.comm).unwrap_or_default();
                    let exe = pid.and_then(warden_sys::process::exe).unwrap_or_default();
                    let shellish = ["sh", "bash", "dash", "nc", "ncat", "socat", "python", "python3", "perl", "php"]
                        .contains(&comm.as_str());
                    let web = self.web_users.contains(&user);
                    let sev = if shellish || web {
                        Severity::Critical
                    } else if s.local.ip().is_loopback() {
                        Severity::Info
                    } else {
                        Severity::Notice
                    };
                    let kind = if shellish { "security.bind_shell" } else { "security.new_listener" };
                    let mut ev = Event::new(
                        kind,
                        sev,
                        format!("new listening socket {} by {comm}[{}] ({user})", s.local, pid.unwrap_or(0)),
                    )
                    .fingerprint(format!("{kind}:{}:{}", s.local, s.uid))
                    .detail("exe", exe)
                    .detail("user", user.clone());
                    if let Some(pid) = pid
                        && let Some(r) = crate::util::process_ref(pid, &|u| cx.shared.user_name(u))
                    {
                        ev = ev.subject(Subject::Process(r));
                    }
                    cx.emit(ev);
                }
            }
        }
        self.listeners = Some(now);
    }
}

/// Filesystems never worth walking for SUID files: pseudo, network,
/// read-only images (snaps) and container layers.
const SUID_SKIP_FS: &[&str] = &[
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "cgroup",
    "cgroup2",
    "debugfs",
    "tracefs",
    "securityfs",
    "pstore",
    "bpf",
    "mqueue",
    "hugetlbfs",
    "configfs",
    "fusectl",
    "autofs",
    "binfmt_misc",
    "nsfs",
    "efivarfs",
    "rpc_pipefs",
    "nfs",
    "nfs4",
    "cifs",
    "smb3",
    "smbfs",
    "9p",
    "ceph",
    "glusterfs",
    "fuse.sshfs",
    "fuse.rclone",
    "squashfs",
    "overlay",
    "iso9660",
    "udf",
];

pub struct SuidScan {
    pub found: BTreeSet<String>,
    pub entries: usize,
    pub skipped_mounts: usize,
}

/// Walk roots for SUID/SGID regular files.
///
/// Mounts with `nosuid` (where the bit has no effect), pseudo and network
/// filesystems and `suid_exclude` globs are pruned; directories are
/// recognised from `getdents` (`d_type`) and only regular files are
/// `stat`ed. Every inode touched still lands in the kernel's inode cache
/// (charged to Warden's cgroup as reclaimable slab), which is why this runs
/// rarely and in its own idle-priority thread, paced by `pace`.
pub fn find_suid_with(roots: &[PathBuf], exclude: &GlobList, pace: &mut warden_sys::pace::Pacer) -> SuidScan {
    const MAX_ENTRIES: usize = 5_000_000;
    let mut skip_mounts: HashSet<PathBuf> = HashSet::new();
    if let Ok(ms) = warden_sys::mounts::mounts() {
        for m in ms {
            let nosuid = m.options.split(',').any(|o| o == "nosuid");
            if (nosuid || SUID_SKIP_FS.contains(&m.fstype.as_str())) && m.mount_point != "/" {
                skip_mounts.insert(PathBuf::from(&m.mount_point));
            }
        }
    }
    let skip = ["/proc", "/sys", "/dev", "/run", "/snap"];
    let mut out = SuidScan { found: BTreeSet::new(), entries: 0, skipped_mounts: 0 };
    let mut visited_roots: HashSet<PathBuf> = HashSet::new();
    for root in roots {
        if !visited_roots.insert(root.clone()) {
            continue;
        }
        let mut stack = vec![root.clone()];
        while let Some(d) = stack.pop() {
            if skip_mounts.contains(&d) {
                out.skipped_mounts += 1;
                continue;
            }
            let ds = d.to_string_lossy();
            if skip.iter().any(|s| ds == *s || ds.starts_with(&format!("{s}/"))) && !ds.starts_with("/dev/shm") {
                continue;
            }
            if !exclude.is_empty() && exclude.is_match(&*d) {
                continue;
            }
            let Ok(rd) = std::fs::read_dir(&d) else { continue };
            for e in rd.filter_map(Result::ok) {
                out.entries += 1;
                pace.step();
                if out.entries > MAX_ENTRIES {
                    return out;
                }
                let Ok(ft) = e.file_type() else { continue };
                if ft.is_dir() {
                    stack.push(e.path());
                } else if ft.is_file()
                    && let Ok(md) = e.metadata()
                    && md.mode() & 0o6000 != 0
                {
                    out.found.insert(e.path().to_string_lossy().into_owned());
                }
            }
        }
    }
    out
}

/// Real-time SUID/SGID sensor: fanotify filesystem marks for attribute
/// changes, creations and renames on every filesystem holding a
/// `suid_paths` root. Only entries that are regular files with the SUID or
/// SGID bit cost a path lookup; the rest is one `fstatat`.
pub fn run_suid_realtime(shared: &Arc<crate::runtime::Shared>) -> Result<(), String> {
    use warden_sys::fanotify_fid::FidWatcher;
    let cfg = shared.config();
    let c = &cfg.integrity;
    if !(c.enabled && c.suid_scan && c.suid_realtime) {
        return Ok(());
    }
    let generation = shared.generation();
    let mut w = FidWatcher::new().map_err(|e| {
        format!(
            "fanotify FAN_REPORT_DFID_NAME: {e}{} (Linux 5.9+ needed; falling back to periodic walks)",
            warden_sys::sched::permission_hint(&e, "CAP_SYS_ADMIN")
        )
    })?;
    let mask = libc::FAN_ATTRIB | libc::FAN_CREATE | libc::FAN_MOVED_TO;
    let mut covered = Vec::new();
    for r in c.suid_paths.iter().map(PathBuf::from).filter(|r| r.is_dir()) {
        match w.watch_filesystem(&r, mask) {
            Ok(_) => covered.push(r),
            Err(e) => {
                tracing::info!(root = %r.display(), error = %e, "no real-time SUID coverage; walked periodically")
            }
        }
    }
    if covered.is_empty() {
        return Err("no filesystem of integrity.suid_paths could be marked (fanotify filesystem marks)".into());
    }
    let exclude = GlobList::new(&c.suid_exclude);
    lock(&shared.suid_rt).covered = covered.clone();
    shared.set_sensor("suid_realtime", crate::runtime::SensorState::Running);
    tracing::info!(filesystems = w.filesystems(), roots = covered.len(), "real-time SUID detection active");

    // Package managers write `x.dpkg-new`, chmod it and rename it: wait a
    // little before reporting, so the detector sees the final state.
    let settle = |p: &str| {
        if ["/usr/", "/bin/", "/sbin/", "/lib", "/opt/"].iter().any(|d| p.starts_with(d)) {
            Duration::from_secs(30)
        } else {
            Duration::from_secs(2)
        }
    };
    let mut waiting: BTreeMap<String, Instant> = BTreeMap::new();
    let mut window = Instant::now();
    let mut in_window = 0u32;
    let mut creates: HashMap<(i32, i32, Vec<u8>), u32> = HashMap::new();
    let mut muted = 0usize;
    const STORM: u32 = 50_000; // events per 10 s before we stop resolving and walk instead
    let result = loop {
        let evs = match w.read_timeout(Duration::from_secs(2)) {
            Ok(v) => v,
            Err(e) => break Err(e.to_string()),
        };
        if shared.generation() != generation || shared.is_shutting_down() {
            break Err("configuration reloaded".into());
        }
        for ev in evs {
            if ev.overflow() {
                lock(&shared.suid_rt).overflow = true;
                shared.metrics.inc("warden_suid_realtime_overflows_total", &[], 1.0);
                continue;
            }
            in_window += 1;
            if in_window > STORM {
                if in_window == STORM + 1 {
                    lock(&shared.suid_rt).overflow = true;
                    tracing::info!(
                        "attribute-change storm; real-time SUID check paused for this window, full walk scheduled"
                    );
                }
                continue;
            }
            shared.metrics.inc("warden_suid_realtime_events_total", &[], 1.0);
            let Ok(st) = w.stat_entry(&ev) else { continue };
            if !(st.is_regular() && st.setid()) {
                // Mute creations (never attribute changes or renames) in
                // directories that create files non-stop: PHP sessions, caches.
                if ev.mask & libc::FAN_CREATE != 0 && muted < 256 {
                    let n = creates.entry((ev.fsid[0], ev.fsid[1], ev.handle.clone())).or_default();
                    *n += 1;
                    if *n == 200 && w.ignore_in_dir(&ev, libc::FAN_CREATE).is_ok() {
                        muted += 1;
                        shared.metrics.set("warden_suid_realtime_muted_dirs", &[], muted as f64);
                    }
                }
                continue;
            }
            let Ok(path) = w.path_of(&ev) else { continue };
            let ps = path.to_string_lossy().into_owned();
            if !covered.iter().any(|r| path.starts_with(r)) || (!exclude.is_empty() && exclude.is_match(&path)) {
                continue;
            }
            let due = Instant::now() + settle(&ps);
            waiting.entry(ps).or_insert(due);
        }
        let now = Instant::now();
        if now.saturating_duration_since(window) >= Duration::from_secs(10) {
            window = now;
            in_window = 0;
            creates.clear();
            w.forget_dirs();
        }
        let due: Vec<String> = waiting.iter().filter(|(_, t)| **t <= now).map(|(p, _)| p.clone()).collect();
        if !due.is_empty() {
            {
                let mut rt = lock(&shared.suid_rt);
                for p in &due {
                    waiting.remove(p);
                    rt.pending.insert(p.clone());
                }
            }
            shared.wake(crate::runtime::Wake::Detector("integrity"));
        }
    };
    lock(&shared.suid_rt).covered.clear();
    result
}

impl Detector for IntegrityDetector {
    fn name(&self) -> &'static str {
        "integrity"
    }

    fn sections(&self) -> &'static [&'static str] {
        &["/integrity", "/daemon/state_dir", "/process/web_users"]
    }

    fn reconfigure(&mut self, cfg: &warden_core::Config) -> bool {
        if cfg.daemon.state_dir.join("integrity.json") != self.path {
            return false; // another baseline file: start over
        }
        // the baseline, the listener set and the SUID schedule stay: a
        // reload does not start a new walk
        self.ignore_ports = cfg.integrity.listener_ignore_ports.iter().copied().collect();
        self.web_users = cfg.process.web_users.iter().cloned().collect();
        self.cfg = cfg.integrity.clone();
        true
    }

    fn interval(&self) -> Duration {
        let mut i = self.cfg.interval;
        if self.cfg.suid_scan {
            if self.suid_job.is_some() {
                i = i.min(Duration::from_secs(2)); // collect the walk promptly
            } else {
                i = i.min(
                    self.suid_next.saturating_duration_since(warden_sys::clock::now()).max(Duration::from_secs(1)),
                );
            }
        }
        i
    }

    fn tick(&mut self, cx: &mut Cx<'_>) {
        self.check_files(cx);
        if self.cfg.suid_scan {
            self.suid_scan(cx);
        }
        if self.cfg.listeners {
            self.check_listeners(cx);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classification() {
        assert_eq!(classify("/etc/ld.so.preload").0, "security.ld_so_preload");
        assert_eq!(classify("/etc/sudoers.d/90-cloud").0, "security.sudoers_changed");
        assert_eq!(classify("/home/bob/.ssh/authorized_keys").0, "security.ssh_keys_changed");
        assert_eq!(classify("/etc/cron.d/x").0, "security.persistence_cron");
        assert_eq!(
            classify("/etc/systemd/system/multi-user.target.wants/evil.service").0,
            "security.persistence_systemd"
        );
        assert_eq!(classify("/etc/hosts").0, "integrity.file_changed");
    }

    #[test]
    fn uid0_detection_and_diff() {
        let a = "root:x:0:0::/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n";
        let b = format!("{a}toor:x:0:0::/root:/bin/bash\n");
        let n: Vec<String> = uid0_accounts(&b).difference(&uid0_accounts(a)).cloned().collect();
        assert_eq!(n, vec!["toor"]);
        let (added, removed) = line_diff(a, &b);
        assert_eq!(added.len(), 1);
        assert!(removed.is_empty());
    }

    #[test]
    fn expand_and_suid() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        std::fs::create_dir(d.path().join("cron.d")).unwrap();
        std::fs::write(d.path().join("cron.d/job"), "* * * * * root id").unwrap();
        std::fs::write(d.path().join("other"), "x").unwrap();
        let pat = format!("{}/cron.d/*", d.path().display());
        let files = expand(&[pat]);
        assert_eq!(files.len(), 1);
        let s = d.path().join("rootme");
        std::fs::write(&s, "x").unwrap();
        std::fs::set_permissions(&s, std::fs::Permissions::from_mode(0o4755)).unwrap();
        let found =
            find_suid_with(&[d.path().to_path_buf()], &GlobList::default(), &mut warden_sys::pace::Pacer::off("suid"))
                .found;
        assert!(found.iter().any(|p| p.ends_with("rootme")));
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn suid_walks_and_realtime_candidates_update_the_baseline() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        let (a, b) = (d.path().join("a"), d.path().join("b"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        let mk = |p: &Path| {
            std::fs::write(p, "x").unwrap();
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o4755)).unwrap();
            p.to_string_lossy().into_owned()
        };
        let a1 = mk(&a.join("one"));
        let b1 = mk(&b.join("one"));
        let mut cfg = warden_core::Config::default();
        cfg.daemon.state_dir = d.path().join("state");
        let shared = crate::runtime::Shared::new(cfg.clone());
        let (sink, events) = crate::runtime::Sink::collector();
        let cx = Cx::new(&shared, &cfg, &sink, "integrity");
        let mut det = IntegrityDetector::new(&cfg);
        let set = |v: &[&String]| v.iter().map(|s| (*s).clone()).collect::<BTreeSet<String>>();

        // first (full) walk: baseline, no alerts
        det.apply_walk(&cx, &[a.clone(), b.clone()], true, set(&[&a1, &b1]));
        assert!(lock(&events).iter().any(|e| e.kind == "integrity.suid_baseline"));
        assert!(det.state.as_ref().unwrap().suid_scanned_ms > 0);
        lock(&events).clear();

        // partial walk of root `a` only: b's entries are kept, a's replaced
        let a2 = mk(&a.join("two"));
        det.apply_walk(&cx, std::slice::from_ref(&a), false, set(&[&a2]));
        let base = det.state.as_ref().unwrap().suid.clone().unwrap();
        assert!(base.contains(&b1) && base.contains(&a2) && !base.contains(&a1));
        let ev: Vec<_> = lock(&events).iter().filter(|e| e.kind == "security.new_suid").cloned().collect();
        assert_eq!(ev.len(), 1);
        assert_eq!(ev[0].details["detected_by"], "walk of roots without real-time coverage");
        lock(&events).clear();

        // real-time candidates: reported once, vanished files ignored
        let b2 = mk(&b.join("two"));
        let gone = b.join("gone.dpkg-new").to_string_lossy().into_owned();
        det.apply_realtime(&cx, set(&[&b2, &gone, &b1]));
        let ev: Vec<_> = lock(&events).iter().filter(|e| e.kind == "security.new_suid").cloned().collect();
        assert_eq!(ev.len(), 1, "{ev:?}");
        assert_eq!(ev[0].details["detected_by"], "real time (fanotify)");
        det.apply_realtime(&cx, set(&[&b2]));
        assert_eq!(lock(&events).iter().filter(|e| e.kind == "security.new_suid").count(), 1, "not twice");
    }

    #[test]
    fn expansion_does_not_walk_unrelated_trees() {
        let d = tempfile::tempdir().unwrap();
        let home = d.path().join("home");
        for u in ["alice", "bob"] {
            std::fs::create_dir_all(home.join(u).join(".ssh")).unwrap();
            // deep, unrelated content that must never be listed
            std::fs::create_dir_all(home.join(u).join("src/a/b/c")).unwrap();
            std::fs::write(home.join(u).join("src/a/b/c/authorized_keys"), "decoy").unwrap();
        }
        std::fs::write(home.join("alice/.ssh/authorized_keys"), "ssh-ed25519 AAAA").unwrap();
        std::fs::write(home.join("stray-file"), "x").unwrap();
        let pat = format!("{}/*/.ssh/authorized_keys", home.display());
        assert_eq!(expand(&[pat]), vec![home.join("alice/.ssh/authorized_keys")]);
        let pat = format!("{}/**/authorized_keys", home.display());
        assert_eq!(expand(&[pat]).len(), 3, "** walks (the real key and both decoys)");
        let pat = format!("{}/alice/.ssh/authorized_keys", home.display());
        assert_eq!(expand(&[pat]).len(), 1, "literal path");
    }

    #[test]
    fn batch_dpkg_verification_reads_md5sums_once() {
        let d = tempfile::tempdir().unwrap();
        let info = d.path().join("info");
        std::fs::create_dir(&info).unwrap();
        let bin = d.path().join("tool");
        std::fs::write(&bin, "hello\n").unwrap();
        let other = d.path().join("other");
        std::fs::write(&other, "tampered\n").unwrap();
        // md5("hello\n") = b1946ac92492d2347c6235b4d2611184
        let rel = |p: &Path| p.to_string_lossy().trim_start_matches('/').to_owned();
        std::fs::write(
            info.join("pkg.md5sums"),
            format!(
                "b1946ac92492d2347c6235b4d2611184  {}\nb1946ac92492d2347c6235b4d2611184  {}\n",
                rel(&bin),
                rel(&other)
            ),
        )
        .unwrap();
        let paths =
            vec![bin.to_string_lossy().into_owned(), other.to_string_lossy().into_owned(), "/nonexistent/x".to_owned()];
        let r = DpkgIndex.verify_many_in(&info, &paths);
        assert_eq!(r[&paths[0]], Some(true));
        assert_eq!(r[&paths[1]], Some(false));
        assert_eq!(r[&paths[2]], None);
    }

    #[test]
    fn dpkg_verification_of_a_packaged_binary() {
        let mut idx = DpkgIndex;
        // On Debian/Ubuntu /usr/bin/ls is packaged and unmodified.
        if std::path::Path::new("/var/lib/dpkg/info/coreutils.md5sums").exists() {
            assert_eq!(idx.verify("/usr/bin/ls"), Some(true));
        }
        assert_eq!(idx.verify("/nonexistent/file"), None);
    }
}
