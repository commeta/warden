//! Web file-integrity monitoring.
//!
//! * **Baseline** of every script-like file per site (BLAKE3 + metadata),
//!   verified on a schedule with idle I/O priority; ctime-based change
//!   detection defeats timestomping.
//! * **Real-time** close-after-write events via fanotify, including the
//!   **writer PID** — the PHP-FPM/Node worker that modified the file.
//! * **Signatures** score content (webshells, droppers, obfuscation,
//!   injected JS, `.htaccess` tricks); scripts inside upload directories and
//!   images with embedded server code are always flagged.
//! * **Correlation** with the access log names the request that most likely
//!   planted the file; requests that later hit a flagged file are blocked.
//! * **Response**: quarantine, kill the writing worker, restart the pool,
//!   block attackers — and auto-accept changes made by trusted deploy tools.

pub mod correlate;
pub mod signatures;
pub mod store;

use crate::runtime::{Lease, SensorState, Shared, Sink, lock};
use serde::Serialize;
use signatures::{Signatures, Verdict};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use store::{Baseline, FileHasher, FileRecord, SiteMatcher, hash_file, walk, walk_paced};
use warden_core::config::{FimConfig, FimSite};
use warden_core::event::now_ms;
use warden_core::{ActionSpec, Event, GlobList, ProcessRef, Severity, Subject};

/// The process that wrote a file (from fanotify).
#[derive(Debug, Clone, Serialize)]
pub struct Writer {
    pub pid: i32,
    pub start_time: u64,
    pub comm: String,
    pub exe: Option<String>,
    pub uid: u32,
    pub user: String,
    pub cmdline: String,
    pub cgroup: Option<String>,
}

impl Writer {
    pub fn read(pid: i32, users: &dyn Fn(u32) -> String) -> Option<Self> {
        let info = warden_sys::process::read_info(pid).ok()?;
        Some(Self {
            pid,
            start_time: info.start_time,
            exe: warden_sys::process::exe(pid),
            uid: info.ruid,
            user: users(info.ruid),
            cmdline: warden_sys::process::cmdline(pid, 512).unwrap_or_default(),
            cgroup: warden_sys::process::cgroup(pid),
            comm: info.comm,
        })
    }

    fn to_ref(&self) -> ProcessRef {
        ProcessRef {
            pid: self.pid,
            start_time: self.start_time,
            comm: self.comm.clone(),
            exe: self.exe.clone(),
            cmdline: Some(self.cmdline.clone()),
            uid: Some(self.uid),
            user: Some(self.user.clone()),
            ppid: None,
            container: self.cgroup.as_deref().and_then(warden_sys::cgroup::container_of),
            cgroup: self.cgroup.clone(),
        }
    }
}

pub enum FimMsg {
    Write {
        path: PathBuf,
        writer: Option<Writer>,
    },
    Overflow,
    Scan {
        site: Option<String>,
        reply: Option<Sender<serde_json::Value>>,
    },
    Accept {
        site: String,
        path: Option<String>,
        reply: Sender<serde_json::Value>,
    },
    Pause {
        site: String,
        seconds: u64,
        reply: Sender<serde_json::Value>,
    },
    Status {
        reply: Sender<serde_json::Value>,
    },
    /// Configuration changed or shutdown started: re-check right away.
    Reload,
}

struct SiteState {
    m: SiteMatcher,
    cfg: FimSite,
    base: Baseline,
    path: PathBuf,
    dirty: bool,
    /// Next scheduled scan, on [`warden_sys::clock`] (real time, sleep
    /// included) — like `paused_until` and `blocked_ips`.
    next_scan: Instant,
    /// A scheduled scan postponed because the disk is busy.
    defer: warden_sys::pace::Deferral,
    paused_until: Option<Instant>,
    burst: VecDeque<(Instant, Option<Writer>)>,
    burst_alerted: Option<Instant>,
    /// Writers whose writes matched the signatures, within the burst window:
    /// a mass change kills only these.
    flagged_writers: VecDeque<(Instant, Writer)>,
    access_seq: u64,
    blocked_ips: HashMap<std::net::IpAddr, Instant>,
}

impl SiteState {
    fn paused(&self) -> bool {
        self.paused_until.is_some_and(|t| warden_sys::clock::now() < t)
    }
}

fn mtime_secs(md: &std::fs::Metadata) -> i64 {
    md.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub struct FimWorker {
    shared: Arc<Shared>,
    sink: Sink,
    cfg: FimConfig,
    sigs: Signatures,
    sites: Vec<SiteState>,
    pending: HashMap<PathBuf, (Instant, Option<Writer>)>,
    generation: u64,
    state_dir: PathBuf,
    web_users: HashSet<String>,
    web_comms: GlobList,
    trusted_writers: GlobList,
    last_save: Instant,
    hasher: FileHasher,
}

impl FimWorker {
    pub fn new(shared: Arc<Shared>, sink: Sink) -> Self {
        let cfg = shared.config();
        let mut w = Self {
            sink,
            cfg: cfg.fim.clone(),
            sigs: Signatures::empty(),
            sites: Vec::new(),
            pending: HashMap::new(),
            generation: 0,
            state_dir: cfg.daemon.state_dir.join("fim"),
            web_users: HashSet::new(),
            web_comms: GlobList::default(),
            trusted_writers: GlobList::default(),
            last_save: Instant::now(),
            hasher: FileHasher::default(),
            shared,
        };
        w.reload();
        w
    }

    fn reload(&mut self) {
        let cfg = self.shared.config();
        self.generation = self.shared.generation();
        self.cfg = cfg.fim.clone();
        self.state_dir = cfg.daemon.state_dir.join("fim");
        let (sigs, errs) = Signatures::load(&cfg.fim.signatures);
        for e in errs {
            tracing::warn!(error = %e, "signature rule rejected");
        }
        self.shared.metrics.set("warden_fim_signatures", &[], sigs.len() as f64);
        self.sigs = sigs;
        self.web_users = cfg.process.web_users.iter().cloned().collect();
        self.web_comms = GlobList::new(&cfg.process.web_comms);
        self.trusted_writers = GlobList::new(&cfg.fim.trusted_writers);
        let mut old: HashMap<String, SiteState> = self.sites.drain(..).map(|s| (s.cfg.name.clone(), s)).collect();
        for s in &cfg.fim.sites {
            if let Some(mut st) = old.remove(&s.name).filter(|st| st.cfg.root == s.root) {
                st.m = SiteMatcher::new(s);
                st.cfg = s.clone();
                self.sites.push(st);
                continue;
            }
            let path = self.state_dir.join(format!("{}.json", sanitize(&s.name)));
            let base =
                Baseline::load(&path).filter(|b| b.root == s.root.to_string_lossy()).unwrap_or_else(|| Baseline {
                    version: 1,
                    site: s.name.clone(),
                    root: s.root.to_string_lossy().into_owned(),
                    created_ms: now_ms(),
                    ..Default::default()
                });
            let first_delay = if self.cfg.scan_on_start || base.files.is_empty() {
                Duration::from_secs(20)
            } else {
                self.cfg.schedule
            };
            self.sites.push(SiteState {
                m: SiteMatcher::new(s),
                cfg: s.clone(),
                base,
                path,
                dirty: false,
                next_scan: warden_sys::clock::now() + first_delay,
                defer: Default::default(),
                paused_until: None,
                burst: VecDeque::new(),
                burst_alerted: None,
                flagged_writers: VecDeque::new(),
                access_seq: 0,
                blocked_ips: HashMap::new(),
            });
        }
    }

    fn emit(&self, mut ev: Event) {
        ev.source = "fim".into();
        self.sink.emit(ev);
    }

    fn quarantine_on(&self, site: &SiteState) -> bool {
        site.cfg.quarantine.unwrap_or(self.cfg.quarantine)
    }

    fn is_web_writer(&self, w: &Writer) -> bool {
        self.web_users.contains(&w.user)
            || (self.web_comms.is_match(&w.comm)
                && w.cgroup.as_deref().is_some_and(|c| c.starts_with("/system.slice/")))
    }

    /// May changes written by `w` be accepted without a `fim.changed` alert?
    /// (Their content is scanned for malicious code either way.) The name is
    /// chosen by the process, so it counts only for a program the kernel
    /// shows to be a system binary — `git`, or the `php`/`node` that runs
    /// `composer`/`npm` (a script's `comm` is the script's name) — never for
    /// a file the writer dropped itself and named `git`.
    fn is_trusted(&self, w: Option<&Writer>) -> bool {
        let Some(w) = w else { return false };
        self.trusted_writers.is_match(&w.comm)
            && w.exe.as_deref().is_some_and(|e| warden_sys::process::is_system_binary(w.pid, e))
            && (self.cfg.trusted_users.is_empty() || self.cfg.trusted_users.contains(&w.user))
            && !self.web_users.contains(&w.user)
    }

    /// Mark suspect requests whose client was also blocked by ModSecurity
    /// recently — the strongest "patient zero" signal there is.
    fn enrich_with_waf(&self, mut suspects: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
        for s in suspects.iter_mut() {
            if let Some(ip) = s.get("ip").and_then(|v| v.as_str()).map(str::to_owned)
                && let Some((n, rules)) = self.shared.waf.hits(&ip)
                && let Some(o) = s.as_object_mut()
            {
                o.insert("waf_hits".into(), n.into());
                o.insert("waf_rules".into(), serde_json::json!(rules));
            }
        }
        // WAF-flagged clients first.
        suspects.sort_by_key(|s| std::cmp::Reverse(s.get("waf_hits").and_then(|v| v.as_u64()).unwrap_or(0)));
        suspects
    }

    /// Build the alert(s) for malicious content.
    fn webshell_events(
        &self,
        idx: usize,
        rel: &str,
        verdict: &Verdict,
        writer: Option<&Writer>,
        initial: bool,
        ts: i64,
    ) -> Vec<Event> {
        let site = &self.sites[idx];
        let abs = site.cfg.root.join(rel);
        let critical = verdict.score >= self.cfg.quarantine_score;
        let sev = if critical { Severity::Critical } else { Severity::Warning };
        let suspects = self.enrich_with_waf(
            self.shared
                .access
                .with(&site.cfg.name, |r| r.suspects(ts, self.cfg.correlate_window.as_secs() as i64, 8))
                .unwrap_or_default(),
        );
        let mut actions = Vec::new();
        if !initial && critical && self.quarantine_on(site) {
            actions.push(ActionSpec::Quarantine);
            if let Some(u) = &site.cfg.restart_unit {
                actions.push(ActionSpec::RestartUnit { unit: Some(u.clone()) });
            }
        }
        let title = format!(
            "{} in site {}: /{rel} (score {}: {})",
            if initial { "suspicious file found during initial baseline" } else { "malicious code" },
            site.cfg.name,
            verdict.score,
            verdict.summary()
        );
        let mut ev = Event::new("security.webshell", sev, title)
            .subject(Subject::File { path: abs.to_string_lossy().into_owned(), site: Some(site.cfg.name.clone()) })
            .fingerprint(format!("security.webshell:{}:{rel}", site.cfg.name))
            .detail("site", site.cfg.name.clone())
            .detail("url_path", format!("/{rel}"))
            .detail("score", verdict.score)
            .detail("hits", serde_json::to_value(&verdict.hits).unwrap_or_default())
            .detail("initial_baseline", initial)
            .actions(actions);
        if !suspects.is_empty() {
            ev = ev.detail("suspect_requests", suspects);
        }
        if let Some(w) = writer {
            ev = ev.detail("writer", serde_json::to_value(w).unwrap_or_default());
        }
        let mut out = vec![ev];
        if let Some(w) = writer
            && !initial
            && critical
            && self.cfg.kill_writer
            && self.is_web_writer(w)
        {
            out.push(
                Event::new(
                    "security.malicious_writer",
                    Severity::Critical,
                    format!("{}[{}] ({}) wrote malicious code to /{rel}", w.comm, w.pid, w.user),
                )
                .subject(Subject::Process(w.to_ref()))
                .fingerprint(format!("security.malicious_writer:{}:{}", w.pid, w.start_time))
                .detail("file", abs.to_string_lossy().into_owned())
                .actions(vec![ActionSpec::Kill { tree: false, grace: Some(Duration::from_secs(1)) }]),
            );
        }
        out
    }

    /// Full verification scan of one site.
    ///
    /// Content is scored while walking, so memory stays flat: only the
    /// verdicts of changed files are kept, never their content (a first
    /// baseline of a 300 MiB site used to hold all of it at once).
    /// `paced`: a scheduled scan, which yields to the workload when the disk
    /// is busy. Realtime writes are processed only between scans, so its
    /// floor is half speed: at most twice as long as unpaced.
    fn full_scan(&mut self, idx: usize, paced: bool) -> serde_json::Value {
        let started = Instant::now();
        let mut pace = if paced {
            warden_sys::pace::Pacer::new("fim", 0.5, self.cfg.low_priority)
        } else {
            warden_sys::pace::Pacer::off("fim")
        };
        let max = self.cfg.max_file_size.as_u64();
        let throttle = self.cfg.max_files_per_sec;
        let first = self.sites[idx].base.files.is_empty();

        enum Kind {
            Added,
            Modified,
            Meta,
            Polyglot,
        }
        type Change = (String, Kind, Option<FileRecord>, Verdict, i64);
        let mut changes: Vec<Change> = Vec::new();
        // 8-byte fingerprints of the paths seen (for deletions), not copies.
        let rs = std::hash::RandomState::new();
        let mut seen: HashSet<u64> = HashSet::with_capacity(self.sites[idx].base.files.len());
        let mut seen_up: HashSet<u64> = HashSet::new();
        let mut uploads: Vec<(String, store::MetaStamp)> = Vec::new();
        let mut hasher = std::mem::take(&mut self.hasher);
        {
            use std::hash::BuildHasher;
            let site = &self.sites[idx];
            let base = &site.base;
            let sigs = &self.sigs;
            walk_paced(&site.m, throttle, &mut pace, |rel, abs, md| {
                let wants = site.m.wants(rel);
                let in_upload = site.m.in_no_scripts(rel);
                if wants {
                    seen.insert(rs.hash_one(rel));
                    let old = base.files.get(rel);
                    if old.is_some_and(|r| r.same_meta(md)) {
                        return;
                    }
                    if md.len() > max.saturating_mul(4) {
                        return; // huge bundles: not worth hashing every scan
                    }
                    let Ok(hash) = hasher.hash(abs, max) else { return };
                    let rec = FileRecord::from_meta(md, hash);
                    let kind = match old {
                        None => Kind::Added,
                        Some(o) if o.hash != rec.hash => Kind::Modified,
                        Some(_) => Kind::Meta,
                    };
                    let mut verdict = Verdict::default();
                    if matches!(kind, Kind::Added | Kind::Modified) {
                        if site.m.signatures_apply(rel) {
                            verdict = sigs.scan(rel.rsplit('/').next().unwrap_or(rel), hasher.head());
                        }
                        if in_upload {
                            verdict.add("script-in-upload-dir", "script file inside an upload/media directory", 100);
                        }
                    }
                    changes.push((rel.to_owned(), kind, Some(rec), verdict, mtime_secs(md)));
                } else if in_upload && md.len() <= 2 << 20 && !base.flagged.contains(rel) {
                    seen_up.insert(rs.hash_one(rel));
                    let stamp = store::MetaStamp::of(md);
                    if base.uploads.get(rel) == Some(&stamp) {
                        return; // unchanged since it was last checked
                    }
                    let mut found = false;
                    if let Ok(f) = std::fs::File::open(abs) {
                        use std::io::Read;
                        let _cold = warden_sys::pagecache::ColdRead::new(&f);
                        let mut v = Vec::new();
                        let _ = (&f).take(256 * 1024).read_to_end(&mut v);
                        found = signatures::has_server_code(&v);
                    }
                    uploads.push((rel.to_owned(), stamp));
                    if found {
                        let mut verdict = Verdict::default();
                        verdict.add(
                            "server-code-in-non-script",
                            "server-side code inside a non-script file in an upload directory",
                            100,
                        );
                        changes.push((rel.to_owned(), Kind::Polyglot, None, verdict, mtime_secs(md)));
                    }
                }
            });
        }
        self.hasher = hasher;
        let deleted: Vec<String> = {
            use std::hash::BuildHasher;
            self.sites[idx].base.files.keys().filter(|k| !seen.contains(&rs.hash_one(k.as_str()))).cloned().collect()
        };
        drop(seen);
        {
            use std::hash::BuildHasher;
            let b = &mut self.sites[idx].base;
            b.uploads.retain(|k, _| seen_up.contains(&rs.hash_one(k.as_str())));
            b.uploads.extend(uploads);
        }

        let paused = self.sites[idx].paused();
        let mut unexpected: Vec<String> = Vec::new();
        let mut flagged = 0usize;
        let mut perm_issues = Vec::new();
        let mut events = Vec::new();
        for (rel, kind, rec, verdict, mtime) in changes {
            if let (Kind::Meta, Some(r)) = (&kind, &rec)
                && r.mode & 0o002 != 0
            {
                perm_issues.push(format!("{rel} ({:o})", r.mode & 0o7777));
            }
            if verdict.score >= self.cfg.alert_score {
                flagged += 1;
                events.extend(self.webshell_events(idx, &rel, &verdict, None, first, mtime));
                self.sites[idx].base.flagged.insert(rel.clone());
            } else if !first && !paused && matches!(kind, Kind::Added | Kind::Modified) {
                unexpected.push(format!("{} /{rel}", if matches!(kind, Kind::Added) { "added" } else { "modified" }));
            }
            if let Some(r) = rec {
                self.sites[idx].base.files.insert(rel, r);
            }
        }
        for e in events {
            self.emit(e);
        }

        let site = &mut self.sites[idx];
        let mut deleted_report = Vec::new();
        for d in &deleted {
            site.base.files.remove(d);
            if !site.base.flagged.remove(d) {
                deleted_report.push(format!("/{d}"));
            }
        }
        let name = site.cfg.name.clone();
        let files = site.base.files.len();
        site.base.last_scan_ms = now_ms();
        site.dirty = true;
        site.next_scan = warden_sys::clock::now() + self.cfg.schedule;

        if first {
            self.emit(
                Event::new(
                    "fim.baseline_created",
                    Severity::Info,
                    format!("FIM baseline for site {name}: {files} files, {flagged} suspicious"),
                )
                .fingerprint(format!("fim.baseline_created:{name}"))
                .detail("site", name.clone())
                .detail("files", files),
            );
        } else {
            if !unexpected.is_empty() {
                let mass = unexpected.len() >= self.cfg.burst_files;
                // as for the real-time burst: many changes alone are an update
                let sev = if mass && flagged > 0 {
                    Severity::Emergency
                } else if unexpected.len() >= 5 {
                    Severity::Warning
                } else {
                    Severity::Notice
                };
                let kind = if mass { "fim.mass_change" } else { "fim.changes" };
                self.emit(
                    Event::new(kind, sev, format!("site {name}: {} unexpected file change(s) since last scan", unexpected.len()))
                        .fingerprint(format!("{kind}:{name}:{}", unexpected.len()))
                        .detail("site", name.clone())
                        .detail("changes", unexpected.iter().take(50).cloned().collect::<Vec<_>>())
                        .detail("hint", "if this was a deployment run `wardenctl fim accept <site>`; use `wardenctl fim pause` around deploys"),
                );
            }
            if !deleted_report.is_empty() {
                self.emit(
                    Event::new(
                        "fim.deleted",
                        Severity::Notice,
                        format!("site {name}: {} file(s) deleted", deleted_report.len()),
                    )
                    .fingerprint(format!("fim.deleted:{name}:{}", deleted_report.len()))
                    .detail("files", deleted_report.iter().take(50).cloned().collect::<Vec<_>>()),
                );
            }
            if !perm_issues.is_empty() {
                self.emit(
                    Event::new(
                        "fim.world_writable",
                        Severity::Warning,
                        format!("site {name}: script files made world-writable"),
                    )
                    .fingerprint(format!("fim.world_writable:{name}"))
                    .detail("files", perm_issues),
                );
            }
        }
        self.shared.metrics.set("warden_fim_files", &[("site", &name)], files as f64);
        self.shared.metrics.set("warden_fim_scan_seconds", &[("site", &name)], started.elapsed().as_secs_f64());
        self.shared.metrics.set("warden_fim_flagged", &[("site", &name)], self.sites[idx].base.flagged.len() as f64);
        self.save(idx);
        // Give the scan's transient allocations back to the OS.
        tracing::debug!(bytes = warden_sys::selfstat::release_memory(), site = %name, "FIM scan memory released");
        let paced = pace.paced().as_secs_f64();
        drop(pace);
        serde_json::json!({"site": name, "files": files, "flagged": flagged, "unexpected": unexpected.len(), "deleted": deleted.len(), "seconds": started.elapsed().as_secs_f64(), "paced_seconds": paced})
    }

    fn site_of(&self, path: &Path) -> Option<(usize, String)> {
        self.sites
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.m.rel(path).map(|r| (i, r)))
            .max_by_key(|(i, _)| self.sites[*i].m.root.as_os_str().len())
    }

    fn on_write(&mut self, path: PathBuf, writer: Option<Writer>) {
        let Some((idx, rel)) = self.site_of(&path) else { return };
        let m = &self.sites[idx].m;
        if !(m.wants(&rel) || m.in_no_scripts(&rel)) {
            return;
        }
        self.shared.metrics.inc("warden_fim_realtime_events_total", &[("site", &self.sites[idx].cfg.name)], 1.0);
        // Debounce: editors and unzip write the same file several times.
        self.pending.insert(path, (Instant::now() + Duration::from_millis(800), writer));
    }

    fn process_write(&mut self, path: &Path, writer: Option<Writer>) {
        let Some((idx, rel)) = self.site_of(path) else { return };
        let Ok(md) = std::fs::symlink_metadata(path) else { return };
        if !md.is_file() {
            return;
        }
        let wants = self.sites[idx].m.wants(&rel);
        let in_upload = self.sites[idx].m.in_no_scripts(&rel);
        let old = self.sites[idx].base.files.get(&rel).cloned();
        if old.as_ref().is_some_and(|r| r.same_meta(&md)) {
            return;
        }
        let Ok(hash) = self.hasher.hash(path, self.cfg.max_file_size.as_u64()) else { return };
        let head = self.hasher.head();
        let rec = FileRecord::from_meta(&md, hash);
        if old.as_ref().is_some_and(|o| o.hash == rec.hash) {
            self.sites[idx].base.files.insert(rel, rec);
            self.sites[idx].dirty = true;
            return;
        }
        let mut verdict = Verdict::default();
        if wants {
            if self.sites[idx].m.signatures_apply(&rel) {
                verdict = self.sigs.scan(rel.rsplit('/').next().unwrap_or(&rel), head);
            }
            if in_upload {
                verdict.add("script-in-upload-dir", "script file inside an upload/media directory", 100);
            }
        } else if signatures::has_server_code(head) {
            verdict.add(
                "server-code-in-non-script",
                "server-side code inside a non-script file in an upload directory",
                100,
            );
        } else {
            return; // ordinary upload (image, PDF...)
        }

        let trusted = self.sites[idx].paused() || self.is_trusted(writer.as_ref());
        let name = self.sites[idx].cfg.name.clone();
        if verdict.score >= self.cfg.alert_score {
            // Real time: suspects are the requests around the write as it
            // happened. The file's mtime is what a dropper sets with
            // `touch()` to an old date (0.13.3 looked there and found no one);
            // only the scheduled scan, which has nothing better, uses it.
            for e in self.webshell_events(idx, &rel, &verdict, writer.as_ref(), false, now_secs()) {
                self.emit(e);
            }
            self.sites[idx].base.flagged.insert(rel.clone());
            if let Some(w) = &writer {
                self.sites[idx].flagged_writers.push_back((Instant::now(), w.clone()));
            }
            // malicious content is a change too: infection spreading
            self.burst(idx, writer.clone());
        } else if trusted {
            self.shared.metrics.inc("warden_fim_auto_accepted_total", &[("site", &name)], 1.0);
        } else {
            let suspects = self.enrich_with_waf(
                self.shared
                    .access
                    .with(&name, |r| r.suspects(now_secs(), self.cfg.correlate_window.as_secs() as i64, 5))
                    .unwrap_or_default(),
            );
            let what = if old.is_none() { "created" } else { "modified" };
            let by = writer.as_ref().map(|w| format!(" by {}[{}] ({})", w.comm, w.pid, w.user)).unwrap_or_default();
            let mut ev = Event::new("fim.changed", Severity::Notice, format!("site {name}: /{rel} {what}{by}"))
                .subject(Subject::File { path: path.to_string_lossy().into_owned(), site: Some(name.clone()) })
                .fingerprint(format!("fim.changed:{name}:{rel}:{}", rec.hash))
                .detail("score", verdict.score);
            if let Some(w) = &writer {
                ev = ev.detail("writer", serde_json::to_value(w).unwrap_or_default());
            }
            if !suspects.is_empty() {
                ev = ev.detail("suspect_requests", suspects);
            }
            self.emit(ev);
            self.burst(idx, writer.clone());
        }
        if wants {
            self.sites[idx].base.files.insert(rel, rec);
            self.sites[idx].dirty = true;
        }
    }

    /// Mass-modification detection (infection spreading through a site).
    ///
    /// Many changes alone are what a CMS or plugin update through the web
    /// UI looks like, written by the same PHP worker an infection would use:
    /// the writers are killed only if their own writes in the window matched
    /// the signatures. Without that it is a warning that says how to tell
    /// Warden about an update (`wardenctl fim pause`). (0.13.3 killed every
    /// web writer of any burst, in the middle of the update.)
    fn burst(&mut self, idx: usize, writer: Option<Writer>) {
        let now = Instant::now();
        let window = self.cfg.burst_window;
        let threshold = self.cfg.burst_files;
        let site = &mut self.sites[idx];
        site.burst.push_back((now, writer));
        while site.burst.front().is_some_and(|(t, _)| now.saturating_duration_since(*t) > window) {
            site.burst.pop_front();
        }
        while site.flagged_writers.front().is_some_and(|(t, _)| now.saturating_duration_since(*t) > window) {
            site.flagged_writers.pop_front();
        }
        if site.burst.len() < threshold || site.burst_alerted.is_some_and(|t| now.saturating_duration_since(t) < window)
        {
            return;
        }
        site.burst_alerted = Some(now);
        let name = site.cfg.name.clone();
        let mut writers: HashMap<(i32, u64), Writer> = HashMap::new();
        for (_, w) in site.burst.iter() {
            if let Some(w) = w {
                writers.entry((w.pid, w.start_time)).or_insert_with(|| w.clone());
            }
        }
        let flagged: HashMap<(i32, u64), Writer> =
            site.flagged_writers.iter().map(|(_, w)| ((w.pid, w.start_time), w.clone())).collect();
        let n = site.burst.len();
        let label = |w: &Writer| format!("{}[{}] ({})", w.comm, w.pid, w.user);
        let list: Vec<String> = writers.values().map(label).collect();
        let secs = window.as_secs();
        if flagged.is_empty() {
            self.emit(
                Event::new(
                    "fim.mass_change",
                    Severity::Warning,
                    format!("site {name}: {n} files changed within {secs}s; none matched the signatures"),
                )
                .fingerprint(format!("fim.mass_change:{name}"))
                .detail("site", name.clone())
                .detail("writers", list)
                .detail("malicious_content", false)
                .detail(
                    "hint",
                    format!(
                        "an update or deployment? pause FIM around it: `wardenctl fim pause {name} 30m` \
                         (changes are still scanned, and malicious code is still reported), then \
                         `wardenctl fim accept {name}` if anything is left"
                    ),
                ),
            );
            return;
        }
        let bad: Vec<String> = flagged.values().map(label).collect();
        self.emit(
            Event::new(
                "fim.mass_change",
                Severity::Emergency,
                format!(
                    "site {name}: {n} files changed within {secs}s, with malicious code — possible infection spreading"
                ),
            )
            .fingerprint(format!("fim.mass_change:{name}"))
            .detail("site", name.clone())
            .detail("writers", list)
            .detail("malicious_content", true)
            .detail("malicious_writers", bad),
        );
        if self.cfg.kill_writer {
            for w in flagged.values().filter(|w| self.is_web_writer(w)) {
                self.emit(
                    Event::new(
                        "security.malicious_writer",
                        Severity::Critical,
                        format!("{}[{}] mass-modifying site {name} with malicious code", w.comm, w.pid),
                    )
                    .subject(Subject::Process(w.to_ref()))
                    .fingerprint(format!("security.malicious_writer:{}:{}", w.pid, w.start_time))
                    .actions(vec![ActionSpec::Kill { tree: false, grace: Some(Duration::from_secs(1)) }]),
                );
            }
        }
    }

    /// Requests that hit flagged files are someone using a webshell.
    fn check_access(&mut self) {
        for idx in 0..self.sites.len() {
            let name = self.sites[idx].cfg.name.clone();
            let since = self.sites[idx].access_seq;
            if self.sites[idx].base.flagged.is_empty() {
                // Nothing to look for: skip the copy of new requests.
                if let Some(last) = self.shared.access.with(&name, |r| r.last_seq()) {
                    self.sites[idx].access_seq = last;
                }
                continue;
            }
            let Some((reqs, last)) = self.shared.access.with(&name, |r| (r.since(since), r.last_seq())) else {
                continue;
            };
            self.sites[idx].access_seq = last;
            if reqs.is_empty() {
                continue;
            }
            let flagged: HashSet<String> = self.sites[idx].base.flagged.iter().map(|r| format!("/{r}")).collect();
            for r in reqs.into_iter().filter(|r| flagged.contains(&*r.path)) {
                let real = warden_sys::clock::now();
                let recent = |t: &Instant| real.saturating_duration_since(*t) < Duration::from_secs(3600);
                if self.sites[idx].blocked_ips.get(&r.ip).is_some_and(recent) {
                    continue;
                }
                self.sites[idx].blocked_ips.retain(|_, t| recent(t));
                self.sites[idx].blocked_ips.insert(r.ip, real);
                let ip = r.ip;
                let mut ev = Event::new(
                    "security.webshell_access",
                    Severity::Critical,
                    format!("{} requested flagged file {} ({} {})", r.ip, r.path, r.method, r.status),
                )
                .subject(Subject::Ip { addr: ip })
                .fingerprint(format!("security.webshell_access:{}:{}", r.ip, r.path))
                .detail("site", name.clone())
                .detail("ip", r.ip.to_string())
                .detail("path", &*r.path);
                ev = if self.cfg.block_attackers {
                    ev.actions(vec![ActionSpec::BlockIp { ttl: Some(Duration::from_secs(86400)) }])
                } else {
                    ev.detail(warden_core::event::IP_BLOCK_OFF, "fim.block_attackers = false")
                };
                self.emit(ev);
            }
        }
    }

    fn save(&mut self, idx: usize) {
        let s = &mut self.sites[idx];
        if !s.dirty {
            return;
        }
        match s.base.save(&s.path) {
            Ok(()) => s.dirty = false,
            Err(e) => tracing::warn!(site = %s.cfg.name, error = %e, "cannot save FIM baseline"),
        }
    }

    fn status(&self) -> serde_json::Value {
        let now = warden_sys::clock::now();
        serde_json::json!({
            "realtime": lock(&self.shared.sensors).get("fim_realtime").cloned(),
            "signatures": self.sigs.len(),
            "sites": self.sites.iter().map(|s| serde_json::json!({
                "name": s.cfg.name,
                "root": s.cfg.root,
                "files": s.base.files.len(),
                "flagged": s.base.flagged.iter().take(100).collect::<Vec<_>>(),
                "last_scan": if s.base.last_scan_ms > 0 { warden_core::event::format_ts_ms(s.base.last_scan_ms) } else { "never".into() },
                "next_scan_in_seconds": s.next_scan.saturating_duration_since(now).as_secs(),
                "paused_for_seconds": s.paused_until.map(|t| t.saturating_duration_since(now).as_secs()).unwrap_or(0),
                "scan_postponed_for_seconds": s.defer.waiting(now).map(|d| d.as_secs()),
            })).collect::<Vec<_>>(),
        })
    }

    fn handle(&mut self, msg: FimMsg) {
        match msg {
            FimMsg::Write { path, writer } => self.on_write(path, writer),
            FimMsg::Overflow => {
                for s in &mut self.sites {
                    s.next_scan = s.next_scan.min(warden_sys::clock::now() + Duration::from_secs(60));
                }
            }
            FimMsg::Scan { site, reply } => {
                let mut out = Vec::new();
                for i in 0..self.sites.len() {
                    if site.as_ref().is_none_or(|n| *n == self.sites[i].cfg.name) {
                        out.push(self.full_scan(i, false)); // the operator is waiting
                    }
                }
                if let Some(r) = reply {
                    let _ = r.send(serde_json::json!(out));
                }
            }
            FimMsg::Accept { site, path, reply } => {
                let Some(idx) = self.sites.iter().position(|s| s.cfg.name == site) else {
                    let _ = reply.send(serde_json::json!({"error": format!("unknown site {site}")}));
                    return;
                };
                let n = match path {
                    Some(p) => {
                        let abs = if p.starts_with('/') && !p.starts_with(&*self.sites[idx].cfg.root.to_string_lossy())
                        {
                            self.sites[idx].cfg.root.join(p.trim_start_matches('/'))
                        } else {
                            PathBuf::from(&p)
                        };
                        let rel = self.sites[idx].m.rel(&abs).unwrap_or_else(|| p.trim_start_matches('/').to_owned());
                        let s = &mut self.sites[idx];
                        s.base.flagged.remove(&rel);
                        match std::fs::symlink_metadata(&abs).ok().zip(hash_file(&abs, 0).ok()) {
                            Some((md, (h, _))) => {
                                s.base.files.insert(rel, FileRecord::from_meta(&md, h));
                            }
                            None => {
                                s.base.files.remove(&rel);
                            }
                        }
                        1
                    }
                    None => {
                        let s = &mut self.sites[idx];
                        s.base.files.clear();
                        s.base.flagged.clear();
                        let mut files = std::collections::BTreeMap::new();
                        walk(&s.m, 0, |rel, abs, md| {
                            if s.m.wants(rel)
                                && let Ok((h, _)) = hash_file(abs, 0)
                            {
                                files.insert(rel.to_owned(), FileRecord::from_meta(md, h));
                            }
                        });
                        let n = files.len();
                        s.base.files = files;
                        n
                    }
                };
                self.sites[idx].dirty = true;
                self.save(idx);
                let _ = reply.send(serde_json::json!({"site": site, "accepted": n}));
            }
            FimMsg::Pause { site, seconds, reply } => {
                let r = match self.sites.iter_mut().find(|s| s.cfg.name == site) {
                    Some(s) => {
                        s.paused_until = Some(warden_sys::clock::now() + Duration::from_secs(seconds));
                        serde_json::json!({"site": site, "paused_seconds": seconds})
                    }
                    None => serde_json::json!({"error": format!("unknown site {site}")}),
                };
                let _ = reply.send(r);
            }
            FimMsg::Status { reply } => {
                let _ = reply.send(self.status());
            }
            FimMsg::Reload => {}
        }
    }

    /// How long until the worker next has something to do (no fixed
    /// polling). Debounced writes and saves are on the monotonic clock,
    /// scheduled scans on the real one: each is measured on its own.
    fn next_wakeup(&self) -> Duration {
        let (mono, real) = (Instant::now(), warden_sys::clock::now());
        let mut d = Duration::from_secs(300);
        for (due, _) in self.pending.values() {
            d = d.min(due.saturating_duration_since(mono));
        }
        for s in &self.sites {
            d = d.min(s.next_scan.saturating_duration_since(real));
            if s.dirty {
                d = d.min((self.last_save + Duration::from_secs(30)).saturating_duration_since(mono));
            }
            // Requests that hit already flagged files.
            if !s.base.flagged.is_empty() && s.cfg.access_log.is_some() {
                d = d.min(Duration::from_secs(2));
            }
        }
        d
    }

    pub fn run(mut self, rx: Receiver<FimMsg>, tx: Sender<FimMsg>, token: u64, lease: Lease) {
        if self.cfg.low_priority
            && let Err(e) = warden_sys::sched::background_thread()
        {
            tracing::debug!(error = %e, "cannot lower FIM thread priority");
        }
        let _keep_channel_open = tx;
        loop {
            if self.shared.is_shutting_down() {
                for i in 0..self.sites.len() {
                    self.save(i);
                }
                return;
            }
            if self.shared.generation() != self.generation {
                for i in 0..self.sites.len() {
                    self.save(i);
                }
                if !lease.wanted() && lease.release() {
                    let mut g = lock(&self.shared.fim_tx);
                    if self.shared.fim_token.load(std::sync::atomic::Ordering::SeqCst) == token {
                        *g = None;
                        self.shared.set_sensor("fim", SensorState::Disabled);
                    }
                    tracing::info!("FIM disabled; worker stopped");
                    return;
                }
                self.reload();
            }
            let wait = self.next_wakeup().max(Duration::from_millis(20));
            match rx.recv_timeout(wait) {
                Ok(m) => self.handle(m),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => return,
            }
            let now = Instant::now();
            let due: Vec<PathBuf> =
                self.pending.iter().filter(|(_, (t, _))| *t <= now).map(|(p, _)| p.clone()).collect();
            for p in due {
                if let Some((_, w)) = self.pending.remove(&p) {
                    self.process_write(&p, w);
                }
            }
            self.check_access();
            if self.cfg.enabled {
                for i in 0..self.sites.len() {
                    let now = warden_sys::clock::now();
                    if now < self.sites[i].next_scan {
                        continue;
                    }
                    // A scheduled rescan waits for a quiet disk (bounded): while
                    // it waits, realtime writes are still processed. The first
                    // baseline is not postponed.
                    if !self.sites[i].base.files.is_empty() {
                        let pressure = warden_sys::pace::io_pressure();
                        let s = &mut self.sites[i];
                        let first = s.defer.waiting(now).is_none();
                        if let Some(wait) = s.defer.check(&warden_sys::pace::params(), "fim", now, pressure) {
                            if first {
                                tracing::info!(
                                    site = %s.cfg.name,
                                    io_pressure_percent = pressure.unwrap_or_default() * 100.0,
                                    "FIM scan postponed: the disk is busy"
                                );
                            }
                            s.next_scan = now + wait;
                            continue;
                        }
                    }
                    let r = self.full_scan(i, true);
                    tracing::info!(result = %r, "FIM scan finished");
                }
            }
            if self.last_save.elapsed() > Duration::from_secs(30) {
                self.last_save = Instant::now();
                for i in 0..self.sites.len() {
                    self.save(i);
                }
            }
        }
    }
}

fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect()
}

/// Sensor: fanotify close-after-write events for all site roots.
///
/// fanotify watches whole mounts, so on a busy host most events concern
/// files outside the sites (PHP sessions, caches, logs). They are dropped
/// before any `/proc` lookup, and directories outside the sites that keep
/// producing events are muted in the kernel (`FAN_MARK_IGNORE`, Linux 6.0+).
pub fn run_realtime(shared: &Arc<Shared>) -> Result<(), String> {
    let cfg = shared.config();
    if !cfg.fim.enabled || !cfg.fim.realtime || cfg.fim.sites.is_empty() {
        return Ok(());
    }
    let tx = lock(&shared.fim_tx).clone().ok_or("FIM worker is not running")?;
    let generation = shared.generation();
    let mut fan = warden_sys::fanotify::Fanotify::new()
        .map_err(|e| format!("fanotify: {e}{}", warden_sys::sched::permission_hint(&e, "CAP_SYS_ADMIN")))?;
    let sites: Vec<SiteMatcher> = cfg.fim.sites.iter().map(SiteMatcher::new).collect();
    for s in &sites {
        fan.watch_mount(&s.root).map_err(|e| format!("fanotify mark {}: {e}", s.root.display()))?;
    }
    let me = std::process::id() as i32;
    shared.set_sensor("fim_realtime", SensorState::Running);
    let users = |u: u32| shared.user_name(u);
    let mut last_overflow = Instant::now() - Duration::from_secs(600);
    let mut hot: HashMap<PathBuf, u32> = HashMap::new();
    let mut window = Instant::now();
    let mut muted = 0usize;
    let mut can_mute = true;
    loop {
        let evs = fan.read_timeout(Duration::from_secs(2)).map_err(|e| e.to_string())?;
        if shared.generation() != generation || shared.is_shutting_down() {
            return Err("configuration reloaded".into());
        }
        for e in evs {
            if e.overflow() {
                shared.metrics.inc("warden_fim_overflows_total", &[], 1.0);
                if last_overflow.elapsed() > Duration::from_secs(300) {
                    last_overflow = Instant::now();
                    let _ = tx.send(FimMsg::Overflow);
                }
                continue;
            }
            if e.pid == me {
                continue;
            }
            let Some(path) = e.path else { continue };
            let relevant = sites.iter().any(|m| m.rel(&path).is_some_and(|rel| m.wants(&rel) || m.in_no_scripts(&rel)));
            if !relevant {
                if can_mute
                    && !sites.iter().any(|m| path.starts_with(&m.root))
                    && let Some(dir) = path.parent()
                {
                    *hot.entry(dir.to_path_buf()).or_default() += 1;
                }
                shared.metrics.inc("warden_fim_realtime_ignored_total", &[], 1.0);
                continue;
            }
            let writer = Writer::read(e.pid, &users);
            if tx.send(FimMsg::Write { path, writer }).is_err() {
                return Err("FIM worker stopped".into());
            }
        }
        if window.elapsed() >= Duration::from_secs(10) {
            window = Instant::now();
            for (dir, n) in hot.drain() {
                if n < 50 || muted >= 256 {
                    continue;
                }
                match fan.ignore_dir(&dir) {
                    Ok(()) => {
                        muted += 1;
                        shared.metrics.set("warden_fim_realtime_muted_dirs", &[], muted as f64);
                        tracing::debug!(dir = %dir.display(), events = n, "fanotify: muted busy directory outside the sites");
                    }
                    Err(e) if e.raw_os_error() == Some(libc::EINVAL) => {
                        can_mute = false; // kernel < 6.0
                        tracing::debug!("fanotify: FAN_MARK_IGNORE not supported; busy directories stay unmuted");
                    }
                    Err(_) => {}
                }
            }
        }
    }
}

/// Offline scan used by `wardenctl scan PATH`: signature verdicts for every
/// script-like file below `root`.
pub fn scan_tree(root: &Path, extra_rules: &[String], min_score: u32) -> Vec<(String, Verdict)> {
    let (sigs, _) = Signatures::load(extra_rules);
    let site = SiteMatcher::new(&FimSite {
        name: "offline".into(),
        root: root.to_path_buf(),
        include: warden_core::config::default_fim_include(),
        exclude: vec!["**/.git/**".into()],
        no_scripts: warden_core::config::default_no_scripts(),
        signature_exclude: warden_core::config::default_signature_exclude(),
        access_log: None,
        quarantine: None,
        restart_unit: None,
    });
    let mut out = Vec::new();
    let mut visit = |rel: &str, abs: &Path| {
        let wants = site.wants(rel);
        let upload = site.in_no_scripts(rel);
        if !wants && !upload {
            return;
        }
        let Ok((_, head)) = hash_file(abs, 16 << 20) else { return };
        let mut v = if wants && site.signatures_apply(rel) {
            sigs.scan(rel.rsplit('/').next().unwrap_or(rel), &head)
        } else {
            Verdict::default()
        };
        if wants && upload {
            v.add("script-in-upload-dir", "script file inside an upload/media directory", 100);
        }
        if !wants && upload && signatures::has_server_code(&head) {
            v.add("server-code-in-non-script", "server-side code inside a non-script file", 100);
        }
        if v.score >= min_score && v.score > 0 {
            out.push((abs.to_string_lossy().into_owned(), v));
        }
    };
    if root.is_file() {
        let name = root.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if let Ok((_, head)) = hash_file(root, 16 << 20) {
            let v = sigs.scan(&name, &head);
            if v.score >= min_score && v.score > 0 {
                out.push((root.to_string_lossy().into_owned(), v));
            }
        }
        return out;
    }
    walk(&site, 0, |rel, abs, _| visit(rel, abs));
    out.sort_by_key(|b| std::cmp::Reverse(b.1.score));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use warden_core::Config;

    fn setup(root: &Path, state: &Path) -> (Arc<Shared>, Arc<std::sync::Mutex<Vec<Event>>>, FimWorker) {
        let mut cfg = Config::default();
        cfg.daemon.state_dir = state.to_path_buf();
        cfg.fim.signatures = vec![];
        cfg.fim.sites.push(FimSite {
            name: "main".into(),
            root: root.to_path_buf(),
            include: warden_core::config::default_fim_include(),
            exclude: warden_core::config::default_fim_exclude(),
            no_scripts: warden_core::config::default_no_scripts(),
            signature_exclude: warden_core::config::default_signature_exclude(),
            access_log: None,
            quarantine: None,
            restart_unit: Some("php8.3-fpm.service".into()),
        });
        let shared = Shared::new(cfg);
        let (sink, store) = Sink::collector();
        let w = FimWorker::new(shared.clone(), sink);
        (shared, store, w)
    }

    #[test]
    fn baseline_then_detect_infection() {
        let site = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let r = site.path();
        std::fs::create_dir_all(r.join("wp-content/uploads/2026")).unwrap();
        std::fs::write(r.join("index.php"), "<?php require 'wp-blog-header.php';").unwrap();
        std::fs::write(r.join("wp-content/uploads/2026/cat.jpg"), b"\xff\xd8\xffJFIF").unwrap();
        let (_shared, events, mut w) = setup(r, state.path());

        let res = w.full_scan(0, false);
        assert_eq!(res["files"], 1);
        assert!(lock(&events).iter().any(|e| e.kind == "fim.baseline_created"));
        lock(&events).clear();

        // infection: modified index + webshell in uploads + polyglot image
        std::thread::sleep(Duration::from_millis(20));
        std::fs::write(r.join("index.php"), "<?php @eval(base64_decode($_POST['k'])); require 'wp-blog-header.php';")
            .unwrap();
        std::fs::write(r.join("wp-content/uploads/2026/x.php"), "<?php echo 1;").unwrap();
        std::fs::write(r.join("wp-content/uploads/2026/av.jpg"), b"\xff\xd8\xff<?php system($_GET[1]); ?>").unwrap();
        std::fs::write(r.join("about.php"), "<?php echo 'about';").unwrap();
        let res = w.full_scan(0, false);
        assert_eq!(res["flagged"], 3, "{res}");
        let ev = lock(&events).clone();
        let shells: Vec<&Event> = ev.iter().filter(|e| e.kind == "security.webshell").collect();
        assert_eq!(shells.len(), 3);
        assert!(shells.iter().all(|e| e.actions.contains(&ActionSpec::Quarantine)));
        assert!(shells.iter().any(|e| e.actions.iter().any(|a| matches!(a, ActionSpec::RestartUnit { .. }))));
        let changes = ev.iter().find(|e| e.kind == "fim.changes").unwrap();
        assert!(changes.details["changes"].to_string().contains("about.php"));

        // flagged files are not re-reported; quarantined (deleted) ones are silent
        lock(&events).clear();
        std::fs::remove_file(r.join("wp-content/uploads/2026/x.php")).unwrap();
        w.full_scan(0, false);
        assert!(!lock(&events).iter().any(|e| e.kind == "security.webshell" || e.kind == "fim.deleted"));
    }

    #[test]
    fn realtime_write_by_trusted_tool_is_accepted() {
        let site = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let r = site.path();
        std::fs::write(r.join("a.php"), "<?php echo 1;").unwrap();
        let (_s, events, mut w) = setup(r, state.path());
        w.full_scan(0, false);
        lock(&events).clear();
        std::fs::write(r.join("b.php"), "<?php echo 2;").unwrap();
        // a real process running a system binary (any will do for the test;
        // the trust needs the running inode, not just a path)
        let mut tool = std::process::Command::new("sleep").arg("10").spawn().unwrap();
        let tpid = tool.id() as i32;
        let texe = warden_sys::process::exe(tpid).unwrap();
        let git = Writer {
            pid: tpid,
            start_time: warden_sys::process::start_time(tpid).unwrap(),
            comm: "git".into(),
            exe: Some(texe.clone()),
            uid: 1000,
            user: "deploy".into(),
            cmdline: "git pull".into(),
            cgroup: None,
        };
        w.process_write(&r.join("b.php"), Some(git.clone()));
        assert!(lock(&events).is_empty());
        assert!(w.sites[0].base.files.contains_key("b.php"));
        // the path of a system binary is not enough: it must be what runs
        // (0.13.3 trusted the path string — a container's /usr/bin/git, say)
        std::fs::write(r.join("f.php"), "<?php echo 6;").unwrap();
        let other = if texe.ends_with("/env") { "/usr/bin/sleep" } else { "/usr/bin/env" };
        let claims = Writer { exe: Some(other.into()), ..git.clone() };
        w.process_write(&r.join("f.php"), Some(claims));
        assert!(lock(&events).iter().any(|e| e.kind == "fim.changed"), "a path it does not run is not trusted");
        lock(&events).clear();
        tool.kill().unwrap();
        tool.wait().unwrap();
        // a writer that only calls itself git — its own binary, or none the
        // kernel could name — gets no such trust
        std::fs::write(r.join("e.php"), "<?php echo 5;").unwrap();
        for exe in [Some("/home/deploy/git".to_owned()), None] {
            lock(&events).clear();
            let fake = Writer { exe, ..git.clone() };
            w.process_write(&r.join("e.php"), Some(fake));
            assert!(lock(&events).iter().any(|e| e.kind == "fim.changed"), "reported");
            w.sites[0].base.files.remove("e.php");
        }
        // the same change by a web worker is reported
        std::fs::write(r.join("c.php"), "<?php echo 3;").unwrap();
        let fpm = Writer {
            pid: 2,
            start_time: 2,
            comm: "php-fpm8.3".into(),
            exe: None,
            uid: 33,
            user: "www-data".into(),
            cmdline: String::new(),
            cgroup: Some("/system.slice/php8.3-fpm.service".into()),
        };
        w.process_write(&r.join("c.php"), Some(fpm.clone()));
        assert!(lock(&events).iter().any(|e| e.kind == "fim.changed"));
        // malicious content by a web worker → quarantine + kill writer
        lock(&events).clear();
        std::fs::write(r.join("d.php"), "<?php system($_REQUEST['c']);").unwrap();
        w.process_write(&r.join("d.php"), Some(fpm));
        let ev = lock(&events).clone();
        assert!(ev.iter().any(|e| e.kind == "security.webshell" && e.severity == Severity::Critical));
        assert!(ev.iter().any(|e| e.kind == "security.malicious_writer"));
    }

    fn fpm(pid: i32) -> Writer {
        Writer {
            pid,
            start_time: pid as u64,
            comm: "php-fpm8.3".into(),
            exe: None,
            uid: 33,
            user: "www-data".into(),
            cmdline: String::new(),
            cgroup: Some("/system.slice/php8.3-fpm.service".into()),
        }
    }

    /// The dropper set an old mtime on its shell (`touch()`): the requests
    /// around the write itself are still found (0.13.3 searched around the
    /// mtime, years back).
    #[test]
    fn realtime_correlation_ignores_a_backdated_mtime() {
        let site = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let r = site.path();
        std::fs::write(r.join("index.php"), "<?php echo 1;").unwrap();
        let (shared, events, mut w) = setup(r, state.path());
        w.full_scan(0, false);
        lock(&events).clear();
        let line = format!(
            "203.0.113.66 - - [{}] \"POST /wp-content/plugins/vuln/upload.php HTTP/1.1\" 200 12 \"-\" \"-\"",
            clf_now()
        );
        shared.access.push("main", correlate::parse_line(&line).unwrap());
        let f = r.join("wp-content-shell.php");
        std::fs::write(&f, "<?php system($_REQUEST['c']);").unwrap();
        let old = std::time::UNIX_EPOCH + Duration::from_secs(1_262_304_000); // 2010
        std::fs::File::options().write(true).open(&f).unwrap().set_modified(old).unwrap();
        w.process_write(&f, Some(fpm(800)));
        let ev = lock(&events).clone();
        let shell = ev.iter().find(|e| e.kind == "security.webshell").expect("webshell");
        assert!(shell.details["suspect_requests"].to_string().contains("203.0.113.66"), "{:?}", shell.details);
    }

    fn clf_now() -> String {
        // dd/Mon/yyyy:HH:MM:SS +0000 for now, without a date crate
        let secs = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let days = secs.div_euclid(86400);
        let tod = secs.rem_euclid(86400);
        // civil from days (Howard Hinnant)
        let z = days + 719468;
        let era = z.div_euclid(146097);
        let doe = z - era * 146097;
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = yoe + era * 400 + if m <= 2 { 1 } else { 0 };
        let mon =
            ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][(m - 1) as usize];
        format!("{d:02}/{mon}/{y}:{:02}:{:02}:{:02} +0000", tod / 3600, tod % 3600 / 60, tod % 60)
    }

    /// A plugin update through the CMS: many files by the PHP worker, none
    /// malicious. A warning that says how to pause FIM — the worker is not
    /// killed in the middle of the update (0.13.3 killed it).
    #[test]
    fn a_mass_change_without_malicious_code_kills_nobody() {
        let site = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let r = site.path();
        std::fs::write(r.join("index.php"), "<?php echo 1;").unwrap();
        let (_s, events, mut w) = setup(r, state.path());
        w.full_scan(0, false);
        lock(&events).clear();
        for i in 0..30 {
            let f = r.join(format!("plugin-{i}.php"));
            std::fs::write(&f, format!("<?php function f{i}() {{ return {i}; }}")).unwrap();
            w.process_write(&f, Some(fpm(500)));
        }
        let ev = lock(&events).clone();
        let mass: Vec<&Event> = ev.iter().filter(|e| e.kind == "fim.mass_change").collect();
        assert_eq!(mass.len(), 1);
        assert_eq!(mass[0].severity, Severity::Warning);
        assert_eq!(mass[0].details["malicious_content"], false);
        assert!(mass[0].details["hint"].as_str().unwrap().contains("wardenctl fim pause main 30m"));
        assert!(!ev.iter().any(|e| e.kind == "security.malicious_writer"), "nobody is killed");
    }

    /// Infection spreading: the burst contains malicious code. Only the
    /// writer whose writes matched is killed, not every web worker that
    /// changed a file in the window.
    #[test]
    fn a_mass_change_with_malicious_code_kills_only_its_writer() {
        let site = tempfile::tempdir().unwrap();
        let state = tempfile::tempdir().unwrap();
        let r = site.path();
        std::fs::write(r.join("index.php"), "<?php echo 1;").unwrap();
        let (_s, events, mut w) = setup(r, state.path());
        w.full_scan(0, false);
        lock(&events).clear();
        for i in 0..20 {
            let f = r.join(format!("cache-{i}.php"));
            std::fs::write(&f, format!("<?php return {i};")).unwrap();
            w.process_write(&f, Some(fpm(600)));
        }
        for i in 0..6 {
            let f = r.join(format!("x{i}.php"));
            std::fs::write(&f, "<?php system($_REQUEST['c']);").unwrap();
            w.process_write(&f, Some(fpm(700)));
        }
        let ev = lock(&events).clone();
        let mass = ev.iter().find(|e| e.kind == "fim.mass_change").expect("mass change");
        assert_eq!(mass.severity, Severity::Emergency);
        assert_eq!(mass.details["malicious_content"], true);
        assert!(mass.details["malicious_writers"].to_string().contains("[700]"));
        let killed: HashSet<i32> = ev
            .iter()
            .filter(|e| e.kind == "security.malicious_writer")
            .filter_map(|e| match &e.subject {
                Subject::Process(p) => Some(p.pid),
                _ => None,
            })
            .collect();
        assert_eq!(killed, HashSet::from([700]), "the worker that only wrote clean files is spared");
    }

    #[test]
    fn offline_scan() {
        let d = tempfile::tempdir().unwrap();
        std::fs::write(d.path().join("ok.php"), "<?php echo 1;").unwrap();
        std::fs::write(d.path().join("bad.php"), "<?php eval($_POST['x']);").unwrap();
        let v = scan_tree(d.path(), &[], 40);
        assert_eq!(v.len(), 1);
        assert!(v[0].0.ends_with("bad.php"));
    }
}
