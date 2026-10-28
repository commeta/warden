//! Where ModSecurity writes: the logs the WAF sensor follows.
//!
//! ModSecurity 2.9 (and libmodsecurity 3) can be set up in many ways, and
//! Warden has to work with all of them:
//!
//! * one serial audit log for the server, or one per virtual host
//!   (`SecAuditLog` inside `<VirtualHost>`) — a `[[waf.log]]` path may be a
//!   glob, new matches are picked up while the sensor runs;
//! * JSON or native records (`SecAuditLogFormat`), auto-detected;
//! * `SecAuditLogType Concurrent`: one file per transaction under
//!   `SecAuditLogStorageDir`, listed in an index (`SecAuditLog`) — or, when
//!   the index is piped to `mlogc`, found by scanning the storage
//!   directory;
//! * audit logging switched off or piped away: the error logs, one per
//!   virtual host if so configured;
//! * the logs the web servers are configured to write, found by
//!   [`crate::waf_discover`] when `waf.discover` is on.
//!
//! Files of a concurrent log are written by the web server's workers, in
//! directories they own: they are opened below the storage directory one
//! component at a time without following symlinks, and only regular files
//! of bounded size are read — an index line naming `../../etc/shadow`, or a
//! storage subdirectory replaced by a symlink, leads nowhere.

use crate::util::{FileTail, WebPrincipals, expand_glob, fill_captures, is_glob};
use crate::waf::{IndexEntry, NativeParser, WafHit, parse_entry, parse_error_line, parse_index_line, parse_json_line};
use std::collections::{HashMap, HashSet};
use std::ffi::CString;
use std::io::{self, Read};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use warden_core::config::{WafConfig, WafFormat, WafLog};
use warden_sys::safefs;

/// The largest transaction file read (a record with a big request body is
/// cut; its head and tail are what the parsers need).
pub const ENTRY_MAX: usize = 4 * 1024 * 1024;
/// Transaction files read per source in one batch; a longer backlog is read
/// in further batches without the pause between polls.
pub const ENTRIES_PER_POLL: usize = 2000;
/// Matches of one glob at most.
const GLOB_LIMIT: usize = 1000;
/// How often globs are expanded again and log ownership looked at.
const RESCAN: Duration = Duration::from_secs(30);

/// A storage directory of a concurrent audit log.
#[derive(Debug)]
pub struct Storage {
    root: PathBuf,
    /// The path as configured (may differ from `root` by symlinks).
    given: PathBuf,
    fd: OwnedFd,
}

fn cstr(s: &str) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in a path"))
}

impl Storage {
    /// Open the configured directory (an operator's path: symlinks owned by
    /// root, or by the owner of the directory holding them, are followed).
    pub fn open(root: &Path) -> io::Result<Self> {
        let (real, fd) = safefs::open_root(root)?;
        Ok(Self { root: real, given: root.to_path_buf(), fd })
    }

    /// An index path as a path below the storage: ModSecurity 2 writes it
    /// relative (`/www-data/20261027/…`), libmodsecurity 3 absolute
    /// (`/var/log/modsec/20261027/…`). An absolute path elsewhere is not
    /// ours to read.
    pub fn relative<'a>(&self, file: &'a str) -> &'a str {
        for base in [&self.given, &self.root] {
            if let Some(rest) = Path::new(file).strip_prefix(base).ok().and_then(|r| r.to_str()) {
                // a suffix of `file`, so it can be borrowed from it
                return &file[file.len() - rest.len()..];
            }
        }
        file
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The components of an index path (`/20261027/20261027-1200/…`):
    /// plain names only.
    fn components(rel: &str) -> io::Result<Vec<&str>> {
        let parts: Vec<&str> = rel.split('/').filter(|c| !c.is_empty()).collect();
        if parts.is_empty() || parts.len() > 8 || parts.iter().any(|c| *c == "." || *c == "..") {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("not a storage path: {rel:?}")));
        }
        Ok(parts)
    }

    /// Read a transaction file below the storage directory: no symlink on
    /// the way or at the end, a regular file, at most [`ENTRY_MAX`] bytes.
    pub fn read(&self, rel: &str) -> io::Result<Vec<u8>> {
        let parts = Self::components(rel)?;
        let (last, dirs) = parts.split_last().ok_or_else(|| io::Error::other("empty path"))?;
        let mut dir: Option<OwnedFd> = None;
        for d in dirs {
            let parent = dir.as_ref().map_or(self.fd.as_fd(), |f| f.as_fd());
            dir = Some(safefs::open_dir_at(parent, &cstr(d)?)?);
        }
        let parent = dir.as_ref().map_or(self.fd.as_fd(), |f| f.as_fd());
        let fd = safefs::open_at(parent, &cstr(last)?, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
        if !safefs::fstat(fd.as_fd())?.is_file() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("{rel} is not a regular file")));
        }
        let mut buf = Vec::new();
        std::fs::File::from(fd).take(ENTRY_MAX as u64).read_to_end(&mut buf)?;
        Ok(buf)
    }

    /// Names in a directory below the storage root (`""` = the root), never
    /// through a symlink.
    fn list(&self, rel: &str) -> io::Result<Vec<String>> {
        let mut dir = safefs::open_dir_at(self.fd.as_fd(), c".")?;
        for d in rel.split('/').filter(|c| !c.is_empty()) {
            dir = safefs::open_dir_at(dir.as_fd(), &cstr(d)?)?;
        }
        let mut s = safefs::DirStream::new(dir)?;
        let mut out = Vec::new();
        while let Some(n) = s.next_name() {
            if let Ok(n) = n.into_string() {
                out.push(n);
            }
        }
        out.sort();
        Ok(out)
    }
}

/// Finds new transaction files of a concurrent log without an index:
/// `<storage>/YYYYMMDD/YYYYMMDD-HHMM/<file>` — or, since ModSecurity 2.9.6,
/// `<storage>/<user>/YYYYMMDD/…` (a directory per account the server runs
/// requests as) — the newest two days and the newest three minutes of each.
#[derive(Debug)]
pub struct Scanner {
    storage: Storage,
    seen: HashMap<String, HashSet<String>>,
    primed: bool,
}

impl Scanner {
    pub fn new(storage: Storage) -> Self {
        Self { storage, seen: HashMap::new(), primed: false }
    }

    /// Paths (relative to the storage) of files that appeared since the
    /// last call; the first call only learns what is there.
    pub fn poll(&mut self, max: usize) -> Vec<String> {
        let mut out = Vec::new();
        let mut live: HashSet<String> = HashSet::new();
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || b == b'-');
        let Ok(top) = self.storage.list("") else { return out };
        // day directories, directly below the storage or one user level down
        let mut day_dirs: Vec<String> = Vec::new();
        for name in top.iter().take(64) {
            if name.len() == 8 && digits(name) {
                day_dirs.push(name.clone());
            } else if let Ok(days) = self.storage.list(name) {
                day_dirs.extend(days.into_iter().filter(|d| d.len() == 8 && digits(d)).map(|d| format!("{name}/{d}")));
            }
        }
        let day_of = |p: &str| p.rsplit('/').next().unwrap_or(p).to_owned();
        day_dirs.sort_by_key(|p| std::cmp::Reverse(day_of(p)));
        let newest: Vec<String> = {
            let mut days: Vec<String> = day_dirs.iter().map(|p| day_of(p)).collect();
            days.dedup();
            days.into_iter().take(2).collect()
        };
        for day_path in day_dirs.iter().filter(|p| newest.contains(&day_of(p))) {
            let day = day_of(day_path);
            let Ok(mins) = self.storage.list(day_path) else { continue };
            for min in mins.iter().rev().filter(|m| m.starts_with(day.as_str()) && digits(m)).take(3) {
                let key = format!("{day_path}/{min}");
                let Ok(files) = self.storage.list(&key) else { continue };
                let seen = self.seen.entry(key.clone()).or_default();
                for f in files {
                    if seen.insert(f.clone()) && self.primed && out.len() < max {
                        out.push(format!("/{key}/{f}"));
                    }
                }
                live.insert(key);
            }
        }
        self.seen.retain(|k, _| live.contains(k));
        self.primed = true;
        out
    }
}

/// How a source is read.
#[derive(Debug)]
enum Feed {
    /// Serial audit log or error log: line by line.
    Lines { tail: FileTail, native: NativeParser },
    /// Concurrent log: index lines name the transaction files.
    Index { tail: FileTail, storage: Storage },
    /// Concurrent log without an index.
    Scan(Scanner),
}

/// A log the sensor follows.
#[derive(Debug)]
pub struct Source {
    pub path: PathBuf,
    pub format: WafFormat,
    pub site: Option<String>,
    /// Why a web account can write it, if it can (see [`WebPrincipals`]).
    pub writable: Option<String>,
    /// From the configuration (or found in the web server's configuration).
    pub discovered: bool,
    /// Rescans in a row that did not want this source any more: a log
    /// between logrotate's rename and create is not dropped at once.
    missing: u8,
    feed: Feed,
}

/// Counters a poll reports back.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct PollStats {
    pub entries_read: u64,
    pub entries_missing: u64,
    /// A source had more than one poll's worth: poll again at once.
    pub saturated: bool,
    /// Entry files whose content is not what their index line says
    /// (changed after ModSecurity wrote them).
    pub entries_mismatch: u64,
}

/// Does an entry file hold what its index line says? ModSecurity 2 and 3
/// both write the MD5 of the entry into the index, through a descriptor the
/// root parent opened; the entry itself sits in a directory the workers
/// (and a webshell running as their user) can write. An index line without
/// a usable digest, or an entry cut at [`ENTRY_MAX`], cannot be checked.
fn entry_matches(e: &IndexEntry, content: &[u8]) -> bool {
    use md5::{Digest, Md5};
    let Some(want) = e.md5.as_deref() else { return true };
    if content.len() as u64 != e.size {
        return content.len() >= ENTRY_MAX && e.size > ENTRY_MAX as u64;
    }
    let got: String = Md5::digest(content).iter().map(|b| format!("{b:02x}")).collect();
    want.eq_ignore_ascii_case(&got)
}

impl Source {
    /// `from_start`: the file appeared after the sensor started (its first
    /// lines are new).
    fn open(log: &WafLog, path: PathBuf, site: Option<String>, from_start: bool, discovered: bool) -> io::Result<Self> {
        let tail = |p: &Path| if from_start { FileTail::from_start(p) } else { FileTail::new(p) };
        let feed = match log.format {
            WafFormat::Concurrent => match &log.storage_dir {
                Some(dir) => Feed::Index { tail: tail(&path), storage: Storage::open(dir)? },
                None => Feed::Scan(Scanner::new(Storage::open(&path)?)),
            },
            _ => Feed::Lines { tail: tail(&path), native: NativeParser::default() },
        };
        Ok(Self { path, format: log.format, site, writable: None, discovered, missing: 0, feed })
    }

    /// New transactions, at most `max` lines / files' worth.
    pub fn poll(&mut self, max: usize, stats: &mut PollStats) -> Vec<WafHit> {
        let mut out = Vec::new();
        match &mut self.feed {
            Feed::Lines { tail, native } => {
                let lines = tail.poll(max);
                stats.saturated |= lines.len() >= max;
                for line in lines {
                    if let Some(h) = parse_line(self.format, &line, native) {
                        out.push(h);
                    }
                }
                native.expire(Instant::now());
            }
            Feed::Index { tail, storage } => {
                // a batch of entries at a time; never skip one (a flood of
                // junk must not push the real attack past the reader)
                let cap = max.min(ENTRIES_PER_POLL);
                let lines = tail.poll(cap);
                stats.saturated |= lines.len() >= cap;
                for line in lines {
                    let Some(e) = parse_index_line(&line) else { continue };
                    match storage.read(storage.relative(&e.file)) {
                        Ok(content) => {
                            stats.entries_read += 1;
                            if !entry_matches(&e, &content) {
                                stats.entries_mismatch += 1;
                                continue;
                            }
                            if let Some(mut h) = parse_entry(&String::from_utf8_lossy(&content)) {
                                // the index line came through root's descriptor
                                h.ip = e.ip.or(h.ip);
                                if h.host.is_none() {
                                    h.host = Some(e.host);
                                }
                                out.push(h);
                            }
                        }
                        // already shipped and deleted by mlogc, or a line
                        // naming something that is not a transaction file
                        Err(_) => stats.entries_missing += 1,
                    }
                }
            }
            Feed::Scan(sc) => {
                let files = sc.poll(ENTRIES_PER_POLL);
                stats.saturated |= files.len() >= ENTRIES_PER_POLL;
                for f in files {
                    match sc.storage.read(&f) {
                        Ok(content) => {
                            stats.entries_read += 1;
                            out.extend(parse_entry(&String::from_utf8_lossy(&content)));
                        }
                        Err(_) => stats.entries_missing += 1,
                    }
                }
            }
        }
        out
    }

    /// The paths whose ownership decides whether the source can be forged.
    fn trust_paths(&self) -> Vec<&Path> {
        match &self.feed {
            Feed::Lines { .. } => vec![self.path.as_path()],
            Feed::Index { storage, .. } => vec![self.path.as_path(), storage.root()],
            Feed::Scan(sc) => vec![sc.storage.root()],
        }
    }
}

/// One line of a serial audit log or an error log.
pub fn parse_line(format: WafFormat, line: &str, native: &mut NativeParser) -> Option<WafHit> {
    match format {
        WafFormat::Json => parse_json_line(line).or_else(|| crate::waf::salvage_json_line(line)),
        WafFormat::ErrorLog => parse_error_line(line),
        WafFormat::Native => native.feed(line),
        WafFormat::Auto | WafFormat::Concurrent => {
            let t = line.trim_start();
            // inside a native record, section H lines read like error-log
            // lines (`Apache-Error: … ModSecurity: …` from ModSecurity 2,
            // `ModSecurity: Warning. …` from libmodsecurity 3), and bodies
            // can hold anything: they belong to the record
            if native.in_transaction() {
                native.feed(line)
            } else if t.starts_with('{') {
                parse_json_line(t).or_else(|| crate::waf::salvage_json_line(t))
            } else if t.contains("ModSecurity:") && !t.starts_with("Message:") {
                parse_error_line(t)
            } else {
                native.feed(line)
            }
        }
    }
}

/// Every log the sensor follows, kept in step with the configuration, the
/// file system (globs) and the web servers' configuration (discovery).
#[derive(Debug)]
pub struct Sources {
    pub list: Vec<Source>,
    started: Instant,
    last_scan: Option<Instant>,
    /// Rescan at the next call, whatever [`RESCAN`] says.
    due: bool,
    /// Paths that could not be opened, and why (for `status`).
    pub problems: Vec<(PathBuf, String)>,
}

impl Sources {
    pub fn new() -> Self {
        Self { list: Vec::new(), started: Instant::now(), last_scan: None, due: false, problems: Vec::new() }
    }

    /// Something changed (discovery found other logs): rescan at the next
    /// [`Self::refresh`].
    pub fn rescan_soon(&mut self) {
        self.due = true;
    }

    /// Expand the configured and discovered logs into concrete sources;
    /// add the new ones, drop the ones no longer wanted, and look at who
    /// can write each. Runs on the first call and every [`RESCAN`]; returns
    /// whether it ran.
    pub fn refresh(&mut self, cfg: &WafConfig, discovered: &[WafLog], web: &WebPrincipals, now: Instant) -> bool {
        if !self.due && self.last_scan.is_some_and(|t| now.saturating_duration_since(t) < RESCAN) {
            return false;
        }
        self.due = false;
        let first = self.last_scan.is_none();
        self.last_scan = Some(now);
        self.problems.clear();
        // concrete (path, log, site, discovered)
        let mut wanted: Vec<(PathBuf, WafLog, Option<String>, bool)> = Vec::new();
        let configured = cfg.logs.iter().map(|l| (l, false));
        let found = discovered.iter().filter(|d| !cfg.logs.iter().any(|l| l.path == d.path)).map(|l| (l, true));
        for (log, disc) in configured.chain(found) {
            if is_glob(&log.path) {
                for (p, caps) in expand_glob(&log.path, GLOB_LIMIT) {
                    let site = log.site.as_deref().map(|s| fill_captures(s, &caps));
                    wanted.push((p, log.clone(), site, disc));
                }
            } else {
                wanted.push((log.path.clone(), log.clone(), log.site.clone(), disc));
            }
        }
        let mut seen = HashSet::new();
        wanted.retain(|(p, _, _, _)| seen.insert(p.clone()));
        let before = self.list.len();
        for s in self.list.iter_mut() {
            let still = wanted.iter().any(|(p, l, _, _)| *p == s.path && l.format == s.format);
            s.missing = if still { 0 } else { s.missing.saturating_add(1) };
        }
        self.list.retain(|s| s.missing < 2);
        let mut changed = self.list.len() != before;
        for (path, log, site, disc) in wanted {
            if self.list.iter().any(|s| s.path == path) {
                continue;
            }
            // a file that appeared after the sensor started is new from
            // its first line; one that was there is followed from its end
            let from_start = !first && created_after(&path, self.started);
            match Source::open(&log, path.clone(), site, from_start, disc) {
                Ok(s) => {
                    self.list.push(s);
                    changed = true;
                }
                Err(e) => self.problems.push((path, e.to_string())),
            }
        }
        for s in self.list.iter_mut() {
            s.writable = s.trust_paths().into_iter().find_map(|p| web.can_write(p));
        }
        let _ = changed;
        true
    }

    /// The sources as `status` shows them.
    pub fn status(&self) -> serde_json::Value {
        let sources: Vec<serde_json::Value> = self
            .list
            .iter()
            .map(|s| {
                let storage = match &s.feed {
                    Feed::Index { storage, .. } => Some(storage.root()),
                    Feed::Scan(sc) => Some(sc.storage.root()),
                    Feed::Lines { .. } => None,
                };
                serde_json::json!({
                    "path": s.path, "format": s.format, "site": s.site, "storage_dir": storage,
                    "discovered": s.discovered, "writable_by_web_user": s.writable,
                })
            })
            .collect();
        let problems: Vec<serde_json::Value> =
            self.problems.iter().map(|(p, why)| serde_json::json!({"path": p, "error": why})).collect();
        serde_json::json!({ "sources": sources, "problems": problems })
    }
}

impl Default for Sources {
    fn default() -> Self {
        Self::new()
    }
}

/// Did `path` come into existence after `t`? Its birth time where the file
/// system records one; otherwise only a small file whose last change is
/// after `t` counts — an old, busy log found later (a new virtual host
/// pointing at it) must not be replayed from its first line.
fn created_after(path: &Path, t: Instant) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(md) = std::fs::metadata(path) else { return false };
    let started = std::time::SystemTime::now() - t.elapsed() - Duration::from_secs(1);
    match md.created() {
        Ok(born) => born >= started,
        Err(_) => {
            let changed = std::time::UNIX_EPOCH + Duration::from_secs(md.ctime().max(0) as u64);
            md.len() <= 1024 * 1024 && changed >= started
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    const NATIVE: &str = "--a1b2c3d4-A--\n[27/Oct/2026:12:00:00 +0300] YdEaYn8AAQEAAAABcdcAAAAA 203.0.113.50 51515 10.0.0.1 80\n--a1b2c3d4-B--\nGET /?id=1%20or%201=1 HTTP/1.1\nHost: example.com\n\n--a1b2c3d4-F--\nHTTP/1.1 403 Forbidden\n\n--a1b2c3d4-H--\nMessage: Access denied with code 403 (phase 2). [file \"/x.conf\"] [line \"1\"] [id \"942100\"] [msg \"SQL Injection Attack Detected via libinjection\"] [severity \"CRITICAL\"]\nAction: Intercepted (phase 2)\n\n--a1b2c3d4-Z--\n";

    fn md5_hex(b: &[u8]) -> String {
        use md5::{Digest, Md5};
        Md5::digest(b).iter().map(|x| format!("{x:02x}")).collect()
    }

    fn concurrent_layout(root: &Path, name: &str, content: &str) -> String {
        let rel = format!("/20261027/20261027-1200/{name}");
        let d = root.join("20261027/20261027-1200");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join(name), content).unwrap();
        rel
    }

    #[test]
    fn concurrent_index_entries_are_read_and_parsed() {
        let storage_dir = tempfile::tempdir().unwrap();
        let logs = tempfile::tempdir().unwrap();
        let index = logs.path().join("index");
        std::fs::write(&index, "").unwrap();
        let log = WafLog {
            path: index.clone(),
            format: WafFormat::Concurrent,
            site: Some("main".into()),
            storage_dir: Some(storage_dir.path().to_path_buf()),
        };
        let mut src = Source::open(&log, index.clone(), log.site.clone(), false, false).unwrap();
        let rel = concurrent_layout(storage_dir.path(), "20261027-120000-YdEaYn8AAQEAAAABcdcAAAAA", NATIVE);
        let mut f = std::fs::OpenOptions::new().append(true).open(&index).unwrap();
        writeln!(
            f,
            "example.com 203.0.113.50 - - [27/Oct/2026:12:00:00 +0300] \"GET /?id=1 HTTP/1.1\" 403 199 \"-\" \"curl/8\" YdEaYn8AAQEAAAABcdcAAAAA \"-\" {rel} 0 {} md5:{}",
            NATIVE.len(),
            md5_hex(NATIVE.as_bytes())
        )
        .unwrap();
        // forged lines: a path out of the storage, and a missing file
        writeln!(f, "h 198.51.100.1 - - [x] \"GET / HTTP/1.1\" 403 1 \"-\" \"-\" U \"-\" /../../etc/passwd 0 10 md5:0")
            .unwrap();
        writeln!(f, "h 198.51.100.2 - - [x] \"GET / HTTP/1.1\" 403 1 \"-\" \"-\" U \"-\" /20261027/20261027-1200/gone 0 10 md5:0").unwrap();
        // libmodsecurity 3: the absolute path, a float length; an absolute
        // path elsewhere is looked up below the storage, and is not there
        let abs = storage_dir.path().join(rel.trim_start_matches('/'));
        writeln!(
            f,
            "x.test 203.0.113.51 - [x] \"GET / HTTP/1.1\" 403 162 - \"-\" 1793.2 - {} 0 {}.000000 md5:{}",
            abs.display(),
            NATIVE.len(),
            md5_hex(NATIVE.as_bytes())
        )
        .unwrap();
        // the entry was changed after its index line was written
        writeln!(
            f,
            "x.test 203.0.113.53 - [x] \"GET / HTTP/1.1\" 403 162 - \"-\" 1793.2 - {} 0 {}.000000 md5:{}",
            abs.display(),
            NATIVE.len(),
            md5_hex(b"what ModSecurity wrote")
        )
        .unwrap();
        writeln!(
            f,
            "x.test 203.0.113.52 - [x] \"GET / HTTP/1.1\" 403 162 - \"-\" 1793.2 - /etc/passwd 0 3750.000000 md5:0"
        )
        .unwrap();
        let mut st = PollStats::default();
        let hits = src.poll(100, &mut st);
        assert_eq!(hits.len(), 2, "{hits:?}");
        assert_eq!(hits[0].ip, Some("203.0.113.50".parse().unwrap()));
        assert_eq!(hits[0].rule_ids, ["942100"]);
        assert!(hits[0].intercepted);
        // the address of the index line (root's descriptor) wins
        assert_eq!(hits[1].ip, Some("203.0.113.51".parse().unwrap()));
        assert_eq!(st, PollStats { entries_read: 3, entries_missing: 3, entries_mismatch: 1, saturated: false });
    }

    /// The workers own the storage subdirectories: one replaced by a
    /// symlink must not lead the root daemon out of the storage.
    #[test]
    fn a_symlinked_storage_subdirectory_is_not_followed() {
        let storage_dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(outside.path().join("20261027-1200")).unwrap();
        std::fs::write(outside.path().join("20261027-1200/secret"), NATIVE).unwrap();
        std::os::unix::fs::symlink(outside.path(), storage_dir.path().join("20261027")).unwrap();
        let st = Storage::open(storage_dir.path()).unwrap();
        assert!(st.read("/20261027/20261027-1200/secret").is_err());
        assert!(st.read("/../x").is_err());
        let file = storage_dir.path().join("plain");
        std::fs::write(&file, NATIVE).unwrap();
        std::os::unix::fs::symlink(&file, storage_dir.path().join("link")).unwrap();
        assert!(st.read("/plain").is_ok());
        assert!(st.read("/link").is_err(), "a symlink as the entry itself is refused");
    }

    /// ModSecurity 2.9.6+ puts a directory per user above the days.
    #[test]
    fn a_concurrent_log_with_user_directories_is_scanned() {
        let storage_dir = tempfile::tempdir().unwrap();
        let user = storage_dir.path().join("www-data");
        concurrent_layout(&user, "old", NATIVE);
        let log = WafLog {
            path: storage_dir.path().to_path_buf(),
            format: WafFormat::Concurrent,
            site: None,
            storage_dir: None,
        };
        let mut src = Source::open(&log, log.path.clone(), None, false, false).unwrap();
        let mut st = PollStats::default();
        assert!(src.poll(100, &mut st).is_empty());
        concurrent_layout(&user, "new", NATIVE);
        assert_eq!(src.poll(100, &mut st).len(), 1);
    }

    #[test]
    fn a_concurrent_log_without_index_is_scanned() {
        let storage_dir = tempfile::tempdir().unwrap();
        concurrent_layout(storage_dir.path(), "old", NATIVE);
        let log = WafLog {
            path: storage_dir.path().to_path_buf(),
            format: WafFormat::Concurrent,
            site: None,
            storage_dir: None,
        };
        let mut src = Source::open(&log, log.path.clone(), None, false, false).unwrap();
        let mut st = PollStats::default();
        assert!(src.poll(100, &mut st).is_empty(), "what was there before is not replayed");
        concurrent_layout(storage_dir.path(), "new", NATIVE);
        let hits = src.poll(100, &mut st);
        assert_eq!(hits.len(), 1);
        assert!(src.poll(100, &mut st).is_empty(), "read once");
    }

    #[test]
    fn per_site_logs_from_a_glob_are_followed_and_new_sites_picked_up() {
        let root = tempfile::tempdir().unwrap();
        let site_log = |s: &str| {
            let d = root.path().join(s);
            std::fs::create_dir_all(&d).unwrap();
            let p = d.join("modsec_audit.log");
            std::fs::write(&p, "").unwrap();
            p
        };
        let a = site_log("alpha");
        let cfg = WafConfig {
            logs: vec![WafLog {
                path: root.path().join("*/modsec_audit.log"),
                format: WafFormat::Auto,
                site: Some("{1}".into()),
                storage_dir: None,
            }],
            ..Default::default()
        };
        let web = WebPrincipals::default();
        let mut srcs = Sources::new();
        let t0 = Instant::now();
        assert!(srcs.refresh(&cfg, &[], &web, t0));
        assert_eq!(srcs.list.len(), 1);
        assert_eq!(srcs.list[0].site.as_deref(), Some("alpha"));
        // a new site appears; its first transaction is already in the file
        let b = site_log("beta");
        std::fs::write(&b, NATIVE).unwrap();
        assert!(!srcs.refresh(&cfg, &[], &web, t0 + Duration::from_secs(1)), "not before RESCAN");
        assert_eq!(srcs.list.len(), 1);
        assert!(srcs.refresh(&cfg, &[], &web, t0 + RESCAN));
        let beta = srcs.list.iter_mut().find(|s| s.site.as_deref() == Some("beta")).unwrap();
        let hits = beta.poll(1000, &mut PollStats::default());
        assert_eq!(hits.len(), 1, "a new log is read from its start");
        // alpha's log goes away: kept through one rescan (logrotate's
        // rename-then-create), dropped at the second
        std::fs::remove_file(&a).unwrap();
        srcs.refresh(&cfg, &[], &web, t0 + RESCAN * 2);
        assert_eq!(srcs.list.len(), 2);
        assert!(srcs.refresh(&cfg, &[], &web, t0 + RESCAN * 3));
        assert_eq!(srcs.list.len(), 1);
    }
}
/// Records written by real ModSecurity builds (Ubuntu 24.04: Apache 2.4.58
/// with ModSecurity 2.9.7, nginx 1.24 with libmodsecurity 3.0.12 and
/// connector 1.0.3, CRS 3.3.5), one per log kind: each must give exactly one
/// transaction with the client, the rules and the verdict.
#[cfg(test)]
mod real_logs {
    use super::*;
    use crate::waf::{parse_entry, parse_index_line};

    fn fixture(name: &str) -> String {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/modsecurity").join(name);
        std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    fn lines(name: &str, format: WafFormat) -> Vec<WafHit> {
        let mut n = NativeParser::default();
        fixture(name).lines().filter_map(|l| parse_line(format, l, &mut n)).collect()
    }

    fn check(h: &WafHit, ip: &str) {
        assert_eq!(h.ip, Some(ip.parse().unwrap()), "{h:?}");
        assert!(h.host.as_deref().is_some_and(|x| x.starts_with("127.0.0.1")), "{h:?}");
        assert!(h.intercepted, "{h:?}");
        for r in ["941100", "942100", "949110"] {
            assert!(h.rule_ids.iter().any(|x| x == r), "{r} missing: {:?}", h.rule_ids);
        }
        assert_eq!(h.summary(), Some("XSS Attack Detected via libinjection"));
    }

    #[test]
    fn serial_native_logs() {
        for (f, ip) in
            [("apache-2.9.7-serial.log", "127.0.0.11"), ("nginx-libmodsecurity-3.0.12-serial.log", "127.0.0.15")]
        {
            for format in [WafFormat::Auto, WafFormat::Native] {
                let hits = lines(f, format);
                assert_eq!(hits.len(), 1, "{f} {format:?}: {hits:?}");
                check(&hits[0], ip);
                assert_eq!(hits[0].status, Some(403));
            }
        }
    }

    #[test]
    fn json_logs() {
        for (f, ip) in [("apache-2.9.7-vhost.json", "127.0.0.12"), ("nginx-libmodsecurity-3.0.12.json", "127.0.0.14")] {
            for format in [WafFormat::Auto, WafFormat::Json] {
                let hits = lines(f, format);
                assert_eq!(hits.len(), 1, "{f} {format:?}");
                check(&hits[0], ip);
            }
        }
    }

    #[test]
    fn concurrent_entries_and_index_lines() {
        for (index, entry, ip) in [
            ("apache-2.9.7-concurrent.index", "apache-2.9.7-concurrent-entry.log", "127.0.0.13"),
            (
                "nginx-libmodsecurity-3.0.12-concurrent.index",
                "nginx-libmodsecurity-3.0.12-concurrent-entry.log",
                "127.0.0.16",
            ),
        ] {
            let e = parse_index_line(fixture(index).trim_end_matches('\n')).unwrap();
            assert_eq!(e.ip, Some(ip.parse().unwrap()));
            let content = fixture(entry);
            assert_eq!(e.size, content.len() as u64, "{index}");
            assert!(entry_matches(&e, content.as_bytes()), "{index}: the digest is the entry's MD5");
            assert!(!entry_matches(&e, content.replace("127.0.0.1", "127.0.0.9").as_bytes()));
            check(&parse_entry(&content).unwrap(), ip);
        }
    }

    /// A request body is logged verbatim (part I): one made of a fake end
    /// of record and a fake record for another address stays body.
    #[test]
    fn a_forged_record_in_a_request_body_stays_body() {
        let real = fixture("apache-2.9.7-serial.log");
        let forged = "--zzzzzzzz-Z--\n--yyyyyyyy-A--\n[27/Oct/2026:20:26:43 +0000] X 192.0.2.77 1 127.0.0.1 80\n--yyyyyyyy-H--\nMessage: Access denied with code 403 (phase 2). [id \"942100\"] [msg \"SQL Injection\"] [severity \"CRITICAL\"]\nAction: Intercepted (phase 2)\n--yyyyyyyy-Z--\n";
        // put it where part I (the body) would be: before section F
        let at = real.find("-F--\n").and_then(|i| real[..i].rfind('\n')).unwrap() + 1;
        let text = format!("{}{forged}{}", &real[..at], &real[at..]);
        for format in [WafFormat::Auto, WafFormat::Native] {
            let mut n = NativeParser::default();
            let hits: Vec<WafHit> = text.lines().filter_map(|l| parse_line(format, l, &mut n)).collect();
            assert_eq!(hits.len(), 1, "{format:?}: {hits:?}");
            check(&hits[0], "127.0.0.11");
        }
        let h = parse_entry(&text).unwrap();
        assert_eq!(h.ip, Some("127.0.0.11".parse().unwrap()));
    }

    /// A record cut by a crash does not swallow the records after it.
    #[test]
    fn a_cut_record_expires() {
        let real = fixture("nginx-libmodsecurity-3.0.12-serial.log");
        let cut = &real[..real.find("-H--").unwrap()];
        let mut n = NativeParser::default();
        assert!(cut.lines().filter_map(|l| parse_line(WafFormat::Auto, l, &mut n)).next().is_none());
        assert!(n.in_transaction());
        n.expire(Instant::now() + Duration::from_secs(60));
        assert!(!n.in_transaction());
        let hits: Vec<WafHit> = real.lines().filter_map(|l| parse_line(WafFormat::Auto, l, &mut n)).collect();
        assert_eq!(hits.len(), 1);
    }
}
