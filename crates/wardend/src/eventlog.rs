//! Persistent JSON-lines event journal with size-based rotation, plus the
//! in-memory ring served to `wardenctl events`.
//!
//! The engine only serializes an event, puts it into the ring and hands
//! the line to the journal writer, a thread of its own: the engine shares
//! the main thread with the control socket and `/health`, and a write to a
//! full or hung disk must not hold them (0.13.3 wrote from the engine).
//!
//! The writer is built for the disk Warden is there for — a full one:
//! * a write that fails half way is cut back to the last complete line,
//!   and a journal that ends in a partial line (a crash, a full disk) is
//!   repaired when it is opened, so every line stays valid JSON;
//! * failures are counted (`warden_journal_write_errors_total`) and logged
//!   at most once a minute;
//! * a rotation that fails (a read-only or full filesystem) is retried
//!   with a back-off instead of on every event.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use warden_core::config::EventLogConfig;
use warden_core::sync::lock;
use warden_core::{Event, Severity};
use warden_detect::Shared;

/// An event kept for `wardenctl events`: the serialized JSON line (2-4x
/// smaller than the `serde_json::Value` tree of the details) plus what the
/// request filters on.
#[derive(Debug, Clone)]
pub struct RingEntry {
    pub id: u64,
    pub severity: Severity,
    pub json: Box<str>,
}

pub type Ring = Arc<Mutex<VecDeque<RingEntry>>>;

/// Lines waiting for the writer. A writer stuck on a hung disk fills it;
/// then lines are dropped and counted, the engine never waits.
const QUEUE: usize = 4096;

/// Highest event id in the journal (current file, else the previous one):
/// only the last 64 KiB are read.
fn last_id(path: &Path) -> Option<u64> {
    let prev = PathBuf::from(format!("{}.1", path.display()));
    [path, prev.as_path()].into_iter().find_map(|p| {
        let mut f = File::open(p).ok()?;
        let len = f.metadata().ok()?.len();
        f.seek(SeekFrom::Start(len.saturating_sub(64 * 1024))).ok()?;
        let mut tail = String::new();
        f.read_to_string(&mut tail).ok()?;
        tail.lines().rev().find_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()?.get("id")?.as_u64())
    })
}

enum Msg {
    Line(String),
    Reconfigure(EventLogConfig),
}

/// The engine's side: ring + hand-off to the writer thread.
#[derive(Debug)]
pub struct EventLog {
    min_severity: Severity,
    ring_size: usize,
    tx: SyncSender<Msg>,
    pub ring: Ring,
    shared: Arc<Shared>,
}

impl std::fmt::Debug for Msg {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Msg::Line(_) => "Line",
            Msg::Reconfigure(_) => "Reconfigure",
        })
    }
}

impl EventLog {
    /// Open the journal and start its writer thread.
    pub fn spawn(cfg: &EventLogConfig, ring: Ring, shared: Arc<Shared>) -> std::io::Result<Self> {
        if let Some(id) = last_id(&cfg.path) {
            warden_core::event::resume_ids_after(id);
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(QUEUE);
        let journal = Journal::new(cfg, Some(shared.clone()));
        std::thread::Builder::new().name("w-journal".into()).spawn(move || journal.run(&rx))?;
        Ok(Self { min_severity: cfg.min_severity, ring_size: cfg.ring_size, tx, ring, shared })
    }

    pub fn reconfigure(&mut self, cfg: &EventLogConfig) {
        self.min_severity = cfg.min_severity;
        self.ring_size = cfg.ring_size;
        let _ = self.tx.send(Msg::Reconfigure(cfg.clone()));
    }

    pub fn record(&mut self, ev: &Event) {
        let mut v = serde_json::to_value(ev).unwrap_or_default();
        if let Some(o) = v.as_object_mut() {
            o.insert("time".into(), ev.time().into());
        }
        let line = v.to_string();
        drop(v);
        if ev.severity >= self.min_severity {
            match self.tx.try_send(Msg::Line(line.clone())) {
                Ok(()) => {}
                Err(TrySendError::Full(_)) => self.shared.metrics.inc("warden_journal_dropped_total", &[], 1.0),
                Err(TrySendError::Disconnected(_)) => {}
            }
        }
        let mut r = lock(&self.ring);
        r.push_back(RingEntry { id: ev.id, severity: ev.severity, json: line.into_boxed_str() });
        while r.len() > self.ring_size.max(10) {
            r.pop_front();
        }
    }
}

/// The writer's side: the file, rotation and error handling.
pub struct Journal {
    cfg: EventLogConfig,
    file: Option<File>,
    size: u64,
    shared: Option<Arc<Shared>>,
    errors: u64,
    last_warn: Option<Instant>,
    /// A rotation failed: do not try again before this.
    rotate_after: Option<Instant>,
    rotate_backoff: Duration,
}

impl Journal {
    pub fn new(cfg: &EventLogConfig, shared: Option<Arc<Shared>>) -> Self {
        let mut j = Self {
            cfg: cfg.clone(),
            file: None,
            size: 0,
            shared,
            errors: 0,
            last_warn: None,
            rotate_after: None,
            rotate_backoff: Duration::from_secs(60),
        };
        j.open();
        j
    }

    fn run(mut self, rx: &Receiver<Msg>) {
        while let Ok(m) = rx.recv() {
            match m {
                Msg::Line(l) => self.write(&l),
                Msg::Reconfigure(c) => self.reconfigure(&c),
            }
        }
    }

    pub fn reconfigure(&mut self, cfg: &EventLogConfig) {
        let moved = cfg.path != self.cfg.path;
        self.cfg = cfg.clone();
        if moved || self.file.is_none() {
            self.file = None;
            self.open();
        }
    }

    #[cfg(test)]
    pub fn errors(&self) -> u64 {
        self.errors
    }

    fn open(&mut self) {
        if let Some(d) = self.cfg.path.parent() {
            let _ = std::fs::create_dir_all(d);
        }
        match OpenOptions::new().create(true).append(true).read(true).open(&self.cfg.path) {
            Ok(f) => {
                self.size = f.metadata().map(|m| m.len()).unwrap_or(0);
                self.file = Some(f);
                self.repair_tail();
            }
            Err(e) => self.failed("cannot open the event journal", &e),
        }
    }

    /// A journal that ends in the middle of a line (a crash, a disk that
    /// filled up mid-write): cut it back to its last complete line, so that
    /// the next event does not glue onto the broken one.
    fn repair_tail(&mut self) {
        let Some(f) = self.file.as_mut() else { return };
        if self.size == 0 {
            return;
        }
        let start = self.size.saturating_sub(64 * 1024);
        let mut tail = Vec::new();
        if f.seek(SeekFrom::Start(start)).is_err() || f.read_to_end(&mut tail).is_err() {
            return;
        }
        if tail.last() == Some(&b'\n') {
            return;
        }
        let keep = match tail.iter().rposition(|b| *b == b'\n') {
            Some(i) => start + i as u64 + 1,
            None if start == 0 => 0,
            None => return, // one 64 KiB "line": leave it, the next one starts fresh below
        };
        if f.set_len(keep).is_ok() {
            tracing::warn!(path = %self.cfg.path.display(), cut = self.size - keep, "event journal ended in a partial line; repaired");
            self.size = keep;
        }
    }

    fn rotate(&mut self) {
        let now = Instant::now();
        if self.rotate_after.is_some_and(|t| now < t) {
            return;
        }
        self.file = None;
        let p = self.cfg.path.clone();
        let name = |i: usize| -> PathBuf { PathBuf::from(format!("{}.{i}", p.display())) };
        let keep = self.cfg.keep.max(1);
        let _ = std::fs::remove_file(name(keep));
        for i in (1..keep).rev() {
            let _ = std::fs::rename(name(i), name(i + 1));
        }
        let renamed = std::fs::rename(&p, name(1));
        self.open();
        match renamed {
            Ok(()) => {
                self.rotate_after = None;
                self.rotate_backoff = Duration::from_secs(60);
            }
            Err(e) => {
                // keep writing to the current file, try again later
                self.failed("cannot rotate the event journal", &e);
                self.rotate_after = Some(now + self.rotate_backoff);
                self.rotate_backoff = (self.rotate_backoff * 2).min(Duration::from_secs(3600));
            }
        }
    }

    /// Append one line (without its newline).
    pub fn write(&mut self, line: &str) {
        if self.size >= self.cfg.max_size.as_u64() {
            self.rotate();
        }
        if self.file.is_none() {
            self.open(); // a disk that came back
        }
        let Some(f) = self.file.as_mut() else { return };
        let mut buf = Vec::with_capacity(line.len() + 1);
        buf.extend_from_slice(line.as_bytes());
        buf.push(b'\n');
        match f.write_all(&buf) {
            Ok(()) => self.size += buf.len() as u64,
            Err(e) => {
                // ENOSPC after part of the line: cut it back off
                let _ = f.set_len(self.size);
                self.failed("cannot write to the event journal", &e);
            }
        }
    }

    fn failed(&mut self, what: &str, e: &std::io::Error) {
        self.errors += 1;
        if let Some(s) = &self.shared {
            s.metrics.inc("warden_journal_write_errors_total", &[], 1.0);
        }
        let now = Instant::now();
        if self.last_warn.is_none_or(|t| now.saturating_duration_since(t) >= Duration::from_secs(60)) {
            self.last_warn = Some(now);
            tracing::warn!(path = %self.cfg.path.display(), error = %e, errors = self.errors, "{what}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use warden_core::ByteSize;

    fn line(i: usize) -> String {
        serde_json::json!({"id": i, "title": format!("event number {i}")}).to_string()
    }

    #[test]
    fn writes_and_rotates() {
        let d = tempfile::tempdir().unwrap();
        let cfg = EventLogConfig {
            path: d.path().join("events.jsonl"),
            max_size: ByteSize(300),
            keep: 2,
            ring_size: 10,
            ..Default::default()
        };
        let mut j = Journal::new(&cfg, None);
        for i in 0..20 {
            j.write(&line(i));
        }
        assert!(d.path().join("events.jsonl.1").exists());
        assert!(d.path().join("events.jsonl.2").exists());
        assert!(!d.path().join("events.jsonl.3").exists());
        let last = std::fs::read_to_string(d.path().join("events.jsonl")).unwrap();
        assert!(last.lines().all(|l| serde_json::from_str::<serde_json::Value>(l).is_ok()));
        assert_eq!(j.errors(), 0);
    }

    #[test]
    fn the_engine_side_hands_lines_to_the_writer_thread() {
        let d = tempfile::tempdir().unwrap();
        let cfg = EventLogConfig { path: d.path().join("events.jsonl"), ring_size: 10, ..Default::default() };
        let shared = Shared::new(warden_core::Config::default());
        let ring: Ring = Default::default();
        let mut l = EventLog::spawn(&cfg, ring.clone(), shared).unwrap();
        for i in 0..20 {
            l.record(&Event::new("t", Severity::Warning, format!("event number {i}")));
        }
        assert_eq!(lock(&ring).len(), 10, "the ring is updated at once");
        let mut lines = 0;
        for _ in 0..100 {
            lines = std::fs::read_to_string(&cfg.path).map(|s| s.lines().count()).unwrap_or(0);
            if lines == 20 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(lines, 20);
    }

    /// A journal that ends in a partial line (the disk filled up, the
    /// daemon was killed mid-write) is cut back to its last complete line.
    #[test]
    fn a_partial_last_line_is_repaired_on_open() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("events.jsonl");
        std::fs::write(&path, format!("{}\n{}\n{{\"id\":3,\"tit", line(1), line(2))).unwrap();
        let cfg = EventLogConfig { path: path.clone(), ..Default::default() };
        let mut j = Journal::new(&cfg, None);
        j.write(&line(4));
        let text = std::fs::read_to_string(&path).unwrap();
        let ids: Vec<u64> = text
            .lines()
            .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["id"].as_u64().unwrap())
            .collect();
        assert_eq!(ids, [1, 2, 4]);
    }

    /// Writes that fail (here: the journal's directory is gone and cannot
    /// be recreated) are counted and reported, never panic, and the journal
    /// resumes when the disk comes back.
    #[test]
    fn write_errors_are_counted_and_the_journal_recovers() {
        let d = tempfile::tempdir().unwrap();
        let dir = d.path().join("log");
        let cfg = EventLogConfig { path: dir.join("events.jsonl"), ..Default::default() };
        let shared = Shared::new(warden_core::Config::default());
        let mut j = Journal::new(&cfg, Some(shared.clone()));
        j.write(&line(1));
        // the directory is replaced by a file: nothing can be opened there
        j.file = None;
        std::fs::remove_dir_all(&dir).unwrap();
        std::fs::write(&dir, "not a directory").unwrap();
        j.write(&line(2));
        j.write(&line(3));
        assert!(j.errors() >= 2);
        assert!(shared.metrics.get("warden_journal_write_errors_total", &[]).unwrap_or(0.0) >= 2.0);
        // back
        std::fs::remove_file(&dir).unwrap();
        j.write(&line(4));
        let text = std::fs::read_to_string(&cfg.path).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
    }

    /// A rotation that fails is retried with a back-off, not on every event.
    #[test]
    fn a_failed_rotation_backs_off() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("events.jsonl");
        let cfg = EventLogConfig { path: path.clone(), max_size: ByteSize(100), keep: 1, ..Default::default() };
        let mut j = Journal::new(&cfg, None);
        // `events.jsonl.1` is a non-empty directory: the rename fails
        std::fs::create_dir(d.path().join("events.jsonl.1")).unwrap();
        std::fs::write(d.path().join("events.jsonl.1/x"), "x").unwrap();
        for i in 0..10 {
            j.write(&line(i));
        }
        assert_eq!(j.errors(), 1, "one failed rotation, then a back-off");
        assert!(j.rotate_after.is_some());
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 10, "the events are still written");
    }

    #[test]
    fn ids_resume_after_the_journal() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("events.jsonl");
        let far = warden_core::event::now_ms() * 1000 + 5_000_000_000;
        std::fs::write(&path, format!("{{\"id\":{},\"kind\":\"x\"}}\nnot json\n", far - 1)).unwrap();
        assert_eq!(last_id(&path), Some(far - 1));
        let cfg = EventLogConfig { path, ..Default::default() };
        let _log = EventLog::spawn(&cfg, Default::default(), Shared::new(warden_core::Config::default())).unwrap();
        assert!(Event::new("t", Severity::Info, "t").id >= far);
    }
}
