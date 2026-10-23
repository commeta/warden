//! FIM baselines and the site walker.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use warden_core::GlobList;
use warden_core::config::FimSite;
use warden_sys::util::write_atomic;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRecord {
    pub size: u64,
    pub mtime: i64,
    pub ctime: i64,
    pub ino: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub hash: Digest,
}

/// BLAKE3 digest, stored as hex in baselines (and compatible with the
/// hex-string format of earlier versions). 32 bytes inline instead of a
/// 64-character heap string per file.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct Digest(pub [u8; 32]);

impl std::fmt::Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
        Digest::from_hex(&s).ok_or_else(|| serde::de::Error::custom("bad digest"))
    }
}

impl Digest {
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok()?;
        }
        Some(Self(out))
    }
}

impl FileRecord {
    pub fn from_meta(md: &std::fs::Metadata, hash: Digest) -> Self {
        Self {
            size: md.size(),
            mtime: md.mtime(),
            ctime: md.ctime(),
            ino: md.ino(),
            mode: md.mode(),
            uid: md.uid(),
            gid: md.gid(),
            hash,
        }
    }

    /// Cheap change check. `ctime` cannot be forged from userspace (touch
    /// -d resets mtime, not ctime), so timestomping does not hide changes.
    pub fn same_meta(&self, md: &std::fs::Metadata) -> bool {
        self.size == md.size() && self.mtime == md.mtime() && self.ctime == md.ctime() && self.ino == md.ino()
    }
}

/// Metadata of a non-script file already checked for embedded server code
/// (uploads): re-read only when it changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaStamp {
    pub size: u64,
    pub mtime: i64,
    pub ctime: i64,
    pub ino: u64,
}

impl MetaStamp {
    pub fn of(md: &std::fs::Metadata) -> Self {
        Self { size: md.size(), mtime: md.mtime(), ctime: md.ctime(), ino: md.ino() }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub site: String,
    pub root: String,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub files: BTreeMap<String, FileRecord>,
    /// Paths already reported as malicious (not re-reported until changed).
    #[serde(default)]
    pub flagged: BTreeSet<String>,
    #[serde(default)]
    pub last_scan_ms: u64,
    /// Upload-directory files already checked for polyglot content.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub uploads: BTreeMap<String, MetaStamp>,
}

impl Baseline {
    pub fn load(path: &Path) -> Option<Self> {
        let data = std::fs::read(path).ok()?;
        serde_json::from_slice(&data).ok()
    }

    pub fn save(&mut self, path: &Path) -> std::io::Result<()> {
        self.updated_ms = warden_core::event::now_ms();
        write_atomic(path, &serde_json::to_vec(self)?)
    }
}

/// Hashes files with a reusable buffer and keeps the first `max` bytes of
/// the current file for signature scanning. Files that were not in the page
/// cache before are evicted after reading (see `warden_sys::pagecache`).
pub struct FileHasher {
    chunk: Box<[u8]>,
    head: Vec<u8>,
}

impl Default for FileHasher {
    fn default() -> Self {
        Self { chunk: vec![0u8; 64 * 1024].into_boxed_slice(), head: Vec::new() }
    }
}

impl FileHasher {
    pub fn hash(&mut self, path: &Path, max: u64) -> std::io::Result<Digest> {
        let f = std::fs::File::open(path)?;
        let _cold = warden_sys::pagecache::ColdRead::new(&f);
        // One huge file must not keep its buffer for the rest of the scan.
        if self.head.capacity() > 4 << 20 {
            self.head = Vec::new();
        }
        self.head.clear();
        let mut h = blake3::Hasher::new();
        let mut total = 0u64;
        loop {
            let n = (&f).read(&mut self.chunk)?;
            if n == 0 {
                break;
            }
            h.update(&self.chunk[..n]);
            if total < max {
                let take = ((max - total) as usize).min(n);
                self.head.extend_from_slice(&self.chunk[..take]);
            }
            total += n as u64;
        }
        Ok(Digest(*h.finalize().as_bytes()))
    }

    /// The first `max` bytes of the file hashed last.
    pub fn head(&self) -> &[u8] {
        &self.head
    }
}

/// One-shot convenience wrapper: `(digest, head)`.
pub fn hash_file(path: &Path, max: u64) -> std::io::Result<(Digest, Vec<u8>)> {
    let mut h = FileHasher::default();
    let d = h.hash(path, max)?;
    Ok((d, std::mem::take(&mut h.head)))
}

/// Compiled site matching rules.
#[derive(Debug)]
pub struct SiteMatcher {
    pub name: String,
    pub root: PathBuf,
    include: GlobList,
    exclude: GlobList,
    no_scripts: GlobList,
    sig_exclude: GlobList,
}

impl SiteMatcher {
    pub fn new(s: &FimSite) -> Self {
        Self {
            name: s.name.clone(),
            root: s.root.clone(),
            include: GlobList::new(&s.include),
            exclude: GlobList::new(&s.exclude),
            no_scripts: GlobList::new(&s.no_scripts),
            sig_exclude: GlobList::new(&s.signature_exclude),
        }
    }

    pub fn rel(&self, abs: &Path) -> Option<String> {
        abs.strip_prefix(&self.root).ok().map(|p| p.to_string_lossy().into_owned()).filter(|s| !s.is_empty())
    }

    pub fn wants(&self, rel: &str) -> bool {
        self.include.is_match(rel) && !self.exclude.is_match(rel)
    }

    pub fn in_no_scripts(&self, rel: &str) -> bool {
        self.no_scripts.is_match(rel)
    }

    pub fn signatures_apply(&self, rel: &str) -> bool {
        !self.sig_exclude.is_match(rel)
    }

    /// Prune whole directories excluded by `dir/**`-style patterns.
    pub fn prune(&self, rel_dir: &str) -> bool {
        self.exclude.is_match(format!("{rel_dir}/.warden-probe"))
    }
}

/// Walk a site (no symlink following), calling `f(rel, abs, metadata)` for
/// every regular file. Throttled to `max_per_sec` files per second.
pub fn walk(site: &SiteMatcher, max_per_sec: u32, f: impl FnMut(&str, &Path, &std::fs::Metadata)) -> usize {
    walk_paced(site, max_per_sec, &mut warden_sys::pace::Pacer::off("fim"), f)
}

/// [`walk`], yielding to the workload when the disk is busy.
pub fn walk_paced(
    site: &SiteMatcher,
    max_per_sec: u32,
    pace: &mut warden_sys::pace::Pacer,
    mut f: impl FnMut(&str, &Path, &std::fs::Metadata),
) -> usize {
    let mut n = 0usize;
    let mut window = Instant::now();
    let mut in_window = 0u32;
    let mut stack = vec![site.root.clone()];
    while let Some(dir) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&dir) else { continue };
        for e in rd.filter_map(Result::ok) {
            let p = e.path();
            pace.step();
            let Ok(md) = std::fs::symlink_metadata(&p) else { continue };
            let Some(rel) = site.rel(&p) else { continue };
            if md.is_dir() {
                if !site.prune(&rel) {
                    stack.push(p);
                }
                continue;
            }
            if !md.is_file() {
                continue;
            }
            n += 1;
            f(&rel, &p, &md);
            if max_per_sec > 0 {
                in_window += 1;
                if in_window >= max_per_sec {
                    let el = window.elapsed();
                    if el < Duration::from_secs(1) {
                        std::thread::sleep(Duration::from_secs(1) - el);
                        pace.exclude(Duration::from_secs(1) - el); // the rate limit, not work
                    }
                    window = Instant::now();
                    in_window = 0;
                }
            }
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site(root: &Path) -> SiteMatcher {
        SiteMatcher::new(&FimSite {
            name: "t".into(),
            root: root.to_path_buf(),
            include: warden_core::config::default_fim_include(),
            exclude: warden_core::config::default_fim_exclude(),
            no_scripts: warden_core::config::default_no_scripts(),
            signature_exclude: warden_core::config::default_signature_exclude(),
            access_log: None,
            quarantine: None,
            restart_unit: None,
        })
    }

    #[test]
    fn walker_respects_include_exclude_and_prunes() {
        let d = tempfile::tempdir().unwrap();
        let r = d.path();
        std::fs::create_dir_all(r.join(".git/objects")).unwrap();
        std::fs::create_dir_all(r.join("wp-content/uploads/2026")).unwrap();
        std::fs::write(r.join("index.php"), "<?php").unwrap();
        std::fs::write(r.join(".git/objects/x.php"), "x").unwrap();
        std::fs::write(r.join("wp-content/uploads/2026/a.jpg"), "x").unwrap();
        std::fs::write(r.join("wp-content/uploads/2026/s.php"), "x").unwrap();
        let s = site(r);
        let mut seen = Vec::new();
        walk(&s, 0, |rel, _, _| seen.push(rel.to_owned()));
        seen.sort();
        assert!(!seen.iter().any(|p| p.starts_with(".git")));
        assert!(s.wants("index.php"));
        assert!(!s.wants("wp-content/uploads/2026/a.jpg"));
        assert!(s.in_no_scripts("wp-content/uploads/2026/s.php"));
        assert!(!s.signatures_apply("assets/app.min.js"));
    }

    #[test]
    fn baseline_roundtrip_and_meta() {
        let d = tempfile::tempdir().unwrap();
        let f = d.path().join("a.php");
        std::fs::write(&f, "<?php echo 1;").unwrap();
        let (h, head) = hash_file(&f, 4).unwrap();
        assert_eq!(head, b"<?ph");
        let md = std::fs::metadata(&f).unwrap();
        let rec = FileRecord::from_meta(&md, h);
        assert!(rec.same_meta(&md));
        assert_eq!(Digest::from_hex(&rec.hash.to_string()), Some(rec.hash));
        let mut b = Baseline { site: "t".into(), ..Default::default() };
        b.files.insert("a.php".into(), rec.clone());
        let p = d.path().join("state/b.json");
        b.save(&p).unwrap();
        assert_eq!(Baseline::load(&p).unwrap().files["a.php"], rec);
        std::fs::write(&f, "<?php echo 2;").unwrap();
        assert!(!rec.same_meta(&std::fs::metadata(&f).unwrap()) || rec.hash != hash_file(&f, 0).unwrap().0);
    }
}
