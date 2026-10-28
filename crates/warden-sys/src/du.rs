//! Bounded "who is using the disk" walk: `du -x --max-depth=N` with an entry
//! and time budget, counting allocated blocks (not apparent sizes) and each
//! hard-linked inode once.
//!
//! Used by the disk detector when a disk is critical or a cleanup could not
//! free space, and by `wardenctl du`. The walk never leaves the starting
//! filesystem and only `stat`s entries; file contents are not read. Its memory
//! is bounded whatever the tree looks like (see `MAX_SLOTS`, `MAX_LINKS`,
//! `MAX_OPEN_DIRS`): a few tens of MiB at the very most. The daemon's walks
//! are paced by I/O pressure ([`crate::pace`]); `wardenctl du` is not.

use crate::safefs;
use std::cmp::Reverse;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::ffi::OsStr;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct DuOptions {
    /// Aggregate directories down to this depth below the root (1–4).
    pub depth: usize,
    /// Entries per list in the report.
    pub top: usize,
    /// Stop after this many directory entries (partial report).
    pub max_entries: u64,
    /// Stop after this much wall time (partial report).
    pub max_time: Duration,
    /// Files at least this big are candidates for the "largest files" list.
    pub min_file: u64,
    /// Yield to the workload when the disk is busy ([`crate::pace`]).
    /// `max_time` then counts working time only, and the walk ends after
    /// at most [`PACED_WALL_FACTOR`] × `max_time` of wall time.
    pub pace: bool,
}

impl Default for DuOptions {
    fn default() -> Self {
        Self {
            depth: 2,
            top: 10,
            max_entries: 2_000_000,
            max_time: Duration::from_secs(120),
            min_file: 64 << 20,
            pace: false,
        }
    }
}

/// A paced walk may take this many times `max_time` of wall time.
pub const PACED_WALL_FACTOR: u32 = 4;
/// Lowest duty of a paced walk: at most 4× slower than unpaced (matches
/// [`PACED_WALL_FACTOR`]: a walk that fits its budget at full speed also
/// fits it at the floor).
const PACED_FLOOR: f64 = 0.25;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DuEntry {
    pub path: PathBuf,
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct DuReport {
    pub root: PathBuf,
    /// Allocated bytes found by the walk.
    pub total: u64,
    /// Bytes in regular files directly in the root directory.
    pub root_files: u64,
    /// `levels[0]` = biggest directories right below the root, `levels[1]`
    /// = one level deeper, and so on (each sorted, largest first).
    pub levels: Vec<Vec<DuEntry>>,
    pub largest_files: Vec<DuEntry>,
    pub entries: u64,
    /// Directories that could not be listed.
    pub errors: u64,
    /// Why the walk stopped early, if it did.
    pub partial: Option<&'static str>,
    #[serde(serialize_with = "ser_secs")]
    pub elapsed: Duration,
    /// Of `elapsed`, time spent pausing for the workload.
    #[serde(serialize_with = "ser_secs")]
    pub paced: Duration,
}

fn ser_secs<S: serde::Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_f64((d.as_secs_f64() * 10.0).round() / 10.0)
}

/// Hard cap on aggregated directories: beyond it, deeper directories are
/// still counted in their (already tracked) parents.
const MAX_SLOTS: usize = 100_000;
/// Hard cap on remembered hard-linked inodes (beyond it, further links are
/// counted again — an over-estimate, never an out-of-memory).
const MAX_LINKS: usize = 500_000;
/// Directories held open at once. The walk is depth-first over open
/// directory handles, so its memory is proportional to the nesting depth —
/// not, as with a stack of pending paths, to the *width* of the tree (a
/// mail spool or a cache with millions of sibling directories). Deeper
/// directories are skipped and the report is marked partial.
const MAX_OPEN_DIRS: usize = 64;
/// Aggregation levels (`DuOptions::depth` is clamped to this).
const MAX_DEPTH: usize = 4;

/// Aggregation slots of a directory and its ancestors, at most one per level.
#[derive(Clone, Copy, Default)]
struct Chain {
    slots: [u32; MAX_DEPTH],
    len: usize,
}

impl Chain {
    fn with(mut self, slot: usize) -> Self {
        self.slots[self.len] = slot as u32;
        self.len += 1;
        self
    }

    fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.slots[..self.len].iter().map(|&s| s as usize)
    }
}

struct Level {
    dir: safefs::DirStream,
    path: PathBuf,
    depth: usize,
    chain: Chain,
}

/// Walk `root` within its filesystem.
pub fn usage(root: &Path, opt: &DuOptions, cancel: Option<&AtomicBool>) -> std::io::Result<DuReport> {
    let started = Instant::now();
    // Over directory descriptors (`safefs`): a directory swapped for a
    // symlink mid-walk cannot make the report list files elsewhere.
    let rootfd = match safefs::open_root(root) {
        Ok((_, fd)) => fd,
        Err(e) if e.raw_os_error() == Some(libc::ENOTDIR) => {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "not a directory"));
        }
        Err(e) => return Err(e),
    };
    let dev = safefs::fstat(rootfd.as_fd())?.dev;
    let depth_max = opt.depth.clamp(1, MAX_DEPTH);
    let mut slots: Vec<(PathBuf, usize, u64)> = Vec::new(); // (path, depth, bytes)
    let mut links: HashSet<u64> = HashSet::new();
    let mut files: BinaryHeap<Reverse<(u64, PathBuf)>> = BinaryHeap::new();
    let mut rep = DuReport { root: root.to_path_buf(), ..Default::default() };
    let mut open = vec![Level {
        dir: safefs::DirStream::new(rootfd)?,
        path: root.to_path_buf(),
        depth: 0,
        chain: Chain::default(),
    }];
    let mut pace =
        if opt.pace { crate::pace::Pacer::new("du", PACED_FLOOR, true) } else { crate::pace::Pacer::off("du") };
    let wall_cap = opt.max_time.saturating_mul(PACED_WALL_FACTOR);
    'walk: loop {
        let nesting = open.len();
        let Some(top) = open.last_mut() else { break };
        let Some(name) = top.dir.next_name() else {
            open.pop();
            continue;
        };
        let (parent_depth, parent_chain) = (top.depth, top.chain);
        rep.entries += 1;
        pace.step();
        if rep.entries.is_multiple_of(4096) {
            if rep.entries >= opt.max_entries {
                rep.partial = Some("entry budget exhausted");
                break 'walk;
            }
            let worked = if pace.is_on() { pace.work_time() } else { started.elapsed() };
            if worked >= opt.max_time {
                rep.partial = Some("time budget exhausted");
                break 'walk;
            }
            if pace.is_on() && started.elapsed() >= wall_cap {
                rep.partial = Some("time budget exhausted (the disk was busy: the walk was paced)");
                break 'walk;
            }
            if cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                rep.partial = Some("cancelled");
                break 'walk;
            }
        }
        // `fstatat(AT_SYMLINK_NOFOLLOW)` relative to the open directory
        let Ok(md) = safefs::stat_at(top.dir.fd(), &name) else { continue };
        if md.dev != dev {
            continue; // a mount point: another filesystem
        }
        let path = top.path.join(OsStr::from_bytes(name.to_bytes()));
        let mut bytes = md.allocated;
        if !md.is_dir() && md.nlink > 1 {
            if links.contains(&md.ino) {
                bytes = 0; // another name of an inode already counted
            } else if links.len() < MAX_LINKS {
                links.insert(md.ino);
            }
        }
        rep.total += bytes;
        for s in parent_chain.iter() {
            slots[s].2 += bytes;
        }
        if md.is_dir() {
            let depth = parent_depth + 1;
            let mut chain = parent_chain;
            if depth <= depth_max && slots.len() < MAX_SLOTS {
                slots.push((path.clone(), depth, bytes));
                chain = chain.with(slots.len() - 1);
            }
            if nesting >= MAX_OPEN_DIRS {
                rep.partial.get_or_insert("directory nesting too deep");
                continue;
            }
            match safefs::open_subdir(top.dir.fd(), &name, &md).and_then(safefs::DirStream::new) {
                Ok(dir) => open.push(Level { dir, path, depth, chain }),
                Err(_) => rep.errors += 1,
            }
        } else if md.is_file() {
            if parent_depth == 0 {
                rep.root_files += bytes;
            }
            if bytes >= opt.min_file {
                files.push(Reverse((bytes, path)));
                if files.len() > opt.top {
                    files.pop();
                }
            }
        }
    }
    let mut by_depth: HashMap<usize, Vec<DuEntry>> = HashMap::new();
    for (path, depth, bytes) in slots {
        by_depth.entry(depth).or_default().push(DuEntry { path, bytes });
    }
    rep.levels = (1..=depth_max)
        .map(|d| {
            let mut v = by_depth.remove(&d).unwrap_or_default();
            v.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
            v.truncate(opt.top);
            v
        })
        .collect();
    let mut lf: Vec<DuEntry> = files.into_iter().map(|Reverse((bytes, path))| DuEntry { path, bytes }).collect();
    lf.sort_by(|a, b| b.bytes.cmp(&a.bytes).then_with(|| a.path.cmp(&b.path)));
    rep.largest_files = lf;
    rep.elapsed = started.elapsed();
    rep.paced = pace.paced();
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Fixture trees go to tmpfs (`/dev/shm`) when it has room. Without
    /// `fsync` the disk still costs: every `mkdir` and `create` on ext4
    /// joins the journal transaction that another writer's `fsync` is
    /// committing, and the 5 000-directory fixture took 90 s next to two
    /// writers (T1). The walk does not care which filesystem it walks.
    fn fixture() -> tempfile::TempDir {
        const TMPFS_MAGIC: i64 = 0x0102_1994;
        let shm = c"/dev/shm";
        // SAFETY: zeroed statfs is a valid out-parameter.
        let mut st: libc::statfs = unsafe { std::mem::zeroed() };
        // SAFETY: a NUL-terminated path and a valid out-pointer.
        let ok = unsafe { libc::statfs(shm.as_ptr(), &mut st) } == 0
            && st.f_type as i64 == TMPFS_MAGIC
            && (st.f_bavail as u64).saturating_mul(st.f_bsize as u64) >= 256 << 20;
        if ok && let Ok(d) = tempfile::tempdir_in("/dev/shm") {
            return d;
        }
        tempfile::tempdir().unwrap()
    }

    /// No `fsync`: the walk counts allocated blocks, which ext4, XFS, btrfs
    /// and tmpfs report for data still in the page cache (delayed
    /// allocation reserves them). With one `fsync` per file the 3 000-file
    /// fixtures took 13 minutes on a disk under load — 325 s for one test
    /// (T1 of the 0.14.2 review).
    fn write(p: &Path, n: usize) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        let mut f = std::fs::File::create(p).unwrap();
        f.write_all(&vec![0x5a; n]).unwrap();
    }

    #[test]
    fn aggregates_by_level_and_counts_hard_links_once() {
        let d = fixture();
        let r = d.path();
        write(&r.join("big/a/blob"), 3 << 20);
        write(&r.join("big/b/blob"), 1 << 20);
        write(&r.join("small/x"), 64 << 10);
        write(&r.join("top.bin"), 512 << 10);
        std::fs::hard_link(r.join("big/a/blob"), r.join("small/alias")).unwrap();
        let opt = DuOptions { min_file: 1 << 20, ..Default::default() };
        let rep = usage(r, &opt, None).unwrap();
        assert!(rep.partial.is_none());
        assert_eq!(rep.levels.len(), 2);
        let mut l1: Vec<_> = rep.levels[0].iter().map(|e| e.path.file_name().unwrap().to_str().unwrap()).collect();
        l1.sort_unstable();
        assert_eq!(l1, ["big", "small"]);
        // The 3 MiB inode has two names, one under big/ and one under small/,
        // and is counted under whichever the walk meets first: the two
        // directories together hold 3 + 1 MiB + 64 KiB once (7 MiB if it were
        // counted twice).
        let both: u64 = rep.levels[0].iter().map(|e| e.bytes).sum();
        assert!((4 << 20..4_600_000).contains(&both), "{both}");
        assert!(rep.levels[0][0].bytes >= 3 << 20, "the biggest directory holds the shared inode or the 1 MiB one");
        assert!(rep.root_files >= 512 << 10);
        assert_eq!(rep.largest_files.len(), 2);
        assert!(rep.largest_files[0].bytes >= 3 << 20);
        assert!(rep.total >= both + rep.root_files);
    }

    #[test]
    fn wide_trees_cost_no_memory_per_sibling_and_deep_ones_are_cut_off() {
        let d = fixture();
        // 3000 sibling directories, each with a file
        for i in 0..3000 {
            write(&d.path().join(format!("w{i:04}/f")), 4096);
        }
        let rep = usage(d.path(), &DuOptions { top: 5, ..Default::default() }, None).unwrap();
        assert!(rep.partial.is_none());
        assert_eq!(rep.levels[0].len(), 5);
        assert!(rep.total >= 3000 * 4096);
        // a chain deeper than the number of directories held open
        let mut deep = d.path().join("deep");
        for _ in 0..(MAX_OPEN_DIRS + 20) {
            deep.push("n");
        }
        write(&deep.join("leaf"), 4096);
        let rep = usage(d.path(), &DuOptions::default(), None).unwrap();
        assert_eq!(rep.partial, Some("directory nesting too deep"));
        assert!(rep.total >= 3000 * 4096, "the rest of the tree is still counted");
    }

    #[test]
    fn budgets_make_partial_reports() {
        let d = fixture();
        for i in 0..5000 {
            std::fs::create_dir_all(d.path().join(format!("d{}/{i}", i % 7))).unwrap();
        }
        let opt = DuOptions { max_entries: 4096, ..Default::default() };
        let rep = usage(d.path(), &opt, None).unwrap();
        assert_eq!(rep.partial, Some("entry budget exhausted"));
        let stop = AtomicBool::new(true);
        let rep = usage(d.path(), &DuOptions::default(), Some(&stop)).unwrap();
        assert_eq!(rep.partial, Some("cancelled"));
        assert!(rep.paced.is_zero(), "an unpaced walk never pauses");
        assert!(usage(&d.path().join("d0/0/none"), &DuOptions::default(), None).is_err());
    }

    #[test]
    fn a_paced_walk_finds_the_same() {
        let d = fixture();
        for i in 0..300 {
            write(&d.path().join(format!("d{}/f{i}", i % 3)), 4096);
        }
        let plain = usage(d.path(), &DuOptions::default(), None).unwrap();
        let paced = usage(d.path(), &DuOptions { pace: true, ..Default::default() }, None).unwrap();
        assert_eq!(paced.total, plain.total);
        assert_eq!(paced.levels, plain.levels);
        assert!(paced.partial.is_none());
        // at least the measuring pause before the first quantum
        assert!(paced.paced >= Duration::from_millis(40), "{:?}", paced.paced);
        assert!(crate::pace::stats().get("du").is_some_and(|s| s.runs >= 1 && !s.active));
    }
}
