//! Disk-space reclamation playbook steps.

use crate::guard::{check_cleanup_path, normalize};
use std::collections::HashSet;
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use warden_core::GlobList;
use warden_core::action::AgeFrom;
use warden_core::glob::glob_roots;
use warden_core::units::human_bytes;
use warden_sys::cmd::{run_cmd, which};
use warden_sys::process;
use warden_sys::safefs::{self, Visit, WalkEntry, WalkOptions};

/// Result of one step: (bytes freed, files touched, human message).
pub type Outcome = Result<(u64, usize, String), String>;

/// Programs whose deleted-but-open files are never truncated: databases
/// use unlinked temp files on purpose.
const NEVER_TRUNCATE_FOR: &[&str] = &[
    "mysqld",
    "mariadbd",
    "postgres",
    "mongod",
    "redis-server",
    "clickhouse-serv",
    "clickhouse",
    "etcd",
    "influxd",
    "elasticsearch",
    "java",
];

/// Bounds of one cleanup step's walk: a `/tmp` with millions of files must
/// not hold the responder (it runs actions one at a time) for long.
const WALK_MAX_ENTRIES: u64 = 2_000_000;
const WALK_MAX_TIME: Duration = Duration::from_secs(120);
const WALK_MAX_DEPTH: usize = 10;

#[derive(Default)]
struct Scan {
    /// A budget ended the walk before every matching file was seen.
    cut: bool,
    /// Entries that could not be examined.
    errors: u64,
}

/// Visit the regular files that match `globs` and not `exclude` (a matching
/// directory is not entered), on device `dev` if given.
///
/// The walk runs over directory descriptors ([`safefs::walk`]): no symlink
/// below a root is followed, so a user who owns a directory under `/tmp`
/// cannot redirect a deletion by swapping it for a symlink mid-walk. Act on
/// an entry only through its descriptor (`safefs::unlink_if_same`); decide
/// policy on [`WalkEntry::real`], the location the descriptor refers to.
fn for_each_match(
    globs: &[String],
    exclude: &[String],
    dev: Option<u64>,
    mut f: impl FnMut(&WalkEntry<'_>) -> Visit,
) -> Scan {
    let gl = GlobList::new(globs);
    let ex = GlobList::new(exclude);
    let opt = WalkOptions {
        max_depth: WALK_MAX_DEPTH,
        one_filesystem: true,
        max_entries: WALK_MAX_ENTRIES,
        deadline: Some(Instant::now() + WALK_MAX_TIME),
    };
    let all = glob_roots(globs);
    // a root inside another root is walked with it
    let roots = all.iter().filter(|r| !all.iter().any(|o| o != *r && r.starts_with(o)));
    let mut scan = Scan::default();
    let mut stopped = false;
    for root in roots {
        let r = safefs::walk(root, &opt, |e| {
            if dev.is_some_and(|d| e.stat.dev != d) || ex.is_match(e.path) {
                return Visit::Skip;
            }
            if !e.stat.is_file() || !gl.is_match(e.path) {
                return Visit::Continue;
            }
            let v = f(e);
            stopped |= v == Visit::Stop;
            v
        });
        match r {
            Ok(s) => {
                scan.cut |= s.cut;
                scan.errors += s.errors;
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => scan.errors += 1,
        }
        if stopped {
            break;
        }
    }
    scan
}

/// The tail of a cleanup message: what was left alone and why.
fn notes(refused: usize, changed: usize, scan: &Scan) -> String {
    let mut s = String::new();
    if refused > 0 {
        s += &format!(", {refused} refused by safety rules");
    }
    if changed > 0 {
        s += &format!(", {changed} changed during the scan and left alone");
    }
    if scan.cut {
        s += &format!(
            "; the scan was cut short by its budget ({} entries / {}s)",
            WALK_MAX_ENTRIES,
            WALK_MAX_TIME.as_secs()
        );
    }
    s
}

/// The timestamp a file is aged by.
fn age_of(st: &safefs::Stat, a: AgeFrom) -> i64 {
    match a {
        AgeFrom::Mtime => st.mtime,
        AgeFrom::Newest => st.newest_time(),
    }
}

fn unix_now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

pub fn journal_vacuum(max_size: Option<u64>, max_age: Option<Duration>) -> Outcome {
    if which("journalctl").is_none() {
        return Err("journalctl not found".into());
    }
    let mut args: Vec<String> = Vec::new();
    if let Some(s) = max_size {
        args.push(format!("--vacuum-size={}M", (s / (1 << 20)).max(16)));
    }
    if let Some(a) = max_age {
        args.push(format!("--vacuum-time={}s", a.as_secs().max(3600)));
    }
    if args.is_empty() {
        args.push("--vacuum-size=512M".into());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let o = run_cmd("journalctl", &refs, Duration::from_secs(120)).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&o.stderr).to_string() + &String::from_utf8_lossy(&o.stdout);
    if !o.status.success() {
        return Err(format!("journalctl failed: {}", text.trim()));
    }
    let freed_line = text.lines().rev().find(|l| l.contains("freed")).unwrap_or("").trim().to_owned();
    Ok((0, 0, if freed_line.is_empty() { "journal vacuumed".into() } else { freed_line }))
}

/// Delete the regular files matching `globs` that are older than
/// `older_than` by `age_from`, at most `max_files` of them.
pub fn delete_old(
    globs: &[String],
    older_than: Duration,
    max_files: Option<usize>,
    dev: Option<u64>,
    age_from: AgeFrom,
    exclude: &[String],
) -> Outcome {
    let cutoff = unix_now().saturating_sub(i64::try_from(older_than.as_secs()).map_err(|_| "bad cutoff")?);
    let limit = max_files.unwrap_or(10_000);
    let (mut freed, mut n, mut refused, mut changed) = (0u64, 0usize, 0usize, 0usize);
    let scan = for_each_match(globs, exclude, dev, |e| {
        if age_of(e.stat, age_from) > cutoff {
            return Visit::Continue;
        }
        if check_cleanup_path(e.real).is_err() {
            refused += 1;
            return Visit::Continue;
        }
        match safefs::unlink_if_same(e.dir, e.name, e.stat) {
            Ok(()) => {
                // another name keeps the blocks
                if e.stat.nlink == 1 {
                    freed += e.stat.allocated;
                }
                n += 1;
            }
            Err(_) => changed += 1,
        }
        if n >= limit { Visit::Stop } else { Visit::Continue }
    });
    Ok((freed, n, format!("deleted {n} file(s), freed {}{}", human_bytes(freed), notes(refused, changed, &scan))))
}

/// Truncate (copytruncate-style) the regular files matching `globs` that
/// are larger than `larger_than`. A file with other hard links is refused.
pub fn truncate_large(globs: &[String], larger_than: u64, dev: Option<u64>) -> Outcome {
    let (mut freed, mut n, mut refused, mut changed) = (0u64, 0usize, 0usize, 0usize);
    let mut names = Vec::new();
    let scan = for_each_match(globs, &[], dev, |e| {
        if e.stat.size <= larger_than {
            return Visit::Continue;
        }
        if check_cleanup_path(e.real).is_err() {
            refused += 1;
            return Visit::Continue;
        }
        // copytruncate semantics: writers keep their descriptor; with
        // O_APPEND they continue at the new end of file.
        match safefs::truncate_if_same(e.dir, e.name, e.stat) {
            Ok(b) => {
                freed += b;
                n += 1;
                names.push(format!("{} ({})", e.real.display(), human_bytes(e.stat.size)));
            }
            Err(_) => changed += 1,
        }
        if n >= 10_000 { Visit::Stop } else { Visit::Continue }
    });
    let list = if names.is_empty() { String::new() } else { format!(": {}", names.join(", ")) };
    Ok((
        freed,
        n,
        format!("truncated {n} file(s), freed {}{list}{}", human_bytes(freed), notes(refused, changed, &scan)),
    ))
}

/// Truncate log-like files that were deleted while still open.
pub fn truncate_deleted(min_size: u64, dev: Option<u64>) -> Outcome {
    let mut freed = 0u64;
    let mut n = 0usize;
    let mut done: HashSet<(u64, u64)> = HashSet::new();
    let mut names = Vec::new();
    for (pid, fd, target, size) in process::deleted_open_files(min_size, dev) {
        let path = target.trim_end_matches(" (deleted)");
        let logish = path.starts_with("/var/log/")
            || [".log", ".out", ".err", ".txt", ".json"].iter().any(|e| path.ends_with(e))
            || path.contains("/log/")
            || path.contains("/logs/");
        // the kernel's record of where the file was: already canonical, and
        // its parent may be gone or replaced, so nothing is resolved
        if !logish || check_cleanup_path(&normalize(Path::new(path))).is_err() {
            continue;
        }
        let comm = process::read_stat(pid).map(|s| s.comm).unwrap_or_default();
        if NEVER_TRUNCATE_FOR.iter().any(|c| comm.starts_with(c)) {
            continue;
        }
        // The descriptor may have been closed and its number reused since
        // the listing: act only on what was opened, if it still is a
        // deleted regular file.
        let fdp = format!("/proc/{pid}/fd/{fd}");
        let Ok(f) = std::fs::OpenOptions::new().write(true).custom_flags(libc::O_NONBLOCK).open(&fdp) else {
            continue;
        };
        let Ok(md) = f.metadata() else { continue };
        if !md.is_file() || md.nlink() != 0 || dev.is_some_and(|d| md.dev() != d) {
            continue;
        }
        if !done.insert((md.dev(), md.ino())) {
            continue;
        }
        if f.set_len(0).is_ok() {
            freed += md.blocks() * 512;
            n += 1;
            names.push(format!("{path} held by {comm}[{pid}] ({})", human_bytes(size)));
        }
    }
    Ok((
        freed,
        n,
        if n == 0 {
            "no deleted-but-open log files found".into()
        } else {
            format!("released {}: {}", human_bytes(freed), names.join("; "))
        },
    ))
}

pub fn apt_clean() -> Outcome {
    let (prog, args): (&str, &[&str]) = if which("apt-get").is_some() {
        ("apt-get", &["clean"])
    } else if which("dnf").is_some() {
        ("dnf", &["clean", "packages"])
    } else if which("yum").is_some() {
        ("yum", &["clean", "packages"])
    } else if which("zypper").is_some() {
        ("zypper", &["clean", "--all"])
    } else {
        return Err("no supported package manager found".into());
    };
    let o = run_cmd(prog, args, Duration::from_secs(300)).map_err(|e| e.to_string())?;
    if o.status.success() {
        Ok((0, 0, format!("{prog} {} done", args.join(" "))))
    } else {
        Err(String::from_utf8_lossy(&o.stderr).trim().to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_and_truncate_in_tmp() {
        let d = tempfile::Builder::new().prefix("warden-cleanup").tempdir_in("/var/tmp").unwrap();
        let old = d.path().join("app.log.1.gz");
        let big = d.path().join("app.log");
        std::fs::write(&old, vec![1u8; 10_000]).unwrap();
        std::fs::write(&big, vec![1u8; 50_000]).unwrap();
        // make `old` two days old
        let t = SystemTime::now() - Duration::from_secs(2 * 86400);
        std::fs::File::options().write(true).open(&old).unwrap().set_modified(t).unwrap();

        let g = vec![format!("{}/*.gz", d.path().display())];
        let (_, n, _) = delete_old(&g, Duration::from_secs(86400), None, None, AgeFrom::Mtime, &[]).unwrap();
        assert_eq!(n, 1);
        assert!(!old.exists());

        let g = vec![format!("{}/*.log", d.path().display())];
        let (freed, n, msg) = truncate_large(&g, 1000, None).unwrap();
        assert_eq!(n, 1, "{msg}");
        assert!(freed > 0);
        assert_eq!(std::fs::metadata(&big).unwrap().len(), 0);
    }

    #[test]
    fn deleted_open_file_is_released() {
        use std::io::Write;
        let d = tempfile::Builder::new().prefix("warden-del").tempdir_in("/var/tmp").unwrap();
        let p = d.path().join("held.log");
        let mut f = std::fs::File::create(&p).unwrap();
        f.write_all(&vec![7u8; 3 << 20]).unwrap();
        f.sync_all().unwrap();
        std::fs::remove_file(&p).unwrap();
        let (freed, n, msg) = truncate_deleted(1 << 20, None).unwrap();
        assert!(n >= 1, "{msg}");
        assert!(freed >= 3 << 20);
        assert_eq!(f.metadata().unwrap().len(), 0);
    }

    #[test]
    fn refuses_system_paths() {
        let (_, n, _) =
            delete_old(&["/etc/*.conf".to_string()], Duration::from_secs(1), Some(5), None, AgeFrom::Mtime, &[])
                .unwrap();
        assert_eq!(n, 0);
    }

    fn try_age(p: &Path, days: u64) -> std::io::Result<()> {
        let t = SystemTime::now() - Duration::from_secs(days * 86400);
        std::fs::File::options()
            .write(true)
            .open(p)?
            .set_times(std::fs::FileTimes::new().set_modified(t).set_accessed(t))
    }

    fn age(p: &Path, days: u64) {
        try_age(p, days).unwrap();
    }

    fn tmp(prefix: &str) -> tempfile::TempDir {
        tempfile::Builder::new().prefix(prefix).tempdir_in("/var/tmp").unwrap()
    }

    /// A symlinked directory below the glob root is never entered (0.13.3
    /// skipped one found by `lstat`, but a swap after the check redirected
    /// its `read_dir` and `remove_file`; see the race test below).
    #[test]
    fn delete_old_does_not_follow_a_symlinked_directory() {
        let (d, victim) = (tmp("warden-sym"), tmp("warden-victim"));
        std::fs::write(victim.path().join("data"), "precious").unwrap();
        age(&victim.path().join("data"), 30);
        std::os::unix::fs::symlink(victim.path(), d.path().join("link")).unwrap();
        let g = vec![format!("{}/**", d.path().display())];
        let (_, n, msg) = delete_old(&g, Duration::from_secs(86400), None, None, AgeFrom::Mtime, &[]).unwrap();
        assert_eq!(n, 0, "{msg}");
        assert!(victim.path().join("data").exists());
    }

    /// A symlink is never truncated through, and neither is a second hard
    /// link (0.13.3 opened the matched path for writing: a symlink swapped in
    /// after its `lstat`, or a hard link, let it truncate any file).
    #[test]
    fn truncate_large_does_not_follow_a_symlinked_file() {
        let (d, victim) = (tmp("warden-trunc"), tmp("warden-victim"));
        let target = victim.path().join("big.db");
        std::fs::write(&target, vec![1u8; 50_000]).unwrap();
        std::os::unix::fs::symlink(&target, d.path().join("app.log")).unwrap();
        let g = vec![format!("{}/*.log", d.path().display())];
        let (_, n, msg) = truncate_large(&g, 1000, None).unwrap();
        assert_eq!(n, 0, "{msg}");
        assert_eq!(std::fs::metadata(&target).unwrap().len(), 50_000);
        // a hard link to someone else's file is not truncated either
        std::fs::remove_file(d.path().join("app.log")).unwrap();
        std::fs::hard_link(&target, d.path().join("app.log")).unwrap();
        let (_, n, msg) = truncate_large(&g, 1000, None).unwrap();
        assert_eq!(n, 0, "{msg}");
        assert_eq!(std::fs::metadata(&target).unwrap().len(), 50_000);
    }

    /// A directory under the cleaned tree is swapped for a symlink to a
    /// victim directory, over and over, while `delete_old` runs; the victim
    /// files have the attacker's names. (0.13.3 lost a third of them.)
    #[test]
    fn delete_old_survives_a_directory_symlink_swap_race() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let (d, victim) = (tmp("warden-race"), tmp("warden-victim"));
        for i in 0..100 {
            let p = victim.path().join(format!("a{i}"));
            std::fs::write(&p, "victim").unwrap();
            age(&p, 30);
        }
        let stop = Arc::new(AtomicBool::new(false));
        let (t, v, s) = (d.path().to_path_buf(), victim.path().to_path_buf(), stop.clone());
        let flipper = std::thread::spawn(move || {
            let (x, parked) = (t.join("x"), t.join("parked"));
            while !s.load(Ordering::Relaxed) {
                let _ = std::fs::create_dir(&x);
                for i in 0..100 {
                    let p = x.join(format!("a{i}"));
                    if std::fs::write(&p, "attacker").is_ok() {
                        let _ = try_age(&p, 30);
                    }
                }
                let _ = std::fs::remove_dir_all(&parked);
                let _ = std::fs::rename(&x, &parked);
                let _ = std::os::unix::fs::symlink(&v, &x);
                std::thread::yield_now();
                let _ = std::fs::remove_file(&x);
            }
        });
        let g = vec![format!("{}/**", d.path().display())];
        let (mut total, started) = (0, Instant::now());
        while total < 1_000 && started.elapsed() < Duration::from_secs(5) {
            total += delete_old(&g, Duration::from_secs(86400), None, None, AgeFrom::Mtime, &[]).unwrap().1;
        }
        stop.store(true, Ordering::Relaxed);
        flipper.join().unwrap();
        assert!(total > 0, "the race was not exercised");
        assert_eq!(std::fs::read_dir(victim.path()).unwrap().count(), 100, "a victim file was deleted");
    }

    /// The log file is swapped for a symlink to a victim file, over and
    /// over, while `truncate_large` runs. (0.13.3 truncated the victim.)
    #[test]
    fn truncate_large_survives_a_file_symlink_swap_race() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let (d, victim) = (tmp("warden-trace"), tmp("warden-victim"));
        let target = victim.path().join("big.db");
        std::fs::write(&target, vec![1u8; 50_000]).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let (t, v, s) = (d.path().to_path_buf(), target.clone(), stop.clone());
        let flipper = std::thread::spawn(move || {
            let x = t.join("x.log");
            while !s.load(Ordering::Relaxed) {
                let _ = std::fs::write(&x, vec![2u8; 50_000]);
                std::thread::yield_now();
                let _ = std::fs::remove_file(&x);
                let _ = std::os::unix::fs::symlink(&v, &x);
                std::thread::yield_now();
                let _ = std::fs::remove_file(&x);
            }
        });
        let g = vec![format!("{}/*.log", d.path().display())];
        let (mut total, started) = (0, Instant::now());
        while total < 200 && started.elapsed() < Duration::from_secs(5) {
            total += truncate_large(&g, 1000, None).unwrap().1;
        }
        stop.store(true, Ordering::Relaxed);
        flipper.join().unwrap();
        assert!(total > 0, "the race was not exercised");
        assert_eq!(std::fs::metadata(&target).unwrap().len(), 50_000, "the victim file was truncated");
    }

    #[test]
    fn age_from_newest_keeps_a_file_that_is_still_read() {
        let day = 86400;
        let st = safefs::Stat {
            dev: 1,
            ino: 1,
            mode: libc::S_IFREG | 0o644,
            nlink: 1,
            uid: 0,
            gid: 0,
            size: 1,
            allocated: 4096,
            atime: 100 * day,
            mtime: 10 * day,
            ctime: 10 * day,
        };
        assert_eq!(age_of(&st, AgeFrom::Mtime), 10 * day);
        assert_eq!(age_of(&st, AgeFrom::Newest), 100 * day);
        // `touch -d` sets an old mtime and atime, but ctime becomes *now*
        let touched = safefs::Stat { atime: 0, mtime: 0, ctime: 100 * day, ..st };
        assert_eq!(age_of(&touched, AgeFrom::Newest), 100 * day);
    }

    #[test]
    fn tmp_semantics_newest_time_and_exclusions() {
        let d = tmp("warden-tmpfiles");
        let base = d.path();
        let stale = base.join("stale");
        let read = base.join("still-read");
        std::fs::write(&stale, "x").unwrap();
        std::fs::write(&read, "x").unwrap();
        age(&stale, 30);
        // old content, but read today (atime now): systemd-tmpfiles keeps it
        let t = SystemTime::now() - Duration::from_secs(30 * 86400);
        std::fs::File::options()
            .write(true)
            .open(&read)
            .unwrap()
            .set_times(std::fs::FileTimes::new().set_modified(t).set_accessed(SystemTime::now()))
            .unwrap();
        let private = base.join("systemd-private-abc-nginx.service-x");
        std::fs::create_dir(&private).unwrap();
        std::fs::write(private.join("f"), "x").unwrap();
        age(&private.join("f"), 30);
        let lock = base.join(".X0-lock");
        std::fs::write(&lock, "x").unwrap();
        age(&lock, 30);

        let g = vec![format!("{}/**", base.display())];
        let ex = vec![format!("{}/systemd-private-*", base.display()), format!("{}/.X*-lock", base.display())];
        let (_, n, msg) = delete_old(&g, Duration::from_secs(10 * 86400), None, None, AgeFrom::Newest, &ex).unwrap();
        // `age()` itself changed ctime to now: under `newest` nothing is old yet
        assert_eq!(n, 0, "{msg}");
        // mtime semantics: everything old except the excluded ones goes
        let (_, n, msg) = delete_old(&g, Duration::from_secs(10 * 86400), None, None, AgeFrom::Mtime, &ex).unwrap();
        assert_eq!(n, 2, "{msg}");
        assert!(!stale.exists() && !read.exists());
        assert!(private.join("f").exists() && lock.exists());
    }

    #[test]
    fn delete_old_stops_at_max_files() {
        let d = tmp("warden-max");
        for i in 0..10 {
            let p = d.path().join(format!("f{i}"));
            std::fs::write(&p, "x").unwrap();
            age(&p, 30);
        }
        let g = vec![format!("{}/*", d.path().display())];
        let (_, n, _) = delete_old(&g, Duration::from_secs(86400), Some(3), None, AgeFrom::Mtime, &[]).unwrap();
        assert_eq!(n, 3);
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 7);
    }
}
