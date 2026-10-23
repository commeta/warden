//! Per-process information from `/proc/<pid>`.
//!
//! All readers tolerate the process disappearing at any moment (ENOENT /
//! ESRCH are normal) and never panic on odd content: `comm` can contain
//! spaces and parentheses, `exe` can be `(deleted)` or `/memfd:...`.

use crate::util::{parse_kb_value, parse_kv_line, read_string};
use std::collections::HashMap;
use std::io;
use std::path::PathBuf;

/// Selected fields of `/proc/<pid>/stat`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Stat {
    pub pid: i32,
    pub comm: String,
    pub state: char,
    pub ppid: i32,
    pub pgrp: i32,
    pub session: i32,
    pub tty_nr: i32,
    pub minflt: u64,
    pub majflt: u64,
    /// User + system CPU time in clock ticks.
    pub utime: u64,
    pub stime: u64,
    pub nice: i64,
    pub num_threads: u64,
    /// Start time in clock ticks after boot — the process identity.
    pub starttime: u64,
    pub vsize: u64,
    pub rss_pages: u64,
}

pub fn parse_stat(content: &str) -> Option<Stat> {
    let open = content.find('(')?;
    let close = content.rfind(')')?;
    if close < open {
        return None;
    }
    let pid = content[..open].trim().parse().ok()?;
    let comm = content[open + 1..close].to_owned();
    let rest: Vec<&str> = content[close + 1..].split_whitespace().collect();
    // rest[i] is field (i + 3) in proc(5) numbering.
    let f = |i: usize| rest.get(i).copied();
    let num = |i: usize| -> Option<u64> { f(i)?.parse().ok() };
    let int = |i: usize| -> Option<i64> { f(i)?.parse().ok() };
    Some(Stat {
        pid,
        comm,
        state: f(0)?.chars().next()?,
        ppid: int(1)? as i32,
        pgrp: int(2)? as i32,
        session: int(3)? as i32,
        tty_nr: int(4)? as i32,
        minflt: num(7)?,
        majflt: num(9)?,
        utime: num(11)?,
        stime: num(12)?,
        nice: int(16)?,
        num_threads: num(17)?,
        starttime: num(19)?,
        vsize: num(20)?,
        rss_pages: num(21)?,
    })
}

/// Selected fields of `/proc/<pid>/status`.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct Status {
    pub name: String,
    pub ppid: i32,
    /// Real, effective, saved, filesystem.
    pub uid: [u32; 4],
    pub gid: [u32; 4],
    pub tracer_pid: i32,
    pub vm_rss: u64,
    /// Anonymous part of the RSS (`RssAnon`, Linux 4.5+): what killing the
    /// process frees. File-backed pages are reclaimable anyway and shared
    /// memory (`RssShmem`) outlives the process.
    pub rss_anon: Option<u64>,
    pub rss_shmem: u64,
    pub vm_swap: u64,
    pub vm_hwm: u64,
    pub threads: u64,
    pub cap_eff: u64,
    pub no_new_privs: bool,
    pub seccomp: u8,
}

pub fn parse_status(content: &str) -> Status {
    let mut s = Status::default();
    let ids = |v: &str| -> [u32; 4] {
        let mut out = [0u32; 4];
        for (i, x) in v.split_whitespace().take(4).enumerate() {
            out[i] = x.parse().unwrap_or(0);
        }
        out
    };
    for line in content.lines() {
        let Some((k, v)) = parse_kv_line(line) else { continue };
        match k {
            "Name" => s.name = v.to_owned(),
            "PPid" => s.ppid = v.parse().unwrap_or(0),
            "Uid" => s.uid = ids(v),
            "Gid" => s.gid = ids(v),
            "TracerPid" => s.tracer_pid = v.parse().unwrap_or(0),
            "VmRSS" => s.vm_rss = parse_kb_value(v).unwrap_or(0),
            "RssAnon" => s.rss_anon = parse_kb_value(v),
            "RssShmem" => s.rss_shmem = parse_kb_value(v).unwrap_or(0),
            "VmSwap" => s.vm_swap = parse_kb_value(v).unwrap_or(0),
            "VmHWM" => s.vm_hwm = parse_kb_value(v).unwrap_or(0),
            "Threads" => s.threads = v.parse().unwrap_or(0),
            "CapEff" => s.cap_eff = u64::from_str_radix(v, 16).unwrap_or(0),
            "NoNewPrivs" => s.no_new_privs = v == "1",
            "Seccomp" => s.seccomp = v.parse().unwrap_or(0),
            _ => {}
        }
    }
    s
}

/// Name, parent and uids from the head of a `status` file — they are in the
/// first ten lines, so parsing stops there (the hot path of the exec sensor).
pub fn parse_status_head(content: &str) -> Status {
    let mut s = Status::default();
    for line in content.lines() {
        let Some((k, v)) = parse_kv_line(line) else { continue };
        match k {
            "Name" => s.name = v.to_owned(),
            "PPid" => s.ppid = v.parse().unwrap_or(0),
            "Uid" => {
                for (i, x) in v.split_whitespace().take(4).enumerate() {
                    s.uid[i] = x.parse().unwrap_or(0);
                }
                break;
            }
            _ => {}
        }
    }
    s
}

/// Raw `/proc/<pid>/status`.
pub fn read_status_raw(pid: i32) -> io::Result<String> {
    crate::util::read_record_lossy(proc_path(pid, "status"))
}

fn proc_path(pid: i32, file: &str) -> PathBuf {
    PathBuf::from(format!("/proc/{pid}/{file}"))
}

pub fn read_stat(pid: i32) -> io::Result<Stat> {
    let s = crate::util::read_record_lossy(proc_path(pid, "stat"))?;
    parse_stat(&s).ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed stat"))
}

pub fn read_status(pid: i32) -> io::Result<Status> {
    Ok(parse_status(&crate::util::read_record_lossy(proc_path(pid, "status"))?))
}

/// Start time (identity) of a process.
pub fn start_time(pid: i32) -> Option<u64> {
    read_stat(pid).ok().map(|s| s.starttime)
}

/// Executable path. Kernel threads have none. May end in ` (deleted)`.
pub fn exe(pid: i32) -> Option<String> {
    std::fs::read_link(proc_path(pid, "exe")).ok().map(|p| p.to_string_lossy().into_owned())
}

/// Basename of an executable path, without a ` (deleted)` suffix.
pub fn exe_basename(exe: &str) -> &str {
    let e = exe.trim_end_matches(" (deleted)");
    e.rsplit('/').next().unwrap_or(e)
}

/// Does `comm` look like what the kernel derives from `exe` at `exec` time —
/// the executable's basename cut to 15 bytes? A process that renamed itself
/// (`prctl(PR_SET_NAME)`) or was started through a symlink does not.
pub fn comm_matches_exe(comm: &str, exe: &str) -> bool {
    let base = exe_basename(exe);
    base == comm || (comm.len() == 15 && base.starts_with(comm))
}

/// Is `pid` really the program its name claims? `comm` is chosen by the
/// process, so on its own it proves nothing. Genuine means: the name is the
/// one the kernel would derive from the executable ([`comm_matches_exe`]),
/// and the running executable is owned by root and not writable by group or
/// others — something an unprivileged attacker cannot have planted.
///
/// The ownership is read through `/proc/<pid>/exe`: that is the inode that
/// is actually running (also after a package upgrade replaced the file), not
/// whatever the path says today. A process in another mount namespace is
/// not the host's daemon whatever its binary: root inside a container can
/// install a root-owned `sshd` there and so claim the protection of the
/// host's. `None` when that could not be determined (the caller decides
/// how to fail).
pub fn verify_daemon(pid: i32, comm: &str, exe: &str) -> Option<bool> {
    if !comm_matches_exe(comm, exe) {
        return Some(false);
    }
    if let (Ok(theirs), Ok(ours)) =
        (std::fs::read_link(proc_path(pid, "ns/mnt")), std::fs::read_link("/proc/self/ns/mnt"))
        && theirs != ours
    {
        return Some(false);
    }
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(proc_path(pid, "exe")).ok()?;
    Some(md.uid() == 0 && md.mode() & 0o022 == 0)
}

const SYSTEM_DIRS: &[&str] = &["/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/", "/usr/lib/", "/usr/libexec/", "/lib/"];

/// Does process `pid` run the host's system binary `exe` (its
/// `/proc/<pid>/exe` link)? A regular file in a system directory that only
/// root can modify is worth believing: an unprivileged attacker can run a
/// program from his own directory under any name, but cannot put one there.
///
/// It must be that very file: the process is in Warden's mount namespace
/// (a container's `/usr/bin/git` is the container's, whoever is root
/// inside), and the inode that runs (`stat /proc/<pid>/exe`) is the one
/// at the path. 0.13.3 checked the path string in Warden's own view, so a
/// process in a container started as `/usr/bin/git` passed for the host's
/// git — and its writes to a bind-mounted site were accepted silently.
pub fn is_system_binary(pid: i32, exe: &str) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (path, deleted) = match exe.strip_suffix(" (deleted)") {
        Some(p) => (p, true),
        None => (exe, false),
    };
    if path.contains("/../") || !SYSTEM_DIRS.iter().any(|d| path.starts_with(d)) || !same_mount_namespace(pid) {
        return false;
    }
    let Ok(running) = std::fs::metadata(proc_path(pid, "exe")) else { return false };
    let root_only = running.is_file() && running.uid() == 0 && running.mode() & 0o022 == 0;
    if deleted {
        // a package upgrade replaced the file under a running process: the
        // old inode itself is the evidence (root's, gone from its directory)
        return root_only && running.nlink() == 0;
    }
    root_only && std::fs::metadata(path).is_ok_and(|p| p.dev() == running.dev() && p.ino() == running.ino())
}

/// Is `pid` in the mount namespace Warden is in?
pub fn same_mount_namespace(pid: i32) -> bool {
    match (std::fs::read_link(proc_path(pid, "ns/mnt")), std::fs::read_link("/proc/self/ns/mnt")) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

pub fn cwd(pid: i32) -> Option<String> {
    std::fs::read_link(proc_path(pid, "cwd")).ok().map(|p| p.to_string_lossy().into_owned())
}

/// Command line with NULs replaced by spaces, capped at `max` bytes.
pub fn cmdline(pid: i32, max: usize) -> Option<String> {
    let raw = crate::util::read_record(proc_path(pid, "cmdline")).ok()?;
    Some(format_cmdline(&raw, max))
}

pub fn format_cmdline(raw: &[u8], max: usize) -> String {
    let trimmed = raw.strip_suffix(&[0]).unwrap_or(raw);
    let cut = &trimmed[..trimmed.len().min(max)];
    let mut s: String = String::from_utf8_lossy(cut).replace('\0', " ");
    if trimmed.len() > max {
        s.push('…');
    }
    s
}

/// Unified (v2) cgroup path, e.g. `/system.slice/nginx.service`.
pub fn cgroup(pid: i32) -> Option<String> {
    let s = String::from_utf8(crate::util::read_record(proc_path(pid, "cgroup")).ok()?).ok()?;
    parse_cgroup(&s)
}

pub fn parse_cgroup(content: &str) -> Option<String> {
    content.lines().find_map(|l| l.strip_prefix("0::").map(str::to_owned))
}

pub fn oom_score_adj(pid: i32) -> Option<i32> {
    read_string(proc_path(pid, "oom_score_adj")).ok()?.trim().parse().ok()
}

pub fn oom_score(pid: i32) -> Option<u32> {
    read_string(proc_path(pid, "oom_score")).ok()?.trim().parse().ok()
}

/// Value of one environment variable of the process (needs ptrace access).
pub fn environ_var(pid: i32, name: &str) -> Option<String> {
    let raw = crate::util::read_record(proc_path(pid, "environ")).ok()?;
    find_env(&raw, name)
}

pub fn find_env(raw: &[u8], name: &str) -> Option<String> {
    raw.split(|b| *b == 0).find_map(|kv| {
        let s = std::str::from_utf8(kv).ok()?;
        let (k, v) = s.split_once('=')?;
        (k == name).then(|| v.to_owned())
    })
}

/// `(fd, link target)` for every open descriptor.
pub fn fds(pid: i32) -> Vec<(i32, String)> {
    let Ok(rd) = std::fs::read_dir(proc_path(pid, "fd")) else { return Vec::new() };
    rd.filter_map(Result::ok)
        .filter_map(|e| {
            let fd: i32 = e.file_name().to_str()?.parse().ok()?;
            let t = std::fs::read_link(e.path()).ok()?;
            Some((fd, t.to_string_lossy().into_owned()))
        })
        .collect()
}

/// Number of open descriptors. Linux 6.2+ reports it as the size of
/// `/proc/<pid>/fd` (one `stat` instead of listing thousands of entries);
/// older kernels report 0 and the directory is counted.
pub fn fd_count(pid: i32) -> usize {
    let p = proc_path(pid, "fd");
    if let Ok(md) = std::fs::metadata(&p)
        && md.len() > 0
    {
        return md.len() as usize;
    }
    std::fs::read_dir(p).map(|rd| rd.count()).unwrap_or(0)
}

/// Targets of descriptors 0, 1 and 2 only (three `readlink`s, no listing).
pub fn stdio_targets(pid: i32) -> [Option<String>; 3] {
    [0, 1, 2]
        .map(|fd| std::fs::read_link(format!("/proc/{pid}/fd/{fd}")).ok().map(|t| t.to_string_lossy().into_owned()))
}

/// Soft RLIMIT_NOFILE from `/proc/<pid>/limits`.
pub fn nofile_limit(pid: i32) -> Option<u64> {
    let s = read_string(proc_path(pid, "limits")).ok()?;
    parse_nofile(&s)
}

pub fn parse_nofile(content: &str) -> Option<u64> {
    let line = content.lines().find(|l| l.starts_with("Max open files"))?;
    line["Max open files".len()..].split_whitespace().next()?.parse().ok()
}

pub fn socket_inode(target: &str) -> Option<u64> {
    target.strip_prefix("socket:[")?.strip_suffix(']')?.parse().ok()
}

/// `(read_bytes, write_bytes)` that hit the block layer (`/proc/<pid>/io`).
pub fn io_bytes(pid: i32) -> Option<(u64, u64)> {
    let s = read_string(proc_path(pid, "io")).ok()?;
    let mut r = None;
    let mut w = None;
    for l in s.lines() {
        if let Some(v) = l.strip_prefix("read_bytes:") {
            r = v.trim().parse().ok();
        } else if let Some(v) = l.strip_prefix("write_bytes:") {
            w = v.trim().parse().ok();
        }
    }
    Some((r?, w?))
}

/// All numeric entries of /proc.
pub fn pids() -> Vec<i32> {
    let Ok(rd) = std::fs::read_dir("/proc") else { return Vec::new() };
    rd.filter_map(Result::ok).filter_map(|e| e.file_name().to_str()?.parse().ok()).collect()
}

/// Kernel threads are children of kthreadd (PID 2) or PID 2 itself.
pub fn is_kernel_thread(stat: &Stat) -> bool {
    stat.pid == 2 || stat.ppid == 2
}

/// A lightweight snapshot of one process (stat + status).
#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct ProcInfo {
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,
    pub state: char,
    pub ruid: u32,
    pub euid: u32,
    pub suid: u32,
    pub rss: u64,
    /// `RssAnon` when the kernel reports it.
    pub rss_anon: Option<u64>,
    pub rss_shmem: u64,
    pub swap: u64,
    pub hwm: u64,
    pub majflt: u64,
    pub cpu_ticks: u64,
    pub start_time: u64,
    pub threads: u64,
    pub tracer_pid: i32,
    pub kernel_thread: bool,
}

/// Is `pid` `ancestor` or one of its descendants (by the live `ppid`
/// chain, at most 64 generations)?
pub fn descends_from(pid: i32, ancestor: i32) -> bool {
    let mut p = pid;
    for _ in 0..64 {
        if p == ancestor {
            return true;
        }
        if p <= 1 {
            return false;
        }
        match read_stat(p) {
            Ok(st) => p = st.ppid,
            Err(_) => return false,
        }
    }
    false
}

/// Was `pid` started by this process (directly or further down)? The
/// programs Warden runs itself: hooks, notification and health commands.
pub fn is_own_descendant(pid: i32) -> bool {
    i32::try_from(std::process::id()).is_ok_and(|me| pid != me && descends_from(pid, me))
}

pub fn read_info(pid: i32) -> io::Result<ProcInfo> {
    let st = read_stat(pid)?;
    let ss = read_status(pid)?;
    Ok(info_from(st, &ss))
}

/// Combine an already-read `stat` and `status` of the same process.
pub fn info_from(st: Stat, ss: &Status) -> ProcInfo {
    ProcInfo {
        pid: st.pid,
        ppid: st.ppid,
        kernel_thread: is_kernel_thread(&st),
        comm: st.comm,
        state: st.state,
        ruid: ss.uid[0],
        euid: ss.uid[1],
        suid: ss.uid[2],
        rss: ss.vm_rss,
        rss_anon: ss.rss_anon,
        rss_shmem: ss.rss_shmem,
        swap: ss.vm_swap,
        hwm: ss.vm_hwm,
        majflt: st.majflt,
        cpu_ticks: st.utime + st.stime,
        start_time: st.starttime,
        threads: ss.threads,
        tracer_pid: ss.tracer_pid,
    }
}

/// Snapshot of all processes, keyed by PID.
pub fn snapshot() -> HashMap<i32, ProcInfo> {
    pids().into_iter().filter_map(|p| read_info(p).ok().map(|i| (p, i))).collect()
}

/// [`ProcInfo`] from `/proc/<pid>/stat` alone — half the reads of
/// [`read_info`], and `status` is the expensive file for the kernel to
/// generate. Credentials are unknown (`u32::MAX`), swap, peak RSS and the
/// tracer are 0.
pub fn read_info_light(pid: i32) -> io::Result<ProcInfo> {
    let st = read_stat(pid)?;
    Ok(ProcInfo {
        pid,
        ppid: st.ppid,
        kernel_thread: is_kernel_thread(&st),
        state: st.state,
        ruid: u32::MAX,
        euid: u32::MAX,
        suid: u32::MAX,
        rss: st.rss_pages * crate::util::page_size(),
        rss_anon: None,
        rss_shmem: 0,
        swap: 0,
        hwm: 0,
        majflt: st.majflt,
        cpu_ticks: st.utime + st.stime,
        start_time: st.starttime,
        threads: st.num_threads,
        tracer_pid: 0,
        comm: st.comm,
    })
}

/// All processes via [`read_info_light`].
pub fn snapshot_light() -> HashMap<i32, ProcInfo> {
    pids().into_iter().filter_map(|p| read_info_light(p).ok().map(|i| (p, i))).collect()
}

/// Direct and indirect children of `pid` given a snapshot.
pub fn descendants(table: &HashMap<i32, ProcInfo>, pid: i32) -> Vec<i32> {
    let mut children: HashMap<i32, Vec<i32>> = HashMap::new();
    for p in table.values() {
        children.entry(p.ppid).or_default().push(p.pid);
    }
    let mut out = Vec::new();
    let mut stack = vec![pid];
    while let Some(p) = stack.pop() {
        if let Some(cs) = children.get(&p) {
            for c in cs {
                if *c != pid && !out.contains(c) {
                    out.push(*c);
                    stack.push(*c);
                }
            }
        }
    }
    out
}

/// Files that are deleted but still held open: `(pid, fd, path, size)`.
/// They consume disk space that `du` cannot see.
pub fn deleted_open_files(min_size: u64, mount_dev: Option<u64>) -> Vec<(i32, i32, String, u64)> {
    use std::os::unix::fs::MetadataExt;
    let mut out = Vec::new();
    for pid in pids() {
        for (fd, target) in fds(pid) {
            if !target.ends_with(" (deleted)") || !target.starts_with('/') || target.starts_with("/memfd:") {
                continue;
            }
            let Ok(md) = std::fs::metadata(format!("/proc/{pid}/fd/{fd}")) else { continue };
            if !md.is_file() || md.len() < min_size {
                continue;
            }
            if mount_dev.is_some_and(|d| d != md.dev()) {
                continue;
            }
            out.push((pid, fd, target, md.len()));
        }
    }
    out.sort_by_key(|b| std::cmp::Reverse(b.3));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exe_names() {
        assert_eq!(exe_basename("/usr/bin/php8.3 (deleted)"), "php8.3");
        assert_eq!(exe_basename("bash"), "bash");
        assert!(comm_matches_exe("sshd", "/usr/sbin/sshd"));
        assert!(comm_matches_exe("sshd", "/usr/sbin/sshd (deleted)"));
        // comm is cut to 15 bytes
        assert!(comm_matches_exe("systemd-journal", "/usr/lib/systemd/systemd-journald"));
        assert!(!comm_matches_exe("systemd-udevd", "/usr/bin/sleep"));
        assert!(!comm_matches_exe("systemd-journ", "/usr/lib/systemd/systemd-journald"));
    }

    #[test]
    fn system_binaries_are_the_running_root_owned_files_in_system_directories() {
        let mut child = std::process::Command::new("sleep").arg("5").spawn().unwrap();
        let pid = child.id() as i32;
        let real = exe(pid).unwrap();
        assert!(real.starts_with("/usr/bin/") || real.starts_with("/bin/"), "{real}");
        assert!(is_system_binary(pid, &real), "{real}");
        // a path that is a system binary, but not the one this process runs
        let other = if std::path::Path::new("/usr/bin/env").exists() { "/usr/bin/env" } else { "/bin/env" };
        assert!(!is_system_binary(pid, other), "the path alone proves nothing");
        assert!(!is_system_binary(pid, "/usr/bin/warden-no-such-binary"));
        assert!(!is_system_binary(pid, "/usr/bin"), "a directory");
        assert!(!is_system_binary(pid, "/usr/bin/../../tmp/x"));
        let d = tempfile::tempdir().unwrap();
        let mine = d.path().join("git");
        std::fs::write(&mine, b"#!/bin/sh\n").unwrap();
        assert!(!is_system_binary(pid, &mine.to_string_lossy()), "named like a tool, but not in a system directory");
        // gone: nothing to believe
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(!is_system_binary(pid, &real));
        assert!(same_mount_namespace(std::process::id() as i32));
        assert!(!same_mount_namespace(i32::MAX));
    }

    /// A process in another mount namespace (a container) runs "/usr/bin/sleep"
    /// — the container's, whatever the host has there: neither a system
    /// binary of the host nor the host's daemon.
    #[test]
    fn descendants_are_found_by_the_parent_chain() {
        let me = std::process::id() as i32;
        let mut child = std::process::Command::new("sh").args(["-c", "sleep 5 & wait"]).spawn().unwrap();
        let sh = child.id() as i32;
        std::thread::sleep(std::time::Duration::from_millis(200));
        let grandchild = pids().into_iter().find(|p| read_stat(*p).is_ok_and(|s| s.ppid == sh));
        assert!(descends_from(sh, me) && is_own_descendant(sh));
        if let Some(g) = grandchild {
            assert!(is_own_descendant(g), "the shell's child is ours too");
        }
        assert!(!is_own_descendant(me), "not a descendant of itself");
        assert!(!is_own_descendant(1));
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn another_mount_namespace_is_not_the_host() {
        // SAFETY: trivial libc call.
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let Ok(mut child) = std::process::Command::new("unshare").args(["-m", "sleep", "5"]).spawn() else { return };
        let pid = child.id() as i32;
        // wait for unshare to exec sleep
        let mut real = String::new();
        for _ in 0..100 {
            real = exe(pid).unwrap_or_default();
            if real.ends_with("/sleep") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        if real.ends_with("/sleep") {
            assert!(!same_mount_namespace(pid));
            assert!(!is_system_binary(pid, &real), "{real}");
            assert_eq!(verify_daemon(pid, "sleep", &real), Some(false));
        }
        child.kill().unwrap();
        child.wait().unwrap();
    }

    #[test]
    fn genuine_needs_matching_name_and_root_owned_binary() {
        let me = std::process::id() as i32;
        let exe = exe(me).unwrap();
        let comm = read_stat(me).unwrap().comm;
        // the test binary is built by the invoking user: only root-owned counts
        let owned_by_root =
            std::fs::metadata(&exe).map(|m| std::os::unix::fs::MetadataExt::uid(&m) == 0).unwrap_or(false);
        let writable =
            std::fs::metadata(&exe).map(|m| std::os::unix::fs::MetadataExt::mode(&m) & 0o022 != 0).unwrap_or(true);
        assert_eq!(verify_daemon(me, &comm, &exe), Some(owned_by_root && !writable));
        // a name the executable does not explain is never genuine
        assert_eq!(verify_daemon(me, "systemd-udevd", &exe), Some(false));
        // unknown process: cannot tell
        assert_eq!(verify_daemon(i32::MAX, "x", "/x/x"), None);
    }

    #[test]
    fn stat_with_hostile_comm() {
        let s = "1234 (a) b (c)) S 1 1234 1234 0 -1 4194560 100 0 7 0 50 25 0 0 20 0 3 0 98765 1000000 250 18446744073709551615";
        let st = parse_stat(s).unwrap();
        assert_eq!(st.pid, 1234);
        assert_eq!(st.comm, "a) b (c)");
        assert_eq!(st.state, 'S');
        assert_eq!(st.ppid, 1);
        assert_eq!(st.minflt, 100);
        assert_eq!(st.majflt, 7);
        assert_eq!(st.utime, 50);
        assert_eq!(st.stime, 25);
        assert_eq!(st.num_threads, 3);
        assert_eq!(st.starttime, 98765);
        assert_eq!(st.rss_pages, 250);
    }

    #[test]
    fn status_parsing() {
        let s = parse_status(
            "Name:\tphp-fpm8.3\nPPid:\t812\nUid:\t33\t0\t0\t0\nGid:\t33\t33\t33\t33\nTracerPid:\t0\nVmHWM:\t 2048 kB\nVmRSS:\t 1024 kB\nRssAnon:\t 256 kB\nRssFile:\t 256 kB\nRssShmem:\t 512 kB\nVmSwap:\t 512 kB\nThreads:\t1\nCapEff:\t000001ffffffffff\nNoNewPrivs:\t1\n",
        );
        assert_eq!(s.name, "php-fpm8.3");
        assert_eq!(s.ppid, 812);
        let h = parse_status_head(
            "Name:\tphp-fpm8.3\nUmask:\t0022\nState:\tS\nPPid:\t812\nUid:\t33\t0\t0\t0\nVmRSS:\t 1 kB\n",
        );
        assert_eq!((h.name.as_str(), h.ppid, h.uid), ("php-fpm8.3", 812, [33, 0, 0, 0]));
        assert_eq!(h.vm_rss, 0, "stops after Uid");
        assert_eq!(s.uid, [33, 0, 0, 0]);
        assert_eq!(s.vm_swap, 512 * 1024);
        assert_eq!((s.rss_anon, s.rss_shmem), (Some(256 * 1024), 512 * 1024));
        assert_eq!(parse_status("VmRSS:\t 1024 kB\n").rss_anon, None, "kernels before 4.5");
        assert_eq!(s.cap_eff, 0x1ffffffffff);
        assert!(s.no_new_privs);
    }

    #[test]
    fn cmdline_env_cgroup_limits() {
        assert_eq!(format_cmdline(b"sh\0-c\0id\0", 100), "sh -c id");
        assert_eq!(format_cmdline(b"abcdef", 3), "abc…");
        assert_eq!(find_env(b"A=1\0LD_PRELOAD=/tmp/x.so\0", "LD_PRELOAD").as_deref(), Some("/tmp/x.so"));
        assert_eq!(find_env(b"A=1\0", "LD_PRELOAD"), None);
        assert_eq!(parse_cgroup("0::/system.slice/nginx.service\n").as_deref(), Some("/system.slice/nginx.service"));
        assert_eq!(
            parse_nofile(
                "Limit Soft Hard Units\nMax open files            1024                 524288               files\n"
            ),
            Some(1024)
        );
        assert_eq!(socket_inode("socket:[12345]"), Some(12345));
        assert_eq!(socket_inode("/dev/null"), None);
    }

    #[test]
    fn own_process_is_readable() {
        let me = std::process::id() as i32;
        let info = read_info(me).unwrap();
        assert_eq!(info.pid, me);
        assert!(info.start_time > 0);
        assert!(exe(me).is_some());
        assert!(fd_count(me) > 0);
    }

    #[test]
    fn descendants_walk() {
        let mut t = HashMap::new();
        for (pid, ppid) in [(10, 1), (11, 10), (12, 11), (13, 1)] {
            t.insert(pid, ProcInfo { pid, ppid, ..Default::default() });
        }
        let mut d = descendants(&t, 10);
        d.sort();
        assert_eq!(d, vec![11, 12]);
    }

    #[test]
    fn light_snapshot_matches_full_one_for_self() {
        let me = std::process::id() as i32;
        let full = read_info(me).unwrap();
        let light = read_info_light(me).unwrap();
        assert_eq!(
            (light.pid, light.ppid, &light.comm, light.start_time),
            (full.pid, full.ppid, &full.comm, full.start_time)
        );
        assert_eq!(light.ruid, u32::MAX, "credentials are not read by the light variant");
        assert!(light.rss > 0 && light.threads >= 1);
        assert!(snapshot_light().contains_key(&me));
    }

    #[test]
    fn fd_count_and_stdio_targets() {
        let me = std::process::id() as i32;
        let before = fd_count(me);
        let listed = std::fs::read_dir(format!("/proc/{me}/fd")).unwrap().count();
        // The directory listing itself holds one extra descriptor.
        assert!(before.abs_diff(listed) <= 8, "{before} vs {listed}");
        let files: Vec<_> = (0..64).map(|_| std::fs::File::open("/proc/self/stat").unwrap()).collect();
        assert!(fd_count(me) >= before + 32);
        drop(files);
        let t = stdio_targets(me);
        assert_eq!(t.len(), 3);
        assert!(t.iter().any(Option::is_some), "a test runner has at least one stdio descriptor");
    }
}
