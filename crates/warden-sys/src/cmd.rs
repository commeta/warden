//! Running external programs with hard timeouts.
//!
//! Every program Warden starts — `systemctl`, `nft`, `journalctl`, operator
//! `exec` hooks, notification commands, command health checks — goes through
//! [`Run`]. There is exactly one implementation, so the properties below hold
//! everywhere:
//!
//! * **hard timeout** — a hung program is killed and reaped;
//! * **no pipe deadlocks** — stdout and stderr are drained while the program
//!   runs and stdin is fed without blocking, so a chatty program (or one that
//!   never reads its input) cannot stall the caller;
//! * **bounded memory** — captured output is capped per stream
//!   ([`DEFAULT_MAX_OUTPUT`]); the rest is read and discarded;
//! * **no sleep-polling** — the wait is one `poll(2)` over the pipes and a
//!   pidfd, so completion is noticed at once and an idle wait costs no
//!   wakeups (without pidfd support, a 20 ms tick is used);
//! * **no hang on inherited pipes** — when the program exits, what is in the
//!   pipes is collected and the call returns, even when a background child
//!   it left behind still holds the write ends open;
//! * **the whole group dies on a timeout** — every program is the leader of a
//!   process group of its own, and a timeout kills the group, not only the
//!   program: what a hung hook started (`curl` under a shell script) cannot
//!   outlive it and keep running with the daemon's privileges;
//! * **optional unprivileged user** — [`Run::user`] runs the program as
//!   another account: supplementary groups, gid and uid are switched in the
//!   child before `exec`, which also drops every capability (the kernel
//!   clears them on a switch away from uid 0).

use std::ffi::{CStr, CString, OsStr, OsString};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Output, Stdio};
use std::time::{Duration, Instant};

/// Default cap for captured stdout / stderr, each.
pub const DEFAULT_MAX_OUTPUT: usize = 1 << 20;

/// Wake-up interval when no pidfd is available (kernel < 5.3).
const FALLBACK_TICK: Duration = Duration::from_millis(20);

/// Reads per pump of one stream: bounds the time spent in one place when the
/// program writes faster than we read, so the deadline is still checked.
const MAX_READS_PER_PUMP: usize = 64;

/// A program to run: build it, then [`Run::run`] it.
#[derive(Debug, Clone)]
pub struct Run<'a> {
    program: &'a str,
    args: Vec<OsString>,
    envs: Vec<(OsString, OsString)>,
    input: Option<&'a [u8]>,
    timeout: Duration,
    max_output: usize,
    user: Option<&'a Credentials>,
}

impl<'a> Run<'a> {
    pub fn new(program: &'a str, timeout: Duration) -> Self {
        Self {
            program,
            args: Vec::new(),
            envs: Vec::new(),
            input: None,
            timeout,
            max_output: DEFAULT_MAX_OUTPUT,
            user: None,
        }
    }

    /// Run as `user` (`None`: as the daemon). The program also gets that
    /// user's `HOME`, `USER` and `LOGNAME`, and `/` as working directory.
    pub fn user(mut self, user: Option<&'a Credentials>) -> Self {
        self.user = user;
        self
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.args.extend(args.into_iter().map(|a| a.as_ref().to_owned()));
        self
    }

    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.envs.push((key.as_ref().to_owned(), value.as_ref().to_owned()));
        self
    }

    /// Feed `data` to the program's stdin (then close it). Without this,
    /// stdin is `/dev/null`.
    pub fn input(mut self, data: &'a [u8]) -> Self {
        self.input = Some(data);
        self
    }

    /// Cap for captured stdout and stderr, each (the excess is discarded).
    pub fn max_output(mut self, bytes: usize) -> Self {
        self.max_output = bytes;
        self
    }

    /// Environment for tools whose output Warden parses: no colour, no
    /// pager, `C` locale.
    pub fn parseable(self) -> Self {
        self.env("SYSTEMD_COLORS", "0").env("SYSTEMD_PAGER", "").env("LC_ALL", "C")
    }

    /// Run to completion (or to the timeout, which kills the program and
    /// returns [`io::ErrorKind::TimedOut`]).
    pub fn run(self) -> io::Result<Output> {
        let mut cmd = Command::new(self.program);
        cmd.args(&self.args);
        for (k, v) in &self.envs {
            cmd.env(k, v);
        }
        cmd.stdin(if self.input.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0);
        if let Some(u) = self.user {
            u.apply(&mut cmd);
        }
        let mut child = cmd.spawn().map_err(|e| match self.user {
            // EPERM from the child before exec: the credential switch
            Some(u) if e.raw_os_error() == Some(libc::EPERM) => io::Error::new(
                e.kind(),
                format!("cannot run {} as {}: {e} (the daemon needs CAP_SETUID and CAP_SETGID)", self.program, u.name),
            ),
            _ => e,
        })?;
        match self.drive(&mut child) {
            Ok(out) => Ok(out),
            Err(e) => {
                kill_group(&mut child);
                Err(e)
            }
        }
    }

    fn drive(&self, child: &mut Child) -> io::Result<Output> {
        let mut pipes = Pipes::new(child, self.input.unwrap_or_default(), self.max_output)?;
        let mut pidfd = open_pidfd(child.id());
        let deadline = Instant::now() + self.timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{} timed out after {:?}", self.program, self.timeout),
                ));
            }
            let wait = if pidfd.is_some() { left } else { left.min(FALLBACK_TICK) };
            let exited = pipes.wait(pidfd.as_ref().map(AsRawFd::as_raw_fd), wait)?;
            pipes.pump();
            if let Some(status) = child.try_wait()? {
                // Whatever is buffered now is all there will be: a background
                // child holding the pipes open must not keep us here.
                pipes.pump();
                return Ok(Output { status, stdout: pipes.out, stderr: pipes.err });
            }
            if exited {
                // Readable pidfd but not yet reapable: do not spin on it.
                pidfd = None;
            }
        }
    }
}

/// `run_cmd` for tools whose output is parsed: C locale, no colour or pager.
pub fn run_cmd(program: &str, args: &[&str], timeout: Duration) -> io::Result<Output> {
    Run::new(program, timeout).args(args).parseable().run()
}

/// Like [`run_cmd`] but feeds `input` to stdin (e.g. `nft -f -`).
pub fn run_with_input(program: &str, args: &[&str], input: &str, timeout: Duration) -> io::Result<Output> {
    Run::new(program, timeout).args(args).env("LC_ALL", "C").input(input.as_bytes()).run()
}

pub fn which(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")
        .unwrap_or_else(|| "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin".into());
    std::env::split_paths(&path).map(|d| d.join(program)).find(|p| p.is_file())
}

/// SIGKILL to the child's whole process group, then reap the child.
fn kill_group(child: &mut Child) {
    if let Ok(pgid) = libc::pid_t::try_from(child.id()) {
        // SAFETY: plain kill(2). The group leader is our child and not reaped
        // yet, so its PID (= the group ID) cannot have been reused.
        unsafe { libc::kill(-pgid, libc::SIGKILL) };
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// An account to run programs as ([`Run::user`]), resolved once through NSS
/// (`getpwnam_r`/`getpwuid_r`, `getgrouplist`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credentials {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    /// Supplementary groups (including `gid`).
    pub groups: Vec<u32>,
    pub home: PathBuf,
}

impl Credentials {
    /// Look up a user by name or numeric UID.
    pub fn lookup(spec: &str) -> io::Result<Self> {
        let not_found = || io::Error::new(io::ErrorKind::NotFound, format!("no such user: {spec}"));
        let name = CString::new(spec).map_err(|_| not_found())?;
        let uid = spec.parse::<libc::uid_t>().ok();
        let mut buf: Vec<libc::c_char> = vec![0; 4096];
        loop {
            // SAFETY: an all-zero passwd is a valid out-parameter (plain
            // integers and null pointers); getpw*_r fill it in.
            let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
            let mut found: *mut libc::passwd = std::ptr::null_mut();
            // SAFETY: every pointer is valid for the call and `buf.len()` is
            // the size of the buffer the strings are written into.
            let rc = unsafe {
                match uid {
                    Some(u) => libc::getpwuid_r(u, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut found),
                    None => libc::getpwnam_r(name.as_ptr(), &mut pwd, buf.as_mut_ptr(), buf.len(), &mut found),
                }
            };
            if rc == libc::ERANGE && buf.len() < 1 << 20 {
                buf.resize(buf.len() * 4, 0);
                continue;
            }
            if rc != 0 {
                return Err(io::Error::from_raw_os_error(rc));
            }
            if found.is_null() {
                return Err(not_found());
            }
            // SAFETY: on success pw_name and pw_dir point to NUL-terminated
            // strings inside `buf`, which is alive here.
            let (user, home) = unsafe { (CStr::from_ptr(pwd.pw_name), CStr::from_ptr(pwd.pw_dir)) };
            let user_c = user.to_owned();
            let groups = group_list(&user_c, pwd.pw_gid);
            return Ok(Self {
                name: user.to_string_lossy().into_owned(),
                uid: pwd.pw_uid,
                gid: pwd.pw_gid,
                groups,
                home: PathBuf::from(home.to_string_lossy().into_owned()),
            });
        }
    }

    /// Whether running as this user changes anything (it is not root).
    pub fn is_root(&self) -> bool {
        self.uid == 0
    }

    fn apply(&self, cmd: &mut Command) {
        cmd.env("HOME", &self.home).env("USER", &self.name).env("LOGNAME", &self.name).current_dir("/");
        if self.is_root() {
            return;
        }
        let (uid, gid, groups) = (self.uid, self.gid, self.groups.clone());
        // SAFETY: the closure runs in the forked child before exec and only
        // makes async-signal-safe system calls on data moved into it; it
        // does not allocate.
        unsafe {
            cmd.pre_exec(move || {
                // groups first, then gid, then uid: each step needs the
                // privilege the next one gives up
                if libc::setgroups(groups.len(), groups.as_ptr()) != 0
                    || libc::setresgid(gid, gid, gid) != 0
                    || libc::setresuid(uid, uid, uid) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
}

/// The supplementary groups of `user` (with `gid`); just `gid` if NSS fails.
fn group_list(user: &CStr, gid: libc::gid_t) -> Vec<libc::gid_t> {
    let mut n: libc::c_int = 32;
    for _ in 0..8 {
        let mut groups: Vec<libc::gid_t> = vec![0; usize::try_from(n).unwrap_or(32)];
        let mut got = n;
        // SAFETY: `groups` has room for `got` entries; getgrouplist updates
        // `got` to the number found (or needed, when it returns -1).
        let rc = unsafe { libc::getgrouplist(user.as_ptr(), gid, groups.as_mut_ptr(), &mut got) };
        if rc >= 0 {
            groups.truncate(usize::try_from(got).unwrap_or(0));
            return groups;
        }
        n = got.max(n.saturating_mul(2));
    }
    vec![gid]
}

fn open_pidfd(pid: u32) -> Option<OwnedFd> {
    // SAFETY: plain syscall with integer arguments.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return None;
    }
    // SAFETY: the kernel returned a fresh descriptor that nothing else owns.
    Some(unsafe { OwnedFd::from_raw_fd(fd as RawFd) })
}

fn set_nonblocking(fd: RawFd) -> io::Result<()> {
    // SAFETY: fcntl on a descriptor we hold open.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// The three pipes of a running child, all non-blocking, pumped from one
/// thread.
struct Pipes<'i> {
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    stdin: Option<ChildStdin>,
    input: &'i [u8],
    sent: usize,
    out: Vec<u8>,
    err: Vec<u8>,
    max: usize,
}

impl<'i> Pipes<'i> {
    fn new(child: &mut Child, input: &'i [u8], max: usize) -> io::Result<Self> {
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let stdin = child.stdin.take();
        for fd in [
            stdout.as_ref().map(AsRawFd::as_raw_fd),
            stderr.as_ref().map(AsRawFd::as_raw_fd),
            stdin.as_ref().map(AsRawFd::as_raw_fd),
        ]
        .into_iter()
        .flatten()
        {
            set_nonblocking(fd)?;
        }
        Ok(Self { stdout, stderr, stdin, input, sent: 0, out: Vec::new(), err: Vec::new(), max })
    }

    /// Sleep until a pipe is ready, the pidfd fires or `timeout` passes.
    /// Returns whether the pidfd reported the exit.
    fn wait(&self, pidfd: Option<RawFd>, timeout: Duration) -> io::Result<bool> {
        let mut fds = [libc::pollfd { fd: -1, events: 0, revents: 0 }; 4];
        let mut n = 0;
        let mut add = |fd: RawFd, events: libc::c_short| {
            fds[n] = libc::pollfd { fd, events, revents: 0 };
            n += 1;
        };
        if let Some(fd) = pidfd {
            add(fd, libc::POLLIN);
        }
        if let Some(s) = &self.stdout {
            add(s.as_raw_fd(), libc::POLLIN);
        }
        if let Some(s) = &self.stderr {
            add(s.as_raw_fd(), libc::POLLIN);
        }
        if let Some(s) = &self.stdin {
            add(s.as_raw_fd(), libc::POLLOUT);
        }
        // Round up: a 0 ms poll would turn the last fraction of a
        // millisecond into a busy loop.
        let ms = timeout.as_micros().div_ceil(1000).min(i32::MAX as u128) as libc::c_int;
        // SAFETY: `fds[..n]` are initialised pollfd structures.
        let r = unsafe { libc::poll(fds.as_mut_ptr(), n as libc::nfds_t, ms) };
        if r < 0 {
            let e = io::Error::last_os_error();
            return if e.kind() == io::ErrorKind::Interrupted { Ok(false) } else { Err(e) };
        }
        Ok(pidfd.is_some() && fds[0].revents & (libc::POLLIN | libc::POLLHUP) != 0)
    }

    /// Move everything that is ready: read what the program wrote, write what
    /// it will take.
    fn pump(&mut self) {
        drain(&mut self.stdout, &mut self.out, self.max);
        drain(&mut self.stderr, &mut self.err, self.max);
        self.feed();
    }

    fn feed(&mut self) {
        let Some(si) = &mut self.stdin else { return };
        while self.sent < self.input.len() {
            match si.write(&self.input[self.sent..]) {
                Ok(0) => break,
                Ok(n) => self.sent += n,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                // EPIPE: the program is not interested in more input.
                Err(_) => break,
            }
        }
        // Done (or abandoned): closing stdin is the program's EOF.
        self.stdin = None;
    }
}

/// Read what is available from `src` into `dst` (keeping at most `max`
/// bytes in total; the rest is consumed and dropped so the writer never
/// blocks). A closed or failed stream is dropped from the poll set.
fn drain<R: Read>(src: &mut Option<R>, dst: &mut Vec<u8>, max: usize) {
    let Some(r) = src.as_mut() else { return };
    let mut buf = [0u8; 8192];
    for _ in 0..MAX_READS_PER_PUMP {
        match r.read(&mut buf) {
            Ok(n) if n > 0 => {
                let room = max.saturating_sub(dst.len());
                dst.extend_from_slice(&buf[..n.min(room)]);
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            // EOF or a broken pipe: nothing more will come.
            _ => {
                *src = None;
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(b: &[u8]) -> String {
        String::from_utf8_lossy(b).into_owned()
    }

    #[test]
    fn output_status_and_env() {
        let o = run_cmd("sh", &["-c", "echo hi; echo err >&2; exit 3"], Duration::from_secs(5)).unwrap();
        assert_eq!(text(&o.stdout).trim(), "hi");
        assert_eq!(text(&o.stderr).trim(), "err");
        assert_eq!(o.status.code(), Some(3));
        let o =
            Run::new("sh", Duration::from_secs(5)).args(["-c", "echo $WARDEN_T"]).env("WARDEN_T", "v").run().unwrap();
        assert_eq!(text(&o.stdout).trim(), "v");
        let e = Run::new("/nonexistent/program", Duration::from_secs(1)).run().unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn timeout_kills_promptly() {
        let t = Instant::now();
        let e = run_cmd("sleep", &["5"], Duration::from_millis(100)).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    }

    #[test]
    fn stdin_is_fed_including_large_input() {
        let o = run_with_input("cat", &[], "hello", Duration::from_secs(5)).unwrap();
        assert_eq!(text(&o.stdout), "hello");
        assert!(which("sh").is_some());
        // 2 MiB through `cat`: stdin and stdout must be pumped together.
        let big = vec![b'x'; 2 << 20];
        let o = Run::new("cat", Duration::from_secs(10)).input(&big).max_output(4 << 20).run().unwrap();
        assert_eq!(o.stdout.len(), big.len());
    }

    #[test]
    fn chatty_program_neither_blocks_nor_grows_memory() {
        // ~3 MB on stdout and the same on stderr, far over the pipe buffer.
        let o = Run::new("sh", Duration::from_secs(10))
            .args(["-c", "head -c 3000000 /dev/zero; head -c 3000000 /dev/zero >&2"])
            .max_output(1000)
            .run()
            .unwrap();
        assert_eq!((o.stdout.len(), o.stderr.len()), (1000, 1000));
    }

    #[test]
    fn program_that_ignores_stdin_does_not_deadlock() {
        let big = vec![b'x'; 4 << 20];
        let t = Instant::now();
        let o = Run::new("sh", Duration::from_secs(10)).args(["-c", "exit 0"]).input(&big).run().unwrap();
        assert!(o.status.success());
        assert!(t.elapsed() < Duration::from_secs(5));
    }

    fn alive(pid: i32) -> bool {
        // gone, or a zombie waiting for its new parent to reap it
        std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .is_ok_and(|s| s.rsplit_once(") ").is_some_and(|(_, rest)| !rest.starts_with('Z')))
    }

    #[test]
    fn a_timeout_kills_what_the_program_started() {
        let dir = tempfile::tempdir().unwrap();
        let pidfile = dir.path().join("pid");
        let script = format!("sleep 30 & echo $! > {}; wait", pidfile.display());
        let e = Run::new("sh", Duration::from_millis(300)).args(["-c", &script]).run().unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::TimedOut);
        let pid: i32 = std::fs::read_to_string(&pidfile).unwrap().trim().parse().unwrap();
        let t = Instant::now();
        while alive(pid) && t.elapsed() < Duration::from_secs(2) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(!alive(pid), "the background sleep {pid} outlived the timed-out hook");
    }

    #[test]
    fn runs_as_another_user_without_capabilities() {
        if !crate::sched::is_root() {
            return;
        }
        let nobody = Credentials::lookup("nobody").unwrap();
        assert!(!nobody.is_root());
        assert_eq!(Credentials::lookup(&nobody.uid.to_string()).unwrap().name, nobody.name);
        let o = Run::new("sh", Duration::from_secs(5))
            .args(["-c", "id -u; id -g; echo $HOME $USER; pwd; grep -E '^Cap(Eff|Prm|Amb)' /proc/self/status"])
            .user(Some(&nobody))
            .run()
            .unwrap();
        let out = text(&o.stdout);
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines[0], nobody.uid.to_string(), "{out}");
        assert_eq!(lines[1], nobody.gid.to_string(), "{out}");
        assert_eq!(lines[2], format!("{} {}", nobody.home.display(), nobody.name));
        assert_eq!(lines[3], "/");
        for cap in &lines[4..] {
            assert!(cap.ends_with("0000000000000000"), "capability left after the switch: {cap}");
        }
        assert!(Credentials::lookup("no-such-user-warden").unwrap_err().kind() == io::ErrorKind::NotFound);
        let root = Credentials::lookup("root").unwrap();
        assert!(root.is_root());
        let o = Run::new("id", Duration::from_secs(5)).args(["-u"]).user(Some(&root)).run().unwrap();
        assert_eq!(text(&o.stdout).trim(), "0");
    }

    #[test]
    fn background_child_holding_the_pipes_does_not_hang_us() {
        let t = Instant::now();
        let o = Run::new("sh", Duration::from_secs(10)).args(["-c", "sleep 3 & echo started"]).run().unwrap();
        assert_eq!(text(&o.stdout).trim(), "started");
        assert!(t.elapsed() < Duration::from_secs(2), "{:?}", t.elapsed());
    }
}
