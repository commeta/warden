//! Helpers shared by detectors.

use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use warden_core::ProcessRef;
use warden_sys::process;

pub use warden_sys::cmd::{run_cmd, which};
pub use warden_sys::process::exe_basename;

/// Build a [`ProcessRef`] for a live PID (None if it vanished).
pub fn process_ref(pid: i32, users: &dyn Fn(u32) -> String) -> Option<ProcessRef> {
    let st = process::read_stat(pid).ok()?;
    let ss = process::read_status(pid).ok();
    let uid = ss.as_ref().map(|s| s.uid[0]);
    let cgroup = process::cgroup(pid);
    Some(ProcessRef {
        pid,
        start_time: st.starttime,
        comm: st.comm,
        exe: process::exe(pid),
        cmdline: process::cmdline(pid, 1024),
        uid,
        user: uid.map(users),
        ppid: Some(st.ppid),
        container: cgroup.as_deref().and_then(warden_sys::cgroup::container_of),
        cgroup,
    })
}

/// Does a path contain glob characters?
pub fn is_glob(p: &Path) -> bool {
    p.to_string_lossy().contains(['*', '?', '['])
}

/// A glob component (`*_audit.log`, `site?`, `[ab]*`) as an anchored regex
/// where each `*` is a capture group.
fn component_regex(pat: &str) -> Option<regex::Regex> {
    let mut re = String::from("^");
    let mut chars = pat.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '*' => re.push_str("([^/]*)"),
            '?' => re.push_str("[^/]"),
            '[' => {
                let mut class = String::from("[");
                if chars.peek() == Some(&'!') {
                    chars.next();
                    class.push('^');
                }
                let mut closed = false;
                for c in chars.by_ref() {
                    if c == ']' {
                        closed = true;
                        break;
                    }
                    if c == '\\' || c == '[' {
                        class.push('\\');
                    }
                    class.push(c);
                }
                if !closed {
                    return None;
                }
                class.push(']');
                re.push_str(&class);
            }
            c => re.push_str(&regex::escape(&c.to_string())),
        }
    }
    re.push('$');
    regex::Regex::new(&re).ok()
}

/// The existing paths a glob matches (`*`, `?` and `[…]` within a path
/// component; a leading dot is matched only explicitly), sorted, at most
/// `limit`, each with what its `*`s matched. A symlink a non-root user owns
/// is never followed or returned: a site user must not be able to point a
/// root daemon at a file of his choosing.
pub fn expand_glob(pattern: &Path, limit: usize) -> Vec<(PathBuf, Vec<String>)> {
    use std::path::Component;
    let mut cur: Vec<(PathBuf, Vec<String>)> = vec![(PathBuf::from("/"), Vec::new())];
    if !pattern.is_absolute() {
        return Vec::new();
    }
    for comp in pattern.components() {
        let Component::Normal(name) = comp else { continue };
        let name = name.to_string_lossy();
        if !name.contains(['*', '?', '[']) {
            for (p, _) in cur.iter_mut() {
                p.push(&*name);
            }
            continue;
        }
        let Some(re) = component_regex(&name) else { return Vec::new() };
        let mut next = Vec::new();
        for (dir, caps) in &cur {
            let Ok(rd) = std::fs::read_dir(dir) else { continue };
            let mut names: Vec<String> = rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
            names.sort();
            for n in names {
                if n.starts_with('.') && !name.starts_with('.') {
                    continue;
                }
                let Some(m) = re.captures(&n) else { continue };
                let p = dir.join(&n);
                if std::fs::symlink_metadata(&p).is_ok_and(|md| md.file_type().is_symlink() && md.uid() != 0) {
                    continue;
                }
                let mut c = caps.clone();
                c.extend(m.iter().skip(1).flatten().map(|g| g.as_str().to_owned()));
                next.push((p, c));
                if next.len() >= limit {
                    break;
                }
            }
        }
        cur = next;
    }
    cur.retain(|(p, _)| std::fs::symlink_metadata(p).is_ok_and(|md| !(md.file_type().is_symlink() && md.uid() != 0)));
    cur.truncate(limit);
    cur
}

/// `{1}`, `{2}`… in `template` replaced with the captures of a glob match.
pub fn fill_captures(template: &str, caps: &[String]) -> String {
    let mut out = template.to_owned();
    for (i, c) in caps.iter().enumerate() {
        out = out.replace(&format!("{{{}}}", i + 1), c);
    }
    out
}

/// The accounts web code runs as (`process.web_users`): their UIDs and the
/// groups they belong to, for deciding whether a log can be forged by
/// whoever controls a webshell.
#[derive(Debug, Clone, Default)]
pub struct WebPrincipals {
    uids: std::collections::HashMap<u32, String>,
    gids: std::collections::HashSet<u32>,
}

impl WebPrincipals {
    pub fn load(web_users: &[String]) -> Self {
        let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
        let group = std::fs::read_to_string("/etc/group").unwrap_or_default();
        Self::from_text(web_users, &passwd, &group)
    }

    pub fn from_text(web_users: &[String], passwd: &str, group: &str) -> Self {
        let mut p = Self::default();
        for e in warden_sys::users::parse_passwd(passwd) {
            if web_users.contains(&e.name) {
                p.uids.insert(e.uid, e.name);
                p.gids.insert(e.gid);
            }
        }
        for line in group.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() < 4 {
                continue;
            }
            let Ok(gid) = f[2].parse::<u32>() else { continue };
            if f[3].split(',').any(|m| web_users.iter().any(|u| u == m.trim())) {
                p.gids.insert(gid);
            }
        }
        p
    }

    /// Can a web account change what `path` says — write the file, or
    /// replace it through a directory on the way? Returns why, or `None`.
    ///
    /// A log a web server opens as root and its workers write through an
    /// inherited descriptor passes; a worker that runs PHP in-process
    /// (`mod_php`) can still write through that descriptor. The check
    /// bounds what a webshell can forge; it does not make a log a witness.
    pub fn can_write(&self, path: &Path) -> Option<String> {
        use std::os::unix::fs::PermissionsExt;
        let lmd = std::fs::symlink_metadata(path).ok()?; // not there (yet): nothing to forge
        if lmd.file_type().is_symlink()
            && let Some(u) = self.uids.get(&lmd.uid())
        {
            return Some(format!("{} is a symlink owned by {u}", path.display()));
        }
        let md = std::fs::metadata(path).unwrap_or(lmd);
        let what = |md: &std::fs::Metadata, p: &Path, dir: bool| -> Option<String> {
            let mode = md.permissions().mode();
            let sticky = dir && mode & 0o1000 != 0;
            let name = if dir { format!("its directory {}", p.display()) } else { p.display().to_string() };
            if let Some(u) = self.uids.get(&md.uid()) {
                return Some(format!("{name} is owned by {u}"));
            }
            if mode & 0o002 != 0 && !sticky {
                return Some(format!("{name} is writable by everybody"));
            }
            if mode & 0o020 != 0 && !sticky && self.gids.contains(&md.gid()) {
                return Some(format!("{name} is writable by group {}, which a web user belongs to", md.gid()));
            }
            None
        };
        if let Some(w) = what(&md, path, false) {
            return Some(w);
        }
        let mut dir = path.parent();
        while let Some(d) = dir {
            if let Ok(dm) = std::fs::metadata(d)
                && let Some(w) = what(&dm, d, true)
            {
                return Some(w);
            }
            dir = d.parent();
        }
        None
    }
}

/// The longest line [`FileTail`] hands out whole. A longer one keeps its
/// first [`LINE_HEAD`] and last [`LINE_TAIL`] bytes with a marker between
/// them: an audit record padded with a large request body must not grow
/// the reader without bound, and must not vanish either — the client
/// address sits at the head of a JSON audit record and the rule messages
/// at its tail.
pub const LINE_HEAD: usize = 64 * 1024;
pub const LINE_TAIL: usize = 256 * 1024;
/// What stands for the elided middle of an overlong line.
pub const ELIDED: &str = "\u{2026}[elided]\u{2026}";

/// Follows a growing text file across rotation (rename + create) and
/// truncation (copytruncate). Starts at the end of the file.
///
/// Lines are read as bytes: a line that is not valid UTF-8 (a raw header
/// byte in an audit record) is handed out with the bad bytes replaced, not
/// dropped — an attacker must not be able to hide a request from Warden
/// with one `\xff` in its User-Agent.
#[derive(Debug)]
pub struct FileTail {
    path: PathBuf,
    reader: Option<BufReader<std::fs::File>>,
    ino: u64,
    pos: u64,
    partial: Vec<u8>,
    /// Bytes of the current partial line, including elided ones.
    partial_len: u64,
}

impl FileTail {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let mut t = Self::closed(path.into());
        t.open(true);
        t
    }

    /// A tail that reads an existing file from its beginning: for a file
    /// that appeared after Warden started (a log of a new site), whose
    /// first lines are as new as the ones that follow.
    pub fn from_start(path: impl Into<PathBuf>) -> Self {
        let mut t = Self::closed(path.into());
        t.open(false);
        t
    }

    fn closed(path: PathBuf) -> Self {
        Self { path, reader: None, ino: 0, pos: 0, partial: Vec::new(), partial_len: 0 }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn open(&mut self, at_end: bool) {
        self.reader = None;
        // an unfinished last line of the previous file is not the start of
        // the first line of this one
        self.partial.clear();
        self.partial_len = 0;
        if let Ok(mut f) = std::fs::File::open(&self.path) {
            let md = f.metadata().ok();
            self.ino = md.as_ref().map(|m| m.ino()).unwrap_or(0);
            self.pos = if at_end { md.map(|m| m.len()).unwrap_or(0) } else { 0 };
            if f.seek(SeekFrom::Start(self.pos)).is_ok() {
                self.reader = Some(BufReader::with_capacity(64 * 1024, f));
            }
        }
    }

    /// Return complete new lines (at most `max`).
    pub fn poll(&mut self, max: usize) -> Vec<String> {
        // Rotation / truncation checks.
        match std::fs::metadata(&self.path) {
            Ok(_) if self.reader.is_none() => self.open(false),
            Ok(md) if md.ino() != self.ino => {
                // Drain the old file first, then switch.
                let mut lines = self.read_lines(max);
                self.open(false);
                lines.extend(self.read_lines(max.saturating_sub(lines.len())));
                return lines;
            }
            Ok(md) if md.len() < self.pos => self.open(false),
            Err(_) => return Vec::new(),
            _ => {}
        }
        self.read_lines(max)
    }

    /// Byte offset of the next unread byte (for tests and status).
    pub fn position(&self) -> u64 {
        self.pos
    }

    fn take_line(&mut self) -> String {
        let elided = self.partial_len > self.partial.len() as u64;
        let mut bytes = std::mem::take(&mut self.partial);
        self.partial_len = 0;
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
        if elided {
            let head = LINE_HEAD.min(bytes.len());
            let tail = bytes.len().saturating_sub(LINE_TAIL).max(head);
            let mut s = String::from_utf8_lossy(&bytes[..head]).into_owned();
            s.push_str(ELIDED);
            s.push_str(&String::from_utf8_lossy(&bytes[tail..]));
            s
        } else {
            match String::from_utf8(bytes) {
                Ok(s) => s,
                Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
            }
        }
    }

    /// Append to the partial line, keeping its head and tail only.
    fn push_partial(&mut self, chunk: &[u8]) {
        self.partial_len += chunk.len() as u64;
        self.partial.extend_from_slice(chunk);
        if self.partial.len() > LINE_HEAD + 2 * LINE_TAIL {
            let keep_from = self.partial.len() - LINE_TAIL;
            self.partial.drain(LINE_HEAD..keep_from);
        }
    }

    fn read_lines(&mut self, max: usize) -> Vec<String> {
        let mut out = Vec::new();
        while out.len() < max {
            let Some(r) = self.reader.as_mut() else { break };
            let (used, newline) = match r.fill_buf() {
                Ok([]) => break,
                Ok(buf) => match buf.iter().position(|&b| b == b'\n') {
                    Some(i) => {
                        let line = buf[..i].to_vec();
                        self.push_partial(&line);
                        (i + 1, true)
                    }
                    None => {
                        let chunk = buf.to_vec();
                        self.push_partial(&chunk);
                        (chunk.len(), false)
                    }
                },
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            };
            if let Some(r) = self.reader.as_mut() {
                r.consume(used);
            }
            self.pos += used as u64;
            if newline {
                out.push(self.take_line());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn tail_follows_rotation_and_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.log");
        std::fs::write(&p, "old line\n").unwrap();
        let mut t = FileTail::new(&p);
        assert!(t.poll(100).is_empty());
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        write!(f, "one\ntw").unwrap();
        assert_eq!(t.poll(100), vec!["one"]);
        writeln!(f, "o").unwrap();
        assert_eq!(t.poll(100), vec!["two"]);
        // rotation
        std::fs::rename(&p, dir.path().join("a.log.1")).unwrap();
        writeln!(f, "late").unwrap();
        std::fs::write(&p, "fresh\n").unwrap();
        assert_eq!(t.poll(100), vec!["late", "fresh"]);
        // truncation
        std::fs::write(&p, "x\n").unwrap();
        assert_eq!(t.poll(100), vec!["x"]);
    }

    /// N15: a line that is not UTF-8 used to be dropped silently (and the
    /// position drifted), so one raw byte in a logged header hid the whole
    /// audit record from Warden.
    #[test]
    fn invalid_utf8_lines_are_kept_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.log");
        std::fs::write(&p, "").unwrap();
        let mut t = FileTail::new(&p);
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"{\"ua\":\"\xff\xfe\"}\r\nnext\n").unwrap();
        let lines = t.poll(100);
        assert_eq!(lines, vec!["{\"ua\":\"\u{fffd}\u{fffd}\"}".to_owned(), "next".to_owned()]);
        assert_eq!(t.position(), std::fs::metadata(&p).unwrap().len(), "no drift");
    }

    #[test]
    fn overlong_lines_keep_head_and_tail() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("audit.log");
        std::fs::write(&p, "").unwrap();
        let mut t = FileTail::new(&p);
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        let body = "x".repeat(5 * 1024 * 1024);
        // written in pieces, read in between: the partial line stays bounded
        write!(f, "HEAD{body}").unwrap();
        assert!(t.poll(10).is_empty());
        assert!(t.partial.len() <= LINE_HEAD + 2 * LINE_TAIL);
        writeln!(f, "{body}TAIL").unwrap();
        writeln!(f, "short").unwrap();
        let lines = t.poll(10);
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("HEADxxx") && lines[0].ends_with("xxxTAIL"));
        assert!(lines[0].contains(ELIDED));
        assert_eq!(lines[0].len(), LINE_HEAD + ELIDED.len() + LINE_TAIL);
        assert_eq!(lines[1], "short");
    }

    #[test]
    fn who_can_write_a_log() {
        use std::os::unix::fs::PermissionsExt;
        let me = unsafe { libc::geteuid() };
        let passwd = format!("root:x:0:0::/root:/bin/sh\nme:x:{me}:4242::/:/bin/sh\nsyslog:x:104:110::/:/bin/false\n");
        let group = "adm:x:4:syslog\nweb:x:4343:me\nsyslog:x:110:\n";
        let web = WebPrincipals::from_text(&["me".to_owned()], &passwd, group);
        let quiet = WebPrincipals::from_text(&["nobody-here".to_owned()], &passwd, group);
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let p = dir.path().join("audit.log");
        std::fs::write(&p, "").unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
        // the file (and its directory) belong to the test's user
        assert!(web.can_write(&p).unwrap().contains("owned by me"), "{:?}", web.can_write(&p));
        assert_eq!(quiet.can_write(&p), None, "a non-web owner (syslog, rsyslog's files) is not a web user");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(quiet.can_write(&p).unwrap().contains("everybody"));
        if me == 0 {
            // root's file in a directory a web group can write to
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o640)).unwrap();
            std::os::unix::fs::chown(dir.path(), None, Some(4343)).unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
            let web = WebPrincipals::from_text(&["www".to_owned()], "www:x:33:33::/:/bin/false\n", "web:x:4343:www\n");
            assert!(web.can_write(&p).unwrap().contains("which a web user belongs to"));
            // Ubuntu's /var/log is root:syslog 0775: a system group is fine
            std::os::unix::fs::chown(dir.path(), None, Some(110)).unwrap();
            assert_eq!(web.can_write(&p), None);
        }
        assert!(web.can_write(&dir.path().join("missing")).is_none());
    }

    #[test]
    fn globs_expand_per_component_with_captures() {
        let d = tempfile::tempdir().unwrap();
        for site in ["alpha.example", "beta.example", ".hidden"] {
            std::fs::create_dir_all(d.path().join(site).join("logs")).unwrap();
            std::fs::write(d.path().join(site).join("logs/modsec_audit.log"), "").unwrap();
        }
        std::fs::write(d.path().join("alpha.example/logs/error.log"), "").unwrap();
        let pat = d.path().join("*/logs/modsec_*.log");
        let got = expand_glob(&pat, 100);
        let names: Vec<(String, Vec<String>)> =
            got.iter().map(|(p, c)| (p.strip_prefix(d.path()).unwrap().display().to_string(), c.clone())).collect();
        assert_eq!(
            names,
            vec![
                (
                    "alpha.example/logs/modsec_audit.log".to_owned(),
                    vec!["alpha.example".to_owned(), "audit".to_owned()]
                ),
                ("beta.example/logs/modsec_audit.log".to_owned(), vec!["beta.example".to_owned(), "audit".to_owned()]),
            ]
        );
        assert_eq!(fill_captures("site-{1}", &got[0].1), "site-alpha.example");
        assert_eq!(expand_glob(&d.path().join("[ab]*/logs/error.log"), 100).len(), 1);
        assert_eq!(expand_glob(&d.path().join("*/logs/modsec_audit.log"), 1).len(), 1, "limit");
        assert!(expand_glob(&d.path().join("[unclosed/x"), 10).is_empty());
        assert!(is_glob(&pat) && !is_glob(Path::new("/var/log/apache2/modsec_audit.log")));
    }

    #[test]
    fn a_new_file_is_read_from_its_start() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("new.log");
        std::fs::write(&p, "first\n").unwrap();
        assert_eq!(FileTail::from_start(&p).poll(10), vec!["first"]);
        assert!(FileTail::new(&p).poll(10).is_empty());
    }
}
