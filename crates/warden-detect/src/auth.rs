//! Authentication events: SSH brute force (with automatic blocking),
//! successful logins after brute force, root logins, sudo/su failures,
//! account and group changes. Source: journald (preferred) or auth.log.

use crate::runtime::{SensorState, Shared, Sink};
use crate::util::{FileTail, which};
use regex::Regex;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use warden_core::config::{AuthConfig, AuthSource};
use warden_core::net::{IpSet, Key};
use warden_core::ratelimit::KeyedWindow;
use warden_core::{ActionSpec, Event, Severity, Subject};

struct Patterns {
    failed: Regex,
    invalid: Regex,
    max_attempts: Regex,
    closed_preauth: Regex,
    accepted: Regex,
    sudo_fail: Regex,
    sudo_cmd: Regex,
    su_fail: Regex,
    useradd: Regex,
    usermod_group: Regex,
    passwd: Regex,
    userdel: Regex,
    syslog_line: Regex,
}

impl Patterns {
    /// Every sshd pattern is anchored at both ends, and the user name is
    /// `.*`: the name is chosen by the client and may itself contain
    /// " from 8.8.8.8 port 1", but the address sshd appends after it is
    /// always the *last* one on the line, which is the one greedy `.*` leaves.
    fn new() -> Self {
        let r = |s: &str| Regex::new(s).expect("static regex");
        const IP: &str = r"(?P<ip>[0-9a-fA-F.:]+)";
        Self {
            failed: r(&format!(
                r"^Failed (?:password|publickey|keyboard-interactive/pam|none) for (?P<invalid>invalid user )?(?P<user>.*) from {IP} port \d+(?: ssh\d)?(?::.*)?$"
            )),
            invalid: r(&format!(r"^Invalid user (?P<user>.*) from {IP}(?: port \d+)?$")),
            max_attempts: r(&format!(
                r"^(?:error: )?(?:maximum authentication attempts exceeded|Too many authentication failures) for (?:invalid user )?(?P<user>.*) from {IP} port \d+(?: ssh\d)?(?: \[preauth\])?$"
            )),
            closed_preauth: r(&format!(
                r"^(?:Connection closed by|Disconnected from|Disconnected by) (?:authenticating|invalid) user (?P<user>.*) {IP} port \d+ \[preauth\]$"
            )),
            accepted: r(&format!(r"^Accepted (?P<method>\S+) for (?P<user>.+) from {IP} port \d+(?: ssh\d)?(?::.*)?$")),
            sudo_fail: r(
                r"^\s*(?P<user>\S+) : (?:(?P<n>\d+) incorrect password attempts?|user NOT in sudoers|command not allowed)",
            ),
            sudo_cmd: r(r"^\s*(?P<user>\S+) : (?:TTY=\S+ ; )?PWD=.* ; USER=(?P<target>\S+) ; COMMAND=(?P<cmd>.*)$"),
            su_fail: r(
                r"(?:FAILED (?:su|SU) for (?P<target>\S+) by (?P<user>\S+)|pam_unix\(su(?:-l)?:auth\): authentication failure.*ruser=(?P<ruser>\S*))",
            ),
            useradd: r(r"^new user: name=(?P<user>[^,]+), UID=(?P<uid>\d+)"),
            usermod_group: r(
                r"^add '(?P<user>[^']+)' to (?:shadow )?group '(?P<group>sudo|wheel|admin|root|adm|docker|lxd|libvirt|disk|shadow)'",
            ),
            passwd: r(r"password (?:changed|for) (?:for )?'?(?P<user>[^'\s]+)'?"),
            userdel: r(r"^delete user '(?P<user>[^']+)'"),
            syslog_line: r(
                r"^(?:[A-Z][a-z]{2}\s+\d+\s+[\d:]+|\S+)\s+\S+\s+(?P<ident>[^\s\[:]+)(?:\[\d+\])?:\s(?P<msg>.*)$",
            ),
        }
    }
}

/// Sources (addresses) remembered for "login succeeded after failures".
const MAX_TRACKED_SOURCES: usize = 50_000;
/// User names kept per source for the brute-force report.
const MAX_USERS_PER_SOURCE: usize = 20;
const MAX_USER_CHARS: usize = 64;

pub struct AuthAnalyzer {
    cfg: AuthConfig,
    p: Patterns,
    web_users: HashSet<String>,
    allow: IpSet,
    /// Per [`Key`]: a brute force spread over the addresses of one IPv6 /64
    /// is one source (N25).
    failures: KeyedWindow<Key>,
    users_tried: HashMap<Key, BTreeSet<String>>,
    /// Sources that recently failed (for "success after brute force").
    recent_fail: HashMap<Key, (Instant, usize)>,
    ipv6_prefix: u8,
}

impl AuthAnalyzer {
    pub fn new(cfg: &AuthConfig, web_users: &[String], firewall_allow: &[String]) -> Self {
        let allow_list: Vec<String> = cfg.allowlist.iter().chain(firewall_allow).cloned().collect();
        Self {
            failures: KeyedWindow::new(cfg.ssh_window),
            cfg: cfg.clone(),
            p: Patterns::new(),
            web_users: web_users.iter().cloned().collect(),
            allow: IpSet::new(&allow_list),
            users_tried: HashMap::new(),
            recent_fail: HashMap::new(),
            ipv6_prefix: warden_core::net::DEFAULT_IPV6_PREFIX,
        }
    }

    /// Count IPv6 sources by the network of `prefix` bits
    /// (`actions.firewall.ipv6_prefix`).
    pub fn with_ipv6_prefix(mut self, prefix: u8) -> Self {
        self.ipv6_prefix = prefix;
        self
    }

    /// Split a classic syslog line into (identifier, message).
    pub fn split_syslog<'a>(&self, line: &'a str) -> Option<(&'a str, &'a str)> {
        let c = self.p.syslog_line.captures(line)?;
        Some((c.name("ident")?.as_str(), c.name("msg")?.as_str()))
    }

    /// Forget sources that went quiet. Called where entries are added: a
    /// flood of failures from many addresses (an IPv6 /64 has plenty) must
    /// not be able to grow the tables without bound.
    fn housekeeping(&mut self, now: Instant) {
        if self.recent_fail.len() <= MAX_TRACKED_SOURCES {
            return;
        }
        self.recent_fail.retain(|_, (t, _)| now.saturating_duration_since(*t) < Duration::from_secs(3600));
        if self.recent_fail.len() > MAX_TRACKED_SOURCES {
            self.recent_fail.clear(); // everything is recent: start over rather than scan again on every line
        }
        let live = &self.recent_fail;
        self.users_tried.retain(|ip, _| live.contains_key(ip));
    }

    fn ssh_failure(&mut self, ip: &str, user: &str, now: Instant) -> Vec<Event> {
        let Ok(ip) = ip.parse::<IpAddr>() else { return vec![] };
        let ip = warden_core::net::canonical(ip);
        let key = Key::of(ip, self.ipv6_prefix);
        self.housekeeping(now);
        let n = self.failures.add(key, now);
        let e = self.recent_fail.entry(key).or_insert((now, 0));
        *e = (now, e.1 + 1);
        let tried = self.users_tried.entry(key).or_default();
        if tried.len() < MAX_USERS_PER_SOURCE {
            // the name is the client's: keep a bounded prefix
            tried.insert(user.chars().take(MAX_USER_CHARS).collect());
        }
        if n < self.cfg.ssh_max_failures {
            return vec![];
        }
        self.failures.reset(&key);
        let users: Vec<String> = self.users_tried.remove(&key).unwrap_or_default().into_iter().collect();
        let allowlisted = self.allow.contains(&ip);
        let mut ev = Event::new(
            "security.ssh_bruteforce",
            Severity::Warning,
            format!("SSH brute force from {key}: {n} failures within {}s", self.cfg.ssh_window.as_secs()),
        )
        // the last address; the responder blocks its network (`prefix`)
        .subject(Subject::Ip { addr: ip })
        .fingerprint(format!("security.ssh_bruteforce:{key}"))
        .detail("failures", n)
        .detail("users_tried", users)
        .detail("ip", ip.to_string());
        if key.is_network() {
            ev = ev.detail("prefix", key.to_string());
        }
        if allowlisted {
            ev = ev.detail("allowlisted", true);
        } else if self.cfg.ssh_block {
            ev = ev.actions(vec![ActionSpec::BlockIp { ttl: Some(self.cfg.ssh_block_ttl) }]);
        } else {
            ev = ev.detail(warden_core::event::IP_BLOCK_OFF, "auth.ssh_block = false");
        }
        vec![ev]
    }

    pub fn analyze(&mut self, ident: &str, msg: &str, now: Instant) -> Vec<Event> {
        let p = &self.p;
        match ident {
            "sshd" | "sshd-session" | "sshd-auth" => {
                if let Some(c) = p.failed.captures(msg).or_else(|| p.max_attempts.captures(msg)) {
                    let (ip, user) = (c["ip"].to_owned(), c["user"].to_owned());
                    return self.ssh_failure(&ip, &user, now);
                }
                if let Some(c) = p.invalid.captures(msg).or_else(|| p.closed_preauth.captures(msg)) {
                    let (ip, user) = (c["ip"].to_owned(), c["user"].to_owned());
                    return self.ssh_failure(&ip, &user, now);
                }
                if let Some(c) = p.accepted.captures(msg) {
                    let user = c["user"].to_owned();
                    let method = c["method"].to_owned();
                    let Ok(ip) = c["ip"].parse::<IpAddr>() else { return vec![] };
                    let ip = warden_core::net::canonical(ip);
                    let mut out = Vec::new();
                    // failures from anywhere in the address's network count
                    let prior = self
                        .recent_fail
                        .get(&Key::of(ip, self.ipv6_prefix))
                        .filter(|(t, _)| now.saturating_duration_since(*t) < Duration::from_secs(3600))
                        .map(|x| x.1)
                        .unwrap_or(0);
                    if prior >= 3 {
                        out.push(
                            Event::new(
                                "security.bruteforce_success",
                                Severity::Critical,
                                format!("successful SSH login as {user} from {ip} after {prior} failures"),
                            )
                            .subject(Subject::User { name: user.clone() })
                            .fingerprint(format!("security.bruteforce_success:{ip}:{user}"))
                            .detail("ip", ip.to_string())
                            .detail("method", method.clone())
                            .detail("hint", "credentials may be compromised: verify the session (`who`, `last`), rotate the password/keys"),
                        );
                    }
                    if user == "root" && self.cfg.alert_root_login {
                        out.push(
                            Event::new(
                                "auth.root_login",
                                Severity::Warning,
                                format!("root logged in via SSH from {ip} ({method})"),
                            )
                            .subject(Subject::User { name: user.clone() })
                            .fingerprint(format!("auth.root_login:{ip}"))
                            .detail("ip", ip.to_string()),
                        );
                    } else {
                        out.push(
                            Event::new(
                                "auth.login",
                                Severity::Info,
                                format!("{user} logged in via SSH from {ip} ({method})"),
                            )
                            .subject(Subject::User { name: user.clone() })
                            .fingerprint(format!("auth.login:{user}:{ip}"))
                            .detail("ip", ip.to_string()),
                        );
                    }
                    return out;
                }
            }
            "sudo" => {
                if let Some(c) = p.sudo_fail.captures(msg)
                    && self.cfg.alert_sudo_failure
                {
                    let user = c["user"].to_owned();
                    let sev = if self.web_users.contains(&user) { Severity::Critical } else { Severity::Warning };
                    return vec![
                        Event::new("auth.sudo_failure", sev, format!("sudo failure for {user}: {}", msg.trim()))
                            .subject(Subject::User { name: user.clone() })
                            .fingerprint(format!("auth.sudo_failure:{user}")),
                    ];
                }
                if let Some(c) = p.sudo_cmd.captures(msg) {
                    let user = c["user"].to_owned();
                    if self.web_users.contains(&user) {
                        return vec![
                            Event::new(
                                "security.web_user_sudo",
                                Severity::Critical,
                                format!("web account {user} used sudo"),
                            )
                            .subject(Subject::User { name: user.clone() })
                            .fingerprint(format!("security.web_user_sudo:{user}"))
                            .detail("command", c["cmd"].to_owned())
                            .detail("target", c["target"].to_owned()),
                        ];
                    }
                    return vec![
                        Event::new(
                            "auth.sudo",
                            Severity::Info,
                            format!("{user} ran as {}: {}", &c["target"], &c["cmd"]),
                        )
                        .subject(Subject::User { name: user.clone() })
                        .fingerprint(format!("auth.sudo:{user}:{}", &c["cmd"])),
                    ];
                }
            }
            "su" => {
                if let Some(c) = p.su_fail.captures(msg)
                    && self.cfg.alert_sudo_failure
                {
                    let user = c.name("user").or(c.name("ruser")).map(|m| m.as_str()).unwrap_or("?").to_owned();
                    return vec![
                        Event::new(
                            "auth.su_failure",
                            Severity::Warning,
                            format!("su authentication failure by {user}"),
                        )
                        .subject(Subject::User { name: user.clone() })
                        .fingerprint(format!("auth.su_failure:{user}")),
                    ];
                }
            }
            "useradd" | "adduser" | "usermod" | "userdel" | "passwd" | "chpasswd" | "gpasswd" | "groupadd"
            | "chage" => {
                if !self.cfg.alert_account_changes {
                    return vec![];
                }
                if let Some(c) = p.useradd.captures(msg) {
                    let uid: u32 = c["uid"].parse().unwrap_or(u32::MAX);
                    let user = c["user"].to_owned();
                    let (kind, sev) = if uid == 0 {
                        ("security.uid0_account", Severity::Critical)
                    } else {
                        ("auth.account_created", Severity::Warning)
                    };
                    return vec![
                        Event::new(kind, sev, format!("user account created: {user} (uid {uid})"))
                            .subject(Subject::User { name: user.clone() })
                            .fingerprint(format!("{kind}:{user}")),
                    ];
                }
                if let Some(c) = p.usermod_group.captures(msg) {
                    let (user, group) = (c["user"].to_owned(), c["group"].to_owned());
                    return vec![
                        Event::new(
                            "auth.privileged_group",
                            Severity::Warning,
                            format!("{user} added to privileged group {group}"),
                        )
                        .subject(Subject::User { name: user.clone() })
                        .fingerprint(format!("auth.privileged_group:{user}:{group}")),
                    ];
                }
                if let Some(c) = p.userdel.captures(msg) {
                    let user = c["user"].to_owned();
                    return vec![
                        Event::new("auth.account_deleted", Severity::Notice, format!("user account deleted: {user}"))
                            .subject(Subject::User { name: user.clone() })
                            .fingerprint(format!("auth.account_deleted:{user}")),
                    ];
                }
                if (ident.starts_with("passwd") || ident == "chpasswd")
                    && let Some(c) = p.passwd.captures(msg)
                {
                    let user = c["user"].to_owned();
                    return vec![
                        Event::new("auth.password_changed", Severity::Notice, format!("password changed for {user}"))
                            .subject(Subject::User { name: user.clone() })
                            .fingerprint(format!("auth.password_changed:{user}")),
                    ];
                }
            }
            _ => {}
        }
        vec![]
    }
}

/// Decode journald's `MESSAGE` (string, or byte array for non-UTF-8).
fn journal_message(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(a) => {
            let bytes: Vec<u8> = a.iter().filter_map(|x| x.as_u64().map(|b| b as u8)).collect();
            Some(String::from_utf8_lossy(&bytes).into_owned())
        }
        _ => None,
    }
}

/// Can a journal entry be believed to come from the program named by its
/// `SYSLOG_IDENTIFIER`? The identifier and the text are whatever the sender
/// wrote — any local user can `logger -t sshd -p authpriv.info "Failed
/// password for root from <someone's address> port 1 ssh2"` — so what is
/// trusted is what journald read from the kernel: the sender's UID, or its
/// executable, which must be a system binary named like the identifier.
/// (`_EXE` can be missing for a process that has already exited, which is how
/// `logger` usually looks, so a missing `_EXE` is not trusted.)
fn journal_sender_trusted(v: &serde_json::Value, ident: &str) -> bool {
    let field = |k: &str| v.get(k).and_then(|x| x.as_str());
    if field("_UID") == Some("0") {
        return true; // root can write anything it likes to the journal anyway
    }
    let Some(exe) = field("_EXE") else { return false };
    let in_system_dir = ["/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/"].iter().any(|d| exe.starts_with(d));
    in_system_dir && exe.rsplit('/').next() == Some(ident)
}

/// Is journald there to read from?
fn journal_available() -> bool {
    which("journalctl").is_some() && std::path::Path::new("/run/systemd/journal").exists()
}

/// Lines of the auth log *file* carry no sender: what they say may come from
/// any local user (`logger -t sshd`). Unless the operator trusts the file
/// (`auth.trust_file`), they are evidence, not grounds for a block (N4).
pub fn untrusted_file_line(mut ev: Event) -> Event {
    if ev.actions.iter().any(|a| matches!(a, ActionSpec::BlockIp { .. })) {
        ev.actions.retain(|a| !matches!(a, ActionSpec::BlockIp { .. }));
        ev = ev.detail(
            warden_core::event::IP_BLOCK_OFF,
            "read from the auth log file, which does not record who wrote a line (auth.trust_file = false)",
        );
    }
    ev.detail("log_source", "file")
}

/// Kills and reaps `journalctl` however the reader leaves (an error, a
/// reload, a panic in the analyzer): it must not outlive the sensor (N16).
struct ReapOnDrop(std::process::Child);

impl Drop for ReapOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub fn run_auth(shared: &Arc<Shared>, sink: &Sink) -> Result<(), String> {
    let cfg = shared.config();
    if !cfg.auth.enabled {
        return Ok(());
    }
    let generation = shared.generation();
    let mut an = AuthAnalyzer::new(&cfg.auth, &cfg.process.web_users, &cfg.actions.firewall.allowlist)
        .with_ipv6_prefix(cfg.actions.firewall.ipv6_prefix);
    let use_journal = match cfg.auth.source {
        AuthSource::Journal => true,
        AuthSource::File => false,
        // journald whenever it runs, even with a live auth.log next to it:
        // only the journal records who sent a line, and a line any user
        // can forge must not block an address (N4 of the 0.14.1 review;
        // 0.14.1 preferred a live auth.log because tailing it is cheaper).
        AuthSource::Auto => journal_available(),
    };
    let emit = |mut ev: Event| {
        ev.source = "auth".into();
        sink.emit(ev);
    };

    if use_journal {
        let child = Command::new("journalctl")
            .args([
                "-f",
                "-n",
                "0",
                "-q",
                "-o",
                "json",
                "--output-fields=MESSAGE,SYSLOG_IDENTIFIER,_UID,_EXE",
                "--no-pager",
                "SYSLOG_FACILITY=4",
                "SYSLOG_FACILITY=10",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("journalctl: {e}"))?;
        let mut child = ReapOnDrop(child);
        let out = child.0.stdout.take().ok_or("journalctl: no stdout")?;
        shared.set_sensor("auth", SensorState::Running);
        let mut reader = warden_sys::util::LineReader::new(out);
        while let Ok(line) = reader.next_line(Duration::from_secs(2)) {
            if shared.generation() != generation || shared.is_shutting_down() {
                return Err("configuration reloaded".into());
            }
            let Some(line) = line else { continue };
            let Ok(v) = serde_json::from_str::<serde_json::Value>(&line) else { continue };
            let ident = v.get("SYSLOG_IDENTIFIER").and_then(|x| x.as_str()).unwrap_or("");
            let Some(msg) = v.get("MESSAGE").and_then(journal_message) else { continue };
            if !journal_sender_trusted(&v, ident) {
                shared.metrics.inc("warden_auth_untrusted_lines_total", &[], 1.0);
                continue;
            }
            for ev in an.analyze(ident, &msg, Instant::now()) {
                emit(ev.detail("log_source", "journal"));
            }
        }
        drop(child);
        Err("journalctl exited".into())
    } else {
        let path = cfg.auth.auth_log.clone();
        if !path.exists() {
            return Err(format!("{} does not exist and journald is unavailable", path.display()));
        }
        let mut tail = FileTail::new(&path);
        shared.set_sensor("auth", SensorState::Running);
        loop {
            if shared.generation() != generation {
                return Err("configuration reloaded".into());
            }
            if shared.is_shutting_down() {
                return Ok(());
            }
            for line in tail.poll(5000) {
                if let Some((ident, msg)) = an.split_syslog(&line) {
                    let (ident, msg) = (ident.to_owned(), msg.to_owned());
                    for ev in an.analyze(&ident, &msg, Instant::now()) {
                        emit(if cfg.auth.trust_file {
                            ev.detail("log_source", "file")
                        } else {
                            untrusted_file_line(ev)
                        });
                    }
                }
            }
            // Poll once a second; a reload or shutdown wakes us at once.
            shared.wait_reload(generation, Duration::from_secs(1));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn an() -> AuthAnalyzer {
        let c = AuthConfig { ssh_max_failures: 3, ..Default::default() };
        AuthAnalyzer::new(&c, &["www-data".to_string()], &["10.0.0.0/8".to_string()])
    }

    #[test]
    fn bruteforce_then_block_then_success() {
        let mut a = an();
        let now = Instant::now();
        assert!(a.analyze("sshd", "Failed password for root from 203.0.113.9 port 4242 ssh2", now).is_empty());
        assert!(a.analyze("sshd", "Invalid user admin from 203.0.113.9 port 4243", now).is_empty());
        let v = a.analyze("sshd", "Failed password for invalid user oracle from 203.0.113.9 port 4244 ssh2", now);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].kind, "security.ssh_bruteforce");
        assert!(matches!(v[0].actions[0], ActionSpec::BlockIp { .. }));
        let users = v[0].details["users_tried"].as_array().unwrap();
        assert_eq!(users.len(), 3);
        let v = a.analyze("sshd", "Accepted password for deploy from 203.0.113.9 port 5000 ssh2", now);
        assert!(v.iter().any(|e| e.kind == "security.bruteforce_success" && e.severity == Severity::Critical));
    }

    /// N4: `logger -t sshd "Failed password for root from <victim>"` lands
    /// in auth.log like a real sshd line. Read from the file, it no longer
    /// blocks the address; the evidence still counts.
    #[test]
    fn lines_from_the_auth_log_file_do_not_block_by_themselves() {
        let mut a = an();
        let now = Instant::now();
        let mut out = Vec::new();
        for i in 0..3 {
            out.extend(a.analyze("sshd", &format!("Failed password for root from 198.51.100.77 port {i} ssh2"), now));
        }
        assert_eq!(out.len(), 1);
        let ev = untrusted_file_line(out.remove(0));
        assert_eq!(ev.kind, "security.ssh_bruteforce");
        assert!(ev.actions.is_empty(), "no block from a line anyone can write");
        assert!(ev.details.contains_key(warden_core::event::IP_BLOCK_OFF));
        assert_eq!(ev.details["log_source"], "file");
    }

    #[test]
    fn allowlisted_ip_is_not_blocked() {
        let mut a = an();
        let now = Instant::now();
        let mut last = vec![];
        for _ in 0..3 {
            last = a.analyze("sshd", "Failed password for bob from 10.1.2.3 port 1 ssh2", now);
        }
        assert_eq!(last.len(), 1);
        assert!(last[0].actions.is_empty());
        assert_eq!(last[0].details["allowlisted"], true);
    }

    #[test]
    fn sudo_and_accounts() {
        let mut a = an();
        let now = Instant::now();
        let v = a.analyze("sudo", "www-data : TTY=unknown ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash", now);
        assert_eq!(v[0].kind, "security.web_user_sudo");
        let v = a.analyze(
            "sudo",
            "    alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls",
            now,
        );
        assert_eq!(v[0].kind, "auth.sudo_failure");
        let v = a.analyze(
            "useradd",
            "new user: name=backdoor, UID=0, GID=0, home=/root, shell=/bin/bash, from=/dev/pts/0",
            now,
        );
        assert_eq!(v[0].kind, "security.uid0_account");
        let v = a.analyze("usermod", "add 'mallory' to group 'sudo'", now);
        assert_eq!(v[0].kind, "auth.privileged_group");
        let v = a.analyze("sshd", "Accepted publickey for root from 198.51.100.1 port 22 ssh2: ED25519 SHA256:x", now);
        assert_eq!(v[0].kind, "auth.root_login");
    }

    #[test]
    fn a_user_name_cannot_choose_the_address_that_gets_blocked() {
        let mut a = an();
        let now = Instant::now();
        // The client picks the user name; sshd appends the real address.
        let lines = [
            "Failed password for invalid user admin from 192.0.2.50 port 22 ssh2 from 203.0.113.7 port 4000 ssh2",
            "Invalid user x from 192.0.2.50 port 22 from 203.0.113.7 port 4001",
            "Connection closed by invalid user y 192.0.2.50 port 22 [preauth] 203.0.113.7 port 4002 [preauth]",
        ];
        let mut out = Vec::new();
        for l in lines {
            out.extend(a.analyze("sshd", l, now));
        }
        assert_eq!(out.len(), 1, "three failures from one real source: {out:?}");
        assert_eq!(out[0].details["ip"], "203.0.113.7");
        assert!(matches!(&out[0].subject, Subject::Ip { addr } if addr.to_string() == "203.0.113.7"));
        assert!(
            a.failures.add(Key::exact("192.0.2.50".parse().unwrap()), now) == 1,
            "the named address was never charged"
        );
    }

    #[test]
    fn real_sshd_lines_still_match() {
        let mut a = an();
        let now = Instant::now();
        let ip = "203.0.113.9";
        let lines = [
            format!("Failed publickey for invalid user git from {ip} port 4242 ssh2: RSA SHA256:abc"),
            format!(
                "error: maximum authentication attempts exceeded for invalid user root from {ip} port 4243 ssh2 [preauth]"
            ),
            format!("Disconnected from authenticating user root {ip} port 4244 [preauth]"),
        ];
        let mut out = Vec::new();
        for l in &lines {
            out.extend(a.analyze("sshd-session", l, now));
        }
        assert_eq!(out.len(), 1, "{out:?}");
        let v = a.analyze("sshd", &format!("Accepted publickey for ops from {ip} port 1 ssh2: ED25519 SHA256:x"), now);
        assert!(v.iter().any(|e| e.kind == "security.bruteforce_success"), "{v:?}");
    }

    #[test]
    fn tables_stay_bounded_under_a_flood_of_sources() {
        let mut a = an();
        let now = Instant::now();
        for i in 0..(MAX_TRACKED_SOURCES as u32 * 2 + 10) {
            // one per /64: distinct sources
            let ip = format!("2001:db8:{:x}:{:x}::1", i >> 16, i & 0xffff);
            a.analyze("sshd", &format!("Failed password for root from {ip} port 1 ssh2"), now);
        }
        assert!(a.recent_fail.len() <= MAX_TRACKED_SOURCES + 1, "{}", a.recent_fail.len());
        assert!(a.users_tried.len() <= MAX_TRACKED_SOURCES + 1, "{}", a.users_tried.len());
        let long = "u".repeat(5000);
        a.analyze("sshd", &format!("Failed password for {long} from 198.51.100.77 port 1 ssh2"), now);
        let tried = &a.users_tried[&Key::exact("198.51.100.77".parse::<IpAddr>().unwrap())];
        assert!(tried.iter().all(|u| u.chars().count() <= MAX_USER_CHARS));
    }

    /// N25: a brute force from the addresses of one IPv6 /64 — one failure
    /// each — is one source, and a login from the /64 afterwards is a
    /// success after brute force.
    #[test]
    fn a_brute_force_spread_over_a_network_is_one_source() {
        let mut a = an();
        let now = Instant::now();
        let mut out = Vec::new();
        for i in 1..=3 {
            out.extend(a.analyze(
                "sshd",
                &format!("Failed password for root from 2001:db8:aa:1::{i} port 1 ssh2"),
                now,
            ));
        }
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].details["prefix"], "2001:db8:aa:1::/64");
        assert_eq!(out[0].details["ip"], "2001:db8:aa:1::3");
        assert!(matches!(out[0].actions[..], [ActionSpec::BlockIp { .. }]));
        let v = a.analyze("sshd", "Accepted password for deploy from 2001:db8:aa:1::99 port 2 ssh2", now);
        assert!(v.iter().any(|e| e.kind == "security.bruteforce_success"), "{v:?}");
        // per address: three one-off sources
        let mut a = an().with_ipv6_prefix(128);
        let mut out = Vec::new();
        for i in 1..=3 {
            out.extend(a.analyze(
                "sshd",
                &format!("Failed password for root from 2001:db8:aa:1::{i} port 1 ssh2"),
                now,
            ));
        }
        assert!(out.is_empty());
    }

    #[test]
    fn journal_lines_need_a_sender_that_the_kernel_vouches_for() {
        use serde_json::json;
        // root's sshd
        assert!(journal_sender_trusted(&json!({"_UID": "0", "_EXE": "/usr/sbin/sshd"}), "sshd"));
        // sudo/su run with the caller's UID: the executable decides
        assert!(journal_sender_trusted(&json!({"_UID": "1000", "_EXE": "/usr/bin/su"}), "su"));
        // `logger -t sshd` as an ordinary user
        assert!(!journal_sender_trusted(&json!({"_UID": "33", "_EXE": "/usr/bin/logger"}), "sshd"));
        // a copy of logger named like the daemon, outside the system directories
        assert!(!journal_sender_trusted(&json!({"_UID": "33", "_EXE": "/tmp/sshd"}), "sshd"));
        // a short-lived sender whose /proc entry was gone when journald looked
        assert!(!journal_sender_trusted(&json!({"_UID": "33"}), "sshd"));
        assert!(!journal_sender_trusted(&json!({}), "sshd"));
    }

    #[test]
    fn syslog_split() {
        let a = an();
        let (i, m) = a
            .split_syslog("Oct 20 12:00:01 web1 sshd[123]: Failed password for root from 1.2.3.4 port 22 ssh2")
            .unwrap();
        assert_eq!(i, "sshd");
        assert!(m.starts_with("Failed"));
        let (i, _) = a
            .split_syslog(
                "2026-10-20T12:00:01.123456+03:00 web1 sudo: alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls",
            )
            .unwrap();
        assert_eq!(i, "sudo");
    }
}
