//! Fuzz-target bodies for every parser that reads input an attacker (or a
//! confused kernel) controls. Each takes arbitrary bytes and must not panic,
//! loop or allocate without bound; the properties checked here are the ones
//! a crash-only fuzzer cannot see.
//!
//! * `fuzz/` (nightly, `cargo fuzz run <target>`) drives them with libFuzzer
//!   — CI runs each for a minute on every pull request;
//! * the tests below run them on stable over a seed corpus and a few
//!   thousand deterministic mutations, so a regression is caught by
//!   `cargo test` too.

use std::time::Instant;
use warden_detect::fim::correlate;
use warden_detect::waf;
use warden_sys::{dbus, fanotify, fanotify_fid, kernel, kmsg, mem, mounts, net, proc_connector, process, psi, users};

/// A fuzz-target body.
pub type Target = fn(&[u8]);

/// Every target, by name (the names of the files in `fuzz/fuzz_targets/`).
pub const TARGETS: &[(&str, Target)] = &[
    ("access_log", access_log),
    ("modsecurity", modsecurity),
    ("dbus", dbus_message),
    ("proc_connector", proc_connector),
    ("fanotify", fanotify),
    ("procfs", procfs),
    ("auth_log", auth_log),
    ("redact", redact),
];

fn lines(data: &[u8]) -> impl Iterator<Item = &str> {
    std::str::from_utf8(data).ok().into_iter().flat_map(str::lines)
}

/// Web server access logs (`fim.site.access_log`): request line, client
/// address and time are attacker-chosen.
pub fn access_log(data: &[u8]) {
    for line in lines(data) {
        if let Some(r) = correlate::parse_line(line) {
            // B15: the time is the bracket before the request, never one the
            // client put into `$remote_user` or the URL
            if let Some(q) = line.find('"') {
                let before = &line[..q];
                if let Some(open) = before.rfind('[') {
                    let t = r.ts;
                    let stamp = before[open + 1..].split(']').next().unwrap_or("");
                    assert_eq!(correlate::parse_clf_time(stamp), Some(t), "{line:?}");
                }
            }
        }
        let _ = correlate::parse_clf_time(line);
    }
}

/// ModSecurity v2 (Apache error log), v3 (nginx error log) and JSON audit
/// records.
pub fn modsecurity(data: &[u8]) {
    for line in lines(data) {
        let _ = waf::parse_error_line(line);
        let _ = waf::parse_json_line(line);
        let _ = waf::parse_client(line);
    }
}

/// A D-Bus message from the system bus (any peer can send Warden a directed
/// signal) and the body unmarshaller with an arbitrary signature.
pub fn dbus_message(data: &[u8]) {
    if let Some(prefix) = data.get(..16).and_then(|p| <&[u8; 16]>::try_from(p).ok()) {
        let _ = dbus::Message::wire_len(prefix);
    }
    if let Ok(m) = dbus::Message::decode(data) {
        let _ = m.args();
        // a decoded message re-encodes (or fails cleanly)
        let _ = m.encode(1);
    }
    // [signature length][signature][body]
    if let Some((&n, rest)) = data.split_first() {
        let n = usize::from(n % 32).min(rest.len());
        let (sig, body) = rest.split_at(n);
        if let Ok(sig) = std::str::from_utf8(sig) {
            let _ = dbus::unmarshal(sig, body, false);
            let _ = dbus::unmarshal(sig, body, true);
        }
    }
}

/// Netlink proc connector datagrams.
pub fn proc_connector(data: &[u8]) {
    let events = proc_connector::parse_datagram(data);
    // one event per netlink message at most, each at least a header long
    assert!(events.len() <= data.len() / 16 + 1);
    let _ = proc_connector::parse_proc_event(data);
}

/// fanotify read buffers: plain metadata and FID/DFID_NAME info records.
pub fn fanotify(data: &[u8]) {
    let plain = fanotify::parse_metadata(data);
    assert!(plain.len() <= data.len() / 24 + 1);
    for ev in fanotify_fid::parse_events(data) {
        assert!(ev.handle.len() <= data.len());
    }
}

/// `/proc` and `/sys` text formats, `/etc/passwd`, `/dev/kmsg` records: a
/// process controls its own `comm` (newlines, parentheses) and cgroup names.
pub fn procfs(data: &[u8]) {
    let Ok(s) = std::str::from_utf8(data) else { return };
    let _ = process::parse_stat(s);
    let _ = process::parse_status(s);
    let _ = process::parse_status_head(s);
    let _ = process::parse_cgroup(s);
    let _ = process::parse_nofile(s);
    let _ = mounts::parse_mountinfo(s);
    let _ = mounts::unescape(s);
    let _ = users::parse_passwd(s);
    let _ = net::parse_snmp(s);
    let _ = net::parse_net_dev(s);
    let _ = net::parse_tcp(s);
    let _ = kernel::parse_modules(s);
    let _ = psi::parse(s);
    let _ = mem::parse_meminfo(s);
    let _ = mem::parse_vmstat(s);
    for line in s.lines() {
        let _ = kmsg::parse_record(line);
    }
}

/// `auth.log` / journal lines (user names and addresses are attacker-chosen).
/// One analyzer for the whole run, like the sensor: its per-IP and per-user
/// state must stay bounded however many distinct inputs it sees.
pub fn auth_log(data: &[u8]) {
    thread_local! {
        static AN: std::cell::RefCell<warden_detect::auth::AuthAnalyzer> = std::cell::RefCell::new({
            let cfg = warden_core::Config::default();
            warden_detect::auth::AuthAnalyzer::new(&cfg.auth, &["www-data".to_owned()], &[])
        });
    }
    let now = Instant::now();
    AN.with(|an| {
        let mut an = an.borrow_mut();
        for line in lines(data) {
            if let Some((ident, msg)) = an.split_syslog(line) {
                let _ = an.analyze(ident, msg, now);
            }
            let _ = an.analyze("sshd", line, now);
        }
    });
}

/// The secret redactor sees all of the above on its way out.
pub fn redact(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    let once = warden_core::redact::text(&s).into_owned();
    // masking never makes text longer than a mask per input byte
    assert!(once.len() <= s.len() * (1 + warden_core::redact::MASK.len()) + 64);
    let mut v = serde_json::Value::String(s.into_owned());
    warden_core::redact::value(&mut v);
}

/// Seeds for the smoke run (and `fuzz/corpus/<target>/` for libFuzzer).
pub fn seeds(target: &str) -> Vec<Vec<u8>> {
    let text = |v: &[&str]| v.iter().map(|s| s.as_bytes().to_vec()).collect::<Vec<_>>();
    match target {
        "access_log" => text(&[
            r#"203.0.113.5 - - [20/Oct/2026:12:00:00 +0000] "POST /wp-content/uploads/x.php HTTP/1.1" 200 12 "-" "curl/8""#,
            r#"203.0.113.5 - [01/Jan/2030:00:00:00 +0000] [20/Oct/2026:12:00:00 +0300] "GET /?q=[x] HTTP/1.1" 404 0"#,
            r#"::1 - user [20/Oct/2026:12:00:00 -0700] "GET / HTTP/2.0" 200 5 "ref" "ua with \"quotes\"""#,
        ]),
        "modsecurity" => text(&[
            r#"[Tue Oct 20 12:00:00.123456 2026] [security2:error] [pid 1:tid 2] [client 203.0.113.5:51234] ModSecurity: Access denied with code 403 (phase 2). [id "949110"] [msg "Inbound Anomaly Score Exceeded"] [severity "CRITICAL"] [hostname "example.com"] [uri "/index.php"]"#,
            r#"2026/10/20 12:00:00 [error] 1#1: *5 [client 198.51.100.9] ModSecurity: Access denied with code 403 (phase 2). [id "949110"] [severity "0"] [hostname "10.0.0.1"] [uri "/"], client: 198.51.100.9, server: example.com"#,
            r#"{"transaction":{"client_ip":"203.0.113.7","request":{"uri":"/x"},"messages":[{"details":{"ruleId":"942100","severity":"2"}}]}}"#,
        ]),
        "dbus" => {
            let mut v = Vec::new();
            if let Ok(m) = dbus::Message::signal(
                "/org/freedesktop/systemd1/unit/nginx_2eservice",
                "org.freedesktop.DBus.Properties",
                "PropertiesChanged",
            )
            .with_body(
                "sa{sv}as",
                &[
                    dbus::Value::str("org.freedesktop.systemd1.Unit"),
                    dbus::Value::Array("{sv}".into(), vec![]),
                    dbus::Value::strings(&["ActiveState"]),
                ],
            ) && let Ok(b) = m.encode(7)
            {
                v.push(b);
            }
            v.push(b"\x05sa{sv}\x04\x00\x00\x00abc\x00".to_vec());
            v
        }
        "proc_connector" => {
            // nlmsghdr(16) + cn_msg(20) + proc_event exec(16 + 8)
            let mut b = Vec::new();
            let len: u32 = 16 + 20 + 24;
            b.extend_from_slice(&len.to_ne_bytes());
            b.extend_from_slice(&[0; 12]);
            b.extend_from_slice(&1u32.to_ne_bytes()); // CN_IDX_PROC
            b.extend_from_slice(&[0; 16]);
            b.extend_from_slice(&2u32.to_ne_bytes()); // PROC_EVENT_EXEC
            b.extend_from_slice(&[0; 12]);
            b.extend_from_slice(&42i32.to_ne_bytes());
            b.extend_from_slice(&42i32.to_ne_bytes());
            vec![b]
        }
        "fanotify" => {
            // metadata(24) + DFID_NAME record: hdr(4) fsid(8) handle(8 + 8) "x.php\0"
            let mut b = Vec::new();
            let rec_len: u16 = 4 + 8 + 8 + 8 + 6;
            let len: u32 = 24 + u32::from(rec_len);
            b.extend_from_slice(&len.to_ne_bytes());
            b.extend_from_slice(&[3, 0]); // vers, reserved
            b.extend_from_slice(&24u16.to_ne_bytes()); // metadata_len
            b.extend_from_slice(&0x100u64.to_ne_bytes()); // FAN_CREATE
            b.extend_from_slice(&(-1i32).to_ne_bytes()); // fd
            b.extend_from_slice(&4242i32.to_ne_bytes()); // pid
            b.extend_from_slice(&[2, 0]);
            b.extend_from_slice(&rec_len.to_ne_bytes());
            b.extend_from_slice(&[1, 0, 0, 0, 2, 0, 0, 0]);
            b.extend_from_slice(&8u32.to_ne_bytes());
            b.extend_from_slice(&1i32.to_ne_bytes());
            b.extend_from_slice(&[9; 8]);
            b.extend_from_slice(b"x.php\0");
            vec![b]
        }
        "procfs" => text(&[
            "1234 (evil) (comm)\n) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 12345 1000000 100 18446744073709551615",
            "Name:\tphp-fpm\nUmask:\t0022\nState:\tS (sleeping)\nTgid:\t7\nPid:\t7\nPPid:\t1\nUid:\t33\t33\t33\t33\nGid:\t33\t33\t33\t33\nVmRSS:\t  1024 kB\nVmSwap:\t0 kB\n",
            "0::/system.slice/nginx.service\n",
            "Max open files            1024                 524288               files\n",
            "36 35 98:0 /mnt1 /mnt\\040with\\040space rw,noatime master:1 - ext4 /dev/root rw,errors=continue\n",
            "root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33::/var/www:/usr/sbin/nologin\n",
            "6,1234,5678901,-;Out of memory: Killed process 4321 (java)\n",
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1\n   1: 00000000000000000000000001000000:0016 00000000000000000000000000000000:0000 0A 00000000:00000001 00:00000000 00000000     0        0 54321 1\n",
            "some avg10=1.50 avg60=0.80 avg300=0.10 total=123456\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n",
            "MemTotal:       16384000 kB\nMemAvailable:    8000000 kB\nSwapTotal: 0 kB\n",
        ]),
        "auth_log" => text(&[
            "Oct 20 12:00:01 host sshd[1]: Failed password for invalid user admin from 192.0.2.9 port 22 ssh2",
            "Oct 20 12:00:02 host sshd[1]: Accepted publickey for root from 2001:db8::1 port 2222 ssh2: ED25519 SHA256:x",
            "Oct 20 12:00:03 host sudo:   www-data : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/sh",
            "Oct 20 12:00:04 host sshd[1]: Failed password for root from 1.2.3.4 from 192.0.2.10 port 1 ssh2",
        ]),
        "redact" => text(&[
            "mysql -uroot -pS3cr3t db",
            "Authorization: Bearer abcdefghijkl\nDB_PASSWORD=x",
            "postgres://u:p@h/db $6$saltsalt$hashhashhash",
        ]),
        _ => Vec::new(),
    }
}

/// A small deterministic PRNG (xorshift64*): the smoke run must be
/// reproducible, and the workspace does not need a `rand` dependency for it.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed | 1)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next_u64() % n as u64) as usize }
    }
}

/// Interesting bytes for mutations: delimiters of the text formats, and
/// lengths that sit on boundaries of the binary ones.
const INTERESTING: &[u8] = b"\0\n\r\t \"'[]{}()<>:;=,%\\-+$@#/\xff\x7f\x80";

/// One mutation of `seed` (bit flips, cut, splice, interesting bytes,
/// repeated blocks — the latter to look for quadratic behaviour).
pub fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut b = seed.to_vec();
    for _ in 0..=rng.below(4) {
        match rng.below(7) {
            0 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] ^= 1 << rng.below(8);
            }
            1 if !b.is_empty() => b.truncate(rng.below(b.len())),
            2 => {
                let i = rng.below(b.len() + 1);
                b.insert(i, INTERESTING[rng.below(INTERESTING.len())]);
            }
            3 if !b.is_empty() => {
                let i = rng.below(b.len());
                b[i] = (rng.next_u64() & 0xff) as u8;
            }
            4 if b.len() > 1 => {
                let (i, j) = (rng.below(b.len()), rng.below(b.len()));
                let (lo, hi) = (i.min(j), i.max(j));
                let block = b[lo..hi].to_vec();
                for _ in 0..rng.below(8) {
                    b.splice(hi..hi, block.iter().copied());
                }
            }
            5 => {
                let n = rng.below(64);
                b.extend((0..n).map(|_| (rng.next_u64() & 0xff) as u8));
            }
            _ if b.len() >= 4 => {
                // a length field set to an extreme
                let i = rng.below(b.len() - 3);
                let v: u32 = [0, 1, 15, 16, 0x7fff_ffff, u32::MAX][rng.below(6)];
                b[i..i + 4].copy_from_slice(&v.to_ne_bytes());
            }
            _ => {}
        }
    }
    b
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::time::Duration;

    /// Every target over its seeds and 3000 mutations of them (plus random
    /// noise): no panic, and no single input slower than a second (a loop
    /// or quadratic behaviour on hostile input).
    #[test]
    fn smoke_run_of_every_target() {
        for (name, target) in TARGETS {
            let seeds = seeds(name);
            assert!(!seeds.is_empty(), "{name}: no seeds");
            let mut rng = Rng::new(0x5eed ^ name.len() as u64);
            let mut slowest = Duration::ZERO;
            for i in 0..3000 {
                let input = if i < seeds.len() {
                    seeds[i].clone()
                } else if i % 10 == 0 {
                    (0..rng.below(512)).map(|_| (rng.next_u64() & 0xff) as u8).collect()
                } else {
                    let seed = &seeds[rng.below(seeds.len())];
                    mutate(&mut rng, seed)
                };
                let t = Instant::now();
                if let Err(e) = std::panic::catch_unwind(|| target(&input)) {
                    panic!("{name} panicked on {:?}: {e:?}", String::from_utf8_lossy(&input));
                }
                slowest = slowest.max(t.elapsed());
                assert!(
                    t.elapsed() < Duration::from_secs(1),
                    "{name}: {:?} on a {}-byte input",
                    t.elapsed(),
                    input.len()
                );
            }
            eprintln!("{name}: slowest input {slowest:?}");
        }
    }

    /// `WARDEN_FUZZ_CORPUS=fuzz/corpus cargo test -p warden-fuzz write_corpus`
    /// writes the seeds where `cargo fuzz run` starts from.
    #[test]
    fn write_corpus() {
        let Some(dir) = std::env::var_os("WARDEN_FUZZ_CORPUS") else { return };
        for (name, _) in TARGETS {
            let d = std::path::Path::new(&dir).join(name);
            std::fs::create_dir_all(&d).expect("corpus directory");
            for (i, s) in seeds(name).iter().enumerate() {
                std::fs::write(d.join(format!("seed-{i}")), s).expect("corpus file");
            }
        }
    }

    #[test]
    fn seeds_exercise_the_parsers() {
        // the binary seeds are well-formed: the smoke run starts from inputs
        // that reach deep into the parsers, not only from their error paths
        assert_eq!(proc_connector::parse_datagram(&seeds("proc_connector")[0]).len(), 1);
        let fid = fanotify_fid::parse_events(&seeds("fanotify")[0]);
        assert_eq!(fid.len(), 1);
        assert_eq!(fid[0].name.as_deref(), Some(std::ffi::OsStr::new("x.php")));
        let m = dbus::Message::decode(&seeds("dbus")[0]).unwrap();
        assert_eq!(m.args().unwrap().len(), 3);
        assert!(correlate::parse_line(std::str::from_utf8(&seeds("access_log")[0]).unwrap()).is_some());
    }
}
