//! Masking secrets in what leaves the host.
//!
//! Event details carry text Warden did not write: integrity diffs of
//! `/etc/environment`, `Environment=` lines of units, the journal tail of a
//! failed unit, process command lines (`mysql -pSECRET`). Locally that is
//! what an operator needs; in a Telegram chat, a Slack channel or a webhook
//! receiver it is a leak. [`event`] masks the values of anything that looks
//! like a credential before a notification is rendered (`notify.details =
//! "safe"`, the default): the key and the shape stay, the value becomes
//! `***`.
//!
//! The rules err on the side of masking: a false positive costs a value in a
//! chat message (the journal keeps the original), a false negative costs a
//! password.

use crate::event::{Event, Subject};
use regex::{Captures, Regex};
use std::borrow::Cow;
use std::sync::LazyLock;

/// What replaces a secret.
pub const MASK: &str = "***";

/// Words that make a key, a flag or a header name a secret's name.
const SECRET_WORDS: &str = r"pass(?:word|wd|phrase)?|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|client[_-]?secret|credentials?|authorization|auth[_-]?token|session[_-]?id|cookie|signature|salt";

struct Rule {
    re: Regex,
    replace: fn(&Captures<'_>) -> String,
}

fn re(pattern: &str) -> Regex {
    Regex::new(pattern).expect("constant pattern (covered by the tests)")
}

fn rule(pattern: &str, replace: fn(&Captures<'_>) -> String) -> Rule {
    Rule { re: re(pattern), replace }
}

fn group<'a>(c: &'a Captures<'_>, i: usize) -> &'a str {
    c.get(i).map_or("", |m| m.as_str())
}

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    vec![
        // PEM private keys, whole
        rule(r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\z)", |_| {
            "-----PRIVATE KEY *** -----".to_owned()
        }),
        // HTTP headers that carry credentials: the rest of the line
        rule(
            r"(?im)\b((?:proxy-)?authorization|cookie|set-cookie|x-api-key|x-auth-token|x-amz-security-token)(\s*:\s*)[^\r\n]+",
            |c| format!("{}{}{MASK}", group(c, 1), group(c, 2)),
        ),
        // `Bearer <token>`, `Basic <base64>` anywhere
        rule(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}", |c| format!("{} {MASK}", group(c, 1))),
        // user:password@ in URLs
        rule(r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^/\s@]+@", |c| format!("{}{MASK}@", group(c, 1))),
        // --password=x, --token x, -password x (a flag named after a secret)
        rule(&format!(r"(?i)(^|\s)(--?[a-z0-9_-]*(?:{SECRET_WORDS})[a-z0-9_-]*)(=|\s+)([^\s]+)"), |c| {
            let value = group(c, 4);
            // `--password-file /path`, `--no-password`: a file name or no value
            if group(c, 2).ends_with("-file") || value.starts_with('-') {
                return c[0].to_owned();
            }
            format!("{}{}{}{MASK}", group(c, 1), group(c, 2), group(c, 3))
        }),
        // KEY=value / key: value where the key names a secret (env files,
        // unit Environment=, DSNs, JSON-ish logs)
        rule(&format!(r#"(?i)\b([a-z0-9_.-]*(?:{SECRET_WORDS})[a-z0-9_.-]*)("?\s*[=:]\s*"?)([^\s"',;&}}\]]+)"#), |c| {
            let value = group(c, 3);
            if value == MASK || value.starts_with("$(") || value.starts_with("${") {
                return c[0].to_owned();
            }
            format!("{}{}{MASK}", group(c, 1), group(c, 2))
        }),
        // crypt(3) hashes (shadow lines in an integrity diff)
        rule(r"\$(1|2[abxy]?|5|6|y|gy|7)\$[./A-Za-z0-9$]{8,}", |c| format!("${}${MASK}", group(c, 1))),
        // well-known token formats
        rule(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", |c| format!("{}{MASK}", group(c, 1))),
        rule(r"\b(gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}", |c| format!("{}{MASK}", group(c, 1))),
        rule(r"\b(xox[abposr]-)[A-Za-z0-9-]{10,}", |c| format!("{}{MASK}", group(c, 1))),
        rule(r"\b(sk-|sk_live_|rk_live_)[A-Za-z0-9_-]{16,}", |c| format!("{}{MASK}", group(c, 1))),
        rule(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}", |_| format!("eyJ{MASK}")),
        // Telegram bot tokens
        rule(r"\b(\d{6,12}):[A-Za-z0-9_-]{30,}\b", |c| format!("{}:{MASK}", group(c, 1))),
    ]
});

/// `mysql -pSECRET` and friends: an attached `-p` value is a password for
/// the MySQL/MariaDB clients (elsewhere `-p` is usually a port or a flag).
static MYSQL_P: LazyLock<Regex> = LazyLock::new(|| re(r"(^|\s)-p([^\s]+)"));
static MYSQL_CLIENT: LazyLock<Regex> = LazyLock::new(|| {
    re(r"(?i)\b(mysql|mariadb|mysqldump|mysqladmin|mysqlimport|mysqlcheck|mysqlsh|mariadb-dump|mariadb-admin)\b")
});
/// `sshpass -p SECRET` (a separate `-p SECRET` is a password only there:
/// `mysql -p` alone prompts).
static SSHPASS: LazyLock<Regex> = LazyLock::new(|| re(r"\b(sshpass\s+(?:-[a-zA-Z]\s+\S+\s+)*-p\s*)(\S+)"));

/// Mask what looks like a secret in `s`.
pub fn text(s: &str) -> Cow<'_, str> {
    let mut out = Cow::Borrowed(s);
    if MYSQL_CLIENT.is_match(&out) {
        let r = MYSQL_P.replace_all(&out, |c: &Captures<'_>| format!("{}-p{MASK}", group(c, 1))).into_owned();
        out = Cow::Owned(r);
    }
    if let Cow::Owned(r) = SSHPASS.replace_all(&out, |c: &Captures<'_>| format!("{}{MASK}", group(c, 1))) {
        out = Cow::Owned(r);
    }
    for r in RULES.iter() {
        if let Cow::Owned(x) = r.re.replace_all(&out, r.replace) {
            out = Cow::Owned(x);
        }
    }
    out
}

/// Does a JSON key name a secret (`password`, `api_key`, `Authorization`)?
fn secret_key(k: &str) -> bool {
    static KEY: LazyLock<Regex> = LazyLock::new(|| re(&format!(r"(?i)^[a-z0-9_.-]*(?:{SECRET_WORDS})[a-z0-9_.-]*$")));
    KEY.is_match(k) && !k.ends_with("_file") && !k.ends_with("_path")
}

/// Mask secrets in a JSON value in place: strings are filtered with
/// [`text`], and the whole value of a key that names a secret is masked.
pub fn value(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) => {
            if let Cow::Owned(r) = text(s) {
                *s = r;
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(value),
        serde_json::Value::Object(m) => {
            for (k, v) in m.iter_mut() {
                if secret_key(k) && !v.is_null() && !v.is_boolean() {
                    *v = MASK.into();
                } else {
                    value(v);
                }
            }
        }
        _ => {}
    }
}

/// How much of an event's detail notifications carry (`notify.details`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Details {
    /// Kind, severity, title, subject and actions only.
    None,
    /// Everything, with secrets masked.
    #[default]
    Safe,
    /// Everything as recorded (the journal always has it this way).
    All,
}

/// The event as notifications may carry it.
pub fn event(ev: &Event, level: Details) -> Cow<'_, Event> {
    if level == Details::All {
        return Cow::Borrowed(ev);
    }
    let mut e = ev.clone();
    if let Subject::Process(p) = &mut e.subject {
        p.cmdline = match level {
            Details::None => None,
            _ => p.cmdline.as_deref().map(|c| text(c).into_owned()),
        };
    }
    if level == Details::None {
        e.details.clear();
    } else {
        for (k, v) in e.details.iter_mut() {
            if secret_key(k) && !v.is_null() && !v.is_boolean() {
                *v = MASK.into();
            } else {
                value(v);
            }
        }
    }
    e.title = text(&e.title).into_owned();
    Cow::Owned(e)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::event::{ProcessRef, Severity};

    fn t(s: &str) -> String {
        text(s).into_owned()
    }

    #[test]
    fn masks_credentials_in_text() {
        let cases = [
            ("mysql -uroot -pS3cr3t! -h db", "mysql -uroot -p*** -h db"),
            ("/usr/bin/mariadb-dump -pXYZ app", "/usr/bin/mariadb-dump -p*** app"),
            ("sshpass -p hunter2 ssh host", "sshpass -p *** ssh host"),
            ("curl --password=abc https://x", "curl --password=*** https://x"),
            ("app --api-key 0123456789 --port 80", "app --api-key *** --port 80"),
            ("+DB_PASSWORD=supersecret", "+DB_PASSWORD=***"),
            ("Environment=\"API_TOKEN=abc123\" \"LANG=C\"", "Environment=\"API_TOKEN=***\" \"LANG=C\""),
            ("export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI", "export AWS_SECRET_ACCESS_KEY=***"),
            ("Authorization: Bearer eyJhbGciOi.xyz", "Authorization: ***"),
            ("got header authorization:basic dXNlcjpwYXNz\nnext", "got header authorization:***\nnext"),
            ("token Bearer abcdefghijkl used", "token Bearer *** used"),
            ("postgres://app:pa55w0rd@db:5432/x", "postgres://app:***@db:5432/x"),
            ("{\"password\": \"p@ss\", \"user\": \"bob\"}", "{\"password\": \"***\", \"user\": \"bob\"}"),
            ("root:$6$abcdefgh$0123456789abcdef:19000:0", "root:$6$***:19000:0"),
            ("key AKIAIOSFODNN7EXAMPLE", "key AKIA***"),
            ("ghp_0123456789abcdefghijABCDEFGHIJ012345", "ghp_***"),
            ("xoxb-1234567890-abcdefghij", "xoxb-***"),
            ("bot 123456789:AAHdqTcvCH1vGWJxfSeofSAs0K5PALDsaw0", "bot 123456789:***"),
            (
                "-----BEGIN OPENSSH PRIVATE KEY-----\nb3Blbn\n-----END OPENSSH PRIVATE KEY-----",
                "-----PRIVATE KEY *** -----",
            ),
        ];
        for (input, want) in cases {
            assert_eq!(t(input), want, "{input}");
        }
    }

    #[test]
    fn leaves_ordinary_text_alone() {
        for s in [
            "mkdir -p /var/www && cp -pr a b",
            "ssh -p 2222 host",
            "disk / at 93% (free 1.2 GiB)",
            "file=/root/.ssh/authorized_keys changed",
            "passwd[123]: password changed for bob",
            "--password-file /etc/app/pw",
            "author=jane",
            "PASSWORD=${DB_PASSWORD}",
        ] {
            assert_eq!(t(s), s, "{s}");
        }
        // nothing to mask: no copy
        assert!(matches!(text("plain text"), Cow::Borrowed(_)));
    }

    #[test]
    fn events_lose_secrets_but_keep_their_shape() {
        let ev = Event::new("systemd.unit_failed", Severity::Warning, "app.service failed")
            .subject(Subject::Process(ProcessRef {
                pid: 7,
                comm: "mysql".into(),
                cmdline: Some("mysql -pTOPSECRET db".into()),
                ..Default::default()
            }))
            .detail("journal_tail", serde_json::json!(["connect postgres://u:pw@h/db", "ok"]))
            .detail("api_key", "abcdef")
            .detail("diff", "-X=1\n+SECRET_KEY=s3cr3t\n")
            .detail("password_file", "/etc/pw")
            .detail("count", 3);
        let safe = event(&ev, Details::Safe);
        let Subject::Process(p) = &safe.subject else { panic!() };
        assert_eq!(p.cmdline.as_deref(), Some("mysql -p*** db"));
        assert_eq!(safe.details["journal_tail"][0], "connect postgres://u:***@h/db");
        assert_eq!(safe.details["api_key"], MASK);
        assert_eq!(safe.details["diff"], "-X=1\n+SECRET_KEY=***\n");
        assert_eq!(safe.details["password_file"], "/etc/pw");
        assert_eq!(safe.details["count"], 3);
        let none = event(&ev, Details::None);
        assert!(none.details.is_empty());
        let Subject::Process(p) = &none.subject else { panic!() };
        assert!(p.cmdline.is_none());
        assert!(matches!(event(&ev, Details::All), Cow::Borrowed(_)));
        // the original is untouched
        assert_eq!(ev.details["api_key"], "abcdef");
    }
}
