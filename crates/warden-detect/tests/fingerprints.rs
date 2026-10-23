#![allow(clippy::unwrap_used)]
//! The fingerprint convention, checked on the sources (every event a
//! detector builds by hand):
//!
//! * a condition `X` is `kind` or `kind:<detail>` — the first segment of the
//!   fingerprint is the event's kind (two kinds that are the two sides of
//!   one condition, `network.link_down`/`_up`, share a base);
//! * a severity in a fingerprint is lowercase (`{sev}`), never `Debug`
//!   output (`{l:?}` gave `limits.pids:Warning` in 0.13.3);
//! * `X:resolved` is the fingerprint of exactly the events marked
//!   `.resolved()`.
//!
//! [`warden_core::event::end_episodes`] and the notifier rely on this: a
//! resolution ends the condition whose fingerprint it extends.

use std::path::{Path, PathBuf};

/// Kinds that report the two sides of one condition under a shared base.
const SHARED_BASE: &[(&str, &str)] = &[("network.link_down", "network.link"), ("network.link_up", "network.link")];

fn sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            sources(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// The first string literal of `s` (after optional `format!(`).
fn literal(s: &str) -> Option<String> {
    let s = s.trim_start();
    let s = s.strip_prefix("format!(").unwrap_or(s).trim_start();
    let s = s.strip_prefix('"')?;
    let end = s.find('"')?;
    Some(s[..end].to_owned())
}

#[derive(Debug)]
struct Site {
    file: String,
    line: usize,
    kind: String,
    fingerprint: String,
    resolved: bool,
}

fn sites() -> Vec<Site> {
    let mut files = Vec::new();
    let crates = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    for c in ["warden-detect", "warden-respond", "wardend", "warden-core"] {
        sources(&crates.join(c).join("src"), &mut files);
    }
    let mut out = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        // tests build events of their own
        let code = text.split("#[cfg(test)]").next().unwrap_or("");
        let mut at = 0;
        while let Some(i) = code[at..].find("Event::new(") {
            let start = at + i;
            at = start + 11;
            let Some(kind) = literal(&code[at..]) else { continue };
            // the builder chain: up to the next event or the end of the statement
            let rest = &code[at..];
            let end = [rest.find("Event::new("), rest.find(";\n"), rest.find("cx.emit(")]
                .into_iter()
                .flatten()
                .min()
                .unwrap_or(rest.len());
            let chain = &rest[..end];
            let Some(fp_at) = chain.find(".fingerprint(") else { continue };
            let Some(fingerprint) = literal(&chain[fp_at + 13..]) else { continue };
            out.push(Site {
                file: f.display().to_string().rsplit("crates/").next().unwrap_or_default().to_owned(),
                line: code[..start].lines().count() + 1,
                kind,
                fingerprint,
                resolved: chain.contains(".resolved()"),
            });
        }
    }
    out
}

#[test]
fn every_fingerprint_follows_the_convention() {
    let sites = sites();
    assert!(sites.len() > 50, "the scan found only {} events", sites.len());
    let mut bad = Vec::new();
    for s in &sites {
        let where_ = format!("{}:{} {} → {}", s.file, s.line, s.kind, s.fingerprint);
        if s.kind.contains('{') || s.fingerprint.starts_with('{') {
            continue; // built from a variable: the helpers that do it are tested themselves
        }
        let first = s.fingerprint.split(':').next().unwrap_or("").replace("{kind}", &s.kind);
        let base_ok = first == s.kind || SHARED_BASE.iter().any(|(k, b)| *k == s.kind && *b == first);
        if !base_ok {
            bad.push(format!("{where_}: the first segment is not the kind"));
        }
        if s.fingerprint.contains(":?}") {
            bad.push(format!("{where_}: Debug output in a fingerprint"));
        }
        if s.fingerprint.ends_with(":resolved") != s.resolved {
            bad.push(format!("{where_}: `:resolved` must go with `.resolved()`"));
        }
    }
    assert!(bad.is_empty(), "fingerprint convention violated:\n{}", bad.join("\n"));
}
