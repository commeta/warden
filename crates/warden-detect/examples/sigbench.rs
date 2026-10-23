//! Signature scanning throughput on a real tree:
//! `cargo run --release -p warden-detect --example sigbench -- /var/www/html`
#![allow(clippy::unwrap_used)]

use std::time::Instant;
use warden_detect::fim::signatures::Signatures;

fn main() {
    let root = std::env::args().nth(1).unwrap_or_else(|| "/var/www/html".into());
    let mut files = Vec::new();
    let mut stack = vec![std::path::PathBuf::from(&root)];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if let Ok(b) = std::fs::read(&p) {
                files.push((p.file_name().unwrap().to_string_lossy().into_owned(), b));
            }
        }
    }
    let bytes: usize = files.iter().map(|f| f.1.len()).sum();
    let t = Instant::now();
    let (sigs, errs) = Signatures::load(&[]);
    assert!(errs.is_empty(), "{errs:?}");
    println!("compile: {:?} ({} rules)", t.elapsed(), sigs.len());
    let t = Instant::now();
    let mut hits = 0u32;
    for (name, data) in &files {
        hits += sigs.scan(name, data).score;
    }
    let s = t.elapsed().as_secs_f64();
    let mib = bytes as f64 / 1048576.0;
    println!(
        "scan (Signatures::scan): {} files, {mib:.0} MiB in {s:.2}s = {:.0} MiB/s (score sum {hits})",
        files.len(),
        mib / s
    );

    // alternatives, for comparison
    let pats = sigs.patterns();
    for cache in [2usize << 20, 32 << 20] {
        let set = regex::bytes::RegexSetBuilder::new(&pats).size_limit(64 << 20).dfa_size_limit(cache).build().unwrap();
        let t = Instant::now();
        let mut n = 0usize;
        for (_, data) in &files {
            n += set.matches(data).iter().count();
        }
        let s = t.elapsed().as_secs_f64();
        println!("RegexSet, DFA cache {} MiB: {:.0} MiB/s ({n} matches)", cache >> 20, mib / s);
    }
    // 0.10 behaviour: Unicode str RegexSet over a lossy UTF-8 copy
    let orig: Vec<String> = pats
        .iter()
        .map(|p| p.strip_prefix("(?-u:").and_then(|x| x.strip_suffix(')')).unwrap_or(p).to_owned())
        .collect();
    let set = regex::RegexSetBuilder::new(&orig).size_limit(50 << 20).build().unwrap();
    let t = Instant::now();
    let mut n = 0usize;
    for (_, data) in files.iter().take(files.len() / 10) {
        n += set.matches(&String::from_utf8_lossy(data)).iter().count();
    }
    let part: usize = files.iter().take(files.len() / 10).map(|f| f.1.len()).sum();
    let s = t.elapsed().as_secs_f64();
    println!("0.10 Unicode RegexSet (first 10% of files): {:.1} MiB/s ({n} matches)", part as f64 / 1048576.0 / s);
    let res: Vec<regex::bytes::Regex> = pats
        .iter()
        .map(|p| regex::bytes::RegexBuilder::new(p).size_limit(64 << 20).dfa_size_limit(2 << 20).build().unwrap())
        .collect();
    let t = Instant::now();
    let mut n = 0usize;
    for (_, data) in &files {
        n += res.iter().filter(|r| r.is_match(data)).count();
    }
    let s = t.elapsed().as_secs_f64();
    println!("{} separate regexes (is_match each): {:.0} MiB/s ({n} matches)", res.len(), mib / s);
}
