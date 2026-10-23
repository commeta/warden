//! Cost of the exec analysis per call, full path vs fast path, on a real
//! process (no connector needed):
//!
//!     cargo run --release -p warden-detect --example execbench [-- 20000]

use std::sync::Mutex;
use std::time::{Duration, Instant};
use warden_core::config::ProcessConfig;
use warden_detect::heuristics::Lineage;
use warden_detect::process::ExecPipeline;

fn main() {
    let n: u32 = std::env::args().nth(1).and_then(|a| a.parse().ok()).unwrap_or(20_000);
    let mut child = std::process::Command::new("sleep").arg("600").spawn().expect("spawn sleep");
    std::thread::sleep(Duration::from_millis(50));
    let pid = child.id() as i32;
    let lin = Mutex::new(Lineage::new(None, Duration::ZERO, false));
    let users = |uid: u32| if uid == 0 { "root".to_owned() } else { uid.to_string() };
    for (name, fast) in [("full analysis", false), ("fast path", true)] {
        let cfg = ProcessConfig { exec_fast_path: fast, exec_recheck_every: 0, ..Default::default() };
        let mut p = ExecPipeline::new(&cfg);
        for _ in 0..10 {
            p.on_exec(pid, &users, &lin);
        }
        let t = Instant::now();
        for _ in 0..n {
            p.on_exec(pid, &users, &lin);
        }
        let per = t.elapsed() / n;
        println!("{name:14} {:>6.1} µs/exec  ({:?})", per.as_secs_f64() * 1e6, p.stats);
    }
    let _ = child.kill();
    let _ = child.wait();
}
