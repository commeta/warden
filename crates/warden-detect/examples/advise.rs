//! Print tuning recommendations for this host: `cargo run -p warden-detect --example advise`
fn main() {
    let env = warden_detect::tuning::gather();
    println!("RAM {} GiB, swap {} MiB, workloads {:?}", env.ram >> 30, env.swap_total >> 20, env.workloads);
    for a in warden_detect::tuning::advise(&env) {
        println!("[{}] {} = {} → {}\n    {}", a.category, a.key, a.current, a.recommended, a.reason);
    }
}
