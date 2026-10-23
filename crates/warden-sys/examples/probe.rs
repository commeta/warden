//! Quick capability probe: `cargo run -p warden-sys --example probe` (as root).
use std::time::Duration;
use warden_sys::*;

fn main() {
    println!("psi memory: {:?}", psi::read(psi::Resource::Memory).map(|p| p.some.avg10));
    println!(
        "psi trigger: {:?}",
        psi::Trigger::new("/proc/pressure/memory", "some", Duration::from_millis(150), Duration::from_secs(1))
            .map(|_| "ok")
    );
    println!("cgroup v2: {}", cgroup::is_v2());
    println!("kmsg: {:?}", kmsg::Reader::open(true).map(|_| "ok"));
    println!("clock: {:?}", kernel::clock_status());
    println!("lsm: {:?}", kernel::lsm_state());
    match proc_connector::Connector::open() {
        Ok(mut c) => {
            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(200));
                let _ = std::process::Command::new("true").status();
            });
            for _ in 0..5 {
                match c.recv() {
                    Ok(Some(ev)) => {
                        println!("proc connector events: {:?}", ev);
                        if ev.iter().any(|e| matches!(e, proc_connector::ProcEvent::Exec { .. })) {
                            break;
                        }
                    }
                    other => {
                        println!("recv: {:?}", other.map(|_| ()));
                        break;
                    }
                }
            }
        }
        Err(e) => println!("proc connector: {e}"),
    }
    match fanotify::Fanotify::new() {
        Ok(mut f) => {
            println!("fanotify mark: {:?}", f.watch_mount(std::path::Path::new("/tmp")));
            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(200));
                let _ = std::fs::write("/tmp/warden-probe.txt", "x");
            });
            println!(
                "fanotify event: {:?}",
                f.read().map(|v| v
                    .into_iter()
                    .filter(|e| e.path.as_deref().is_some_and(|p| p.ends_with("warden-probe.txt")))
                    .collect::<Vec<_>>())
            );
        }
        Err(e) => println!("fanotify: {e}"),
    }
    println!("deleted open >1MiB: {}", process::deleted_open_files(1 << 20, None).len());
    println!(
        "listeners: {:?}",
        net::tcp_sockets().into_iter().filter(|s| s.state == net::TCP_LISTEN).map(|s| s.local).collect::<Vec<_>>()
    );
    println!("thermal: {:?} edac: {:?}", hw::thermal(), hw::edac());
    println!("taint: {:?}", kernel::tainted().map(kernel::taint_letters));
}
