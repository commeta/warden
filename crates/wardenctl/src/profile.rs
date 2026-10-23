//! `wardenctl profile`: the daemon's own CPU, I/O and memory per thread and
//! per module, from two samples taken `interval` apart.

use serde_json::Value;
use std::collections::HashMap;
use warden_core::units::human_bytes;

fn u(v: &Value) -> u64 {
    v.as_u64().unwrap_or_else(|| v.as_i64().map(|x| x.max(0) as u64).unwrap_or(0))
}

fn cpu_us(usage: &Value) -> u64 {
    u(&usage["user_us"]) + u(&usage["sys_us"])
}

fn secs(us: u64) -> String {
    let s = us as f64 / 1e6;
    if s >= 100.0 { format!("{s:.0}s") } else { format!("{s:.2}s") }
}

fn pct(delta_us: u64, wall: f64) -> String {
    format!("{:.2}%", delta_us as f64 / 1e6 / wall.max(1e-6) * 100.0)
}

fn hb(v: u64) -> String {
    if v == 0 { "0".into() } else { human_bytes(v) }
}

pub fn print(a: &Value, b: &Value) {
    let wall = (u(&b["ts_ms"]).saturating_sub(u(&a["ts_ms"]))) as f64 / 1000.0;
    println!(
        "Warden {} — self profile over {wall:.1}s (uptime {}s)\n",
        b["version"].as_str().unwrap_or("?"),
        u(&b["uptime_seconds"])
    );

    // ---- memory
    let p = &b["process"];
    println!(
        "Process   RSS {} (anon {}, file {}), peak {}, mlock'd VMAs {}, threads {}, CPU total {} (+{} in children)",
        hb(u(&p["rss"])),
        hb(u(&p["rss_anon"])),
        hb(u(&p["rss_file"])),
        hb(u(&p["rss_peak"])),
        hb(u(&p["locked"])),
        u(&p["threads"]),
        secs(cpu_us(&p["usage"])),
        secs(u(&p["children_cpu_us"])),
    );
    let pcpu = cpu_us(&b["process"]["usage"]).saturating_sub(cpu_us(&a["process"]["usage"]));
    println!("          CPU now {} of one core", pct(pcpu, wall));
    if b["heap_tracking"].as_bool() == Some(true) {
        let h = &b["heap_total"];
        println!(
            "Heap      live {}, peak {}, allocated since start {} in {} allocations",
            hb(u(&h["live"])),
            hb(u(&h["peak"])),
            hb(u(&h["allocated"])),
            u(&h["allocations"])
        );
    }
    if let Some(m) = b["malloc"].as_object() {
        println!(
            "malloc    from OS {}, in use {}, free (cached) {}",
            hb(u(&m["system"])),
            hb(u(&m["in_use"])),
            hb(u(&m["free"]))
        );
    }
    if let Some(cg) = b["cgroup"].as_object() {
        let us = &cg["usage"];
        println!(
            "cgroup    {}: {} = anon {} + page cache {} + kernel {} (pinned {}, reclaimable {})",
            cg["path"].as_str().unwrap_or("?"),
            hb(u(&us["current"])),
            hb(u(&us["anon"])),
            hb(u(&us["file"])),
            hb(u(&us["kernel"])),
            hb(u(&cg["pinned"])),
            hb(u(&cg["reclaimable"])),
        );
        println!("          (page cache and reclaimable slab are freed by the kernel on demand)");
    }
    match b["page_cache_guard"].as_bool() {
        Some(true) => println!("Scans     evict the page cache they bring in (cachestat available)"),
        Some(false) => println!("Scans     cannot evict their page cache (no cachestat: kernel < 6.5 or seccomp)"),
        None => {}
    }

    // ---- threads
    println!(
        "\n{:<16} {:<44} {:>9} {:>8} {:>9} {:>10} {:>10} {:>9}",
        "THREAD", "ROLE", "CPU", "CPU now", "wakeup/s", "read", "written", "syscall/s"
    );
    let before: HashMap<i64, &Value> =
        a["threads"].as_array().into_iter().flatten().map(|t| (t["tid"].as_i64().unwrap_or(0), t)).collect();
    for t in b["threads"].as_array().into_iter().flatten() {
        let tid = t["tid"].as_i64().unwrap_or(0);
        let prev = before.get(&tid);
        let d_cpu = cpu_us(&t["usage"]).saturating_sub(prev.map(|p| cpu_us(&p["usage"])).unwrap_or(0));
        let d_csw = u(&t["ctx_switches"]).saturating_sub(prev.map(|p| u(&p["ctx_switches"])).unwrap_or(0));
        let sc = |x: &Value| u(&x["usage"]["syscr"]) + u(&x["usage"]["syscw"]);
        let d_sc = sc(t).saturating_sub(prev.map(|p| sc(p)).unwrap_or(0));
        println!(
            "{:<16} {:<44} {:>9} {:>8} {:>9.1} {:>10} {:>10} {:>9.1}",
            t["name"].as_str().unwrap_or("?"),
            t["role"].as_str().unwrap_or(""),
            secs(cpu_us(&t["usage"])),
            pct(d_cpu, wall),
            d_csw as f64 / wall.max(1e-6),
            hb(u(&t["usage"]["rchar"])),
            hb(u(&t["usage"]["wchar"])),
            d_sc as f64 / wall.max(1e-6),
        );
    }

    // ---- detector modules
    if let Some(mods) = b["modules"].as_object()
        && !mods.is_empty()
    {
        println!(
            "\n{:<14} {:<15} {:>8} {:>9} {:>8} {:>9} {:>9} {:>10} {:>10}",
            "DETECTOR", "THREAD", "ticks", "CPU", "CPU now", "avg tick", "max tick", "read", "block I/O"
        );
        for (name, m) in mods {
            let prev = &a["modules"][name];
            let d = cpu_us(&m["usage"]).saturating_sub(cpu_us(&prev["usage"]));
            let ticks = u(&m["ticks"]).max(1);
            println!(
                "{:<14} {:<15} {:>8} {:>9} {:>8} {:>8.2}ms {:>8.1}ms {:>10} {:>10}",
                name,
                m["thread"].as_str().unwrap_or(""),
                u(&m["ticks"]),
                secs(cpu_us(&m["usage"])),
                pct(d, wall),
                u(&m["busy_us"]) as f64 / ticks as f64 / 1000.0,
                u(&m["max_tick_us"]) as f64 / 1000.0,
                hb(u(&m["usage"]["rchar"])),
                hb(u(&m["usage"]["read_bytes"]) + u(&m["usage"]["write_bytes"])),
            );
        }
    }

    // ---- heap per module
    if b["heap_tracking"].as_bool() == Some(true) {
        println!("\n{:<16} {:>10} {:>10} {:>12} {:>12}", "HEAP SCOPE", "live", "peak", "allocated", "alloc/s now");
        let before: HashMap<&str, &Value> =
            a["heap"].as_array().into_iter().flatten().filter_map(|h| Some((h["scope"].as_str()?, h))).collect();
        let mut rows: Vec<&Value> = b["heap"].as_array().into_iter().flatten().collect();
        rows.sort_by_key(|h| std::cmp::Reverse(u(&h["live"])));
        for h in rows {
            let name = h["scope"].as_str().unwrap_or("?");
            if u(&h["allocations"]) == 0 {
                continue;
            }
            let d = u(&h["allocated"]).saturating_sub(before.get(name).map(|p| u(&p["allocated"])).unwrap_or(0));
            println!(
                "{:<16} {:>10} {:>10} {:>12} {:>11}/s",
                name,
                hb(u(&h["live"])),
                hb(u(&h["peak"])),
                hb(u(&h["allocated"])),
                hb((d as f64 / wall.max(1e-6)) as u64),
            );
        }
    } else {
        println!("\n(heap attribution unavailable: wardend built without the `alloc-stats` feature)");
    }

    // ---- what is running
    let running: Vec<&str> = b["running"].as_array().into_iter().flatten().filter_map(|v| v.as_str()).collect();
    let disabled: Vec<&str> = b["sensors"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, s)| s["state"] == "disabled")
        .map(|(n, _)| n.as_str())
        .collect();
    println!(
        "\nRunning components: fast scheduler, {}",
        if running.is_empty() { "-".into() } else { running.join(", ") }
    );
    if !disabled.is_empty() {
        println!("Disabled (no thread, no memory): {}", disabled.join(", "));
    }
}
