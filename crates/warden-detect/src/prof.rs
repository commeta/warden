//! Self-profiling: CPU, I/O and heap attributed to Warden's modules.
//!
//! * **Heap** — `wardend` installs [`TrackingAlloc`] as its global
//!   allocator. Every allocation is charged to the *scope* active on the
//!   allocating thread (a detector tick, a sensor thread, the engine …) until
//!   it is freed, wherever that happens. Cost: a 16-byte header and a few
//!   relaxed atomic adds per allocation.
//! * **CPU / I/O of detectors** — the schedulers sample
//!   `getrusage(RUSAGE_THREAD)` and `/proc/thread-self/io` around every tick
//!   (two syscalls), so detectors that share a scheduler thread are still
//!   measured separately.
//! * **Sensors** run in their own threads and are measured per thread from
//!   `/proc/self/task` when a report is requested.
//!
//! `wardenctl profile` turns two reports into rates; `/metrics` exports
//! `warden_module_*` and `warden_self_*` series.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering::Relaxed};
use std::time::Duration;
use warden_sys::selfstat::{self, Usage};

pub const MAX_SCOPES: usize = 64;

#[repr(align(64))]
struct Counters {
    live: AtomicI64,
    peak: AtomicI64,
    total: AtomicU64,
    count: AtomicU64,
}

impl Counters {
    const fn new() -> Self {
        Self { live: AtomicI64::new(0), peak: AtomicI64::new(0), total: AtomicU64::new(0), count: AtomicU64::new(0) }
    }

    #[inline]
    fn grow(&self, n: i64) {
        let live = self.live.fetch_add(n, Relaxed) + n;
        if live > self.peak.load(Relaxed) {
            self.peak.fetch_max(live, Relaxed);
        }
        self.total.fetch_add(n as u64, Relaxed);
        self.count.fetch_add(1, Relaxed);
    }

    #[inline]
    fn shrink(&self, n: i64) {
        self.live.fetch_sub(n, Relaxed);
    }
}

static SCOPES: [Counters; MAX_SCOPES] = [const { Counters::new() }; MAX_SCOPES];
static GLOBAL: Counters = Counters::new();
static NAMES: Mutex<Vec<&'static str>> = Mutex::new(Vec::new());
static TRACKING: AtomicBool = AtomicBool::new(false);

thread_local! {
    static CURRENT: Cell<u8> = const { Cell::new(0) };
}

fn names() -> std::sync::MutexGuard<'static, Vec<&'static str>> {
    let mut n = warden_core::sync::lock(&NAMES);
    if n.is_empty() {
        n.push("core");
    }
    n
}

/// Stable small id for a scope name (registered on first use; scope 0 is
/// "core": startup and anything not attributed elsewhere).
pub fn scope_id(name: &'static str) -> u8 {
    let mut n = names();
    if let Some(i) = n.iter().position(|x| *x == name) {
        return i as u8;
    }
    if n.len() >= MAX_SCOPES {
        return (MAX_SCOPES - 1) as u8;
    }
    n.push(name);
    (n.len() - 1) as u8
}

/// Charge allocations on this thread to `id` until the guard is dropped.
pub struct Enter(u8);

pub fn enter(id: u8) -> Enter {
    Enter(CURRENT.try_with(|c| c.replace(id)).unwrap_or(0))
}

/// Make `id` the default scope of the current thread (sensor threads).
pub fn set_thread_scope(id: u8) {
    let _ = CURRENT.try_with(|c| c.set(id));
}

impl Drop for Enter {
    fn drop(&mut self) {
        let _ = CURRENT.try_with(|c| c.set(self.0));
    }
}

#[inline]
fn current() -> u8 {
    CURRENT.try_with(|c| c.get()).unwrap_or(0)
}

/// Global allocator that attributes heap usage to scopes. Install it in the
/// binary: `#[global_allocator] static A: TrackingAlloc = TrackingAlloc;`
/// and call [`mark_tracking`] at startup.
pub struct TrackingAlloc;

const HDR: usize = 16;

#[inline]
fn header(l: &Layout) -> usize {
    l.align().max(HDR)
}

// SAFETY: every block handed out is `HDR`-or-more bytes into a block from
// `System` allocated with the same (size + header, align ≥ 16) layout that
// `dealloc`/`realloc` reconstruct; the scope byte lives inside the header.
unsafe impl GlobalAlloc for TrackingAlloc {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        let hdr = header(&l);
        let Some(Ok(inner)) = l.size().checked_add(hdr).map(|s| Layout::from_size_align(s, hdr)) else {
            return std::ptr::null_mut();
        };
        // SAFETY: `inner` has non-zero size.
        let base = unsafe { System.alloc(inner) };
        if base.is_null() {
            return base;
        }
        let id = current();
        // SAFETY: `base + hdr` is inside the block; the byte before it is ours.
        unsafe {
            let user = base.add(hdr);
            user.sub(1).write(id);
            SCOPES[id as usize % MAX_SCOPES].grow(l.size() as i64);
            GLOBAL.grow(l.size() as i64);
            user
        }
    }

    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        let hdr = header(&l);
        let Some(Ok(inner)) = l.size().checked_add(hdr).map(|s| Layout::from_size_align(s, hdr)) else {
            return std::ptr::null_mut();
        };
        // SAFETY: as in `alloc`.
        let base = unsafe { System.alloc_zeroed(inner) };
        if base.is_null() {
            return base;
        }
        let id = current();
        // SAFETY: as in `alloc`.
        unsafe {
            let user = base.add(hdr);
            user.sub(1).write(id);
            SCOPES[id as usize % MAX_SCOPES].grow(l.size() as i64);
            GLOBAL.grow(l.size() as i64);
            user
        }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, l: Layout) {
        let hdr = header(&l);
        // SAFETY: `ptr` came from `alloc` with this layout (GlobalAlloc
        // contract), so the header and the base pointer are valid.
        unsafe {
            let id = ptr.sub(1).read();
            SCOPES[id as usize % MAX_SCOPES].shrink(l.size() as i64);
            GLOBAL.shrink(l.size() as i64);
            System.dealloc(ptr.sub(hdr), Layout::from_size_align_unchecked(l.size() + hdr, hdr));
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, l: Layout, new_size: usize) -> *mut u8 {
        let hdr = header(&l);
        let Some(Ok(_)) = new_size.checked_add(hdr).map(|s| Layout::from_size_align(s, hdr)) else {
            return std::ptr::null_mut();
        };
        // SAFETY: `ptr` came from `alloc` with layout `l`; System.realloc
        // keeps the first min(old, new) bytes, which include the header.
        unsafe {
            let id = ptr.sub(1).read();
            let base =
                System.realloc(ptr.sub(hdr), Layout::from_size_align_unchecked(l.size() + hdr, hdr), new_size + hdr);
            if base.is_null() {
                return base;
            }
            let c = &SCOPES[id as usize % MAX_SCOPES];
            let delta = new_size as i64 - l.size() as i64;
            if delta >= 0 {
                c.grow(delta);
                GLOBAL.grow(delta);
            } else {
                c.shrink(-delta);
                GLOBAL.shrink(-delta);
            }
            base.add(hdr)
        }
    }
}

/// Called by the binary that installed [`TrackingAlloc`].
pub fn mark_tracking() {
    TRACKING.store(true, Relaxed);
}

pub fn heap_tracking() -> bool {
    TRACKING.load(Relaxed)
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct HeapScope {
    pub scope: &'static str,
    /// Bytes currently allocated by this scope.
    pub live: i64,
    pub peak: i64,
    /// Bytes allocated since start (churn).
    pub allocated: u64,
    pub allocations: u64,
}

pub fn heap() -> (HeapScope, Vec<HeapScope>) {
    let n = names().clone();
    let snap = |name, c: &Counters| HeapScope {
        scope: name,
        live: c.live.load(Relaxed),
        peak: c.peak.load(Relaxed),
        allocated: c.total.load(Relaxed),
        allocations: c.count.load(Relaxed),
    };
    let total = snap("total", &GLOBAL);
    let v = n.iter().enumerate().map(|(i, name)| snap(name, &SCOPES[i])).collect();
    (total, v)
}

// ---------------------------------------------------------------------------
// detector ticks
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, serde::Serialize)]
pub struct ModuleStats {
    pub thread: String,
    pub ticks: u64,
    pub usage: Usage,
    pub busy_us: u64,
    pub max_tick_us: u64,
    pub last_tick_us: u64,
}

static MODULES: Mutex<BTreeMap<&'static str, ModuleStats>> = Mutex::new(BTreeMap::new());

/// Measure one tick of `module` (call on the thread that runs it).
pub struct Tick {
    module: &'static str,
    before: Usage,
    started: std::time::Instant,
    _scope: Enter,
}

pub fn tick(module: &'static str, scope: u8) -> Tick {
    Tick { module, before: selfstat::thread_usage(), started: std::time::Instant::now(), _scope: enter(scope) }
}

impl Tick {
    /// Finish the measurement; returns the wall time of the tick.
    pub fn finish(self) -> Duration {
        let took = self.started.elapsed();
        let mut d = selfstat::thread_usage().saturating_sub(&self.before);
        // the second sample's own read of /proc/thread-self/io
        d.syscr = d.syscr.saturating_sub(1);
        let mut m = warden_core::sync::lock(&MODULES);
        let e = m.entry(self.module).or_default();
        if e.thread.is_empty() {
            e.thread = std::thread::current().name().unwrap_or("?").to_owned();
        }
        e.ticks += 1;
        e.usage.add(&d);
        let us = took.as_micros() as u64;
        e.busy_us += us;
        e.last_tick_us = us;
        e.max_tick_us = e.max_tick_us.max(us);
        took
    }
}

pub fn modules() -> BTreeMap<&'static str, ModuleStats> {
    warden_core::sync::lock(&MODULES).clone()
}

/// Which module(s) a thread serves (for the per-thread table).
pub fn thread_role(name: &str) -> &'static str {
    match name {
        "w-sched-fast" => "memory cpu io limits network hw kernel stall",
        "w-sched-slow" => "disk process integrity systemd tuning",
        "w-sched-health" => "health checks",
        "w-psi_trigger" => "memory (PSI trigger)",
        "w-kmsg" => "kernel log",
        "w-auth" => "auth",
        "w-proc_connecto" => "process (exec events)",
        "w-access_log" => "fim (access log)",
        "w-waf" => "waf",
        "w-fim" => "fim (worker)",
        "w-fim_realtime" => "fim (fanotify)",
        "w-respond" => "actions",
        "w-notify" => "notifications",
        "w-suid-scan" => "integrity (SUID walk)",
        "w-suid_realtime" => "integrity (SUID, fanotify)",
        "w-systemd_dbus" => "systemd (D-Bus)",
        "w-disk-du" => "disk (usage report)",
        "w-blocking" => "control socket helpers",
        "wardend" => "engine, control socket, metrics",
        _ => "",
    }
}

/// Full self-profile (served over the control socket).
pub fn report() -> serde_json::Value {
    let (total, scopes) = heap();
    let threads: Vec<serde_json::Value> = selfstat::threads()
        .into_iter()
        .map(|t| {
            serde_json::json!({
                "tid": t.tid, "name": t.name, "role": thread_role(&t.name),
                "usage": t.usage, "ctx_switches": t.ctx_switches,
            })
        })
        .collect();
    let cgroup = selfstat::self_cgroup().and_then(|cg| {
        let m = warden_sys::cgroup::memory_usage(&cg)?;
        Some(serde_json::json!({
            "path": cg, "usage": m, "pinned": m.pinned(), "reclaimable": m.reclaimable(),
        }))
    });
    serde_json::json!({
        "ts_ms": warden_core::event::now_ms(),
        "process": selfstat::process_usage(),
        "threads": threads,
        "modules": modules(),
        "heap_tracking": heap_tracking(),
        "heap_total": total,
        "heap": scopes,
        "malloc": selfstat::malloc_info(),
        "cgroup": cgroup,
        "page_cache_guard": warden_sys::pagecache::available(),
    })
}

/// Publish profile gauges/counters into the metrics registry.
pub fn export(m: &crate::runtime::Metrics) {
    let p = selfstat::process_usage();
    m.set("warden_self_rss_bytes", &[("kind", "anon")], p.rss_anon as f64);
    m.set("warden_self_rss_bytes", &[("kind", "file")], p.rss_file as f64);
    m.set("warden_self_threads", &[], p.threads as f64);
    m.set("warden_self_cpu_seconds_total", &[], p.usage.cpu_us() as f64 / 1e6);
    m.set("warden_self_children_cpu_seconds_total", &[], p.children_cpu_us as f64 / 1e6);
    if let Some(cg) = selfstat::self_cgroup()
        && let Some(u) = warden_sys::cgroup::memory_usage(&cg)
    {
        m.set("warden_self_cgroup_memory_bytes", &[("kind", "anon")], u.anon as f64);
        m.set("warden_self_cgroup_memory_bytes", &[("kind", "page_cache")], u.file as f64);
        m.set("warden_self_cgroup_memory_bytes", &[("kind", "kernel")], u.kernel as f64);
    }
    for (name, s) in modules() {
        m.set("warden_module_cpu_seconds_total", &[("module", name)], s.usage.cpu_us() as f64 / 1e6);
        m.set("warden_module_read_bytes_total", &[("module", name)], s.usage.rchar as f64);
        m.set("warden_module_ticks_total", &[("module", name)], s.ticks as f64);
    }
    for t in selfstat::threads() {
        m.set("warden_thread_cpu_seconds_total", &[("thread", &t.name)], t.usage.cpu_us() as f64 / 1e6);
    }
    for (scan, s) in warden_sys::pace::stats() {
        let l = [("scan", scan)];
        m.set("warden_pacing_duty", &l, s.duty);
        m.set("warden_pacing_active", &l, if s.active { 1.0 } else { 0.0 });
        m.set("warden_pacing_paced_seconds_total", &l, s.paced_seconds);
        m.set("warden_pacing_deferrals_total", &l, s.deferrals as f64);
        if let Some(p) = s.io_pressure {
            m.set("warden_pacing_io_pressure_ratio", &l, p);
        }
    }
    if heap_tracking() {
        let (total, scopes) = heap();
        m.set("warden_self_heap_bytes", &[], total.live as f64);
        for s in scopes {
            m.set("warden_module_heap_bytes", &[("module", s.scope)], s.live as f64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scopes_and_ticks() {
        let a = scope_id("test-scope-a");
        assert_eq!(scope_id("test-scope-a"), a);
        assert_ne!(scope_id("test-scope-b"), a);
        let t = tick("test-module", a);
        let v: Vec<u8> = vec![1; 1000];
        std::hint::black_box(&v);
        let _ = std::fs::read("/proc/self/status");
        t.finish();
        let m = modules();
        let s = &m["test-module"];
        assert_eq!(s.ticks, 1);
        assert!(s.usage.syscr >= 1);
    }
}
