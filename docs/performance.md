# Performance: what each module costs

Warden is meant to run on the smallest VPS next to the workload it guards.
This page records what every module costs in CPU, I/O and memory, how that
was measured, and how to measure it on your own host.

## Results: 0.11.0 → 0.12.0

Same VM and method as below. For the rows that changed, 0.11.0 was re-run
on the same stand the same day (`bench/results/0.12.0/ab-0.11.0`); the full
0.12 matrix is in `bench/results/0.12.0`
(`python3 bench/compare.py bench/results/0.12.0/ab-0.11.0 bench/results/0.12.0`).
Every module not listed is within noise of 0.11.

| module | CPU at start, s | CPU steady, % of a core | wake-ups/s | read, MiB |
|---|---:|---:|---:|---:|
| `process` (300 idle processes, 20 exec/s) | 0.27 → **0.18** | 0.51 → **0.26** | 56.1 → **40.6** | 44.5 → **19.7** |
| `exec_storm` (300 exec/s from one parent) | 1.26 → **0.78** | 3.08 → **1.77** | 534.7 → **379.4** | 317.9 → **110.2** |
| `integrity` ¹ | 0.03 → 0.01 | 0.00 → 3.62 | 0.3 → 1.0 | 0.7 → 0.8 |
| `all` ¹ | 2.99 → 2.85 | 1.04 → 3.38 | 92.1 → **75.3** | 741.7 → **653.7** |

¹ The first SUID walk (5.7 s of CPU, see below) falls inside the
measurement window in 0.12 and outside it in 0.11. Without it, the live
threads of `all` add up to 1.01% of a core (0.11: 1.03%): at 20 exec/s the
exec sensor saves 0.1% (0.385% → 0.278%) and FIM, unchanged, dominates.
Memory cgroup peak of these two rows: 13 → 779 MiB and 114 → 874 MiB, all
of it the walk's reclaimable directory cache and dentry/inode slab.

Per thread:

| scenario, thread | CPU, s | read/write calls/s | read, MiB |
|---|---:|---:|---:|
| `process`, `w-proc_connector` (exec events) | 0.43 → **0.22** | 265 → **42** | 34.7 → **12.1** |
| `process`, `w-sched-slow` (periodic scan) | 0.06 → **0.05** | 90 → **23** | 9.8 → **7.5** |
| `exec_storm`, `w-proc_connector` | 2.75 → **1.60** | 2615 → **480** | 317.2 → **109.8** |

Per `exec`, with [`bench/exec_syscalls.py`](../bench/exec_syscalls.py)
(1 800 execs at ~390/s: `sleep 0.3` and `sh -c "sleep 0.3; :"` from one
parent, as root; CPU of the sensor thread without tracing, system calls with
`strace -c` in a second burst):

| | CPU per exec | system calls per exec | `/proc` opens per exec |
|---|---:|---:|---:|
| 0.11.0 | 183 µs | 36.5 | 6.3 |
| 0.12.0, `exec_fast_path = false` (parent cache, kernel filter, `recvmmsg`, one `read` per file) | 150 µs | 24.1 | 5.3 |
| **0.12.0** (default) | **94 µs** | **13.5** | **2.2** |

The children here live long enough to be analysed; the ~68 system calls
quoted for 0.11 below came from a load of short-lived processes and counted
differently, so compare rows of the same table only. Per call, without the
kernel side (`cargo run --release -p warden-detect --example execbench`):
full analysis ~31 µs, fast path ~9 µs. The biggest single cost left is
reading another process's `environ` (~15 µs) for the LD_PRELOAD check of
root processes, which is why the fast path samples it; non-root build users
never pay it.

What changed:

* **Exec sensor** — parent cache, the fast path for repeated benign
  combinations, kernel-side filtering of fork events (6.6+), `recvmmsg`,
  single-`read` `/proc` files. See [detectors.md](detectors.md#how-exec-events-are-analysed)
  for what the fast path still checks.
* **Periodic process scan** — with the connector running, the table comes
  from `stat` only; user names, descriptor lists and `status` are read only
  for the processes a rule needs.
* **SUID walk** — replaced by fanotify filesystem marks (the
  `w-suid_realtime` thread: 0.0 s CPU, 0.6 wake-ups/s on this VM). The walk
  now runs at +2 min only without a fresh baseline (first start, upgrade
  from 0.11) and then every 7 days, instead of ~5 min after every start and
  every 6 hours. One walk of the default roots on this VM: **5.7 s CPU,
  286 MiB read, ~780 MiB charged to the cgroup** (282 MiB page cache of
  directories, 495 MiB dentry/inode slab — reclaimable, but it is what
  `systemctl status` shows). That is why the `integrity` row looks worse in
  0.12: the 200 s scenario now contains the first walk (+120 s), while 0.11
  only reached it at its second tick (+300 s), after the measurement ended.
  Per day: 0.11 ≥ 4 walks, 0.12 one per week.
* **systemd** — no `systemctl` process every 30 s while the D-Bus
  subscription is up; a failed unit is reported ~40 ms after systemd's
  signal instead of up to 30 s later (measured by
  `crates/warden-detect/tests/systemd_dbus.rs`, including the fake
  service's 20 ms loop and the `journalctl` call for the log tail; the VM
  has no systemd, so the `systemd` row cannot show it — the D-Bus thread
  is not even created there).
* **Disk usage report** — costs nothing until a cleanup fails; then one
  bounded walk per mount per day at idle I/O priority, paced since 0.13.1
  ([below](#background-scans-and-io-pressure); `wardenctl du /usr`:
  155 000 entries in 3.8 s on this VM).

## Results: 0.10.0 → 0.11.0

Measured with [`bench/profile.py`](../bench/profile.py) on a 2-vCPU / 8 GiB
VM (kernel 6.18). Every row runs the daemon with **only that module
enabled** (the `all` row: production defaults with every load at once);
loads are listed [below](#the-lab-matrix-benchprofilepy). "At start" is CPU
spent in the first 40 s (first scans, baselines); "steady" is the rate
afterwards; the cgroup column is what `systemctl status` would call
*Memory:* (anon + page cache + kernel). The raw data of these two releases
lives in the `v0.10.0` and `v0.11.0` tags (`bench/results/`); any two result
directories are compared with `python3 bench/compare.py <old> <new>`.

| module | CPU at start, s | CPU steady, % of a core | wake-ups/s | RSS, MiB | peak RSS, MiB | threads | memory cgroup peak, MiB | read, MiB |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `idle` | 0.14 → **0.01** | 0.04 → **0.00** | 8.5 → **0.3** | 46.5 → **9.4** | 50.6 → **9.4** | 16 → **5** | 47 → **10** | 0.0 → **0.0** |
| `memory` | 0.14 → **0.00** | 0.04 → **0.04** | 8.6 → **1.1** | 46.7 → **9.6** | 50.8 → **9.6** | 16 → **6** | 47 → **11** | 0.3 → **0.3** |
| `cpu` | 0.21 → **0.00** | 0.04 → **0.02** | 8.5 → **0.3** | 46.5 → **9.5** | 50.7 → **9.5** | 16 → **5** | 47 → **10** | 0.0 → **0.0** |
| `io` | 0.23 → **0.00** | 0.04 → **0.02** | 8.5 → **0.3** | 46.7 → **9.6** | 50.6 → **9.6** | 16 → **5** | 47 → **10** | 0.0 → **0.0** |
| `stall` | 0.16 → **0.00** | 0.02 → **0.02** | 8.5 → **1.1** | 46.5 → **9.7** | 50.7 → **9.7** | 16 → **5** | 47 → **10** | 0.0 → **0.0** |
| `limits` | 0.19 → **0.01** | 0.04 → **0.00** | 8.5 → **0.3** | 46.6 → **9.4** | 50.7 → **9.4** | 16 → **5** | 47 → **10** | 0.0 → **0.0** |
| `network` | 0.15 → **0.01** | 0.04 → **0.02** | 8.6 → **0.3** | 46.8 → **9.9** | 50.9 → **9.9** | 16 → **5** | 47 → **10** | 0.1 → **0.1** |
| `hardware` | 0.15 → **0.00** | 0.04 → **0.00** | 8.6 → **0.3** | 46.5 → **9.4** | 50.6 → **9.4** | 16 → **5** | 47 → **10** | 0.0 → **0.0** |
| `kernel` | 0.16 → **0.01** | 0.04 → **0.04** | 10.1 → **2.7** | 48.8 → **12.5** | 52.9 → **12.5** | 16 → **6** | 49 → **13** | 0.0 → **0.0** |
| `disk` | 0.15 → **0.01** | 0.02 → **0.00** | 8.6 → **0.4** | 46.7 → **9.8** | 51.0 → **9.8** | 16 → **6** | 48 → **11** | 0.0 → **0.0** |
| `process` | 0.52 → **0.22** | 0.69 → **0.45** | 65.0 → **55.5** | 48.1 → **10.9** | 52.2 → **10.9** | 16 → **7** | 51 → **14** | 42.4 → **44.4** |
| `integrity` | 0.18 → **0.03** | 0.03 → **0.00** | 8.6 → **0.3** | 47.4 → **10.3** | 51.6 → **10.3** | 16 → **6** | 54 → **13** | 0.7 → **0.7** |
| `systemd` | 0.14 → **0.01** | 0.04 → **0.00** | 8.6 → **0.3** | 46.6 → **9.4** | 50.8 → **9.4** | 16 → **6** | 47 → **10** | 0.0 → **0.0** |
| `auth` | 0.16 → **0.01** | 0.06 → **0.02** | 10.1 → **1.3** | 47.5 → **10.7** | 51.4 → **10.7** | 16 → **6** | 48 → **11** | 0.1 → **0.1** |
| `fim` | 11.75 → **2.59** | 100.00 → **0.34** | 319.2 → **20.8** | 641.2 → **21.0** | 641.2 → **24.3** | 16 → **8** | 1345 → **99** | 593.8 → **592.2** |
| `access_log` | 11.14 → **2.38** | 99.49 → **0.03** | 10.3 → **1.3** | 651.2 → **21.5** | 651.2 → **22.8** | 16 → **7** | 1351 → **88** | 594.7 → **594.7** |
| `waf` | 0.20 → **0.03** | 0.12 → **0.08** | 28.4 → **12.6** | 49.1 → **10.9** | 50.6 → **10.9** | 16 → **6** | 50 → **12** | 1.0 → **1.0** |
| `health` | 0.16 → **0.02** | 0.06 → **0.02** | 9.2 → **1.0** | 47.1 → **10.2** | 51.2 → **10.2** | 16 → **6** | 48 → **11** | 0.0 → **0.0** |
| `tuning` | 0.14 → **0.00** | 0.04 → **0.00** | 8.6 → **0.3** | 46.6 → **9.5** | 50.8 → **9.5** | 16 → **6** | 47 → **10** | 0.0 → **0.0** |
| `all` | 12.01 → **2.99** | 100.67 → **1.04** | 420.2 → **92.1** | 664.9 → **33.7** | 664.9 → **36.6** | 16 → **15** | 1376 → **114** | 753.0 → **741.7** |

In 0.10 the FIM rows are capped by the run length: the first baseline was
still running when the measurement ended (the `fim` scenario runs 240 s,
`all` 300 s); "steady" 100% means one core busy for the whole run.

What the numbers say:

* **A disabled module now costs nothing.** With everything disabled 0.10
  ran 16 threads, woke up 8.5 times a second and held 46.5 MiB — 38 MiB of
  it FIM signatures compiled (twice) even with `fim.enabled = false`. 0.11
  runs 5 threads (main, fast scheduler, responder, notifier, one blocking-pool
  thread), wakes 0.3 times a second and holds 9.4 MiB. Every single-module row
  is now "idle + that module".
* **FIM was the bottleneck by two orders of magnitude.** On a 590 MiB site
  0.10 did not finish its first baseline in 240 s of CPU (the Unicode
  signature set over a lossy UTF-8 copy ran below 3 MiB/s), held the content
  of every file until the walk ended (641 MiB RSS) and left 673 MiB of page
  cache charged to Warden's cgroup. 0.11 builds the baseline in ~2.6 s of
  CPU (~230 MiB/s), at 21 MiB RSS, and evicts the cache it pulled in: the
  cgroup peaks at 99 MiB instead of 1.35 GiB.
* **fanotify noise is muted in the kernel.** 300 writes/s outside the site
  (same mount) cost 307 wake-ups/s in 0.10; busy directories outside the
  sites are now ignored with `FAN_MARK_IGNORE` (5 wake-ups/s).
* **The exec sensor is the remaining steady cost** — it reads `/proc` for
  every `exec` on the host. See the per-exec figures below.

### Per thread, everything enabled (`all`, 300 s)

| thread | 0.10 CPU, s | 0.11 CPU, s | 0.10 → 0.11 wake-ups/s | 0.10 → 0.11 syscalls/s |
|---|---:|---:|---:|---:|
| `w-fim` (worker: baseline, signatures) | 268.20 (unfinished) | **3.43** | 21.9 → 8.8 | 0 → 15 |
| `w-proc_connector` (exec events) | 1.73 | **1.15** | 60.4 → 59.8 | 1119 → **274** |
| `w-fim_realtime` (fanotify) | 1.70 | **0.28** | 307.8 → **5.2** | 430 → 45 |
| `w-sched-slow` (disk, process, integrity, systemd, tuning) | 0.22 | 0.20 | 1.4 → 0.2 | 344 → 97 |
| `w-waf`, `w-access_log`, `w-auth`, `w-kmsg` | 0.27 | 0.19 | 8.7 → 7.3 | 16 → 11 |
| `w-sched-fast` (memory … stall) | 0.04 | 0.05 | 1.4 → 1.4 | 17 → 8 |
| main / `w-async` ×2 (engine, control, metrics) | 0.17 | 0.29 | 9.4 → 5.8 | 11 → 20 |
| `w-notify`, `w-respond`, `w-psi_trigger`, `w-sched-health` | 0.03 | 0.04 | 9.0 → 1.8 | 32 → 0 |

### Exec events (0.11)

Every `exec` on the host is analysed: the process's `stat`, `status`,
`cmdline`, `cgroup`, `exe`, the parent's `status` (and, only when a rule
needs it, the parent's `exe`/`cgroup`), and `environ` of root processes
(LD_PRELOAD check). With `strace -c` on the sensor thread:

| | syscalls per exec | CPU per exec |
|---|---:|---:|
| 0.10 | ~134 (`std::fs::read`: `statx` + ~6 growing reads per `/proc` file; `poll` before every `recv`) | ~290 µs |
| 0.11 | **~68** (one 8 KiB block read + EOF read; `recv(MSG_DONTWAIT)` first) | **~195 µs** |

At 20 `exec`/s that is 0.4% of a core. A CI/build server running thousands
of `exec`/s pays proportionally; there `process.proc_connector = false`
keeps the periodic scan (every `scan_interval`) and drops the per-exec cost.

### Signature engine

`cargo run --release -p warden-detect --example sigbench -- <tree>` on the
590 MiB test site (39 built-in rules):

| engine | throughput |
|---|---:|
| 0.10: Unicode `RegexSet` over a lossy UTF-8 copy | 1.3 MiB/s |
| 39 separate byte regexes (`is_match` each) | 87 MiB/s |
| **0.11: one ASCII byte `RegexSet`** (+ PHP entropy heuristics) | **437 MiB/s** |

Compiling the set takes ~10 ms (and happens only when FIM is enabled).

### Heap with everything disabled (valgrind DHAT, 30 s)

| | allocated in total | live at peak | blocks |
|---|---:|---:|---:|
| 0.10 | 282 MB | 44.5 MB (38.5 MB of it FIM signatures) | 1 381 398 |
| 0.11 | **1.1 MB** | **0.26 MB** | 10 190 |

### What `wardenctl profile` shows under the full load

```
Warden 0.11.0 — self profile over 20.0s (uptime 169s)

Process   RSS 31.2MiB (anon 21.4MiB, file 9.8MiB), peak 34.3MiB, threads 15, CPU total 4.35s
          CPU now 1.20% of one core
Heap      live 18.6MiB, peak 20.7MiB, allocated since start 377.5MiB in 1362942 allocations
malloc    from OS 22.7MiB, in use 21.7MiB, free (cached) 975.7KiB
Scans     evict the page cache they bring in (cachestat available)

DETECTOR       THREAD             ticks       CPU  CPU now  avg tick  max tick       read  block I/O
disk           w-sched-slow           6     0.01s    0.00%     2.74ms     15.2ms    13.8KiB   136.0KiB
integrity      w-sched-slow           1     0.02s    0.00%    24.94ms     24.9ms   728.6KiB     3.6MiB
memory         w-sched-fast          85     0.00s    0.00%     0.17ms      0.3ms   465.5KiB          0
network        w-sched-fast          17     0.01s    0.01%     0.67ms      2.7ms   101.2KiB    20.0KiB
process        w-sched-slow          12     0.10s    0.06%     9.50ms     31.8ms    13.3MiB          0
…

HEAP SCOPE             live       peak    allocated  alloc/s now
fim                  8.1MiB    14.0MiB     140.4MiB    799.1KiB/s     ← baseline of 20 000 files
access_log           3.5MiB     3.5MiB      10.3MiB    130.6KiB/s     ← 15 min ring at 200 req/s
engine               2.2MiB     2.2MiB      12.4MiB     63.5KiB/s     ← event ring
kmsg                 2.0MiB     2.6MiB      15.0MiB        411B/s     ← compiled rules + kernel log tail
proc_connector     401.6KiB   436.8KiB     118.9MiB    702.2KiB/s
…
```

## Background scans and I/O pressure

Three scans read a lot of metadata in one go: the disk-usage walk (when a
disk is critical and cleanup did not help), the SUID/SGID walk (a full one
per `suid_rescan`) and the scheduled FIM rescan of each site. Since 0.13.1
they yield to the workload (`[daemon.pacing]`, on by default):

* **What is measured.** PSI `some` for I/O — the share of time at least one
  task waited for I/O. A scan's own waits are part of that number, so the
  pressure the *others* feel is measured while the scan pauses (every stall
  in a pause belongs to someone else). While the scan works, the system-wide
  stall minus the stall of Warden's own cgroup is a lower bound of the
  others' stall; when even the bound exceeds the target the scan backs off
  at once.
* **Duty cycle.** The scan works in 200 ms quanta and pauses after each so
  that work / (work + pause) is its duty. Above `io_pressure` (10 %) the duty
  halves, down to a floor, so every scan finishes: ¼ for the disk walk (at
  most 4× slower; its `usage_report_max_time` counts working time, with a
  hard 4× wall-clock cap), ⅒ for the SUID walk (nothing waits for it), ½ for
  FIM (its worker processes real-time writes only between scans). Below half
  the target the duty grows back. At full speed a 50 ms probe pause per 2 s
  of work (2.5 %) keeps the measurement fresh.
* **I/O class.** While the duty is reduced or the pressure is noticeable,
  the scanning thread is in the idle class; on a quiet disk it is in
  best-effort level 7, so that the occasional write of a quiet host does not
  stall a scan for seconds (mq-deadline lets idle requests wait up to
  `prio_aging_expire`, 10 s). `io_class = "idle"` keeps the idle class
  throughout. `bfq` and `mq-deadline` honour the classes; `none` and `kyber`
  — the default for NVMe — ignore them, and there the duty cycle is what
  protects the workload (`wardenctl doctor` shows the scheduler).
* **Start.** A scheduled SUID or FIM rescan that finds `io some avg10` above
  the target is postponed by 2 minutes, for at most `max_defer` (1 h) in a
  row; then it runs anyway, paced. The first baseline and a SUID walk after
  lost real-time events are not postponed. While FIM waits, real-time writes
  are still processed.
* **Never paced:** `wardenctl du`, `wardenctl fim scan`, cleanup actions —
  someone is waiting for them.

What it does is visible in `wardenctl status` (`Pacing:` line), in
`warden_pacing_*` metrics per scan (duty, time paused, postponed starts, the
others' pressure), in `paced_seconds` of `disk.usage_report` and of FIM scan
results, and in the `postponed` log lines.

**Lab check** (2-vCPU VM, virtio disk, `du` of `/usr`: 159 000 entries,
caches dropped before each run — the host's cache still serves most of it,
the very first cold walk took 5.0 s; the "workload" is a WAL-like loop of
16 KiB writes + `fdatasync`; every row run 3 times):

| | walk | paused | duty at the end |
|---|---|---|---|
| quiet disk, unpaced | 1.3–1.4 s | — | — |
| quiet disk, paced | 1.3–1.4 s | 0.1 s (the probes) | 1.0 |
| WAL workload, unpaced | 2.2–2.3 s | — | — |
| WAL workload, paced | 8.5–8.6 s | 6.3 s | 0.25 (others' pressure ≈ 48 %) |

On a quiet disk pacing costs nothing measurable. Under the WAL workload the
walk drops to its floor and takes 3.7× longer. On this VM the walk did not
measurably slow the workload either way (its throughput varied by ±30 %
between runs on its own; the host page cache serves most metadata reads), so
the lab shows the mechanism, not the benefit: that needs a disk the scan
really competes for (a rotating disk, network block storage, a saturated
SSD). Note the trade-off: PSI tells that someone waits, not who caused it —
a workload that always waits on `fsync` keeps scans at their floor even when
they are not the cause. That is deliberate: Warden assumes it might be.

## Measuring on your own host

### Live, from the running daemon

```
sudo wardenctl profile -i 10
```

Two samples ten seconds apart:

* **Process** — RSS split into anonymous and file-backed memory, peak RSS,
  locked memory, CPU now and since start (plus reaped helpers such as
  `systemctl`, `journalctl`, `nft`).
* **Heap** — bytes live and allocated since start, charged to the module that
  allocated them (tracking allocator; build feature `alloc-stats`, on by
  default; overhead: a 16-byte header and a few atomic adds per allocation).
* **cgroup** — what `systemctl status wardend` reports as *Memory:*, split
  into anon / page cache / kernel, with the pinned vs. reclaimable total.
  Page cache and reclaimable slab are **not** Warden's own memory: the
  kernel drops them under pressure (see below).
* **Threads** — CPU, wake-ups/s, bytes read/written and syscalls per thread,
  with the module each thread serves.
* **Detectors** — per detector: ticks, CPU, average/maximum tick time and
  bytes read, measured around each tick with `getrusage(RUSAGE_THREAD)` and
  `/proc/thread-self/io` (detectors sharing a scheduler thread are separated).
* **Running / disabled components** — a disabled module has no thread.

The same numbers are exported to Prometheus: `warden_module_cpu_seconds_total`,
`warden_module_read_bytes_total`, `warden_module_ticks_total`,
`warden_module_heap_bytes`, `warden_thread_cpu_seconds_total`,
`warden_self_rss_bytes{kind}`, `warden_self_cgroup_memory_bytes{kind}`,
`warden_self_heap_bytes`, `warden_suid_scan_entries`, `warden_suid_scan_seconds`.

### The lab matrix (`bench/profile.py`)

```
cargo build --release
sudo python3 bench/profile.py --wardend target/release/wardend            # ≈ 35 min
sudo python3 bench/profile.py --only idle,fim,all --duration 120
sudo python3 bench/exec_syscalls.py --wardend target/release/wardend   # system calls and CPU per exec
cargo run --release -p warden-detect --example execbench                # full analysis vs fast path, per call
```

For each scenario the script writes a configuration in which **everything is
disabled except the module under test**, drops the page cache, starts the
daemon (dry-run) inside its own memory cgroup, drives a synthetic load and
samples `/proc/<pid>/task/*/{stat,status,io}`, `/proc/<pid>/status` and the
cgroup every second. CPU "startup" is everything up to `--warmup` (40 s:
first scans, baselines); "steady" is the rate after it.

| scenario | load |
|---|---|
| `idle` | nothing enabled — the daemon core |
| `memory`, `cpu`, `io`, `stall`, `limits`, `network`, `hardware` | none (they read `/proc` and `/sys`) |
| `kernel` | 20 kernel messages/s written to `/dev/kmsg` |
| `disk` | 10 s interval |
| `process` | 300 idle processes + 20 `exec`/s |
| `exec_storm` | process module, 200 spawns/s from one parent (`/bin/true` and `sh -c "true; :"`, i.e. 300 `exec`/s) |
| `integrity` | the real system; SUID walk after 120 s (200 s run) |
| `systemd` | `systemctl list-units --state=failed` every 30 s |
| `auth` | 10 auth.log lines/s (20% failed SSH logins) |
| `fim` | a 20 000-file, ~590 MiB site: baseline, 5 writes/s inside, 300 writes/s outside the site on the same mount |
| `access_log` | the same site, 200 requests/s in the access log |
| `waf` | 20 ModSecurity denials/s (nginx error log) |
| `health` | 3 HTTP + 3 TCP checks every 10 s |
| `tuning` | workload detection and sysctl advice |
| `all` | production defaults with every load above at once |

Heap attribution of a single run: build with symbols and use valgrind DHAT:

```
cargo build --profile profiling -p wardend
sudo valgrind --tool=dhat --dhat-out-file=dhat.json target/profiling/wardend --config /etc/warden/warden.toml
python3 bench/dhat_modules.py dhat.json
```

## Page cache, slab and "Memory: 2.8G" in `systemctl status`

The kernel charges a page of file cache to the cgroup of whoever first read
it, and an inode/dentry to whoever first looked the file up. A daemon that
hashes files, reads dpkg's checksum lists and walks the filesystem for SUID
binaries therefore shows a large `memory.current` that is almost entirely
**reclaimable**: it is not Warden's memory, it is the kernel's cache, freed
the moment anything else needs RAM. Since 0.11:

* files read only to be hashed (FIM, integrity, dpkg checksums) are evicted
  after reading **if they were not cached before** (`cachestat(2)`, Linux
  6.5+; on older kernels nothing is evicted — Warden never drops someone
  else's hot data);
* the SUID walk skips `nosuid`, pseudo, network and image filesystems and
  `integrity.suid_exclude` (container layers, snap/flatpak stores), and
  stats only regular files;
* `memory.pressure` events rank `top_cgroups` by memory a cgroup **pins**
  (anon + shmem + unreclaimable kernel memory) and show page cache and
  reclaimable memory separately;
* `wardenctl profile` shows the split for Warden's own cgroup.
