# Warden — Architecture

## Overview

Warden is a single daemon (`wardend`) plus a control CLI (`wardenctl`). The
daemon runs a set of **detectors** and **sensors** that only ever produce
`Event`s. Events flow through an **engine** that applies operator policy,
deduplicates, journals, scores and notifies, and finally hands any attached
**actions** to a **responder** that executes them under strict safety rules.

```
                       ┌───────────────────────────────────────────────┐
  kernel interfaces    │                   wardend                      │
  /proc /sys /dev/kmsg │                                                │
  netlink  fanotify    │   detectors ─┐                                 │
  pidfd  cgroup v2 ────┼─▶  sensors  ─┼─▶ Sink ─▶ bounded queue ─▶ Engine│
                       │              │                        │         │
                       │              │        policy · dedup ·│journal  │
                       │              │        heuristics ·    │metrics  │
                       │              │        notifications   │         │
                       │              │                        ▼         │
                       │              │                    Responder     │
                       │              │        kill · stop · cgroup ·    │
                       │              │        quarantine · cleanup ·    │
                       │   results ◀──┘        block_ip · snapshot       │
                       │                                                 │
                       │   control.sock (root) ◀── wardenctl             │
                       │   127.0.0.1:9184 /metrics /health               │
                       └───────────────────────────────────────────────┘
```

## Crates

| crate | responsibility | depends on |
|---|---|---|
| `warden-core` | config model, event model, actions, policy, hysteresis, rate limiting, control protocol | — |
| `warden-sys` | Linux interface wrappers (PSI, procfs, pidfd, cgroup, kmsg, netlink, fanotify, nftables helpers) | `libc` |
| `warden-detect` | detectors, sensors, FIM, heuristics, the scheduler/supervisor runtime | core, sys |
| `warden-respond` | guarded remediation (kill, cleanup, quarantine, firewall, snapshots) | core, sys |
| `wardend` | the daemon: engine, event log, notifications, control + metrics servers | all |
| `wardenctl` | control CLI and offline diagnostics (`doctor`, `psi`, `mem-top`, `scan`) | core, sys, detect |

The split keeps the privileged, side-effecting code (`warden-respond`) small
and separately testable, and lets `warden-core` stay pure (no I/O) so its
logic — thresholds, policy, scoring — is exhaustively unit-tested.

## Threading model

Only what the configuration enables runs. Each module that needs a thread is
a *component* with a `wanted(config)` predicate (`warden_detect::COMPONENTS`):
a disabled module has **no thread, no timer, no buffers and no compiled
rules**. After a reload the supervisor starts newly enabled components, and
components that are no longer wanted stop themselves (under the registry
lock, so a concurrent re-enable can never be lost).

* **Fast scheduler** (always) — memory, CPU, I/O, limits, network, hardware,
  kernel state. It is the **stall detector** (1 s sleeps whose lateness is
  measured) and its heartbeat feeds the systemd watchdog; with
  `stall.enabled = false` it wakes only every 5 s.
* **Slow scheduler** — disk, process scan, integrity, systemd units, tuning;
  **health scheduler** — HTTP/TCP/command probes (a hung endpoint cannot delay
  disk checks). Schedulers sleep until the next detector is due — no fixed
  polling — and are woken immediately by a reload.
* **Event-driven sensors**, one supervised thread each: the PSI trigger,
  `/dev/kmsg`, the netlink proc connector, the auth tailer, the fanotify
  watchers (web FIM; SUID/SGID on filesystem marks), the systemd D-Bus
  subscription, the access-log and ModSecurity tailers, and the FIM worker. Blocking
  reads use `poll()` with a timeout, so a reload or shutdown is noticed within
  2 s even on a silent host; a reload restarts a sensor at once (it is not
  counted as a failure).
* **Engine, control socket and metrics endpoint** share the main thread
  (tokio current-thread runtime); a small blocking pool serves slow control
  requests. The event journal has a writer thread of its own (bounded queue):
  a write to a full or hung disk never holds the engine, `status` or
  `/health`. Control-plane state (quarantine, tuning, circuit breakers) lives
  in `Handles`, separate from the executor, so `status`, `quarantine_*`,
  `tuning`, `/health` and shutdown never wait for a running action or hook.
  Accept loops retry on errors, pause on descriptor exhaustion and cap
  concurrent clients.
* **Responder**, two supervised lanes, and the **notifier**, each a thread
  with a bounded queue. Events whose actions contain containment — `kill`,
  `stop`, `freeze_cgroup`, `kill_cgroup`, `block_ip`, `quarantine`,
  `throttle` — go to the *urgent* lane; everything else (`restart_unit`,
  `apt_clean`, journal vacuum, file cleanup, `exec` hooks, `limit_unit`,
  `sysctl`, a lone snapshot) to the *slow* lane, so a kill during a 5-minute
  `apt-get clean` does not wait for it. Within a lane actions run
  sequentially; every kill is in the urgent lane, so two kills never race.
  The lanes share one set of circuit breakers (the hourly budgets,
  cooldowns, the snapshot interval: a slot is reserved under a short lock
  and given back if the action was not attempted). Notifications never
  block detection. A panic restarts the thread; on shutdown the daemon waits
  for both lanes to finish their current action.

The daemon measures itself: every detector tick is wrapped in
`getrusage(RUSAGE_THREAD)` + `/proc/thread-self/io`, and a tracking allocator
charges each heap allocation to the module that made it (`wardenctl profile`,
`warden_module_*` metrics, [performance.md](performance.md)).

Background scans (the disk-usage walk, the SUID/SGID walk, scheduled FIM
scans) run at nice 19 in the idle I/O class and are **paced by I/O
pressure** (`warden_sys::pace`): they pause between 200 ms quanta when other
tasks wait for I/O, move between the idle and best-effort-7 classes, and a
scheduled rescan that finds the disk busy is postponed (bounded). Details and
measurements: [performance.md](performance.md#background-scans-and-io-pressure).

Two clocks. `Instant` (`CLOCK_MONOTONIC`) stops while the machine is
suspended; it measures what must be continuous — sustain and hysteresis,
timeouts, rates. What an operator configures and reads in real time — dedup
windows, cooldowns, per-hour budgets, back-offs, scan schedules, suspicion
decay, ages in events — runs on `warden_sys::clock::now()`, the monotonic
clock plus the time slept since start (`CLOCK_BOOTTIME`). Instants from the
two are never compared with each other; `Cx` carries both (`now`, `real`).

Every program Warden starts (`systemctl`, `nft`, `journalctl`, `exec` hooks,
notification commands, health-check commands) goes through one runner,
`warden_sys::cmd::Run`: hard timeout, bounded output, `poll(2)` on the pipes
and a pidfd instead of sleep-polling.

Every detector tick runs inside `catch_unwind`: a panicking detector is
disabled with exponential backoff instead of taking the daemon down. Sensors
are restarted with backoff by their supervisor. A poisoned mutex is recovered
rather than propagated.

## Event lifecycle

1. A detector/sensor builds an `Event` (kind, severity, subject, details,
   proposed actions, a `fingerprint` for deduplication). The queue to the
   engine (8192 events) never blocks a detector; when it is full, it gives
   up the oldest event of the *lowest* priority below the newcomer's
   (severity, one level up for `security.*`; resolutions and `action.*`
   results rank high), so a flood of noise cannot push a security finding or
   a critical event out. Events still leave in arrival order. Drops are
   counted in `warden_events_dropped_total{priority}`.
2. The engine applies **policy** rules (suppress / alert-only / re-rate /
   add-or-replace actions).
3. Action-less events are **deduplicated** within a window (escalations in
   severity always pass).
4. The event is **logged** (tracing) and **journaled** (JSON lines, rotated).
5. **Heuristics** accumulate per-process and per-IP suspicion with
   exponential decay; crossing a threshold emits a new `heuristics.*` event
   (which re-enters the pipeline and can itself carry actions).
6. The event is **notified** (webhook / Telegram / command), subject to its
   own dedup and rate limit.
7. If it carries actions and is not a "resolved" event, it goes to the
   **responder**; each action's outcome returns as an `action.*` event.

## Safety model

Destructive actions pass through, in order:

* **dry-run** — nothing destructive executes (snapshots still do); every
  action is logged as it *would* have run. It is the **default**
  (`dry_run = true`): remediation is an explicit decision.
* **protection lists** — PID 1, kernel threads, Warden itself, and the
  configured `comm`/`exe`/`units`/`uids` (sshd, systemd, journald, dbus,
  getty, the daemon's own service…) are never signalled, stopped or frozen.
  A `comm` match counts only for a process verified to be that program
  (see [security.md](security.md#what-warden-trusts)).
* **identity pinning** — a process is signalled through a `pidfd` only after
  its start-time is re-verified, so a recycled PID is never hit.
* **circuit breakers** — global budgets (`max_kills_per_hour`,
  `max_actions_per_hour`), per-target cooldowns (keyed by the complete action
  and its target, so the steps of a playbook do not share one), per-unit
  restart budgets (`systemd.max_restarts_per_hour`, the only one). A budget
  is consulted before an action and charged only once the action was really
  attempted: a refusal (protected target), a skip (the process is already
  gone) or a dry run costs nothing.
* **path guards** — cleanup never touches `/etc`, `/usr`, `/var/lib`, `…/.ssh`
  etc.; quarantine only acts under a configured site root or a temp dir.
  Cleanup, quarantine and the disk walks work on **directory descriptors**
  (`warden_sys::safefs`): directories are opened with `O_NOFOLLOW`, entries
  are examined with `fstatat` and acted on with `unlinkat`/`openat`/
  `renameat2(RENAME_NOREPLACE)` relative to the descriptor, after checking
  that the name still refers to the inode that was examined. The policy is
  decided on the path the descriptor really has, so a user who swaps a
  directory under `/tmp` or a site for a symlink mid-action can make the
  action fail, never redirect it. On the way to a configured root only a
  symlink owned by root or by the owner of its directory is followed (the
  `fs.protected_symlinks` rule).
* **effectiveness** — a memory kill that does not raise MemAvailable by at
  least half of what its victim held stops kills for the rest of the episode
  (`memory.kill_ineffective`), and kills per episode are capped
  (`memory.max_kills_per_episode`); evidence whose actions were withheld on
  purpose (`act_on_existing = false`, a policy `alert_only`) never makes the
  heuristics contain a process; a FIM mass change kills only writers whose
  own writes matched the signatures.

Reloads (`SIGHUP`) **preserve** the circuit breakers, so a reload cannot be
used to bypass a budget, and the runtime dry-run override (unless the
configuration's own `dry_run` changed); every change of the effective mode is
a `warden.dry_run` event. Detectors are not rebuilt: each declares the
configuration sections it is built from (`Detector::sections`); a detector
whose sections did not change is kept as it is, one whose sections changed
adopts them (`Detector::reconfigure`) and keeps its levels, open
conditions, baselines and schedules. Only a detector that cannot is
replaced, and a disabled one removed — after resolving what it had open
(`closed_by: reload`), so no incident is left open for ever. A reload that
changes a setting read once at startup (`daemon.state_dir`, `mlock`,
`metrics.listen`, …) says so in `warden.reloaded` (`restart_required`).

Every condition a detector reports has the same lifecycle
(`warden_core::condition`, or a `LevelTracker` for thresholds): it is
reported when it starts (with its actions), reminded with an exponential
back-off while it holds, and resolved when it stops. Its fingerprint is
`kind[:detail]:<severity>`, its resolution `kind[:detail]:resolved` — a
convention checked by a test on the sources.

## State on disk

```
/etc/warden/warden.toml            main configuration
/etc/warden/conf.d/*.toml          drop-ins (merged; record lists appended, playbooks replaced)
/etc/warden/signatures.d/*.toml    extra FIM signature rules
/var/lib/warden/
  integrity.json                   system-file baseline
  lineage.json                     learned parent→child process lineages
  disk-cleanups.json               what each cleanup playbook freed (survives restarts)
  dry-run.json                     the `wardenctl dry-run on|off` override (survives reloads and restarts)
  sysctl-changes.json              journal of tuned sysctls (for rollback)
  fim/<site>.json                  per-site FIM baseline (hashes + flagged)
  quarantine/<id>/{blob,meta.json} quarantined files (mode 000) + metadata
  snapshots/<ts>_<reason>/         diagnostic snapshots
/var/log/warden/events.jsonl[.N]   the event journal (format: [events.md](events.md))
/run/warden/control.sock           control socket (root only)
```

## Why these kernel interfaces

* **PSI** (`/proc/pressure/*`, triggers) reports *lost time* due to resource
  contention — it rises long before `MemAvailable` hits zero, which is what
  makes "the server froze for 10 minutes" detectable and even preventable.
* **pidfd** makes kill/stop race-free against PID reuse.
* **netlink proc connector** gives real-time exec/uid/ptrace events with no
  eBPF toolchain, BTF or kernel headers — it works on stock distro kernels
  back to 2.6.15.
* **fanotify** (mount mark, `FAN_CLASS_NOTIF`) reports the **writer PID** of a
  changed file, which is what lets Warden name the PHP/Node worker infecting a
  site rather than just noticing the change. In file-handle mode on
  filesystem marks (`FAN_REPORT_DFID_NAME`) it reports `chmod u+s` anywhere
  on a filesystem, which replaces most of the SUID walk — the heaviest
  operation for the inode cache.
* **D-Bus** (a ~850-line built-in client: SASL `EXTERNAL`, marshalling, no
  libdbus) delivers systemd unit state changes as they happen instead of a
  `systemctl` process every 30 s.
* **cgroup v2** (`cgroup.freeze`, `cgroup.kill`) contains or removes a whole
  runaway service atomically.
* **dpkg md5sums** turn "a system binary changed" into "a system binary
  changed and no longer matches its package" — distinguishing an upgrade from
  tampering.
