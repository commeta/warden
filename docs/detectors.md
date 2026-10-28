# Detectors & event reference

Every event has a dotted `kind`, a severity, a subject and structured details.
This is the catalogue of what Warden emits and the configuration that governs
it. `[section]` refers to `warden.toml`. The fields of each event's `details`
and the journal format are in [events.md](events.md).

## Stability

| kind | severity | trigger | config | default action |
|---|---|---|---|---|
| `memory.pressure` | warning→critical | PSI memory full avg10, `MemAvailable`, swap usage sustained past `sustain`. `top_cgroups` is ranked by memory a cgroup *pins* (anon + shmem + unreclaimable kernel memory) and shows page cache / reclaimable separately | `[memory]` | `on_critical` (snapshot, kill worst culprit) |
| `memory.swap_storm` | critical | sustained paging (pswpin/out + major faults) with high PSI full — "long swapping / server hangs" | `[memory.swap_storm]` | snapshot, kill |
| `memory.kill_ineffective` | warning | a memory kill did not raise `MemAvailable` by at least half of what the victim held (anonymous memory + swap — what the culprit ranking counts): the memory is held by tmpfs/shared memory/kernel slab, and kills stop until the episode ends. Kills that do help are capped by `max_kills_per_episode` (3) | `[memory]` | — |
| `memory.oom_kill` / `kernel.oom_kill` | warning | kernel OOM killer fired; names the service/container when its own cgroup limit was hit | `[kernel] on_oom_kill` | snapshot |
| `cpu.pressure` | warning→critical | PSI cpu avg60, load/CPU, iowait, D-state tasks | `[cpu]` | `on_critical` |
| `cpu.fork_storm` | warning | process-creation rate (fork bomb) | `[cpu] fork_rate_warning` | — |
| `process.cpu_hog` | warning | one process ≥`hog_percent` for `hog_duration` | `[cpu]` | — |
| `io.pressure` | warning→critical | PSI io full avg10; names top I/O processes | `[io]` | `on_critical` |
| `system.stall` | warning→critical | the daemon's own scheduler woke up late (whole-host freeze) | `[stall]` | snapshot |
| `disk.space` | warning→critical | filesystem usage; lists deleted-but-open files and biggest files (gathered within 1 s so the alert and its cleanup do not wait; `largest_files_partial` when cut short). Reminders back off (15m, 30m, 1h … 24h) unless usage grows by a point; a cleanup run that freed < 1% (min. 256 MiB) pauses the playbook with the same backoff (`cleanup_skipped`); that history is saved in `disk-cleanups.json`, so a restart or reload does not repeat a useless cleanup. The playbook walks over directory descriptors and never follows a symlink below a root (a directory swapped for a symlink mid-walk cannot redirect a deletion); the default `/tmp` step ages files like `systemd-tmpfiles` (`age_from = "newest"`: the newest of atime/mtime/ctime) and skips `PrivateTmp` directories, X server locks and sockets (`exclude`) | `[disk]` | `cleanup` playbook |
| `disk.usage_report` | notice | "who is using the disk": the cleanup freed (almost) nothing, or a critical mount has nothing to clean (a critical mount starts the walk at once) → bounded background `du -x` (one filesystem, idle I/O priority, paced by I/O pressure — `[daemon.pacing]`, memory bounded whatever the tree looks like, `usage_report_max_entries` / `usage_report_max_time`): biggest directories on two levels, largest files, `not_found_by_walk` (deleted-but-open files, data under mount points, snapshots). At most once per mount per `usage_report_every`; later `disk.space` reminders carry `biggest_dirs` | `[disk]` | — |
| `disk.inodes` | warning→critical | inode exhaustion | `[disk]` | — |
| `disk.readonly` | critical | rw filesystem remounted read-only (I/O errors) | `[disk]` | snapshot |
| `disk.fill_prediction` | warning | linear projection says the mount fills within `horizon` | `[disk]` | — |
| `limits.file_handles` / `.pids` / `.conntrack` | warning→critical | system-wide resource limits | `[limits]` | `sysctl` growth with `[tuning] auto_grow` |
| `limits.process_fds` | warning | one process near its `RLIMIT_NOFILE` | `[limits]` | — |
| `network.listen_overflow` / `.syn_flood` / `.retransmits` / `.iface_errors` | warning | TCP/interface counters | `[network]` | — |
| `process.zombies` / `.uninterruptible` | warning | zombie pile-up / long D-state | `[limits]`, `[process]` | — |
| `systemd.unit_failed` | warning→critical | a unit entered `failed` — instantly over D-Bus (`detected_by: dbus`), or by polling `systemctl` every `interval` when the system bus is unavailable (`detected_by: systemctl`); critical when the auto-restart budget is exhausted. Recovery (`info` + `resolved`) is reported when the unit settles (`active`, `inactive`, `reloading`); a failed unit that is only starting again (a timer, an auto-restart) stays failed until that run ends | `[systemd]` | optional `restart_unit` |
| `health.down` | critical | an HTTP/TCP/command probe failed `failures` times in a row (hung service) | `[[health.check]]` | snapshot + `restart_unit` when `unit` is set |
| `process.limit_exceeded` | warning | a `[[process.limit]]` rule: sustained CPU, lifetime or RSS over the limit | `[[process.limit]]` | per rule (`throttle`, `kill`, `limit_unit`…) |
| `tuning.advice` | notice | a sysctl/kernel setting does not fit the hardware or workload | `[tuning]` | none (advice); capacity limits grow with `auto_grow` |
| `waf.hit` | info | ModSecurity blocked a request (≤1 event per peer per minute: an address, or an IPv6 /64) | `[waf]` | — |
| `hardware.memory_corrected` / `_uncorrected` | warning / critical | EDAC ECC errors | `[hardware]` | — |
| `hardware.temperature` | warning→critical | thermal zones | `[hardware]` | — |
| `system.clock_unsynchronized` | warning | for 15 min: the kernel's sync flag is off (what `timedatectl` shows) or the NTP daemon's estimated error exceeds `clock_max_error`. The kernel's `maxerror` is only exported as a metric: it grows 500 µs/s between NTP polls on healthy hosts | `[hardware]` | — |
| `kernel.*` | notice→critical | `/dev/kmsg`: oops, hung task, soft/hard lockup, RCU stall, fs/io errors, MCE, conntrack-full… | `[kernel]` | per-rule |
| `kernel.taint` / `security.kernel_module_loaded` | warning | taint flags change / module loaded | `[kernel]` | — |

## Intrusion & integrity

| kind | severity | trigger | default action |
|---|---|---|---|
| `security.privilege_escalation` | critical | root process whose non-root parent is not a known broker; `setuid(0)` by a program that never had root | stop, snapshot |
| `security.unknown_suid_exec` | critical | euid 0 for a non-root user via a SUID binary not in the allowlist | stop |
| `security.fileless_exec` | critical | execution from `memfd:`, or from an image deleted from a writable location (`/tmp`, `/dev/shm`, home, web roots). Container runtimes (runc, crun, …) legitimately re-exec from a memfd: that is exempt only for a runtime image started by a trusted system binary (or by a runtime of the same user), never because of a name | stop |
| `process.stale_binary` | notice | the binary was replaced on disk (package upgrade) while the process runs the old one; the hint names the unit to restart | — |
| `process.deleted_binary` | warning | the binary was removed from a system path and not replaced | — |
| `security.reverse_shell` | critical | shell with stdin/stdout on a TCP socket | kill |
| `security.miner` / `security.miner_port` | critical / warning | known miner names, or CPU burn + mining-pool port | kill |
| `security.masquerade` | critical | userspace process disguised as a `[kernel]` thread (a root-owned system binary whose name merely resembles one, like `/usr/sbin/watchdog`, is not reported) | — |
| `security.web_spawn` | warning→critical | web worker (php-fpm/node/…, non-root) spawning a shell or tool; critical with downloader/reverse-shell red flags | kill (on red flags) |
| `security.db_spawn` | warning→critical | database server (mysqld, postgres, redis…) spawning a shell or tool — SQLi→RCE | kill (on red flags) |
| `security.waf_attack` | warning | one peer — an address, or an IPv6 /64 — blocked by ModSecurity `block_after` times within `window` | block_ip |
| `security.exec_from_writable` | notice→critical | execution of a binary/script from a writable/upload location | — |
| `security.ld_preload` | warning | privileged/web process with a suspicious `LD_PRELOAD` | — |
| `security.ptrace` | notice→warning | a non-debugger attached ptrace (code injection) | — |
| `security.new_lineage` | notice | a service/web account ran a program never seen during learning | — |
| `security.ssh_bruteforce` | warning | repeated SSH auth failures from one peer (an address, or an IPv6 /64) | block_ip |
| `security.bruteforce_success` | critical | a successful login after a burst of failures | — |
| `security.web_user_sudo` | critical | a web account used sudo | — |
| `auth.root_login` / `auth.sudo_failure` / `auth.privileged_group` / `auth.account_created` … | info→critical | auth-log/journal events | — |
| `security.uid0_account` | critical | a new uid-0 account appeared | — |
| `security.webshell` | warning→critical | signatures flagged a site file (score ≥ `fim.alert_score`) | quarantine, restart pool |
| `security.malicious_writer` | critical | the web worker that wrote the flagged file; in a mass change (`fim.mass_change`), only writers whose own writes in the window matched the signatures — a burst of clean changes (a CMS update) kills nobody | kill |
| `security.webshell_access` | critical | a request hit a flagged file (someone using the shell) | block_ip |
| `security.new_suid` | info→critical | a new SUID/SGID file: in real time via fanotify filesystem marks (`detected_by: real time (fanotify)`), or by the walk (`integrity.suid_rescan`, after an overflow, on kernels without `FAN_REPORT_DFID_NAME`). Critical in writable locations, info when dpkg verifies the file | — |
| `security.binary_replaced` / `security.sudoers_changed` / `security.persistence_*` / `security.ssh_key_added` / `security.ld_so_preload` | notice→critical | integrity baseline changes to critical files | — |
| `security.new_listener` / `security.bind_shell` | notice→critical | a new listening socket (shell-like ⇒ critical) | — |
| `security.lsm_disabled` | critical | AppArmor disabled / SELinux → permissive at runtime | — |
| `heuristics.suspicious` / `heuristics.contain` / `heuristics.ip_threshold` | warning→critical | accumulated suspicion crossed a threshold | `on_contain` / block_ip |

### How exec events are analysed

Every `exec` on the host (proc connector) is analysed against the rules
above. A (parent name and uids, executable, uids) combination that passed
the full analysis three times takes a **fast path** (`process.exec_fast_path`):
one `/proc/<pid>/status` read and an `exe` readlink, the parent from a cache.
The fast path still checks scripts started from writable locations (shells
and interpreters, every exec) and LD_PRELOAD of root processes (one exec in
four), and every `process.exec_recheck_every`-th exec (16) gets the full
analysis anyway. Combinations involving a web or database parent, a web
user, a uid change (sudo/su/setuid binaries), a deleted, memfd or writable
executable, or a kernel-thread-like name are always fully analysed, and a
finding resets the combination. Set `exec_fast_path = false` to analyse
every exec in full.

## Heuristic scoring

Each `security.*` finding adds points (`[heuristics.weights]`) to the subject
process and/or IP. Scores decay with a half-life (`half_life`). A process
crossing `alert_score` raises `heuristics.suspicious`; crossing `contain_score`
raises `heuristics.contain` (which carries `on_contain`, default stop+snapshot).
Half of each finding's weight also flows to the parent, so a worker that keeps
spawning suspicious children becomes a target itself. Inspect live scores with
`wardenctl scores`.

Remote peers are scored by address, and IPv6 by the network of
`actions.firewall.ipv6_prefix` bits (/64) that holds the address: the
addresses an attacker rotates through within his prefix add up to one
score. A peer crossing `ip_block_score` raises `heuristics.ip_threshold` with
`block_ip` — unless the finding that crossed it comes from a source that
deliberately does not block: `auth.ssh_block = false`, `waf.block = false`,
`fim.block_attackers = false`, an allowlisted address, or a `[[policy]]` that
made the event `alert_only` or took its `block_ip` away. Such events carry
`ip_block_off` (the reason) and still add to the address's score, so a later
finding from a source that does block can trigger the block with all the
evidence. To never block addresses at all: `[actions.firewall] enabled =
false` (`block_ip` is then refused).

## What a block takes

`block_ip` blocks the event's address (`subject`, else `details.ip`) for its
TTL (`waf.block_ttl`, `auth.ssh_block_ttl`, a day for `webshell_access`,
`actions.firewall.default_ttl` otherwise). An IPv4 address is blocked
alone; an IPv6 address by its network of `actions.firewall.ipv6_prefix`
bits — `details.prefix` of the finding names it, e.g. `2001:db8:aa:1::/64`.
The network is narrowed to the one address when an allowlisted address or
another address with an established SSH session lies in it, and the result
(`action.block_ip`) says so. Blocks are made in batches by the network lane
of the executor (see [architecture.md](architecture.md#threading-model)),
under their own hourly budget (`max_blocks_per_hour`); `wardenctl block` and
`unblock` accept an address or a network of the configured prefix, and
unblocking an IPv6 address lifts its network's block too.

## Tuning without editing core config

Use `[[policy]]` rules (see the reference config) to silence a known-good
pattern, downgrade a noisy detector to alert-only, or add a stronger action on
a specific subject — all without touching detector thresholds. Run a day in
`dry_run = true` (the default), review `wardenctl events`, write policies for
the false positives, then enable actions.
