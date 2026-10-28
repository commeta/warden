# Event catalogue

Everything Warden notices is an **event**; everything it does is reported as
one. This page lists every `kind` the daemon can emit, with its usual
severity and what triggers it. Triggers, thresholds and default actions of the
main detectors are explained in [detectors.md](detectors.md); the settings are
in the reference [`config/warden.toml`](../config/warden.toml).

## Anatomy

One JSON object per line in `events.path` (default
`/var/log/warden/events.jsonl`), the same object on `wardenctl events --json`
and in `WARDEN_EVENT_JSON`:

| field | meaning |
|---|---|
| `id` | unique and increasing, also across restarts (`wardenctl events --since-id N`) |
| `ts_ms` | Unix time, milliseconds |
| `kind` | dotted name from the tables below |
| `severity` | `info` < `notice` < `warning` < `critical` < `emergency` |
| `title` | one line for humans |
| `subject` | what the event is about: `system`, `process`, `file`, `mount`, `unit`, `ip`, `user` or `cgroup`. Actions are resolved against it (`kill` kills the subject process, `block_ip` blocks the subject address, …) |
| `source` | the detector that produced it |
| `fingerprint` | de-duplication key: the same fingerprint inside the cooldown is reported once. Its first segment is the event's kind; a condition is reported as `kind[:detail]:<severity>` (`cpu.pressure:warning`, `disk.space:/:critical`, `process.cpu_hog:812:9731:warning`) and resolved as `kind[:detail]:resolved`. A resolution ends the episode of `X` and every `X:…`, so the condition coming back is reported again at once, and so is the next resolution. A notifier channel gets a resolution only if it got its condition |
| `details` | structured facts (`exe`, `cmdline`, `parent`, `cgroup`, `ip`, …). `ip` is the address an event is about, and `prefix` the IPv6 network a block of it takes (`2001:db8:aa:1::/64`, with `actions.firewall.ipv6_prefix` below 128); `policy` lists the `[[policy]]` rules that matched; `ip_block_off` says why an event about an address does not block it (e.g. `"auth.ssh_block = false"`, `"policy office NAT"`) — the heuristics then do not block on it either; `actions_withheld` says why an event's actions were withheld on purpose (`"process.act_on_existing = false"`, `"policy #2 (alert_only)"`) — it still counts towards the process's suspicion score, but cannot make the heuristics contain it |
| `actions` | what the detector asked for; the outcome follows as `action.*` events |
| `resolved` | `true` on the "back to normal" event of a condition |

**Conditions.** Everything that reports a state — a level over a threshold,
a process over a limit, a mount gone read-only — has one lifecycle: it is
reported when it starts (with its actions), reminded with an exponential
back-off while it holds (`reminder`, `next_reminder_in`: the first after
`repeat` or 10 minutes, then doubling, at most daily), reported at once when
its severity changes, and resolved when it stops (`info` + `resolved`,
`lasted_seconds`). A resolution with `closed_by: reload` was sent because a
reload disabled the detector that watched the condition, not because it
cleared.

Process subjects carry the PID **and** the start time; every action re-checks
both, so a recycled PID is never touched.

## Hooks: events in your own scripts

Both the `exec` action and a `[[notify.command]]` notifier start the program
with the event in its environment (a notifier gets it as `notify.details`
allows — secrets masked by default, see [security](security.md); an `exec`
hook gets the original):

| variable | content |
|---|---|
| `WARDEN_EVENT_JSON` | the whole event (without `details` if it would not fit into one environment string, ~100 KB) |
| `WARDEN_EVENT_KIND` | `kind` |
| `WARDEN_SEVERITY` | `severity` |
| `WARDEN_SUBJECT` | `subject` as text, e.g. `process php-fpm8.3[4012] user=www-data` |
| `WARDEN_TITLE` | `title` |

A hook runs as root with the daemon's capabilities unless you give it an
account: `user = "…"` on the `exec` action, the notifier or the command health
check, or `daemon.command_user` for all of them — the package creates the
system user `_warden` for this; a per-item `user = "root"` keeps one hook
privileged. The switch happens in the child before `exec`
(supplementary groups, gid, uid) and drops every capability; the program
gets that user's `HOME`, `USER`, `LOGNAME` and `/` as working directory, so
it must be readable and executable by that user. An unknown user fails the
hook (it never falls back to root); `wardend --check-config` warns about it.
Every hook is the leader of its own process group, and its timeout kills
the whole group — what it started in the background dies with it. An
`exec` action has no stdin; a notifier command gets the message
text on stdin. What a hook prints is read concurrently and capped (64 KiB for
`exec`, of which the first 500 characters of stdout go into the `action.exec`
result; 4 KiB for notifiers), so a chatty hook, or a child that keeps the
pipes open, cannot block the daemon.

## Reading the tables

*Severity* is the usual one; where a range is shown the detector chooses by
how bad the condition is. Detectors are enabled in their `[section]` of
`warden.toml`; a kind never appears when its detector is off.

## Stability

| kind | severity | when |
|---|---|---|
| `memory.pressure` | warning → critical | PSI memory stall, low `MemAvailable` or swap use, sustained past `sustain`; names the culprit (RSS, its anonymous part, swap) and top cgroups. `kill_withheld` says why the kill was taken off (an ineffective kill earlier in the episode, or `max_kills_per_episode` reached) |
| `memory.swap_storm` | critical | sustained paging with high PSI full: the "server hangs, swaps" situation (same `kill_withheld`) |
| `memory.kill_ineffective` | warning | a victim was killed, but MemAvailable rose by less than half of what it held (`expected`, `freed`): the memory is held elsewhere — `shmem` (tmpfs, shared memory), `slab_unreclaimable` — and kills stop until the episode ends; `hint` says where to look |
| `memory.oom_kill` | warning | the kernel OOM killer fired (counter moved) |
| `cpu.pressure` | warning → critical | PSI cpu, load per CPU, iowait or D-state tasks |
| `cpu.fork_storm` | warning | fork rate above `fork_rate_warning` |
| `io.pressure` | warning → critical | PSI io full; names the top I/O processes |
| `process.cpu_hog` | warning | one process over `hog_percent` for `hog_duration`; resolved when it calms down or exits |
| `process.limit_exceeded` | warning | a `[[process.limit]]` rule: sustained CPU, lifetime or RSS; one condition per rule and process, resolved when it is back within the limit |
| `process.zombies` | warning | zombie pile-up; resolved when below `zombies_warning` |
| `process.uninterruptible` | warning | long D-state; resolved when the process leaves it |
| `limits.process_fds` | warning | one process close to its `RLIMIT_NOFILE`; resolved when it is not |
| `limits.file_handles`, `limits.pids`, `limits.conntrack` | warning → critical | a system-wide limit is nearly used up; `[tuning] auto_grow` may raise it |
| `system.stall` | warning → critical | Warden's own memory-locked scheduler thread woke up late: the whole host was frozen |
| `system.clock_unsynchronized` | warning | for 15 minutes the clock is not synchronised (kernel flag or estimated error); `info` when it is again |
| `warden.slow_detector` | notice | a detector took unusually long (its name and duration are in the title) |
| `warden.worker_panic` | warning | a daemon thread (executor, notifier, sensor) panicked; it was restarted and the failing item skipped |
| `warden.queue_overflow` | warning / critical | a queue of the executor or the notifier was full and work was lost: `dropped` (queue → event kind → count) and `total`. **critical** when containment (a kill, stop, quarantine) was lost. The first loss is reported at once, later ones summed up once a minute |
| `warden.journal_suppressed` | notice | informational events of one kind over `events.max_info_per_minute` in the last minute were not journaled (they were still scored, notified and acted on): `suppressed` (kind → count), `total` |

## Disk

| kind | severity | when |
|---|---|---|
| `disk.space` | warning → critical | usage over the thresholds; `info` + `resolved` when back to normal. Carries `deleted_but_open` and `largest_files` (`largest_files_partial` when the 1 s budget cut the walk); reminders back off |
| `disk.inodes` | warning → critical | inode exhaustion; steps down, reminds with back-off and is resolved like `disk.space` |
| `disk.readonly` | notice / critical | **critical**: a filesystem became read-only while watched (I/O or filesystem errors), with a snapshot; **notice**: it already was when first seen (startup). `info` + `resolved` when it is writable again |
| `disk.fill_prediction` | warning | the mount fills up within `horizon` at the current rate |
| `disk.usage_report` | notice | "who is using the disk": a bounded background walk, started at once for a critical mount and after any cleanup that freed nothing |

## Hardware and kernel

| kind | severity | when |
|---|---|---|
| `hardware.memory_corrected` | warning | EDAC: corrected ECC errors |
| `hardware.memory_uncorrected` | critical | EDAC: uncorrectable ECC errors |
| `hardware.temperature` | warning → critical | a thermal zone over its threshold; `info` when normal again |
| `hardware.thermal_throttle` | warning | the kernel log says the CPU clock was throttled |
| `hardware.mce` | warning | machine-check events |
| `kernel.oom_kill` | warning | the kernel log reports an OOM kill; names the cgroup whose limit was hit |
| `kernel.hung_task` | warning | "blocked for more than N seconds" |
| `kernel.soft_lockup`, `kernel.hard_lockup` | critical | CPU lockups |
| `kernel.rcu_stall` | warning | RCU stall detected |
| `kernel.oops` | critical | oops, BUG, general protection fault, panic |
| `kernel.fs_error` | critical | ext4/XFS/btrfs/F2FS errors |
| `kernel.io_error` | warning | block-device or NVMe/ATA errors (the device is in `details`) |
| `kernel.segfault` | info | a user process segfaulted |
| `kernel.segfault_burst` | warning | the same program crashed repeatedly within 5 minutes |
| `kernel.unsigned_module`, `kernel.out_of_tree_module` | warning / notice | module signature or taint messages |
| `kernel.taint` | warning → critical | the kernel's taint flags changed (critical for a forced module, machine check, bad page, live patch…) |
| `network.conntrack_full` | critical | "nf_conntrack: table full, dropping packet" |
| `network.syn_flood_kernel` | warning | the kernel logged "Possible SYN flooding" |
| `network.link_down`, `network.link_up` | warning / info + `resolved` | link state changes, once per change and interface (a flap is reported in full); fingerprint `network.link:<iface>`, `:resolved` for "up" |
| `network.listen_overflow` | warning | accept queues overflowing; resolved |
| `network.syn_flood` | warning | SYN cookies in use at a high rate; resolved |
| `network.retransmits` | warning | TCP retransmissions over the threshold; resolved |
| `network.iface_errors` | warning | interface errors and drops per second; resolved, also when the interface disappears (its counters and metric series are dropped) |
| `lsm.apparmor_denied`, `lsm.selinux_denied` | info | access denials |
| `lsm.denial_burst` | warning | many denials of the same program in a short time |
| `tuning.advice` | notice | a sysctl or kernel setting does not fit the hardware or the workload (`wardenctl tuning`) |

## Services

| kind | severity | when |
|---|---|---|
| `systemd.unit_failed` | warning → critical | a unit entered `failed`, reported at once over D-Bus; for `auto_restart` units with a `restart_unit` action — the responder's per-unit budget (`max_restarts_per_hour`, charged only for restarts that ran) decides; critical when the unit failed more often than that within the hour |
| `health.down` | critical | a `[[health.check]]` probe failed `failures` times in a row; `info` + `resolved` when it recovers |

## Intrusion

| kind | severity | when |
|---|---|---|
| `security.privilege_escalation` | critical | a root process from a non-root parent that is not a known broker; `setuid(0)` by a program that never had root |
| `security.unknown_suid_exec` | critical | euid 0 for a non-root user through a SUID binary that is not allowed |
| `security.fileless_exec` | critical | code runs from `memfd:` or from an image deleted from a writable place. The memfd of a container runtime is accepted only when a system runtime binary started it |
| `security.reverse_shell` | critical | a shell with stdin/stdout on a TCP socket |
| `security.bind_shell`, `security.new_listener` | critical / notice | a new listening socket; shell-like ones are critical |
| `security.miner`, `security.miner_port` | critical / warning | a known miner name, or CPU burn plus a mining-pool port |
| `security.masquerade` | critical | a process disguised as a `[kernel]` thread |
| `security.web_spawn` | warning → critical | a web worker spawned a shell or tool; critical with downloader or reverse-shell flags |
| `security.db_spawn` | warning → critical | a database server spawned a shell or tool |
| `security.exec_from_writable` | notice → critical | a program started from a writable or upload location |
| `security.ld_preload` | warning | a privileged or web process with a suspicious `LD_PRELOAD` |
| `security.ptrace` | notice → warning | a non-debugger attached with ptrace |
| `security.new_lineage` | notice | a service or web account ran a program never seen while learning |
| `process.stale_binary` | notice | the binary was replaced on disk (package upgrade) while the process still runs the old one; the hint names the unit to restart |
| `process.deleted_binary` | warning | the binary was removed from a system path and not replaced |
| `security.webshell` | warning → critical | signatures flagged a site file (score at or above `fim.alert_score`) |
| `security.malicious_writer` | critical | the web worker that wrote a flagged file |
| `security.webshell_access` | critical | a request hit a flagged file: someone is using the shell |
| `security.waf_attack` | warning | one peer — an address, or an IPv6 network (`prefix`) — blocked by ModSecurity `block_after` times within `window` |
| `waf.hit` | info | ModSecurity blocked a request (at most one event per peer per minute: an address, an IPv6 /64) |
| `security.waf_log_tampered` | warning | entries of a concurrent ModSecurity audit log no longer match the MD5 written into its index: someone who can write the storage directory rewrote them; they are ignored (`log`, `entries`, `log_trust`) |
| `security.kernel_lockdown_violation` | warning | kernel lockdown refused something |
| `security.kernel_module_loaded` | notice | a kernel module was loaded |
| `security.lsm_disabled` | critical | AppArmor was disabled, or SELinux went permissive, at runtime |
| `security.lsm_profiles_unloaded` | warning | the number of enforced AppArmor profiles dropped |
| `heuristics.suspicious` | warning | accumulated suspicion score of a process crossed `alert_score`; `containment_withheld` when it also crossed `contain_score` on evidence whose actions were withheld (`actions_withheld`) |
| `heuristics.contain` | critical | …crossed `contain_score`; carries `on_contain` |
| `heuristics.ip_threshold` | warning | the same for a remote peer: an address, or an IPv6 network (`prefix`) — its addresses add up to one score |

## Authentication

The journal source accepts a line only from a sender the kernel vouches for
(root, or the system binary that matches the program name); `logger -t sshd`
from an unprivileged user is counted in `warden_auth_untrusted_lines_total`
and ignored. The `auth.log` file source cannot tell senders apart.

| kind | severity | when |
|---|---|---|
| `security.ssh_bruteforce` | warning | repeated SSH failures from one peer (an address, or an IPv6 network: `prefix`); blocks it with `block_ip` unless allow-listed |
| `security.bruteforce_success` | critical | a login succeeded from a peer (an address, an IPv6 network) after a burst of failures |
| `auth.root_login` | warning | root logged in over SSH (`alert_root_login`) |
| `auth.login` | info | an SSH login |
| `auth.sudo` | info | a `sudo` command |
| `auth.sudo_failure` | warning / critical | sudo failures; critical for a web account |
| `security.web_user_sudo` | critical | a web account used `sudo` |
| `auth.su_failure` | warning | `su` authentication failure |
| `auth.account_created` | warning | a user account was created |
| `security.uid0_account` | critical | a new account with uid 0 |
| `auth.privileged_group` | warning | a user was added to `sudo`, `wheel`, `docker`, … |
| `auth.account_deleted` | notice | a user account was deleted |
| `auth.password_changed` | notice | a password was changed |

## Integrity

| kind | severity | when |
|---|---|---|
| `integrity.baseline_created` | info | the system-file baseline was taken (first start) |
| `integrity.file_changed` | notice → warning | a watched file changed |
| `integrity.accounts_changed` | notice | `/etc/passwd`, `group`, `shadow`, `gshadow` changed |
| `security.binary_replaced` | critical | `sudo`, `sshd`, `passwd`, `login` or `su` changed |
| `security.sudoers_changed` | warning | `sudoers` or `sudoers.d` changed |
| `security.ssh_keys_changed`, `security.ssh_key_added` | warning | `authorized_keys` changed or gained a key |
| `security.pam_changed` | warning | PAM configuration changed |
| `security.ld_so_preload` | critical | `/etc/ld.so.preload` appeared or changed |
| `security.persistence_cron`, `security.persistence_systemd`, `security.persistence_shell`, `security.persistence_system` | warning | startup places changed: cron, systemd units, shell profiles, other system-wide hooks |
| `integrity.suid_baseline` | info | the SUID/SGID baseline was taken |
| `security.new_suid` | info → critical | a new SUID/SGID file, in real time through fanotify or by the periodic walk |
| `fim.baseline_created` | info | the baseline of a web site was taken |
| `fim.changed` | notice | a file of a site changed (with the writer, when known) |
| `fim.changes` | notice | summary of changes found by a scan |
| `fim.mass_change` | warning → emergency | `burst_files` changes within `burst_window`. **emergency** only when changes in the window matched the signatures (`malicious_content: true`, `malicious_writers`): an infection spreading, and only those writers are killed (`kill_writer`). Without malicious content it is a **warning** — what a CMS or plugin update looks like — with a `hint` to pause FIM around updates (`wardenctl fim pause <site> 30m`) |
| `fim.deleted` | notice | site files were deleted |
| `fim.world_writable` | warning | script files were made world-writable |

## What Warden did

Every action that was executed, refused or skipped is reported as an event of
kind `action.<name>`: the subject of the original event, `details.status`
(`done`, `dry_run`, `skipped` — cooldown or rate limit —, `refused` — protected
target or budget — or `failed`), `details.cause_id` / `cause_kind` / `cause`
pointing at the event that asked for it and, for cleanups, `details.freed_bytes`.
Severity follows the outcome: `warning` for a real change or a failure,
`notice` for a dry run, a refusal or a cleanup that found nothing, `info`
for a snapshot or a skip. A `block_ip` result names what was blocked
(`block_ip 2001:db8:aa:1::/64 → done: blocked 2001:db8:aa:1::/64 for 3600s`)
and why only an address was when its network was narrowed; two requests
for one target in the same batch are one block, the second `skipped`.

`<name>` is one of `snapshot`, `kill`, `stop`, `freeze_cgroup`, `kill_cgroup`,
`restart_unit`, `quarantine`, `block_ip`, `journal_vacuum`, `delete_old`,
`truncate_large`, `truncate_deleted`, `apt_clean`, `throttle`, `limit_unit`,
`sysctl`, `exec`.

The daemon itself reports:

| kind | severity | when |
|---|---|---|
| `warden.started` | info | start (with `dry_run` and `dry_run_source`: `config`, `cli` or `override`) |
| `warden.reloaded`, `warden.reload_failed` | info / warning | `SIGHUP` / `systemctl reload`; `notice` with `restart_required` when a changed setting is read only at startup (`daemon.state_dir`, `daemon.mlock`, `metrics.listen`, …) |
| `warden.dry_run` | notice | the effective dry-run mode changed: `enabled`, `source` (`override` — `wardenctl dry-run on/off`, kept across reloads and restarts; `config` — a reload, `wardenctl dry-run reset`, or an override dropped because `dry_run` was changed in the configuration; `cli` — `--dry-run`) and `reason`. Also at startup when a stored override is in effect |
| `warden.quarantine_restored` | notice | a quarantined file was restored |
| `warden.tuning_reverted` | notice | sysctl changes made by Warden were reverted |
| `warden.manual_snapshot` | notice | `wardenctl snapshot` |
