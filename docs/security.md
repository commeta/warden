# Security & operational notes

## Privileges

Warden needs broad read visibility and a few targeted capabilities, not
unconstrained root. The systemd unit grants exactly:

| capability | why |
|---|---|
| `CAP_KILL` | signal processes it did not start |
| `CAP_SYS_PTRACE` | read `/proc/<pid>/{exe,environ,stack}` of other users |
| `CAP_SYS_ADMIN` | fanotify mount marks (real-time FIM) |
| `CAP_NET_ADMIN` | netlink proc connector, nftables blocklist |
| `CAP_SYS_RESOURCE` | PSI triggers, read limits |
| `CAP_SYS_NICE` | ioprio/nice for background scanners and the `throttle` action |
| `CAP_SYSLOG` | read `/dev/kmsg` when `kernel.dmesg_restrict=1` (Ubuntu default) |
| `CAP_LINUX_IMMUTABLE` | quarantine webshells that attackers made immutable (`chattr +i`) |
| `CAP_IPC_LOCK` | `mlockall` |
| `CAP_DAC_READ_SEARCH`, `CAP_DAC_OVERRIDE`, `CAP_FOWNER`, `CAP_CHOWN` | hash any file, quarantine with correct ownership |
| `CAP_AUDIT_READ` | read the audit log |
| `CAP_SETUID`, `CAP_SETGID` | run hooks and commands as an unprivileged `user` (`daemon.command_user`) |

`CAP_SYS_TIME` is deliberately absent: the seccomp filter allows `adjtimex()`
for *reading* the clock-sync state, and without the capability the kernel
refuses any attempt to change the clock.

The unit also sets `NoNewPrivileges`, `RestrictNamespaces`, `RestrictSUIDSGID`,
`ProtectKernelModules` (no module loading, `/usr/lib/modules` hidden;
`/proc/modules` stays readable), `ProtectHostname` (a private UTS namespace:
nothing Warden runs can rename the host — Warden reads the name at start, so
set `daemon.hostname` or restart it after renaming the host),
`RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK`, `UMask=0027`,
`OOMScoreAdjust=-900` with `OOMPolicy=continue` (the guardian keeps running
through an OOM event) and a seccomp allow-list:

```
SystemCallFilter=@system-service fanotify_init fanotify_mark adjtimex clock_adjtime cachestat open_by_handle_at
SystemCallErrorNumber=EPERM
```

`@mount` is not in it (until 0.14.0 it was, for "statfs-family helpers" —
but `statfs`/`fstatfs` are in `@file-system`): together with
`CAP_SYS_ADMIN` it would let a compromised daemon or hook `mount`,
`pivot_root` or `move_mount`. `systemctl reload wardend` validates the new
configuration first (`ExecReload=wardend --check-config`) and fails with the
reason instead of reporting success while the daemon keeps the old one.

`cachestat` lets scans evict only the page cache they brought in (Linux
6.5+, optional: without it nothing is evicted). `open_by_handle_at`
(with `CAP_DAC_READ_SEARCH`) resolves the file handles of the real-time SUID
sensor (fanotify filesystem marks); without it SUID files are found by the
periodic walk.

`SystemCallErrorNumber=EPERM` is essential for a guardian: a syscall missing
from the list fails with EPERM and degrades one sensor (shown by
`wardenctl status` / `doctor`) instead of killing the whole daemon with
SIGSYS. The list is verified by `scripts/check-seccomp.sh` (strace of the
daemon and its helpers vs. `systemd-analyze syscall-filter`, and the socket
families they open vs. `RestrictAddressFamilies`) and by the CI job that
installs and runs the real unit. `wardenctl doctor` flags an installed unit
that still allows `@mount`, blocks a needed address family or lacks
`CAP_SETUID`/`CAP_SETGID`.

Deliberately **not** enabled: `ProtectHome` (web roots often live in
`/home/*/public_html`; FIM and quarantine need them), `MemoryDenyWriteExecute`
(inherited by your `exec` actions and notification hooks — Node/Java/libffi
would break), `ProtectKernelTunables` (the guarded `sysctl` action). If you run Warden outside systemd, grant the same
capabilities (or run as root) — `wardenctl doctor` reports what is missing and
what each missing piece costs.

## Attack surface

* The **control socket** is mode `0600`, root-only, and additionally verifies
  the peer's UID via `SO_PEERCRED`. The protocol is one JSON object per line.
* The **metrics/health endpoint** binds loopback by default. Keep it there, or
  put it behind your monitoring network; it exposes no secrets but does reveal
  host state.
* **Notifications** carry details Warden did not write: integrity diffs of
  `/etc/environment` or a unit's `Environment=`, the journal tail of a failed
  unit, process command lines (`mysql -pSECRET`). With `notify.details =
  "safe"` (the default) secrets are masked before anything is rendered for a
  webhook, Telegram or a notification command: passwords on command lines
  (`--password=…`, `-p…` of the MySQL clients, `sshpass -p`), `KEY=value`
  and `"key": "value"` pairs whose key names a secret (`*PASSWORD*`,
  `*TOKEN*`, `*SECRET*`, `*API_KEY*`…), `Authorization`/`Cookie` headers,
  `Bearer`/`Basic` credentials, `user:password@` in URLs, PEM private keys,
  crypt hashes and well-known token formats (AWS, GitHub, Slack, Telegram,
  JWT) become `***`. `none` sends only kind, severity, title, subject and
  actions; `all` sends everything. The journal (`events.jsonl`, root-only)
  and `exec` hooks always get the original. The Telegram bot token is also
  removed from error logs. Webhook headers (for auth) live in the config
  file — keep `warden.toml` mode `0640`.
* Warden **never executes** file content it inspects; signatures are matched,
  not run. Quarantined files are stored mode `000`.
* `exec` actions, `command` notifiers and command health checks run programs
  **you** configure, with the event passed via environment/stdin. By default
  they run as root with the daemon's capabilities (`CAP_SYS_ADMIN`,
  `CAP_DAC_OVERRIDE`…), so treat those paths as privileged — or give them an
  account (`daemon.command_user = "_warden"` — the package creates that
  system user — or `user` per hook): the switch drops every capability, and
  a timeout kills the hook's whole process group. What these programs start
  is not mistaken for a web worker's children even when the account is one
  of `process.web_users` (`nobody`).
* **D-Bus**: Warden connects to the system bus as a plain client (no name
  owned, no methods exported) and calls only systemd's read-only
  `ListUnitsFiltered` and `Subscribe`. A match rule on the sender is not
  enough — the bus still delivers a *directed* signal from anyone to Warden's
  unique name — so every signal is checked against the bus-stamped sender:
  it must be the current owner of `org.freedesktop.systemd1` (resolved with
  `GetNameOwner`, kept current from `NameOwnerChanged`). A forged
  `PropertiesChanged` cannot trigger an auto-restart. The parser is bounded
  (64 MiB per message, nesting depth 64) and rejects malformed messages.

## What Warden trusts

Warden acts on a finding only when the facts behind it come from the kernel,
not from the process or the user the finding is about:

| trusted (kernel-vouched) | not trusted (chosen by the subject) |
|---|---|
| the PID (and pidfd), `/proc/<pid>/exe`, the cgroup, the UID | `comm`, `argv[0]`, the command line |
| a root-owned, non-writable system binary as an executable | a user name typed at a login prompt, text in a log line |
| the sender stamped by the bus daemon | the contents of a D-Bus message |
| journald's `_UID` / `_EXE` fields | the syslog identifier (`logger -t sshd`) |

Where this matters:

* **Protection by name.** A `[protection] comm` match shields a process only
  if the process is verified to be that program (a system binary whose name
  explains `comm`); a miner that calls itself `systemd-udevd` gets nothing
  from its name. Protection by executable, unit/cgroup and UID needs no such
  check. When the check cannot be made, Warden leaves the process alone.
* **Authentication logs.** The user name in an `sshd` line is chosen by the
  client, the address is appended by `sshd` last: patterns are anchored on
  that, so a login name cannot pose as a second address and make Warden
  block it. Journal entries are accepted only when `_UID=0` or `_EXE` is a
  system binary named like the identifier; a missing `_EXE` is untrusted.
  Per-source state is bounded, so a flood of sources cannot grow memory.
* **`memfd` programs** are normal for container runtimes. The exemption goes
  to a parent that is a trusted system binary (or the same user's runtime),
  never to a name the process picked.
* **FIM `trusted_writers`**: the writer's executable must be a system binary
  owned by root; a matching `comm` is not enough.
* **"A system binary"** is checked on what runs, not on a path: the process
  must be in Warden's mount namespace (a container's `/usr/bin/git` is the
  container's, whoever is root inside it), and the inode behind
  `/proc/<pid>/exe` must be the one at the path. The same namespace rule
  applies to the daemons a protected name stands for (`sshd`, `journald`…):
  a container cannot claim the host's protection for its processes.
* **Access logs**: the time of a line is the server's bracketed field just
  before the request — the user field before it comes from the client and
  may contain brackets — and the correlation ring is bounded by when lines
  arrived, so a forged or skewed time cannot empty it.
* **The auth log file** (0.14.2). A syslog file does not record who sent a
  line: `logger -t sshd "Failed password for root from <victim>"` lands in
  `auth.log` like a real `sshd` line. `auth.source = "auto"` reads journald
  whenever it runs, which records the sender; lines read from the file are
  evidence but do not block unless `auth.trust_file = true`.
* **Logs a web user can write** (0.14.2). A webshell runs as the web user;
  if that user can write a log Warden reads (nginx on Debian owns its logs
  as `www-data`, ModSecurity-nginx workers write the audit log, the workers
  of a concurrent audit log own its files), it can name any address in it.
  Warden checks the owner and mode of every WAF and access log and their
  directories against `process.web_users` and their groups, reports a
  writable one (`log_trust` in the event, `wardenctl doctor`), and does not
  block on a web-writable access log (`fim.trust_writable_logs = false`).
  WAF logs still block by default (`waf.trust_writable_logs = true`: on
  such servers there is no other source).
* **Live SSH sessions** (0.14.2). Whatever the evidence, an address with an
  established SSH session to the host is not blocked
  (`actions.firewall.protect_ssh_sessions`), unless the evidence is about
  SSH itself and comes from the journal: a forged line cannot lock the
  administrator out. Allow-list admin networks anyway.
* **Concurrent ModSecurity logs.** The index and the transaction files are
  written by the web server's workers: files are opened below the storage
  directory one component at a time without following symlinks, only
  regular files of bounded size are read, in batches, none skipped; an
  entry whose MD5 differs from its index line is ignored and reported.
* **Web server configuration** read by WAF discovery must be owned by root
  and not writable by others; anything else is skipped and reported.

## Failure behaviour

* A detector panic disables only that detector (exponential backoff); a sensor
  failure restarts only that sensor. The daemon stays up.
* The action executor and the notifier are supervised: a panic restarts the
  thread (and is logged) instead of silently ending remediation or alerts.
  Their queues are bounded; control, metrics and `/health` do not share a lock
  with the executor and keep answering while an action or hook is running.
* The control and metrics servers survive `accept` errors, back off when file
  descriptors run out (`LimitNOFILE=16384` in the unit) and cap concurrent
  connections.
* Memory is bounded by design: the `du` walk keeps at most 64 open
  directories and capped tables; scans hand freed heap back to the kernel
  (`mlockall` is lifted around `malloc_trim` when the host is calm).
* If the event queue saturates (a storm of findings), events are dropped
  and counted (`warden_events_dropped_total{priority}`), never blocking
  detection or remediation — the least important first: noise an attacker
  generates to hide a finding evicts only other noise, never a `security.*`
  or critical event. Containment actions have their own executor lane, so a
  slow cleanup or hook cannot delay a kill.
* The systemd **watchdog** restarts Warden if the fast scheduler stops feeding
  its heartbeat (a true hang), and `/health` returns 503 in the same case.
  The heartbeat is measured on the monotonic clock: an NTP step or a resume
  from suspend is not a hang.
* The event **journal** survives a full disk: a write that fails half way is
  cut back to the last complete line, a journal that ends in a partial line
  is repaired when it is opened, failures are counted
  (`warden_journal_write_errors_total`) and a failed rotation is retried
  with a back-off.
* nftables blocks carry kernel **timeouts**, so if Warden dies, blocks expire
  on their own and nothing needs cleanup.

## Safe rollout

1. Install with `--profile webserver` (or `workstation`). The shipped default
   is `dry_run = true`, and the `.deb` does not even start the service.
2. Run for a representative period. Review `wardenctl events` and
   `wardenctl scores`.
3. Add `[[policy]]` rules to suppress or alert-only on any false positives
   (the event's `details` give you exact `subject`/`cmdline`/`kind` to match).
4. Enable remediation: `wardenctl dry-run off` (immediate; kept across
   reloads and restarts until `wardenctl dry-run reset` or a change of
   `dry_run` in the configuration) or `dry_run = false` in `warden.toml`
   (`install.sh --enforce` does this at install time).
5. Keep `max_kills_per_hour` / `max_actions_per_hour` conservative at first.

## What Warden is not

Warden is a host guardian: pressure/stability detection and
heuristic + signature-based intrusion detection with guarded auto-remediation.
It is **not** a replacement for a kernel-level EDR, a full IDS/IPS, a
vulnerability scanner, or a backup system. It complements them: it buys you
time during resource emergencies and catches the common, high-signal intrusion
patterns (webshells, reverse shells, miners, privilege escalation, persistence)
quickly and cheaply, on stock kernels, with no agent in the kernel.

## Reporting issues

Security-relevant issues: please use the repository's private advisory channel
rather than a public issue. Include `wardenctl doctor` output, the relevant
`events.jsonl` lines and the diagnostic snapshot directory if one was taken.
