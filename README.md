<div align="center">

# 🛡️ Warden

**A host guardian daemon for Linux servers and workstations — written entirely in Rust.**

Warden watches the health of a machine and *acts* when it goes wrong: it catches
memory pressure and swap storms **before** the OOM killer, before the server
"hangs for ten minutes"; it keeps disks from filling up; and it detects and
contains intrusions — webshells, reverse shells, miners, privilege escalation,
persistence — with guarded, configurable automatic remediation.

[Architecture](docs/architecture.md) · [Detectors & events](docs/detectors.md) · [Security notes](docs/security.md) · [Reference config](config/warden.toml)

[![build](https://github.com/commeta/warden/actions/workflows/ci.yml/badge.svg)](https://github.com/commeta/warden/actions/workflows/ci.yml) ![status](https://img.shields.io/badge/status-beta-orange) ![rust](https://img.shields.io/badge/rust-1.88%2B-informational) ![platform](https://img.shields.io/badge/platform-Linux%204.20%2B-blue) ![license](https://img.shields.io/badge/license-MIT-green)

</div>

---

## Why Warden

`free -h` lies to you. By the time it shows low memory, the kernel has already
been stalling your processes for seconds, reclaiming and re-faulting pages,
and the box is unreachable over SSH. Classic monitoring tells you *after* the
incident. Warden uses the kernel's **Pressure Stall Information (PSI)** — the
actual time your tasks lose waiting for memory, CPU and I/O — to see the
problem forming and either page you or kill the right process *before* the
machine locks up.

The same daemon watches for the mundane disasters that take servers down at
3 a.m. (a journal filling the root filesystem, a filesystem going read-only,
conntrack table full, a failed unit) and the deliberate ones (a PHP worker
spawning `curl … | sh`, a webshell appearing in `wp-content/uploads`, a
process that became root without going through `sudo`, a new SUID binary in
`/tmp`). It can fix the first kind automatically and contain the second — all
under strict safety rules so it never kills your database or your SSH session.

One self-contained binary (dynamically linked only against glibc ≥ 2.34 and
libgcc). No agent in the kernel, no eBPF toolchain, no Python runtime. The
`.deb` installs and runs on Debian 12, Ubuntu 22.04 and 24.04 (checked in CI);
any Linux with glibc 2.34+ runs it from the tarball (kernel features: see
[Compatibility](#compatibility)).
Small enough for a 1 GiB VPS: ~10 MiB RSS with a typical set of detectors,
~33 MiB with every module on and a 20 000-file site under FIM; a module you
disable has no thread and no memory at all ([measurements](docs/performance.md)).

## Highlights

- **Memory pressure & swap storms (PSI).** Detects sustained stalls and
  thrashing with a configurable detection time, registers a kernel PSI trigger
  for instant wake-up, ranks the real culprit (what a kill would free —
  anonymous memory + swap — plus OOM badness and paging activity) and can
  kill it before the kernel OOM killer picks the wrong victim; a kill that
  does not free memory stops further kills for the episode. Warden `mlock`s itself so it stays responsive while the host
  thrashes.
- **Whole-host freeze detection.** Measures how late its own high-priority,
  memory-locked scheduler wakes up — a direct signal that the machine was
  unresponsive, with a diagnostic snapshot captured during the freeze.
- **Disk self-healing.** Space, inodes, read-only remounts, and a fill-rate
  *prediction*. An ordered cleanup playbook (vacuum journald, `apt clean`,
  delete old logs, truncate huge logs, release deleted-but-open files) runs
  only on the affected filesystem and never touches system directories. When
  cleanup cannot help, a bounded background `du` reports **who is using the
  disk** (biggest directories and files) — `wardenctl du` does the same on
  demand.
- **Intrusion detection with real-time process events.** Via the netlink
  **proc connector** (no eBPF): privilege escalation, fileless execution,
  reverse shells, crypto-miners, process masquerading, LD_PRELOAD injection,
  ptrace injection, and web workers spawning shells/downloaders. Repeated
  benign execs (build servers, cron storms) take a fast path that reads one
  `/proc` file instead of six.
- **Web file-integrity monitoring.** BLAKE3 baselines of every script on your
  sites, verified on a schedule *and* in real time via **fanotify** (which
  reports the **writer PID** — the exact worker that infected the file). A
  signature engine flags webshells/droppers in PHP, Node, Python, JSP/ASP and
  `.htaccess` tricks; access-log correlation names the request that planted
  the file and blocks the IPs using the shell.
- **System integrity & auth.** Baselines `/etc/passwd`, sudoers, SSH keys,
  cron, systemd units, `ld.so.preload`, PAM… (with dpkg-checksum verification
  so package upgrades aren't false positives), sees a new SUID/SGID file **the
  moment it appears** (fanotify filesystem marks; a weekly walk remains as a
  safety net), watches listening sockets, and parses journald/auth.log for SSH brute force (with
  automatic blocking), root logins and account changes.
- **ModSecurity integration (v2 and v3).** Reads the audit log (native or
  JSON) or the Apache/nginx error log, blocks clients that ModSecurity keeps
  stopping (it judges requests, Warden remembers attackers) and ranks
  WAF-flagged IPs first when hunting the request that planted a webshell.
- **Works with every web stack.** nginx, Apache, LiteSpeed; PHP via FPM,
  mod_php, CGI/FastCGI/mod_fcgid, suEXEC/mpm-itk per-site users; Node, Python,
  Ruby, Java app servers — see [docs/integrations.md](docs/integrations.md).
- **Failed systemd units in real time.** Unit state changes arrive over
  D-Bus (no `systemctl` process every 30 s); optional auto-restart with an
  hourly budget.
- **Hung services, microservices, databases.** HTTP/TCP/command health checks
  restart services that are alive but not answering (`pg_isready`,
  `redis-cli ping`, `/health`); `[[process.limit]]` rules throttle or kill
  stuck scripts (CPU for N minutes, lifetime, RSS); a database spawning a shell
  (SQLi → RCE) is detected; events name the Docker/Podman/Kubernetes container
  and the service whose own memory limit was hit.
- **Adapts to the machine.** Memory thresholds scale with RAM and follow the
  cgroup limit inside containers. A tuning advisor explains which sysctls do
  not fit your hardware and workload; capacity limits (conntrack, pid_max,
  file-max) can grow automatically within RAM-derived caps — behaviour knobs
  are never changed behind your back.
- **Heuristic scoring.** Individual findings accumulate per-process and per-IP
  suspicion with exponential decay; crossing a threshold contains the process
  or blocks the address. It also learns each service's normal
  parent→child lineage and flags never-seen ones.
- **Guarded auto-remediation.** kill (race-free via pidfd), SIGSTOP for
  forensics, throttle (nice + idle I/O), freeze/kill a cgroup, restart a unit,
  runtime unit limits, quarantine a file (even one made `chattr +i`), block an
  IP (nftables with kernel timeouts), bounded sysctl growth, diagnostic
  snapshots, cleanup, or your own hook. Protected-process lists, circuit breakers, per-target
  cooldowns, path guards and a global **dry-run** keep it safe.
- **Operable.** Prometheus `/metrics` and `/health`, a JSON-lines event
  journal, Slack/Mattermost/Telegram/command notifications, a rich
  `wardenctl`, live config reload, and an offline `wardenctl doctor`.

## How it looks

```console
$ wardenctl status
Warden 0.14.2 on web-01 — pid 914, up 6days 2h  
Levels:   memory ok   cpu ok   io ok   disk warning
Sensors:  psi_trigger running · kmsg running · proc_connector running ·
          auth running · fim_realtime running · access_log running
FIM sites: ["main","api"]      Max heuristic score: 0

$ wardenctl events -n 6
12:41:07 critical  memory.swap_storm      swap storm for 64s: 3100 pages/s swapped, PSI full 42.1%
                   actions: snapshot, kill
12:41:07 warning   action.kill            kill php-fpm8.3[20433] → done: killed after 5s, released ~1.9GiB
12:55:19 critical  security.web_spawn     web worker php-fpm8.3[21044] (www-data) spawned sh: sh -c curl -s http://… | sh
                   actions: kill
12:55:19 critical  security.webshell      malicious code in site main: /wp-content/uploads/cache.php (score 230)
                   actions: quarantine, restart_unit
12:55:20 critical  security.webshell_access  203.0.113.66 requested flagged file /wp-content/uploads/cache.php
                   actions: block_ip
12:55:20 warning   action.block_ip        block_ip 203.0.113.66 → done: blocked for 24h

$ wardenctl mem-top -n 3 --interval 2s
memory PSI: some avg10=38.20 | full avg10=12.80  (full = all tasks stalled)
     PID        RSS       SWAP       PEAK     MAJFLT/s  COMMAND
   20433     1.9GiB   412.0MiB     2.1GiB        880.0  php-fpm8.3
    1044   820.0MiB    12.0MiB   900.0MiB         12.0  mysqld
```

## Install

### From source (any distro)

```bash
# 1. Rust for your normal user (not root): https://rustup.rs
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# 2. Build as your normal user — never with sudo
git clone https://github.com/commeta/warden && cd warden
cargo build --release

# 3. Install as root (profiles: webserver | workstation | database)
sudo ./scripts/install.sh --profile webserver
# edit /etc/warden/warden.toml and conf.d/ (at minimum: FIM site roots, firewall allowlist);
# it starts in observe-only mode (dry_run = true) — see "Quick start & safe rollout"
sudo wardenctl doctor
sudo systemctl enable --now wardend
```

`install.sh` run through sudo builds as the invoking user with *their*
toolchain if the binaries are missing or stale, so you can also skip step 2.
Re-running it upgrades binaries and the unit, keeps your configuration (new
reference files go next to it as `*.new`) and restarts a running service.

Requires Rust ≥ 1.88 to build (edition 2024 `let` chains). Recommended runtime tools: `nftables` (IP
blocking) and `systemd`/`journalctl` (auth events, journal vacuum). Warden
degrades gracefully without them — `wardenctl doctor` tells you what each
missing piece costs.

### Debian / Ubuntu package

```bash
./scripts/build-deb.sh            # as your normal user → target/debian/warden_0.14.2-1_amd64.deb
sudo apt install ./target/debian/warden_*.deb
./scripts/build-deb.sh --portable # for other machines: linked in an Ubuntu 22.04 container (docker/podman),
                                  # → target/portable/debian/…, installs on Debian 12, Ubuntu 22.04 and newer
```

A plain build needs the glibc of the machine it was built on (2.39 on
Ubuntu 24.04), and its package says so; build with `--portable` for a
package to install elsewhere.

The package installs both binaries, the systemd unit (neither enabled nor
started), the reference config as a conffile (`dry_run = true`), and example
drop-ins/signatures under `/usr/share/warden/`. Enable it yourself once the
configuration is reviewed: `sudo systemctl enable --now wardend`. An upgrade
restarts a running service and leaves a stopped one alone.

### Troubleshooting the install

| symptom | cause | fix |
|---|---|---|
| `sudo ./scripts/install.sh` → `cargo not found` | sudo resets `PATH` (`secure_path`), rustup lives in `~/.cargo/bin` | fixed in 0.10: the script finds your toolchain; or `cargo build --release` first, then `sudo ./scripts/install.sh --no-build` |
| `rustup could not choose a version of cargo to run` | cargo started as root with your `PATH`, but root has no rustup default | build as your user (above); don't run cargo through sudo |
| `cargo install cargo-deb` → `Permission denied (os error 13)` in `~/.cargo/registry` | an earlier `sudo -E … cargo` wrote root-owned files into your home | `sudo chown -R "$USER": ~/.cargo ~/.rustup ./target` (install.sh 0.10 repairs this automatically) |
| `wardend.service: Main process exited, code=dumped, status=31/SYS` | seccomp filter of the 0.9 unit killed the daemon (fanotify/adjtimex not allowed) | install 0.10 (`sudo ./scripts/install.sh`), then `sudo systemctl reset-failed wardend && sudo systemctl restart wardend`; `wardenctl doctor` checks the installed unit |
| a sensor shows `unavailable … (os error 1)` | missing capability, or a call blocked by a customised unit | `wardenctl doctor` names which one |

## Quick start & safe rollout

Warden ships safe: destructive actions are conservative and every one of them
is gated. The recommended path:

1. Start in **dry-run**. This is the shipped default (`dry_run = true` in
   `warden.toml`; both `install.sh` and the `.deb` leave it on): Warden
   detects and reports everything but changes nothing. What it *would* have
   done is in the event journal — see [docs/events.md](docs/events.md) for
   every event and what the fields mean.
2. Watch for a day: `wardenctl events -f`, `wardenctl scores`,
   `wardenctl top`.
3. Silence any false positives with `[[policy]]` rules (copy the event's
   `subject`/`cmdline` into a `suppress` or `alert_only` rule).
4. Turn remediation on: `wardenctl dry-run off` takes effect at once and is
   kept across reloads and restarts (it is stored in the state directory;
   `wardenctl status` shows what decided the mode, `wardenctl dry-run reset`
   returns to the configuration). Or set `dry_run = false` in `warden.toml`
   and `systemctl reload wardend` (or install with `install.sh --enforce`);
   a change of `dry_run` in the configuration wins over an older override.

## Configuration

Everything lives in `/etc/warden/warden.toml`, with drop-ins in
`/etc/warden/conf.d/*.toml` (merged in order; record lists such as
`[[fim.site]]`, `[[policy]]`, `[[health.check]]` are appended, everything
else — including playbooks such as `disk.cleanup` or `memory.on_critical` —
is replaced). An empty file is valid — every setting has a
production-sane default. A typo is a startup error, not a silently ignored
setting:

```bash
wardend --check-config          # validate
wardend --print-defaults        # dump all defaults as commented TOML
```

The fully commented [`config/warden.toml`](config/warden.toml) documents every
option. A minimal web-server addition:

```toml
# /etc/warden/conf.d/90-sites.toml
[[fim.site]]
name = "main"
root = "/var/www/html"
access_log = "/var/log/nginx/access.log"
restart_unit = "php8.3-fpm.service"

[actions.firewall]
allowlist = ["127.0.0.0/8", "::1/128", "198.51.100.0/24"]   # your admin/monitoring nets

[systemd]
auto_restart = ["nginx.service", "php8.3-fpm.service"]
```

### The detection-time knob you asked about

```toml
[memory.swap_storm]
sustain = "60s"   # how long sustained swapping must last before Warden acts
                  # ("долгий свопинг, когда сервер зависает надолго")
```
and the kernel PSI trigger for instant reaction:
```toml
[memory.trigger]
enabled = true
kind    = "some"     # or "full"
stall   = "150ms"    # like: echo "some 150000 1000000" > /proc/pressure/memory
window  = "1s"
```

## `wardenctl` cheat sheet

| command | what |
|---|---|
| `wardenctl status` | levels, sensors, learning state |
| `wardenctl events [-n N] [-s warning] [-f]` | recent events (follow with `-f`) |
| `wardenctl top` | memory culprit ranking (who gets killed and why) |
| `wardenctl scores` | live heuristic suspicion scores |
| `wardenctl mem-top --interval 2s` | per-process RSS/swap/major-faults-per-sec |
| `wardenctl psi` | current PSI for cpu/memory/io |
| `wardenctl fim status \| scan [site] \| accept <site> [path] \| pause <site> 30m` | FIM control (pause around deploys) |
| `wardenctl block <ip> [--ttl 1h] \| unblock <ip> \| blocklist` | firewall |
| `wardenctl quarantine list \| restore <id>` | quarantined files |
| `wardenctl snapshot [reason]` | capture a diagnostic snapshot now |
| `wardenctl tuning [--revert]` | kernel tuning advice; sysctl changes Warden made (and undo) |
| `wardenctl profile [-i 10]` | Warden's **own** CPU / I/O / memory per thread, per detector and per heap scope |
| `wardenctl doctor` | **offline** host capability check + installed unit (seccomp/caps/crash) diagnosis |
| `wardenctl scan /var/www` | **offline** signature scan of a tree |
| `wardenctl du [/var] [-d 2] [-n 15] [--idle]` | **offline** who is using the disk: biggest directories per level and files (one filesystem, bounded) |

## Observability

`http://127.0.0.1:9184/metrics` (Prometheus) exposes PSI gauges, memory/swap,
disk usage and fill-ETA per mount, per-detector tick time, event/action
counters, bytes reclaimed, blocklist size, sensor up/down and more.
`/health` returns 503 if the fast scheduler's heartbeat goes stale (the same
signal that drives the systemd watchdog). Warden also profiles itself:
`warden_module_cpu_seconds_total`, `warden_module_heap_bytes`,
`warden_thread_cpu_seconds_total`, `warden_self_cgroup_memory_bytes{kind=anon|page_cache|kernel}`
— see [docs/performance.md](docs/performance.md) for what each module costs. Every event and action result is
also written as JSON to `/var/log/warden/events.jsonl` (rotated).

## Project layout

```
crates/
  warden-core/      config · events · actions · policy · hysteresis · rate limits   (pure, no I/O)
  warden-sys/       PSI · procfs · pidfd · cgroup v2 · kmsg · netlink · fanotify · nftables
  warden-detect/    detectors · sensors · FIM (signatures + correlation) · ModSecurity · health checks ·
                    tuning advisor · heuristics · scheduler
  warden-respond/   guarded actions: kill · stop · throttle · cgroup · unit limits · quarantine · cleanup ·
                    firewall · sysctl · snapshot
  wardend/          the daemon: engine · event log · notifications · control + metrics servers
  wardenctl/        control CLI + offline diagnostics
config/             reference warden.toml, conf.d profiles (webserver, database, workstation), example signatures
packaging/          systemd unit, nftables template, deb maintainer scripts
scripts/            install.sh · uninstall.sh · build-deb.sh [--portable] · check-seccomp.sh · check-glibc.sh ·
                    test-deb-install.sh
fuzz/               cargo-fuzz targets for every parser of untrusted input (bodies in crates/warden-fuzz)
bench/              profile.py (per-module CPU/I/O/RAM matrix) · dhat_modules.py (heap by module)
docs/               architecture · detectors · integrations (web stacks, ModSecurity, DB, containers) · security ·
                    events (catalogue of every event) · performance (measured cost of every module) ·
                    reviews/ (code review and audit reports, Russian)
```

## Building & testing

```bash
cargo build --release --workspace
cargo test  --workspace        # unit tests; some need root (procfs/pidfd/fanotify) — run with sudo
sudo cargo test --workspace    # includes the end-to-end daemon test
cargo clippy --workspace --all-targets -- -D warnings
sudo ./scripts/check-seccomp.sh   # the unit allows every syscall and socket family the daemon uses
sudo cargo llvm-cov --workspace   # line coverage (CI floor: .github/coverage-floor)
cd fuzz && cargo +nightly fuzz run access_log   # libFuzzer; `cargo test -p warden-fuzz` is the stable smoke run
./scripts/build-deb.sh --portable # the release package (linked in an Ubuntu 22.04 container)
```

CI additionally installs the real systemd unit on a fresh Ubuntu 24.04 VM,
starts it, checks it stays up without restarts or core dumps, and has it
catch a webshell — the class of failure unit tests cannot see. It builds the
`.deb` on Ubuntu 22.04 and installs and starts it in clean Debian 12,
Ubuntu 22.04 and 24.04 containers; measures coverage on every push and pull
request (job summary and a PR comment; the build fails below the floor or
when coverage drops more than half a point under main's); and fuzzes every
parser of untrusted input for a minute per target.

The test suite is extensive and deliberately exercises real kernel interfaces
(it parses live `/proc`, opens pidfds, registers PSI triggers and fanotify
marks) rather than only mocks, plus a full end-to-end test that boots the
`wardend` binary and fires real incidents at it.

## Compatibility

| feature | needs | without it |
|---|---|---|
| the binaries | glibc 2.34+ (Debian 12, Ubuntu 22.04, RHEL 9 and newer) | — |
| PSI pressure & triggers | Linux 4.20+, `CONFIG_PSI=y` (boot `psi=1` on RHEL) | pressure detection degraded |
| race-free kill | pidfd (Linux 5.3+) | falls back to start-time re-check |
| real-time process events | proc connector + `CAP_NET_ADMIN` (fork events filtered in the kernel on 6.6+) | falls back to periodic `/proc` scans |
| real-time SUID/SGID detection | fanotify `FAN_REPORT_DFID_NAME` (Linux 5.9+), `CAP_SYS_ADMIN` + `CAP_DAC_READ_SEARCH` | periodic walk only |
| instant failed-unit alerts | systemd + system D-Bus | `systemctl` polling every `systemd.interval` |
| real-time web FIM | fanotify + `CAP_SYS_ADMIN` | falls back to scheduled scans |
| freeze/kill a service | cgroup v2 | those actions unavailable |
| IP blocking | `nft` | block actions fail (reported) |
| auth events, journal vacuum | systemd/journalctl (else auth.log) | reads the log file instead |
| WAF correlation | ModSecurity v2 or v3 writing an audit or error log | — |
| quarantine of `chattr +i` files | `CAP_LINUX_IMMUTABLE` (granted by the unit) | quarantine fails with EPERM (reported) |

Run `wardenctl doctor` on any host for a definitive report.

## License

MIT — see [LICENSE](LICENSE).

> ⚠️ **Beta.** Warden takes destructive actions on your system. Start in
> `dry_run = true` (the default), review what it would do, and keep the circuit-breaker
> budgets conservative until you trust it in your environment.
