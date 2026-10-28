# Integrations: web stacks, ModSecurity, databases, microservices

## Web servers and PHP SAPIs

Warden does not plug into the web server — it watches **files** (FIM) and
**processes** (proc connector). That makes it work the same with every server
and every way of running PHP, Node, Python or Ruby. What differs between
stacks is *which process runs request code* and *as which user*; the defaults
cover the common setups:

| stack | process that runs request code | user | covered by |
|---|---|---|---|
| nginx + PHP-FPM | `php-fpm8.x` pool workers | `www-data` or one user per pool | `web_comms` (`php-fpm*`) + non-root, `web_users` |
| Apache + mod_php (prefork) | `apache2` / `httpd` workers | `www-data` / `apache` | `web_comms` + non-root (the root master is ignored) |
| Apache + PHP-FPM (proxy_fcgi) | `php-fpm*` workers | pool user | as nginx + FPM |
| Apache + mod_fcgid / FastCGI | `php-cgi` processes spawned by Apache | `www-data` or suEXEC user | `web_comms` (`php-cgi*`) |
| Apache + suEXEC / mpm-itk / mod_ruid2 | workers switched to the site owner | per-site user | `web_comms` + non-root (works without listing every site user) |
| CGI (mod_cgi, nginx + fcgiwrap) | `perl`/`python`/`sh` scripts | `www-data` | allow scripts by path: `[[process.allowed_children]] parent = "apache2", child = "/usr/lib/cgi-bin/**"` |
| LiteSpeed / OpenLiteSpeed | `lsphp` | site user | `web_comms` (`lsphp*`, `litespeed`, `lshttpd`) |
| FrankenPHP, HHVM | `frankenphp`, `hhvm` | service user | `web_comms` |
| Node.js / Deno / Bun | `node`, `deno`, `bun` | service user | `web_comms` |
| Python (gunicorn, uWSGI, uvicorn, daphne) | named workers | service user | `web_comms` |
| Ruby (puma, unicorn, Passenger), Java (Tomcat), .NET | named workers | service user | `web_comms` |

"Non-root" matters: master processes of Apache/nginx run as root and
legitimately start helpers (piped loggers like `rotatelogs`, config tests);
request code always runs in unprivileged workers. Warden only treats
non-root processes with these names as web workers — plus anything running as
an account in `web_users`.

The FIM is server-agnostic too: point `[[fim.site]] root` at the document root
and `access_log` at the server's access log in combined/common format (the
default for both nginx and Apache).

**CMS and plugin updates.** An update through the CMS admin (WordPress,
Joomla, Bitrix, an `npm`/`composer` run by the PHP worker) changes hundreds
of files, written by the same PHP worker an infection would use. Warden tells
the two apart by content: a mass change kills writers only when their own
writes matched the signatures; a burst of clean changes is a
`fim.mass_change` warning. Pause the FIM around planned updates so that the
changes are accepted into the baseline — they are still scanned, and
malicious code is still reported and quarantined:

```bash
wardenctl fim pause main 30m     # before the update (site name from [[fim.site]])
# ... update ...
wardenctl fim accept main        # if anything is left to accept
```

Deployments by `git`, `rsync` and other tools in `fim.trusted_writers` are
accepted without a pause.

## ModSecurity (v2 and v3)

| | ModSecurity v2 (`mod_security2`) | ModSecurity v3 (libmodsecurity) |
|---|---|---|
| servers | Apache httpd | nginx (ModSecurity-nginx connector), Apache connector |
| Debian/Ubuntu packages | `libapache2-mod-security2` | `libmodsecurity3` + `libnginx-mod-http-modsecurity` |
| what Warden reads | `SecAuditLog` (native or JSON) and/or Apache `error.log` | `SecAuditLog` (native or JSON) and/or nginx `error.log` |

Both branches are maintained under OWASP; the rule set most people use is the
OWASP Core Rule Set (CRS). Warden does **not** replace ModSecurity — it adds
what a per-request WAF cannot do:

* **memory across requests**: count blocked transactions per client peer —
  an IPv4 address, an IPv6 network of `actions.firewall.ipv6_prefix` (/64 by
  default), so an attacker rotating addresses inside his /64 is one source —
  and, after `waf.block_after` within `waf.window`, block it in nftables for
  `block_ttl` (fail2ban-like, with no per-distro regex maintenance). Blocks
  are batched: ten thousand of them take about a second and a half and do
  not delay a kill;
* **heuristic scoring**: each persistent attacker adds `waf_attack` points
  to the peer's suspicion score shared with SSH brute force, webshell access…;
* **correlation with the filesystem**: when a script appears or changes, the
  FIM's list of suspect requests puts clients that ModSecurity flagged first
  (`waf_hits`, `waf_rules`) — usually the attacker who found the hole.

Minimal setup:

```toml
# /etc/warden/conf.d/60-modsecurity.toml
[[waf.log]]
path = "/var/log/apache2/modsec_audit.log"   # or /var/log/nginx/error.log
site = "main"                                # the [[fim.site]] it protects
```

Formats are detected per line (`format = "auto"`): JSON audit logs from both
branches, the native serial audit log (`--xxxx-A--` / `---xxxx---A--`), and
error-log lines (`ModSecurity: Access denied ...`). One request logged as
several lines (one per matched rule) is counted once via its `unique_id`.

Tuning knobs: `min_rule_severity` (default `critical`), `ignore_rules` for CRS
false positives on your applications, `count_detection_only` while
ModSecurity runs in `DetectionOnly`.

## Databases

* **Never the OOM victim by accident** — DB servers are in `memory.culprit.avoid`
  (score × 0.2, × 0.05 in the database profile). Setting `OOMScoreAdjust=-800`
  in the DB's unit makes both the kernel and Warden skip it.
* **Data is never cleaned** — `/var/lib` is hard-protected from every cleanup
  and quarantine action.
* **Health**: "the process is running" ≠ "the database answers". Use command
  checks: `mysqladmin ping`, `pg_isready`, `redis-cli ping` (examples in
  `config/conf.d/50-database.toml`). After `failures` consecutive misses Warden
  takes a snapshot and restarts the unit, then waits `grace` (InnoDB/WAL
  recovery) before judging again.
* **SQL injection → command execution**: a shell or tool started by
  `mysqld`, `postgres`, `redis-server`, `mongod`… raises `security.db_spawn`
  (critical and killed when the command line is a downloader/reverse shell).
  PostgreSQL's `archive_command` legitimately runs through `sh -c` — allow it
  with `[[process.allowed_children]] parent = "postgres"`.
* **UDF backdoors**: new or changed `.so` files in `/usr/lib/mysql/plugin/`
  are reported by the integrity detector.
* **Kernel settings for databases**: `wardenctl tuning` flags THP=always with
  Redis/MongoDB, high swappiness on DB hosts, Elasticsearch's
  `vm.max_map_count`, and percentage-based dirty limits on large-RAM machines.

## Microservices and containers

* **Health checks** (`[[health.check]]`, `type = "http" | "tcp" | "command"`)
  run in their own thread: one hung endpoint never delays other detectors.
* **Attribution**: process events carry `container=` — `docker:<name>` (systemd
  and cgroupfs drivers), `podman:<id>`, `k8s:pod-<uid>/<container>`,
  `lxc:<name>`, `machine:<name>` (systemd-nspawn).
* **Which service is stalling**: memory pressure events list the cgroups with
  the highest memory PSI (`most_stalled_cgroups`), not only the biggest ones.
* **Cgroup-limited OOM**: when a service or container hits its own
  `MemoryMax`/container limit, the event says so — "api.service hit its memory
  limit" — instead of a generic OOM.
* **Inside a container**: memory thresholds use the container's cgroup limit
  and the container's own PSI, not the host's.
* **Actions on services**: `restart_unit`, `freeze_cgroup`/`kill_cgroup`
  (cgroup v2), `limit_unit` (runtime `CPUQuota=`/`MemoryHigh=`/`MemoryMax=`).

## Long-running and hung processes

| situation | how Warden sees it | typical action |
|---|---|---|
| PHP script in an infinite loop | `[[process.limit]]` `cpu_percent` for `cpu_duration` | `kill` (FPM respawns the worker) |
| CGI/CLI script running for hours | `[[process.limit]]` `max_runtime` | `kill` or `throttle` |
| worker leaking memory | `[[process.limit]]` `max_rss` | report, `restart_unit` |
| backup/dump hurting production | `[[process.limit]]` on `mysqldump`, `pg_dump`… | `throttle` (nice 19 + idle I/O) |
| service alive but not answering | `[[health.check]]` | snapshot + `restart_unit` |
| task stuck in the kernel (NFS, dying disk) | `process.uninterruptible`, `kernel.hung_task` | snapshot (signals cannot help: fix storage) |
| whole host frozen | `system.stall` (scheduler lateness) | snapshot captured *during* the freeze |

## Kernel tuning — what Warden does and does not change

Dynamic tuning sounds attractive, but most sysctls trade latency against
throughput or safety against performance, and an automatic change made at
03:00 is a change nobody reviewed. Warden therefore splits them:

* **Capacity limits** — tables and counters that make the kernel *refuse work*
  when exhausted: `nf_conntrack_max` (new connections dropped), `kernel.pid_max`
  (fork fails), `fs.file-max` (open fails). With `[tuning] auto_grow = true`
  Warden doubles them when the limits detector sees them nearly full, never
  beyond a RAM-proportional cap, journals the original value
  (`wardenctl tuning --revert` restores everything) and, with `persist = true`,
  writes `/etc/sysctl.d/90-warden.conf`.
* **Behaviour knobs** — swappiness, dirty ratios, overcommit, THP, somaxconn,
  security hardening sysctls: only **recommended**, with the reason and the
  measurement that triggered it (`wardenctl tuning`).

"How much memory is there" is answered dynamically: memory thresholds scale
with RAM (`memory.auto_scale`) and follow the cgroup limit inside containers.
