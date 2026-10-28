#!/usr/bin/env python3
"""Per-module resource profile of wardend (CPU, I/O, RAM, wake-ups).

Runs the daemon once per scenario with a configuration where everything is
disabled except the module under test, drives a synthetic load for that
module and samples the process every second:

* per thread   — CPU (utime+stime), context switches (wake-ups), rchar/wchar,
                 syscalls (/proc/<pid>/task/<tid>/{stat,status,io});
* process      — RSS (anon/file), peak RSS, threads, children (journalctl…);
* memory cgroup (v1 or v2, if one can be created) — page cache and kernel
                 memory (dentries/inodes) charged to the daemon: this is what
                 `systemctl status wardend` shows as "Memory:".

Every scenario runs in dry-run mode, so no action is ever taken.

    sudo python3 bench/profile.py --wardend target/release/wardend
    sudo python3 bench/profile.py --only idle,fim --duration 60

Results: bench/results/latest/<scenario>.json and a Markdown summary on stdout.
The measurements quoted in docs/performance.md are in bench/results/<version>
(`python3 bench/compare.py <old> <new>` compares two of them); the results of
older releases are in the matching git tags.
"""

import argparse
import json
import os
import random
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CLK = os.sysconf("SC_CLK_TCK")
PAGE = os.sysconf("SC_PAGE_SIZE")

BASE = """
[daemon]
dry_run = true
state_dir = "{w}/state"
runtime_dir = "{w}/run"
control_socket = "{w}/run/control.sock"
log_format = "text"
log_level = "info"
[metrics]
enabled = false
listen = "127.0.0.1:19184"
[events]
path = "{w}/events.jsonl"
[actions]
quarantine_dir = "{w}/quarantine"
snapshot_dir = "{w}/snapshots"
[actions.firewall]
enabled = false
[memory]
enabled = false
[cpu]
enabled = false
[io]
enabled = false
[stall]
enabled = false
[disk]
enabled = false
[limits]
enabled = false
[network]
enabled = false
[systemd]
enabled = false
[hardware]
enabled = false
[kernel]
enabled = false
[process]
enabled = false
[integrity]
enabled = false
[auth]
enabled = false
[fim]
enabled = false
[waf]
enabled = false
[health]
enabled = false
[tuning]
advise = false
[heuristics]
enabled = false
"""

# ---------------------------------------------------------------------------
# load generators (each returns a stop() callable)
# ---------------------------------------------------------------------------


def every(rate, fn):
    stop = threading.Event()

    def loop():
        i = 0
        t0 = time.monotonic()
        while not stop.is_set():
            fn(i)
            i += 1
            delay = t0 + i / rate - time.monotonic()
            if delay > 0:
                stop.wait(delay)

    threading.Thread(target=loop, daemon=True).start()
    return stop.set


def make_site(root, n, seed=7):
    rnd = random.Random(seed)
    words = ["$user", "$post", "function", "return", "array", "echo", "if", "foreach", "=>", "null", "$this->db"]
    dirs = [os.path.join(root, *(f"d{rnd.randrange(30)}" for _ in range(rnd.randrange(1, 4)))) for _ in range(400)]
    total = 0
    for i in range(n):
        d = dirs[i % len(dirs)]
        os.makedirs(d, exist_ok=True)
        r = rnd.random()
        size = rnd.randrange(1500, 8000) if r < 0.7 else rnd.randrange(8000, 64000) if r < 0.97 else rnd.randrange(64000, 1 << 20)
        ext = ".php" if i % 4 else ".js"
        body, blen = [], 0
        while blen < size:
            line = " ".join(rnd.choice(words) for _ in range(12)) + ";\n"
            body.append(line)
            blen += len(line)
        data = ("<?php\n" if ext == ".php" else "") + "".join(body)
        with open(os.path.join(d, f"f{i}{ext}"), "w") as f:
            f.write(data)
        total += len(data)
    return total


def gen_site_writes(root, rate):
    def w(i):
        p = os.path.join(root, "live", f"w{i % 50}.php")
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(f"<?php echo {i};\n")
    return every(rate, w)


def gen_noise_writes(d, rate):
    """Writes outside every site root, on the same mount (fanotify cost)."""
    os.makedirs(d, exist_ok=True)

    def w(i):
        with open(os.path.join(d, f"n{i % 200}.log"), "a") as f:
            f.write("x" * 100 + "\n")
    return every(rate, w)


def gen_access_log(path, rate):
    f = open(path, "a", buffering=1)
    paths = ["/", "/index.php", "/wp-login.php", "/wp-admin/admin-ajax.php", "/blog/post-1", "/static/app.js"]

    def w(i):
        ts = time.strftime("%d/%b/%Y:%H:%M:%S +0000", time.gmtime())
        m = "POST" if i % 17 == 0 else "GET"
        f.write(f'198.51.100.{i % 250} - - [{ts}] "{m} {paths[i % len(paths)]}?q={i} HTTP/1.1" 200 {512 + i % 4096} "-" "Mozilla/5.0"\n')
    return every(rate, w)


def gen_waf_log(path, rate):
    f = open(path, "a", buffering=1)

    def w(i):
        ts = time.strftime("%Y/%m/%d %H:%M:%S")
        ip = f"203.0.113.{i % 200}"
        f.write(
            f'{ts} [error] 1234#1234: *{i} [client {ip}] ModSecurity: Access denied with code 403 (phase 2). '
            f'Matched "Operator `Ge\' with parameter `5\' against variable `TX:BLOCKING_INBOUND_ANOMALY_SCORE\' (Value: `5\' ) '
            f'[file "/etc/nginx/crs/rules/REQUEST-949-BLOCKING-EVALUATION.conf"] [line "222"] [id "949110"] [rev ""] '
            f'[msg "Inbound Anomaly Score Exceeded (Total Score: 5)"] [data ""] [severity "0"] [ver "OWASP_CRS/4.0.0"] '
            f'[hostname "10.0.0.1"] [uri "/"] [unique_id "{i}"] [ref ""], client: {ip}, server: example.com, '
            f'request: "GET /?id={i} HTTP/1.1", host: "example.com"\n'
        )
    return every(rate, w)


def gen_auth_log(path, rate):
    f = open(path, "a", buffering=1)

    def w(i):
        ts = time.strftime("%b %d %H:%M:%S")
        if i % 5 == 0:
            line = f"{ts} host sshd[{1000 + i}]: Failed password for invalid user u{i} from 192.0.2.{i % 200} port 22 ssh2"
        else:
            line = f"{ts} host CRON[{2000 + i}]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)"
        f.write(line + "\n")
    return every(rate, w)


def gen_kmsg(rate):
    try:
        f = open("/dev/kmsg", "w", buffering=1)
    except OSError as e:
        print(f"  (kmsg load unavailable: {e})", file=sys.stderr)
        return lambda: None

    def w(i):
        try:
            f.write(f"<6>wprof: synthetic kernel message {i} eth0 link state ok\n")
        except OSError:
            pass
    return every(rate, w)


def gen_processes(idle, exec_rate):
    procs = [subprocess.Popen(["sleep", "3600"]) for _ in range(idle)]

    def churn(i):
        subprocess.Popen(["/bin/true"]).wait()
    stop = every(exec_rate, churn)

    def done():
        stop()
        for p in procs:
            p.kill()
        for p in procs:
            p.wait()
    return done


def gen_exec_storm(rate):
    """A build server in miniature: one parent spawning the same few
    programs over and over (`true`, and `sh -c` that runs `true`)."""
    def churn(i):
        if i % 2:
            subprocess.Popen(["/bin/true"]).wait()
        else:
            subprocess.Popen(["sh", "-c", "true; :"]).wait()
    return every(rate, churn)


def gen_http(port):
    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok\n")

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv.shutdown


# ---------------------------------------------------------------------------
# scenarios
# ---------------------------------------------------------------------------

SITE_FILES = int(os.environ.get("WPROF_SITE_FILES", "20000"))


def scenario_list(w):
    site = f"{w}/site"
    fim_site = f"""
[fim]
enabled = true
realtime = true
scan_on_start = true
signatures = []
[[fim.site]]
name = "main"
root = "{site}"
access_log = "{w}/access.log"
"""
    health = """
[health]
enabled = true
""" + "".join(
        f"""
[[health.check]]
name = "{kind}{i}"
type = "{kind}"
{"url = 'http://127.0.0.1:18080/'" if kind == "http" else "address = '127.0.0.1:18080'"}
interval = "10s"
"""
        for i in range(3)
        for kind in ("http", "tcp")
    )
    return [
        dict(name="idle", cfg="", desc="everything disabled (daemon core only)"),
        dict(name="memory", cfg="[memory]\nenabled = true\n", desc="PSI, swap storm, culprits, PSI trigger"),
        dict(name="cpu", cfg="[cpu]\nenabled = true\n", desc="CPU PSI, load, iowait, forks"),
        dict(name="io", cfg="[io]\nenabled = true\n", desc="I/O PSI, top I/O processes"),
        dict(name="stall", cfg="[stall]\nenabled = true\n", desc="host freeze detection"),
        dict(name="limits", cfg="[limits]\nenabled = true\n", desc="fds, pids, conntrack"),
        dict(name="network", cfg="[network]\nenabled = true\n", desc="queues, SYN flood, errors"),
        dict(name="hardware", cfg="[hardware]\nenabled = true\n", desc="EDAC, thermal, clock"),
        dict(name="kernel", cfg="[kernel]\nenabled = true\n", desc="kmsg (20 msg/s) + taint/modules/LSM",
             load=lambda: [gen_kmsg(20)]),
        dict(name="disk", cfg="[disk]\nenabled = true\ninterval = \"10s\"\n", desc="space/inodes/ro (10s interval)"),
        dict(name="process", cfg="[process]\nenabled = true\n", desc="scanner + exec sensor; 300 idle procs, 20 exec/s",
             load=lambda: [gen_processes(300, 20)]),
        dict(name="exec_storm", cfg="[process]\nenabled = true\n", desc="exec sensor under 300 exec/s (build-server pattern)",
             load=lambda: [gen_exec_storm(200)]),
        dict(name="integrity", cfg="[integrity]\nenabled = true\n", desc="system files, SUID walk (+120s), listeners",
             duration=200),
        dict(name="systemd", cfg="[systemd]\nenabled = true\n", desc="failed units"),
        dict(name="auth", cfg=f"[auth]\nenabled = true\nsource = \"file\"\nauth_log = \"{w}/auth.log\"\n",
             desc="auth.log tail, 10 lines/s", load=lambda: [gen_auth_log(f"{w}/auth.log", 10)]),
        dict(name="fim", cfg=fim_site, desc=f"site {SITE_FILES} files: baseline + 5 writes/s in site + 300/s outside",
             site=True, duration=240, load=lambda: [gen_site_writes(site, 5), gen_noise_writes(f"{w}/noise", 300)]),
        dict(name="access_log", cfg=fim_site.replace("realtime = true", "realtime = false"),
             desc="FIM access-log correlation, 200 req/s", site=True, duration=240,
             load=lambda: [gen_access_log(f"{w}/access.log", 200)]),
        dict(name="waf", cfg=f"[waf]\nenabled = true\n[[waf.log]]\npath = \"{w}/modsec.log\"\n",
             desc="ModSecurity error log, 20 hits/s", load=lambda: [gen_waf_log(f"{w}/modsec.log", 20)]),
        dict(name="health", cfg=health, desc="6 checks (3 http + 3 tcp) every 10s", load=lambda: [gen_http(18080)]),
        dict(name="tuning", cfg="[tuning]\nadvise = true\n", desc="workload detection + sysctl advice"),
        dict(name="all", cfg=None, desc="production defaults + every load above", site=True, duration=300,
             load=lambda: [gen_kmsg(20), gen_processes(300, 20), gen_auth_log(f"{w}/auth.log", 10),
                           gen_site_writes(site, 5), gen_noise_writes(f"{w}/noise", 300),
                           gen_access_log(f"{w}/access.log", 200), gen_waf_log(f"{w}/modsec.log", 20),
                           gen_http(18080)]),
    ]


def all_on_cfg(w):
    return f"""
[daemon]
dry_run = true
state_dir = "{w}/state"
runtime_dir = "{w}/run"
control_socket = "{w}/run/control.sock"
log_format = "text"
[metrics]
listen = "127.0.0.1:19184"
[events]
path = "{w}/events.jsonl"
[actions]
quarantine_dir = "{w}/quarantine"
snapshot_dir = "{w}/snapshots"
[actions.firewall]
enabled = false
[auth]
source = "file"
auth_log = "{w}/auth.log"
[fim]
signatures = []
[[fim.site]]
name = "main"
root = "{w}/site"
access_log = "{w}/access.log"
[[waf.log]]
path = "{w}/modsec.log"
[[health.check]]
name = "web"
type = "http"
url = "http://127.0.0.1:18080/"
interval = "10s"
"""


# ---------------------------------------------------------------------------
# sampling
# ---------------------------------------------------------------------------


def kv(path):
    out = {}
    try:
        with open(path) as f:
            for line in f:
                k, _, v = line.partition(":")
                out[k.strip()] = v.strip()
    except OSError:
        pass
    return out


def stat_fields(path):
    with open(path) as f:
        s = f.read()
    comm = s[s.index("(") + 1 : s.rindex(")")]
    return comm, s[s.rindex(")") + 2 :].split()


def num(v):
    try:
        return int(v.split()[0])
    except (ValueError, IndexError, AttributeError):
        return 0


def sample_proc(pid):
    """One snapshot of the daemon: process totals and every thread."""
    now = time.monotonic()
    try:
        comm, f = stat_fields(f"/proc/{pid}/stat")
    except OSError:
        return None
    st = kv(f"/proc/{pid}/status")
    io = {k: num(v) for k, v in kv(f"/proc/{pid}/io").items()}
    snap = {
        "t": now,
        "cpu": (int(f[11]) + int(f[12])) / CLK,
        "child_cpu": (int(f[13]) + int(f[14])) / CLK,
        "rss": num(st.get("VmRSS")) * 1024,
        "anon": num(st.get("RssAnon")) * 1024,
        "file": num(st.get("RssFile")) * 1024,
        "hwm": num(st.get("VmHWM")) * 1024,
        "threads": num(st.get("Threads")),
        "io": io,
        "tasks": {},
    }
    try:
        tids = os.listdir(f"/proc/{pid}/task")
    except OSError:
        tids = []
    for tid in tids:
        base = f"/proc/{pid}/task/{tid}"
        try:
            tcomm, tf = stat_fields(f"{base}/stat")
        except OSError:
            continue
        ts = kv(f"{base}/status")
        tio = {k: num(v) for k, v in kv(f"{base}/io").items()}
        snap["tasks"][tid] = {
            "name": tcomm,
            "cpu": (int(tf[11]) + int(tf[12])) / CLK,
            "csw": num(ts.get("voluntary_ctxt_switches")) + num(ts.get("nonvoluntary_ctxt_switches")),
            "rchar": tio.get("rchar", 0),
            "wchar": tio.get("wchar", 0),
            "syscalls": tio.get("syscr", 0) + tio.get("syscw", 0),
            "read_bytes": tio.get("read_bytes", 0),
        }
    # running (not yet reaped) children, e.g. `journalctl -f`
    kids = []
    for p in os.listdir("/proc"):
        if not p.isdigit():
            continue
        try:
            c, cf = stat_fields(f"/proc/{p}/stat")
        except OSError:
            continue
        if cf[1] == str(pid):
            kids.append({"pid": int(p), "comm": c, "cpu": (int(cf[11]) + int(cf[12])) / CLK, "rss": int(cf[21]) * PAGE})
    snap["children"] = kids
    return snap


class Cgroup:
    """A child memory cgroup next to ours (v2 or v1), if the host allows it."""

    def __init__(self, name):
        self.path = None
        self.v2 = os.path.exists("/sys/fs/cgroup/cgroup.controllers")
        try:
            with open("/proc/self/cgroup") as f:
                lines = f.read().splitlines()
            if self.v2:
                rel = next(l.split(":", 2)[2] for l in lines if l.startswith("0::"))
                parent = "/sys/fs/cgroup" + rel
            else:
                rel = next(l.split(":", 2)[2] for l in lines if ":memory:" in l)
                parent = "/sys/fs/cgroup/memory" + rel
            p = os.path.join(parent, name)
            os.makedirs(p, exist_ok=True)
            self.path = p
        except (OSError, StopIteration):
            self.path = None

    def read(self):
        if not self.path:
            return {}
        if self.v2:
            st = {k: num(v) for k, v in (l.split(" ", 1) for l in open(f"{self.path}/memory.stat").read().splitlines())}
            return {"total": num(open(f"{self.path}/memory.current").read()), "anon": st.get("anon", 0),
                    "file": st.get("file", 0), "kernel": st.get("kernel", 0),
                    "slab": st.get("slab", 0), "peak": num(open(f"{self.path}/memory.peak").read())
                    if os.path.exists(f"{self.path}/memory.peak") else 0}
        st = {k: num(v) for k, v in (l.split(" ", 1) for l in open(f"{self.path}/memory.stat").read().splitlines())}
        kmem = num(open(f"{self.path}/memory.kmem.usage_in_bytes").read()) if os.path.exists(
            f"{self.path}/memory.kmem.usage_in_bytes") else 0
        return {"total": num(open(f"{self.path}/memory.usage_in_bytes").read()), "anon": st.get("rss", 0),
                "file": st.get("cache", 0), "kernel": kmem, "slab": kmem,
                "peak": num(open(f"{self.path}/memory.max_usage_in_bytes").read())}

    def remove(self):
        if self.path:
            try:
                os.rmdir(self.path)
            except OSError:
                pass


# ---------------------------------------------------------------------------


def run(sc, args, outdir):
    w = args.workdir
    os.makedirs(f"{w}/conf.d", exist_ok=True)
    for f in ("access.log", "modsec.log", "auth.log"):
        open(f"{w}/{f}", "w").close()
    if sc.get("site"):
        t0 = time.time()
        size = make_site(f"{w}/site", SITE_FILES)
        print(f"  site: {SITE_FILES} files, {size / 2**20:.0f} MiB ({time.time() - t0:.0f}s)", file=sys.stderr)
    if sc["cfg"] is None:
        main = all_on_cfg(w)
    else:
        main = BASE.format(w=w)
        with open(f"{w}/conf.d/50-scenario.toml", "w") as f:
            f.write(sc["cfg"])
    with open(f"{w}/warden.toml", "w") as f:
        f.write(main)
    if args.drop_caches:
        subprocess.run(["sync"])
        try:
            with open("/proc/sys/vm/drop_caches", "w") as f:
                f.write("3\n")
        except OSError:
            pass
    cg = Cgroup(f"wprof-{sc['name']}-{os.getpid()}")
    stops = sc.get("load", lambda: [])()
    log = open(f"{w}/wardend.log", "w")
    enter = f"echo $$ > {cg.path}/cgroup.procs; " if cg.path else ""
    env = dict(os.environ, **({"MALLOC_ARENA_MAX": args.arena_max} if args.arena_max else {}))
    proc = subprocess.Popen(["sh", "-c", f"{enter}exec {args.wardend} --config {w}/warden.toml"], stdout=log,
                            stderr=subprocess.STDOUT, env=env)
    duration = sc.get("duration", args.duration)
    samples, cgs = [], []
    t_end = time.monotonic() + duration
    while time.monotonic() < t_end and proc.poll() is None:
        s = sample_proc(proc.pid)
        if s:
            samples.append(s)
            cgs.append(cg.read())
        time.sleep(args.interval)
    alive = proc.poll() is None
    if not alive:
        log.flush()
        print("  daemon exited early:\n" + open(f"{w}/wardend.log").read()[-2000:], file=sys.stderr)
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        proc.kill()
    for s in stops:
        s()
    cg.remove()
    res = summarize(sc, samples, cgs, args)
    res["exited_early"] = not alive
    with open(os.path.join(outdir, f"{sc['name']}.json"), "w") as f:
        json.dump(res, f, indent=1)
    if args.keep:
        res["workdir"] = w
    return res


def summarize(sc, samples, cgs, args):
    if len(samples) < 3:
        return {"name": sc["name"], "desc": sc["desc"], "error": "daemon did not run"}
    warm = args.warmup
    first, last = samples[0], samples[-1]
    steady = [s for s in samples if s["t"] - first["t"] >= warm] or samples
    s0 = steady[0]
    span = max(last["t"] - s0["t"], 1e-6)
    # per thread name: totals over the whole run and rates over the steady window
    threads = {}
    for tid, t in last["tasks"].items():
        first_t = next((s["tasks"][tid] for s in samples if tid in s["tasks"]), t)
        steady_t = s0["tasks"].get(tid, {"cpu": 0, "csw": 0, "rchar": 0, "syscalls": 0, "wchar": 0})
        th = threads.setdefault(t["name"], {"n": 0, "cpu_total": 0.0, "cpu_steady": 0.0, "wakeups_steady": 0,
                                            "rchar_total": 0, "wchar_total": 0, "syscalls_steady": 0})
        th["n"] += 1
        th["cpu_total"] += t["cpu"]
        th["cpu_steady"] += t["cpu"] - steady_t["cpu"]
        th["wakeups_steady"] += t["csw"] - steady_t["csw"]
        th["rchar_total"] += t["rchar"]
        th["wchar_total"] += t["wchar"]
        th["syscalls_steady"] += t["syscalls"] - steady_t["syscalls"]
        _ = first_t
    live_cpu = sum(t["cpu"] for t in last["tasks"].values())
    for th in threads.values():
        th["cpu_steady_pct"] = round(100 * th["cpu_steady"] / span, 3)
        th["wakeups_per_s"] = round(th["wakeups_steady"] / span, 2)
        th["syscalls_per_s"] = round(th["syscalls_steady"] / span, 1)
    kids_cpu = sum(k["cpu"] for k in last["children"])
    return {
        "name": sc["name"],
        "desc": sc["desc"],
        "seconds": round(last["t"] - first["t"], 1),
        "cpu_total_s": round(last["cpu"], 3),
        "cpu_startup_s": round(s0["cpu"], 3),
        "cpu_steady_pct": round(100 * (last["cpu"] - s0["cpu"]) / span, 3),
        "cpu_exited_threads_s": round(max(last["cpu"] - live_cpu, 0), 3),
        "children_cpu_s": round(last["child_cpu"] + kids_cpu, 3),
        "children_rss": sum(k["rss"] for k in last["children"]),
        "children": sorted({k["comm"] for k in last["children"]}),
        "wakeups_per_s": round(sum(t["wakeups_steady"] for t in threads.values()) / span, 2),
        "rss_steady": last["rss"],
        "rss_anon": last["anon"],
        "rss_file": last["file"],
        "rss_peak": max(s["hwm"] for s in samples),
        "threads": last["threads"],
        "threads_max": max(s["threads"] for s in samples),
        "rchar_total": last["io"].get("rchar", 0),
        "wchar_total": last["io"].get("wchar", 0),
        "read_bytes_total": last["io"].get("read_bytes", 0),
        "syscalls_per_s": round((last["io"].get("syscr", 0) + last["io"].get("syscw", 0)
                                 - s0["io"].get("syscr", 0) - s0["io"].get("syscw", 0)) / span, 1),
        "cgroup_last": cgs[-1] if cgs else {},
        "cgroup_peak": max((c.get("total", 0) for c in cgs), default=0),
        "cgroup_file_peak": max((c.get("file", 0) for c in cgs), default=0),
        "cgroup_kernel_peak": max((c.get("kernel", 0) for c in cgs), default=0),
        "per_thread": dict(sorted(threads.items(), key=lambda kv: -kv[1]["cpu_total"])),
    }


def mib(b):
    return f"{b / 2**20:.1f}"


def report(results):
    print("| module | load | CPU startup, s | CPU steady, % core | wake-ups/s | syscalls/s | RSS, MiB (anon) | peak RSS | threads | read, MiB | cgroup peak (cache / kernel), MiB | children |")
    print("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|")
    for r in results:
        if "error" in r:
            print(f"| {r['name']} | {r['desc']} | — | — | — | — | — | — | — | — | — | {r['error']} |")
            continue
        cg = r["cgroup_last"]
        cgs = f"{mib(r['cgroup_peak'])} ({mib(r['cgroup_file_peak'])} / {mib(r['cgroup_kernel_peak'])})" if cg else "—"
        kids = ", ".join(r["children"]) + (f" {mib(r['children_rss'])} MiB" if r["children"] else "")
        print(
            f"| {r['name']} | {r['desc']} | {r['cpu_startup_s']:.2f} | {r['cpu_steady_pct']:.2f} | {r['wakeups_per_s']:.1f} "
            f"| {r['syscalls_per_s']:.0f} | {mib(r['rss_steady'])} ({mib(r['rss_anon'])}) | {mib(r['rss_peak'])} "
            f"| {r['threads']}/{r['threads_max']} | {mib(r['rchar_total'])} | {cgs} | {kids} |"
        )
    print()
    for r in results:
        if r.get("name") != "all" or "error" in r:
            continue
        print("Per thread (scenario `all`):\n")
        print("| thread | CPU total, s | CPU steady, % | wake-ups/s | syscalls/s | read, MiB | written, MiB |")
        print("|---|---:|---:|---:|---:|---:|---:|")
        for name, t in r["per_thread"].items():
            print(f"| {name}{' ×' + str(t['n']) if t['n'] > 1 else ''} | {t['cpu_total']:.2f} | {t['cpu_steady_pct']:.2f} "
                  f"| {t['wakeups_per_s']:.1f} | {t['syscalls_per_s']:.0f} | {mib(t['rchar_total'])} | {mib(t['wchar_total'])} |")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--wardend", default="target/release/wardend")
    ap.add_argument("--duration", type=int, default=90, help="seconds per scenario (default 90)")
    ap.add_argument("--warmup", type=int, default=40, help="seconds excluded from steady-state rates")
    ap.add_argument("--interval", type=float, default=1.0)
    ap.add_argument("--only", help="comma-separated scenario names")
    ap.add_argument("--out", default="bench/results/latest")
    ap.add_argument("--workdir", default=None, help="where temporary sites/configs are created")
    ap.add_argument("--no-drop-caches", dest="drop_caches", action="store_false")
    ap.add_argument("--arena-max", help="set MALLOC_ARENA_MAX for the daemon")
    ap.add_argument("--keep", action="store_true", help="keep work directories")
    ap.add_argument("--json", action="store_true", help="print the summary as JSON instead of Markdown")
    args = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("run as root (the daemon needs it, and so do /dev/kmsg and cgroups)")
    args.wardend = os.path.abspath(args.wardend)
    os.makedirs(args.out, exist_ok=True)
    w = args.workdir or "/var/tmp"
    names = args.only.split(",") if args.only else [s["name"] for s in scenario_list("/x")]
    results = []
    for name in names:
        print(f"== {name}", file=sys.stderr)
        # scenario closures need the real work dir: rebuild the list per run
        wd = tempfile.mkdtemp(prefix="wprof-", dir=w)
        args.workdir = wd
        sc = next(s for s in scenario_list(wd) if s["name"] == name)
        results.append(run(sc, args, args.out))
        if not args.keep:
            shutil.rmtree(wd, ignore_errors=True)
    if args.json:
        print(json.dumps(results, indent=1))
    else:
        report(results)


if __name__ == "__main__":
    main()
