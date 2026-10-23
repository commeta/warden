#!/usr/bin/env python3
"""System calls the exec sensor makes per `exec` on the host.

Starts wardend with only the process module (dry run, scan every hour),
attaches `strace -c` to its proc-connector thread, runs a burst of execs
(`sleep 0.3` and `sh -c "sleep 0.3; :"`, i.e. the build-server pattern of
one parent spawning the same programs) and divides the totals by the number of
execs.

    sudo python3 bench/exec_syscalls.py --wardend target/release/wardend [--execs 600]
"""

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time

CFG = """
[daemon]
dry_run = true
state_dir = "{w}/state"
runtime_dir = "{w}/run"
control_socket = "{w}/run/control.sock"
[metrics]
enabled = false
[events]
path = "{w}/events.jsonl"
[actions.firewall]
enabled = false
{off}
[process]
enabled = true
proc_connector = true
scan_interval = "1h"
{extra}
"""
MODULES = ["memory", "cpu", "io", "stall", "disk", "limits", "network", "systemd", "hardware", "kernel",
           "auth", "integrity", "fim", "waf", "health"]


def thread_of(pid, name, timeout=10):
    t = time.monotonic()
    while time.monotonic() - t < timeout:
        for tid in os.listdir(f"/proc/{pid}/task"):
            try:
                if name.startswith(open(f"/proc/{pid}/task/{tid}/comm").read().strip()):
                    return int(tid)
            except OSError:
                pass
        time.sleep(0.1)
    sys.exit(f"thread {name} not found")


def burst(n, rate):
    """`n` spawns at `rate`/s; returns the wall time."""
    t0 = time.monotonic()
    live = []
    for i in range(n):
        # Children live long enough to be analysed (like compilers on a
        # build server); `true` would exit before /proc is read.
        if i % 2:
            live.append(subprocess.Popen(["sleep", "0.3"]))
        else:
            live.append(subprocess.Popen(["sh", "-c", "sleep 0.3; :"]))
        time.sleep(1 / rate)
    took = time.monotonic() - t0
    for p in live:
        p.wait()
    return took


def cpu_ticks(pid, tid):
    f = open(f"/proc/{pid}/task/{tid}/stat").read().rsplit(")", 1)[1].split()
    return int(f[11]) + int(f[12])


def parse_strace(path):
    calls = {}
    for line in open(path):
        m = re.match(r"\s*[\d.]+\s+[\d.]+\s+\d+\s+(\d+)\s+(?:\d+\s+)?(\w+)$", line)
        if m and m.group(2) != "total":
            calls[m.group(2)] = int(m.group(1))
    return calls


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wardend", required=True)
    ap.add_argument("--execs", type=int, default=1200, help="spawns (each `sh -c` adds one more exec)")
    ap.add_argument("--rate", type=float, default=300, help="spawns per second")
    ap.add_argument("--extra", default="", help="extra lines for [process]")
    ap.add_argument("--json", help="write results here")
    a = ap.parse_args()
    w = tempfile.mkdtemp(prefix="wexec-")
    off = "\n".join(f"[{m}]\nenabled = false" for m in MODULES)
    open(f"{w}/warden.toml", "w").write(CFG.format(w=w, off=off, extra=a.extra))
    log = open(f"{w}/log", "w")
    d = subprocess.Popen([a.wardend, "--config", f"{w}/warden.toml"], stdout=log, stderr=log)
    try:
        tid = thread_of(d.pid, "w-proc_connector")
        time.sleep(1.5)
        # Phase 1: CPU time of the sensor thread, undisturbed.
        c0 = cpu_ticks(d.pid, tid)
        burst(a.execs, a.rate)
        time.sleep(1.0)
        cpu = cpu_ticks(d.pid, tid) - c0
        # Phase 2: system calls (strace slows the thread down, so separately).
        st = subprocess.Popen(["strace", "-c", "-o", f"{w}/strace.txt", "-p", str(tid)],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1.0)
        took = burst(a.execs, a.rate)
        time.sleep(1.5)  # let the sensor drain its socket
        st.send_signal(signal.SIGINT)
        st.wait()
    finally:
        d.send_signal(signal.SIGTERM)
        d.wait()
    execs = a.execs + a.execs // 2  # sh -c "sleep 0.3; :" execs sh and then sleep
    calls = parse_strace(f"{w}/strace.txt")
    total = sum(calls.values())
    res = {
        "wardend": a.wardend,
        "execs": execs,
        "exec_per_sec": round(execs / took),
        "cpu_us_per_exec": round(cpu * 1e6 / os.sysconf("SC_CLK_TCK") / execs, 1),
        "syscalls_per_exec": round(total / execs, 1),
        "opens_per_exec": round(calls.get("openat", 0) / execs, 1),
        "by_syscall": {k: round(v / execs, 2) for k, v in sorted(calls.items(), key=lambda kv: -kv[1])},
    }
    print(json.dumps(res, indent=2))
    if a.json:
        json.dump(res, open(a.json, "w"), indent=2)


if __name__ == "__main__":
    main()
