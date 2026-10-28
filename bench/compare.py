#!/usr/bin/env python3
"""Compare two bench/profile.py result directories (before → after).

    python3 bench/compare.py results-0.10 results-0.11 [--threads all]

Later directories override earlier ones per scenario, so a partial re-run
can be layered over a full run: `compare.py base,rerun after`.
"""

import json
import os
import sys


def load(spec):
    out = {}
    for d in spec.split(","):
        for f in sorted(os.listdir(d)):
            if f.endswith(".json"):
                r = json.load(open(os.path.join(d, f)))
                if "error" not in r:
                    out[r["name"]] = r
    return out


def mib(b):
    return b / 2**20


def cell(a, b, fmt, unit=""):
    if a is None and b is None:
        return "—"
    if a is None:
        return f"{fmt.format(b)}{unit}"
    if b is None:
        return f"{fmt.format(a)}{unit} → —"
    return f"{fmt.format(a)} → **{fmt.format(b)}**{unit}"


def main():
    before, after = load(sys.argv[1]), load(sys.argv[2])
    canon = ["idle", "memory", "cpu", "io", "stall", "limits", "network", "hardware", "kernel", "disk", "process",
             "integrity", "systemd", "auth", "fim", "access_log", "waf", "health", "tuning", "all"]
    names = set(before) | set(after)
    order = [n for n in canon if n in names] + sorted(names - set(canon))
    print("| module | CPU at start, s | CPU steady, % of a core | wake-ups/s | RSS, MiB | peak RSS, MiB | threads | memory cgroup peak, MiB | read, MiB |")
    print("|---|---:|---:|---:|---:|---:|---:|---:|---:|")
    for n in order:
        a, b = before.get(n), after.get(n)
        g = lambda r, k, f=(lambda x: x): None if r is None else f(r[k])
        print(
            f"| `{n}` | {cell(g(a, 'cpu_startup_s'), g(b, 'cpu_startup_s'), '{:.2f}')} "
            f"| {cell(g(a, 'cpu_steady_pct'), g(b, 'cpu_steady_pct'), '{:.2f}')} "
            f"| {cell(g(a, 'wakeups_per_s'), g(b, 'wakeups_per_s'), '{:.1f}')} "
            f"| {cell(g(a, 'rss_steady', mib), g(b, 'rss_steady', mib), '{:.1f}')} "
            f"| {cell(g(a, 'rss_peak', mib), g(b, 'rss_peak', mib), '{:.1f}')} "
            f"| {cell(g(a, 'threads'), g(b, 'threads'), '{}')} "
            f"| {cell(g(a, 'cgroup_peak', mib), g(b, 'cgroup_peak', mib), '{:.0f}')} "
            f"| {cell(g(a, 'rchar_total', mib), g(b, 'rchar_total', mib), '{:.1f}')} |"
        )
    if "--threads" in sys.argv:
        name = sys.argv[sys.argv.index("--threads") + 1]
        for label, r in (("before", before.get(name)), ("after", after.get(name))):
            if not r:
                continue
            print(f"\nPer thread, scenario `{name}` ({label}):\n")
            print("| thread | CPU total, s | CPU steady, % | wake-ups/s | syscalls/s | read, MiB |")
            print("|---|---:|---:|---:|---:|---:|")
            for t, v in r["per_thread"].items():
                n = f" ×{v['n']}" if v["n"] > 1 else ""
                print(f"| {t}{n} | {v['cpu_total']:.2f} | {v['cpu_steady_pct']:.2f} | {v['wakeups_per_s']:.1f} "
                      f"| {v['syscalls_per_s']:.0f} | {mib(v['rchar_total']):.1f} |")


if __name__ == "__main__":
    main()
