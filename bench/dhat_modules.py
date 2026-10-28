#!/usr/bin/env python3
"""Attribute a valgrind DHAT heap profile to Warden modules.

    valgrind --tool=dhat --dhat-out-file=dhat.json target/profiling/wardend --config ...
    python3 bench/dhat_modules.py dhat.json [--top 15]

For every allocation site the first stack frame inside Warden's own crates
names the module (warden_detect::fim::signatures, warden_core::config, ...).
Prints, per module: bytes allocated in total, bytes live at the global heap
peak (t-gmax), bytes live at exit and the number of allocations.
"""

import json
import re
import sys
from collections import defaultdict

OURS = re.compile(r"(warden_(?:core|sys|detect|respond)|wardend|wardenctl)::([a-z_0-9]+)(?:::([a-z_0-9]+))?")
SKIP = ("::runtime::lock", "alloc::", "core::")


def module_of(frames, ftbl):
    for fi in frames:
        f = ftbl[fi]
        m = OURS.search(f)
        if not m:
            continue
        crate, mod, sub = m.groups()
        if sub and mod in ("fim",):
            return f"{crate}::{mod}::{sub}"
        return f"{crate}::{mod}"
    # name the first non-std frame for allocations outside our crates
    for fi in frames:
        f = ftbl[fi]
        if "regex" in f:
            return "<regex (outside warden frames)>"
        if "tokio" in f:
            return "<tokio>"
    return "<other>"


def first_frame(frames, ftbl):
    for fi in frames:
        f = ftbl[fi]
        if OURS.search(f) and not any(s in f for s in SKIP):
            return re.sub(r"^0x[0-9A-F]+: ", "", f)[:150]
    return ftbl[frames[0]][:150] if frames else "?"


def main():
    path = sys.argv[1]
    top = int(sys.argv[sys.argv.index("--top") + 1]) if "--top" in sys.argv else 12
    d = json.load(open(path))
    ftbl = d["ftbl"]
    agg = defaultdict(lambda: [0, 0, 0, 0])
    sites = []
    for pp in d["pps"]:
        m = module_of(pp["fs"], ftbl)
        a = agg[m]
        a[0] += pp["tb"]
        a[1] += pp.get("gb", 0)
        a[2] += pp.get("eb", 0)
        a[3] += pp["tbk"]
        sites.append((pp["tb"], pp.get("gb", 0), pp["tbk"], m, first_frame(pp["fs"], ftbl)))
    tot = [sum(v[i] for v in agg.values()) for i in range(4)]
    mib = lambda b: f"{b / 2**20:8.2f}"
    print(f"{'module':44} {'total MiB':>10} {'at peak MiB':>12} {'at end MiB':>11} {'allocs':>10}")
    for m, v in sorted(agg.items(), key=lambda kv: -max(kv[1][0], kv[1][1] * 20)):
        print(f"{m:44} {mib(v[0]):>10} {mib(v[1]):>12} {mib(v[2]):>11} {v[3]:>10}")
    print(f"{'TOTAL':44} {mib(tot[0]):>10} {mib(tot[1]):>12} {mib(tot[2]):>11} {tot[3]:>10}")
    print(f"\nTop allocation sites by bytes live at peak:")
    for tb, gb, n, m, f in sorted(sites, key=lambda s: -s[1])[:top]:
        print(f"  {mib(gb)} MiB peak, {mib(tb)} MiB total, {n:>8} allocs  {f}")
    print(f"\nTop allocation sites by total bytes allocated (churn):")
    for tb, gb, n, m, f in sorted(sites, key=lambda s: -s[0])[:top]:
        print(f"  {mib(tb)} MiB total, {n:>8} allocs  {f}")


if __name__ == "__main__":
    main()
