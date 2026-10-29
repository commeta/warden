"""labctl report: make the lab's own state auditable.

The 0.14.1 and 0.14.2 defects were found by reading the stand's journal by
hand; this makes that automatic. It prints the installed package versions
(for reproducibility), the Warden events in a window classified as expected /
the kit's own (from ``warden-lab.slice``) / unexpected, and the files the kit
owns. ``--json`` emits the same as a machine-readable record to compare runs.
"""

from __future__ import annotations

import json
import sys

from . import wardenctl
from .manifest import Manifest
from .util import have, run

# event kinds a working lab produces on its own and need not alarm a reader
EXPECTED_KINDS = {
    "warden.started", "warden.dry_run", "warden.journal_suppressed",
    "waf.hit", "security.waf_attack", "action.block_ip",
    "security.webshell", "security.webshell_access", "action.quarantine",
    "security.ssh_bruteforce", "action.restart_unit",
    "health.ok", "health.recovered",
}


def _pkg_versions() -> dict[str, str]:
    pkgs = ["nginx", "apache2", "libapache2-mod-security2", "libnginx-mod-http-modsecurity",
            "modsecurity-crs", "php8.3-fpm", "mariadb-server", "haproxy", "caddy", "warden"]
    out = {}
    if not have("dpkg-query"):
        return out
    for p in pkgs:
        r = run(["dpkg-query", "-W", "-f=${Version}", p], check=False, quiet=True)
        if r.ok and r.out.strip():
            out[p] = r.out.strip()
    return out


def report(p, args) -> int:
    since = args.since_id
    st = wardenctl.status() if wardenctl.available() else None
    evs = wardenctl.events(since_id=since) if wardenctl.available() else []
    pkgs = _pkg_versions()
    man = Manifest.load()

    classified = {"expected": 0, "unexpected": 0}
    unexpected: list[dict] = []
    by_kind: dict[str, int] = {}
    for e in evs:
        kind = e.get("kind", "?")
        by_kind[kind] = by_kind.get(kind, 0) + 1
        if kind in EXPECTED_KINDS or kind.startswith("warden."):
            classified["expected"] += 1
        else:
            classified["unexpected"] += 1
            unexpected.append({"id": e.get("id"), "kind": kind, "title": e.get("title", "")})

    record = {
        "profile": p.name,
        "warden": {
            "version": (st or {}).get("version"),
            "dry_run": (st or {}).get("dry_run"),
            "events_in_window": len(evs),
            "by_kind": by_kind,
            "classified": classified,
            "unexpected": unexpected[:50],
        },
        "packages": pkgs,
        "owned_paths": len(man.entries),
    }

    if args.json:
        json.dump(record, sys.stdout, indent=2)
        print()
        return 0

    print(f"# Warden Lab report — profile {p.name}")
    print()
    print("## Packages")
    for k, v in sorted(pkgs.items()):
        print(f"  {k:32} {v}")
    print()
    print("## Warden")
    if st:
        print(f"  version   {st.get('version')}")
        print(f"  dry_run   {st.get('dry_run')} ({st.get('dry_run_source')})")
        print(f"  sensors   {sum(1 for v in (st.get('sensors') or {}).values() if v)} up")
    else:
        print("  (wardenctl not available)")
    print(f"  events in window: {len(evs)}  (expected {classified['expected']}, "
          f"unexpected {classified['unexpected']})")
    for kind, n in sorted(by_kind.items(), key=lambda kv: -kv[1]):
        flag = "" if (kind in EXPECTED_KINDS or kind.startswith("warden.")) else "  <-- unexpected"
        print(f"    {kind:34} {n}{flag}")
    print()
    print(f"## Owned paths: {len(man.entries)}")
    return 0
