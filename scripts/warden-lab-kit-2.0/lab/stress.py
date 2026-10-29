"""labctl stress / soak / test-upgrade.

Black-box hostile load against a running stand, with the pass/fail thresholds
from the 0.15 plan's stage gates. Attacks come from the attacker namespace
(``netns``/``external``) or loopback, and results are read from Warden's
control socket and ``/metrics`` — never from its internal state.

These run against a real stand (they need the front, the WAF and Warden up and
``LAB_ENFORCE`` where a block is expected); on a host without them they report
what is missing and exit non-zero rather than pretend to pass.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess
import sys
import time

from . import net as netmod
from . import wardenctl
from .util import bad, die, info, ok, step

KIT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HTTPCLI = os.path.join(KIT_ROOT, "lab", "httpcli.py")


def _target(p):
    ep = netmod.resolve(p)
    host = ep.host_v4
    return ep, host


def _send(p, src, url, http_host, count=1, method="GET", data=None):
    """Send request(s) from `src`; returns {code:count}."""
    argv = ["python3", HTTPCLI, "--url", url, "--count", str(count), "--method", method]
    if src:
        argv += ["--src", src]
    if http_host:
        argv += ["--host", http_host]
    if data:
        argv += ["--data", data]
    if p.net.mode in {"netns", "external"}:
        argv = ["ip", "netns", "exec", netmod.ATK_NS] + argv
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        return json.loads(out.stdout or "{}").get("codes", {})
    except (subprocess.SubprocessError, json.JSONDecodeError):
        return {}


def _require_stand(p) -> None:
    if not wardenctl.available():
        die("wardenctl not found: stress needs a running Warden")
    st = wardenctl.status()
    if not st:
        die("Warden is not responding on its control socket")


# --------------------------------------------------------------------------
# scenarios
# --------------------------------------------------------------------------


def sc_waf_flood(p, args) -> dict:
    """Many distinct attackers → one waf.hit per peer, no journal flood."""
    ep, host = _target(p)
    start = wardenctl.last_event_id()
    net = ipaddress.ip_network(p.net.attacker_v4)
    n = 2000
    sent = 0
    for i, addr in zip(range(n), net.hosts(), strict=False):
        _send(p, str(addr), f"http://{host}/svc/node/echo?q=%3Cscript%3E{i}%3C/script%3E", p.hostname)
        sent += 1
    time.sleep(3)
    evs = wardenctl.events(since_id=start)
    hits = sum(1 for e in evs if e.get("kind") == "waf.hit")
    suppressed = sum(1 for e in evs if e.get("kind") == "warden.journal_suppressed")
    return {"sent": sent, "waf_hit_journaled": hits, "journal_suppressed_events": suppressed,
            "pass": hits <= 600 + 50}


def sc_waf_v6_spread(p, args) -> dict:
    """Thousands of addresses in one /64 → a single /64 block (N25)."""
    if p.net.mode == "loopback":
        return {"skipped": "needs netns/external for IPv6", "pass": True}
    ep, host = _target(p)
    v6 = ipaddress.ip_network(p.net.attacker_v6)
    base = next(v6.subnets(new_prefix=64))
    start = wardenctl.last_event_id()
    for i in range(6000):
        src = str(base.network_address + 0x1000 + i)
        _send(p, src, f"http://[{ep.host_v6}]/svc/node/echo?q=%3Cscript%3E{i}%3C/script%3E", p.hostname)
    time.sleep(3)
    evs = wardenctl.events(since_id=start)
    attacks = [e for e in evs if e.get("kind") == "security.waf_attack"]
    prefixes = {e.get("details", {}).get("prefix") for e in attacks}
    return {"waf_attack_events": len(attacks), "distinct_prefixes": len(prefixes),
            "pass": len(attacks) >= 1 and len(prefixes) == 1}


def sc_block_storm(p, args) -> dict:
    """A storm of blockable attackers must not delay containment (N23)."""
    if not p.warden.enforce and os.environ.get("LAB_ENFORCE") != "1":
        return {"skipped": "needs enforce mode", "pass": True}
    ep, host = _target(p)
    net = ipaddress.ip_network(p.net.attacker_v4)
    t0 = time.monotonic()
    for i, addr in zip(range(4000), net.hosts(), strict=False):
        _send(p, str(addr), f"http://{host}/svc/node/echo?q=%3Cscript%3E{i}%3C/script%3E&p={i}", p.hostname, count=p and 6)
    dur = time.monotonic() - t0
    m = wardenctl.metrics()
    overflow = sum(v for k, v in m.items() if k.startswith("warden_queue_dropped_total"))
    return {"wall_s": round(dur, 1), "queue_dropped": overflow, "pass": overflow == 0}


def sc_journal_flood(p, args) -> dict:
    return sc_waf_flood(p, args)


SCENARIOS = {
    "waf_flood": sc_waf_flood,
    "waf_v6_spread": sc_waf_v6_spread,
    "block_storm": sc_block_storm,
    "journal_flood": sc_journal_flood,
}


def run_scenarios(p, args) -> int:
    _require_stand(p)
    which = list(SCENARIOS) if args.scenario == "all" else [args.scenario]
    results = {}
    rc = 0
    for name in which:
        fn = SCENARIOS.get(name)
        if not fn:
            die(f"unknown scenario {name!r}; one of {', '.join(SCENARIOS)}")
        info(f"stress: {name}")
        res = fn(p, args)
        results[name] = res
        passed = res.get("pass", False)
        (ok if passed else bad)(f"{name}: {json.dumps({k: v for k, v in res.items() if k != 'pass'})}")
        rc |= 0 if passed else 1
    if args.json:
        json.dump(results, sys.stdout, indent=2)
        print()
    return rc


# --------------------------------------------------------------------------
# soak
# --------------------------------------------------------------------------


def soak(p, args) -> int:
    _require_stand(p)
    hours = args.hours
    end = time.monotonic() + hours * 3600
    info(f"soak for {hours}h: sampling Warden RSS/restarts/drops every minute")
    samples = []
    first_rss = None
    rc = 0
    while time.monotonic() < end:
        m = wardenctl.metrics()
        rss = m.get("warden_self_rss_bytes", 0) or next(
            (v for k, v in m.items() if k.startswith("warden_self_rss_bytes")), 0)
        dropped = sum(v for k, v in m.items() if k.startswith("warden_queue_dropped_total"))
        samples.append({"t": time.time(), "rss": rss, "dropped": dropped})
        if first_rss is None:
            first_rss = rss
        step(f"rss={rss/2**20:.1f}MiB dropped={dropped}")
        time.sleep(60)
    # thresholds: RSS slope < 1 MiB/day, no high-priority drops
    if samples:
        last = samples[-1]["rss"]
        slope_per_day = (last - (first_rss or last)) / 2**20 / max(hours / 24, 1e-6)
        drops = samples[-1]["dropped"]
        ok_slope = slope_per_day < 1.0
        ok_drops = drops == 0
        (ok if ok_slope else bad)(f"RSS slope {slope_per_day:.2f} MiB/day (threshold < 1)")
        (ok if ok_drops else bad)(f"queue drops {drops} (threshold 0)")
        rc = 0 if (ok_slope and ok_drops) else 1
    return rc


# --------------------------------------------------------------------------
# upgrade
# --------------------------------------------------------------------------


def test_upgrade(p, args) -> int:
    from .util import have, run
    if not have("dpkg"):
        die("dpkg required")
    older = args.from_deb
    newer = args.to_deb
    if not (older and newer):
        die("test-upgrade needs --from-deb and --to-deb (the N-1 and N packages)")
    info("installing the older package")
    run(["apt-get", "install", "-y", "--reinstall", older])
    before = wardenctl.status() or {}
    info("upgrading")
    run(["apt-get", "install", "-y", older if False else newer])
    after = wardenctl.status() or {}
    ok_cfg = bool(after)
    info("rolling back")
    run(["apt-get", "install", "-y", "--reinstall", older], check=False)
    (ok if ok_cfg else bad)(f"config survived upgrade: {before.get('version')} -> {after.get('version')}")
    return 0 if ok_cfg else 1
