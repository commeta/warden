"""A thin client for the Warden control socket, via the ``wardenctl`` binary.

Everything that observes Warden (report, stress, soak, the pytest ``warden``
fixture) goes through here, so the kit never reads Warden's internal state —
it asks the same questions an operator would, over the documented control
socket (``wardenctl --json …``). This keeps the tests black-box.
"""

from __future__ import annotations

import json
import urllib.request

from .util import have, run


def available() -> bool:
    return have("wardenctl")


def _json(args: list[str]):
    r = run(["wardenctl", "--json", *args], check=False, quiet=True)
    if not r.ok:
        return None
    try:
        return json.loads(r.out)
    except json.JSONDecodeError:
        return None


def status() -> dict | None:
    return _json(["status"])


def events(since_id: int = 0, limit: int = 2000, min_severity: str | None = None) -> list[dict]:
    args = ["events", "-n", str(limit)]
    if since_id:
        args += ["--since", str(since_id)] if False else []  # wardenctl filters client-side
    data = _json(args)
    if not isinstance(data, list):
        return []
    out = [e for e in data if int(e.get("id", 0)) > since_id]
    if min_severity:
        order = {"info": 0, "notice": 1, "warning": 2, "critical": 3}
        th = order.get(min_severity, 0)
        out = [e for e in out if order.get(e.get("severity", "info"), 0) >= th]
    return out


def last_event_id() -> int:
    data = _json(["events", "-n", "1"])
    if isinstance(data, list) and data:
        return max(int(e.get("id", 0)) for e in data)
    return 0


def set_dry_run(enabled: bool | None) -> bool:
    if enabled is None:
        r = run(["wardenctl", "dry-run", "reset"], check=False, quiet=True)
    else:
        r = run(["wardenctl", "dry-run", "off" if not enabled else "on"], check=False, quiet=True)
    return r.ok


def unblock(ip: str) -> bool:
    return run(["wardenctl", "unblock", ip], check=False, quiet=True).ok


def blocklist() -> list:
    data = _json(["blocklist"])
    return data if isinstance(data, list) else []


def metrics(url: str = "http://127.0.0.1:9184/metrics") -> dict[str, float]:
    """Scrape the Prometheus endpoint into a flat {line: value} dict."""
    out: dict[str, float] = {}
    try:
        with urllib.request.urlopen(url, timeout=3) as r:  # noqa: S310 (localhost)
            body = r.read().decode("utf-8", "replace")
    except Exception:
        return out
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, val = line.rpartition(" ")
        try:
            out[key] = float(val)
        except ValueError:
            continue
    return out
