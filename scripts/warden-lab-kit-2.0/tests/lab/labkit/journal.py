"""A per-test event window over the Warden journal.

Each request carries a unique ``t=<tag>`` in its URI, so an assertion matches
only this test's own events (the end of L3 — a stale event can no longer pass
a test). ``assert_quiet`` fails the test if anything outside an allow-list
showed up in the window.
"""
from __future__ import annotations

import time
import uuid

from .warden import Warden


class Journal:
    def __init__(self, warden: Warden):
        self.w = warden
        self.start = warden.last_event_id() if warden.available() else 0

    def tag(self) -> str:
        return uuid.uuid4().hex[:12]

    def expect(self, kind, *, ip=None, uri_contains=None, within=10.0):
        deadline = time.monotonic() + within
        while time.monotonic() < deadline:
            for e in self.w.events(since_id=self.start):
                if e.get("kind") != kind:
                    continue
                if ip and _addr(e) != ip:
                    continue
                if uri_contains and uri_contains not in _text(e):
                    continue
                return e
            time.sleep(0.5)
        raise AssertionError(f"no {kind} event (ip={ip}, uri~{uri_contains}) within {within}s")

    def none(self, kind, *, within=3.0) -> bool:
        deadline = time.monotonic() + within
        while time.monotonic() < deadline:
            if any(e.get("kind") == kind for e in self.w.events(since_id=self.start)):
                return False
            time.sleep(0.5)
        return True

    def assert_quiet(self, allowed):
        allowed = set(allowed) | {"warden.started", "warden.dry_run", "warden.journal_suppressed"}
        unexpected = [e for e in self.w.events(since_id=self.start)
                      if e.get("kind") not in allowed and not e.get("kind", "").startswith("warden.")]
        assert not unexpected, "unexpected events in window: " + ", ".join(
            f"{e.get('kind')}#{e.get('id')}" for e in unexpected[:10])


def _addr(e):
    s = e.get("subject") or {}
    return s.get("addr") or (e.get("details") or {}).get("ip")


def _text(e):
    return (e.get("title", "") + " " + str(e.get("details", {})))
