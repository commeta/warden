"""Warden control-socket view for the tests (wraps lab.wardenctl)."""
from __future__ import annotations

from lab import wardenctl

from . import env  # noqa: F401  (ensures lab is importable)


class Warden:
    def available(self) -> bool:
        return wardenctl.available()

    def status(self):
        return wardenctl.status()

    def fim_status(self):
        return wardenctl.fim_status()

    def events(self, since_id=0, min_severity=None):
        return wardenctl.events(since_id=since_id, min_severity=min_severity)

    def last_event_id(self) -> int:
        return wardenctl.last_event_id()

    def dry_run(self, enabled):
        return wardenctl.set_dry_run(enabled)

    def unblock(self, ip):
        return wardenctl.unblock(ip)

    def metrics(self):
        return wardenctl.metrics()
