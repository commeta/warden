"""Fixtures for the Warden Lab black-box suite.

The suite runs against a stand that labctl has already applied; it needs the
profile (LAB_PROFILE) to know what to probe. Tests that need a real block run
only under LAB_ENFORCE=1, and always restore dry-run and unblock afterwards.
"""
from __future__ import annotations

import os
import sys

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
KIT = os.path.dirname(os.path.dirname(HERE))
for p in (KIT, HERE):
    if p not in sys.path:
        sys.path.insert(0, p)

from labkit import env, netns  # noqa: E402
from labkit.http import Client  # noqa: E402
from labkit.journal import Journal  # noqa: E402
from labkit.warden import Warden  # noqa: E402


@pytest.fixture(scope="session")
def profile():
    return env.load_profile()


@pytest.fixture(scope="session")
def ep(profile):
    return env.endpoints(profile)


@pytest.fixture(scope="session")
def lab(profile, ep):
    class Lab:
        def __init__(self):
            self.p = profile
            self.ep = ep
            self.hostname = profile.hostname
        def site_host(self, site):
            return self.hostname if site == "portal" else f"{site}.{self.hostname}"
        @property
        def block_after(self):
            return 5
    return Lab()


@pytest.fixture(scope="session")
def warden():
    return Warden()


@pytest.fixture
def journal(warden):
    return Journal(warden)


@pytest.fixture
def attacker(profile, ep):
    return Client(profile, ep, ns=netns.attacker_ns(profile), role="attacker")


@pytest.fixture
def client(profile, ep):
    return Client(profile, ep, ns=netns.client_ns(profile), role="client")


@pytest.fixture
def enforce(warden, attacker):
    """Context in which Warden actually acts; only with LAB_ENFORCE=1."""
    import contextlib

    @contextlib.contextmanager
    def _ctx():
        if os.environ.get("LAB_ENFORCE") != "1":
            pytest.skip("enforcing test: set LAB_ENFORCE=1 on a disposable stand")
        if not warden.available():
            pytest.skip("wardenctl not available")
        warden.dry_run(False)
        used: list[str] = []
        try:
            yield used
        finally:
            for ip in used:
                warden.unblock(ip)
            warden.dry_run(None)
            st = warden.status() or {}
            assert st.get("dry_run") in (True, None), "dry-run was not restored"
    return _ctx


def pytest_configure(config):
    for m in ("smoke", "waf", "warden", "enforce", "ipv6", "forgery",
              "fim", "spawn", "health", "resilience", "upgrade", "stress"):
        config.addinivalue_line("markers", m)


def _skip_if_no_stand(warden):
    if not warden.available():
        pytest.skip("no running Warden on this host")
