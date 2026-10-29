"""Roles: the unit of composition.

Each role is a module exposing a :class:`Role` instance in ``ROLE``. A role
has one interface:

* ``packages(p)``  -> apt packages it needs (installed once, pinned where asked);
* ``render(p, ctx)`` -> a :class:`lab.render.Plan` (files + dirs it owns);
* ``post_apply(p, ctx)`` -> imperative steps that are not files (enable a unit,
  create a DB, seed CRS from git) — kept to a minimum and idempotent;
* ``verify(p, ctx)`` -> cheap checks returning a list of (name, ok, detail);
* ``packages`` and ``render`` must be pure (no host writes) so ``plan`` works
  without root.

The order in :data:`ORDER` is the apply order.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from ..render import Plan
from ..util import die


class Ctx:
    """Shared, mutable context passed through a run (paths, computed addrs)."""

    def __init__(self, profile, root: str) -> None:
        self.p = profile
        self.kit_root = root           # the kit directory on disk
        self.data: dict = {}           # roles stash computed values here

    def set(self, key: str, value) -> None:
        self.data[key] = value

    def get(self, key: str, default=None):
        return self.data.get(key, default)


class RoleModule(Protocol):
    def packages(self, p) -> list[str]: ...
    def render(self, p, ctx: Ctx) -> Plan: ...
    def post_apply(self, p, ctx: Ctx) -> None: ...
    def verify(self, p, ctx: Ctx) -> list[tuple[str, bool, str]]: ...


@dataclass
class Role:
    name: str
    packages: Callable = lambda p: []
    render: Callable = lambda p, ctx: Plan()
    # imperative steps that must happen BEFORE files are written/validated
    # (retire a distro default site, enable server modules): keeps the config
    # authoritative before `nginx -t` / `apache2ctl configtest` runs.
    pre_apply: Callable = lambda p, ctx: None
    post_apply: Callable = lambda p, ctx: None
    verify: Callable = lambda p, ctx: []
    # system accounts the role needs to exist before files are chowned to them:
    # returns [(name, home), ...]. Created before manifest apply.
    users: Callable = lambda p: []
    # should this role run for this profile?
    active: Callable = lambda p: True


# Apply order: base paths, network, TLS, databases, the WAF engine and CRS,
# the front, applications, microservices, then Warden last (it reads the rest).
ORDER = [
    "base",
    "net",
    "tls",
    "db",
    "crs",
    "waf",
    "front",
    "app_php",
    "svc",
    "warden",
]

_CACHE: dict[str, Role] = {}


def get(name: str) -> Role:
    if name in _CACHE:
        return _CACHE[name]
    try:
        mod = importlib.import_module(f"lab.roles.{name}")
    except ModuleNotFoundError as e:
        die(f"no such role: {name} ({e})")
    role = getattr(mod, "ROLE", None)
    if not isinstance(role, Role):
        die(f"role module {name} has no ROLE")
    _CACHE[name] = role
    return role


def active_roles(p) -> list[Role]:
    out = []
    for name in ORDER:
        r = get(name)
        if r.active(p):
            out.append(r)
    return out
