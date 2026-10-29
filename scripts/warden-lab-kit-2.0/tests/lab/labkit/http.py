"""HTTP from a chosen source address, honouring the profile's net mode.

In netns/external mode a request from the attacker runs inside the attacker
namespace (so its freebind source addresses are routable); in loopback mode it
runs directly. Raw-bytes requests support the forgery tests.
"""
from __future__ import annotations

import ipaddress
import json
import os
import subprocess

from . import env

KIT = env.KIT
HTTPCLI = os.path.join(KIT, "lab", "httpcli.py")


class Client:
    def __init__(self, profile, ep, *, ns: str | None, role: str):
        self.p = profile
        self.ep = ep
        self.ns = ns              # namespace to run in, or None
        self.role = role         # "attacker" | "client"
        self._v4_seq = 0
        self._v6_seq = 0

    # -- source address pools ------------------------------------------
    def new_ipv4(self) -> str:
        if self.p.net.mode in {"loopback", "lan"}:
            if self.role == "client":
                return self.ep.cli_v4
            return "127.0.0.2"
        net = ipaddress.ip_network(self.ep.atk_v4_range)
        self._v4_seq += 1
        return str(net.network_address + 0x100 + self._v4_seq)

    def new_ipv6_in_prefix(self, prefix64: str | None = None) -> str:
        net = ipaddress.ip_network(self.ep.atk_v6_range)
        base = next(net.subnets(new_prefix=64)) if net.prefixlen < 64 else net
        self._v6_seq += 1
        return str(base.network_address + 0x1000 + self._v6_seq)

    # -- requests ------------------------------------------------------
    def get(self, path, *, host=None, src=None, tls=False, count=1):
        return self._run("GET", path, host, src, tls, None, count)

    def post(self, path, data, *, host=None, src=None, tls=False):
        return self._run("POST", path, host, src, tls, data, 1)

    def _run(self, method, path, host, src, tls, data, count):
        scheme = "https" if tls else "http"
        target = self.ep.host_v4
        url = f"{scheme}://{target}{path}"
        argv = ["python3", HTTPCLI, "--url", url, "--method", method, "--count", str(count)]
        if host:
            argv += ["--host", host]
        if src:
            argv += ["--src", src]
        if data:
            argv += ["--data", data]
        if self.ns:
            argv = ["ip", "netns", "exec", self.ns] + argv
        out = subprocess.run(argv, capture_output=True, text=True, timeout=60)
        try:
            return json.loads(out.stdout or "{}")
        except json.JSONDecodeError:
            return {"codes": {}, "error": out.stderr[:200]}

    def status(self, path, **kw) -> int:
        r = self.get(path, **kw)
        codes = r.get("codes", {})
        # single request: return the one code
        for c in codes:
            return int(c)
        return 0
