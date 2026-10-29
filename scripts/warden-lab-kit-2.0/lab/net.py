"""Network layout: loopback, network namespaces, or an external interface.

Three modes, chosen by ``[net] mode``:

* **loopback** — everything on ``lo``; the trusted client is ``127.0.0.1`` and
  the attacker a second loopback address. Works anywhere (CI without extra
  caps), but the block is dropped on ``lo`` (the 1.x limitation, L4).
* **netns** — two veth pairs into namespaces ``lab-cli`` (trusted, in the
  allowlist) and ``lab-atk`` (the attacker, with ``IP_FREEBIND`` and a local
  route for whole attacker ranges, so one process sends from thousands of
  IPv4 and IPv6 addresses). The front faces a real interface, so Warden's
  nftables drop is exercised off ``lo`` and IPv6 /64 rotation is real.
* **external** — the front binds a real NIC for production; the attacker
  namespace is still created for the test suite, and the trusted networks from
  the profile go into the firewall and the Warden allowlist.

The helpers here are also what the pytest ``attacker``/``client`` fixtures use
to run a request from a namespace.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .util import have, run

# fixed lab addresses within the configured CIDRs
HOST_V4_OFFSET = 1       # the front's address on the lab bridge
CLI_V4_OFFSET = 2
ATK_V4_OFFSET = 3


@dataclass
class Endpoints:
    """Concrete addresses a profile's net mode resolves to."""

    host_v4: str
    host_v6: str
    cli_v4: str
    cli_v6: str
    # the attacker sends from anywhere in these ranges (freebind)
    atk_v4_range: str
    atk_v6_range: str
    front_bind: str          # address the front listens on
    trusted: list[str]       # allowlist entries for Warden + firewall

    def one_atk_v4(self) -> str:
        return str(next(ipaddress.ip_network(self.atk_v4_range).hosts()))

    def one_atk_v6(self) -> str:
        net = ipaddress.ip_network(self.atk_v6_range)
        return str(net.network_address + 0x10)


def resolve(p) -> Endpoints:
    n = p.net
    if n.mode == "loopback":
        return Endpoints(
            host_v4="127.0.0.1", host_v6="::1",
            cli_v4="127.0.0.1", cli_v6="::1",
            atk_v4_range="127.0.0.2/32", atk_v6_range="::1/128",
            front_bind="127.0.0.1",
            trusted=["127.0.0.0/8", "::1/128"],
        )
    if n.mode == "lan":
        # Real browsers reach the wildcard listener through external_iface, but
        # the black-box test harness runs locally and must target loopback. Use
        # one loopback source for the attacker; do not allowlist 127.0.0.0/8 in
        # Warden, otherwise the block/enforcement tests could never work.
        return Endpoints(
            host_v4="127.0.0.1", host_v6="::1",
            cli_v4="127.0.0.1", cli_v6="::1",
            atk_v4_range="127.0.0.2/32", atk_v6_range="::1/128",
            front_bind="0.0.0.0",
            trusted=list(n.trusted) + ["127.0.0.1/32", "::1/128"],
        )
    v4 = ipaddress.ip_network(n.v4_cidr)
    v6 = ipaddress.ip_network(n.v6_cidr)
    hosts4 = list(v4.hosts())
    host_v4 = str(hosts4[HOST_V4_OFFSET - 1])
    cli_v4 = str(hosts4[CLI_V4_OFFSET - 1])
    host_v6 = str(v6.network_address + 1)
    cli_v6 = str(v6.network_address + 2)
    if n.mode in {"lan", "external"}:
        trusted = list(n.trusted)
        front_bind = "0.0.0.0"
    else:  # netns
        trusted = [n.v4_cidr, n.v6_cidr, "127.0.0.0/8", "::1/128"]
        front_bind = host_v4
    return Endpoints(
        host_v4=host_v4, host_v6=host_v6, cli_v4=cli_v4, cli_v6=cli_v6,
        atk_v4_range=n.attacker_v4, atk_v6_range=n.attacker_v6,
        front_bind=front_bind, trusted=trusted,
    )


# --------------------------------------------------------------------------
# namespace setup (netns / external test harness)
# --------------------------------------------------------------------------

CLI_NS = "lab-cli"
ATK_NS = "lab-atk"


def netns_exists(name: str) -> bool:
    r = run(["ip", "netns", "list"], check=False, quiet=True)
    return any(line.split()[0] == name for line in r.out.splitlines() if line.strip())


def setup_namespaces(p, ep: Endpoints) -> None:
    """Create the cli/attacker namespaces and veth pairs (idempotent)."""
    if not have("ip"):
        from .util import die
        die("iproute2 (ip) is required for net.mode = netns/external")
    v4 = ipaddress.ip_network(p.net.v4_cidr)
    v6 = ipaddress.ip_network(p.net.v6_cidr)
    prefix4 = v4.prefixlen
    prefix6 = v6.prefixlen

    for ns, host_off, peer_v4, peer_v6 in (
        (CLI_NS, 10, ep.cli_v4, ep.cli_v6),
        (ATK_NS, 20, None, None),
    ):
        if not netns_exists(ns):
            run(["ip", "netns", "add", ns])
        host_if = f"vh-{ns[-3:]}"
        peer_if = f"vp-{ns[-3:]}"
        # (re)create the veth pair
        run(["ip", "link", "del", host_if], check=False, quiet=True)
        run(["ip", "link", "add", host_if, "type", "veth", "peer", "name", peer_if])
        run(["ip", "link", "set", peer_if, "netns", ns])
        host_addr = str(v4.network_address + host_off)
        host_addr6 = str(v6.network_address + host_off)
        run(["ip", "addr", "add", f"{host_addr}/{prefix4}", "dev", host_if], check=False, quiet=True)
        run(["ip", "-6", "addr", "add", f"{host_addr6}/{prefix6}", "dev", host_if], check=False, quiet=True)
        if ns == CLI_NS:
            # .1 is the target bound by the front; assign it to a host veth as
            # well. It disappears automatically when that pair is deleted.
            run(["ip", "addr", "add", f"{ep.host_v4}/{prefix4}", "dev", host_if], check=False, quiet=True)
            run(["ip", "-6", "addr", "add", f"{ep.host_v6}/{prefix6}", "dev", host_if], check=False, quiet=True)
        run(["ip", "link", "set", host_if, "up"])
        run(["ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"])
        run(["ip", "netns", "exec", ns, "ip", "link", "set", peer_if, "up"])
        if ns == CLI_NS:
            run(["ip", "netns", "exec", ns, "ip", "addr", "add", f"{peer_v4}/{prefix4}", "dev", peer_if])
            run(["ip", "netns", "exec", ns, "ip", "-6", "addr", "add", f"{peer_v6}/{prefix6}", "dev", peer_if])
            run(["ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", host_addr])
            run(["ip", "netns", "exec", ns, "ip", "-6", "route", "add", "default", "via", host_addr6])
        else:
            # attacker: freebind source selection over whole ranges
            atk_base4 = str(v4.network_address + 21)
            atk_base6 = str(v6.network_address + 21)
            run(["ip", "netns", "exec", ns, "ip", "addr", "add", f"{atk_base4}/{prefix4}", "dev", peer_if])
            run(["ip", "netns", "exec", ns, "ip", "-6", "addr", "add", f"{atk_base6}/{prefix6}", "dev", peer_if])
            run(["ip", "netns", "exec", ns, "ip", "route", "add", "default", "via", host_addr])
            run(["ip", "netns", "exec", ns, "ip", "-6", "route", "add", "default", "via", host_addr6])
            # route whole attacker ranges locally so freebind can pick any src
            run(["ip", "netns", "exec", ns, "ip", "route", "add", "local", p.net.attacker_v4, "dev", "lo"], check=False, quiet=True)
            run(["ip", "netns", "exec", ns, "ip", "-6", "route", "add", "local", p.net.attacker_v6, "dev", "lo"], check=False, quiet=True)
            # the attacker reaches the front; the host routes replies back
            run(["ip", "route", "add", p.net.attacker_v4, "dev", host_if], check=False, quiet=True)
            run(["ip", "-6", "route", "add", p.net.attacker_v6, "dev", host_if], check=False, quiet=True)
    # the host forwards between its own interfaces for the attacker ranges
    run(["sysctl", "-q", "net.ipv4.ip_forward=1"], check=False, quiet=True)
    run(["sysctl", "-q", "net.ipv6.conf.all.forwarding=1"], check=False, quiet=True)


def teardown_namespaces() -> None:
    for ns in (CLI_NS, ATK_NS):
        if netns_exists(ns):
            run(["ip", "netns", "del", ns], check=False, quiet=True)
    for host_if in ("vh-cli", "vh-atk"):
        run(["ip", "link", "del", host_if], check=False, quiet=True)
