"""net: the lab's own nftables barrier and the client/attacker namespaces.

The kit owns one nftables table, ``inet lab_filter`` (never ``flush
ruleset``, never ``inet warden`` — that is Warden's). It is an *extra* barrier
in front of the lab's services; Warden's own table drops blocked attackers
before it. In ``external`` mode the front is reachable from the NIC; in
``loopback``/``netns`` modes only ``lo`` and the lab veths may reach the
service ports.
"""

from __future__ import annotations

from .. import net as netmod
from .. import roles
from ..render import FileSpec, Plan, render_template
from ..util import have, run, warn

# ports the lab services listen on (front + microservices + optional sshd)
FRONT_PORTS = "80, 443"
SVC_PORTS = "3100-3199"
BACKEND_PORTS = "8080"


def _active(p) -> bool:
    return True


def render(p, ctx) -> Plan:
    ep = netmod.resolve(p)
    ctx.set("endpoints", ep)
    plan = Plan()

    if p.net.mode == "lan":
        # LAN mode: expose only the front ports, only on the selected NIC,
        # and only to explicitly trusted source networks. Everything else
        # reaching the front ports is dropped; microservice ports stay private.
        trusted_v4 = _v4(p.net.trusted)
        trusted_v6 = _v6(p.net.trusted)
        allow_rules = []
        if trusted_v4:
            allow_rules.append(
                f'        iifname "{p.net.external_iface}" ip saddr {{ {", ".join(trusted_v4)} }} '
                f'tcp dport {{ {FRONT_PORTS} }} accept'
            )
        if trusted_v6:
            allow_rules.append(
                f'        iifname "{p.net.external_iface}" ip6 saddr {{ {", ".join(trusted_v6)} }} '
                f'tcp dport {{ {FRONT_PORTS} }} accept'
            )
        body = render_template(
            "net/lab_filter_lan.nft",
            {
                "FRONT_PORTS": FRONT_PORTS,
                "SVC_PORTS": SVC_PORTS,
                "BACKEND_PORTS": BACKEND_PORTS,
                "IFACE": p.net.external_iface,
                "TRUSTED_ACCEPT": "\n".join(allow_rules) or "        # no valid trusted networks",
            },
        )
    elif p.net.mode == "external":
        # production: the front is public; the firewall rate-limits new conns
        # and still keeps the microservice ports private.
        allow_src = "".join(
            f"        ip  saddr {{ {c} }} accept\n" for c in _v4(p.net.trusted)
        )
        body = render_template(
            "net/lab_filter_external.nft",
            {
                "FRONT_PORTS": FRONT_PORTS,
                "SVC_PORTS": SVC_PORTS,
                "BACKEND_PORTS": BACKEND_PORTS,
                "IFACE": p.net.external_iface,
                "TRUSTED_ACCEPT": allow_src or "        # (no extra trusted v4 nets)\n",
            },
        )
    else:
        body = render_template(
            "net/lab_filter_local.nft",
            {"FRONT_PORTS": FRONT_PORTS, "SVC_PORTS": SVC_PORTS},
        )

    plan.files.append(
        FileSpec(
            "/etc/warden-lab/lab_filter.nft", body, "root", "root", 0o640, "net",
            validate=("nft", "-c", "-f", "/etc/warden-lab/lab_filter.nft"),
            restart=("warden-lab-nftables.service",),
        )
    )
    plan.files.append(
        FileSpec(
            "/etc/systemd/system/warden-lab-nftables.service",
            render_template("systemd/warden-lab-nftables.service", {}),
            "root", "root", 0o644, "net",
            restart=("warden-lab-nftables.service",),
        )
    )
    return plan


def _v4(nets: list[str]) -> list[str]:
    return [n for n in nets if ":" not in n]


def _v6(nets: list[str]) -> list[str]:
    return [n for n in nets if ":" in n]


def post_apply(p, ctx) -> None:
    if have("systemctl"):
        run(["systemctl", "daemon-reload"], check=False, quiet=True)
        run(["systemctl", "enable", "--now", "warden-lab-nftables.service"])
    if p.net.mode in {"netns", "external"}:
        ep = ctx.get("endpoints")
        try:
            netmod.setup_namespaces(p, ep)
        except Exception as e:  # namespaces need caps; don't fail the whole apply
            warn(f"namespace setup skipped: {e}")


def verify(p, ctx):
    out = []
    if have("nft"):
        r = run(["nft", "list", "table", "inet", "lab_filter"], check=False, quiet=True)
        out.append(("nft table inet lab_filter", r.ok, r.err.strip()[:120]))
    if p.net.mode in {"netns", "external"}:
        out.append((f"netns {netmod.ATK_NS}", netmod.netns_exists(netmod.ATK_NS), ""))
    return out


ROLE = roles.Role(name="net", render=render, post_apply=post_apply, verify=verify, active=_active)
