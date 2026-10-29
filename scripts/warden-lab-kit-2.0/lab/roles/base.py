"""base: the directories, the slice for the kit's own work, the DB secret.

Everything the kit writes lives under a handful of owned roots, so ``reset``
can take it all away. The DB password is generated once into a root-only
file (never into the project tree), and a ``warden-lab.slice`` isolates the
kit's own build/test work from the services Warden watches — so ``report``
can tell "the lab did this" from "a real worker did this".
"""

from __future__ import annotations

import os
import secrets

from .. import roles
from ..render import DirSpec, FileSpec, Plan, render_template

SECRET_DIR = "/etc/warden-lab"
LOG_DIR = "/var/log/warden-lab"
WWW_ROOT = "/var/www/warden-lab"
RUN_DIR = "/run/warden-lab"
DB_PASSWORD_FILE = os.path.join(SECRET_DIR, "db-password")


def _dirs(p) -> list[DirSpec]:
    return [
        DirSpec(SECRET_DIR, "root", "root", 0o750, "base"),
        DirSpec(LOG_DIR, "root", "adm", 0o750, "base"),
        DirSpec(WWW_ROOT, "root", "root", 0o755, "base"),
        DirSpec(RUN_DIR, "root", "root", 0o755, "base"),
    ]


def packages(p) -> list[str]:
    """Packages required by the kit itself, diagnostics and black-box tests.

    Feature-specific roles add server/runtime packages. Keeping these here
    means a clean Ubuntu Server can run ``labctl apply`` without a manual
    pre-install checklist.
    """
    return [
        "ca-certificates",
        "curl",
        "iproute2",
        "nftables",
        "openssl",
        "python3-pytest",
        "python3-pytest-timeout",
    ]


def render(p, ctx) -> Plan:
    plan = Plan()
    plan.dirs.extend(_dirs(p))
    # a slice for the kit's own build and test processes (resource isolation
    # and an attribution marker Warden reporting can key on)
    plan.files.append(
        FileSpec(
            path="/etc/systemd/system/warden-lab.slice",
            content=render_template("systemd/warden-lab.slice", {}),
            role="base",
            mode=0o644,
            restart=(),
        )
    )
    # a human-readable record of what this host is running as a lab
    info = render_template(
        "warden/labinfo.txt",
        {
            "PROFILE": p.name,
            "FRONT": p.front,
            "WAF": f"{p.waf.engine}/{p.waf.mode}",
            "SITES": ", ".join(p.sites) or "(none)",
            "SERVICES": ", ".join(p.services) or "(none)",
            "NET": p.net.mode,
        },
    )
    plan.files.append(
        FileSpec(os.path.join(SECRET_DIR, "labinfo.txt"), info, "root", "root", 0o640, "base")
    )
    return plan


def post_apply(p, ctx) -> None:
    # generate the DB password once; never regenerate (it would orphan the DB)
    if not os.path.exists(DB_PASSWORD_FILE):
        with open(DB_PASSWORD_FILE, "w", encoding="utf-8") as f:
            f.write(secrets.token_hex(24) + "\n")
        os.chmod(DB_PASSWORD_FILE, 0o600)
        os.chown(DB_PASSWORD_FILE, 0, 0)
    ctx.set("db_password_file", DB_PASSWORD_FILE)
    from ..util import have, run
    if have("systemctl"):
        run(["systemctl", "daemon-reload"], check=False, quiet=True)


def verify(p, ctx):
    out = []
    for d in (SECRET_DIR, LOG_DIR, WWW_ROOT):
        out.append((f"dir {d}", os.path.isdir(d), ""))
    st = os.stat(DB_PASSWORD_FILE) if os.path.exists(DB_PASSWORD_FILE) else None
    out.append(("db secret root-only", bool(st) and (st.st_mode & 0o077) == 0, ""))
    return out


ROLE = roles.Role(name="base", packages=packages, render=render, post_apply=post_apply, verify=verify)
