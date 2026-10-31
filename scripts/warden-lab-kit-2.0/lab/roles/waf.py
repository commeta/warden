"""waf: ModSecurity 2.9 or libmodsecurity 3, in one of six audit-log modes.

This role produces the ModSecurity configuration and tells the rest of the
kit what Warden should read. The six modes are exactly those Warden 0.14.3
supports (serial native/JSON, per-site, concurrent with and without an index,
error-log only); ``labctl apply --set waf.mode=…`` flips between them on one
stand, which is how the pytest suite covers all six.

It contributes to the shared context:

* ``waf_main`` — the rules file the front includes (base + crs-setup + rules);
* ``waf_logs`` — the ``[[waf.log]]`` entries for the Warden drop-in;
* ``waf_audit`` — paths/ownership the front role realises for the worker;
* ``web_users`` — the worker accounts (so Warden trusts the right logs).

Known 0.14.2 pitfalls are baked in: explicit ``Include`` (never
``IncludeOptional``) for libmodsecurity 3, the ModSecurity 2.9 serial audit
log kept ``root:adm 0640``, and CRS wired so rule IDs 949/959/980 drive the
event headline Warden shows.
"""

from __future__ import annotations

import os

from .. import roles
from ..render import DirSpec, FileSpec, Plan, render_template

MODSEC_DIR = "/etc/warden-lab/modsec"
AUD = "/var/log/warden-lab/modsec"


def _active(p) -> bool:
    return p.waf.engine in {"modsec2", "modsec3"}


def packages(p) -> list[str]:
    if p.waf.engine == "modsec2":
        return ["libapache2-mod-security2"]
    if p.waf.engine == "modsec3":
        # the nginx connector module (CRS comes from the crs role)
        return ["libnginx-mod-http-modsecurity", "libmodsecurity3"]
    return []


def _audit_block(mode: str, worker_user: str, front: str, sites: list[str]) -> tuple[str, list[dict], dict]:
    """Return ModSecurity directives and Warden sources, scoped to vhosts.

    Every supported audit mode uses a distinct per-vhost path. Serial formats
    are read through one wildcard with the vhost directory captured as the
    Warden site name. Concurrent modes get one index/storage pair per vhost,
    while error-log mode reads each vhost's own server error log.
    """
    parts = "ABIJDEFHZ"
    desc: dict = {"mode": mode}
    site_root = f"{AUD}/sites"
    if mode in {"serial-native", "serial-json", "per-site"}:
        json_mode = mode == "serial-json"
        fmt = "json" if json_mode else "native"
        block = _serial(None, parts, json=json_mode)
        # Use explicit paths instead of a wildcard. Warden 0.14.3 can expand
        # wildcard sources, but its offline doctor does not consistently mark
        # these per-vhost serial logs as followed on a fresh install. Exact
        # paths are unambiguous and retain the vhost -> FIM-site relationship.
        logs = [
            {"path": f"{site_root}/{site}/audit.log", "format": fmt, "site": site}
            for site in sites
        ]
        desc.update(kind="per-site", dir=site_root, format=fmt)
    elif mode in {"concurrent-index", "concurrent-noindex"}:
        # ModSecurity's index and transaction storage are scoped per vhost.
        # The noindex variant asks Warden to scan only each storage directory;
        # ModSecurity still maintains its own index file for transaction writes.
        block = _concurrent(parts=parts)
        if mode == "concurrent-index":
            logs = [
                {"path": f"{site_root}/{site}/index", "format": "concurrent",
                 "storage_dir": f"{site_root}/{site}/data", "site": site}
                for site in sites
            ]
        else:
            logs = [
                {"path": f"{site_root}/{site}/data", "format": "concurrent", "site": site}
                for site in sites
            ]
        desc.update(kind=mode, dir=site_root)
    elif mode == "error-log":
        block = "SecAuditEngine Off\n"
        log_root = "/var/log/warden-lab/apache" if front in {"apache-prefork", "apache-event"} else "/var/log/warden-lab/nginx"
        logs = [
            {"path": f"{log_root}/{site}.error.log", "format": "error_log", "site": site}
            for site in sites
        ]
        desc.update(kind="error-log", path_glob=f"{log_root}/*.error.log")
    else:  # pragma: no cover - validated earlier
        raise AssertionError(mode)
    desc["worker"] = worker_user
    return block, logs, desc


def _serial(path: str | None, parts: str, *, json: bool) -> str:
    lines = [
        "SecAuditEngine RelevantOnly",
        "SecAuditLogType Serial",
        f"SecAuditLogParts {parts}",
    ]
    if path:
        lines.append(f"SecAuditLog {path}")
    if json:
        lines.append("SecAuditLogFormat JSON")
    return "\n".join(lines) + "\n"


def _concurrent(*, parts: str) -> str:
    return (
        "SecAuditEngine RelevantOnly\n"
        "SecAuditLogType Concurrent\n"
        f"SecAuditLogParts {parts}\n"
    )


def _worker_user(p) -> str:
    # every front in the kit runs its workers as www-data
    return "www-data"


def render(p, ctx) -> Plan:
    plan = Plan()
    worker = _worker_user(p)
    ctx.data.setdefault("web_users", [])
    if worker not in ctx.data["web_users"]:
        ctx.data["web_users"].append(worker)

    engine_state = "On"  # blocking; DetectionOnly is a per-test override
    audit, logs, desc = _audit_block(p.waf.mode, worker, p.front, list(p.sites))
    ctx.set("waf_audit", desc)
    ctx.set("waf_logs", logs)

    base = render_template("waf/modsecurity.conf", {"ENGINE": engine_state, "AUDIT": audit.rstrip()})
    plan.dirs.append(DirSpec(MODSEC_DIR, "root", "root", 0o755, "waf"))
    plan.dirs.append(DirSpec(AUD, "root", "adm", 0o750, "waf"))
    if desc.get("kind") == "per-site":
        audit_owner = "root" if p.front == "apache-prefork" else worker
        plan.dirs.append(DirSpec(f"{AUD}/sites", audit_owner, "adm", 0o750, "waf"))
    elif desc.get("kind") in {"concurrent-index", "concurrent-noindex"}:
        plan.dirs.append(DirSpec(f"{AUD}/sites", worker, "adm", 0o750, "waf"))
    plan.files.append(FileSpec(f"{MODSEC_DIR}/modsecurity.conf", base, "root", "root", 0o644, "waf"))

    # unicode mapping the base conf references (shipped by both packages)
    um = _find_unicode_mapping(p)
    if um:
        try:
            data = open(um, "rb").read()
            plan.files.append(FileSpec(f"{MODSEC_DIR}/unicode.mapping", data, "root", "root", 0o644, "waf"))
        except OSError:
            pass

    # the single rules entrypoint the front loads: base + CRS (set by crs role)
    crs_setup = ctx.get("crs_setup", "/etc/warden-lab/crs/crs-setup.conf")
    crs_rules_glob = ctx.get("crs_rules_glob", "/etc/warden-lab/crs/rules/*.conf")
    main = render_template(
        "waf/main.conf",
        {
            "MODSEC_CONF": f"{MODSEC_DIR}/modsecurity.conf",
            "CRS_SETUP": crs_setup,
            "CRS_RULES": crs_rules_glob,
            "EXCLUSIONS": f"{MODSEC_DIR}/lab-exclusions.conf",
        },
    )
    plan.files.append(FileSpec(f"{MODSEC_DIR}/main.conf", main, "root", "root", 0o644, "waf"))
    ctx.set("waf_main", f"{MODSEC_DIR}/main.conf")

    # CMS-shaped false-positive exclusions (admin editors, REST bodies) so the
    # sites' legitimate "save" actions are not themselves blocked.
    plan.files.append(
        FileSpec(f"{MODSEC_DIR}/lab-exclusions.conf",
                 render_template("waf/lab-exclusions.conf", {}),
                 "root", "root", 0o644, "waf")
    )
    return plan


def _find_unicode_mapping(p) -> str | None:
    for c in (
        "/etc/nginx/unicode.mapping",
        "/usr/share/nginx/docs/modsecurity/unicode.mapping",
        "/usr/share/modsecurity-crs/unicode.mapping",
        "/etc/modsecurity/unicode.mapping",
        "/usr/share/doc/libapache2-mod-security2/examples/unicode.mapping",
        "/usr/share/modsecurity/unicode.mapping",
    ):
        if os.path.exists(c):
            return c
    return None


def post_apply(p, ctx) -> None:
    desc = ctx.get("waf_audit", {})
    worker = desc.get("worker", "www-data")
    os.makedirs(AUD, exist_ok=True)

    import grp
    import pwd

    def own(path, user, group, mode):
        try:
            os.chown(path, pwd.getpwnam(user).pw_uid, grp.getgrnam(group).gr_gid)
            os.chmod(path, mode)
        except KeyError:
            pass

    kind = desc.get("kind")
    if kind == "per-site":
        site_root = desc["dir"]
        # Apache prefork opens audit files in the privileged parent; nginx
        # and Apache event workers write them as the web account.
        log_user = "root" if p.front == "apache-prefork" else worker
        os.makedirs(site_root, exist_ok=True)
        own(site_root, log_user, "adm", 0o750)
        for site in p.sites:
            site_dir = os.path.join(site_root, site)
            os.makedirs(site_dir, exist_ok=True)
            log_path = os.path.join(site_dir, "audit.log")
            open(log_path, "a", encoding="utf-8").close()
            own(site_dir, log_user, "adm", 0o750)
            own(log_path, log_user, "adm", 0o640)
    elif kind in {"concurrent-index", "concurrent-noindex"}:
        site_root = desc["dir"]
        os.makedirs(site_root, exist_ok=True)
        own(site_root, worker, "adm", 0o750)
        for site in p.sites:
            site_dir = os.path.join(site_root, site)
            data_dir = os.path.join(site_dir, "data")
            os.makedirs(data_dir, exist_ok=True)
            index_path = os.path.join(site_dir, "index")
            open(index_path, "a", encoding="utf-8").close()
            own(site_dir, worker, "adm", 0o750)
            own(data_dir, worker, "adm", 0o750)
            own(index_path, worker, "adm", 0o640)
    # Error-log mode is provisioned by the front role, which owns each
    # vhost's error log. No ModSecurity audit file needs pre-creation here.


def verify(p, ctx):
    out = [("modsec main.conf", os.path.exists(f"{MODSEC_DIR}/main.conf"), "")]
    desc = ctx.get("waf_audit", {})
    kind = desc.get("kind")
    if kind == "per-site":
        for site in p.sites:
            path = os.path.join(desc["dir"], site, "audit.log")
            out.append((f"waf audit log {site}", os.path.isfile(path), path))
    elif kind in {"concurrent-index", "concurrent-noindex"}:
        for site in p.sites:
            site_dir = os.path.join(desc["dir"], site)
            index_path = os.path.join(site_dir, "index")
            data_dir = os.path.join(site_dir, "data")
            good = os.path.isfile(index_path) and os.path.isdir(data_dir)
            out.append((f"waf concurrent storage {site}", good, site_dir))
    return out


ROLE = roles.Role(name="waf", packages=packages, render=render, post_apply=post_apply, verify=verify, active=_active)
