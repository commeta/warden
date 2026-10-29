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


def _audit_block(mode: str, worker_user: str) -> tuple[str, list[dict], dict]:
    """Return (ModSecurity audit directives, warden [[waf.log]] list, descriptor)."""
    parts = "ABIJDEFHZ"
    desc: dict = {"mode": mode}
    if mode == "serial-native":
        block = _serial(f"{AUD}/audit.log", parts, json=False)
        logs = [{"path": f"{AUD}/audit.log", "format": "native", "site": "main"}]
        desc.update(kind="file", path=f"{AUD}/audit.log")
    elif mode == "serial-json":
        block = _serial(f"{AUD}/audit.log", parts, json=True)
        logs = [{"path": f"{AUD}/audit.log", "format": "json", "site": "main"}]
        desc.update(kind="file", path=f"{AUD}/audit.log")
    elif mode == "per-site":
        # the front sets SecAuditLog per vhost; base only sets type+parts
        block = (
            "SecAuditEngine RelevantOnly\n"
            "SecAuditLogType Serial\n"
            f"SecAuditLogParts {parts}\n"
            "# SecAuditLog is set per virtual host (one log per site)\n"
        )
        logs = [{"path": f"{AUD}/sites/*/audit.log", "format": "native", "site": "{1}"}]
        desc.update(kind="per-site", dir=f"{AUD}/sites")
    elif mode == "concurrent-index":
        block = _concurrent(index=f"{AUD}/index", storage=f"{AUD}/data", parts=parts)
        logs = [{"path": f"{AUD}/index", "format": "concurrent",
                 "storage_dir": f"{AUD}/data", "site": "main"}]
        desc.update(kind="concurrent", index=f"{AUD}/index", storage=f"{AUD}/data")
    elif mode == "concurrent-noindex":
        # ModSecurity still writes an index, but Warden is pointed at the
        # storage directory and scans it (no index) — exercising that path.
        block = _concurrent(index=f"{AUD}/index", storage=f"{AUD}/data", parts=parts)
        logs = [{"path": f"{AUD}/data", "format": "concurrent", "site": "main"}]
        desc.update(kind="concurrent", index=f"{AUD}/index", storage=f"{AUD}/data")
    elif mode == "error-log":
        block = "SecAuditEngine Off\n"
        logs = [{"path": "@ERRORLOG@", "format": "error_log", "site": "main"}]
        desc.update(kind="error-log")
    else:  # pragma: no cover - validated earlier
        raise AssertionError(mode)
    desc["worker"] = worker_user
    return block, logs, desc


def _serial(path: str, parts: str, *, json: bool) -> str:
    lines = [
        "SecAuditEngine RelevantOnly",
        "SecAuditLogType Serial",
        f"SecAuditLog {path}",
        f"SecAuditLogParts {parts}",
    ]
    if json:
        lines.append("SecAuditLogFormat JSON")
    return "\n".join(lines) + "\n"


def _concurrent(*, index: str, storage: str, parts: str) -> str:
    return (
        "SecAuditEngine RelevantOnly\n"
        "SecAuditLogType Concurrent\n"
        f"SecAuditLog {index}\n"
        f"SecAuditLogStorageDir {storage}\n"
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
    audit, logs, desc = _audit_block(p.waf.mode, worker)
    ctx.set("waf_audit", desc)
    ctx.set("waf_logs", logs)

    base = render_template("waf/modsecurity.conf", {"ENGINE": engine_state, "AUDIT": audit.rstrip()})
    plan.dirs.append(DirSpec(MODSEC_DIR, "root", "root", 0o755, "waf"))
    plan.dirs.append(DirSpec(AUD, "root", "adm", 0o750, "waf"))
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
    kind = desc.get("mode")
    if kind in {"serial-native", "serial-json"}:
        path = desc["path"]
        open(path, "a").close()
        # Apache prefork (mod_security2) opens the serial log as root → keep it
        # root:adm 0640 (not web-writable: a www-data log could be forged).
        # nginx/event workers write it themselves → web-writable (Warden then
        # flags log_trust, which is the realistic N5 case).
        if p.front == "apache-prefork":
            own(path, "root", "adm", 0o640)
        else:
            own(path, worker, "adm", 0o640)
    elif kind in {"concurrent-index", "concurrent-noindex"}:
        os.makedirs(desc["storage"], exist_ok=True)
        open(desc["index"], "a").close()
        # the per-transaction files are written by workers — that is the
        # tamper surface (MD5-in-index) the forgery tests exercise.
        own(desc["storage"], worker, "adm", 0o750)
        own(desc["index"], worker, "adm", 0o640)
    elif kind == "per-site":
        os.makedirs(f"{AUD}/sites", exist_ok=True)
        own(f"{AUD}/sites", worker, "adm", 0o750)


def verify(p, ctx):
    out = [("modsec main.conf", os.path.exists(f"{MODSEC_DIR}/main.conf"), "")]
    return out


ROLE = roles.Role(name="waf", packages=packages, render=render, post_apply=post_apply, verify=verify, active=_active)
