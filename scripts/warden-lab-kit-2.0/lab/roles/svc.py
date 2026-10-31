"""svc: the microservices, one contract across many runtimes.

Every service answers the same contract, so one pytest covers all of them:

* ``GET /health``   -> 200 ``ok`` (becomes a Warden ``[[health.check]]``);
* ``GET /echo?q=``  -> reflects input (an XSS target);
* ``GET /item?id=`` -> a read-only SQLite lookup (a SQLi target, not itself vulnerable);
* ``POST /upload``  -> writes a file under the service's FIM-watched dir (webshell fixtures);
* ``GET /spawn``    -> runs a fixed ``/usr/bin/id`` (exercises ``security.web_spawn`` per process model);
* ``GET /sleep?ms`` / ``GET /alloc?mb`` -> health and memory-detector tests.

Each service is its own system user and a hardened systemd unit in the
``warden-lab.slice``; it binds ``127.0.0.1:31xx`` (private — the front proxies
it through the WAF). All runtimes use only their standard library, so the kit
installs from the Ubuntu archive and needs no language package registry.
"""

from __future__ import annotations

import os
import shutil

from .. import layout, roles
from ..fim import fim_include_globs
from ..render import DirSpec, FileSpec, Plan, render_template
from ..util import ensure_system_user, have, run, step, warn

SVC_ROOT = f"{layout.WWW}/services"

# runtime -> (apt packages, start argv template, needs build)
RUNTIMES = {
    "node": {"pkgs": ["nodejs", "sqlite3"], "exec": "/usr/bin/node @DIR@/server.js", "build": None},
    "ws": {"pkgs": ["nodejs"], "exec": "/usr/bin/node @DIR@/server.js", "build": None},
    "python-asgi": {"pkgs": ["python3"], "exec": "/usr/bin/python3 @DIR@/server.py", "build": None},
    "python-wsgi": {"pkgs": ["python3"], "exec": "/usr/bin/python3 @DIR@/server.py", "build": None},
    "perl": {"pkgs": ["perl", "sqlite3"], "exec": "/usr/bin/perl @DIR@/server.pl", "build": None},
    "ruby": {"pkgs": ["ruby", "sqlite3"], "exec": "/usr/bin/ruby @DIR@/server.rb", "build": None},
    "go": {"pkgs": ["golang-1.22-go", "sqlite3"], "exec": "@DIR@/server", "build": "go"},
    "java": {"pkgs": ["openjdk-21-jdk-headless", "sqlite3"], "exec": "/usr/bin/java -cp @DIR@ Server", "build": "java"},
    "dotnet": {"pkgs": ["dotnet-sdk-8.0", "sqlite3"], "exec": "@DIR@/server", "build": "dotnet"},
    "php-fpm": {"pkgs": ["php8.3-fpm", "php8.3-sqlite3"], "exec": "", "build": None},  # a FastCGI pool, not a unit
}


def _active(p) -> bool:
    return bool(p.services)


def packages(p) -> list[str]:
    pk: list[str] = []
    for s in p.services:
        pk += RUNTIMES.get(s, {}).get("pkgs", [])
    return pk


def users(p):
    return [(layout.svc_user(n), layout.svc_root(n)) for n in p.services if n in RUNTIMES]


def render(p, ctx) -> Plan:
    plan = Plan()
    plan.dirs.append(DirSpec(SVC_ROOT, "root", "root", 0o755, "svc"))
    hc = ctx.data.setdefault("health_checks", [])
    web_users = ctx.data.setdefault("web_users", [])
    fim = ctx.data.setdefault("fim_sites", [])
    portal_access_log = (ctx.get("sites", {}).get("portal") or {}).get("access_log")

    for name in p.services:
        if name not in RUNTIMES:
            continue
        user = layout.svc_user(name)
        if user not in web_users:
            web_users.append(user)
        root = layout.svc_root(name)
        plan.dirs.append(DirSpec(root, "root", user, 0o750, "svc"))
        plan.dirs.append(DirSpec(f"{root}/uploads", user, user, 0o750, "svc"))
        plan.dirs.append(DirSpec(f"{root}/data", user, user, 0o750, "svc"))

        restart_unit = "php8.3-fpm.service" if name == "php-fpm" else f"warden-lab-svc-{name}.service"
        # Microservices are reverse-proxied from the portal vhost. Register
        # their roots as distinct Warden FIM sites so uploads are monitored and
        # access-log correlation resolves to the portal's request log.
        fim.append({
            "name": f"svc-{name}",
            "root": root,
            "access_log": portal_access_log,
            "no_scripts": ["uploads/**"],
            "include": fim_include_globs(),
            "restart_unit": restart_unit,
        })

        if name == "php-fpm":
            pool = render_template(
                "front/php-fpm-pool.conf",
                {"NAME": "svc-php-fpm", "USER": user, "RUNUSER": user,
                 "SOCK": layout.svc_fpm_sock(name), "BASE": layout.svc_root(name)},
            )
            plan.files.append(
                FileSpec("/etc/php/8.3/fpm/pool.d/lab-svc-php-fpm.conf", pool, "root", "root", 0o644, "svc",
                         restart=("php8.3-fpm.service",))
            )
            # health check via the front (http) — added by warden role through the front route
            hc.append({"name": "svc-php-fpm", "type": "http",
                       "url": "http://127.0.0.1/svc/php-fpm/health", "unit": "php8.3-fpm.service"})
            continue

        port = layout.svc_port(name)
        exec_line = RUNTIMES[name]["exec"].replace("@DIR@", root)
        unit = render_template(
            "systemd/warden-lab-svc.service",
            {
                "NAME": name,
                "USER": user,
                "EXEC": exec_line,
                "ROOT": root,
                "PORT": str(port or 0),
                "ENVPORT": str(port or 0),
            },
        )
        plan.files.append(
            # Do not start before post_apply has deployed the service source.
            # svc.post_apply reloads systemd, deploys/builds code, then restarts.
            FileSpec(f"/etc/systemd/system/warden-lab-svc-{name}.service", unit, "root", "root", 0o644, "svc")
        )
        hc.append({"name": f"svc-{name}", "type": "http",
                   "url": f"http://{layout.svc_addr(name)}/health",
                   "unit": f"warden-lab-svc-{name}.service"})
    return plan


def post_apply(p, ctx) -> None:
    kit = ctx.kit_root
    if have("systemctl"):
        run(["systemctl", "daemon-reload"], check=False, quiet=True)
    for name in p.services:
        if name not in RUNTIMES:
            continue
        user = layout.svc_user(name)
        root = layout.svc_root(name)
        ensure_system_user(user, home=root)
        _deploy(kit, name, root, user)
        _build(name, root)
        _own(root, user)
        if name == "php-fpm":
            if have("systemctl"):
                run(["systemctl", "reload", "php8.3-fpm.service"], check=False, quiet=True)
            continue
        if have("systemctl"):
            unit = f"warden-lab-svc-{name}.service"
            run(["systemctl", "enable", unit])
            # restart starts inactive units too; code is now deployed/built.
            run(["systemctl", "restart", unit])


def _deploy(kit: str, name: str, root: str, user: str) -> None:
    src = os.path.join(kit, "services", name)
    if not os.path.isdir(src):
        warn(f"no service code for {name} at {src}")
        return
    for entry in os.listdir(src):
        s = os.path.join(src, entry)
        d = os.path.join(root, entry)
        if os.path.isdir(s):
            shutil.copytree(s, d, dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
        else:
            shutil.copy2(s, d)
    # a shared read-only SQLite corpus for /item
    _seed_sqlite(os.path.join(root, "data", "items.sqlite"))
    step(f"deployed service {name} -> {root}")


def _seed_sqlite(path: str) -> None:
    import sqlite3
    if os.path.exists(path):
        return
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY, name TEXT, note TEXT)")
    con.executemany(
        "INSERT OR IGNORE INTO items VALUES (?,?,?)",
        [(1, "alpha", "first"), (2, "beta", "second"), (3, "gamma", "third")],
    )
    con.commit()
    con.close()


def _build(name: str, root: str) -> None:
    kind = RUNTIMES[name].get("build")
    if kind == "go":
        go = _find_go()
        if not go:
            warn("go toolchain not found; skipping go service build")
            return
        run([go, "build", "-o", os.path.join(root, "server"), "."],
            cwd=root, env={"GOCACHE": "/tmp/warden-lab-gocache", "HOME": "/tmp", "GOFLAGS": "-mod=mod"}, check=False)
    elif kind == "java":
        if have("javac"):
            run(["javac", "-d", root, os.path.join(root, "Server.java")], check=False)
    elif kind == "dotnet":
        if have("dotnet"):
            run(["dotnet", "publish", "-c", "Release", "-o", root, root],
                env={"DOTNET_CLI_HOME": "/tmp", "HOME": "/tmp"}, check=False)
        else:
            warn("dotnet SDK not present; the dotnet service is optional and was skipped")


def _find_go() -> str | None:
    for c in ("/usr/lib/go-1.22/bin/go", "/usr/local/go/bin/go", shutil_which("go")):
        if c and os.path.exists(c):
            return c
    return None


def shutil_which(x):
    import shutil as sh
    return sh.which(x)


def _own(root: str, user: str) -> None:
    """Make deployed code immutable to the service; keep only data/uploads writable.

    The service account's primary group receives read/execute access to the
    code tree. The service itself owns the two explicitly mutable directories.
    This avoids executing scripts from a directory the runtime can rewrite.
    """
    import pwd
    import stat

    try:
        account = pwd.getpwnam(user)
        uid = account.pw_uid
        gid = account.pw_gid
    except KeyError:
        return

    writable_roots = {"uploads", "data"}

    def writable_path(path: str) -> bool:
        rel = os.path.relpath(path, root)
        first = rel.split(os.sep, 1)[0]
        return first in writable_roots

    for dirpath, _dirs, files in os.walk(root, topdown=True, followlinks=False):
        mutable = writable_path(dirpath)
        if mutable:
            os.chown(dirpath, uid, gid)
            os.chmod(dirpath, 0o750)
        else:
            os.chown(dirpath, 0, gid)
            os.chmod(dirpath, 0o750)

        for name in files:
            fp = os.path.join(dirpath, name)
            try:
                st = os.lstat(fp)
            except FileNotFoundError:
                continue
            # Do not follow deployed symlinks when assigning ownership.
            if stat.S_ISLNK(st.st_mode):
                os.chown(fp, 0, gid, follow_symlinks=False)
                continue
            mutable_file = writable_path(fp)
            if mutable_file:
                os.chown(fp, uid, gid)
                os.chmod(fp, 0o640)
            else:
                os.chown(fp, 0, gid)
                # Preserve executable semantics for compiled apphosts/binaries,
                # but never preserve write bits for group or other users.
                mode = 0o750 if st.st_mode & 0o111 else 0o640
                os.chmod(fp, mode)


def verify(p, ctx):
    out = []
    for name in p.services:
        if name == "php-fpm" or name not in RUNTIMES:
            continue
        addr = layout.svc_addr(name)
        r = run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", f"http://{addr}/health"],
                check=False, quiet=True) if have("curl") else None
        out.append((f"svc {name} /health", bool(r and r.out.strip() == "200"), addr))
    return out


ROLE = roles.Role(name="svc", packages=packages, render=render, post_apply=post_apply, verify=verify, users=users, active=_active)
