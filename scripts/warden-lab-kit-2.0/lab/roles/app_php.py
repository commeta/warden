"""app_php: the emulated CMS sites and the portal.

Each site is a system user of its own, a docroot under
``/var/www/warden-lab/sites/<site>``, a writable ``uploads/`` that FIM marks
"no scripts here", and — on the FPM fronts — a dedicated PHP-FPM pool running
as that user over a unix socket. The site code is the shared emulator in
``sites/`` deployed per engine, so a webshell dropped into one site's uploads
is attributed to that site and that user.

The role fills in the per-site user / restart unit for the Warden drop-in and
declares each site as a FIM site with explicit script coverage and no-scripts uploads.
"""

from __future__ import annotations

import os
import shutil

from .. import layout, roles
from ..fim import fim_include_globs
from ..render import DirSpec, FileSpec, Plan, render_template
from ..util import ensure_system_user, run, step

KIT_SITES = "sites"   # relative to the kit root


def _active(p) -> bool:
    return bool(p.sites)


def packages(p) -> list[str]:
    pk = ["php8.3-cli", "php8.3-sqlite3"]
    if p.php_model == "fpm":
        pk.append("php8.3-fpm")
    return pk


def users(p):
    return [(layout.site_user(s), layout.site_root(s)) for s in p.sites]


def render(p, ctx) -> Plan:
    plan = Plan()
    sites = ctx.data.setdefault("sites", {})
    web_users = ctx.data.setdefault("web_users", [])
    fim = ctx.data.setdefault("fim_sites", [])

    plan.dirs.append(DirSpec(layout.SITES_ROOT, "root", "root", 0o755, "app_php"))

    for s in p.sites:
        user = layout.site_user(s)
        root = layout.site_root(s)
        meta = sites.setdefault(s, {})
        meta["user"] = user
        if user not in web_users:
            web_users.append(user)
        # Shared-hosting ownership: the site user owns the tree (so PHP-FPM,
        # which runs as that user, serves it and a webshell is attributed to
        # it), group www-data so the web server can read and stat it. The
        # webroot is not group-writable; only uploads/ is writable by the
        # site user (where a dropped webshell would land).
        plan.dirs.append(DirSpec(root, user, "www-data", 0o750, "app_php"))
        plan.dirs.append(DirSpec(f"{root}/public", user, "www-data", 0o750, "app_php"))
        plan.dirs.append(DirSpec(f"{root}/public/uploads", user, "www-data", 0o750, "app_php"))
        plan.dirs.append(DirSpec(f"{root}/data", user, user, 0o750, "app_php"))

        if p.php_model == "fpm":
            pool = render_template(
                "front/php-fpm-pool.conf",
                {
                    "NAME": s,
                    "USER": user,
                    "SOCK": layout.site_fpm_sock(s),
                    "RUNUSER": user,
                    "BASE": layout.site_root(s),
                },
            )
            plan.files.append(
                FileSpec(layout.site_fpm_pool(s), pool, "root", "root", 0o644, "app_php",
                         validate=(), restart=("php8.3-fpm.service",))
            )
            meta["restart_unit"] = "php8.3-fpm.service"
        else:
            meta["restart_unit"] = "apache2.service"

        # FIM site: baseline the code, watch uploads for scripts
        fim.append(
            {
                "name": s,
                "root": f"{root}/public",
                "access_log": meta.get("access_log"),
                "no_scripts": ["uploads/**"],
                "include": fim_include_globs(),
                "restart_unit": meta["restart_unit"],
            }
        )
    return plan


def post_apply(p, ctx) -> None:
    kit = ctx.kit_root
    for s in p.sites:
        user = layout.site_user(s)
        ensure_system_user(user, home=layout.site_root(s))
        _deploy(kit, s, layout.site_root(s), user)
        _seed_site_db(layout.site_root(s))
        if s == "portal":
            _portal_manifest(p, layout.site_root(s))
    import grp
    import pwd
    # re-assert ownership after deploy: owner = site user (PHP-FPM reads as
    # owner), group = www-data (the web server reads/stats via the group).
    try:
        web_gid = grp.getgrnam("www-data").gr_gid
    except KeyError:
        web_gid = 0
    for s in p.sites:
        user = layout.site_user(s)
        root = layout.site_root(s)
        try:
            uid, gid = pwd.getpwnam(user).pw_uid, grp.getgrnam(user).gr_gid
        except KeyError:
            continue
        for dirpath, _dirs, files in os.walk(f"{root}/public"):
            os.chown(dirpath, uid, web_gid)
            os.chmod(dirpath, 0o750)
            for f in files:
                fp = os.path.join(dirpath, f)
                os.chown(fp, uid, web_gid)
                os.chmod(fp, 0o640)
        if os.path.isdir(f"{root}/public/uploads"):
            os.chown(f"{root}/public/uploads", uid, web_gid)
            os.chmod(f"{root}/public/uploads", 0o750)
        if os.path.isdir(f"{root}/data"):
            os.chown(f"{root}/data", uid, gid)
            os.chmod(f"{root}/data", 0o750)
    from ..util import have
    if have("systemctl") and p.php_model == "fpm":
        run(["systemctl", "reload", "php8.3-fpm.service"], check=False, quiet=True)


def _seed_site_db(root: str) -> None:
    """A read-only posts corpus for the /lab/sqli target."""
    import sqlite3
    data = os.path.join(root, "data")
    os.makedirs(data, exist_ok=True)
    path = os.path.join(data, "site.sqlite")
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, title TEXT, body TEXT)")
    con.executemany(
        "INSERT OR IGNORE INTO posts VALUES (?,?,?)",
        [(1, "First post", "Hello from the Warden lab."),
         (2, "Second post", "A read-only corpus for SQLi probes."),
         (3, "Third post", "ModSecurity should stop the injection first.")],
    )
    con.commit()
    con.close()


def _portal_manifest(p, root: str) -> None:
    public = os.path.join(root, "public")
    os.makedirs(public, exist_ok=True)
    sites = "', '".join(p.sites)
    services = "', '".join(p.services)
    php = (
        "<?php\nreturn [\n"
        f"    'hostname' => '{p.hostname}',\n"
        f"    'sites' => ['{sites}'],\n"
        f"    'services' => ['{services}'],\n"
        "];\n"
    )
    with open(os.path.join(public, "_manifest.php"), "w", encoding="utf-8") as f:
        f.write(php)


def _deploy(kit: str, site: str, root: str, user: str) -> None:
    """Copy the shared core and the engine-specific files into the docroot."""
    public = os.path.join(root, "public")
    os.makedirs(public, exist_ok=True)
    core = os.path.join(kit, KIT_SITES, "_core")
    engine = os.path.join(kit, KIT_SITES, site)
    for src in (core, engine):
        if not os.path.isdir(src):
            continue
        for name in os.listdir(src):
            s = os.path.join(src, name)
            d = os.path.join(public, name)
            if os.path.isdir(s):
                shutil.copytree(s, d, dirs_exist_ok=True, ignore=shutil.ignore_patterns('__pycache__','*.pyc'))
            else:
                shutil.copy2(s, d)
    step(f"deployed site {site} -> {public}")


def verify(p, ctx):
    out = []
    for s in p.sites:
        idx = f"{layout.site_root(s)}/public/index.php"
        out.append((f"site {s} index.php", os.path.exists(idx), ""))
    return out


ROLE = roles.Role(name="app_php", packages=packages, render=render, post_apply=post_apply, verify=verify, users=users, active=_active)
