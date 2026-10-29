"""db: optional backend databases (MariaDB, PostgreSQL, Redis).

Sites are self-contained on SQLite by default, so the kit works with no DB
server at all. When a profile lists databases, this role installs them, seeds
a read-only ``posts`` table in MariaDB for the classic SQLi lab page, and
contributes:

* a ``[[health.check]]`` per server (command probes: ``mysqladmin ping``,
  ``pg_isready``, ``redis-cli ping``) for the Warden drop-in;
* the ``databases`` hint for Warden's tuning advisor.

The MariaDB credentials live in ``/etc/warden-lab/db.php`` (``root:www-data
0640``) and the password in the root-only secret file — never in the project
tree.
"""

from __future__ import annotations

import os

from .. import roles
from ..render import Plan
from ..util import have, run, warn

DB_NAME = "wardenlab"
DB_USER = "wardenlab"
DB_PHP = "/etc/warden-lab/db.php"


def _active(p) -> bool:
    return bool(p.databases)


def packages(p) -> list[str]:
    pkgs = []
    if "mariadb" in p.databases:
        pkgs += ["mariadb-server", "php8.3-mysql"]
    if "postgres" in p.databases:
        pkgs += ["postgresql"]
    if "redis" in p.databases:
        pkgs += ["redis-server"]
    return pkgs


def render(p, ctx) -> Plan:
    hc = ctx.data.setdefault("health_checks", [])
    if "mariadb" in p.databases:
        hc.append(
            {"name": "mariadb", "type": "command", "program": "/usr/bin/mysqladmin",
             "args": ["--defaults-file=/etc/warden-lab/mysql-probe.cnf", "ping"],
             "expect_output": "alive", "unit": "mariadb.service"}
        )
    if "postgres" in p.databases:
        hc.append(
            {"name": "postgres", "type": "command", "program": "/usr/bin/pg_isready",
             "args": ["-q"], "unit": "postgresql.service"}
        )
    if "redis" in p.databases:
        hc.append(
            {"name": "redis", "type": "command", "program": "/usr/bin/redis-cli",
             "args": ["ping"], "expect_output": "PONG", "unit": "redis-server.service"}
        )
    plan = Plan()
    return plan


def post_apply(p, ctx) -> None:
    pw = _password()
    if "mariadb" in p.databases:
        _mariadb(pw)
    if "postgres" in p.databases and have("systemctl"):
        run(["systemctl", "enable", "--now", "postgresql.service"], check=False, quiet=True)
    if "redis" in p.databases and have("systemctl"):
        run(["systemctl", "enable", "--now", "redis-server.service"], check=False, quiet=True)


def _password() -> str:
    try:
        with open("/etc/warden-lab/db-password", encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def _mariadb(pw: str) -> None:
    if not have("mysql"):
        warn("mariadb client not installed; skipping MariaDB seed (install the package or drop 'mariadb' from databases)")
        return
    if not have("systemctl"):
        warn("no systemd; skipping MariaDB bring-up")
        return
    run(["systemctl", "enable", "--now", "mariadb.service"], check=False, quiet=True)
    sql = f"""
CREATE DATABASE IF NOT EXISTS {DB_NAME} CHARACTER SET utf8mb4;
CREATE USER IF NOT EXISTS '{DB_USER}'@'localhost' IDENTIFIED BY '{pw}';
GRANT SELECT ON {DB_NAME}.* TO '{DB_USER}'@'localhost';
FLUSH PRIVILEGES;
USE {DB_NAME};
CREATE TABLE IF NOT EXISTS posts (id INT PRIMARY KEY, title VARCHAR(200), body TEXT);
INSERT IGNORE INTO posts (id,title,body) VALUES
  (1,'First post','Hello from the Warden lab.'),
  (2,'Second post','A read-only corpus for SQLi probes.'),
  (3,'Third post','ModSecurity should stop the injection before this runs.');
"""
    run(["mysql"], input=sql, check=False)
    # a probe cnf so the health check logs in without the password on the CLI
    with open("/etc/warden-lab/mysql-probe.cnf", "w", encoding="utf-8") as f:
        f.write(f"[client]\nuser={DB_USER}\npassword={pw}\nhost=localhost\n")
    os.chmod("/etc/warden-lab/mysql-probe.cnf", 0o640)
    import grp
    os.chown("/etc/warden-lab/mysql-probe.cnf", 0, grp.getgrnam("www-data").gr_gid if _grp("www-data") else 0)
    # credentials the SQLi page reads
    php = (
        "<?php\n"
        f"define('LAB_DB_HOST','127.0.0.1');\n"
        f"define('LAB_DB_NAME','{DB_NAME}');\n"
        f"define('LAB_DB_USER','{DB_USER}');\n"
        f"define('LAB_DB_PASS','{pw}');\n"
    )
    with open(DB_PHP, "w", encoding="utf-8") as f:
        f.write(php)
    os.chmod(DB_PHP, 0o640)
    if _grp("www-data"):
        os.chown(DB_PHP, 0, grp.getgrnam("www-data").gr_gid)


def _grp(name: str) -> bool:
    import grp as g
    try:
        g.getgrnam(name)
        return True
    except KeyError:
        return False


def verify(p, ctx):
    out = []
    if "mariadb" in p.databases:
        out.append(("mariadb reachable", have("mysqladmin") and run(["mysqladmin", "ping"], check=False, quiet=True).ok, ""))
    if "redis" in p.databases:
        out.append(("redis reachable", have("redis-cli") and run(["redis-cli", "ping"], check=False, quiet=True).out.strip() == "PONG", ""))
    return out


ROLE = roles.Role(name="db", packages=packages, render=render, post_apply=post_apply, verify=verify, active=_active)
