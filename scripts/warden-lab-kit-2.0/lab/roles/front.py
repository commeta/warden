"""front: the web front, with ModSecurity wired in.

One role renders whichever front the profile selected. Each CMS site is a
virtual host of its own (``<site>.<hostname>``) with its own docroot, access
log and — on the FPM fronts — its own PHP-FPM pool and system user, so the
``site`` field in Warden's WAF/FIM events is real and a shared-hosting layout
is reproduced. Microservices are reverse-proxied under ``/svc/<name>/`` on the
default (portal) vhost, through the WAF.

Fronts:

* ``nginx``          — ModSecurity 3 connector, PHP-FPM per site;
* ``apache-prefork`` — mod_php + mod_security2 (PHP in the server process);
* ``apache-event``   — PHP-FPM + mod_security2;
* ``haproxy``/``caddy`` — terminate TLS and proxy, with X-Forwarded-For, to an
  internal ``nginx + ModSecurity 3`` tier on 127.0.0.1:8080 (so the forwarded
  client address, which decides who Warden blocks, is exercised too).

The role fills ``ctx['sites']`` (root + access log per site) for the PHP and
Warden roles, and records which server error log the ``error-log`` WAF mode
reads.
"""

from __future__ import annotations

import os

from .. import layout, roles
from ..render import DirSpec, FileSpec, Plan, render_template
from ..util import have, run

NGINX_LOG = "/var/log/warden-lab/nginx"
APACHE_LOG = "/var/log/warden-lab/apache"
PORTAL = "portal"


def _has_ipv6() -> bool:
    """Whether the host can bind IPv6 (so nginx -t does not fail where it can't)."""
    import socket
    if not socket.has_ipv6:
        return False
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.bind(("::", 0))
        s.close()
        return True
    except OSError:
        return False


def packages(p) -> list[str]:
    pk: list[str] = []
    if p.front == "nginx" or p.edge:
        pk += ["nginx"]
    if p.front in {"apache-prefork", "apache-event"}:
        pk += ["apache2"]
    if p.front == "apache-event":
        pk += ["libapache2-mod-fcgid"]
    if p.front == "haproxy":
        pk += ["haproxy"]
    if p.front == "caddy":
        pk += ["caddy"]
    if p.php_model == "fpm":
        pk += ["php8.3-fpm"]
    elif p.php_model == "module":
        pk += ["libapache2-mod-php8.3"]
    return pk


def _site_hosts(p) -> list[str]:
    return [s for s in p.sites if s != PORTAL]


def _register_sites(p, ctx) -> dict:
    sites = ctx.data.setdefault("sites", {})
    front = p.front
    for s in p.sites:
        meta = sites.setdefault(s, {})
        meta["root"] = layout.site_root(s)
        meta["docroot"] = f"{layout.site_root(s)}/public"
        if front == "nginx" or p.edge:
            meta["access_log"] = f"{NGINX_LOG}/{s}.access.log"
        else:
            meta["access_log"] = f"{APACHE_LOG}/{s}.access.log"
        meta["server_name"] = p.hostname if s == PORTAL else f"{s}.{p.hostname}"
    return sites


def render(p, ctx) -> Plan:
    _register_sites(p, ctx)
    plan = Plan()
    if p.front == "nginx":
        _nginx(p, ctx, plan, internal=False)
    elif p.front in {"apache-prefork", "apache-event"}:
        _apache(p, ctx, plan)
    elif p.front == "haproxy":
        _nginx(p, ctx, plan, internal=True)
        _haproxy(p, ctx, plan)
    elif p.front == "caddy":
        _nginx(p, ctx, plan, internal=True)
        _caddy(p, ctx, plan)
    return plan


# --------------------------------------------------------------------------
# nginx (ModSecurity 3)
# --------------------------------------------------------------------------


def _security_headers(prod: bool) -> str:
    h = [
        'add_header X-Content-Type-Options "nosniff" always;',
        'add_header X-Frame-Options "SAMEORIGIN" always;',
        'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
        "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'\" always;",
    ]
    if prod:
        h.append('add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;')
    return "\n        ".join(h)


def _nginx_php_location(sock: str) -> str:
    return (
        "location ~ \\.php$ {\n"
        "            include snippets/fastcgi-php.conf;\n"
        f"            fastcgi_pass unix:{sock};\n"
        "            fastcgi_param HTTPS $https if_not_empty;\n"
        "            fastcgi_read_timeout 30s;\n"
        "        }"
    )


def _nginx_svc_locations(p) -> str:
    out = []
    for name in p.services:
        if name == "php-fpm":
            # a FastCGI pool, not an HTTP upstream: route /svc/php-fpm/ to it
            svc_root = layout.svc_root("php-fpm") + "/public"
            # the PHP service is a single front controller that routes on
            # REQUEST_URI, so every /svc/php-fpm/* request goes straight to its
            # index.php (no alias/try_files footguns).
            out.append(
                f"        location ^~ /svc/php-fpm/ {{\n"
                f"            include fastcgi_params;\n"
                f"            fastcgi_param SCRIPT_FILENAME {svc_root}/index.php;\n"
                f"            fastcgi_param SCRIPT_NAME /svc/php-fpm/index.php;\n"
                f"            fastcgi_param LAB_ROOT {layout.svc_root('php-fpm')};\n"
                f"            fastcgi_pass unix:{layout.svc_fpm_sock('php-fpm')};\n"
                f"        }}"
            )
            continue
        addr = layout.svc_addr(name)
        if not addr:
            continue
        proto = "http"
        extra = ""
        if name == "ws":
            extra = (
                "\n            proxy_http_version 1.1;"
                '\n            proxy_set_header Upgrade $http_upgrade;'
                '\n            proxy_set_header Connection "upgrade";'
            )
        out.append(
            f"        location /svc/{name}/ {{\n"
            f"            proxy_pass {proto}://{addr}/;\n"
            "            proxy_set_header Host $host;\n"
            "            proxy_set_header X-Real-IP $remote_addr;\n"
            "            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n"
            "            proxy_set_header X-Forwarded-Proto $scheme;"
            f"{extra}\n"
            "        }"
        )
    return "\n".join(out) or "        # (no microservices in this profile)"


def _nginx(p, ctx, plan, *, internal: bool) -> None:
    sites = ctx.get("sites", {})
    prod = p.production and not internal
    cert = ctx.get("tls_cert", "/etc/warden-lab/tls/fullchain.pem")
    key = ctx.get("tls_key", "/etc/warden-lab/tls/privkey.pem")
    modsec = "on" if p.waf.engine == "modsec3" else "off"
    main = ctx.get("waf_main", "/etc/warden-lab/modsec/main.conf")

    plan.dirs.append(DirSpec(NGINX_LOG, "www-data", "adm", 0o750, "front"))

    servers = []
    svc = _nginx_svc_locations(p)
    for s in p.sites:
        meta = sites[s]
        is_portal = s == PORTAL
        default = " default_server" if is_portal else ""
        # listen directives
        if internal:
            listen = [f"listen 127.0.0.1:8080{default};"]
            realip = (
                "set_real_ip_from 127.0.0.1;\n    set_real_ip_from ::1;\n"
                "    real_ip_header X-Forwarded-For;\n    real_ip_recursive on;"
            )
            tls_lines = ""
        else:
            v6 = _has_ipv6()
            listen = [f"listen 80{default};"]
            if v6:
                listen.append(f"listen [::]:80{default};")
            realip = ""
            tls6 = f"\n    listen [::]:443 ssl http2{default};" if v6 else ""
            tls_lines = (
                f"\n    listen 443 ssl http2{default};{tls6}\n"
                f"    ssl_certificate {cert};\n"
                f"    ssl_certificate_key {key};\n"
                "    ssl_protocols TLSv1.2 TLSv1.3;\n"
                "    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;\n"
                "    ssl_prefer_server_ciphers off;\n"
                "    ssl_session_cache shared:labSSL:10m;\n"
                "    ssl_session_timeout 1d;"
            )
        server_name = meta["server_name"] + (" localhost" if is_portal else "")
        php = _nginx_php_location(layout.site_fpm_sock(s))
        this_svc = svc if is_portal else "        # /svc proxies live on the portal vhost"
        per_site_audit = ""
        if modsec == "on" and p.waf.mode in {"serial-native", "serial-json", "per-site"}:
            per_site_audit = (
                f"\n    modsecurity_rules 'SecAuditLog /var/log/warden-lab/modsec/sites/{s}/audit.log';"
            )
            audit_owner = "root" if p.front == "apache-prefork" else "www-data"
            plan.dirs.append(DirSpec(f"/var/log/warden-lab/modsec/sites/{s}", audit_owner, "adm", 0o750, "front"))
        elif modsec == "on" and p.waf.mode in {"concurrent-index", "concurrent-noindex"}:
            per_site_audit = (
                f"\n    modsecurity_rules 'SecAuditLog /var/log/warden-lab/modsec/sites/{s}/index; "
                f"SecAuditLogStorageDir /var/log/warden-lab/modsec/sites/{s}/data';"
            )
            plan.dirs.append(DirSpec(f"/var/log/warden-lab/modsec/sites/{s}", "www-data", "adm", 0o750, "front"))
            plan.dirs.append(DirSpec(f"/var/log/warden-lab/modsec/sites/{s}/data", "www-data", "adm", 0o750, "front"))
        listen_block = "\n    ".join(listen)
        headers = _security_headers(prod)
        redirect = ""
        if prod:
            # production: plain HTTP (except ACME) → HTTPS
            redirect = (
                "\n    location /.well-known/acme-challenge/ { allow all; root /var/www/html; }"
                "\n    if ($scheme = http) { return 308 https://$host$request_uri; }"
            )
        realip_line = f"\n    {realip}" if realip else ""
        block = (
            f"server {{\n"
            f"    {listen_block}{tls_lines}{realip_line}\n"
            f"    server_name {server_name};\n"
            f"    root {meta['docroot']};\n"
            f"    index index.php index.html;\n"
            f"    access_log {meta['access_log']} labcombined;\n"
            f"    error_log {NGINX_LOG}/{s}.error.log warn;\n"
            f"    client_max_body_size 16m;\n"
            f"    server_tokens off;\n"
            f"    {headers}\n"
            f"    modsecurity {modsec};\n"
            + (f"    modsecurity_rules_file {main};{per_site_audit}\n" if modsec == "on" else "")
            + f"{redirect}\n"
            f"    location / {{ try_files $uri $uri/ /index.php?$query_string; }}\n"
            # a webshell dropped into uploads/ is reachable (so the access
            # correlation fires) but never executed — production-safe.
            f"    location ~* ^/uploads/.*\\.(php|phar|phtml|pht)$ {{ add_header X-Lab-Uploads denied; return 403; }}\n"
            f"    {php}\n"
            f"{this_svc}\n"
            f"    location ~ /\\.(?!well-known) {{ deny all; }}\n"
            f"}}"
        )
        servers.append(block)

    conf = render_template(
        "front/nginx-head.conf",
        {"SERVERS": "\n\n".join(servers)},
    )
    path = "/etc/nginx/conf.d/warden-lab.conf"
    plan.files.append(
        FileSpec(path, conf, "root", "root", 0o644, "front",
                 validate=("nginx", "-t"), restart=("nginx.service",))
    )
    if p.waf.mode == "error-log":
        ctx.set("waf_error_log", f"{NGINX_LOG}/{PORTAL}.error.log")
        ctx.set("waf_error_log_glob", f"{NGINX_LOG}/*.error.log")


# --------------------------------------------------------------------------
# Apache (mod_security2)
# --------------------------------------------------------------------------


def _apache(p, ctx, plan) -> None:
    sites = ctx.get("sites", {})
    prod = p.production
    cert = ctx.get("tls_cert", "/etc/warden-lab/tls/fullchain.pem")
    key = ctx.get("tls_key", "/etc/warden-lab/tls/privkey.pem")
    main = ctx.get("waf_main", "/etc/warden-lab/modsec/main.conf")
    plan.dirs.append(DirSpec(APACHE_LOG, "root", "adm", 0o750, "front"))

    vhosts = []
    svc = _apache_svc_blocks(p)
    for s in p.sites:
        meta = sites[s]
        php = _apache_php_block(p, s) if True else ""
        this_svc = svc if s == PORTAL else "    # /svc proxies live on the portal vhost"
        # Bind audit records to this virtual host. The audit type/parts are
        # global; only the destination (and concurrent storage directory) is
        # overridden in the vhost context.
        if p.waf.mode in {"serial-native", "serial-json", "per-site"}:
            per_site_audit = f"\n        SecAuditLog /var/log/warden-lab/modsec/sites/{s}/audit.log"
            audit_owner = "root" if p.front == "apache-prefork" else "www-data"
            plan.dirs.append(DirSpec(f"/var/log/warden-lab/modsec/sites/{s}", audit_owner, "adm", 0o750, "front"))
        elif p.waf.mode in {"concurrent-index", "concurrent-noindex"}:
            per_site_audit = (
                f"\n        SecAuditLog /var/log/warden-lab/modsec/sites/{s}/index"
                f"\n        SecAuditLogStorageDir /var/log/warden-lab/modsec/sites/{s}/data"
            )
            plan.dirs.append(DirSpec(f"/var/log/warden-lab/modsec/sites/{s}", "www-data", "adm", 0o750, "front"))
            plan.dirs.append(DirSpec(f"/var/log/warden-lab/modsec/sites/{s}/data", "www-data", "adm", 0o750, "front"))
        else:
            per_site_audit = "\n        # (no serial audit file in error-log mode)"
        vhosts.append(
            render_template(
                "front/apache-vhost.conf",
                {
                    "SERVER_NAME": meta["server_name"],
                    "ALIASES": f"ServerAlias {p.hostname} localhost" if s == PORTAL else "",
                    "ROOT": meta["docroot"],
                    "ACCESS_LOG": meta["access_log"],
                    "ERROR_LOG": f"{APACHE_LOG}/{s}.error.log",
                    "PHP_BLOCK": php,
                    "SVC_BLOCK": this_svc,
                    "CERT": cert,
                    "KEY": key,
                    "PER_SITE_AUDIT": per_site_audit,
                    "HSTS": 'Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains"' if prod else "",
                },
            )
        )

    conf = render_template("front/apache-main.conf", {"VHOSTS": "\n\n".join(vhosts), "MODSEC_MAIN": main})
    # conf-enabled is auto-included by Apache: no a2ensite needed, and the
    # file is manifest-owned so reset removes it cleanly.
    plan.files.append(
        FileSpec("/etc/apache2/conf-enabled/warden-lab.conf", conf, "root", "root", 0o644, "front",
                 validate=("apache2ctl", "configtest"), restart=("apache2.service",))
    )
    # The distro's mods-available/security2.conf auto-includes the CRS *.load,
    # which would collide (duplicate rule IDs) with the CRS our config loads.
    # Replace it with a minimal module config so the kit is the single source
    # of ModSecurity truth (the manifest moves the original aside).
    plan.files.append(
        FileSpec("/etc/apache2/mods-available/security2.conf",
                 render_template("front/apache-security2.conf", {}),
                 "root", "root", 0o644, "front",
                 restart=("apache2.service",))
    )
    # a ports/modules hint file we own (loaded via our conf's listen)
    if p.waf.mode == "error-log":
        ctx.set("waf_error_log", f"{APACHE_LOG}/{PORTAL}.error.log")
        ctx.set("waf_error_log_glob", f"{APACHE_LOG}/*.error.log")


def _apache_php_block(p, site: str) -> str:
    if p.php_model == "module":
        return (
            "<FilesMatch \\.php$>\n"
            "        SetHandler application/x-httpd-php\n"
            "    </FilesMatch>"
        )
    sock = layout.site_fpm_sock(site)
    return (
        "<FilesMatch \\.php$>\n"
        f"        SetHandler \"proxy:unix:{sock}|fcgi://localhost\"\n"
        "    </FilesMatch>"
    )


def _apache_svc_blocks(p) -> str:
    out = []
    for name in p.services:
        if name == "php-fpm":
            svc_root = layout.svc_root("php-fpm") + "/public"
            sock = layout.svc_fpm_sock("php-fpm")
            out.append(
                f"    Alias /svc/php-fpm {svc_root}\n"
                f"    <Directory {svc_root}>\n"
                f"        Require all granted\n"
                f"        SetEnv LAB_ROOT {layout.svc_root('php-fpm')}\n"
                f"        <FilesMatch \\.php$>\n"
                f"            SetHandler \"proxy:unix:{sock}|fcgi://localhost\"\n"
                f"        </FilesMatch>\n"
                f"        FallbackResource /svc/php-fpm/index.php\n"
                f"    </Directory>"
            )
            continue
        addr = layout.svc_addr(name)
        if not addr:
            continue
        out.append(
            f"    <Location /svc/{name}/>\n"
            f"        ProxyPass http://{addr}/\n"
            f"        ProxyPassReverse http://{addr}/\n"
            "        RequestHeader set X-Forwarded-Proto %{REQUEST_SCHEME}s\n"
            "    </Location>"
        )
    return "\n".join(out) or "    # (no microservices in this profile)"


# --------------------------------------------------------------------------
# edge proxies (HAProxy / Caddy) in front of the nginx+modsec3 tier
# --------------------------------------------------------------------------


def _haproxy(p, ctx, plan) -> None:
    cert = ctx.get("tls_cert")
    key = ctx.get("tls_key")
    plan.files.append(
        FileSpec(
            "/etc/warden-lab/haproxy.pem",
            _read_concat(cert, key),
            "root", "root", 0o600, "front",
        )
    )
    conf = render_template("front/haproxy.cfg", {"PEM": "/etc/warden-lab/haproxy.pem"})
    plan.files.append(
        FileSpec("/etc/haproxy/haproxy.cfg", conf, "root", "root", 0o644, "front",
                 validate=("haproxy", "-c", "-f", "/etc/haproxy/haproxy.cfg"),
                 restart=("haproxy.service",))
    )


def _caddy(p, ctx, plan) -> None:
    conf = render_template(
        "front/Caddyfile",
        {"HOSTNAME": p.hostname, "CERT": ctx.get("tls_cert"), "KEY": ctx.get("tls_key")},
    )
    plan.files.append(
        FileSpec("/etc/caddy/Caddyfile", conf, "root", "root", 0o644, "front",
                 restart=("caddy.service",))
    )


def _read_concat(*paths) -> bytes:
    out = b""
    for pth in paths:
        try:
            out += open(pth, "rb").read()
        except OSError:
            pass
    return out or b"# certificate not yet generated\n"


# --------------------------------------------------------------------------


def pre_apply(p, ctx) -> None:
    # make our config authoritative BEFORE it is written and validated
    if p.front == "nginx" or p.edge:
        for d in ("/etc/nginx/sites-enabled/default",):
            if os.path.islink(d) or os.path.exists(d):
                try:
                    os.remove(d)
                except OSError:
                    pass
    if p.front in {"apache-prefork", "apache-event"} and have("a2enmod"):
        if p.php_model == "module":
            run(["a2dismod", "-q", "mpm_event", "mpm_worker"], check=False, quiet=True)
            run(["a2enmod", "-q", "mpm_prefork"], check=False, quiet=True)
            run(["a2enmod", "-q", "php8.3"], check=False, quiet=True)
        else:
            run(["a2enmod", "-q", "mpm_event"], check=False, quiet=True)
        # proxy modules are always needed: /svc/<name>/ reverse-proxies the
        # microservices, and the php-fpm service uses proxy_fcgi.
        for m in ("proxy", "proxy_http", "proxy_fcgi", "security2", "headers", "rewrite", "ssl"):
            run(["a2enmod", "-q", m], check=False, quiet=True)
        for d in ("/etc/apache2/sites-enabled/000-default.conf",
                  "/etc/apache2/sites-enabled/default-ssl.conf"):
            if os.path.islink(d) or os.path.exists(d):
                try:
                    os.remove(d)
                except OSError:
                    pass


def post_apply(p, ctx) -> None:
    if have("systemctl"):
        if p.php_model == "fpm":
            run(["systemctl", "enable", "--now", "php8.3-fpm.service"], check=False, quiet=True)


def verify(p, ctx):
    out = []
    if p.front == "nginx" or p.edge:
        if have("nginx"):
            out.append(("nginx -t", run(["nginx", "-t"], check=False, quiet=True).ok, ""))
    if p.front in {"apache-prefork", "apache-event"} and have("apache2ctl"):
        out.append(("apache2 configtest", run(["apache2ctl", "configtest"], check=False, quiet=True).ok, ""))
    return out


ROLE = roles.Role(name="front", packages=packages, render=render, pre_apply=pre_apply, post_apply=post_apply, verify=verify)
