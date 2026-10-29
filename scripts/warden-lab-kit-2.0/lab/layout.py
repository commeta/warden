"""Deterministic names, paths and ports shared by several roles.

Because the front, the PHP sites, the microservices and the Warden drop-in
all need to agree on where a thing lives, the convention is defined once
here. Nothing in this module touches the host, so any role can import it
during ``render`` (which must stay pure).
"""

from __future__ import annotations

WWW = "/var/www/warden-lab"
RUN = "/run/warden-lab"
SITES_ROOT = f"{WWW}/sites"

# microservice ports (contract: 127.0.0.1:31xx). Index is stable across runs.
SERVICE_PORTS = {
    "php-fpm": None,         # php-fpm is a FastCGI pool, not an HTTP port
    "node": 3101,
    "python-asgi": 3102,
    "python-wsgi": 3103,
    "go": 3104,
    "java": 3105,
    "ruby": 3106,
    "perl": 3107,
    "dotnet": 3108,
    "ws": 3109,
}


def site_user(site: str) -> str:
    return f"lab-{site}"[:32]


def site_root(site: str) -> str:
    return f"{SITES_ROOT}/{site}"


def site_fpm_sock(site: str) -> str:
    return f"{RUN}/fpm-{site}.sock"


def site_fpm_pool(site: str) -> str:
    return f"/etc/php/8.3/fpm/pool.d/lab-{site}.conf"


def svc_user(name: str) -> str:
    return f"labsvc-{name}"[:32]


def svc_root(name: str) -> str:
    return f"{WWW}/services/{name}"


def svc_addr(name: str) -> str:
    port = SERVICE_PORTS.get(name)
    return f"127.0.0.1:{port}" if port else ""


def svc_port(name: str) -> int | None:
    return SERVICE_PORTS.get(name)


def svc_fpm_sock(name: str) -> str:
    # the php-fpm microservice shares the convention but has its own pool
    return f"{RUN}/svc-php-fpm.sock"
