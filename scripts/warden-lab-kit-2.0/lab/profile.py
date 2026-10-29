"""The declarative lab profile (``lab.toml``) and its compatibility matrix.

A profile is pure data: a front, a WAF engine and log mode, a CRS source, a
set of enabled sites and microservices, a Warden source, and the network
layout. :func:`load` reads and validates it *before anything is installed*,
so an impossible combination (microservices with no WAF, ModSecurity 2.9 on
nginx) is refused by ``labctl plan`` rather than discovered half way through
``apply``.
"""

from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass, field
from typing import Any

from .util import die

# --------------------------------------------------------------------------
# the compatibility matrix (review: "Фронты и выбор ModSecurity")
# --------------------------------------------------------------------------

# front -> which ModSecurity engines it can carry itself.
#   "2"  = ModSecurity 2.9 in-server (Apache mod_security2)
#   "3"  = libmodsecurity 3 connector
#   "edge" = no WAF of its own; sits in front of the nginx+ModSecurity3 tier
FRONTS: dict[str, dict[str, Any]] = {
    "nginx": {"engines": ["3"], "php": "fpm", "desc": "nginx 1.24 + ModSecurity 3"},
    "apache-prefork": {"engines": ["2"], "php": "module", "desc": "Apache prefork + mod_php + ModSecurity 2.9"},
    "apache-event": {"engines": ["2"], "php": "fpm", "desc": "Apache event + PHP-FPM + ModSecurity 2.9"},
    "haproxy": {"engines": ["edge"], "php": "fpm", "desc": "HAProxy 2.8 → nginx + ModSecurity 3 (X-Forwarded-For)"},
    "caddy": {"engines": ["edge"], "php": "fpm", "desc": "Caddy 2 → nginx + ModSecurity 3 (X-Forwarded-For)"},
}

# ModSecurity audit-log modes Warden 0.14.3 reads (review table of six).
WAF_MODES = [
    "serial-native",   # SecAuditLog, native serial (--xxxx-A--)
    "serial-json",     # SecAuditLog, SecAuditLogFormat JSON
    "per-site",        # one SecAuditLog per virtual host (glob)
    "concurrent-index",   # SecAuditLogType Concurrent with an index file
    "concurrent-noindex",  # Concurrent, no index (storage dir scanned)
    "error-log",       # no audit log; the server's error.log only
]

WAF_ENGINES = ["none", "modsec2", "modsec3"]

SERVICES = [
    "php-fpm", "node", "python-asgi", "python-wsgi",
    "go", "java", "ruby", "perl", "dotnet", "ws",
]
# Services that need a package not in the Ubuntu archive: off unless asked.
SERVICES_OPTIONAL = {"dotnet"}

SITES = ["wordpress", "modx", "opencart", "joomla", "drupal", "bitrix", "portal"]

CRS_SOURCES = ["package", "4.x"]

WARDEN_SOURCES = ["release", "deb", "source", "none"]
# Verified asset published by commeta/warden release 0.14.3 (Ubuntu/Debian amd64).
# Keep version and checksum pinned together; do not resolve a mutable "latest" URL.
DEFAULT_WARDEN_VERSION = "0.14.3"
DEFAULT_WARDEN_SHA256 = "acc3e47112307cacdf4e025570f99e0afcc4131cf9e5395b554daaf68bc5470c"


# --------------------------------------------------------------------------
# dataclasses
# --------------------------------------------------------------------------


@dataclass
class NetCfg:
    mode: str = "loopback"          # loopback | netns | lan | external
    external_iface: str = ""         # external mode: the NIC to bind on
    v4_cidr: str = "10.77.0.0/24"
    v6_cidr: str = "fd77::/64"
    attacker_v4: str = "198.18.0.0/15"
    attacker_v6: str = "2001:db8:a::/48"
    # external mode: real client/admin networks allow-listed in Warden & firewall
    trusted: list[str] = field(default_factory=list)


@dataclass
class WafCfg:
    engine: str = "modsec3"          # none | modsec2 | modsec3
    mode: str = "serial-native"
    paranoia: int = 1
    anomaly_in: int = 5
    anomaly_out: int = 4


@dataclass
class CrsCfg:
    source: str = "package"          # package | 4.x
    ref: str = ""                     # 4.x: a tag, e.g. v4.18.0
    sha256: str = ""                  # 4.x: sha256 of the tag's tarball


@dataclass
class TlsCfg:
    mode: str = "self-signed"        # self-signed | files | acme
    domains: list[str] = field(default_factory=list)
    cert_file: str = ""
    key_file: str = ""
    acme_email: str = ""
    acme_staging: bool = True


@dataclass
class WardenCfg:
    source: str = "release"          # release | deb | source | none
    version: str = DEFAULT_WARDEN_VERSION
    sha256: str = DEFAULT_WARDEN_SHA256
    deb_file: str = ""
    deb_sha256: str = ""
    source_dir: str = ""
    source_ref: str = "main"
    enforce: bool = False            # install with dry_run=false (production)


@dataclass
class Profile:
    name: str
    front: str = "nginx"
    hostname: str = "lab.local"
    net: NetCfg = field(default_factory=NetCfg)
    tls: TlsCfg = field(default_factory=TlsCfg)
    waf: WafCfg = field(default_factory=WafCfg)
    crs: CrsCfg = field(default_factory=CrsCfg)
    sites: list[str] = field(default_factory=lambda: ["portal", "wordpress"])
    services: list[str] = field(default_factory=lambda: ["php-fpm", "node", "python-asgi"])
    databases: list[str] = field(default_factory=lambda: ["mariadb"])
    warden: WardenCfg = field(default_factory=WardenCfg)
    # free-form: forwarded to templates (e.g. rate limits for production)
    production: bool = False
    source_path: str = ""

    @property
    def edge(self) -> bool:
        return FRONTS[self.front]["engines"] == ["edge"]

    @property
    def php_model(self) -> str:
        return FRONTS[self.front]["php"]


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------


def _section(data: dict, key: str) -> dict:
    v = data.get(key, {})
    if not isinstance(v, dict):
        die(f"[{key}] must be a table")
    return v


def load(path: str, overrides: list[str] | None = None) -> Profile:
    try:
        with open(path, "rb") as f:
            data = tomllib.load(f)
    except FileNotFoundError:
        die(f"profile not found: {path}")
    except tomllib.TOMLDecodeError as e:
        die(f"{path}: invalid TOML: {e}")
    except OSError as e:
        die(f"{path}: {e}")

    lab = _section(data, "lab")
    p = Profile(name=str(lab.get("name") or "lab"))
    p.front = str(lab.get("front", p.front))
    p.hostname = str(lab.get("hostname", p.hostname))
    p.sites = list(lab.get("sites", p.sites))
    p.services = list(lab.get("services", p.services))
    p.databases = list(lab.get("databases", p.databases))
    p.production = bool(lab.get("production", p.production))

    n = _section(data, "net")
    p.net = NetCfg(
        mode=str(n.get("mode", p.net.mode)),
        external_iface=str(n.get("external_iface", "")),
        v4_cidr=str(n.get("v4_cidr", p.net.v4_cidr)),
        v6_cidr=str(n.get("v6_cidr", p.net.v6_cidr)),
        attacker_v4=str(n.get("attacker_v4", p.net.attacker_v4)),
        attacker_v6=str(n.get("attacker_v6", p.net.attacker_v6)),
        trusted=list(n.get("trusted", [])),
    )

    t = _section(data, "tls")
    if t:
        p.tls = TlsCfg(
            mode=str(t.get("mode", p.tls.mode)),
            domains=list(t.get("domains", [])),
            cert_file=str(t.get("cert_file", "")),
            key_file=str(t.get("key_file", "")),
            acme_email=str(t.get("acme_email", "")),
            acme_staging=bool(t.get("acme_staging", True)),
        )

    w = _section(data, "waf")
    p.waf = WafCfg(
        engine=str(w.get("engine", p.waf.engine)),
        mode=str(w.get("mode", p.waf.mode)),
        paranoia=int(w.get("paranoia", p.waf.paranoia)),
        anomaly_in=int(w.get("anomaly_in", p.waf.anomaly_in)),
        anomaly_out=int(w.get("anomaly_out", p.waf.anomaly_out)),
    )

    c = _section(data, "crs")
    p.crs = CrsCfg(
        source=str(c.get("source", p.crs.source)),
        ref=str(c.get("ref", "")),
        sha256=str(c.get("sha256", "")),
    )

    wd = _section(data, "warden")
    p.warden = WardenCfg(
        source=str(wd.get("source", p.warden.source)),
        version=str(wd.get("version", p.warden.version)),
        sha256=str(wd.get("sha256", p.warden.sha256)),
        deb_file=str(wd.get("deb_file", "")),
        deb_sha256=str(wd.get("deb_sha256", "")),
        source_dir=str(wd.get("source_dir", "")),
        source_ref=str(wd.get("source_ref", "main")),
        enforce=bool(wd.get("enforce", False)),
    )

    p.source_path = path
    for o in overrides or []:
        _apply_override(p, o)
    validate(p)
    return p


def _apply_override(p: Profile, spec: str) -> None:
    """``--set waf.mode=serial-json`` style overrides (dotted key = value)."""
    if "=" not in spec:
        die(f"--set expects key=value, got {spec!r}")
    key, _, value = spec.partition("=")
    key = key.strip()
    value = value.strip()
    table, _, field_name = key.partition(".")
    targets = {
        "waf": p.waf, "net": p.net, "crs": p.crs, "tls": p.tls, "warden": p.warden,
    }
    if table in targets and field_name:
        obj = targets[table]
        if not hasattr(obj, field_name):
            die(f"--set: unknown key {key!r}")
        cur = getattr(obj, field_name)
        setattr(obj, field_name, _coerce(value, cur))
        return
    if key in {"front", "hostname", "production"}:
        setattr(p, key, _coerce(value, getattr(p, key)))
        return
    if key in {"sites", "services", "databases"}:
        setattr(p, key, [s for s in value.split(",") if s])
        return
    die(f"--set: unknown key {key!r}")


def _coerce(value: str, current: Any) -> Any:
    if isinstance(current, bool):
        return value.lower() in {"1", "true", "yes", "on"}
    if isinstance(current, int):
        return int(value)
    return value


# --------------------------------------------------------------------------
# validation + compatibility matrix
# --------------------------------------------------------------------------


def validate(p: Profile) -> None:
    if not p.name or not p.name.replace("-", "").replace("_", "").isalnum():
        die(f"lab.name must be alphanumeric/-/_: {p.name!r}")
    if p.front not in FRONTS:
        die(f"unknown front {p.front!r}; one of {', '.join(FRONTS)}")
    if p.waf.engine not in WAF_ENGINES:
        die(f"unknown waf.engine {p.waf.engine!r}; one of {', '.join(WAF_ENGINES)}")
    if p.waf.mode not in WAF_MODES:
        die(f"unknown waf.mode {p.waf.mode!r}; one of {', '.join(WAF_MODES)}")
    if not 1 <= p.waf.paranoia <= 4:
        die("waf.paranoia must be 1..4")

    engines = FRONTS[p.front]["engines"]
    want = {"modsec2": "2", "modsec3": "3", "none": "none"}[p.waf.engine]
    if p.edge:
        # edge fronts carry no WAF themselves: they require the nginx+modsec3 tier
        if p.waf.engine not in {"modsec3"}:
            die(
                f"front {p.front!r} is an edge proxy: it needs waf.engine=modsec3 "
                "(served by the nginx + ModSecurity 3 tier behind it)"
            )
    elif want != "none" and want not in engines:
        human = {"2": "ModSecurity 2.9", "3": "ModSecurity 3"}
        die(
            f"front {p.front!r} cannot carry {human.get(want, want)}: "
            f"it supports {', '.join(human.get(e, e) for e in engines)}. "
            "See the compatibility matrix in docs/ARCHITECTURE.ru.md."
        )

    if p.services and p.waf.engine == "none":
        die(
            "microservices are proxied through the WAF, so a profile with "
            "[lab] services needs a WAF engine (waf.engine = modsec2|modsec3)"
        )
    if p.sites and p.waf.engine == "none":
        die("a site with no WAF is not a Warden lab; set waf.engine")

    for s in p.services:
        if s not in SERVICES:
            die(f"unknown service {s!r}; one of {', '.join(SERVICES)}")
    for s in p.sites:
        if s not in SITES:
            die(f"unknown site {s!r}; one of {', '.join(SITES)}")

    if p.crs.source not in CRS_SOURCES:
        die(f"unknown crs.source {p.crs.source!r}")
    if p.crs.source == "4.x":
        if not p.crs.ref:
            die("crs.source = '4.x' needs crs.ref (a tag, e.g. v4.18.0)")
        if not _is_sha256(p.crs.sha256):
            die("crs.source = '4.x' needs crs.sha256 (64 hex chars) to pin the tarball")

    # TLS input must be complete before apply; never let a missing certificate
    # become a late nginx -t failure after other files/services were changed.
    if p.tls.mode not in {"self-signed", "files", "acme"}:
        die(f"unknown tls.mode {p.tls.mode!r}; choose self-signed|files|acme")
    dns_name = re.compile(r"(?=^.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$")
    if not dns_name.fullmatch(p.hostname):
        die(f"lab.hostname is not a valid DNS hostname: {p.hostname!r}")
    for domain in p.tls.domains:
        if not dns_name.fullmatch(domain):
            die(f"invalid TLS DNS name in tls.domains: {domain!r}")
    if p.tls.mode == "files" and not (p.tls.cert_file and p.tls.key_file):
        die("tls.mode='files' requires both tls.cert_file and tls.key_file")
    if p.tls.mode == "acme" and not p.tls.domains:
        die("tls.mode='acme' requires at least one public DNS name in tls.domains")
    if p.tls.mode == "acme":
        # One front certificate serves the portal and all emulated site vhosts.
        # Refuse an incomplete SAN list instead of installing a cert that only
        # works on the first vhost and causes browser hostname errors elsewhere.
        required_names = {p.hostname.lower()}
        required_names.update(f"{site}.{p.hostname}".lower() for site in p.sites if site != "portal")
        supplied_names = {name.lower() for name in p.tls.domains}
        missing_names = sorted(required_names - supplied_names)
        if missing_names:
            die("tls.mode='acme' tls.domains must include every virtual-host name: " + ", ".join(missing_names))

    if p.warden.source not in WARDEN_SOURCES:
        die(f"unknown warden.source {p.warden.source!r}")
    if p.warden.source == "release":
        if not p.warden.version:
            die("warden.source = 'release' needs warden.version")
        if not _is_sha256(p.warden.sha256):
            die("warden.source = 'release' needs warden.sha256 (the .deb's sha256sum)")
    if p.warden.source == "deb":
        if not p.warden.deb_file:
            die("warden.source = 'deb' needs warden.deb_file")
        if not _is_sha256(p.warden.deb_sha256):
            die("warden.source = 'deb' needs warden.deb_sha256 (64 hex chars); unpinned packages are refused")

    # Validate lab/attacker networks here so bad input produces a concise
    # profile error instead of an uncaught ipaddress traceback in lab/net.py.
    for field_name, value in (
        ("net.v4_cidr", p.net.v4_cidr),
        ("net.v6_cidr", p.net.v6_cidr),
        ("net.attacker_v4", p.net.attacker_v4),
        ("net.attacker_v6", p.net.attacker_v6),
    ):
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as e:
            detail = ""
            try:
                normalized = ipaddress.ip_network(value, strict=False)
                if str(normalized) != value:
                    detail = f"; network address should be {normalized} (not an interface IP)"
            except ValueError:
                pass
            die(f"invalid {field_name}={value!r}{detail}: {e}")
        expected_v6 = field_name.endswith("v6_cidr") or field_name.endswith("attacker_v6")
        if network.version != (6 if expected_v6 else 4):
            die(f"{field_name} must be IPv{'6' if expected_v6 else '4'} CIDR, got {value!r}")

    nmode = p.net.mode
    if nmode not in {"loopback", "netns", "lan", "external"}:
        die(f"net.mode must be loopback|netns|lan|external, got {nmode!r}")
    if nmode in {"lan", "external"}:
        if not p.net.external_iface:
            die(f"net.mode = {nmode!r} needs net.external_iface (the NIC to serve on)")
        if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", p.net.external_iface):
            die("net.external_iface must be a simple Linux interface name (max 15 characters)")
        if not p.net.trusted:
            die(
                f"net.mode = {nmode!r} needs net.trusted (CIDRs allowed to reach "
                "the front; they are also added to the Warden allowlist)"
            )
        normalized_trusted = []
        for network in p.net.trusted:
            try:
                parsed = ipaddress.ip_network(network, strict=False)
            except ValueError:
                die(f"invalid network in net.trusted: {network!r}")
            if str(parsed) in {"0.0.0.0/0", "::/0"}:
                die("net.trusted must not contain 0.0.0.0/0 or ::/0; specify trusted client IPs/subnets")
            normalized_trusted.append(str(parsed))
        p.net.trusted = list(dict.fromkeys(normalized_trusted))
    if p.production and p.tls.mode == "self-signed" and nmode == "external":
        # allowed, but almost never what you want on a public server
        pass


def _is_sha256(s: str) -> bool:
    return len(s) == 64 and all(c in "0123456789abcdefABCDEF" for c in s)


def summary(p: Profile) -> str:
    lines = [
        f"profile    {p.name}",
        f"front      {p.front}  ({FRONTS[p.front]['desc']})",
        f"waf        {p.waf.engine} / {p.waf.mode}  paranoia {p.waf.paranoia}",
        f"crs        {p.crs.source}" + (f" {p.crs.ref}" if p.crs.ref else ""),
        f"sites      {', '.join(p.sites) or '(none)'}",
        f"services   {', '.join(p.services) or '(none)'}",
        f"databases  {', '.join(p.databases) or '(none)'}",
        f"net        {p.net.mode}"
        + (f" on {p.net.external_iface}" if p.net.mode in {'lan', 'external'} else ""),
        f"tls        {p.tls.mode}",
        f"warden     {p.warden.source}"
        + (f" {p.warden.version}" if p.warden.version else ""),
        f"mode       {'ENFORCE (dry_run=false)' if p.warden.enforce else 'observe (dry_run=true)'}",
    ]
    return "\n".join(lines)
