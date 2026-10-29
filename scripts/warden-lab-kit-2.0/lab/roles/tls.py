"""TLS certificates for the selected front.

All certificate modes fail early and explicitly: self-signed for a lab,
operator-provided files, or ACME HTTP-01 for a public DNS name. ACME temporarily
stops active HTTP frontends because standalone certbot must bind port 80.
"""
from __future__ import annotations

import os
import shutil
import tempfile

from .. import roles
from ..render import DirSpec, Plan
from ..util import die, have, run, step

TLS_DIR = "/etc/warden-lab/tls"
CERT = os.path.join(TLS_DIR, "fullchain.pem")
KEY = os.path.join(TLS_DIR, "privkey.pem")
# These can be started automatically by apt after package installation and
# would otherwise occupy :80 while certbot --standalone requests a challenge.
FRONT_UNITS = ("nginx.service", "apache2.service", "haproxy.service", "caddy.service")


def packages(p) -> list[str]:
    return ["certbot"] if p.tls.mode == "acme" else []


def render(p, ctx) -> Plan:
    ctx.set("tls_cert", CERT)
    ctx.set("tls_key", KEY)
    plan = Plan()
    plan.dirs.append(DirSpec(TLS_DIR, "root", "root", 0o750, "tls"))
    return plan


def pre_apply(p, ctx) -> None:
    os.makedirs(TLS_DIR, exist_ok=True)
    os.chmod(TLS_DIR, 0o750)
    mode = p.tls.mode
    if mode == "files":
        _install_files(p)
    elif mode == "acme":
        _acme(p)
    elif mode == "self-signed":
        _self_signed(p)
    else:  # Profile validation should catch this before apply.
        die(f"unsupported tls.mode={mode!r}")


def _validate_pair(cert: str, key: str) -> None:
    if not os.path.isfile(cert) or not os.path.isfile(key):
        die(f"TLS certificate/key pair not found: cert={cert!r}, key={key!r}")
    cert_check = run(["openssl", "x509", "-in", cert, "-noout"], check=False, quiet=True)
    if not cert_check.ok:
        die(f"invalid PEM certificate {cert}: {cert_check.err.strip() or cert_check.out.strip()}")
    key_check = run(["openssl", "pkey", "-in", key, "-noout"], check=False, quiet=True)
    if not key_check.ok:
        die(f"invalid PEM private key {key}: {key_check.err.strip() or key_check.out.strip()}")
    cert_pub = run(["openssl", "x509", "-in", cert, "-pubkey", "-noout"], check=False, quiet=True)
    key_pub = run(["openssl", "pkey", "-in", key, "-pubout"], check=False, quiet=True)
    if not cert_pub.ok or not key_pub.ok or cert_pub.out.strip() != key_pub.out.strip():
        die(f"TLS certificate and private key do not form a matching pair: {cert}, {key}")


def _install_files(p) -> None:
    cert_src, key_src = p.tls.cert_file, p.tls.key_file
    _validate_pair(cert_src, key_src)
    # Copy via temporary regular files and os.replace. This matters when a
    # previous ACME profile left CERT/KEY as symlinks into /etc/letsencrypt:
    # writing through those symlinks would overwrite Certbot-managed files.
    for src, dst, mode in ((cert_src, CERT, 0o644), (key_src, KEY, 0o600)):
        fd, tmp = tempfile.mkstemp(prefix=".tls-import-", dir=TLS_DIR)
        os.close(fd)
        try:
            shutil.copyfile(src, tmp)
            os.chmod(tmp, mode)
            os.replace(tmp, dst)
        finally:
            try:
                os.unlink(tmp)
            except FileNotFoundError:
                pass
    _validate_pair(CERT, KEY)
    _validate_names(p, CERT)


def _required_names(p) -> list[str]:
    names = [p.hostname]
    names.extend(f"{site}.{p.hostname}" for site in p.sites if site != "portal")
    return list(dict.fromkeys(names))


def _validate_names(p, cert: str) -> None:
    for name in _required_names(p):
        check = run(["openssl", "x509", "-in", cert, "-noout", "-checkhost", name], check=False, quiet=True)
        if not check.ok:
            die(f"TLS certificate {cert} does not cover virtual-host name {name!r}; add it to the certificate SANs")


def _self_signed(p) -> None:
    if not have("openssl"):
        die("openssl is required to generate the self-signed certificate; the base role should install it")
    names = list(dict.fromkeys([*_required_names(p), *p.tls.domains]))
    # Reuse a certificate only when the key matches and every configured
    # virtual-host DNS name is present. This lets operators change hostname
    # or sites and safely re-apply.
    if os.path.exists(CERT) and os.path.exists(KEY):
        old = run(["openssl", "x509", "-in", CERT, "-noout"], check=False, quiet=True)
        if old.ok:
            pair = run(["openssl", "x509", "-in", CERT, "-pubkey", "-noout"], check=False, quiet=True)
            key_pub = run(["openssl", "pkey", "-in", KEY, "-pubout"], check=False, quiet=True)
            names_ok = all(
                run(["openssl", "x509", "-in", CERT, "-noout", "-checkhost", name], check=False, quiet=True).ok
                for name in names
            )
            if pair.ok and key_pub.ok and pair.out.strip() == key_pub.out.strip() and names_ok:
                return
    for path in (CERT, KEY):
        if os.path.islink(path) or os.path.exists(path):
            os.remove(path)
    san = ",".join(f"DNS:{n}" for n in names) + ",DNS:localhost,IP:127.0.0.1"
    run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", KEY, "-out", CERT, "-days", "825",
        "-subj", f"/CN={names[0]}", "-addext", f"subjectAltName={san}",
    ])
    os.chmod(KEY, 0o600)
    os.chmod(CERT, 0o644)
    _validate_pair(CERT, KEY)
    _validate_names(p, CERT)


def _acme(p) -> None:
    if not have("certbot"):
        die("certbot is required for tls.mode=acme; the profile dependency installer should install it")
    if not p.tls.domains:
        die("tls.mode=acme needs at least one public DNS name in [tls].domains")
    if not have("systemctl"):
        die("tls.mode=acme requires systemd to stop HTTP frontends during the standalone challenge")

    stopped: list[str] = []
    try:
        for unit in FRONT_UNITS:
            active = run(["systemctl", "is-active", "--quiet", unit], check=False, quiet=True)
            if active.ok:
                run(["systemctl", "stop", unit])
                stopped.append(unit)
        argv = [
            "certbot", "certonly", "--standalone", "--non-interactive",
            "--agree-tos", "--preferred-challenges", "http",
            "--keep-until-expiring",
        ]
        if p.tls.acme_email:
            argv += ["-m", p.tls.acme_email]
        else:
            argv += ["--register-unsafely-without-email"]
        if p.tls.acme_staging:
            argv.append("--staging")
        for domain in p.tls.domains:
            argv += ["-d", domain]
        run(argv, timeout=600)
        live = f"/etc/letsencrypt/live/{p.tls.domains[0]}"
        for src, dst in ((f"{live}/fullchain.pem", CERT), (f"{live}/privkey.pem", KEY)):
            if not os.path.isfile(src):
                die(f"certbot returned success but the expected file is missing: {src}")
            if os.path.islink(dst) or os.path.exists(dst):
                os.remove(dst)
            os.symlink(src, dst)
        _validate_pair(CERT, KEY)
        _validate_names(p, CERT)
        step(f"ACME certificate ready for {', '.join(p.tls.domains)}")
    finally:
        # Restore whatever was active before the challenge, even on failure.
        # The front role will validate/apply the kit config after this hook.
        for unit in reversed(stopped):
            run(["systemctl", "start", unit], check=False, quiet=True)


def verify(p, ctx):
    return [("tls cert present", os.path.isfile(CERT) and os.path.isfile(KEY), f"{CERT}, {KEY}")]


ROLE = roles.Role(name="tls", packages=packages, render=render, pre_apply=pre_apply, verify=verify)
