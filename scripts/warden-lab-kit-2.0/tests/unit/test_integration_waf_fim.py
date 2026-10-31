from __future__ import annotations

import json
import os
import pwd
import tomllib
from pathlib import Path
from types import SimpleNamespace

import pytest

from lab.profile import load
from lab.roles import app_php, front, svc, waf, warden
from lab.roles import Ctx
from tests.lab.labkit.http import Client
from lab.net import resolve

KIT = Path(__file__).resolve().parents[2]
CI_PROFILE = KIT / "profiles" / "ci-nginx-modsec3.toml"
APACHE_PROFILE = KIT / "profiles" / "apache-modsec2.toml"


def _render_stack(mode: str = "serial-json", profile_path: Path = CI_PROFILE):
    p = load(str(profile_path))
    p.waf.mode = mode
    ctx = Ctx(p, str(KIT))
    plan = waf.render(p, ctx)
    plan.extend(front.render(p, ctx))
    plan.extend(app_php.render(p, ctx))
    plan.extend(svc.render(p, ctx))
    plan.extend(warden.render(p, ctx))
    return p, ctx, plan


def _file_content(plan, path: str) -> str:
    spec = next(item for item in plan.files if item.path == path)
    data = spec.content
    return data.decode() if isinstance(data, bytes) else data


@pytest.mark.parametrize(
    ("mode", "fmt"),
    [("serial-json", "json"), ("serial-native", "native"), ("per-site", "native")],
)
def test_serial_waf_logs_are_bound_to_virtual_hosts(mode: str, fmt: str):
    _p, ctx, plan = _render_stack(mode)

    logs = ctx.get("waf_logs")
    assert logs == [
        {"path": f"/var/log/warden-lab/modsec/sites/{site}/audit.log",
         "format": fmt, "site": site}
        for site in ("portal", "wordpress", "opencart")
    ]

    nginx = _file_content(plan, "/etc/nginx/conf.d/warden-lab.conf")
    for site in ("portal", "wordpress", "opencart"):
        assert (
            f"modsecurity_rules 'SecAuditLog "
            f"/var/log/warden-lab/modsec/sites/{site}/audit.log';"
        ) in nginx

    dropin = _file_content(plan, "/etc/warden/conf.d/60-warden-lab.toml")
    tomllib.loads(dropin)
    for site in ("portal", "wordpress", "opencart"):
        assert f'path = "/var/log/warden-lab/modsec/sites/{site}/audit.log"' in dropin
        assert f'site = "{site}"' in dropin
    assert 'format = "' + fmt + '"' in dropin
    assert "sites/*/audit.log" not in dropin
    assert "trust_writable_logs = false" in dropin



@pytest.mark.parametrize("mode", ["concurrent-index", "concurrent-noindex"])
def test_concurrent_waf_logs_are_bound_to_virtual_hosts(mode: str):
    _p, ctx, plan = _render_stack(mode)
    logs = ctx.get("waf_logs")
    dropin = _file_content(plan, "/etc/warden/conf.d/60-warden-lab.toml")
    tomllib.loads(dropin)
    assert len(logs) == 3
    for site in ("portal", "wordpress", "opencart"):
        nginx = _file_content(plan, "/etc/nginx/conf.d/warden-lab.conf")
        assert f"SecAuditLog /var/log/warden-lab/modsec/sites/{site}/index" in nginx
        assert f"SecAuditLogStorageDir /var/log/warden-lab/modsec/sites/{site}/data" in nginx
        matches = [entry for entry in logs if entry.get("site") == site]
        assert len(matches) == 1
        if mode == "concurrent-index":
            assert matches[0]["path"] == f"/var/log/warden-lab/modsec/sites/{site}/index"
            assert matches[0]["storage_dir"] == f"/var/log/warden-lab/modsec/sites/{site}/data"
        else:
            assert matches[0]["path"] == f"/var/log/warden-lab/modsec/sites/{site}/data"
            assert "storage_dir" not in matches[0]


def test_error_log_mode_registers_all_vhost_error_logs():
    _p, ctx, plan = _render_stack("error-log")
    assert ctx.get("waf_logs") == [
        {"path": f"/var/log/warden-lab/nginx/{site}.error.log",
         "format": "error_log", "site": site}
        for site in ("portal", "wordpress", "opencart")
    ]
    dropin = _file_content(plan, "/etc/warden/conf.d/60-warden-lab.toml")
    tomllib.loads(dropin)
    for site in ("portal", "wordpress", "opencart"):
        assert f'path = "/var/log/warden-lab/nginx/{site}.error.log"' in dropin
        assert f'site = "{site}"' in dropin



@pytest.mark.parametrize("mode", ["serial-native", "concurrent-index", "concurrent-noindex"])
def test_apache_audit_configuration_is_bound_to_each_vhost(mode: str):
    _p, ctx, plan = _render_stack(mode, profile_path=APACHE_PROFILE)
    conf = _file_content(plan, "/etc/apache2/conf-enabled/warden-lab.conf")
    for site in ("portal", "wordpress", "modx"):
        assert f"SecAuditLog /var/log/warden-lab/modsec/sites/{site}/" in conf
        if mode in {"concurrent-index", "concurrent-noindex"}:
            assert (
                f"SecAuditLogStorageDir /var/log/warden-lab/modsec/sites/{site}/data"
            ) in conf
    logs = ctx.get("waf_logs")
    assert all(entry.get("site") for entry in logs)

def test_microservices_are_registered_as_fim_sites():
    _p, ctx, plan = _render_stack()
    fim = {item["name"]: item for item in ctx.get("fim_sites")}

    for service, unit in (
        ("php-fpm", "php8.3-fpm.service"),
        ("node", "warden-lab-svc-node.service"),
        ("python-asgi", "warden-lab-svc-python-asgi.service"),
    ):
        entry = fim[f"svc-{service}"]
        assert entry["root"] == f"/var/www/warden-lab/services/{service}"
        assert entry["no_scripts"] == ["uploads/**"]
        assert "uploads/*.php" in entry["include"]
        assert "uploads/**/*.php" in entry["include"]
        assert entry["access_log"] == "/var/log/warden-lab/nginx/portal.access.log"
        assert entry["restart_unit"] == unit

    dropin = _file_content(plan, "/etc/warden/conf.d/60-warden-lab.toml")
    for name in ("svc-php-fpm", "svc-node", "svc-python-asgi"):
        assert f'name = "{name}"' in dropin


def test_synthetic_webshell_signature_filters_by_basename():
    signature = (KIT / "templates/warden/lab-signatures.toml").read_text()
    for extension in ("php", "phtml", "pht", "phar", "txt"):
        assert f'"*.{extension}"' in signature
        assert f'"**/*.{extension}"' not in signature
    assert "@MARKER@_[A-Z0-9]{8}" in signature


def test_all_fim_sites_render_explicit_upload_script_coverage():
    _p, ctx, plan = _render_stack()
    dropin = _file_content(plan, "/etc/warden/conf.d/60-warden-lab.toml")
    parsed = tomllib.loads(dropin)
    fim_sites = parsed["fim"]["site"]
    assert fim_sites
    for entry in fim_sites:
        include = entry["include"]
        for pattern in (
            "uploads/*.php", "uploads/**/*.php",
            "uploads/*.php[0-9]", "uploads/**/*.php[0-9]",
            "uploads/*.phtml", "uploads/**/*.phtml",
            "uploads/*.pht", "uploads/**/*.pht",
            "uploads/*.phar", "uploads/**/*.phar",
        ):
            assert pattern in include, (entry["name"], pattern)
        assert entry["no_scripts"] == ["uploads/**"]
    assert parsed["waf"]["trust_writable_logs"] is False


def test_fim_upload_bridge_is_rendered_and_covers_each_site():
    _p, ctx, plan = _render_stack()
    config = _file_content(plan, "/etc/warden-lab/fim-bridge.json")
    parsed = json.loads(config)
    expected = [
        {"name": entry["name"], "upload_root": entry["root"] + "/uploads"}
        for entry in ctx.get("fim_sites")
    ]
    assert parsed["sites"] == expected
    assert parsed["debounce_seconds"] == 0.8
    assert parsed["min_scan_interval_seconds"] == 3.0
    unit = _file_content(plan, "/etc/systemd/system/warden-lab-fim-bridge.service")
    assert "After=wardend.service" in unit
    assert "Requires=wardend.service" in unit
    assert "ProtectSystem=strict" in unit
    assert "NoNewPrivileges=yes" in unit
    assert "CapabilityBoundingSet=CAP_DAC_READ_SEARCH" in unit
    assert "AmbientCapabilities=CAP_DAC_READ_SEARCH" in unit
    script = _file_content(plan, "/usr/local/libexec/warden-lab-fim-bridge.py")
    assert "inotify_init1" in script
    assert '"fim", "scan", site' in script


def test_php_fpm_upload_endpoint_does_not_report_failed_writes_as_success():
    source = (KIT / "services/php-fpm/public/index.php").read_text()
    assert "$written = @file_put_contents(" in source
    assert "$written === false || $written !== strlen($payload)" in source
    assert "http_response_code(500); echo 'upload write failed'" in source


def test_service_code_is_root_owned_and_only_data_uploads_are_mutable(tmp_path, monkeypatch):
    root = tmp_path / "node"
    (root / "uploads").mkdir(parents=True)
    (root / "data").mkdir()
    (root / "nested").mkdir()
    (root / "server.js").write_text("console.log('ok')")
    (root / "nested" / "module.js").write_text("module.exports = 1")
    (root / "uploads" / "shell.php").write_text("test marker")
    (root / "data" / "items.sqlite").write_bytes(b"sqlite")

    fake_user = SimpleNamespace(pw_uid=2201, pw_gid=2202)
    monkeypatch.setattr(pwd, "getpwnam", lambda _name: fake_user)
    ownership: dict[str, tuple[int, int]] = {}
    modes: dict[str, int] = {}

    def fake_chown(path, uid, gid, **kwargs):
        ownership[os.fspath(path)] = (uid, gid)

    def fake_chmod(path, mode, **kwargs):
        modes[os.fspath(path)] = mode

    monkeypatch.setattr(os, "chown", fake_chown)
    monkeypatch.setattr(os, "chmod", fake_chmod)

    svc._own(str(root), "labsvc-node")

    code = os.fspath(root / "server.js")
    nested_code = os.fspath(root / "nested" / "module.js")
    upload = os.fspath(root / "uploads" / "shell.php")
    database = os.fspath(root / "data" / "items.sqlite")

    assert ownership[code] == (0, 2202)
    assert ownership[nested_code] == (0, 2202)
    assert modes[code] == 0o640
    assert modes[nested_code] == 0o640

    assert ownership[upload] == (2201, 2202)
    assert ownership[database] == (2201, 2202)
    assert modes[upload] == 0o640
    assert modes[database] == 0o640

    # Runtime user has directory traversal/read access but no write bit in code.
    assert modes[os.fspath(root)] == 0o750
    assert modes[os.fspath(root / "nested")] == 0o750
    assert modes[os.fspath(root / "uploads")] == 0o750
    assert modes[os.fspath(root / "data")] == 0o750


def test_loopback_and_lan_attacker_sources_are_unique():
    p = load(str(CI_PROFILE))
    client_a = Client(p, resolve(p), ns=None, role="attacker")
    client_b = Client(p, resolve(p), ns=None, role="attacker")
    first = client_a.new_ipv4()
    second = client_b.new_ipv4()
    assert first.startswith("127.")
    assert second.startswith("127.")
    assert first != second


def test_serial_waf_post_apply_creates_and_owns_each_vhost_log(tmp_path, monkeypatch):
    import grp
    import pwd
    from types import SimpleNamespace

    p, ctx, _plan = _render_stack("serial-json")
    site_root = tmp_path / "sites"
    ctx.set("waf_audit", {
        **ctx.get("waf_audit"),
        "dir": str(site_root),
    })
    monkeypatch.setattr(waf, "AUD", str(tmp_path))
    monkeypatch.setattr(pwd, "getpwnam", lambda _name: SimpleNamespace(pw_uid=1001, pw_gid=1001))
    monkeypatch.setattr(grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=4))
    monkeypatch.setattr(os, "chown", lambda *args, **kwargs: None)
    monkeypatch.setattr(os, "chmod", lambda *args, **kwargs: None)

    waf.post_apply(p, ctx)

    for site in p.sites:
        assert (site_root / site / "audit.log").is_file()



@pytest.mark.parametrize("mode", ["concurrent-index", "concurrent-noindex"])
def test_concurrent_waf_post_apply_creates_per_vhost_storage(tmp_path, monkeypatch, mode):
    import grp
    import pwd
    from types import SimpleNamespace

    p, ctx, _plan = _render_stack(mode)
    site_root = tmp_path / "sites"
    ctx.set("waf_audit", {**ctx.get("waf_audit"), "dir": str(site_root)})
    monkeypatch.setattr(waf, "AUD", str(tmp_path))
    monkeypatch.setattr(pwd, "getpwnam", lambda _name: SimpleNamespace(pw_uid=1001, pw_gid=1001))
    monkeypatch.setattr(grp, "getgrnam", lambda _name: SimpleNamespace(gr_gid=4))
    monkeypatch.setattr(os, "chown", lambda *args, **kwargs: None)
    monkeypatch.setattr(os, "chmod", lambda *args, **kwargs: None)

    waf.post_apply(p, ctx)

    for site in p.sites:
        assert (site_root / site / "index").is_file()
        assert (site_root / site / "data").is_dir()


def test_labctl_test_forwards_pytest_output(monkeypatch, capsys):
    from types import SimpleNamespace
    from lab import cli
    from lab.util import Result

    monkeypatch.setattr(cli, "_load", lambda _args: object())
    monkeypatch.setattr(cli, "have", lambda _name: True)
    monkeypatch.setattr(cli, "run", lambda *args, **kwargs: Result(1, "2 failed\n", "pytest stderr\n"))
    args = SimpleNamespace(profile="/tmp/lab.toml", enforce=False, markers=None, k=None)

    assert cli.cmd_test(args) == 1
    output = capsys.readouterr()
    assert "2 failed" in output.out
    assert "pytest stderr" in output.err


def test_php_fpm_service_pool_uses_its_primary_group():
    _p, _ctx, plan = _render_stack()
    pool = _file_content(plan, "/etc/php/8.3/fpm/pool.d/lab-svc-php-fpm.conf")
    assert "user = labsvc-php-fpm" in pool
    assert "group = labsvc-php-fpm" in pool
    # Nginx still reaches the FastCGI socket through the web-server group.
    assert "listen.group = www-data" in pool


def test_waf_verify_checks_each_virtual_host_log(tmp_path, monkeypatch):
    p, ctx, _plan = _render_stack("serial-json")
    modsec_dir = tmp_path / "modsec"
    modsec_dir.mkdir()
    (modsec_dir / "main.conf").write_text("# test")
    site_root = tmp_path / "sites"
    for site in p.sites:
        site_dir = site_root / site
        site_dir.mkdir(parents=True)
        (site_dir / "audit.log").write_text("")
    monkeypatch.setattr(waf, "MODSEC_DIR", str(modsec_dir))
    ctx.set("waf_audit", {**ctx.get("waf_audit"), "dir": str(site_root)})

    checks = waf.verify(p, ctx)
    assert checks[0][1] is True
    assert len(checks) == 1 + len(p.sites)
    assert all(ok for _name, ok, _detail in checks)
