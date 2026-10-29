"""Unit tests for the render engine and the manifest's dry-run plan."""
import os
import sys

KIT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if KIT not in sys.path:
    sys.path.insert(0, KIT)

from lab.render import render_string  # noqa: E402


def test_token_substitution():
    assert render_string("a @X@ b", {"X": "1"}) == "a 1 b"


def test_literal_at_escape():
    # @@ becomes a literal @ (nft set references survive)
    assert render_string("update @@blocklist { }", {}) == "update @blocklist { }"


def test_missing_token_is_error():
    import pytest

    from lab.util import LabError
    with pytest.raises(LabError):
        render_string("@MISSING@", {})


def test_plans_render_for_all_profiles():
    from lab import profile as P
    from lab import roles
    from lab.render import Plan
    from lab.roles import Ctx
    for name in ("ci-nginx-modsec3", "apache-modsec2", "full", "production-external"):
        p = P.load(os.path.join(KIT, "profiles", f"{name}.toml"))
        ctx = Ctx(p, KIT)
        plan = Plan()
        for r in roles.active_roles(p):
            plan.extend(r.render(p, ctx))
        assert plan.files, f"{name}: no files rendered"
        # the Warden drop-in must be valid TOML
        import tomllib
        generated_warden = tomllib.loads(ctx.get("warden_dropin"))
        assert generated_warden["daemon"]["dry_run"] is (not p.warden.enforce)



def test_lan_firewall_only_allows_trusted_cidrs(tmp_path):
    from lab import profile as P
    from lab.roles import Ctx
    from lab.roles import net as netrole

    body = """[lab]
name = "lan-test"
front = "nginx"
sites = ["portal"]
services = []
[net]
mode = "lan"
external_iface = "enp0s3"
trusted = ["192.168.1.25/32", "fd00::/64"]
[waf]
engine = "modsec3"
mode = "serial-native"
[crs]
source = "package"
[warden]
source = "none"
"""
    f = tmp_path / "lab.toml"
    f.write_text(body)
    p = P.load(str(f))
    ctx = Ctx(p, KIT)
    plan = netrole.render(p, ctx)
    content = next(x.content.decode() for x in plan.files if x.path == "/etc/warden-lab/lab_filter.nft")
    assert 'iifname "enp0s3" ip saddr { 192.168.1.25/32 } tcp dport { 80, 443 } accept' in content
    assert 'iifname "enp0s3" ip6 saddr { fd00::/64 } tcp dport { 80, 443 } accept' in content
    assert 'tcp dport { 80, 443 } iifname != "lo" iifname != "vh-*" drop' in content
    assert 'tcp dport { 8080 } iifname != "lo" iifname != "vh-*" drop' in content
    assert 'tcp dport { 3100-3199 } iifname != "lo" iifname != "vh-*" drop' in content
    # The trusted allow comes first, then every non-trusted external source is
    # dropped before the generic established-session accept.
    assert content.index('ip saddr { 192.168.1.25/32 }') < content.index('tcp dport { 80, 443 } iifname !=')
    assert content.index('tcp dport { 80, 443 } iifname !=') < content.index('ct state established,related accept')


def test_external_firewall_limits_front_to_selected_nic_and_hides_backend(tmp_path):
    from lab import profile as P
    from lab.roles import Ctx
    from lab.roles import net as netrole

    body = """[lab]
name = "external-test"
front = "nginx"
sites = ["portal"]
services = []
[net]
mode = "external"
external_iface = "enp0s8"
trusted = ["192.168.1.25/32"]
[waf]
engine = "modsec3"
mode = "serial-native"
[crs]
source = "package"
[warden]
source = "none"
"""
    f = tmp_path / "lab.toml"
    f.write_text(body)
    p = P.load(str(f))
    ctx = Ctx(p, KIT)
    plan = netrole.render(p, ctx)
    content = next(x.content.decode() for x in plan.files if x.path == "/etc/warden-lab/lab_filter.nft")
    assert 'tcp dport { 80, 443 } iifname != "enp0s8" drop' in content
    assert 'tcp dport { 8080 } iifname != "lo" iifname != "vh-*" drop' in content
    assert 'tcp dport { 3100-3199 } iifname != "lo" iifname != "vh-*" drop' in content
    assert content.index('tcp dport { 80, 443 } iifname !=') < content.index('ct state established,related accept')


def test_warden_release_url_uses_actual_tag_without_v_prefix():
    from lab.roles.warden import release_url
    assert release_url("0.14.3") == (
        "https://github.com/commeta/warden/releases/download/0.14.3/"
        "warden_0.14.3-1_amd64.deb"
    )


def test_base_role_declares_host_and_test_dependencies():
    from lab import profile as P
    from lab.roles import Ctx
    from lab.roles import base
    p = P.load(os.path.join(KIT, "profiles", "ci-nginx-modsec3.toml"))
    pkgs = base.packages(p)
    assert {"curl", "ca-certificates", "iproute2", "nftables", "openssl", "python3-pytest"}.issubset(set(pkgs))


def test_lan_test_endpoints_use_loopback_but_front_binds_external():
    from lab import profile as P
    from lab.net import resolve
    from lab.roles import Ctx

    p = P.Profile(name="lan", front="nginx")
    p.net.mode = "lan"
    p.net.external_iface = "enp0s8"
    p.net.trusted = ["192.168.56.1/32"]
    ep = resolve(p)
    assert ep.front_bind == "0.0.0.0"
    assert ep.cli_v4 == "127.0.0.1"
    assert ep.atk_v4_range == "127.0.0.2/32"
    assert "192.168.56.1/32" in ep.trusted


def test_tls_files_mode_replaces_acme_symlinks_without_writing_through_them(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import lab.roles.tls as tls

    tls_dir = tmp_path / "tls"
    tls_dir.mkdir()
    letsencrypt_dir = tmp_path / "letsencrypt"
    letsencrypt_dir.mkdir()
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    le_cert = letsencrypt_dir / "fullchain.pem"
    le_key = letsencrypt_dir / "privkey.pem"
    le_cert.write_text("letsencrypt-cert")
    le_key.write_text("letsencrypt-key")
    cert_src = source_dir / "fullchain.pem"
    key_src = source_dir / "privkey.pem"
    cert_src.write_text("imported-cert")
    key_src.write_text("imported-key")
    cert_dst = tls_dir / "fullchain.pem"
    key_dst = tls_dir / "privkey.pem"
    cert_dst.symlink_to(le_cert)
    key_dst.symlink_to(le_key)

    monkeypatch.setattr(tls, "TLS_DIR", str(tls_dir))
    monkeypatch.setattr(tls, "CERT", str(cert_dst))
    monkeypatch.setattr(tls, "KEY", str(key_dst))
    monkeypatch.setattr(tls, "_validate_pair", lambda cert, key: None)
    monkeypatch.setattr(tls, "_validate_names", lambda p, cert: None)
    p = SimpleNamespace(tls=SimpleNamespace(cert_file=str(cert_src), key_file=str(key_src)), sites=[], hostname="lab.local")

    tls._install_files(p)

    assert not cert_dst.is_symlink()
    assert not key_dst.is_symlink()
    assert cert_dst.read_text() == "imported-cert"
    assert key_dst.read_text() == "imported-key"
    assert le_cert.read_text() == "letsencrypt-cert"
    assert le_key.read_text() == "letsencrypt-key"


def test_firewall_templates_are_idempotent_and_only_destroy_kit_table():
    from pathlib import Path

    root = Path(KIT) / "templates" / "net"
    for name in ("lab_filter_local.nft", "lab_filter_lan.nft", "lab_filter_external.nft"):
        content = (root / name).read_text()
        assert "destroy table inet lab_filter" in content
        assert content.index("destroy table inet lab_filter") < content.index("table inet lab_filter {")
        assert "flush ruleset" not in content
        assert "destroy table inet warden" not in content
