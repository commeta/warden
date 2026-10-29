"""Unit tests for labctl's profile loading and compatibility matrix.

These run anywhere (no root, no stand): they are the CI gate for the kit's
own logic.
"""
import os
import sys

import pytest

KIT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if KIT not in sys.path:
    sys.path.insert(0, KIT)

from lab import profile as P  # noqa: E402
from lab.util import LabError  # noqa: E402


def _write(tmp_path, body):
    f = tmp_path / "lab.toml"
    f.write_text(body)
    return str(f)


BASE = """
[lab]
name = "t"
front = "nginx"
sites = ["portal"]
services = []
[waf]
engine = "modsec3"
mode = "serial-native"
[crs]
source = "package"
[warden]
source = "none"
"""


def test_loads_minimal(tmp_path):
    p = P.load(_write(tmp_path, BASE))
    assert p.front == "nginx"
    assert p.waf.engine == "modsec3"


def test_apache_cannot_carry_modsec3(tmp_path):
    body = BASE.replace('front = "nginx"', 'front = "apache-prefork"')
    with pytest.raises(LabError):
        P.load(_write(tmp_path, body))


def test_services_require_waf(tmp_path):
    body = BASE.replace('services = []', 'services = ["node"]').replace('engine = "modsec3"', 'engine = "none"')
    with pytest.raises(LabError):
        P.load(_write(tmp_path, body))


def test_edge_front_requires_modsec3(tmp_path):
    body = BASE.replace('front = "nginx"', 'front = "haproxy"').replace('engine = "modsec3"', 'engine = "modsec2"')
    with pytest.raises(LabError):
        P.load(_write(tmp_path, body))


def test_external_needs_iface_and_trusted(tmp_path):
    body = BASE + '\n[net]\nmode = "external"\n'
    with pytest.raises(LabError):
        P.load(_write(tmp_path, body))


def test_lan_needs_iface_and_trusted(tmp_path):
    body = BASE + '\n[net]\nmode = "lan"\n'
    with pytest.raises(LabError):
        P.load(_write(tmp_path, body))


def test_lan_mode_loads_with_allowlist(tmp_path):
    body = BASE + '\n[net]\nmode = "lan"\nexternal_iface = "enp0s3"\ntrusted = ["192.168.1.25/32", "fd00::/64"]\n'
    p = P.load(_write(tmp_path, body))
    assert p.net.mode == "lan"
    assert p.net.external_iface == "enp0s3"
    assert p.net.trusted == ["192.168.1.25/32", "fd00::/64"]


def test_lan_rejects_invalid_trusted_cidr(tmp_path):
    body = BASE + '\n[net]\nmode = "lan"\nexternal_iface = "enp0s3"\ntrusted = ["not-a-network"]\n'
    with pytest.raises(LabError):
        P.load(_write(tmp_path, body))


def test_crs_4x_needs_pin(tmp_path):
    body = BASE.replace('source = "package"', 'source = "4.x"\nref = "v4.18.0"')
    with pytest.raises(LabError):
        P.load(_write(tmp_path, body))


def test_set_override(tmp_path):
    p = P.load(_write(tmp_path, BASE), ["waf.mode=serial-json"])
    assert p.waf.mode == "serial-json"


def test_all_waf_modes_valid(tmp_path):
    for mode in P.WAF_MODES:
        p = P.load(_write(tmp_path, BASE), [f"waf.mode={mode}"])
        assert p.waf.mode == mode


def test_warden_is_default_and_pinned_when_section_omitted(tmp_path):
    body = BASE.replace('[warden]\nsource = "none"\n', '')
    p = P.load(_write(tmp_path, body))
    assert p.warden.source == "release"
    assert p.warden.version == "0.14.3"
    assert p.warden.sha256 == "acc3e47112307cacdf4e025570f99e0afcc4131cf9e5395b554daaf68bc5470c"
    assert p.warden.enforce is False


def test_bad_internal_cidr_fails_with_profile_error_not_traceback(tmp_path):
    body = BASE + '\n[net]\nv4_cidr = "192.168.56.110/24"\n'
    with pytest.raises(LabError, match=r"net.v4_cidr.*192.168.56.0/24"):
        P.load(_write(tmp_path, body))


def test_tls_files_requires_both_paths(tmp_path):
    body = BASE + '\n[tls]\nmode = "files"\ncert_file = "/tmp/cert.pem"\n'
    with pytest.raises(LabError, match="requires both tls.cert_file and tls.key_file"):
        P.load(_write(tmp_path, body))


def test_tls_acme_requires_domains(tmp_path):
    body = BASE + '\n[tls]\nmode = "acme"\n'
    with pytest.raises(LabError, match="requires at least one public DNS name"):
        P.load(_write(tmp_path, body))


def test_tls_rejects_invalid_dns_name(tmp_path):
    body = BASE.replace('name = "t"', 'name = "t"') + '\n[tls]\nmode = "self-signed"\ndomains = ["bad domain.example"]\n'
    with pytest.raises(LabError, match="invalid TLS DNS name"):
        P.load(_write(tmp_path, body))


def test_wildcard_trusted_network_is_rejected_for_lan(tmp_path):
    body = BASE + '\n[net]\nmode = "lan"\nexternal_iface = "enp0s3"\ntrusted = ["0.0.0.0/0"]\n'
    with pytest.raises(LabError, match="must not contain 0.0.0.0/0"):
        P.load(_write(tmp_path, body))
