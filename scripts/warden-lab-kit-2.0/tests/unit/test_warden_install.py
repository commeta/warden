"""Tests for pinned Warden package installation."""
import hashlib
import os
import sys

import pytest

KIT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if KIT not in sys.path:
    sys.path.insert(0, KIT)

from lab.roles import warden  # noqa: E402
from lab.util import LabError, Result  # noqa: E402


def test_release_url_uses_actual_release_tag():
    assert warden.release_url("0.14.3") == (
        "https://github.com/commeta/warden/releases/download/0.14.3/"
        "warden_0.14.3-1_amd64.deb"
    )


def test_bad_package_checksum_is_refused_before_apt(tmp_path, monkeypatch):
    package = tmp_path / "warden.deb"
    package.write_bytes(b"not really a deb, checksum test only")
    calls = []
    monkeypatch.setattr(warden, "run", lambda args, **kwargs: calls.append(args) or Result(0, "", ""))
    with pytest.raises(LabError, match="refusing to install"):
        warden._install_deb(str(package), "0" * 64)
    assert calls == []


def test_pinned_package_checksum_is_required(tmp_path, monkeypatch):
    package = tmp_path / "warden.deb"
    package.write_bytes(b"test package bytes")
    calls = []
    monkeypatch.setattr(warden, "run", lambda args, **kwargs: calls.append((args, kwargs)) or Result(0, "", ""))
    with pytest.raises(LabError, match="pinned 64-character"):
        warden._install_deb(str(package), "")
    assert calls == []


def test_valid_checksum_installs_local_package_noninteractive(tmp_path, monkeypatch):
    package = tmp_path / "warden.deb"
    package.write_bytes(b"test package bytes")
    checksum = hashlib.sha256(package.read_bytes()).hexdigest()
    calls = []
    monkeypatch.setattr(warden, "run", lambda args, **kwargs: calls.append((args, kwargs)) or Result(0, "", ""))
    warden._install_deb(str(package), checksum)
    assert calls[0][0] == ["apt-get", "install", "-y", "--no-install-recommends", str(package)]
    assert calls[0][1]["env"]["DEBIAN_FRONTEND"] == "noninteractive"
