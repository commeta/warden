"""Service restart failures must not be reported as successful applies."""
import os
import sys

import pytest

KIT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if KIT not in sys.path:
    sys.path.insert(0, KIT)

from lab import manifest  # noqa: E402
from lab.util import LabError, Result  # noqa: E402


def test_restart_prioritizes_firewall_before_front(monkeypatch):
    calls = []
    monkeypatch.setattr(manifest.shutil, "which", lambda name: "/usr/bin/systemctl")

    def fake_run(args, **kwargs):
        calls.append(args[-1])
        return Result(0, "", "")

    monkeypatch.setattr(manifest, "run", fake_run)
    assert manifest._restart({"nginx.service", "warden-lab-nftables.service"}) == [
        "warden-lab-nftables.service", "nginx.service"
    ]
    assert calls == ["warden-lab-nftables.service", "nginx.service"]


def test_restart_failure_is_fatal(monkeypatch):
    monkeypatch.setattr(manifest.shutil, "which", lambda name: "/usr/bin/systemctl")

    def fake_run(args, **kwargs):
        raise LabError("command failed (1): systemctl restart nginx.service\nfailed")

    monkeypatch.setattr(manifest, "run", fake_run)
    with pytest.raises(LabError, match="restart nginx.service failed"):
        manifest._restart({"nginx.service"})


def test_manifest_persists_pending_restarts_for_retry(tmp_path, monkeypatch):
    monkeypatch.setattr(manifest, "STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(manifest, "STATE_FILE", str(tmp_path / "state" / "state.json"))
    state = manifest.Manifest("lan-test")
    state.pending_restarts = ["nginx.service", "warden-lab-nftables.service"]
    state.save()

    loaded = manifest.Manifest.load()
    assert loaded.profile == "lan-test"
    assert loaded.pending_restarts == ["nginx.service", "warden-lab-nftables.service"]


def test_failed_validation_does_not_make_next_apply_displace_kit_file(tmp_path, monkeypatch):
    import grp
    import pwd
    from lab.render import FileSpec, Plan

    state_dir = tmp_path / "state"
    monkeypatch.setattr(manifest, "STATE_DIR", str(state_dir))
    monkeypatch.setattr(manifest, "STATE_FILE", str(state_dir / "state.json"))
    monkeypatch.setattr(manifest.shutil, "which", lambda name: "/usr/bin/systemctl")
    monkeypatch.setattr(manifest, "_chown", lambda path, owner, group: None)

    owner = pwd.getpwuid(os.geteuid()).pw_name
    group = grp.getgrgid(os.getegid()).gr_name
    config = tmp_path / "nginx.conf"
    spec = FileSpec(
        str(config), "valid on retry\n", owner, group, 0o640, "front",
        validate=("fake-configtest",), restart=("nginx.service",),
    )
    plan = Plan()
    plan.files.append(spec)
    calls = []
    fail_validation_once = {"yes": True}

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[0] == "fake-configtest" and fail_validation_once["yes"]:
            fail_validation_once["yes"] = False
            raise LabError("simulated config validation failure")
        return Result(0, "", "")

    monkeypatch.setattr(manifest, "run", fake_run)
    with pytest.raises(LabError, match="simulated config validation failure"):
        manifest.apply(plan, "retry-test")

    loaded = manifest.Manifest.load()
    assert str(config) in loaded.entries
    assert loaded.pending_restarts == ["nginx.service"]
    assert config.read_text() == "valid on retry\n"

    def no_displace(_path):
        raise AssertionError("Kit-owned file must not be displaced on retry")

    monkeypatch.setattr(manifest, "_displace", no_displace)
    result = manifest.apply(plan, "retry-test")
    assert result.unchanged == 1
    assert result.restarted == ["nginx.service"]
    assert manifest.Manifest.load().pending_restarts == []
    assert config.read_text() == "valid on retry\n"
