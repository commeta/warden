"""Tests for safe package/service orchestration helpers."""
import os
import sys

KIT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if KIT not in sys.path:
    sys.path.insert(0, KIT)

from lab import util  # noqa: E402


def test_defer_service_starts_creates_and_removes_own_policy(tmp_path):
    policy = tmp_path / "policy-rc.d"
    with util.defer_service_starts(str(policy)):
        assert policy.exists()
        assert policy.read_text().endswith("exit 101\n")
        assert os.access(policy, os.X_OK)
    assert not policy.exists()


def test_defer_service_starts_preserves_existing_admin_policy(tmp_path):
    policy = tmp_path / "policy-rc.d"
    policy.write_text("#!/bin/sh\nexit 0\n")
    policy.chmod(0o755)
    with util.defer_service_starts(str(policy)):
        assert policy.read_text() == "#!/bin/sh\nexit 0\n"
    assert policy.read_text() == "#!/bin/sh\nexit 0\n"


def test_defer_service_starts_removes_own_policy_on_exception(tmp_path):
    policy = tmp_path / "policy-rc.d"
    try:
        with util.defer_service_starts(str(policy)):
            raise RuntimeError("simulated apt failure")
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected simulated error")
    assert not policy.exists()
