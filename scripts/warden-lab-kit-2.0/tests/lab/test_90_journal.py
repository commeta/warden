"""The whole window has no unexpected events or false positives."""
import pytest


@pytest.mark.warden
def test_window_is_quiet_apart_from_expected(client, lab, journal, warden):
    if not warden.available():
        pytest.skip("no Warden")
    # a handful of benign requests
    client.get("/", host=lab.hostname)
    client.get("/lab/xss?q=hello", host=lab.hostname)
    journal.assert_quiet(allowed={
        "waf.hit", "security.waf_attack", "action.block_ip",
        "auth.login", "health.ok",
    })
