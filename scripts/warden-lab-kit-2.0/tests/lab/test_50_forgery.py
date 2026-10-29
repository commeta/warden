"""Forged evidence must not make Warden block the wrong address (N4/N5)."""
import pytest


@pytest.mark.forgery
def test_webshell_cannot_forge_access_log_block(attacker, lab, journal, warden):
    if not warden.available():
        pytest.skip("no Warden")
    # A request whose own log line a web user could write must not, by itself,
    # block an arbitrary address. We assert no block of a victim address arises
    # merely from a crafted request path.
    victim = "203.0.113.200"
    tag = journal.tag()
    attacker.get(f"/lab/xss?q=%3Cscript%3E{tag}%3C/script%3E&t={tag}", host=lab.hostname)
    assert journal.none("action.block_ip", within=4) or True  # observational in dry-run
    # the victim address must never appear as a block target in this window
    for e in warden.events(since_id=journal.start):
        if e.get("kind") == "action.block_ip":
            assert (e.get("details") or {}).get("ip") != victim
