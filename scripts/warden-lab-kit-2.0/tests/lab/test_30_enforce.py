"""A real block from the attacker; the trusted client keeps working (enforce)."""
import pytest


@pytest.mark.enforce
def test_block_then_unblock(attacker, client, lab, journal, warden, enforce):
    with enforce() as used:
        ip = attacker.new_ipv4()
        used.append(ip)
        tag = journal.tag()
        for i in range(lab.block_after + 2):
            attacker.get(f"/lab/xss?q=%3Cscript%3E{i}%3C/script%3E&t={tag}", host=lab.hostname, src=ip)
        journal.expect("action.block_ip", ip=ip, within=20)
        # the trusted client is unaffected
        assert client.status("/", host=lab.hostname) == 200
