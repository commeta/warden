"""An IPv6 attacker rotating addresses inside one /64 is one source (N25)."""
import pytest


@pytest.mark.ipv6
@pytest.mark.warden
def test_rotation_in_one_64_is_one_block(attacker, lab, journal, warden):
    if lab.p.net.mode in {"loopback", "lan"}:
        pytest.skip("IPv6 rotation needs the netns/external attack namespace")
    if not warden.available():
        pytest.skip("no Warden")
    tag = journal.tag()
    for i in range(20):
        src = attacker.new_ipv6_in_prefix()
        attacker.get(f"/lab/xss?q=%3Cscript%3E{i}%3C/script%3E&t={tag}", host=lab.hostname, src=src)
    ev = journal.expect("security.waf_attack", within=20)
    assert "/" in ev["details"].get("prefix", ""), "expected a /64 prefix in the event"
