"""Warden counts WAF activity per peer and raises waf_attack with the address."""
import pytest


@pytest.mark.warden
def test_waf_attack_is_counted_per_address(attacker, lab, journal, warden):
    if not warden.available():
        pytest.skip("no Warden")
    ip = attacker.new_ipv4()
    tag = journal.tag()
    for i in range(lab.block_after + 1):
        attacker.get(f"/lab/xss?q=%3Cscript%3E{i}%3C/script%3E&t={tag}", host=lab.hostname, src=ip)
    ev = journal.expect("security.waf_attack", ip=ip, within=15)
    assert ev["details"].get("ip") == ip


@pytest.mark.warden
def test_waf_hit_names_the_site(attacker, lab, journal, warden):
    if not warden.available():
        pytest.skip("no Warden")
    site = next((s for s in lab.p.sites if s != "portal"), "portal")
    tag = journal.tag()
    attacker.get(f"/lab/xss?q=%3Cscript%3E{tag}%3C/script%3E&t={tag}", host=lab.site_host(site))
    ev = journal.expect("waf.hit", within=15)
    assert "site" in ev.get("details", {})
