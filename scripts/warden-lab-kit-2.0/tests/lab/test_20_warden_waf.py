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
    # A unique peer avoids Warden's intentional <=1 waf.hit/minute dedup for
    # a peer, while the URI tag ensures this event belongs to this test.
    src = attacker.new_ipv4()
    attacker.get(f"/lab/xss?q=%3Cscript%3E{tag}%3C/script%3E&t={tag}",
                 host=lab.site_host(site), src=src)
    ev = journal.expect("waf.hit", uri_contains=tag, within=15)
    assert ev.get("details", {}).get("site") == site, ev
