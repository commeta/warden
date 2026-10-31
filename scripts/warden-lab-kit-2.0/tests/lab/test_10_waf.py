"""ModSecurity blocks the classic attacks and records this run's request."""
import pytest
from labkit import modsec

ATTACKS = [
    ("xss", "/lab/xss?q=%3Cscript%3Ealert(1)%3C/script%3E"),
    ("sqli", "/lab/sqli?id=1%20OR%201=1--"),
    ("traversal", "/lab/traversal?file=../../../../etc/passwd"),
    ("rce", "/lab/cmd?x=%3Bcat%20/etc/passwd"),
]


@pytest.mark.waf
@pytest.mark.parametrize("name,path", ATTACKS)
def test_attack_is_blocked(attacker, lab, journal, name, path):
    tag = journal.tag()
    code = attacker.status(f"{path}&t={tag}", host=lab.hostname, src=attacker.new_ipv4())
    assert code == 403, f"{name}: expected 403, got {code}"


@pytest.mark.waf
def test_legit_admin_save_is_not_blocked(client, lab):
    r = client.post("/lab/admin-save", "content=%3Cb%3Ehello%3C/b%3E+and+1%3D1", host=lab.hostname)
    assert "200" in r.get("codes", {}), f"admin save blocked: {r}"


@pytest.mark.waf
def test_modsecurity_recorded_the_request(attacker, lab):
    tag = "wlt" + "0a1b2c3d"
    attacker.get(f"/lab/xss?q=%3Cscript%3E{tag}%3C/script%3E&t={tag}",
                 host=lab.hostname, src=attacker.new_ipv4())
    assert modsec.saw_request(lab.p.waf.mode, tag), "ModSecurity did not record the probe"
