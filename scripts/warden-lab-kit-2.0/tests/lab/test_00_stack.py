"""Stack up: the front serves each site and each microservice answers /health."""
import pytest


@pytest.mark.smoke
def test_portal_home(client, lab):
    assert client.status("/", host=lab.hostname) == 200


@pytest.mark.smoke
def test_each_site_identifies_itself(client, lab):
    for site in lab.p.sites:
        if site == "portal":
            continue
        r = client.get("/lab/info", host=lab.site_host(site))
        assert r.get("codes"), f"{site}: no response"
        assert str(200) in r["codes"], f"{site}: {r['codes']}"


@pytest.mark.smoke
def test_microservices_health(client, lab):
    for svc in lab.p.services:
        code = client.status(f"/svc/{svc}/health", host=lab.hostname)
        assert code == 200, f"svc {svc} health = {code}"


@pytest.mark.smoke
def test_https_serves(client, lab):
    if lab.p.tls.mode == "files" and not lab.p.tls.cert_file:
        pytest.skip("no TLS configured")
    assert client.status("/", host=lab.hostname, tls=True) == 200
