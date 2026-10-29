"""A webshell dropped into uploads is detected; its access is correlated."""
import pytest


@pytest.mark.fim
def test_webshell_upload_is_detected(attacker, lab, journal, warden):
    if not warden.available():
        pytest.skip("no Warden")
    marker = "WARDEN_LAB_WEBSHELL_MARKER_" + "AB12CD34"
    svc = next((s for s in lab.p.services if s in ("node", "php-fpm", "python-asgi")), None)
    if not svc:
        pytest.skip("no suitable microservice for upload")
    attacker.post(f"/svc/{svc}/upload?name=shell.php", marker, host=lab.hostname)
    # FIM realtime or the next scan flags it
    journal.expect("security.webshell", within=30)
