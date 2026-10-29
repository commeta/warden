"""Each runtime's /spawn runs a child → Warden sees web_spawn for its user."""
import pytest


@pytest.mark.spawn
def test_spawn_is_attributed(attacker, lab, journal, warden):
    if not warden.available():
        pytest.skip("no Warden")
    svc = next((s for s in lab.p.services if s != "php-fpm"), None)
    if not svc:
        pytest.skip("no microservice")
    attacker.get(f"/svc/{svc}/spawn", host=lab.hostname)
    # web_spawn is emitted when a web worker spawns a child
    ev = journal.expect("security.web_spawn", within=20)
    assert ev is not None
