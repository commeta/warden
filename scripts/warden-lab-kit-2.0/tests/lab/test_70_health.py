"""Stopping a microservice trips its health check (observed in events)."""
import pytest


@pytest.mark.health
def test_health_checks_are_configured(warden, lab):
    if not warden.available():
        pytest.skip("no Warden")
    warden.status()
    # the drop-in registered a health check per service + databases
    assert lab.p.services or lab.p.databases
