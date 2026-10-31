"""A webshell dropped into uploads is detected; its access is correlated."""
from pathlib import Path

import pytest

from lab import layout


@pytest.mark.fim
def test_webshell_upload_is_detected(attacker, lab, journal, warden):
    if not warden.available():
        pytest.skip("no Warden")
    tag = journal.tag()
    marker = "WARDEN_LAB_WEBSHELL_MARKER_" + tag[:8].upper()
    svc = next((s for s in lab.p.services if s in ("node", "php-fpm", "python-asgi")), None)
    if not svc:
        pytest.skip("no suitable microservice for upload")

    # A unique path prevents a previous interrupted run from leaving the same
    # file in the FIM baseline and making an identical overwrite invisible.
    filename = f"shell-{tag}.php"
    path = Path(layout.svc_root(svc)) / "uploads" / filename
    detected = False
    try:
        result = attacker.post(
            f"/svc/{svc}/upload?name={filename}", marker, host=lab.hostname
        )
        assert "200" in result.get("codes", {}), f"upload failed: {result}"
        # Do not confuse an HTTP 200 from an upload handler with a successful
        # filesystem write. Assert the exact bytes before testing FIM delivery.
        assert path.is_file(), f"upload returned 200 but did not create {path}: {result}"
        assert path.read_text() == marker, f"upload content differs from marker: {path}"
        try:
            event = journal.expect("security.webshell", uri_contains=filename, within=30)
        except AssertionError as exc:
            fim_state = warden.fim_status()
            daemon_state = warden.status() or {}
            sensors = daemon_state.get("sensors", {})
            bridge_state = "unknown"
            try:
                from lab.util import run
                probe = run(["systemctl", "is-active", "warden-lab-fim-bridge.service"],
                            check=False, quiet=True)
                bridge_state = (probe.out or probe.err).strip() or "inactive"
            except Exception as probe_exc:  # diagnostics must not hide the original failure
                bridge_state = f"probe failed: {probe_exc}"
            bridge_logs = "unavailable"
            try:
                logs = run(["journalctl", "-u", "warden-lab-fim-bridge.service", "-n", "20", "--no-pager"],
                           check=False, quiet=True)
                bridge_logs = (logs.out or logs.err).strip()[-3000:] or "(no bridge logs)"
            except Exception as probe_exc:  # diagnostics must not hide the original failure
                bridge_logs = f"journal probe failed: {probe_exc}"
            # A manual site scan is diagnostic only: the test still fails if
            # realtime delivery missed the upload, but its output tells us
            # whether Warden's regular FIM traversal sees the file.
            try:
                manual = run(["wardenctl", "fim", "scan", f"svc-{svc}"], check=False, quiet=True)
                manual_scan = (manual.out or manual.err).strip()[-2000:] or f"exit={manual.code}"
            except Exception as probe_exc:  # diagnostics must not hide the original failure
                manual_scan = f"manual scan probe failed: {probe_exc}"
            raise AssertionError(
                f"{exc}; uploaded file exists={path.is_file()}, size={path.stat().st_size if path.exists() else 'n/a'}; "
                f"Warden FIM status={fim_state}; fim_realtime={sensors.get('fim_realtime')}; "
                f"upload bridge={bridge_state}; bridge logs={bridge_logs}; manual FIM scan={manual_scan}"
            ) from exc
        assert event.get("details", {}).get("site") == f"svc-{svc}", event
        detected = True
    finally:
        # Keep a failed upload on disk so the operator can run `wardenctl fim
        # scan <site>` and inspect the exact file after a realtime miss.
        if detected:
            path.unlink(missing_ok=True)
