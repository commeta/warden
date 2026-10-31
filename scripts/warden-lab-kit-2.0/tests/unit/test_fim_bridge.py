from __future__ import annotations

import os
import time
from pathlib import Path

from lab.fim_bridge import InotifyBridge, Site, load_config


def test_inotify_bridge_observes_nested_script_close_write(tmp_path: Path):
    upload_root = tmp_path / "uploads"
    nested = upload_root / "2026" / "10"
    nested.mkdir(parents=True)
    bridge = InotifyBridge([Site("svc-php-fpm", str(upload_root))], debounce_seconds=0.1)
    try:
        target = nested / "shell-test.php"
        target.write_text("WARDEN_LAB_WEBSHELL_MARKER_DEADBEEF", encoding="utf-8")

        deadline = time.monotonic() + 2.0
        observed = set()
        while time.monotonic() < deadline and not observed:
            observed |= bridge.read_events(timeout=0.1)
        assert "svc-php-fpm" in observed
        due = bridge.due_sites(now=max(bridge.pending.values()))
        assert due == ["svc-php-fpm"]
    finally:
        bridge.close()


def test_inotify_bridge_ignores_non_script_uploads(tmp_path: Path):
    upload_root = tmp_path / "uploads"
    upload_root.mkdir()
    bridge = InotifyBridge([Site("svc-node", str(upload_root))], debounce_seconds=0.1)
    try:
        (upload_root / "photo.jpg").write_bytes(b"not executable")
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            bridge.read_events(timeout=0.05)
        assert bridge.pending == {}
    finally:
        bridge.close()


def test_inotify_bridge_candidate_extensions_cover_web_script_types():
    for filename in ("shell.php", "shell.php5", "shell.phtml", "runner.py", "payload.js", ".htaccess", "readme.txt"):
        assert InotifyBridge.candidate(filename), filename
    for filename in ("photo.jpg", "archive.zip", "items.sqlite"):
        assert not InotifyBridge.candidate(filename), filename


def test_inotify_bridge_adds_watches_for_new_nested_directories(tmp_path: Path):
    upload_root = tmp_path / "uploads"
    upload_root.mkdir()
    bridge = InotifyBridge([Site("svc-php-fpm", str(upload_root))], debounce_seconds=0.1)
    try:
        nested = upload_root / "2026" / "11"
        nested.mkdir(parents=True)
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and len(bridge.watch_map) < 3:
            bridge.read_events(timeout=0.1)
        assert len(bridge.watch_map) >= 3

        target = nested / "moved-shell.php"
        staged = tmp_path / "staged.php"
        staged.write_text("WARDEN_LAB_WEBSHELL_MARKER_CAFEBABE", encoding="utf-8")
        os.replace(staged, target)
        deadline = time.monotonic() + 2.0
        observed = set()
        while time.monotonic() < deadline and not observed:
            observed |= bridge.read_events(timeout=0.1)
        assert "svc-php-fpm" in observed
    finally:
        bridge.close()


def test_inotify_bridge_rate_limits_full_site_scans(tmp_path: Path):
    upload_root = tmp_path / "uploads"
    upload_root.mkdir()
    bridge = InotifyBridge(
        [Site("svc-node", str(upload_root))],
        debounce_seconds=0.1,
        min_scan_interval_seconds=3.0,
    )
    try:
        bridge.schedule("svc-node", now=100.0)
        assert bridge.due_sites(now=100.2) == ["svc-node"]

        bridge.schedule("svc-node", now=101.0)
        assert bridge.due_sites(now=101.2) == []
        assert bridge.pending["svc-node"] == 103.2
        assert bridge.due_sites(now=103.3) == ["svc-node"]
    finally:
        bridge.close()


def test_bridge_config_parses_scan_throttle_and_rejects_untrusted_paths(tmp_path: Path):
    cfg = tmp_path / "bridge.json"
    cfg.write_text(
        '{"debounce_seconds":0.8,"min_scan_interval_seconds":4.0,'
        '"sites":[{"name":"svc-php-fpm",'
        '"upload_root":"/var/www/warden-lab/services/php-fpm/uploads"}]}',
        encoding="utf-8",
    )
    sites, debounce, min_interval = load_config(str(cfg))
    assert sites == [Site("svc-php-fpm", "/var/www/warden-lab/services/php-fpm/uploads")]
    assert debounce == 0.8
    assert min_interval == 4.0

    cfg.write_text(
        '{"sites":[{"name":"svc-php-fpm","upload_root":"/etc"}]}',
        encoding="utf-8",
    )
    try:
        load_config(str(cfg))
    except ValueError as exc:
        assert "outside /var/www/warden-lab" in str(exc)
    else:
        raise AssertionError("outside upload roots must be rejected")


def test_inotify_bridge_catches_hardlink_created_in_uploads(tmp_path: Path):
    upload_root = tmp_path / "uploads"
    upload_root.mkdir()
    staged = tmp_path / "staged.php"
    staged.write_text("WARDEN_LAB_WEBSHELL_MARKER_DEADBEEF", encoding="utf-8")
    bridge = InotifyBridge([Site("svc-python-asgi", str(upload_root))], debounce_seconds=0.1)
    try:
        os.link(staged, upload_root / "linked-shell.php")
        deadline = time.monotonic() + 2.0
        observed = set()
        while time.monotonic() < deadline and not observed:
            observed |= bridge.read_events(timeout=0.1)
        assert "svc-python-asgi" in observed
    finally:
        bridge.close()
