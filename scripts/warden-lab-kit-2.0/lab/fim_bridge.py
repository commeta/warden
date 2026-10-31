#!/usr/bin/env python3
"""Bridge upload writes from private systemd mount namespaces into Warden FIM.

Warden 0.14.3 uses fanotify mount marks. Some systemd services write through
private mount namespaces, where those marks may not see the close-after-write.
Inotify marks the upload directory inode instead, so this small helper asks
Warden to run its normal full FIM scan for the corresponding site.

Only configured upload trees are watched. The Warden daemon remains the
authority for signatures, baselines, events, quarantine and policy.
"""
from __future__ import annotations

import argparse
import ctypes
import errno
import json
import logging
import os
import re
import select
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Any

# inotify event masks from <sys/inotify.h>
IN_CLOSE_WRITE = 0x00000008
IN_MOVED_TO = 0x00000080
IN_CREATE = 0x00000100
IN_Q_OVERFLOW = 0x00004000
IN_IGNORED = 0x00008000
IN_ISDIR = 0x40000000
WATCH_MASK = IN_CLOSE_WRITE | IN_MOVED_TO | IN_CREATE
EVENT_HEADER = struct.Struct("iIII")

# Keep in sync with the script/config types shipped in lab/fim.py and
# Warden's default fim.site.include list. Uploads are scanned only for files
# that can contain server-side code or a configured synthetic signature.
SCRIPT_SUFFIXES = {
    ".php", ".php0", ".php1", ".php2", ".php3", ".php4", ".php5", ".php6", ".php7", ".php8", ".php9",
    ".phtml", ".pht", ".phar", ".inc", ".module", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".py",
    ".pyc", ".rb", ".pl", ".pm", ".cgi", ".sh", ".jsp", ".jspx", ".asp", ".aspx", ".cfm",
    ".html", ".htm", ".shtml", ".svg", ".so", ".wasm", ".txt",
}
SCRIPT_NAMES = {".htaccess", ".user.ini", "php.ini", "web.config"}
SITE_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


@dataclass(frozen=True)
class Site:
    name: str
    upload_root: str


class InotifyBridge:
    """Recursive inotify watcher that coalesces changes per Warden FIM site."""

    def __init__(
        self,
        sites: list[Site],
        debounce_seconds: float = 0.8,
        min_scan_interval_seconds: float = 3.0,
    ) -> None:
        if not sites:
            raise ValueError("at least one FIM upload site is required")
        if not (0.1 <= debounce_seconds <= 30.0):
            raise ValueError("debounce_seconds must be between 0.1 and 30")
        if not (0.5 <= min_scan_interval_seconds <= 300.0):
            raise ValueError("min_scan_interval_seconds must be between 0.5 and 300")
        libc = ctypes.CDLL(None, use_errno=True)
        libc.inotify_init1.argtypes = [ctypes.c_int]
        libc.inotify_init1.restype = ctypes.c_int
        libc.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        libc.inotify_add_watch.restype = ctypes.c_int
        self._libc = libc
        self.fd = libc.inotify_init1(os.O_CLOEXEC | os.O_NONBLOCK)
        if self.fd < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
        self.sites = sites
        self.debounce_seconds = debounce_seconds
        self.min_scan_interval_seconds = min_scan_interval_seconds
        self.watch_map: dict[int, tuple[str, str]] = {}
        self.pending: dict[str, float] = {}
        self.last_scan: dict[str, float] = {}
        self._closed = False
        for site in sites:
            if not os.path.isabs(site.upload_root):
                raise ValueError(f"upload root must be absolute: {site.upload_root}")
            self.add_tree(site.upload_root, site.name)

    @staticmethod
    def candidate(filename: str) -> bool:
        base = os.path.basename(filename).lower()
        if base in SCRIPT_NAMES:
            return True
        return os.path.splitext(base)[1] in SCRIPT_SUFFIXES

    def _add_watch(self, directory: str, site: str) -> None:
        try:
            wd = self._libc.inotify_add_watch(self.fd, os.fsencode(directory), WATCH_MASK)
        except OSError:
            return
        if wd < 0:
            err = ctypes.get_errno()
            # A directory may disappear while the tree is being walked.
            if err not in (errno.ENOENT, errno.ENOTDIR, errno.EACCES):
                logging.warning("cannot watch %s: %s", directory, os.strerror(err))
            return
        self.watch_map[wd] = (site, directory)

    def add_tree(self, root: str, site: str) -> None:
        if not os.path.isdir(root) or os.path.islink(root):
            logging.warning("upload directory is not present or is a symlink: %s", root)
            return
        for directory, dirs, _files in os.walk(root, followlinks=False):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(directory, d))]
            self._add_watch(directory, site)

    def schedule(self, site: str, now: float | None = None) -> None:
        self.pending[site] = (time.monotonic() if now is None else now) + self.debounce_seconds

    def handle_buffer(self, data: bytes, now: float | None = None) -> set[str]:
        """Parse one kernel read; return sites newly scheduled by this batch."""
        changed: set[str] = set()
        offset = 0
        stamp = time.monotonic() if now is None else now
        while offset + EVENT_HEADER.size <= len(data):
            wd, mask, _cookie, name_len = EVENT_HEADER.unpack_from(data, offset)
            offset += EVENT_HEADER.size
            if name_len > len(data) - offset:
                break
            raw_name = data[offset:offset + name_len].split(b"\0", 1)[0]
            offset += name_len
            if mask & IN_Q_OVERFLOW:
                for site in self.sites:
                    self.pending[site.name] = stamp + self.debounce_seconds
                    changed.add(site.name)
                continue
            if mask & IN_IGNORED:
                self.watch_map.pop(wd, None)
                continue
            watch = self.watch_map.get(wd)
            if watch is None:
                continue
            site_name, directory = watch
            name = os.fsdecode(raw_name) if raw_name else ""
            path = os.path.join(directory, name) if name else directory
            if mask & IN_ISDIR:
                if name and mask & (IN_CREATE | IN_MOVED_TO):
                    self.add_tree(path, site_name)
                    # The new subtree may already contain files by the time
                    # its watches are attached; a scan closes that race.
                    self.pending[site_name] = stamp + self.debounce_seconds
                    changed.add(site_name)
                continue
            # IN_CREATE also catches a hard-link placed into uploads: it has
            # no subsequent close-after-write event on the destination inode.
            if name and mask & (IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_TO) and self.candidate(name):
                self.pending[site_name] = stamp + self.debounce_seconds
                changed.add(site_name)
        return changed

    def read_events(self, timeout: float = 1.0) -> set[str]:
        readable, _, _ = select.select([self.fd], [], [], max(0.0, timeout))
        if not readable:
            return set()
        try:
            data = os.read(self.fd, 256 * 1024)
        except BlockingIOError:
            return set()
        return self.handle_buffer(data)

    def due_sites(self, now: float | None = None) -> list[str]:
        stamp = time.monotonic() if now is None else now
        due: list[str] = []
        for name, deadline in sorted(self.pending.items()):
            if deadline > stamp:
                continue
            next_allowed = self.last_scan.get(name, float("-inf")) + self.min_scan_interval_seconds
            if stamp < next_allowed:
                # A writable upload directory is attacker-controlled input.
                # Rate-limit full-site scans so repeated uploads cannot turn
                # the bridge into an unbounded scan trigger.
                self.pending[name] = next_allowed
                continue
            due.append(name)
        for name in due:
            self.pending.pop(name, None)
            self.last_scan[name] = stamp
        return due

    def close(self) -> None:
        if not self._closed:
            os.close(self.fd)
            self._closed = True


def load_config(path: str) -> tuple[list[Site], float, float]:
    with open(path, encoding="utf-8") as stream:
        payload: Any = json.load(stream)
    if not isinstance(payload, dict) or not isinstance(payload.get("sites"), list):
        raise ValueError("config must contain a sites array")
    sites: list[Site] = []
    seen: set[str] = set()
    for item in payload["sites"]:
        if not isinstance(item, dict):
            raise ValueError("each site must be an object")
        name = str(item.get("name", ""))
        root = str(item.get("upload_root", ""))
        if not SITE_NAME.fullmatch(name) or name in seen:
            raise ValueError(f"invalid or duplicate site name: {name!r}")
        if not os.path.isabs(root) or os.path.normpath(root) != root:
            raise ValueError(f"upload_root must be a normalized absolute path: {root!r}")
        # Kit-managed roots live below this fixed tree. This avoids turning a
        # writable config into an arbitrary filesystem watcher.
        if not root.startswith("/var/www/warden-lab/"):
            raise ValueError(f"upload_root is outside /var/www/warden-lab: {root}")
        seen.add(name)
        sites.append(Site(name, root))
    debounce = float(payload.get("debounce_seconds", 0.8))
    min_interval = float(payload.get("min_scan_interval_seconds", 3.0))
    if not (0.5 <= min_interval <= 300.0):
        raise ValueError("min_scan_interval_seconds must be between 0.5 and 300")
    return sites, debounce, min_interval


def run_scan(site: str) -> None:
    try:
        result = subprocess.run(
            ["/usr/bin/wardenctl", "fim", "scan", site],
            check=False,
            capture_output=True,
            text=True,
            timeout=300,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        logging.error("Warden FIM scan failed for %s: %s", site, exc)
        return
    if result.returncode:
        logging.error("Warden FIM scan failed for %s (exit %s): %s", site, result.returncode,
                      (result.stderr or result.stdout).strip()[:1000])
        return
    logging.info("Warden FIM upload scan completed for %s: %s", site,
                 " ".join((result.stdout or "").split())[:500])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", stream=sys.stdout)
    try:
        sites, debounce, min_interval = load_config(args.config)
        bridge = InotifyBridge(sites, debounce, min_interval)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        logging.error("cannot start FIM upload bridge: %s", exc)
        return 1

    if not bridge.watch_map:
        logging.warning("no upload directories are currently watchable; waiting for directory creation")
    logging.info(
        "watching %d upload directories for %d FIM sites (debounce %.1fs, min scan interval %.1fs)",
        len(bridge.watch_map), len(sites), debounce, min_interval,
    )
    try:
        while True:
            bridge.read_events(timeout=0.5)
            for site in bridge.due_sites():
                run_scan(site)
    except KeyboardInterrupt:
        return 0
    finally:
        bridge.close()


if __name__ == "__main__":
    raise SystemExit(main())
