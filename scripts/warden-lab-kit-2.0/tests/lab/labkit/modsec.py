"""Confirm ModSecurity itself logged a request, to split 'WAF didn't see it'
from 'Warden didn't read it'. Reads whichever audit-log mode the profile uses.
"""
from __future__ import annotations

import glob
import os

AUD = "/var/log/warden-lab/modsec"


def saw_request(mode: str, tag: str) -> bool:
    """Did ModSecurity record a transaction whose URI carries this tag?"""
    if mode in ("serial-native", "serial-json"):
        return _grep(f"{AUD}/audit.log", tag)
    if mode == "per-site":
        return any(_grep(p, tag) for p in glob.glob(f"{AUD}/sites/*/audit.log"))
    if mode in ("concurrent-index", "concurrent-noindex"):
        for root, _d, files in os.walk(f"{AUD}/data"):
            for f in files:
                if _grep(os.path.join(root, f), tag):
                    return True
        return False
    if mode == "error-log":
        for p in glob.glob("/var/log/warden-lab/nginx/*.error.log") + glob.glob("/var/log/warden-lab/apache/*.error.log"):
            if _grep(p, tag):
                return True
        return False
    return False


def _grep(path: str, needle: str) -> bool:
    try:
        with open(path, errors="replace") as f:
            return needle in f.read()
    except OSError:
        return False
