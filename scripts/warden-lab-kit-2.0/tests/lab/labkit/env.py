"""Resolve the profile and the stand's addresses for the fixtures."""
from __future__ import annotations

import os
import sys

# env.py is at <kit>/tests/lab/labkit/env.py → four levels up is the kit root
KIT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
if KIT not in sys.path:
    sys.path.insert(0, KIT)

from lab import net as netmod  # noqa: E402
from lab import profile as pmod  # noqa: E402


def load_profile():
    path = os.environ.get("LAB_PROFILE") or os.path.join(os.getcwd(), "lab.toml")
    return pmod.load(path, (os.environ.get("LAB_SET") or "").split(";") if os.environ.get("LAB_SET") else [])


def endpoints(p):
    return netmod.resolve(p)
