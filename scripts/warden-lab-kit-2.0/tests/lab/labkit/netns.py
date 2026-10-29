"""Namespace awareness for the fixtures."""
from __future__ import annotations

from lab import net as netmod


def attacker_ns(p):
    return netmod.ATK_NS if p.net.mode in ("netns", "external") else None


def client_ns(p):
    return netmod.CLI_NS if p.net.mode in ("netns", "external") else None
