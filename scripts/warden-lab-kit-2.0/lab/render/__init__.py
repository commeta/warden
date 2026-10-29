"""Rendering: roles describe files, they never write them.

A role's ``render`` returns a list of :class:`FileSpec` — a path, its bytes,
owner, mode and the unit to restart when it changes. ``apply`` (in
:mod:`lab.manifest`) is the only thing that writes to disk, so every file the
kit owns is tracked, diffed and removed when a role stops producing it. This
is what closes L1 of the review (an imperative script that could not take a
file *away*).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

from ..util import die

TEMPLATES = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "..", "templates")
TEMPLATES = os.path.normpath(TEMPLATES)


@dataclass
class FileSpec:
    """A file the kit owns, as a role wants it on disk."""

    path: str
    content: bytes
    owner: str = "root"
    group: str = "root"
    mode: int = 0o644
    role: str = ""
    # units to (re)start / validate after this file changes
    restart: tuple[str, ...] = ()
    # a config validator command to run before any restart, e.g. ("nginx", "-t")
    validate: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if isinstance(self.content, str):
            self.content = self.content.encode()
        if not self.path.startswith("/"):
            die(f"FileSpec.path must be absolute: {self.path}")


@dataclass
class DirSpec:
    """A directory the kit owns (uploads, storage, docroots)."""

    path: str
    owner: str = "root"
    group: str = "root"
    mode: int = 0o755
    role: str = ""


@dataclass
class Plan:
    files: list[FileSpec] = field(default_factory=list)
    dirs: list[DirSpec] = field(default_factory=list)

    def extend(self, other: Plan) -> None:
        self.files.extend(other.files)
        self.dirs.extend(other.dirs)


# A token is @NAME@; a literal '@' is written @@ (so nft set references like
# `update @@blocklist` survive). Config files use { } and ${ } freely, and a
# bare '@' (an email, a comment) is left untouched.
_TOKEN = re.compile(r"@([A-Za-z_][A-Za-z0-9_]*)@|@@")


def render_template(name: str, mapping: dict[str, object]) -> str:
    """Load ``templates/<name>`` and substitute ``@VAR@`` tokens.

    A value missing from ``mapping`` for a token that appears in the template
    is a hard error: a typo never reaches a config file silently.
    """
    path = os.path.join(TEMPLATES, name)
    try:
        with open(path, encoding="utf-8") as f:
            raw = f.read()
    except FileNotFoundError:
        die(f"template not found: {name}")
    return render_string(raw, mapping, where=name)


def render_string(raw: str, mapping: dict[str, object], *, where: str = "<string>") -> str:
    missing: list[str] = []

    def repl(m: re.Match) -> str:
        if m.group(0) == "@@":
            return "@"
        key = m.group(1)
        if key not in mapping:
            missing.append(key)
            return m.group(0)
        return str(mapping[key])

    out = _TOKEN.sub(repl, raw)
    if missing:
        die(f"template {where}: no value for @{missing[0]}@")
    return out
