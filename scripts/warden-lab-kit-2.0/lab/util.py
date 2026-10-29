"""Small shared helpers: process execution, logging, hashing, root checks.

Everything that touches the host goes through :func:`run`, which logs the
command and refuses to hide failures. Nothing here imports another lab
module, so it can be used from every role and from the tests' helpers.
"""

from __future__ import annotations

import grp
import hashlib
import os
import pwd
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator, NoReturn

# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------

_COLOR = sys.stderr.isatty() and os.environ.get("NO_COLOR") is None


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


class LabError(Exception):
    """A clean, expected failure: labctl prints the message and exits 1."""


def die(msg: str) -> NoReturn:
    raise LabError(msg)


def info(msg: str) -> None:
    print(_c("1;34", "==>") + " " + msg, file=sys.stderr, flush=True)


def step(msg: str) -> None:
    print(_c("1;32", "  ·") + " " + msg, file=sys.stderr, flush=True)


def warn(msg: str) -> None:
    print(_c("1;33", "warning:") + " " + msg, file=sys.stderr, flush=True)


def ok(msg: str) -> None:
    print(_c("1;32", "OK") + " " + msg, file=sys.stderr, flush=True)


def bad(msg: str) -> None:
    print(_c("1;31", "FAIL") + " " + msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# process execution
# --------------------------------------------------------------------------


@dataclass
class Result:
    code: int
    out: str
    err: str

    @property
    def ok(self) -> bool:
        return self.code == 0


def run(
    argv: list[str],
    *,
    check: bool = True,
    input: str | None = None,
    env: dict[str, str] | None = None,
    cwd: str | None = None,
    timeout: float | None = None,
    quiet: bool = False,
) -> Result:
    """Run a command (never through a shell) and return its output.

    ``check`` raises :class:`LabError` on a non-zero exit with the captured
    stderr, so a failing ``nginx -t`` or ``apt-get`` stops ``apply`` with a
    useful message instead of a Python traceback.
    """

    if not quiet:
        step(" ".join(argv))
    full_env = dict(os.environ)
    if env:
        full_env.update(env)
    try:
        p = subprocess.run(
            argv,
            input=input,
            text=True,
            capture_output=True,
            env=full_env,
            cwd=cwd,
            timeout=timeout,
        )
    except FileNotFoundError:
        die(f"command not found: {argv[0]}")
    except subprocess.TimeoutExpired:
        die(f"command timed out after {timeout}s: {' '.join(argv)}")
    res = Result(p.returncode, p.stdout or "", p.stderr or "")
    if check and not res.ok:
        detail = (res.err.strip() or res.out.strip() or "no output")[:4000]
        die(f"command failed ({res.code}): {' '.join(argv)}\n{detail}")
    return res



@contextmanager
def defer_service_starts(policy: str = "/usr/sbin/policy-rc.d") -> Iterator[None]:
    """Temporarily prevent Debian package scripts from starting services.

    An existing administrator policy is never replaced or removed. This is
    used while installing dependencies and Warden itself so the Kit can apply
    and validate firewall/configuration files before explicitly starting units.
    """
    try:
        fd = os.open(policy, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
    except FileExistsError:
        # Respect an administrator-owned policy-rc.d exactly as configured.
        yield
        return

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(
                "#!/bin/sh\n"
                "# Temporary Warden Lab Kit service-start guard.\n"
                "exit 101\n"
            )
        step("temporarily deferring package service starts until configuration is validated")
        yield
    finally:
        try:
            os.unlink(policy)
        except FileNotFoundError:
            pass


def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


# --------------------------------------------------------------------------
# identity / privilege
# --------------------------------------------------------------------------


def require_root() -> None:
    if os.geteuid() != 0:
        die("this command must run as root (use sudo)")


def invoking_user() -> str:
    """The human behind sudo, or the current user."""
    return os.environ.get("SUDO_USER") or pwd.getpwuid(os.getuid()).pw_name


def user_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def group_exists(name: str) -> bool:
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False


def ensure_system_user(name: str, *, home: str, shell: str = "/usr/sbin/nologin") -> None:
    """Create a locked system account with its own group, idempotently."""
    if not group_exists(name):
        run(["groupadd", "--system", name], quiet=True)
    if not user_exists(name):
        run(
            [
                "useradd",
                "--system",
                "--gid",
                name,
                "--home-dir",
                home,
                "--shell",
                shell,
                "--no-create-home",
                name,
            ],
            quiet=True,
        )


# --------------------------------------------------------------------------
# hashing
# --------------------------------------------------------------------------


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------
# misc
# --------------------------------------------------------------------------


def now_ms() -> int:
    return int(time.time() * 1000)


@dataclass
class Timer:
    label: str
    started: float = field(default_factory=time.monotonic)

    def done(self) -> float:
        return time.monotonic() - self.started
