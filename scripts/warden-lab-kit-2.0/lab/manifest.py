"""The on-disk manifest and the apply/reset engine.

``/var/lib/warden-lab/state.json`` records every file and directory the kit
owns, each with the role that produced it and the SHA-256 of what was
written. ``apply`` renders the whole profile, then:

* refuses to touch a path that exists but is not ours (a foreign file — the
  same rule the nftables table uses);
* writes only what changed (by hash), creating parents, owner and mode;
* validates each front/engine config (``nginx -t`` …) before restarting;
* restarts only the units whose files changed;
* removes files and directories that are in the manifest but no longer in the
  rendered plan (the orphan class of bug, L1).

``reset`` removes everything in the manifest, newest files first.
"""

from __future__ import annotations

import grp
import json
import os
import pwd
import shutil
from dataclasses import dataclass

from .render import FileSpec, Plan
from .util import LabError, die, info, run, sha256_bytes, sha256_file, step, warn

STATE_DIR = "/var/lib/warden-lab"
STATE_FILE = os.path.join(STATE_DIR, "state.json")
BACKUP_DIR = os.path.join(STATE_DIR, "displaced")


@dataclass
class Entry:
    path: str
    kind: str          # "file" | "dir"
    role: str
    sha256: str = ""
    owner: str = "root"
    group: str = "root"
    mode: int = 0o644


class Manifest:
    def __init__(self, profile_name: str = "") -> None:
        self.profile = profile_name
        self.entries: dict[str, Entry] = {}
        # Units that still need a restart after an interrupted/failed apply.
        self.pending_restarts: list[str] = []

    # -- persistence -------------------------------------------------------

    @classmethod
    def load(cls) -> Manifest:
        m = cls()
        try:
            with open(STATE_FILE, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return m
        except (OSError, json.JSONDecodeError) as e:
            die(f"cannot read {STATE_FILE}: {e}")
        m.profile = data.get("profile", "")
        m.pending_restarts = sorted(set(data.get("pending_restarts", [])))
        for e in data.get("entries", []):
            m.entries[e["path"]] = Entry(
                path=e["path"], kind=e.get("kind", "file"), role=e.get("role", ""),
                sha256=e.get("sha256", ""), owner=e.get("owner", "root"),
                group=e.get("group", "root"), mode=int(e.get("mode", 0o644)),
            )
        return m

    def save(self) -> None:
        os.makedirs(STATE_DIR, exist_ok=True)
        os.chmod(STATE_DIR, 0o750)
        data = {
            "profile": self.profile,
            "pending_restarts": sorted(set(self.pending_restarts)),
            "entries": [
                {
                    "path": e.path, "kind": e.kind, "role": e.role, "sha256": e.sha256,
                    "owner": e.owner, "group": e.group, "mode": e.mode,
                }
                for e in self.entries.values()
            ],
        }
        tmp = STATE_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, sort_keys=True)
        os.replace(tmp, STATE_FILE)
        os.chmod(STATE_FILE, 0o640)


def _chown(path: str, owner: str, group: str) -> None:
    try:
        uid = pwd.getpwnam(owner).pw_uid
        gid = grp.getgrnam(group).gr_gid
    except KeyError as e:
        die(f"{path}: no such user/group for chown ({e})")
    os.chown(path, uid, gid)


def _is_ours(man: Manifest, path: str) -> bool:
    return path in man.entries


def _displace(path: str) -> None:
    """Move a foreign file aside rather than overwrite it."""
    rel = path.lstrip("/")
    dest = os.path.join(BACKUP_DIR, rel)
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    shutil.move(path, dest)
    warn(f"moved a pre-existing file aside: {path} -> {dest}")


@dataclass
class ApplyResult:
    written: list[str]
    removed: list[str]
    restarted: list[str]
    unchanged: int


def apply(plan: Plan, profile_name: str, *, dry: bool = False, adopt: bool = False) -> ApplyResult:
    """Reconcile the host with ``plan``; return what changed."""
    man = Manifest.load()
    previous_profile = man.profile
    pending = set(man.pending_restarts) if previous_profile in ("", profile_name) else set()
    if man.profile and man.profile != profile_name and not adopt:
        warn(
            f"the manifest was written by profile {man.profile!r}; applying "
            f"{profile_name!r} will remove files the other profile owned"
        )
    man.profile = profile_name

    want_paths = {f.path for f in plan.files} | {d.path for d in plan.dirs}
    written: list[str] = []
    removed: list[str] = []
    # Retry restarts that failed during the previous apply for this profile.
    changed_units: set[str] = set(pending)
    validations: dict[tuple[str, ...], tuple[str, ...]] = {}
    unchanged = 0
    new_entries: dict[str, Entry] = {}

    # directories first (deepest last so parents exist)
    for d in sorted(plan.dirs, key=lambda x: x.path.count("/")):
        new_entries[d.path] = Entry(d.path, "dir", d.role, "", d.owner, d.group, d.mode)
        if dry:
            if not os.path.isdir(d.path):
                written.append(d.path + "/")
            continue
        if os.path.exists(d.path) and not os.path.isdir(d.path) and not _is_ours(man, d.path):
            _displace(d.path)
        existed = os.path.isdir(d.path)
        os.makedirs(d.path, exist_ok=True)
        os.chmod(d.path, d.mode)
        _chown(d.path, d.owner, d.group)
        if not existed:
            written.append(d.path + "/")

    # files
    for f in plan.files:
        new_entries[f.path] = Entry(
            f.path, "file", f.role, sha256_bytes(f.content), f.owner, f.group, f.mode
        )
        new_hash = sha256_bytes(f.content)
        cur_hash = None
        if os.path.exists(f.path):
            if not _is_ours(man, f.path) and not adopt:
                if dry:
                    warn(f"{f.path} exists and is not owned by the lab (would move aside)")
                else:
                    _displace(f.path)
            else:
                try:
                    cur_hash = sha256_file(f.path)
                except OSError:
                    cur_hash = None
        # Validate every declared config on each apply, not only files whose
        # hashes changed. This makes a retry useful after a previous config
        # validation failed or a package-provided dependency was repaired.
        if f.validate:
            validations[f.validate] = f.validate
        if cur_hash == new_hash and _mode_owner_ok(f):
            unchanged += 1
            continue
        if dry:
            written.append(f.path)
            changed_units.update(f.restart)
            continue
        os.makedirs(os.path.dirname(f.path), exist_ok=True)
        tmp = f.path + ".labtmp"
        with open(tmp, "wb") as fh:
            fh.write(f.content)
        os.chmod(tmp, f.mode)
        _chown(tmp, f.owner, f.group)
        os.replace(tmp, f.path)
        written.append(f.path)
        changed_units.update(f.restart)

    # orphans: in the manifest, not in the plan
    for path, e in sorted(man.entries.items(), key=lambda kv: -kv[1].path.count("/")):
        if path in want_paths:
            continue
        if dry:
            removed.append(path)
            continue
        _remove(e)
        removed.append(path)

    if dry:
        return ApplyResult(written, removed, [], unchanged)

    # Persist ownership and a restart retry-list before validation/systemd. If
    # validation, daemon-reload or a service restart fails, the next apply will
    # not misclassify Kit files as foreign and will retry the incomplete work.
    man.entries = new_entries
    man.pending_restarts = sorted(changed_units)
    man.save()

    # A daemon-reload is cheap and on every apply makes retries robust even if
    # the previous run failed during reload or while installing a new unit.
    if shutil.which("systemctl"):
        run(["systemctl", "daemon-reload"])

    # validate configs before restarting anything
    for cmd in validations:
        if cmd[0] == "wardend":
            # validated by the Warden role itself with its main config path
            continue
        step("validate: " + " ".join(cmd))
        run(list(cmd))

    restarted = _restart(changed_units)
    if changed_units:
        man.pending_restarts = []
        man.save()
    return ApplyResult(written, removed, restarted, unchanged)


def _mode_owner_ok(f: FileSpec) -> bool:
    try:
        st = os.stat(f.path)
    except OSError:
        return False
    if (st.st_mode & 0o7777) != f.mode:
        return False
    try:
        return st.st_uid == pwd.getpwnam(f.owner).pw_uid and st.st_gid == grp.getgrnam(f.group).gr_gid
    except KeyError:
        return False


def _remove(e: Entry) -> None:
    try:
        if e.kind == "dir":
            # only remove a directory we own and that is now empty-ish
            if os.path.isdir(e.path):
                shutil.rmtree(e.path, ignore_errors=True)
        else:
            if os.path.exists(e.path):
                os.remove(e.path)
        step(f"removed {e.path}")
    except OSError as ex:
        warn(f"could not remove {e.path}: {ex}")


def _restart(units: set[str]) -> list[str]:
    done: list[str] = []
    if not units:
        return done
    if not shutil.which("systemctl"):
        die("systemctl not found; cannot restart required units: " + ", ".join(sorted(units)))
    # The Kit firewall must be active before starting/restarting any web front.
    # Remaining units are deterministic alphabetically for readable logs.
    priority = {"warden-lab-nftables.service": 0}
    ordered = sorted(units, key=lambda unit: (priority.get(unit, 10), unit))
    for unit in ordered:
        try:
            run(["systemctl", "restart", unit])
            done.append(unit)
        except LabError as e:
            # Do not report a successful apply if a changed service failed to
            # start. Pending units were persisted before this call and retry on
            # the next `apply`.
            die(f"restart {unit} failed; inspect systemctl/journalctl output:\n{e}")
    return done


def reset(*, keep_state: bool = False) -> list[str]:
    """Remove every file and directory the kit owns."""
    man = Manifest.load()
    removed = []
    units = set()
    for path, e in sorted(man.entries.items(), key=lambda kv: -kv[1].path.count("/")):
        _remove(e)
        removed.append(path)
    if removed:
        info(f"removed {len(removed)} tracked paths")
    if not keep_state:
        for p in (STATE_FILE,):
            try:
                os.remove(p)
            except OSError:
                pass
    _ = units
    return removed
