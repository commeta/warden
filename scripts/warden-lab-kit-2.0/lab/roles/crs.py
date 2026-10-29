"""crs: the OWASP Core Rule Set, from the distro package or a pinned 4.x tag.

The event headline Warden shows depends on CRS rule IDs 949/959/980, so the
rule set is a first-class, pinned input:

* ``source = "package"`` uses Ubuntu's ``modsecurity-crs`` (CRS 3.3.5);
* ``source = "4.x"`` clones a pinned tag over git (release tarballs are not
  always reachable) and checks the tree digest against ``crs.sha256`` —
  ``labctl crs-digest <ref>`` prints the digest to pin.

Either way the role writes ``crs-setup.conf`` with the profile's paranoia and
anomaly thresholds and points the WAF role at the rules directory.
"""

from __future__ import annotations

import os

from .. import roles
from ..render import DirSpec, FileSpec, Plan, render_template
from ..util import die, have, run, sha256_bytes, step

CRS_DIR = "/etc/warden-lab/crs"
SRC_DIR = os.path.join(CRS_DIR, "src")           # 4.x checkout
REPO = "https://github.com/coreruleset/coreruleset.git"


def _active(p) -> bool:
    return p.waf.engine in {"modsec2", "modsec3"}


def packages(p) -> list[str]:
    if p.crs.source == "package":
        return ["modsecurity-crs"]
    if p.crs.source == "4.x":
        return ["git"]
    return []


def _rules_root(p) -> str:
    if p.crs.source == "4.x":
        return SRC_DIR
    for c in ("/usr/share/modsecurity-crs/rules",
              "/usr/share/modsecurity-crs/owasp-crs/rules",
              "/usr/share/owasp-modsecurity-crs/rules"):
        if os.path.isdir(c):
            return os.path.dirname(c)
    # not installed yet (plan without root): assume the Debian layout
    return "/usr/share/modsecurity-crs"


def render(p, ctx) -> Plan:
    plan = Plan()
    plan.dirs.append(DirSpec(CRS_DIR, "root", "root", 0o755, "crs"))
    root = _rules_root(p)
    rules_glob = os.path.join(root, "rules", "*.conf")
    setup = render_template(
        "waf/crs-setup.conf",
        {
            "PARANOIA": p.waf.paranoia,
            "ANOMALY_IN": p.waf.anomaly_in,
            "ANOMALY_OUT": p.waf.anomaly_out,
        },
    )
    plan.files.append(FileSpec(f"{CRS_DIR}/crs-setup.conf", setup, "root", "root", 0o644, "crs"))
    ctx.set("crs_setup", f"{CRS_DIR}/crs-setup.conf")
    ctx.set("crs_rules_glob", rules_glob)
    ctx.set("crs_rules_root", root)
    return plan


def pre_apply(p, ctx) -> None:
    if p.crs.source != "4.x":
        return
    if not have("git"):
        die("git is required for crs.source = 4.x")
    os.makedirs(CRS_DIR, exist_ok=True)
    if not os.path.isdir(os.path.join(SRC_DIR, ".git")):
        run(["git", "init", "-q", SRC_DIR])
        run(["git", "-C", SRC_DIR, "remote", "add", "origin", REPO], check=False, quiet=True)
    run(["git", "-C", SRC_DIR, "fetch", "--depth=1", "origin", p.crs.ref])
    run(["git", "-C", SRC_DIR, "checkout", "-q", "--detach", "FETCH_HEAD"])
    digest = _tree_digest(SRC_DIR)
    if digest != p.crs.sha256.lower():
        die(
            f"CRS {p.crs.ref}: tree digest {digest} does not match the pinned "
            f"crs.sha256 {p.crs.sha256}. Run 'labctl crs-digest {p.crs.ref}' and "
            "update the profile if the change is expected."
        )
    step(f"CRS {p.crs.ref} verified ({digest[:16]}…)")


def tree_digest(ref: str) -> str:
    """Clone a tag into a temp dir and return its digest (for labctl crs-digest)."""
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        run(["git", "init", "-q", tmp])
        run(["git", "-C", tmp, "remote", "add", "origin", REPO], quiet=True)
        run(["git", "-C", tmp, "fetch", "--depth=1", "origin", ref])
        run(["git", "-C", tmp, "checkout", "-q", "--detach", "FETCH_HEAD"])
        return _tree_digest(tmp)


def _tree_digest(root: str) -> str:
    h = []
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirnames:
            dirnames.remove(".git")
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            try:
                with open(full, "rb") as f:
                    h.append(rel + ":" + sha256_bytes(f.read()))
            except OSError:
                continue
    return sha256_bytes("\n".join(sorted(h)).encode())


def verify(p, ctx):
    root = ctx.get("crs_rules_root") or _rules_root(p)
    has = os.path.isdir(os.path.join(root, "rules"))
    return [("CRS rules present", has, root)]


ROLE = roles.Role(name="crs", packages=packages, render=render, pre_apply=pre_apply, verify=verify, active=_active)
