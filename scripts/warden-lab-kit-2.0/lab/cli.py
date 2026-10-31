"""labctl: the single entry point.

Commands:

    doctor        check the host can run the selected profile
    plan          render the profile and show what apply would change (no writes)
    apply         install packages, reconcile files, bring services up
    verify        cheap post-apply health checks
    report        packages, Warden events in a window, and what the kit owns
    stress        hostile-load scenarios with pass/fail thresholds
    soak          long run watching Warden's own RSS/restarts/drops
    test          run the pytest black-box suite against the stand
    test-upgrade  N-1 -> N -> rollback of the Warden package
    reset         remove everything the kit owns
    migrate       turn an old lab.env into a lab.toml
    crs-digest    print the tree digest of a CRS tag (to pin crs.sha256)
"""

from __future__ import annotations

import argparse
import os
import sys

from . import VERSION, roles
from . import profile as profilemod
from .manifest import apply as manifest_apply
from .manifest import reset as manifest_reset
from .roles import Ctx
from .util import (LabError, bad, defer_service_starts, die, have, info, ok,
                    require_root, run, step, warn)

KIT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_PROFILE = os.path.join(os.getcwd(), "lab.toml")


# --------------------------------------------------------------------------
# building the plan
# --------------------------------------------------------------------------


def _load(args) -> profilemod.Profile:
    path = args.profile or DEFAULT_PROFILE
    return profilemod.load(path, args.set or [])


def _build_plan(p):
    ctx = Ctx(p, KIT_ROOT)
    active = roles.active_roles(p)
    pkgs: list[str] = []
    from .render import Plan
    plan = Plan()
    for r in active:
        pkgs += r.packages(p)
        plan.extend(r.render(p, ctx))
    # de-dup packages, keep order
    seen = set()
    pkgs = [x for x in pkgs if not (x in seen or seen.add(x))]
    return plan, ctx, active, pkgs


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def cmd_plan(args) -> int:
    p = _load(args)
    print(profilemod.summary(p))
    plan, ctx, active, pkgs = _build_plan(p)
    res = manifest_apply(plan, p.name, dry=True)
    print()
    info(f"packages: {' '.join(pkgs) or '(none)'}")
    info(f"would write/update {len(res.written)} path(s), remove {len(res.removed)}")
    for w in res.written:
        step("+ " + w)
    for r in res.removed:
        step("- " + r)
    return 0


def cmd_doctor(args) -> int:
    p = _load(args)
    print(profilemod.summary(p))
    print()
    problems = 0
    checks = [
        ("root", os.geteuid() == 0, "most commands need sudo"),
        ("systemd", have("systemctl"), "services are managed by systemd"),
        ("python3.12+", sys.version_info >= (3, 12), "labctl targets Python 3.12"),
        ("apt-get", have("apt-get"), "packages are installed with apt"),
    ]
    for name, good, why in checks:
        (ok if good else bad)(f"{name}  {'' if good else '— ' + why}")
        problems += 0 if good else 1
    # compatibility is already validated by load(); echo the matrix choice
    front = profilemod.FRONTS[p.front]
    info(f"front {p.front}: {front['desc']}")
    if not have("nft"):
        info("nftables is not installed yet; labctl apply will install it")
    if p.net.mode in {"netns", "lan", "external"} and not have("ip"):
        info("iproute2 is not installed yet; labctl apply will install it")
    if problems:
        warn(f"{problems} precondition(s) unmet")
    return 1 if problems else 0


def cmd_apply(args) -> int:
    require_root()
    p = _load(args)
    info(f"applying profile {p.name}")
    plan, ctx, active, pkgs = _build_plan(p)
    if pkgs and not args.no_packages:
        _install_packages(pkgs)
        # Re-render after packages exist. Some roles discover package-provided
        # files (e.g. nginx unicode.mapping and CRS rules) while rendering.
        # Keeping the pre-install plan causes first-run configurations to
        # reference files that were not yet present when the plan was built.
        plan, ctx, active, pkgs_after = _build_plan(p)
        if pkgs_after != pkgs:
            die("package requirements changed after installation; run labctl plan and review the profile")
    # create the accounts files will be chowned to, before anything is written
    from .util import ensure_system_user
    for r in active:
        for name, home in r.users(p):
            ensure_system_user(name, home=home)
    # imperative prep that must precede writing/validating config
    for r in active:
        try:
            r.pre_apply(p, ctx)
        except LabError:
            raise
        except Exception as e:
            die(f"role {r.name} pre-apply failed: {type(e).__name__}: {e}")
    res = manifest_apply(plan, p.name, adopt=args.adopt)
    info(f"wrote {len(res.written)}, removed {len(res.removed)}, unchanged {res.unchanged}")
    for r in active:
        try:
            r.post_apply(p, ctx)
        except LabError:
            raise
        except Exception as e:
            die(f"role {r.name} post-apply failed: {type(e).__name__}: {e}")
    if res.restarted:
        info("restarted: " + ", ".join(res.restarted))
    ok(f"profile {p.name} applied")
    return 0


def _install_packages(pkgs: list[str]) -> None:
    if not have("apt-get"):
        die("apt-get not found; automatic dependency installation is required")
    env = {"DEBIAN_FRONTEND": "noninteractive"}
    info(f"installing {len(pkgs)} package(s)")
    # Refresh APT metadata before inhibiting service starts.
    run(["apt-get", "update", "-qq"], env=env)

    # Defer package postinst service starts until generated firewall/configs
    # have been written and validated. Never overwrite an administrator policy.
    with defer_service_starts():
        run(["apt-get", "install", "-y", "--no-install-recommends", *pkgs], env=env)


def cmd_verify(args) -> int:
    p = _load(args)
    plan, ctx, active, pkgs = _build_plan(p)
    # re-run render so ctx is populated, then verify
    failures = 0
    for r in active:
        for name, good, detail in r.verify(p, ctx):
            (ok if good else bad)(f"[{r.name}] {name}  {detail if not good else ''}".rstrip())
            failures += 0 if good else 1
    if failures:
        warn(f"{failures} check(s) failed")
    else:
        ok("all checks passed")
    return 1 if failures else 0


def cmd_reset(args) -> int:
    require_root()
    if not args.yes:
        warn("this removes every file the kit owns. Re-run with --yes to confirm.")
        return 1
    manifest_reset()
    if have("systemctl"):
        run(["systemctl", "daemon-reload"], check=False, quiet=True)
    try:
        from . import net as netmod
        netmod.teardown_namespaces()
    except Exception:
        pass
    ok("reset complete")
    return 0


def cmd_migrate(args) -> int:
    from .migrate import migrate
    out = migrate(args.env or "lab.env", args.out or "lab.toml")
    ok(f"wrote {out}")
    return 0


def cmd_crs_digest(args) -> int:
    from .roles.crs import tree_digest
    d = tree_digest(args.ref)
    print(d)
    return 0


def cmd_report(args) -> int:
    from .report import report
    return report(_load(args), args)


def cmd_stress(args) -> int:
    from .stress import run_scenarios
    return run_scenarios(_load(args), args)


def cmd_soak(args) -> int:
    from .stress import soak
    return soak(_load(args), args)


def cmd_test(args) -> int:
    _load(args)  # validate the profile
    pytest = have("pytest") or have("pytest-3")
    if not pytest:
        die("pytest not found (apt install python3-pytest python3-pytest-timeout)")
    env = {"LAB_PROFILE": args.profile or DEFAULT_PROFILE}
    if args.enforce:
        env["LAB_ENFORCE"] = "1"
    argv = ["pytest", "-q", os.path.join(KIT_ROOT, "tests", "lab")]
    if args.markers:
        argv += ["-m", args.markers]
    if args.k:
        argv += ["-k", args.k]
    r = run(argv, check=False, env=env)
    # run() captures output for structured CLI logging; pytest's report is
    # the primary result of this command, so forward both streams verbatim.
    if r.out:
        print(r.out, end="" if r.out.endswith("\n") else "\n")
    if r.err:
        print(r.err, file=sys.stderr, end="" if r.err.endswith("\n") else "\n")
    return r.code


def cmd_test_upgrade(args) -> int:
    from .stress import test_upgrade
    return test_upgrade(_load(args), args)


# --------------------------------------------------------------------------
# argument parser
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="labctl", description=f"Warden Lab Kit {VERSION}")
    ap.add_argument("--version", action="version", version=f"labctl {VERSION}")
    ap.add_argument("-p", "--profile", help="path to lab.toml (default ./lab.toml)")
    ap.add_argument("--set", action="append", metavar="key=value", help="override a profile value")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="check host preconditions").set_defaults(fn=cmd_doctor)
    sub.add_parser("plan", help="show what apply would change").set_defaults(fn=cmd_plan)
    a = sub.add_parser("apply", help="install and reconcile the stand")
    a.add_argument("--no-packages", action="store_true", help="do not run apt")
    a.add_argument("--adopt", action="store_true", help="take over pre-existing files instead of moving them aside")
    a.set_defaults(fn=cmd_apply)
    sub.add_parser("verify", help="post-apply health checks").set_defaults(fn=cmd_verify)
    r = sub.add_parser("reset", help="remove everything the kit owns")
    r.add_argument("--yes", action="store_true")
    r.set_defaults(fn=cmd_reset)
    m = sub.add_parser("migrate", help="convert lab.env to lab.toml")
    m.add_argument("--env")
    m.add_argument("--out")
    m.set_defaults(fn=cmd_migrate)
    c = sub.add_parser("crs-digest", help="print the tree digest of a CRS tag")
    c.add_argument("ref")
    c.set_defaults(fn=cmd_crs_digest)
    rp = sub.add_parser("report", help="packages, events in a window, owned files")
    rp.add_argument("--since-id", type=int, default=0)
    rp.add_argument("--json", action="store_true")
    rp.set_defaults(fn=cmd_report)
    st = sub.add_parser("stress", help="hostile-load scenarios")
    st.add_argument("scenario", nargs="?", default="all")
    st.add_argument("--json", action="store_true")
    st.set_defaults(fn=cmd_stress)
    sk = sub.add_parser("soak", help="long stability run")
    sk.add_argument("--hours", type=float, default=1.0)
    sk.set_defaults(fn=cmd_soak)
    t = sub.add_parser("test", help="run the pytest suite")
    t.add_argument("-m", "--markers")
    t.add_argument("-k")
    t.add_argument("--enforce", action="store_true")
    t.set_defaults(fn=cmd_test)
    tu = sub.add_parser("test-upgrade", help="N-1 -> N -> rollback of the Warden package")
    tu.add_argument("--from-deb", required=False)
    tu.add_argument("--to-deb", required=False)
    tu.set_defaults(fn=cmd_test_upgrade)
    return ap


def main(argv: list[str] | None = None) -> int:
    ap = build_parser()
    args = ap.parse_args(argv)
    try:
        return args.fn(args)
    except LabError as e:
        bad(str(e))
        return 1
    except KeyboardInterrupt:
        return 130
