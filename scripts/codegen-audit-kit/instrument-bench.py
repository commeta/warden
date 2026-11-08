#!/usr/bin/env python3
"""Create isolated, auditable benchmark copies with optional strace/perf hooks.

The upstream Warden checkout is never modified. Patches fail closed if their
expected upstream anchors drift.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def patch_profile(src: Path, dst: Path) -> dict:
    text = src.read_text(encoding="utf-8")
    start_anchor = '''    proc = subprocess.Popen(["sh", "-c", f"{enter}exec {args.wardend} --config {w}/warden.toml"], stdout=log,
                            stderr=subprocess.STDOUT, env=env)
'''
    start_insert = start_anchor + '''    # Optional syscall-count attachment used only by the audit harness.
    audit_strace_proc = None
    audit_strace_scenarios = set(filter(None, os.environ.get("WARDEN_AUDIT_STRACE_SCENARIOS", "").split(",")))
    audit_strace_root = os.environ.get("WARDEN_AUDIT_STRACE_DIR")
    if sc["name"] in audit_strace_scenarios and audit_strace_root and shutil.which("strace"):
        os.makedirs(audit_strace_root, exist_ok=True)
        audit_strace_path = os.path.join(audit_strace_root, sc["name"] + ".strace-summary.txt")
        try:
            with open(audit_strace_path + ".attach.log", "w") as audit_trace_log:
                audit_strace_proc = subprocess.Popen(
                    ["strace", "-f", "-c", "-p", str(proc.pid), "-o", audit_strace_path],
                    stdout=audit_trace_log, stderr=subprocess.STDOUT)
                time.sleep(0.5)
                if audit_strace_proc.poll() is not None:
                    audit_strace_proc = None
        except OSError:
            audit_strace_proc = None
'''
    if text.count(start_anchor) != 1:
        raise RuntimeError(f"profile anchor mismatch: daemon launch count={text.count(start_anchor)}")
    text = text.replace(start_anchor, start_insert, 1)

    stop_anchor = '''    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        proc.kill()
'''
    stop_insert = '''    if audit_strace_proc is not None:
        try:
            # SIGINT detaches strace and flushes its -c summary without signalling the daemon.
            audit_strace_proc.send_signal(signal.SIGINT)
            audit_strace_proc.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            try:
                audit_strace_proc.kill()
                audit_strace_proc.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                pass
    # The daemon may have exited between the sample-loop check and shutdown.
    # Reap it without turning the original startup error into a lost JSON result.
    try:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
    except ProcessLookupError:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
'''
    if text.count(stop_anchor) != 1:
        raise RuntimeError(f"profile stop anchor mismatch: count={text.count(stop_anchor)}")
    text = text.replace(stop_anchor, stop_insert, 1)

    cleanup_anchor = '''    for s in stops:
        s()
    cg.remove()
'''
    cleanup_insert = '''    for stop_load in stops:
        try:
            stop_load()
        except Exception as stop_error:
            print(f"  load-generator cleanup failed: {stop_error!r}", file=sys.stderr)
    cg.remove()
    log.flush()
    log.close()
'''
    if text.count(cleanup_anchor) != 1:
        raise RuntimeError(f"profile cleanup anchor mismatch: count={text.count(cleanup_anchor)}")
    text = text.replace(cleanup_anchor, cleanup_insert, 1)

    # A new cgroup directory is not proof that the memory controller was
    # delegated by systemd. If memory.stat is absent, keep /proc sampling.
    cg_anchor = '    cg = Cgroup(f"wprof-{sc[\'name\']}-{os.getpid()}")\n'
    if cg_anchor in text:
        cg_insert = cg_anchor + '''    # Never move a daemon into a cgroup with no enabled memory controller.
    if cg.path and not os.path.isfile(os.path.join(cg.path, "memory.stat")):
        cg.remove()
        cg.path = None
'''
        text = text.replace(cg_anchor, cg_insert, 1)
    read_anchor = "            cgs.append(cg.read())\n"
    if read_anchor in text:
        read_insert = '''            try:
                cgs.append(cg.read())
            except (OSError, ValueError, KeyError) as cg_error:
                # cgroup controller might disappear on systemd scope changes;
                # no false total=0 claims: an empty object means unavailable.
                print(f"  cgroup sampling unavailable: {cg_error!r}", file=sys.stderr)
                cg.path = None
                cgs.append({})
'''
        text = text.replace(read_anchor, read_insert, 1)
    # Record IPC failures as an explicit scenario failure even if CPU samples
    # were collected successfully and the daemon stayed alive.
    ipc_anchor = '''    res["exited_early"] = not alive
'''
    if ipc_anchor in text:
        ipc_insert = ipc_anchor + '''    try:
        with open(f"{w}/wardend.log", errors="replace") as audit_log_file:
            audit_log = audit_log_file.read()
        if "cannot create the control socket" in audit_log or "path must be shorter than SUN_LEN" in audit_log:
            res["error"] = "control socket failed to start (see retained wardend.log)"
    except OSError as audit_ipc_error:
        res["ipc_log_error"] = repr(audit_ipc_error)
'''
        text = text.replace(ipc_anchor, ipc_insert, 1)

    # Record the retained workdir in the per-scenario JSON (upstream adds it only
    # after serializing the object, which makes the file lose this provenance).
    workdir_anchor = '''    with open(os.path.join(outdir, f"{sc['name']}.json"), "w") as f:
        json.dump(res, f, indent=1)
    if args.keep:
        res["workdir"] = w
'''
    workdir_insert = '''    if args.keep:
        res["workdir"] = w
    with open(os.path.join(outdir, f"{sc['name']}.json"), "w") as f:
        json.dump(res, f, indent=1)
'''
    if text.count(workdir_anchor) != 1:
        raise RuntimeError(f"profile workdir JSON anchor mismatch: {text.count(workdir_anchor)}")
    text = text.replace(workdir_anchor, workdir_insert, 1)

    # Keep exceptions local to a scenario and produce JSON with a traceback.
    if "import traceback\n" not in text:
        import_anchor = "import threading\n"
        if text.count(import_anchor) != 1:
            raise RuntimeError("profile traceback import anchor mismatch")
        text = text.replace(import_anchor, import_anchor + "import traceback\n", 1)
    loop_anchor = '''    for name in names:
        print(f"== {name}", file=sys.stderr)
        # scenario closures need the real work dir: rebuild the list per run
        wd = tempfile.mkdtemp(prefix="wprof-", dir=w)
        args.workdir = wd
        sc = next(s for s in scenario_list(wd) if s["name"] == name)
        results.append(run(sc, args, args.out))
        if not args.keep:
            shutil.rmtree(wd, ignore_errors=True)
'''
    loop_insert = '''    os.makedirs(w, exist_ok=True)
    for name in names:
        print(f"== {name}", file=sys.stderr)
        wd = None
        sc = None
        try:
            # Scenario closures need the real work dir: rebuild the list per run.
            wd = tempfile.mkdtemp(prefix="wprof-", dir=w)
            args.workdir = wd
            sc = next(s for s in scenario_list(wd) if s["name"] == name)
            results.append(run(sc, args, args.out))
        except Exception as exc:
            failure = {"name": name, "desc": sc.get("desc") if sc else "scenario setup failed",
                       "error": f"{type(exc).__name__}: {exc}", "traceback": traceback.format_exc(),
                       "exited_early": True}
            if args.keep and wd:
                failure["workdir"] = wd
            try:
                with open(os.path.join(args.out, f"{name}.json"), "w") as failure_file:
                    json.dump(failure, failure_file, indent=1)
            except OSError as write_error:
                print(f"  could not write scenario failure JSON: {write_error!r}", file=sys.stderr)
            results.append(failure)
            print(f"  scenario {name} failed: {failure['error']}\\n{failure['traceback']}", file=sys.stderr)
        finally:
            if wd and not args.keep:
                shutil.rmtree(wd, ignore_errors=True)
'''
    if text.count(loop_anchor) != 1:
        raise RuntimeError(f"profile scenario-loop anchor mismatch: {text.count(loop_anchor)}")
    text = text.replace(loop_anchor, loop_insert, 1)

    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(text, encoding="utf-8")
    return {"source": str(src), "instrumented": str(dst), "source_sha256": sha256(src),
            "instrumented_sha256": sha256(dst),
            "patches": ["optional strace -f -c attach for selected scenarios",
                        "safe daemon termination/reaping", "load-generator cleanup and log close",
                        "per-scenario exception JSON and traceback", "serialize retained workdir",
                        "create missing workdir parent", "graceful cgroup-memory fallback", "fail on control-socket startup error"]}


def patch_stress(src: Path, dst: Path) -> dict:
    text = src.read_text(encoding="utf-8")
    start = text.index("def maybe_perf(a, d, w, name):\n")
    end = text.index("\n\nSCENARIOS =", start)
    replacement = '''def maybe_perf(a, d, w, name):
    record_enabled = bool(a.perf)
    stat_enabled = os.environ.get("WARDEN_AUDIT_PERF_STAT", "0") == "1"
    if not record_enabled and not stat_enabled:
        return None
    seconds = max(1, min(20, a.duration - 2))
    result = {}
    if record_enabled:
        out = f"{a.out}/{name}.perf.data"
        record_log = out + ".log"
        with open(record_log, "w") as record_stderr:
            subprocess.Popen(["perf", "record", "-e", os.environ.get("WARDEN_AUDIT_PERF_RECORD_EVENT", "cycles"),
                              "-F", "499", "-g", "--call-graph", "dwarf,16384",
                              "-p", str(d.p.pid), "-o", out, "--", "sleep", str(seconds)],
                             stdout=record_stderr, stderr=subprocess.STDOUT)
        result.update({"record": out, "record_log": record_log})
    # Collect PMU summaries independently: perf stat may work even when call-graph
    # sampling is denied by kernel/VM policy. Unsupported events are pre-filtered.
    if stat_enabled:
        events = os.environ.get("WARDEN_AUDIT_PERF_EVENTS", "cycles,instructions")
        stat_out = f"{a.out}/{name}.perf-stat.csv"
        stat_log = stat_out + ".log"
        with open(stat_log, "w") as stat_stderr:
            subprocess.Popen(["timeout", "--signal=INT", "--kill-after=5", str(seconds), "perf", "stat", "-x,",
                              "-e", events, "-p", str(d.p.pid), "-o", stat_out],
                             stdout=stat_stderr, stderr=subprocess.STDOUT)
        result.update({"stat": stat_out, "stat_log": stat_log})
    return result
'''
    text = text[:start] + replacement + text[end:]

    # The upstream spread scenario did not collect perf. Add the same bounded
    # call-graph + PMU samples used by the other safe workload scenarios.
    fstart = text.index("def sc_waf_v6_spread(a, w):\n")
    fend = text.index("\n\ndef block_target", fstart)
    block = text[fstart:fend]
    launch_anchor = '    t0 = time.monotonic(); th.start()\n'
    if block.count(launch_anchor) != 1:
        raise RuntimeError(f"stress waf_v6_spread launch anchor mismatch: {block.count(launch_anchor)}")
    block = block.replace(launch_anchor, launch_anchor + '    perf = maybe_perf(a, d, w, "waf_v6_spread")\n', 1)
    return_anchor = '"v4_control_transactions": n2[0],\n                               "v4_waf_attack_events": sum(e["kind"] == "security.waf_attack" for e in evs2)})'
    if block.count(return_anchor) != 1:
        raise RuntimeError("stress waf_v6_spread result anchor mismatch")
    block = block.replace(return_anchor, '"v4_control_transactions": n2[0],\n                               "v4_waf_attack_events": sum(e["kind"] == "security.waf_attack" for e in evs2),\n                               "perf": perf})', 1)
    text = text[:fstart] + block + text[fend:]

    # Temporary dirs remain under /tmp, never a long results/.../ subtree.
    # Copy small diagnostics to results before removing private runtime data.
    old_workdir = '        os.chmod(w, 0o755)\n'
    if text.count(old_workdir) != 1:
        raise RuntimeError(f"stress runtime chmod anchor drift: {text.count(old_workdir)}")
    text = text.replace(old_workdir, '        os.chmod(w, 0o700)\n', 1)
    old_result = '        res[name]["workdir"] = w\n'
    if text.count(old_result) != 1:
        raise RuntimeError(f"stress result anchor drift: {text.count(old_result)}")
    new_result = '''        # Do not report a complete stress scenario when its IPC cannot start.
        diag = os.path.join(a.out, "worklogs", name)
        os.makedirs(diag, exist_ok=True)
        daemon_log = os.path.join(w, "daemon.log")
        if os.path.isfile(daemon_log):
            with open(daemon_log, errors="replace") as lf:
                observed = lf.read()
            if "cannot create the control socket" in observed or "path must be shorter than SUN_LEN" in observed:
                res[name]["error"] = "control socket startup failed"
        else:
            res[name]["control_socket_verification"] = "daemon log unavailable"
        for filename in ("warden.toml", "daemon.log"):
            source_file = os.path.join(w, filename)
            if os.path.isfile(source_file) and not os.path.islink(source_file):
                shutil.copyfile(source_file, os.path.join(diag, filename))
        res[name]["workdir"] = diag
        shutil.rmtree(w, ignore_errors=True)
'''
    text = text.replace(old_result, new_result, 1)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(text, encoding="utf-8")
    return {"source": str(src), "instrumented": str(dst), "source_sha256": sha256(src),
            "instrumented_sha256": sha256(dst),
            "patches": ["perf stat CSV alongside independent perf record", "perf call graph added to waf_v6_spread",
                        "private short-lived runtime directories with copied daemon/config evidence",
                        "fail on control-socket startup error"]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=("profile", "stress"))
    ap.add_argument("--source", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--manifest", type=Path)
    args = ap.parse_args()
    result = patch_profile(args.source, args.output) if args.kind == "profile" else patch_stress(args.source, args.output)
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
