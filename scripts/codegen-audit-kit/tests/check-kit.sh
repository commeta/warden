#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
TMP="$(mktemp -d)"
cleanup() { rm -rf -- "$TMP"; }
trap cleanup EXIT

for script in install-deps.sh run-audit.sh run-full-audit.sh continue-audit.sh; do
  bash -n "$ROOT/$script"
done
python3 -m py_compile "$ROOT/audit.py" "$ROOT/codegen-analysis.py" "$ROOT/instrument-bench.py" "$ROOT/pack-results.sh"
rm -rf "$ROOT/__pycache__"
"$ROOT/run-audit.sh" --help >/dev/null
"$ROOT/run-full-audit.sh" --help >/dev/null
"$ROOT/continue-audit.sh" --help >/dev/null
"$ROOT/pack-results.sh" --help >/dev/null

# Exercise instrumentation anchors against small fixtures mirroring upstream main.
cat > "$TMP/profile.py" <<'PY'
import argparse, json, os, shutil, subprocess, signal, sys, tempfile, time
import threading

def scenario_list(w):
    return [{"name": "idle", "cfg": "", "desc": "idle"}]

def run(sc, args, outdir):
    w = args.workdir
    os.makedirs(w, exist_ok=True)
    os.makedirs(outdir, exist_ok=True)
    log = open(os.path.join(w, "wardend.log"), "w")
    enter = ""
    env = dict(os.environ)
    stops = []
    class Cgroup:
        def remove(self): pass
    cg = Cgroup()
    proc = subprocess.Popen(["sh", "-c", f"{enter}exec {args.wardend} --config {w}/warden.toml"], stdout=log,
                            stderr=subprocess.STDOUT, env=env)
    duration = args.duration
    samples, cgs = [], []
    t_end = time.monotonic() + duration
    while time.monotonic() < t_end and proc.poll() is None:
        time.sleep(args.interval)
    alive = proc.poll() is None
    if not alive:
        log.flush()
        print("  daemon exited early:\n" + open(os.path.join(w, "wardend.log")).read()[-2000:], file=sys.stderr)
    proc.send_signal(signal.SIGTERM)
    try:
        proc.wait(10)
    except subprocess.TimeoutExpired:
        proc.kill()
    for s in stops:
        s()
    cg.remove()
    res = {"name": sc["name"], "desc": sc["desc"],
           "error": None if alive else "daemon did not run", "exited_early": not alive}
    with open(os.path.join(outdir, f"{sc['name']}.json"), "w") as f:
        json.dump(res, f, indent=1)
    if args.keep:
        res["workdir"] = w
    return res

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wardend", default="/bin/false")
    ap.add_argument("--duration", type=int, default=2)
    ap.add_argument("--warmup", type=int, default=0)
    ap.add_argument("--interval", type=float, default=0.1)
    ap.add_argument("--only", default="idle")
    ap.add_argument("--out", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--no-drop-caches", dest="drop_caches", action="store_false")
    ap.add_argument("--keep", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--arena-max")
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    w = args.workdir
    names = args.only.split(",") if args.only else [s["name"] for s in scenario_list("/x")]
    results = []
    for name in names:
        print(f"== {name}", file=sys.stderr)
        # scenario closures need the real work dir: rebuild the list per run
        wd = tempfile.mkdtemp(prefix="wprof-", dir=w)
        args.workdir = wd
        sc = next(s for s in scenario_list(wd) if s["name"] == name)
        results.append(run(sc, args, args.out))
        if not args.keep:
            shutil.rmtree(wd, ignore_errors=True)
    if args.json:
        print(json.dumps(results, indent=1))
    else:
        print(results)

if __name__ == "__main__":
    main()
PY
python3 "$ROOT/instrument-bench.py" profile --source "$TMP/profile.py" --output "$TMP/profile-instrumented.py" --manifest "$TMP/profile.patch.json" >/dev/null
python3 -m py_compile "$TMP/profile-instrumented.py"
grep -q 'strace.*-f.*-c' "$TMP/profile-instrumented.py"
grep -q 'proc.poll() is None' "$TMP/profile-instrumented.py"
grep -q 'traceback.format_exc()' "$TMP/profile-instrumented.py"
# An early daemon exit must become a JSON profile failure, not an uncaught exception.
python3 "$TMP/profile-instrumented.py" --wardend /bin/false --only idle --duration 2 --warmup 0 --interval 0.1 \
  --out "$TMP/profile-out" --workdir "$TMP/profile-work" --no-drop-caches --keep --json > "$TMP/profile.stdout" 2> "$TMP/profile.stderr"
python3 - "$TMP/profile-out/idle.json" <<'PY_PROFILE'
import json, pathlib, sys
item=json.loads(pathlib.Path(sys.argv[1]).read_text())
assert item["error"] == "daemon did not run", item
assert item["exited_early"] is True, item
assert pathlib.Path(item["workdir"]).is_dir(), item
PY_PROFILE
# An unexpected Python-side scenario setup error must also be retained with traceback.
python3 "$TMP/profile-instrumented.py" --wardend /bin/false --only absent --duration 2 --warmup 0 --interval 0.1 \
  --out "$TMP/profile-exception-out" --workdir "$TMP/profile-exception-work" --no-drop-caches --keep --json > "$TMP/profile-exception.stdout" 2> "$TMP/profile-exception.stderr"
python3 - "$TMP/profile-exception-out/absent.json" <<'PY_PROFILE_EXCEPTION'
import json, pathlib, sys
item=json.loads(pathlib.Path(sys.argv[1]).read_text())
assert item["error"].startswith("StopIteration:"), item
assert "traceback" in item and "next(s for s in scenario_list" in item["traceback"], item
assert pathlib.Path(item["workdir"]).is_dir(), item
PY_PROFILE_EXCEPTION

cat > "$TMP/stress.py" <<'PY'
import os, subprocess, threading, time

def sc_waf_v6_spread(a, w):
    th = threading.Thread(target=lambda: None)
    t0 = time.monotonic(); th.start()
    time.sleep(a.duration)
    return summary(d, t0, t1, {"v6_transactions": n[0], "v6_addresses": n[0] // 4,
                               "v6_waf_attack_events": sum(e["kind"] == "security.waf_attack" for e in evs),
                               "v6_heuristics_ip_threshold": sum(e["kind"] == "heuristics.ip_threshold" for e in evs),
                               "v6_block_targets": sorted({block_target(e) for e in evs if e["kind"] == "action.block_ip"}),
                               "v6_waf_hit_events": sum(e["kind"] == "waf.hit" for e in evs),
                               "v4_control_transactions": n2[0],
                               "v4_waf_attack_events": sum(e["kind"] == "security.waf_attack" for e in evs2)})

def block_target(e): return ""

def fixture_runtime(a):
    for name in ("fixture",):
        w = "/tmp/fixture-wst"
        os.chmod(w, 0o755)
        res = {"fixture": {}}
        res[name]["workdir"] = w

def maybe_perf(a, d, w, name):
    if not a.perf:
        return None
    out = f"{a.out}/{name}.perf.data"
    p = subprocess.Popen(["perf", "record", "-F", "499", "-g", "--call-graph", "dwarf,16384", "-p", str(d.p.pid), "-o", out, "--", "sleep", str(min(20, a.duration - 2))],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return out


SCENARIOS = {}
PY
python3 "$ROOT/instrument-bench.py" stress --source "$TMP/stress.py" --output "$TMP/stress-instrumented.py" >/dev/null
python3 -m py_compile "$TMP/stress-instrumented.py"
grep -q 'perf stat' "$TMP/stress-instrumented.py"
grep -q 'maybe_perf(a, d, w, "waf_v6_spread")' "$TMP/stress-instrumented.py"

# Exercise the analysis packer and ensure the extra full-mode evidence is retained.
A="$TMP/fake-audit"; mkdir -p "$A/source/warden" "$A/artifacts/mir" "$A/artifacts/instrumented" "$A/artifacts/audit-kit" "$A/reports/codegen" "$A/runtime-profile-syscalls" "$A/runtime-stress" "$A/profile-preflight-work/wprof-test"
printf '[workspace]\n' > "$A/source/warden/Cargo.toml"
printf 'binary' > "$A/artifacts/wardend.production"
printf 'MIR' > "$A/artifacts/mir/example.mir"
printf 'patch' > "$A/artifacts/instrumented/bench-stress-perf.py"
printf '1.2.0\n' > "$A/artifacts/audit-kit/VERSION"
printf 'MCA' > "$A/reports/codegen/mca.txt"
printf 'syscall' > "$A/runtime-profile-syscalls/process.strace-summary.txt"
printf 'perf' > "$A/runtime-stress/exec.perf.data"
printf 'stat' > "$A/runtime-stress/exec.perf-stat.csv"
printf 'daemon log' > "$A/profile-preflight-work/wprof-test/wardend.log"
printf 'idle config' > "$A/profile-preflight-work/wprof-test/warden.toml"
"$ROOT/pack-results.sh" "$A" --include-perf-data --output "$TMP/fake-bundle.tar.gz" >/dev/null
python3 - "$TMP/fake-bundle.tar.gz" <<'PY'
import sys, tarfile
with tarfile.open(sys.argv[1], 'r:gz') as tf:
    names=set(tf.getnames())
need=('artifacts/mir/example.mir','artifacts/instrumented/bench-stress-perf.py',
      'artifacts/audit-kit/VERSION','reports/codegen/mca.txt',
      'runtime-profile-syscalls/process.strace-summary.txt','runtime-stress/exec.perf.data',
      'runtime-stress/exec.perf-stat.csv','profile-preflight-work/wprof-test/wardend.log',
      'profile-preflight-work/wprof-test/warden.toml','BUNDLE-SHA256SUMS')
root=next(n.split('/')[0] for n in names)
missing=[f'{root}/{x}' for x in need if f'{root}/{x}' not in names]
if missing: raise SystemExit(f'missing bundle entries: {missing}')
PY

rm -rf "$ROOT/__pycache__"

# The flaky timing exception must match only one exact known failure shape.
python3 - "$ROOT" <<'PY_RETRY'
import importlib.util, pathlib, sys, tempfile
root = pathlib.Path(sys.argv[1]); sys.path.insert(0, str(root))
spec = importlib.util.spec_from_file_location("audit_module", root / "audit.py")
mod = importlib.util.module_from_spec(spec); sys.modules[spec.name] = mod; spec.loader.exec_module(mod)
a = mod.Audit.__new__(mod.Audit)
with tempfile.TemporaryDirectory() as td:
    log = pathlib.Path(td) / "test.log"
    log.write_text("""test tests::smoke_run_of_every_target ... FAILED

failures:
---- tests::smoke_run_of_every_target stdout ----
modsecurity: 1.010026467s on a 263-byte input
thread 'tests::smoke_run_of_every_target' panicked at fuzz.rs:373:17:

failures:
    tests::smoke_run_of_every_target

test result: FAILED. 3 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out
""")
    ok, details = a._is_known_fuzz_smoke_timing_failure(log)
    assert ok, details
    log.write_text(log.read_text() + "test another::failure ... FAILED\n")
    ok, details = a._is_known_fuzz_smoke_timing_failure(log)
    assert not ok, details
    base = log.read_text().replace("1.010026467s", "1.051026467s")
    log.write_text(base)
    ok, details = a._is_known_fuzz_smoke_timing_failure(log)
    assert not ok, details
    # A failed workspace test must leave machine-readable evidence with the exact failed test and tail.
    a.reports = pathlib.Path(td) / "reports"; a.reports.mkdir()
    a.out = pathlib.Path(td)
    a._write_cargo_test_failure_report(log)
    report = __import__("json").loads((a.reports / "cargo-test-failure-analysis.json").read_text())
    assert report["failed_tests"] == ["tests::smoke_run_of_every_target", "another::failure"], report
    assert "test result: FAILED." in report["tail_120_lines"], report
PY_RETRY

# Simulate raw-bundle failure and verify that finalization preserves a compact fallback.
python3 - "$ROOT" <<'PY_BUNDLE'
import importlib.util, json, pathlib, sys, tarfile, tempfile
from types import SimpleNamespace
root = pathlib.Path(sys.argv[1]); sys.path.insert(0, str(root))
spec = importlib.util.spec_from_file_location("audit_fallback_test", root / "audit.py")
mod = importlib.util.module_from_spec(spec); sys.modules[spec.name] = mod; spec.loader.exec_module(mod)
with tempfile.TemporaryDirectory() as td:
    base = pathlib.Path(td); kit = base / "kit"; kit.mkdir()
    (kit / "pack-results.sh").write_text("""import pathlib, sys, tarfile
if '--include-llvm-raw' in sys.argv:
    print('synthetic raw archive failure')
    raise SystemExit(7)
root = pathlib.Path(sys.argv[1]); sys.path.insert(0, str(root)); out = pathlib.Path(sys.argv[sys.argv.index('--output') + 1])
with tarfile.open(out, 'w:gz') as tf:
    tf.add(root, arcname=root.name)
print('synthetic compact archive created')
""")
    mod.KIT = kit
    audit = mod.Audit(base / "audit", SimpleNamespace(full=True))
    audit.full_pass_complete = True
    archive = audit.finalize()
    assert archive and archive.is_file()
    summary = json.loads((audit.out / "reports/audit-summary.json").read_text())
    assert summary["bundle_mode"] == "compact_fallback", summary
    assert summary["full_pass_complete"] is False, summary
    assert (audit.out / "reports/bundle-full-attempt-failed.txt").is_file()
    with tarfile.open(archive, "r:gz") as tf:
        names = tf.getnames()
        assert any(name.endswith("bundle-full-attempt-failed.txt") for name in names), names
    assert pathlib.Path(str(archive) + ".sha256").is_file()
PY_BUNDLE

rm -rf "$ROOT/__pycache__"
printf 'OK: syntax, CLI, retry guards, profile diagnostics, instrumentation, perf/strace and archive fallback\n'

python3 -m unittest discover -s "$ROOT/tests" -p "test_*.py" -v
