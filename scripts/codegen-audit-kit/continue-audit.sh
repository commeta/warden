#!/usr/bin/env bash
# Append an isolated follow-up run to an existing Warden audit. Never overwrite prior runs.
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage:
  ./continue-audit.sh AUDIT_DIR [--profile] [--stress] [options]

Options:
  --profile                 CPU/RSS/syscall profiles: idle, process, waf.
  --stress                  Safe non-firewall stress tests; perf recording only if preflight passes.
  --profile-duration SEC    Seconds per profile scenario (default 60; >=20).
  --profile-warmup SEC      Warm-up excluded from rates (default 15; >=0).
  --stress-duration SEC     Seconds per stress scenario (default 30; >=10).
  --rerun-checks            Force fmt and strict Clippy even if prior audit steps passed.
  --skip-fmt                Do not run fmt if prior result is missing/failed.
  --skip-clippy             Do not run strict Clippy if prior result is missing/failed.
  --skip-perf-preflight     Do not probe hardware performance counters.
  --archive                 Create a compact analysis bundle after collection.
  -h, --help                Show this help.

Each invocation writes to followup-runs/<UTC timestamp>-<unique suffix>/.
It does not rebuild wardend, alter sysctls, flush caches, or run firewall stress.
USAGE
}
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 2; }
log() { printf '\n==> %s\n' "$*"; }

[[ $# -ge 1 ]] || { usage; exit 2; }
[[ "$1" != "-h" && "$1" != "--help" ]] || { usage; exit 0; }
AUDIT_DIR="$(realpath -e -- "$1")"
shift
RUN_PROFILE=0 RUN_STRESS=0 DO_FMT=1 DO_CLIPPY=1 DO_PERF=1 DO_ARCHIVE=0 FORCE_CHECKS=0
PROFILE_DURATION=60 PROFILE_WARMUP=15 STRESS_DURATION=30
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) RUN_PROFILE=1; shift ;;
    --stress) RUN_STRESS=1; shift ;;
    --profile-duration) [[ $# -ge 2 ]] || fail 'missing --profile-duration value'; PROFILE_DURATION="$2"; shift 2 ;;
    --profile-warmup) [[ $# -ge 2 ]] || fail 'missing --profile-warmup value'; PROFILE_WARMUP="$2"; shift 2 ;;
    --stress-duration) [[ $# -ge 2 ]] || fail 'missing --stress-duration value'; STRESS_DURATION="$2"; shift 2 ;;
    --rerun-checks) FORCE_CHECKS=1; shift ;;
    --skip-fmt) DO_FMT=0; shift ;;
    --skip-clippy) DO_CLIPPY=0; shift ;;
    --skip-perf-preflight) DO_PERF=0; shift ;;
    --archive) DO_ARCHIVE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown option: $1" ;;
  esac
done
[[ -d "$AUDIT_DIR/source/warden" && -f "$AUDIT_DIR/source/warden/Cargo.toml" ]] || fail 'source/warden Cargo.toml not found'
REPO="$AUDIT_DIR/source/warden"
PROFILE_BIN="$AUDIT_DIR/artifacts/wardend.production"
STRESS_BIN="$AUDIT_DIR/artifacts/wardend.release-unstripped"
if (( RUN_PROFILE )); then
  [[ -x "$PROFILE_BIN" ]] || fail "missing executable production binary: $PROFILE_BIN"
fi
if (( RUN_STRESS )); then
  [[ -x "$STRESS_BIN" ]] || fail "missing executable release-unstripped binary: $STRESS_BIN"
fi
[[ "$PROFILE_DURATION" =~ ^[0-9]+$ ]] && (( PROFILE_DURATION >= 20 )) || fail '--profile-duration must be >=20'
[[ "$PROFILE_WARMUP" =~ ^[0-9]+$ ]] && (( PROFILE_WARMUP >= 0 )) || fail '--profile-warmup must be >=0'
[[ "$STRESS_DURATION" =~ ^[0-9]+$ ]] && (( STRESS_DURATION >= 10 )) || fail '--stress-duration must be >=10'

source "$HOME/.cargo/env" 2>/dev/null || true
export PATH="$HOME/.cargo/bin:$PATH"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUNS_DIR="$AUDIT_DIR/followup-runs"
mkdir -p "$RUNS_DIR"
# mktemp ensures a second/parallel invocation cannot reuse an earlier run path.
RUN_DIR="$(mktemp -d "$RUNS_DIR/$(date -u +%Y%m%dT%H%M%SZ)-XXXXXX")"
RUN_ID="$(basename "$RUN_DIR")"
LOG_DIR="$RUN_DIR/logs" REPORT_DIR="$RUN_DIR/reports"
mkdir -p "$LOG_DIR" "$REPORT_DIR"
STATUS=0 PERF_OK=0
python3 - "$REPORT_DIR/runtime-binary-provenance.json" "$PROFILE_BIN" "$STRESS_BIN" "$RUN_PROFILE" "$RUN_STRESS" <<'PY_PROVENANCE'
import hashlib, json, pathlib, sys
out = pathlib.Path(sys.argv[1]); rows = {}
for label, path, enabled in zip(('profile', 'stress'), sys.argv[2:4], sys.argv[4:6]):
    if enabled == '1':
        binary = pathlib.Path(path)
        h = hashlib.sha256()
        with binary.open('rb') as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                h.update(chunk)
        rows[label] = {'path': str(binary), 'sha256': h.hexdigest()}
out.write_text(json.dumps(rows, indent=2) + '\n', encoding='utf-8')
PY_PROVENANCE

run_logged() {
  local label="$1"; shift
  local logfile="$LOG_DIR/$label.log"
  log "$label"
  printf '$' > "$logfile"; printf ' %q' "$@" >> "$logfile"; printf '\n\n' >> "$logfile"
  if "$@" >> "$logfile" 2>&1; then
    printf 'OK\n' | tee -a "$logfile"; return 0
  else
    local rc=$?
    printf 'FAILED (exit=%s)\n' "$rc" | tee -a "$logfile"
    STATUS=1; return "$rc"
  fi
}

# Reuse successful CI checks from reports/steps.json. Rerun only missing/failed checks,
# unless --rerun-checks explicitly requests a fresh run.
prior_step_ok() {
  local step_name="$1"
  python3 - "$AUDIT_DIR/reports/steps.json" "$step_name" <<'PY'
import json, sys
from pathlib import Path
p=Path(sys.argv[1])
if not p.is_file(): raise SystemExit(1)
try: rows=json.loads(p.read_text(encoding='utf-8'))
except Exception: raise SystemExit(1)
for row in rows:
    if row.get('name') == sys.argv[2]:
        raise SystemExit(0 if row.get('status') == 'ok' or row.get('exit_code') == 0 else 1)
raise SystemExit(1)
PY
}

# Validate the serial test log. 1.0.2 stores the root CI log as cargo_test_ci_root_serial.log;
# older/manual follow-ups may use cargo_test_ci_serial.log.
TEST_LOG=""
for candidate in \
  "$AUDIT_DIR/logs/cargo_test_ci_root_serial.log" \
  "$AUDIT_DIR/logs/cargo_test_ci_serial.log" \
  "$AUDIT_DIR/logs/cargo_test_ci_serial_unprivileged.log"; do
  if [[ -s "$candidate" ]]; then TEST_LOG="$candidate"; break; fi
done
if [[ -f "$AUDIT_DIR/reports/test-validation.json" ]]; then
  if python3 - "$AUDIT_DIR/reports/test-validation.json" "$REPORT_DIR/serial-test-summary.txt" <<'PY_VALIDATION'
import json, pathlib, sys
report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding='utf-8'))
pathlib.Path(sys.argv[2]).write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
if report.get('coverage_complete') is not True or report.get('root_serial') is not True:
    raise SystemExit(1)
PY_VALIDATION
  then
    echo 'OK: complete root serial coverage recorded by collector' > "$REPORT_DIR/serial-test-validation.status.txt"
  else
    echo 'FAILED: aggregate test coverage incomplete; see serial-test-summary.txt' | tee "$REPORT_DIR/serial-test-validation.status.txt"
    STATUS=1
  fi
elif [[ -n "$TEST_LOG" ]]; then
  if python3 - "$TEST_LOG" "$REPORT_DIR/serial-test-summary.txt" <<'PY'
import re, sys
from pathlib import Path
src=Path(sys.argv[1]).read_text(encoding='utf-8', errors='replace')
rows=re.findall(r'test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured;', src)
passed=sum(int(r[1]) for r in rows); failed=sum(int(r[2]) for r in rows)
ignored=sum(int(r[3]) for r in rows); bad=sum(r[0] != 'ok' for r in rows)
errors=re.findall(r'(?m)^error(?:\[[^]]+\])?:.*$', src)
root_ci='cargo_test_ci_root_serial.log' in sys.argv[1]
out=(f'result_groups={len(rows)}\npassed={passed}\nfailed={failed}\nignored={ignored}\n'
     f'failed_groups={bad}\ncargo_errors={len(errors)}\nroot_serial_log={str(root_ci).lower()}\nsource_log={sys.argv[1]}\n')
Path(sys.argv[2]).write_text(out, encoding='utf-8')
if not rows or not passed or failed or bad or errors: raise SystemExit(1)
print(f'Validated {passed} passed, {failed} failed across {len(rows)} test result groups')
PY
  then
    echo 'OK: legacy test log; 1.0.7 targeted recovery does not establish complete workspace coverage' > "$REPORT_DIR/serial-test-validation.status.txt"
  else
    echo 'FAILED: see serial-test-summary.txt and source log' | tee "$REPORT_DIR/serial-test-validation.status.txt"
    STATUS=1
  fi
else
  echo 'MISSING: no serial Cargo test log found; tests are not assumed to have passed.' | tee "$REPORT_DIR/serial-test-validation.status.txt"
  STATUS=1
fi

cd "$REPO"
if (( DO_FMT )); then
  if (( ! FORCE_CHECKS )) && prior_step_ok cargo_fmt_check; then
    echo 'REUSED: prior run-audit cargo_fmt_check passed' | tee "$REPORT_DIR/cargo-fmt-check.status.txt"
  else
    run_logged cargo-fmt-check cargo fmt --all --check || true
    [[ -f "$LOG_DIR/cargo-fmt-check.log" ]] && grep -q '^OK$' "$LOG_DIR/cargo-fmt-check.log" || STATUS=1
  fi
else
  echo 'SKIPPED by --skip-fmt' > "$REPORT_DIR/cargo-fmt-check.status.txt"
fi

if (( DO_CLIPPY )); then
  if (( ! FORCE_CHECKS )) && prior_step_ok cargo_clippy_ci_strict; then
    echo 'REUSED: prior run-audit cargo_clippy_ci_strict passed' | tee "$REPORT_DIR/cargo-clippy-ci-strict.status.txt"
  else
    CLIPPY_TARGET="$RUN_DIR/clippy-target"; mkdir -p "$CLIPPY_TARGET"
    if cargo clippy --version >/dev/null 2>&1; then
      if CARGO_TARGET_DIR="$CLIPPY_TARGET" cargo clippy --workspace --all-targets --locked -- -D warnings \
        > "$LOG_DIR/cargo-clippy-ci-strict.log" 2>&1; then
        echo 'OK' | tee "$REPORT_DIR/cargo-clippy-ci-strict.status.txt"
      else
        rc=$?; printf 'FAILED (exit=%s)\n' "$rc" | tee "$REPORT_DIR/cargo-clippy-ci-strict.status.txt"; STATUS=1
      fi
    else
      echo 'FAILED: requested cargo-clippy is unavailable' | tee "$REPORT_DIR/cargo-clippy-ci-strict.status.txt"; STATUS=1
    fi
  fi
else
  echo 'SKIPPED by --skip-clippy' > "$REPORT_DIR/cargo-clippy-ci-strict.status.txt"
fi

root_prefix() { if (( EUID == 0 )); then printf '%s' ''; else command -v sudo; fi; }
run_as_root() {
  if (( EUID == 0 )); then "$@"; else sudo -E env "PATH=$PATH" "$@"; fi
}

if (( RUN_STRESS && DO_PERF )); then
  log 'perf preflight: cycles,instructions'
  if command -v perf >/dev/null 2>&1; then
    if run_as_root perf stat -e cycles,instructions -- true > "$LOG_DIR/perf-preflight.log" 2>&1; then
      PERF_OK=1; echo 'available=true' | tee "$REPORT_DIR/perf-preflight.status.txt"
    else
      echo 'available=false' | tee "$REPORT_DIR/perf-preflight.status.txt"
      echo 'Stress will still run; perf call graphs will be omitted.' >> "$REPORT_DIR/perf-preflight.status.txt"
    fi
  else
    echo 'available=false; perf command missing' | tee "$REPORT_DIR/perf-preflight.status.txt"
  fi
elif (( RUN_STRESS )); then
  echo 'not checked by --skip-perf-preflight' > "$REPORT_DIR/perf-preflight.status.txt"
fi

metrics_port_free() {
  if command -v ss >/dev/null 2>&1; then
    ! ss -H -ltn 2>/dev/null | awk '$4 ~ /:19184$/ {found=1} END {exit !found}'
  else
    return 0
  fi
}

if (( RUN_PROFILE )); then
  if ! metrics_port_free; then
    echo 'SKIPPED: TCP port 19184 is already listening' | tee "$REPORT_DIR/runtime-profile.status.txt"
    STATUS=1
  else
    PROFILE_OUT="$RUN_DIR/runtime-profile" PROFILE_WORK="$RUN_DIR/profile-work"
    mkdir -p "$PROFILE_OUT" "$PROFILE_WORK"
    log 'runtime profile: idle/process/waf; dry-run; no cache drop'
    if run_as_root python3 "$REPO/bench/profile.py" \
      --wardend "$PROFILE_BIN" --only idle,process,waf \
      --duration "$PROFILE_DURATION" --warmup "$PROFILE_WARMUP" --interval 1 \
      --out "$PROFILE_OUT" --workdir "$PROFILE_WORK" --no-drop-caches --json \
      > "$REPORT_DIR/runtime-profile-summary.json" 2> "$LOG_DIR/runtime-profile.stderr.log"; then
      if python3 - "$REPORT_DIR/runtime-profile-summary.json" "$REPORT_DIR/profile-inventory.json" <<'PY_PROFILE_VALIDATION'
import json, pathlib, sys
summary, output = map(pathlib.Path, sys.argv[1:])
expected = ('idle', 'process', 'waf')
required = ('cpu_steady_pct', 'rss_steady', 'rss_peak', 'syscalls_per_s', 'per_thread')
try:
    raw = json.loads(summary.read_text(encoding='utf-8'))
except (OSError, ValueError) as exc:
    raw = None
    parse_error = str(exc)
else:
    parse_error = None
items = raw if isinstance(raw, list) else []
names = [item.get('name') for item in items if isinstance(item, dict)]
shape_ok = len(items) == len(expected) and all(names.count(name) == 1 for name in expected)
inventory = {}
for scenario in expected:
    matches = [item for item in items if isinstance(item, dict) and item.get('name') == scenario]
    item = matches[0] if len(matches) == 1 else {}
    missing = [key for key in required if key not in item]
    inventory[scenario] = {'present': len(matches) == 1, 'error': item.get('error'),
                           'exited_early': item.get('exited_early'), 'missing_metrics': missing,
                           'ok': len(matches) == 1 and not item.get('error') and item.get('exited_early') is False and not missing}
complete = shape_ok and all(item['ok'] for item in inventory.values())
output.write_text(json.dumps({'complete': complete, 'expected': expected, 'parse_error': parse_error,
                              'scenarios': inventory}, indent=2) + '\n', encoding='utf-8')
raise SystemExit(0 if complete else 1)
PY_PROFILE_VALIDATION
      then
        echo 'OK' | tee "$REPORT_DIR/runtime-profile.status.txt"
      else
        echo 'FAILED: missing or invalid profile scenarios; see profile-inventory.json' | tee "$REPORT_DIR/runtime-profile.status.txt"; STATUS=1
      fi
    else
      rc=$?; printf 'FAILED (exit=%s)\n' "$rc" | tee "$REPORT_DIR/runtime-profile.status.txt"; STATUS=1
    fi
  fi
fi

if (( RUN_STRESS )); then
  if ! metrics_port_free; then
    echo 'SKIPPED: TCP port 19184 is already listening' | tee "$REPORT_DIR/runtime-stress.status.txt"
    STATUS=1
  else
    STRESS_OUT="$RUN_DIR/runtime-stress" STRESS_TMP="$RUN_DIR/runtime-stress/tmp"
    mkdir -p "$STRESS_TMP"; chmod 1777 "$STRESS_TMP"
    STRESS_ARGS=(python3 "$REPO/bench/stress.py" --wardend "$STRESS_BIN"
      --only exec_storm,waf_v6_unique,waf_v6_spread,auth_unique
      --duration "$STRESS_DURATION" --out "$STRESS_OUT")
    (( PERF_OK )) && STRESS_ARGS+=(--perf)
    log "runtime stress: non-firewall; duration=${STRESS_DURATION}s; perf=${PERF_OK}"
    STRESS_STARTED_NS="$(date +%s%N)"
    if run_as_root env "TMPDIR=$STRESS_TMP" "${STRESS_ARGS[@]}" \
      > "$LOG_DIR/runtime-stress.stdout.log" 2> "$LOG_DIR/runtime-stress.stderr.log"; then
      if python3 - "$STRESS_OUT" "$STRESS_STARTED_NS" "$REPORT_DIR/safe-stress-inventory.json" <<'PY_STRESS_VALIDATION'
import json, pathlib, sys
root, started, output = pathlib.Path(sys.argv[1]), int(sys.argv[2]), pathlib.Path(sys.argv[3])
expected = ('exec_storm', 'waf_v6_unique', 'waf_v6_spread', 'auth_unique')
required = ('cpu_load_seconds', 'rss_peak_mib', 'threads')
candidates = sorted((path for path in root.glob('stress-*.json') if path.stat().st_mtime_ns >= started),
                    key=lambda path: path.stat().st_mtime_ns)
source = candidates[-1] if candidates else None
try:
    raw = json.loads(source.read_text(encoding='utf-8')) if source else None
except (OSError, ValueError):
    raw = None
inventory = {}
for scenario in expected:
    item = raw.get(scenario) if isinstance(raw, dict) else None
    present = isinstance(item, dict)
    missing = [key for key in required if not present or key not in item]
    error = item.get('error') if present else 'scenario result missing'
    inventory[scenario] = {'present': present, 'error': error, 'missing_metrics': missing,
                           'ok': present and not error and not missing}
complete = bool(source) and all(item['ok'] for item in inventory.values())
output.write_text(json.dumps({'complete': complete, 'summary': str(source) if source else None,
                              'expected': expected, 'scenarios': inventory}, indent=2) + '\n', encoding='utf-8')
raise SystemExit(0 if complete else 1)
PY_STRESS_VALIDATION
      then
        echo "OK (perf_recording=$PERF_OK)" | tee "$REPORT_DIR/runtime-stress.status.txt"
      else
        echo 'FAILED: missing or invalid stress scenarios; see safe-stress-inventory.json' | tee "$REPORT_DIR/runtime-stress.status.txt"; STATUS=1
      fi
    else
      rc=$?; printf 'FAILED (exit=%s)\n' "$rc" | tee "$REPORT_DIR/runtime-stress.status.txt"; STATUS=1
    fi
    if (( PERF_OK )); then
      PERF_REPORT_DIR="$RUN_DIR/perf-reports"; mkdir -p "$PERF_REPORT_DIR"
      shopt -s nullglob
      for data in "$STRESS_OUT"/*.perf.data; do
        stem="$(basename "$data" .perf.data)"
        run_as_root perf report --stdio -i "$data" --percent-limit 0.5 \
          > "$PERF_REPORT_DIR/$stem.report.txt" 2>&1 || STATUS=1
        run_as_root perf annotate --stdio -i "$data" \
          > "$PERF_REPORT_DIR/$stem.annotate.txt" 2>&1 || STATUS=1
      done
      shopt -u nullglob
    fi
  fi
fi

# Benchmarks execute with root; restore only this unique run's output subtree.
for root_written in "$RUN_DIR/runtime-profile" "$RUN_DIR/runtime-stress" "$RUN_DIR/profile-work"; do
  if [[ -e "$root_written" && $EUID -ne 0 ]]; then
    sudo chown -R "$(id -u):$(id -g)" "$root_written" || STATUS=1
  fi
done

python3 - "$AUDIT_DIR" "$RUN_ID" "$RUN_DIR" "$STATUS" "$RUN_PROFILE" "$RUN_STRESS" "$PERF_OK" <<'PY'
import hashlib, sys
from pathlib import Path
root=Path(sys.argv[1]); run_id=sys.argv[2]; run_dir=Path(sys.argv[3])
status, profile, stress, perf = sys.argv[4:8]
def digest(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()
(root / 'SHA256SUMS').write_text(''.join(
    f"{digest(p)}  {p.relative_to(root)}\n"
    for p in sorted(root.rglob('*')) if p.is_file() and p.name != 'SHA256SUMS'
), encoding='utf-8')
(run_dir / 'reports' / 'followup-summary.txt').write_text(
    f"run_id={run_id}\naudit_dir={root}\nprofile={profile}\nstress={stress}\nperf_available={perf}\nstatus={status}\n",
    encoding='utf-8')
PY

if (( DO_ARCHIVE )); then
  [[ -x "$SCRIPT_DIR/pack-results.sh" ]] || fail 'pack-results.sh is missing next to continue-audit.sh'
  "$SCRIPT_DIR/pack-results.sh" "$AUDIT_DIR" --include-perf-data --output "$AUDIT_DIR.analysis-bundle-$RUN_ID.tar.gz"
fi

cat "$RUN_DIR/reports/followup-summary.txt"
printf 'followup_run_dir=%s\n' "$RUN_DIR"
exit "$STATUS"
