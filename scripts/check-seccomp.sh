#!/usr/bin/env bash
# Verify that the systemd unit's SystemCallFilter allows every syscall the
# daemon (and the helper programs it runs: nft, journalctl, apt-get, systemctl)
# actually makes. Runs wardend under strace with a sandboxed configuration,
# exercises the main code paths, then compares against the expanded filter.
#
#   sudo ./scripts/check-seccomp.sh [path/to/wardend] [seconds]
#
# Requires: root, strace, systemd-analyze, python3, pgrep, realpath.
# Exit 1 if the trace finds a syscall or address family not allowed by the unit.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
BIN="${1:-$ROOT/target/release/wardend}"
SECS="${2:-25}"
UNIT="${UNIT:-$ROOT/packaging/systemd/wardend.service}"
TABLE="warden-seccomp-check"
W=""
TRACER=""

fail() {
    printf 'check-seccomp.sh: %s\n' "$*" >&2
    exit 2
}

[[ "$EUID" -eq 0 ]] ||
    fail "run as root (sudo ./scripts/check-seccomp.sh)"

for t in strace systemd-analyze python3 pgrep realpath; do
    command -v "$t" >/dev/null 2>&1 ||
        fail "missing required command: $t"
done

[[ "$SECS" =~ ^[1-9][0-9]*$ ]] ||
    fail "seconds must be a positive integer: $SECS"

[[ -x "$BIN" ]] ||
    fail "binary is not executable: $BIN (build with cargo build --release)"

[[ -f "$UNIT" ]] ||
    fail "systemd unit not found: $UNIT"

BIN="$(realpath -- "$BIN")"
UNIT="$(realpath -- "$UNIT")"
CTL="$(dirname -- "$BIN")/wardenctl"
W="$(mktemp -d /tmp/warden-seccomp.XXXXXX)"

# Find only the test daemon. The strace process also has the binary and config
# path in argv, so its PID must explicitly be excluded.
daemon_pids() {
    local pid

    while IFS= read -r pid; do
        if [[ -n "$pid" && "$pid" != "$TRACER" ]]; then
            printf '%s\n' "$pid"
        fi
    done < <(
        pgrep -f -- "$BIN --config $W/w.toml" 2>/dev/null || true
    )
}

stop_daemon() {
    local pid
    local -a pids=()

    mapfile -t pids < <(daemon_pids)

    for pid in "${pids[@]}"; do
        kill -TERM "$pid" >/dev/null 2>&1 || true
    done

    # Give wardend a moment to exit cleanly.
    for _ in {1..30}; do
        mapfile -t pids < <(daemon_pids)

        if ((${#pids[@]} == 0)); then
            break
        fi

        sleep 0.1
    done

    # Force-stop only this test instance if graceful shutdown did not work.
    mapfile -t pids < <(daemon_pids)

    for pid in "${pids[@]}"; do
        kill -KILL "$pid" >/dev/null 2>&1 || true
    done

    # Let strace reap its tracees and flush the output file.
    if [[ -n "$TRACER" ]]; then
        wait "$TRACER" 2>/dev/null || true
        TRACER=""
    fi
}

cleanup() {
    local rc=$?

    # Avoid recursion and preserve the actual test result.
    trap - EXIT INT TERM

    stop_daemon || true

    # The daemon may never have created the dedicated table. Missing-table
    # cleanup is not a seccomp failure and must not change the exit status.
    if command -v nft >/dev/null 2>&1; then
        nft delete table inet "$TABLE" >/dev/null 2>&1 || true
    fi

    if [[ "${KEEP:-0}" == 1 ]]; then
        printf 'kept test files: %s\n' "$W"
    else
        rm -rf -- "$W" || true
    fi

    exit "$rc"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$W/www/uploads" "$W/old" "$W/state" "$W/run"

printf '%s\n' '<?php echo 1;' > "$W/www/index.php"
: > "$W/www/access.log"
: > "$W/auth.log"

head -c 2048 /dev/urandom > "$W/old/a.gz"
touch -d '3 days ago' "$W/old/a.gz"

cat > "$W/w.toml" <<EOF_CONFIG
[daemon]
# Run actions for real so helpers (nft, journalctl, apt-get) are traced too.
# All filesystem changes are isolated under $W, except the dedicated nft table.
dry_run = false
state_dir = "$W/state"
runtime_dir = "$W/run"
control_socket = "$W/run/control.sock"

[metrics]
listen = "127.0.0.1:19199"

[events]
path = "$W/events.jsonl"

[actions]
quarantine_dir = "$W/state/q"
snapshot_dir = "$W/state/snap"
snapshot_min_interval = "1s"

[actions.firewall]
table = "$TABLE"

[disk]
interval = "3s"
warning_percent = 0.5
critical_percent = 1.0
cleanup_target_percent = 0
cleanup = [
  { do = "journal_vacuum", max_size = "100GiB" },
  "apt_clean",
  { do = "delete_old", paths = ["$W/old/*.gz"], older_than = "1d" }
]

[auth]
source = "file"
auth_log = "$W/auth.log"
ssh_max_failures = 2

[process]
scan_interval = "3s"

[integrity]
interval = "5s"
suid_interval = "1s"
suid_paths = ["$W"]

[[health.check]]
name = "self-metrics"
type = "http"
url = "http://127.0.0.1:19199/health"
interval = "3s"

[[fim.site]]
name = "s"
root = "$W/www"
access_log = "$W/www/access.log"
EOF_CONFIG

echo "==> tracing $BIN for ${SECS}s"

strace -f -qq -o "$W/trace" \
    "$BIN" --config "$W/w.toml" >"$W/daemon.log" 2>&1 &
TRACER=$!

ready=0

for _ in {1..40}; do
    if [[ -S "$W/run/control.sock" ]]; then
        ready=1
        break
    fi

    if ! kill -0 "$TRACER" 2>/dev/null; then
        break
    fi

    sleep 0.25
done

if [[ "$ready" != 1 ]] || ! kill -0 "$TRACER" 2>/dev/null; then
    echo "wardend did not start under strace:" >&2
    cat "$W/daemon.log" >&2
    exit 1
fi

sleep 3

printf '%s\n' '<?php system($_GET["c"]);' > "$W/www/uploads/x.php"

for i in 1 2; do
    printf \
        'Oct 20 12:00:0%s h sshd[1]: Failed password for root from 192.0.2.9 port 1%s ssh2\n' \
        "$i" "$i" >> "$W/auth.log"
done

# Exercise the local control interface where wardenctl is available.
if [[ -x "$CTL" ]]; then
    "$CTL" --socket "$W/run/control.sock" status \
        >/dev/null 2>&1 || true

    "$CTL" --socket "$W/run/control.sock" top \
        >/dev/null 2>&1 || true

    "$CTL" --socket "$W/run/control.sock" scores \
        >/dev/null 2>&1 || true

    "$CTL" --socket "$W/run/control.sock" fim scan \
        >/dev/null 2>&1 || true

    "$CTL" --socket "$W/run/control.sock" snapshot seccomp-check \
        >/dev/null 2>&1 || true

    "$CTL" --socket "$W/run/control.sock" blocklist \
        >/dev/null 2>&1 || true
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl list-units --state=failed --no-pager \
        >/dev/null 2>&1 || true
fi

sleep "$SECS"

if ! kill -0 "$TRACER" 2>/dev/null; then
    echo "wardend exited during the trace:" >&2
    cat "$W/daemon.log" >&2
    exit 1
fi

# Stop the daemon and wait for strace to flush its output before parsing it.
stop_daemon

python3 -I - "$W/trace" "$UNIT" <<'PY'
import re
import subprocess
import sys

trace, unit = sys.argv[1], sys.argv[2]


def expand(group, seen):
    if group in seen:
        return set()

    seen.add(group)

    proc = subprocess.run(
        ["systemd-analyze", "syscall-filter", group],
        capture_output=True,
        text=True,
        check=False,
    )

    if proc.returncode != 0:
        detail = (
            proc.stderr.strip()
            or proc.stdout.strip()
            or f"exit {proc.returncode}"
        )
        raise SystemExit(
            f"check-seccomp.sh: cannot expand syscall group {group}: {detail}"
        )

    out = re.sub(r"\x1b\[[0-9;]*m", "", proc.stdout)
    result = set()

    # systemd-analyze prints a heading first. The remaining non-comment lines
    # are syscall-group names (starting with @) or individual syscalls.
    for line in out.splitlines()[1:]:
        item = line.strip()

        if not item or item.startswith("#"):
            continue

        if item.startswith("@"):
            result.update(expand(item, seen))
        else:
            result.add(item)

    return result


allow, deny = set(), set()
has_filter = False

with open(unit, encoding="utf-8") as unit_file:
    for line in unit_file:
        line = line.strip()

        if not line.startswith("SystemCallFilter="):
            continue

        has_filter = True
        value = line.split("=", 1)[1].strip()

        if not value:
            allow.clear()
            deny.clear()
            continue

        inverted = value.startswith("~")
        items = value.lstrip("~").split()
        target = deny if inverted else allow

        for item in items:
            if item.startswith("@"):
                target.update(expand(item, set()))
            else:
                target.add(item)

if not has_filter:
    raise SystemExit(
        "check-seccomp.sh: unit has no SystemCallFilter= directive"
    )

# If an allow-list is present, subtract denied groups from it. If the unit
# has only an inverted filter, all syscalls except the deny-list are allowed.
if allow:
    allowed = allow - deny
    allowed_description = str(len(allowed))
elif deny:
    allowed = None
    allowed_description = "all except deny-list"
else:
    allowed = set()
    allowed_description = "0 (empty filter)"

families = None

with open(unit, encoding="utf-8") as unit_file:
    for line in unit_file:
        line = line.strip()

        if not line.startswith("RestrictAddressFamilies="):
            continue

        value = line.split("=", 1)[1].strip().split()

        if not value:
            families = None
            continue

        if value[0].startswith("~"):
            raise SystemExit(
                "check-seccomp.sh: a deny-list RestrictAddressFamilies "
                "is not supported"
            )

        if families is None:
            families = set()

        families.update(value)

used, opened = set(), set()

with open(trace, encoding="utf-8", errors="replace") as trace_file:
    for line in trace_file:
        match = re.match(r"\d+\s+(?:<\.\.\. )?([a-z_0-9]+)[( ]", line)

        if match and match.group(1) not in (
            "exited",
            "killed",
            "resumed",
        ):
            used.add(match.group(1))

        family = re.match(
            r"\d+\s+socket(?:pair)?\((AF_[A-Z0-9]+),",
            line,
        )

        if family:
            opened.add(family.group(1))

if not used:
    raise SystemExit(
        "check-seccomp.sh: no syscalls parsed from strace output; "
        "refusing a vacuous pass"
    )

if allowed is None:
    missing = sorted(used & deny)
else:
    missing = sorted(used - allowed)

print(
    f"syscalls used: {len(used)}   "
    f"allowed by unit: {allowed_description}"
)
print("address families opened:", " ".join(sorted(opened)) or "-")

bad = False

if missing:
    print("NOT ALLOWED by the unit filter:", " ".join(missing))
    bad = True

if families is not None and opened - families:
    print(
        "NOT ALLOWED by RestrictAddressFamilies:",
        " ".join(sorted(opened - families)),
    )
    bad = True

if bad:
    raise SystemExit(1)

print(
    "OK: every syscall and address family used by wardend "
    "and its helpers is allowed"
)
PY
