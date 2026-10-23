#!/usr/bin/env bash
# Verify that the systemd unit's SystemCallFilter allows every syscall the
# daemon (and the helper programs it runs: nft, journalctl, apt-get, systemctl)
# actually makes. Runs wardend under strace with a sandboxed configuration,
# exercises the main code paths, then compares against the expanded filter.
#
#   sudo ./scripts/check-seccomp.sh [path/to/wardend] [seconds]
#
# Requires: root, strace, systemd-analyze, python3. Exit 1 if a syscall is missing.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-$ROOT/target/release/wardend}"
SECS="${2:-25}"
UNIT="${UNIT:-$ROOT/packaging/systemd/wardend.service}"
CTL="$(dirname "$BIN")/wardenctl"

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 2; }
for t in strace systemd-analyze python3; do command -v "$t" >/dev/null || { echo "missing $t" >&2; exit 2; }; done
[ -x "$BIN" ] || { echo "build first: cargo build --release" >&2; exit 2; }

W="$(mktemp -d /tmp/warden-seccomp.XXXXXX)"
trap 'pkill -TERM -f "$BIN --config $W/w.toml" 2>/dev/null || true; command -v nft >/dev/null && nft delete table inet warden-seccomp-check 2>/dev/null; if [ "${KEEP:-0}" = 1 ]; then echo "kept $W"; else rm -rf "$W"; fi' EXIT
mkdir -p "$W"/{www/uploads,old,state,run}
echo '<?php echo 1;' > "$W/www/index.php"; : > "$W/www/access.log"; : > "$W/auth.log"
head -c 2048 /dev/urandom > "$W/old/a.gz"; touch -d '3 days ago' "$W/old/a.gz"
cat > "$W/w.toml" <<EOF
[daemon]
# run the actions for real (0.13 made dry-run the default): their helpers
# (nft, journalctl, apt-get) must be traced too. Everything they touch is
# under $W or in the dedicated nft table removed on exit.
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
table = "warden-seccomp-check"
[disk]
interval = "3s"
warning_percent = 0.5
critical_percent = 1.0
cleanup_target_percent = 0
cleanup = [ { do = "journal_vacuum", max_size = "100GiB" }, "apt_clean", { do = "delete_old", paths = ["$W/old/*.gz"], older_than = "1d" } ]
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
EOF

echo "==> tracing $BIN for ${SECS}s"
strace -f -qq -o "$W/trace" "$BIN" --config "$W/w.toml" >"$W/daemon.log" 2>&1 &
TRACER=$!
for _ in $(seq 1 40); do [ -S "$W/run/control.sock" ] && break; sleep 0.25; done
# A daemon that refused its configuration or crashed traces almost nothing and
# would make the comparison below vacuous.
if ! [ -S "$W/run/control.sock" ] || ! kill -0 "$TRACER" 2>/dev/null; then
    echo "wardend did not start under strace:" >&2; cat "$W/daemon.log" >&2; exit 1
fi
sleep 3
echo '<?php system($_GET["c"]);' > "$W/www/uploads/x.php"
for i in 1 2; do echo "Oct 20 12:00:0$i h sshd[1]: Failed password for root from 192.0.2.9 port 1$i ssh2" >> "$W/auth.log"; done
if [ -x "$CTL" ]; then
    for c in status top scores "fim scan" "snapshot seccomp-check" blocklist; do "$CTL" --socket "$W/run/control.sock" $c >/dev/null 2>&1 || true; done
fi
command -v systemctl >/dev/null && systemctl list-units --state=failed --no-pager >/dev/null 2>&1 || true
sleep "$SECS"
kill -0 "$TRACER" 2>/dev/null || { echo "wardend exited during the trace:" >&2; cat "$W/daemon.log" >&2; exit 1; }
pkill -TERM -f "$BIN --config $W/w.toml" || true
sleep 2

python3 -I - "$W/trace" "$UNIT" <<'PY'
import re, subprocess, sys
trace, unit = sys.argv[1], sys.argv[2]

def expand(group, seen):
    if group in seen: return set()
    seen.add(group)
    out = subprocess.run(["systemd-analyze", "syscall-filter", group], capture_output=True, text=True).stdout
    out = re.sub(r"\x1b\[[0-9;]*m", "", out)
    res = set()
    for line in out.splitlines()[1:]:
        t = line.strip()
        if not t or t.startswith("#"): continue
        res |= expand(t, seen) if t.startswith("@") else {t}
    return res

allow, deny = set(), set()
for line in open(unit):
    line = line.strip()
    if not line.startswith("SystemCallFilter="): continue
    val = line.split("=", 1)[1]
    neg = val.startswith("~")
    for item in val.lstrip("~").split():
        s = expand(item, set()) if item.startswith("@") else {item}
        (deny if neg else allow).update(s)
allowed = allow - deny

families = None  # RestrictAddressFamilies (None = not restricted)
for line in open(unit):
    line = line.strip()
    if line.startswith("RestrictAddressFamilies="):
        val = line.split("=", 1)[1].split()
        if val and val[0].startswith("~"):
            sys.exit("check-seccomp.sh: a deny-list RestrictAddressFamilies is not supported")
        families = (families or set()) | set(val)

used, opened = set(), set()
for line in open(trace, errors="replace"):
    m = re.match(r"\d+\s+(?:<\.\.\. )?([a-z_0-9]+)[( ]", line)
    if m and m.group(1) not in ("exited", "killed", "resumed"):
        used.add(m.group(1))
    f = re.match(r"\d+\s+socket(?:pair)?\((AF_[A-Z0-9]+),", line)
    if f:
        opened.add(f.group(1))
missing = sorted(used - allowed)
print(f"syscalls used: {len(used)}   allowed by unit: {len(allowed)}")
print("address families opened:", " ".join(sorted(opened)) or "-")
bad = False
if missing:
    print("NOT ALLOWED by the unit filter:", " ".join(missing))
    bad = True
if families is not None and opened - families:
    print("NOT ALLOWED by RestrictAddressFamilies:", " ".join(sorted(opened - families)))
    bad = True
if bad:
    sys.exit(1)
print("OK: every syscall and address family used by wardend and its helpers is allowed")
PY
