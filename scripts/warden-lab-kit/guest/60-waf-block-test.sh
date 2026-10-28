#!/usr/bin/env bash
# Deliberately active Warden integration test. Run only on a dedicated lab system after review.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/lab-common.sh
source "$ROOT/lib/lab-common.sh"
lab_load_config "$ROOT"; lab_validate_config
[[ $# -eq 0 ]] || lab_die 'No target argument is accepted.'
[[ $EUID -eq 0 ]] || lab_die "Run: sudo env ACK_WARDEN_ENFORCEMENT=YES $0"
[[ "${ACK_WARDEN_ENFORCEMENT:-}" == YES ]] || lab_die 'Set ACK_WARDEN_ENFORCEMENT=YES only after reviewing active Warden actions.'
command -v curl >/dev/null || lab_die 'curl is required'
command -v wardenctl >/dev/null || lab_die 'wardenctl is required; install Warden first'
systemctl is-active --quiet wardend.service || lab_die 'wardend.service is not active'
MAINCFG=/etc/warden/warden.toml
[[ -r "$MAINCFG" ]] || lab_die "Cannot read $MAINCFG"
grep -Eq '^[[:space:]]*dry_run[[:space:]]*=[[:space:]]*false([[:space:]]*(#.*)?)?$' "$MAINCFG" || lab_die 'Warden must explicitly have dry_run = false for this test. Back up, change, validate, and reload the config first.'
wardend --check-config --config "$MAINCFG" || lab_die 'Warden configuration is invalid'
BASE="http://${LAB_IP}"
probe() {
  local source_ip="$1" label="$2" url="$3" expected="$4" code
  code="$(curl --interface "$source_ip" --noproxy '*' -k -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"
  printf '%-22s source=%-15s HTTP %s (expected %s)\n' "$label" "$source_ip" "$code" "$expected"
  [[ "$code" == "$expected" ]]
}
# The evidence must be this run's, about this address (L3 of the 0.14.2
# review: an old waf_attack of any address among the last 100 events passed).
last_event_id() {
  wardenctl --json events -n 1 2>/dev/null | python3 -c 'import json,sys
try:
    v = json.load(sys.stdin)
    print(max([e.get("id", 0) for e in v] or [0]))
except ValueError:
    print(0)'
}
# 127.0.0.1 is normal/allowlisted; 127.0.0.2 is reserved and must not be allowlisted.
wardenctl unblock "$ATTACKER_IP" >/dev/null 2>&1 || true
probe "$ATTACKER_IP" attacker-preflight "$BASE/health.php" 200 || lab_die 'The alternate loopback source cannot reach the service; no conclusion can be drawn.'
START_ID="$(last_event_id)"
[[ "$START_ID" =~ ^[0-9]+$ ]] || lab_die 'Cannot read the event journal through wardenctl'
failed=0
probe "$ATTACKER_IP" xss "$BASE/xss.php?q=%3Cscript%3Ealert(61)%3C/script%3E" 403 || failed=1
probe "$ATTACKER_IP" sqli "$BASE/sqli.php?id=61%20OR%201=1" 403 || failed=1
probe "$ATTACKER_IP" traversal "$BASE/traversal.php?file=../../../../../etc/passwd" 403 || failed=1
probe "$ATTACKER_IP" xss-repeat "$BASE/xss.php?q=%3Cscript%3Ealert(62)%3C/script%3E" 403 || failed=1
probe "$ATTACKER_IP" sqli-repeat "$BASE/sqli.php?id=62%20OR%201=1" 403 || failed=1
(( failed == 0 )) || lab_die 'One or more ModSecurity probes did not return 403.'
BLOCKED=0
for _ in $(seq 1 15); do
  CODE="$(curl --interface "$ATTACKER_IP" --noproxy '*' -sS --connect-timeout 1 --max-time 2 -o /dev/null -w '%{http_code}' "$BASE/health.php" 2>/dev/null || true)"
  if [[ "$CODE" == 000 ]]; then BLOCKED=1; break; fi
  sleep 1
done
printf '%-22s source=%-15s HTTP %s (expected 000)\n' 'post-block-health' "$ATTACKER_IP" "${CODE:-000}"
CONTROL_CODE="$(curl --interface "$LAB_IP" --noproxy '*' -sS --connect-timeout 2 --max-time 5 -o /dev/null -w '%{http_code}' "$BASE/health.php" 2>/dev/null || true)"
printf '%-22s source=%-15s HTTP %s (expected 200)\n' 'control-health' "$LAB_IP" "$CONTROL_CODE"
TABLE_HAS_IP=0; EVENT_FOUND=0
# exactly this address in Warden's IPv4 set (not 127.0.0.20 in a text listing)
nft -j list set inet warden blocklist4 2>/dev/null | python3 -c 'import json,sys
ip = sys.argv[1]
try:
    v = json.load(sys.stdin)
except ValueError:
    sys.exit(1)
vals = []
for it in v.get("nftables", []):
    for e in it.get("set", {}).get("elem", []):
        x = e.get("elem", e) if isinstance(e, dict) else e
        vals.append(x.get("val") if isinstance(x, dict) else x)
sys.exit(0 if ip in vals else 1)' "$ATTACKER_IP" && TABLE_HAS_IP=1 || true
# a waf_attack about this address and the block of it, both after START_ID
wardenctl --json events -n 2000 2>/dev/null | python3 -c 'import json,sys
since, ip = int(sys.argv[1]), sys.argv[2]
try:
    evs = [e for e in json.load(sys.stdin) if e.get("id", 0) > since]
except ValueError:
    sys.exit(1)
addr = lambda e: (e.get("subject") or {}).get("addr") or (e.get("details") or {}).get("ip")
attack = [e for e in evs if e["kind"] == "security.waf_attack" and addr(e) == ip]
block = [e for e in evs if e["kind"] == "action.block_ip" and addr(e) == ip and (e.get("details") or {}).get("status") == "done"]
for e in attack[:1] + block[:1]:
    print("  evidence:", e["kind"], "id=%s:" % e["id"], e["title"])
sys.exit(0 if attack and block else 1)' "$START_ID" "$ATTACKER_IP" && EVENT_FOUND=1 || true
if (( BLOCKED == 0 || TABLE_HAS_IP == 0 || EVENT_FOUND == 0 )) || [[ "$CONTROL_CODE" != 200 ]]; then
  cat >&2 <<HINT
Active block acceptance failed. Inspect:
  sudo wardenctl status
  sudo wardenctl events -n 100
  sudo wardenctl blocklist
  sudo nft list table inet warden
Expected: source $ATTACKER_IP is blocked, source $LAB_IP still returns HTTP 200,
a security.waf_attack and a done action.block_ip about $ATTACKER_IP after event
id $START_ID, and $ATTACKER_IP in the nftables set inet warden blocklist4.
After review restore dry_run=true and run: sudo wardenctl unblock $ATTACKER_IP
HINT
  exit 1
fi
cat <<DONE
Active Warden block test passed.
Immediately restore dry_run = true in $MAINCFG:
  sudo cp -a $MAINCFG.pre-enforce $MAINCFG  # if you made this backup
  sudo wardend --check-config --config $MAINCFG
  sudo systemctl reload wardend
  sudo wardenctl unblock $ATTACKER_IP
Then verify: sudo wardenctl status
DONE
