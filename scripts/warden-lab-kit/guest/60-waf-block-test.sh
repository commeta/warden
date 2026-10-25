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
# 127.0.0.1 is normal/allowlisted; 127.0.0.2 is reserved and must not be allowlisted.
wardenctl unblock "$ATTACKER_IP" >/dev/null 2>&1 || true
probe "$ATTACKER_IP" attacker-preflight "$BASE/health.php" 200 || lab_die 'The alternate loopback source cannot reach the service; no conclusion can be drawn.'
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
nft list table inet warden 2>/dev/null | grep -Fq "$ATTACKER_IP" && TABLE_HAS_IP=1 || true
wardenctl events -n 100 2>/dev/null | grep -Eq 'security\.waf_attack|action\.block_ip' && EVENT_FOUND=1 || true
if (( BLOCKED == 0 || TABLE_HAS_IP == 0 || EVENT_FOUND == 0 )) || [[ "$CONTROL_CODE" != 200 ]]; then
  cat >&2 <<HINT
Active block acceptance failed. Inspect:
  sudo wardenctl status
  sudo wardenctl events -n 100
  sudo wardenctl blocklist
  sudo nft list table inet warden
Expected: source $ATTACKER_IP is blocked, source $LAB_IP still returns HTTP 200,
and Warden event/action evidence plus an nftables blocklist entry.
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
