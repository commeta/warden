#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/lab-common.sh
source "$ROOT/lib/lab-common.sh"
lab_load_config "$ROOT"; lab_validate_config
[[ $# -eq 0 ]] || lab_die "This test is pinned to LAB_IP=${LAB_IP}; no target argument is accepted."
command -v curl >/dev/null || lab_die 'curl is required'
BASE="http://${LAB_IP}"
probe() {
  local label="$1" url="$2" expected="$3" code
  code="$(curl --interface "$LAB_IP" --noproxy '*' -k -sS --connect-timeout 3 --max-time 8 -o /dev/null -w '%{http_code}' "$url" 2>/dev/null || true)"
  printf '%-18s HTTP %s (expected %s)\n' "$label" "$code" "$expected"
  [[ "$code" == "$expected" ]]
}
failed=0
probe health "$BASE/health.php" 200 || failed=1
probe https-health "https://${LAB_IP}/health.php" 200 || failed=1
probe xss "$BASE/xss.php?q=%3Cscript%3Ealert(1)%3C/script%3E" 403 || failed=1
probe sqli "$BASE/sqli.php?id=1%20OR%201=1" 403 || failed=1
probe traversal "$BASE/traversal.php?file=../../../../../etc/passwd" 403 || failed=1
# Five distinct ModSecurity-denied transactions cross Warden's block_after threshold.
probe xss-repeat "$BASE/xss.php?q=%3Cscript%3Ealert(2)%3C/script%3E" 403 || failed=1
probe sqli-repeat "$BASE/sqli.php?id=2%20OR%201=1" 403 || failed=1
if (( failed )); then
  cat >&2 <<'HINT'
WAF smoke test failed. Inspect services/configuration:
  sudo ./guest/30-validate.sh
  sudo apachectl configtest && sudo nginx -t
  sudo tail -n 80 /var/log/apache2/error.log /var/log/apache2/modsec_audit.log
  sudo nft list table inet lab_filter
HINT
  exit 1
fi
if [[ -r /var/log/apache2/modsec_audit.log ]] && ! grep -q -- '-A--' /var/log/apache2/modsec_audit.log; then echo 'No serial ModSecurity audit transaction found.' >&2; exit 1; fi
echo 'Local WAF smoke tests passed.'
if command -v wardenctl >/dev/null && systemctl is-active --quiet wardend.service; then wardenctl events -n 30 || true; fi
