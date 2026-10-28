#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/lab-common.sh
source "$ROOT/lib/lab-common.sh"
lab_load_config "$ROOT"
lab_validate_config
[[ $EUID -eq 0 ]] || lab_die "Run: sudo $0"
lab_require_loopback
FAIL=0
check() { printf '\n== %s ==\n' "$*"; if "$@"; then :; else FAIL=1; fi; }
check systemctl is-active nginx
check systemctl is-active apache2
check systemctl is-active mysql
check apachectl configtest
check nginx -t
check nft --version

printf '\n== Native nftables local-service guard ==\n'
NFT_TABLE="$(nft list table inet lab_filter 2>/dev/null || true)"
if [[ -z "$NFT_TABLE" ]]; then echo 'Missing inet lab_filter base policy' >&2; FAIL=1; else printf '%s\n' "$NFT_TABLE"; fi
NFT_CHAIN="$(nft list chain inet lab_filter input 2>/dev/null || true)"
if [[ -z "$NFT_CHAIN" ]]; then
  echo 'Missing inet lab_filter input chain' >&2; FAIL=1
else
  printf '%s\n' "$NFT_CHAIN"
  grep -Fq 'iifname != "lo" tcp dport { 80, 443, 8080, 3306 }' <<< "$NFT_CHAIN" || { echo 'Missing non-loopback service-port drop rule' >&2; FAIL=1; }
  grep -Fq 'drop' <<< "$NFT_CHAIN" || { echo 'Missing service-port drop action' >&2; FAIL=1; }
fi
check systemctl is-active warden-lab-nftables.service
if systemctl is-active --quiet nftables.service; then
  echo 'The stock nftables.service is active; inspect it because a global ruleset load may erase dynamic Warden rules.' >&2; FAIL=1
fi

printf '\n== Apache modules ==\n'
APACHE_MODULES="$(apachectl -M 2>&1)" || FAIL=1
printf '%s\n' "$APACHE_MODULES" | grep -E 'security2_module|php_module|mpm_prefork_module|remoteip_module' || true
for MODULE in security2_module php_module mpm_prefork_module remoteip_module; do
  if ! grep -Fq "$MODULE" <<< "$APACHE_MODULES"; then echo "Missing Apache module: $MODULE" >&2; FAIL=1; fi
done
printf '\n== ModSecurity directives ==\n'
grep -E '^[[:space:]]*SecRuleEngine|^[[:space:]]*SecAuditLog(Type|Parts)?[[:space:]]' /etc/modsecurity/modsecurity.conf || FAIL=1
grep -Eq '^[[:space:]]*SecRuleEngine[[:space:]]+On([[:space:]]|$)' /etc/modsecurity/modsecurity.conf || FAIL=1
grep -Eq '^[[:space:]]*SecAuditLogType[[:space:]]+Serial([[:space:]]|$)' /etc/modsecurity/modsecurity.conf || FAIL=1
grep -Eq '^[[:space:]]*SecAuditLog[[:space:]]+/var/log/apache2/modsec_audit\.log([[:space:]]|$)' /etc/modsecurity/modsecurity.conf || FAIL=1
test -r /usr/share/modsecurity-crs/owasp-crs.load || FAIL=1
SECURITY2_CONF=/etc/apache2/mods-available/security2.conf
CRS_INCLUDE_COUNT="$(grep -Ec '^[[:space:]]*IncludeOptional[[:space:]]+/usr/share/modsecurity-crs/owasp-crs\.load([[:space:]]|$)' "$SECURITY2_CONF" 2>/dev/null || true)"
if [[ "$CRS_INCLUDE_COUNT" != 1 ]]; then echo "Expected one packaged CRS loader include; found $CRS_INCLUDE_COUNT" >&2; FAIL=1; fi
if grep -Eq '^[[:space:]]*Include(Optional)?[[:space:]]+/usr/share/modsecurity-crs/rules/\*\.conf' "$SECURITY2_CONF"; then echo 'CRS rules are included twice' >&2; FAIL=1; fi
[[ ! -e /etc/apache2/conf-enabled/warden-lab-crs.conf ]] || { echo 'Legacy duplicate CRS include still exists' >&2; FAIL=1; }

printf '\n== Listener boundaries ==\n'
LISTENERS="$(ss -H -lntp)"
printf '%s\n' "$LISTENERS" | awk '$4=="127.0.0.1:80" {print; ok=1} END {exit !ok}' || FAIL=1
printf '%s\n' "$LISTENERS" | awk '$4=="127.0.0.1:443" {print; ok=1} END {exit !ok}' || FAIL=1
printf '%s\n' "$LISTENERS" | awk '$4=="127.0.0.1:8080" {print; ok=1} END {exit !ok}' || FAIL=1
printf '%s\n' "$LISTENERS" | awk '$4=="127.0.0.1:3306" {print; ok=1} END {exit !ok}' || FAIL=1
if printf '%s\n' "$LISTENERS" | awk '$1=="LISTEN" {a=$4; if (a ~ /:8080$/ && a!="127.0.0.1:8080") {print; bad=1}; if (a ~ /:3306$/ && a!="127.0.0.1:3306") {print; bad=1}; if (a ~ /:80$/ && a!="127.0.0.1:80") {print; bad=1}; if (a ~ /:443$/ && a!="127.0.0.1:443") {print; bad=1}} END {exit !bad}'; then
  echo 'ERROR: a lab service is listening beyond loopback.' >&2; FAIL=1
fi

printf '\n== Local backend health ==\n'
CODE="$(curl --interface "$LAB_IP" --noproxy '*' -sS --max-time 5 -o /dev/null -w '%{http_code}' "http://127.0.0.1:8080/health.php" || true)"
echo "Apache backend HTTP status=$CODE"; [[ "$CODE" == 200 ]] || FAIL=1

printf '\n== MySQL app credentials (read-only query) ==\n'
for item in /etc/warden-lab /etc/warden-lab/db.php /etc/warden-lab/db-password; do
  if [[ -e "$item" ]]; then stat -c '%U:%G %a %n' "$item"; else echo "Missing $item" >&2; FAIL=1; fi
done
[[ "$(stat -c '%U:%G:%a' /etc/warden-lab 2>/dev/null || true)" == 'root:www-data:710' ]] || { echo 'Expected /etc/warden-lab root:www-data mode 0710' >&2; FAIL=1; }
[[ "$(stat -c '%U:%G:%a' /etc/warden-lab/db.php 2>/dev/null || true)" == 'root:www-data:640' ]] || { echo 'Expected db.php root:www-data mode 0640' >&2; FAIL=1; }
[[ "$(stat -c '%U:%G:%a' /etc/warden-lab/db-password 2>/dev/null || true)" == 'root:root:600' ]] || { echo 'Expected db-password root:root mode 0600' >&2; FAIL=1; }
if ! runuser -u www-data -- test -r /etc/warden-lab/db.php; then
  echo 'www-data cannot read db.php; check directory and file group/permissions.' >&2; FAIL=1
elif runuser -u www-data -- test -r /etc/warden-lab/db-password; then
  echo 'Security error: www-data can read the password file.' >&2; FAIL=1
else
  if runuser -u www-data -- php -d display_errors=1 -d error_reporting=-1 <<'PHPTEST'
<?php
require '/etc/warden-lab/db.php';
mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);
$db = new mysqli(LAB_DB_HOST, LAB_DB_USER, LAB_DB_PASS, LAB_DB_NAME);
$result = $db->query('SELECT id, title FROM posts ORDER BY id LIMIT 1');
if ($result->num_rows < 1) { fwrite(STDERR, "posts table contains no fixture rows\n"); exit(1); }
$row = $result->fetch_assoc();
echo "MySQL query OK; fixture row id=" . (int)$row['id'] . "\n";
$db->close();
PHPTEST
  then :; else echo 'PHP could not read its config or connect with the read-only app DB account' >&2; FAIL=1; fi
fi

printf '\n== HTTP/WAF local probes ==\n'
# A tag of this run in every probe: the audit-log check below must find these
# requests, not any record left by an earlier run (L3 of the 0.14.2 review).
TAG="wl$(date +%s%N)"
for spec in \
  'health|200|/health.php' \
  "xss|403|/xss.php?q=%3Cscript%3Ealert(1)%3C/script%3E&wlt=${TAG}" \
  "sqli|403|/sqli.php?id=1%20OR%201=1&wlt=${TAG}" \
  "traversal|403|/traversal.php?file=../../../../../etc/passwd&wlt=${TAG}"; do
  NAME="${spec%%|*}"; REST="${spec#*|}"; EXPECTED="${REST%%|*}"; PATH_Q="${REST#*|}"
  EXTRA=(); [[ "$PATH_Q" == /health.php ]] || EXTRA=(--interface "$LAB_IP")
  CODE="$(curl "${EXTRA[@]}" --noproxy '*' -k -sS --max-time 8 -o /dev/null -w '%{http_code}' "http://${LAB_IP}${PATH_Q}" || true)"
  printf '%-12s HTTP %s (expected %s)\n' "$NAME" "$CODE" "$EXPECTED"
  [[ "$CODE" == "$EXPECTED" ]] || FAIL=1
done
printf '\n== ModSecurity audit log ==\n'
ls -lh /var/log/apache2/modsec_audit.log || FAIL=1
TAGGED=0
for _ in 1 2 3 4 5; do
  TAGGED="$(grep -cF -- "wlt=${TAG}" /var/log/apache2/modsec_audit.log || true)"
  (( TAGGED >= 3 )) && break
  sleep 1
done
echo "Audit records of this run's probes: ${TAGGED} (expected 3, tag ${TAG})"
(( TAGGED >= 3 )) || { echo 'The audit log lacks the transactions of these probes' >&2; FAIL=1; }
if command -v wardend >/dev/null; then
  printf '\n== Warden config ==\n'
  wardend --check-config --config /etc/warden/warden.toml || FAIL=1
  wardenctl status || true
  wardenctl doctor || true
fi
if (( FAIL )); then echo 'One or more checks failed; inspect service and ModSecurity logs.' >&2; exit 1; fi
echo 'All validation checks passed. Run guest/40-waf-smoke.sh and guest/50-longrun-smoke.sh for remaining local tests.'
