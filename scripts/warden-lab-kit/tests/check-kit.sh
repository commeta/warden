#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
failures=0
fail() { printf 'FAIL %s\n' "$*" >&2; failures=$((failures+1)); }
printf '== Bash syntax ==\n'
while IFS= read -r -d '' f; do
  if bash -n "$f"; then printf 'OK   %s\n' "${f#"$ROOT"/}"; else fail "bash syntax: ${f#"$ROOT"/}"; fi
done < <(find "$ROOT" -type f \( -name '*.sh' -o -name '*.sh.in' \) -print0)

printf '\n== PHP syntax ==\n'
if command -v php >/dev/null; then
  while IFS= read -r -d '' f; do php -l "$f" >/dev/null || fail "PHP syntax: ${f#"$ROOT"/}"; done < <(find "$ROOT/guest/site" -type f -name '*.php' -print0)
  echo 'OK   guest/site PHP files'
else echo 'SKIP PHP lint: PHP CLI unavailable'; fi

printf '\n== Rendered Nginx configuration ==\n'
if command -v nginx >/dev/null && command -v openssl >/dev/null; then
  T_NGINX="$(mktemp -d)"; trap 'rm -rf "${T_NGINX:-}" "${T_APACHE:-}" "${TMP_PARSER:-}"' EXIT
  mkdir -p "$T_NGINX/logs"
  openssl req -x509 -nodes -newkey rsa:2048 -keyout "$T_NGINX/key.pem" -out "$T_NGINX/cert.pem" -days 1 -subj '/CN=warden-lab.test' -addext 'subjectAltName=IP:127.0.0.1,DNS:warden-lab.test' >/dev/null 2>&1
  sed -e 's/{{LAB_IP}}/127.0.0.1/g' -e "s|/etc/nginx/ssl/warden-lab.crt|$T_NGINX/cert.pem|g" -e "s|/etc/nginx/ssl/warden-lab.key|$T_NGINX/key.pem|g" "$ROOT/guest/config/nginx-site.conf.in" > "$T_NGINX/site.conf"
  cat > "$T_NGINX/nginx.conf" <<EOF_NGINX
worker_processes 1;
pid $T_NGINX/nginx.pid;
error_log $T_NGINX/logs/error.log;
events { worker_connections 128; }
http { include /etc/nginx/mime.types; default_type application/octet-stream; include $T_NGINX/site.conf; }
EOF_NGINX
  if nginx -t -q -c "$T_NGINX/nginx.conf" -p "$T_NGINX/"; then echo 'OK   rendered Nginx site'; else fail 'rendered Nginx site'; fi
  rm -rf "$T_NGINX"; T_NGINX=""
else echo 'SKIP Nginx test: nginx/openssl unavailable'; fi

printf '\n== Rendered Apache configuration ==\n'
if command -v apache2 >/dev/null && [[ -f /usr/lib/apache2/modules/mod_remoteip.so && -f /usr/lib/apache2/modules/mod_headers.so && -f /usr/lib/apache2/modules/mod_mpm_prefork.so ]]; then
  PHP_MODULE="$(find /usr/lib/apache2/modules -maxdepth 1 -type f -name 'libphp*.so' -print -quit)"
  if [[ -n "$PHP_MODULE" ]]; then
    T_APACHE="$(mktemp -d)"; mkdir -p "$T_APACHE/docroot/uploads"
    sed -e 's/{{LAB_IP}}/127.0.0.1/g' -e "s|/var/www/warden-lab/public/uploads|$T_APACHE/docroot/uploads|g" -e "s|/var/www/warden-lab/public|$T_APACHE/docroot|g" "$ROOT/guest/config/apache-vhost.conf.in" > "$T_APACHE/vhost.conf"
    cat > "$T_APACHE/httpd.conf" <<EOF_APACHE
ServerRoot /etc/apache2
ServerName localhost
PidFile $T_APACHE/httpd.pid
ErrorLog $T_APACHE/error.log
Listen 127.0.0.1:8080
User www-data
Group www-data
TypesConfig /etc/mime.types
LoadModule mpm_prefork_module /usr/lib/apache2/modules/mod_mpm_prefork.so
LoadModule authz_core_module /usr/lib/apache2/modules/mod_authz_core.so
LoadModule authz_host_module /usr/lib/apache2/modules/mod_authz_host.so
LoadModule dir_module /usr/lib/apache2/modules/mod_dir.so
LoadModule mime_module /usr/lib/apache2/modules/mod_mime.so
LoadModule remoteip_module /usr/lib/apache2/modules/mod_remoteip.so
LoadModule headers_module /usr/lib/apache2/modules/mod_headers.so
LoadModule php_module $PHP_MODULE
Include $T_APACHE/vhost.conf
EOF_APACHE
    if apache2 -f "$T_APACHE/httpd.conf" -t; then echo 'OK   rendered Apache vhost'; else fail 'rendered Apache vhost'; fi
    rm -rf "$T_APACHE"; T_APACHE=""
  else echo 'SKIP Apache vhost test: mod_php module unavailable'; fi
else echo 'SKIP Apache test: required Apache modules unavailable'; fi

printf '\n== lab.env schema and Warden TOML ==\n'
if ! python3 - "$ROOT" <<'PYTHONCHECK'
from pathlib import Path
import ipaddress, re, sys, tomllib
root=Path(sys.argv[1])
env={}
for n,line in enumerate((root/'lab.env.example').read_text().splitlines(),1):
    if not line.strip() or line.lstrip().startswith('#'): continue
    if not re.fullmatch(r'[A-Z][A-Z0-9_]*=[A-Za-z0-9_./:-]+',line): raise SystemExit(f'lab.env.example:{n}: invalid strict KEY=value')
    k,v=line.split('=',1)
    if k in env: raise SystemExit(f'duplicate key: {k}')
    env[k]=v
required={'LAB_IP','ATTACKER_IP','DB_NAME','DB_USER','DB_PASSWORD','WARDEN_VERSION','WARDEN_DEB_SHA256'}
if set(env) != required: raise SystemExit(f'env keys mismatch: {set(env)^required}')
lab,attacker=ipaddress.IPv4Address(env['LAB_IP']),ipaddress.IPv4Address(env['ATTACKER_IP'])
loop=ipaddress.IPv4Network('127.0.0.0/8')
if lab != ipaddress.IPv4Address('127.0.0.1') or lab not in loop or attacker not in loop or attacker == lab: raise SystemExit('lab addresses must be distinct loopback IPv4 addresses')
if not re.fullmatch(r'[A-Za-z0-9_]{1,32}',env['DB_NAME']) or not re.fullmatch(r'[A-Za-z0-9_]{1,32}',env['DB_USER']): raise SystemExit('unsafe database identifier')
if env['DB_PASSWORD']!='GENERATE' and not re.fullmatch(r'[a-fA-F0-9]{16,128}',env['DB_PASSWORD']): raise SystemExit('unsafe DB password value')
if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+',env['WARDEN_VERSION']) or not re.fullmatch(r'[a-fA-F0-9]{64}',env['WARDEN_DEB_SHA256']): raise SystemExit('invalid Warden version/hash')
template=(root/'guest/config/warden-dropin.toml.in').read_text().replace('{{LAB_IP}}',str(lab))
cfg=tomllib.loads(template)
fw=[ipaddress.ip_network(x) for x in cfg['actions']['firewall']['allowlist']]
auth=[ipaddress.ip_network(x) for x in cfg['auth']['allowlist']]
if any(attacker in n for n in fw+auth): raise SystemExit('active-test source must not be in Warden allowlists')
if not any(lab in n for n in fw+auth): raise SystemExit('routine local source must be allowlisted')
if cfg['waf']['block_after'] != 5 or not cfg['waf']['block']: raise SystemExit('WAF integration threshold/action mismatch')
if cfg['waf']['log'][0]['format'] != 'native': raise SystemExit('ModSecurity log format mismatch')
print('OK strict lab.env schema and local IPs')
print('OK rendered Warden TOML and allowlist separation')
PYTHONCHECK
then fail 'lab.env or Warden TOML checks'; fi

printf '\n== Runtime parser tests ==\n'
TMP_PARSER="$(mktemp -d)"; cp "$ROOT/lab.env.example" "$TMP_PARSER/lab.env"
if bash -c 'source "$1/lib/lab-common.sh"; lab_load_config "$2"' _ "$ROOT" "$TMP_PARSER" >/dev/null 2>&1; then fail 'permissive lab.env mode was accepted'; else echo 'OK   permissive lab.env mode rejected'; fi
chmod 600 "$TMP_PARSER/lab.env"
if bash -c 'set -euo pipefail; source "$1/lib/lab-common.sh"; lab_load_config "$2"; lab_validate_config' _ "$ROOT" "$TMP_PARSER"; then echo 'OK   strict runtime parser accepts example'; else fail 'valid lab.env rejected'; fi
MARKER="$TMP_PARSER/payload-ran"
printf '\nLAB_IP=$(touch %s)\n' "$MARKER" >> "$TMP_PARSER/lab.env"; chmod 600 "$TMP_PARSER/lab.env"
if bash -c 'source "$1/lib/lab-common.sh"; lab_load_config "$2"' _ "$ROOT" "$TMP_PARSER" >/dev/null 2>&1; then fail 'shell payload accepted'; elif [[ ! -e "$MARKER" ]]; then echo 'OK   shell payload rejected without execution'; else fail 'parser executed shell payload'; fi
cp "$ROOT/lab.env.example" "$TMP_PARSER/lab.env"; printf 'LAB_IP=127.0.0.1\n' >> "$TMP_PARSER/lab.env"; chmod 600 "$TMP_PARSER/lab.env"
if bash -c 'source "$1/lib/lab-common.sh"; lab_load_config "$2"' _ "$ROOT" "$TMP_PARSER" >/dev/null 2>&1; then fail 'duplicate key accepted'; else echo 'OK   duplicate keys rejected'; fi
rm -rf "$TMP_PARSER"; TMP_PARSER=""

printf '\n== Local firewall and wiring checks ==\n'
grep -q 'nftables openssl curl logrotate ca-certificates' "$ROOT/guest/10-install-stack.sh" || fail 'nftables package install missing'
grep -q 'inet lab_filter' "$ROOT/guest/config/nft-base-apply.sh.in" || fail 'base nft table missing'
grep -q 'iifname != "lo" tcp dport { 80, 443, 8080, 3306 }' "$ROOT/guest/config/nft-base-apply.sh.in" || fail 'local-only port guard missing'
if grep -Eq 'flush[[:space:]]+ruleset' "$ROOT/guest/config/nft-base-apply.sh.in"; then fail 'global ruleset flush found'; else echo 'OK   firewall helper does not flush global ruleset'; fi
grep -q 'RemoteIPInternalProxy 127.0.0.1' "$ROOT/guest/config/apache-vhost.conf.in" || fail 'Apache proxy trust boundary missing'
grep -q 'listen {{LAB_IP}}:80' "$ROOT/guest/config/nginx-site.conf.in" || fail 'Nginx local listener missing'
grep -q 'dry_run = true' "$ROOT/guest/20-install-warden.sh" || fail 'Warden dry-run default missing'
grep -Fq '$ROOT/guest/config/warden-dropin.toml.in' "$ROOT/guest/20-install-warden.sh" || fail 'Warden drop-in path is incorrect'
if [[ -d "$ROOT/host" ]]; then fail 'obsolete host-side scripts directory remains'; fi
# (run logs in docs/ quote test names such as `cgroup::tests::containers`)
if grep -RniE 'VirtualBox|VBoxManage|HOSTONLY|HOST_IP|VBOX_|host-only|host-side|host side|хостовая часть|хостовой части|контейнер|container|guest/01-netplan-hostonly|\$ROOT/system/' "$ROOT" --exclude='SHA256SUMS' --exclude='check-kit.sh' --exclude='*.log'; then fail 'legacy virtualization/deployment references remain'; else echo 'OK   no legacy virtualization/deployment references'; fi
grep -q 'runuser -u www-data -- test -r /etc/warden-lab/db.php' "$ROOT/guest/30-validate.sh" || fail 'DB effective permissions validation missing'
grep -q 'ACK_WARDEN_ENFORCEMENT=YES' "$ROOT/guest/60-waf-block-test.sh" || fail 'active test acknowledgement missing'
# logrotate fails on a second entry for a file /etc/logrotate.d/apache2 covers
if grep -Rq '^/var/log/apache2/' "$ROOT/guest" --include='*.sh'; then fail 'kit rotates a file in /var/log/apache2 (duplicates /etc/logrotate.d/apache2)'; else echo 'OK   no duplicate logrotate entry for /var/log/apache2'; fi
# the audit log must not be writable by the web user
if grep -q 'chown www-data[^ ]* .*modsec_audit.log' "$ROOT/guest/10-install-stack.sh"; then fail 'modsec_audit.log owned by www-data (forgeable by a webshell)'; else echo 'OK   audit log not owned by www-data'; fi
for required in README.md lab.env.example lib/lab-common.sh docs/FIREWALL-ARCHITECTURE.md docs/TEST-MATRIX.md guest/01-prepare.sh guest/10-install-stack.sh guest/20-install-warden.sh guest/30-validate.sh guest/40-waf-smoke.sh guest/50-longrun-smoke.sh guest/60-waf-block-test.sh guest/config/nft-base-apply.sh.in guest/config/warden-dropin.toml.in guest/systemd/warden-lab-nftables.service; do
  [[ -f "$ROOT/$required" ]] || fail "missing file: $required"
done

if command -v shellcheck >/dev/null; then
  printf '\n== ShellCheck ==\n'
  # sources are found next to each script; info-level notes are not failures
  find "$ROOT" -type f -name '*.sh' -print0 | xargs -0 shellcheck -x -P SCRIPTDIR -S warning || fail 'ShellCheck'
else printf '\nSKIP ShellCheck: executable unavailable\n'; fi

if (( failures )); then printf '\nFAILED: %s check(s)\n' "$failures" >&2; exit 1; fi
printf '\nPASS: all available static kit checks completed\n'
