#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/lab-common.sh
source "$ROOT/lib/lab-common.sh"
lab_load_config "$ROOT"
lab_validate_config
[[ $EUID -eq 0 ]] || lab_die "Run: sudo $0"

source /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]] || lab_die "Requires Ubuntu Server 24.04 LTS; found ${PRETTY_NAME:-unknown}."
command -v apt-get >/dev/null || lab_die "apt-get not found"
command -v ip >/dev/null || lab_die "iproute2 is required"
lab_require_loopback

export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 update
# nftables provides the nft CLI for Warden and a separate, persistent lab ingress chain.
# We intentionally do NOT enable nftables.service: Ubuntu's stock /etc/nftables.conf
# may flush the complete ruleset. This kit owns only inet lab_filter and never runs
# `flush ruleset`; Warden independently owns inet warden.
apt-get install -y --no-install-recommends nftables openssl curl logrotate ca-certificates
command -v nft >/dev/null || lab_die "nft CLI missing after installing package nftables"
nft --version
NFTABLES_ENABLE_STATE="$(systemctl is-enabled nftables.service 2>/dev/null || true)"
case "$NFTABLES_ENABLE_STATE" in
  enabled|enabled-runtime|linked|linked-runtime|alias)
    lab_die "nftables.service is enabled ($NFTABLES_ENABLE_STATE). Inspect its /etc/nftables.conf before proceeding; this kit uses a dedicated service and must not race a ruleset-wide flush." ;;
esac
if systemctl is-active --quiet nftables.service; then
  lab_die "nftables.service is active. Inspect its /etc/nftables.conf before proceeding; this kit uses a dedicated service and must not race a ruleset-wide flush."
fi

# Refuse to modify an unowned table. On a first install, mark ownership only if
# the table does not already exist; on reruns the marker authorizes updating our chain.
install -d -o root -g root -m 0750 /etc/warden-lab
NFT_MARKER=/etc/warden-lab/nft-base-managed
if nft list table inet lab_filter >/dev/null 2>&1; then
  [[ -f "$NFT_MARKER" ]] || lab_die "Table inet lab_filter already exists without $NFT_MARKER; refusing to modify a table not created by this kit. Inspect nft list table inet lab_filter."
else
  install -o root -g root -m 0600 /dev/null "$NFT_MARKER"
fi
install -o root -g root -m 0750 -d /usr/local/sbin
install -o root -g root -m 0750 "$ROOT/guest/config/nft-base-apply.sh.in" /usr/local/sbin/warden-lab-nft-apply
install -o root -g root -m 0644 "$ROOT/guest/systemd/warden-lab-nftables.service" /etc/systemd/system/warden-lab-nftables.service
# Ensure Warden (whose upstream unit uses DefaultDependencies=no) comes after our base chain.
install -d -o root -g root -m 0755 /etc/systemd/system/wardend.service.d
cat > /etc/systemd/system/wardend.service.d/10-warden-lab-firewall.conf <<'UNITDROPIN'
[Unit]
Requires=warden-lab-nftables.service
After=warden-lab-nftables.service
UNITDROPIN
systemctl daemon-reload
/usr/local/sbin/warden-lab-nft-apply
systemctl enable warden-lab-nftables.service >/dev/null
systemctl start warden-lab-nftables.service
nft list table inet lab_filter

# Package maintainer scripts may start/restart services during apt. Stop old
# listeners first: on reruns Nginx may already own :80 while Apache's package
# scripts still use the default Listen *:80. Remove only the extra CRS include
# that older versions of this kit created; it duplicated the packaged loader.
for UNIT in nginx apache2; do
  systemctl stop "$UNIT" >/dev/null 2>&1 || true
done
if command -v a2disconf >/dev/null 2>&1; then
  a2disconf warden-lab-crs >/dev/null 2>&1 || true
fi
rm -f /etc/apache2/conf-enabled/warden-lab-crs.conf /etc/apache2/conf-available/warden-lab-crs.conf

# Install Apache/PHP/MySQL/ModSecurity first, while Nginx is stopped and absent
# from this transaction. Apache may temporarily start on :80; below we switch it
# to 127.0.0.1:8080 and validate it before installing/starting Nginx.
apt-get install -y --no-install-recommends \
  apache2 libapache2-mod-php8.3 php8.3-cli php8.3-mysql php8.3-curl php8.3-xml php8.3-mbstring \
  mysql-server libapache2-mod-security2 modsecurity-crs

# Apache package creation gives us the www-data account. The private lab config
# directory must permit path traversal by that group so mod_php can read db.php,
# while remaining unlistable to www-data and keeping db-password root-only.
# Previous kit revisions left this directory root:root 0750, which made the
# group-readable db.php unreachable and caused the validation/app to fail with
# "require(/etc/warden-lab/db.php): Permission denied".
getent group www-data >/dev/null || lab_die "The www-data group is missing after Apache installation."
chown root:www-data /etc/warden-lab
chmod 0710 /etc/warden-lab

# Keep the DB password outside the project tree and never source it as shell code.
PASSFILE=/etc/warden-lab/db-password
if [[ "$DB_PASSWORD" == GENERATE ]]; then
  if [[ -s "$PASSFILE" ]]; then
    DB_PASSWORD="$(tr -d '\r\n' < "$PASSFILE")"
  else
    DB_PASSWORD="$(openssl rand -hex 32)"
    install -o root -g root -m 0600 /dev/null "$PASSFILE"
    printf '%s\n' "$DB_PASSWORD" > "$PASSFILE"
  fi
else
  install -o root -g root -m 0600 /dev/null "$PASSFILE"
  printf '%s\n' "$DB_PASSWORD" > "$PASSFILE"
  # Migrate secrets left by older kit revisions out of project-local lab.env.
  # The strict parser substitutes the protected password file on later runs.
  if grep -q '^DB_PASSWORD=' "$CFG"; then
    sed -i 's/^DB_PASSWORD=.*/DB_PASSWORD=GENERATE/' "$CFG"
    chmod 0600 "$CFG"
  fi
fi
chown root:root "$PASSFILE"
chmod 0600 "$PASSFILE"
[[ "$DB_PASSWORD" =~ ^[A-Fa-f0-9]{16,128}$ ]] || lab_die "Password file contains an invalid value"

# Set a deterministic global name to avoid the harmless AH00558 warning in
# installer/validator output. This does not affect the configured lab site.
cat > /etc/apache2/conf-available/warden-lab-servername.conf <<'SERVERNAME'
ServerName 127.0.0.1
SERVERNAME
a2enconf warden-lab-servername >/dev/null

# PHP must run in mod_php (prefork), not PHP-FPM.
a2dismod mpm_event >/dev/null 2>&1 || true
a2dismod mpm_worker >/dev/null 2>&1 || true
a2enmod mpm_prefork php8.3 security2 remoteip headers rewrite >/dev/null

# Restrict MySQL to loopback; no database listener is exposed on network interfaces.
install -d -m 0755 /etc/mysql/mysql.conf.d
cat > /etc/mysql/mysql.conf.d/99-warden-lab.cnf <<'MYSQLCFG'
[mysqld]
bind-address = 127.0.0.1
local_infile = 0
MYSQLCFG
systemctl enable mysql
systemctl restart mysql

mysql <<SQL
CREATE DATABASE IF NOT EXISTS \`${DB_NAME}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
ALTER USER '${DB_USER}'@'localhost' IDENTIFIED BY '${DB_PASSWORD}';
REVOKE ALL PRIVILEGES, GRANT OPTION FROM '${DB_USER}'@'localhost';
GRANT SELECT ON \`${DB_NAME}\`.* TO '${DB_USER}'@'localhost';
USE \`${DB_NAME}\`;
CREATE TABLE IF NOT EXISTS posts (
  id INT PRIMARY KEY AUTO_INCREMENT,
  title VARCHAR(120) NOT NULL,
  body TEXT NOT NULL
) ENGINE=InnoDB;
INSERT INTO posts (id,title,body) VALUES
 (1,'Hello lab','This is dummy data for isolated security testing.'),
 (2,'WAF checks','Requests should be evaluated by ModSecurity v2 + OWASP CRS.'),
 (3,'Incident drill','The SQL account is deliberately read-only.')
ON DUPLICATE KEY UPDATE title=VALUES(title), body=VALUES(body);
SQL

(
  umask 077
  cat > /etc/warden-lab/db.php <<PHP
<?php
// Private lab DB config; outside DocumentRoot. File is root:www-data 0640.
const LAB_DB_HOST = 'localhost';
const LAB_DB_NAME = '${DB_NAME}';
const LAB_DB_USER = '${DB_USER}';
const LAB_DB_PASS = '${DB_PASSWORD}';
PHP
)
chown root:www-data /etc/warden-lab/db.php
chmod 0640 /etc/warden-lab/db.php
# Test the effective permissions as the actual Apache worker identity. Do not
# loosen db-password (0600) or the directory's no-listing policy to make this pass.
runuser -u www-data -- test -r /etc/warden-lab/db.php || lab_die "www-data cannot read /etc/warden-lab/db.php; check /etc/warden-lab (root:www-data 0710) and db.php (root:www-data 0640)."
runuser -u www-data -- test ! -r /etc/warden-lab/db-password || lab_die "Security error: www-data can read /etc/warden-lab/db-password; the secret must remain root-only."

# ModSecurity v2 base config. Normalize active directives without touching comments.
MODSEC=/etc/modsecurity/modsecurity.conf
if [[ ! -f "$MODSEC" ]]; then
  [[ -r /etc/modsecurity/modsecurity.conf-recommended ]] || lab_die "Missing modsecurity.conf-recommended"
  cp /etc/modsecurity/modsecurity.conf-recommended "$MODSEC"
fi
set_modsec_directive() {
  local key="$1" value="$2"
  if grep -Eq "^[[:space:]]*${key}[[:space:]]+" "$MODSEC"; then
    sed -i -E "s|^[[:space:]]*${key}[[:space:]]+.*|${key} ${value}|" "$MODSEC"
  else
    printf '%s %s\n' "$key" "$value" >> "$MODSEC"
  fi
}
set_modsec_directive SecRuleEngine On
set_modsec_directive SecAuditEngine RelevantOnly
set_modsec_directive SecAuditLogType Serial
set_modsec_directive SecAuditLogParts ABIJDEFHZ
set_modsec_directive SecAuditLog /var/log/apache2/modsec_audit.log

# Normalize Ubuntu/Debian Apache ModSecurity includes. The package's
# security2.conf may be a symlink under mods-enabled; grep -R skips symlinked
# files on common GNU grep versions. The old check therefore missed the
# packaged CRS loader and added warden-lab-crs.conf, loading CRS twice and
# failing with "Found another rule with the same id" (crs-setup.conf).
CRS_LOADER=/usr/share/modsecurity-crs/owasp-crs.load
[[ -r "$CRS_LOADER" ]] || lab_die "CRS loader not found at $CRS_LOADER; inspect package contents before continuing."
SECURITY2_CONF=/etc/apache2/mods-available/security2.conf
SECURITY2_BACKUP=/etc/warden-lab/security2.conf.pre-warden-lab
if [[ -f "$SECURITY2_CONF" && ! -e "$SECURITY2_BACKUP" ]]; then
  cp -a "$SECURITY2_CONF" "$SECURITY2_BACKUP"
fi
cat > "$SECURITY2_CONF" <<'SECURITY2'
<IfModule security2_module>
    SecDataDir /var/cache/modsecurity
    # Load the base engine config once, then let the packaged CRS loader include
    # crs-setup.conf and the rules/*.conf exactly once.
    IncludeOptional /etc/modsecurity/*.conf
    IncludeOptional /usr/share/modsecurity-crs/owasp-crs.load
</IfModule>
SECURITY2
# Remove any previously enabled kit-created CRS include (known path/ownership).
if command -v a2disconf >/dev/null 2>&1; then
  a2disconf warden-lab-crs >/dev/null 2>&1 || true
fi
rm -f /etc/apache2/conf-enabled/warden-lab-crs.conf /etc/apache2/conf-available/warden-lab-crs.conf

# The serial audit log is opened by Apache's root parent and written by the
# children through the inherited descriptor: it stays root:adm, so a webshell
# running as www-data cannot forge entries that make Warden block an address
# (Warden reports logs a web user can write, see `wardenctl doctor`).
touch /var/log/apache2/modsec_audit.log
chown root:adm /var/log/apache2/modsec_audit.log
chmod 0640 /var/log/apache2/modsec_audit.log
# PHP writes its own error log as www-data: keep it out of /var/log/apache2,
# whose rotation (/etc/logrotate.d/apache2) recreates files as root.
install -d -o root -g adm -m 0750 /var/log/warden-lab
touch /var/log/warden-lab/php-error.log
chown www-data:adm /var/log/warden-lab/php-error.log
chmod 0640 /var/log/warden-lab/php-error.log
rm -f /var/log/apache2/php-error.log
install -d -o www-data -g www-data -m 0750 /var/cache/modsecurity

# Install a deliberately vulnerable but bounded test site. Uploads can be written
# for FIM drills, while script execution in that directory is denied by Apache.
install -d -o root -g root -m 0755 /var/www/warden-lab/public/files
install -d -o www-data -g www-data -m 0750 /var/www/warden-lab/public/uploads
install -o root -g root -m 0644 "$ROOT"/guest/site/*.php /var/www/warden-lab/public/
install -o root -g root -m 0644 "$ROOT"/guest/site/files/* /var/www/warden-lab/public/files/
chown root:root /var/www/warden-lab
chmod 0755 /var/www/warden-lab
find /var/www/warden-lab/public -maxdepth 1 -type d ! -path /var/www/warden-lab/public/uploads -exec chown root:root {} +
find /var/www/warden-lab/public -maxdepth 1 -type f -exec chown root:root {} +
find /var/www/warden-lab/public -maxdepth 1 -type d ! -path /var/www/warden-lab/public/uploads -exec chmod 0755 {} +
find /var/www/warden-lab/public -type f -exec chmod 0644 {} +

# Apache listens only on loopback behind the local Nginx/WAF reverse proxy.
cat > /etc/apache2/ports.conf <<'PORTS'
Listen 127.0.0.1:8080
PORTS
sed "s/{{LAB_IP}}/${LAB_IP}/g" "$ROOT/guest/config/apache-vhost.conf.in" > /etc/apache2/sites-available/warden-lab.conf
a2dissite 000-default.conf >/dev/null 2>&1 || true
a2ensite warden-lab.conf >/dev/null

# Ensure the Apache backend is fully valid and moved off :80 BEFORE Nginx is
# installed/started. This also catches duplicate CRS includes at the right stage.
apachectl configtest
systemctl enable apache2 mysql
systemctl restart apache2 mysql

# Nginx also binds only to loopback so the test site remains local to this system.
apt-get install -y --no-install-recommends nginx

# Self-signed cert for local HTTPS tests; no public name/CA is used.
install -d -m 0700 /etc/nginx/ssl
CERT=/etc/nginx/ssl/warden-lab.crt
CERT_KEY=/etc/nginx/ssl/warden-lab.key
# Reissue when the configured lab IP changes; never keep a stale SAN from an old lab.env.
if [[ ! -s "$CERT" || ! -s "$CERT_KEY" ]] || ! openssl x509 -in "$CERT" -noout -ext subjectAltName 2>/dev/null | grep -Fq "IP:${LAB_IP}"; then
  openssl req -x509 -nodes -newkey rsa:3072 -sha256 -days 825 \
    -keyout "$CERT_KEY" -out "$CERT" \
    -subj '/CN=warden-lab.test' -addext "subjectAltName=IP:${LAB_IP},DNS:warden-lab.test" >/dev/null 2>&1
fi
chmod 0600 "$CERT_KEY"
sed "s/{{LAB_IP}}/${LAB_IP}/g" "$ROOT/guest/config/nginx-site.conf.in" > /etc/nginx/sites-available/warden-lab
rm -f /etc/nginx/sites-enabled/default
ln -sfn /etc/nginx/sites-available/warden-lab /etc/nginx/sites-enabled/warden-lab

# Log rotation. /var/log/apache2/*.log — the ModSecurity audit log too — is
# rotated by the package's /etc/logrotate.d/apache2 (with a graceful reload).
# A second entry for the same file made logrotate fail every night ("duplicate
# log entry"), so all of the host's log rotation failed with it.
rm -f /etc/logrotate.d/warden-lab-modsecurity
cat > /etc/logrotate.d/warden-lab-php <<'LOGROTATE'
/var/log/warden-lab/php-error.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data adm
}
LOGROTATE
logrotate --debug /etc/logrotate.conf >/dev/null 2>&1 || lab_die "logrotate rejects the configuration: run 'logrotate --debug /etc/logrotate.conf'"

# Bound journal usage for long-running testing.
install -d -m 0755 /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/warden-lab.conf <<'JOURNAL'
[Journal]
SystemMaxUse=512M
RuntimeMaxUse=128M
MaxRetentionSec=14day
JOURNAL
systemctl restart systemd-journald

# Validate configs before restarting the public-facing services.
apachectl configtest
nginx -t
systemctl enable nginx apache2 mysql
systemctl restart apache2 nginx mysql
sleep 2

cat <<DONE

Stack installed.
  Lab URL : http://${LAB_IP}/ (loopback only)
  HTTPS   : https://${LAB_IP}/ (self-signed; use -k from curl; loopback only)
  DB user : ${DB_USER} (SELECT only; credentials protected under /etc/warden-lab/)
  Apache  : 127.0.0.1:8080 only
  ModSec  : $(grep -m1 -E '^[[:space:]]*SecRuleEngine' "$MODSEC")
  CRS     : $CRS_LOADER (loaded once by security2.conf)
  Firewall: nftables inet lab_filter blocks lab service ports on non-loopback interfaces
  Warden  : retains its separate inet warden table for temporary IP blocks

Run local tests:
  sudo $ROOT/guest/30-validate.sh
  $ROOT/guest/40-waf-smoke.sh
  $ROOT/guest/50-longrun-smoke.sh 60 8
DONE
