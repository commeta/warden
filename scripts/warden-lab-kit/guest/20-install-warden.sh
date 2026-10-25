#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/lab-common.sh
source "$ROOT/lib/lab-common.sh"
lab_load_config "$ROOT"
lab_validate_config
[[ $EUID -eq 0 ]] || lab_die "Run: sudo env ACK_WARDEN_PRERELEASE_RISK=YES $0"
[[ "${ACK_WARDEN_PRERELEASE_RISK:-}" == YES ]] || {
  cat >&2 <<'WARN'
STOP: Warden 0.14.1 is a prerelease. Review upstream source and provenance before installing a privileged daemon.
The package may kill processes, quarantine files, restart units and alter nftables. A SHA-256 pin protects integrity
against unexpected download changes, but is not a signature and does not prove that the publisher/build is trusted.
To proceed only in this dedicated disposable lab system, rerun with ACK_WARDEN_PRERELEASE_RISK=YES.
WARN
  exit 2
}
[[ "$(dpkg --print-architecture)" == amd64 ]] || lab_die "Pinned .deb is amd64 only."
command -v nft >/dev/null || lab_die "The 'nft' CLI is missing. Run guest/10-install-stack.sh first (it installs package nftables)."
command -v curl >/dev/null || lab_die "curl is required to download the pinned release"
command -v sha256sum >/dev/null || lab_die "sha256sum is required for package verification"
command -v dpkg-deb >/dev/null || lab_die "dpkg-deb is required to inspect the package before installation"

VERSION="$WARDEN_VERSION"
SHA="${WARDEN_DEB_SHA256,,}"
URL="https://github.com/commeta/warden/releases/download/${VERSION}/warden_${VERSION}-1_amd64.deb"
DEB_TMP="$(mktemp --suffix=.deb /var/tmp/warden-lab-deb.XXXXXXXXXX)"
DROPIN_TMP="$(mktemp /var/tmp/warden-lab-config.XXXXXXXXXX)"
cleanup() { rm -f "$DEB_TMP" "$DROPIN_TMP"; }
trap cleanup EXIT

curl --fail --location --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 180 --retry 3 "$URL" -o "$DEB_TMP"
printf '%s  %s\n' "$SHA" "$DEB_TMP" | sha256sum --check --status || lab_die "SHA-256 mismatch; refusing to install $URL"
dpkg-deb --info "$DEB_TMP" >/dev/null || lab_die "Downloaded file is not a valid Debian package"
PKG_NAME="$(dpkg-deb -f "$DEB_TMP" Package)"
PKG_VERSION="$(dpkg-deb -f "$DEB_TMP" Version)"
PKG_ARCH="$(dpkg-deb -f "$DEB_TMP" Architecture)"
[[ "$PKG_NAME" == warden ]] || lab_die "Expected package 'warden', got '$PKG_NAME'"
[[ "$PKG_VERSION" == "${VERSION}-1" ]] || lab_die "Expected Warden package version ${VERSION}-1, got $PKG_VERSION"
[[ "$PKG_ARCH" == amd64 ]] || lab_die "Expected amd64 package, got $PKG_ARCH"

# Install from the verified local file; apt resolves declared runtime dependencies.
apt-get update
apt-get install -y --no-install-recommends "$DEB_TMP"
install -d -o root -g root -m 0755 /etc/warden/conf.d

# Render and validate the Warden integration before replacing an existing drop-in.
sed -e "s/{{LAB_IP}}/${LAB_IP}/g" \
  "$ROOT/guest/config/warden-dropin.toml.in" > "$DROPIN_TMP"
python3 - "$DROPIN_TMP" <<'PY' || lab_die "Generated Warden TOML is invalid"
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    tomllib.load(f)
PY

DROPIN=/etc/warden/conf.d/60-warden-lab.toml
DROPIN_BACKUP=""
if [[ -e "$DROPIN" ]]; then
  DROPIN_BACKUP="$DROPIN.bak.$(date +%s)"
  cp -a "$DROPIN" "$DROPIN_BACKUP"
fi
install -o root -g root -m 0644 "$DROPIN_TMP" "$DROPIN"

MAINCFG=/etc/warden/warden.toml
[[ -f "$MAINCFG" ]] || lab_die "Expected Warden config $MAINCFG was not installed"
MAIN_BACKUP="$MAINCFG.bak.$(date +%s)"
cp -a "$MAINCFG" "$MAIN_BACKUP"
if grep -Eq '^[[:space:]]*dry_run[[:space:]]*=' "$MAINCFG"; then
  sed -i -E 's/^[[:space:]]*dry_run[[:space:]]*=.*/dry_run = true/' "$MAINCFG"
else
  if grep -q '^\[daemon\][[:space:]]*$' "$MAINCFG"; then
    sed -i '/^\[daemon\][[:space:]]*$/a dry_run = true' "$MAINCFG"
  else
    lab_die "Could not find [daemon] or dry_run in $MAINCFG; refusing to guess the config layout"
  fi
fi

restore_previous_config() {
  cp -a "$MAIN_BACKUP" "$MAINCFG"
  if [[ -n "$DROPIN_BACKUP" ]]; then
    cp -a "$DROPIN_BACKUP" "$DROPIN"
  else
    rm -f "$DROPIN"
  fi
}
if ! wardend --check-config --config "$MAINCFG"; then
  echo "Warden config validation failed; restoring previous configuration files." >&2
  restore_previous_config
  wardend --check-config --config "$MAINCFG" || true
  lab_die "Warden config invalid; previous main config/drop-in restored"
fi

# Updating the drop-in on a re-run must take effect if the service is already
# running, but never auto-start it on first installation. Roll back on reload failure.
if systemctl is-active --quiet wardend.service; then
  if ! systemctl reload wardend.service; then
    echo "Warden reload failed; restoring previous configuration files." >&2
    restore_previous_config
    wardend --check-config --config "$MAINCFG" || true
    systemctl reload wardend.service || true
    lab_die "Warden reload failed; previous config restored (service may need manual inspection)"
  fi
  echo "Active Warden service reloaded with validated lab drop-in; dry_run remains true."
fi

cat <<'DONE'
Warden installed and configuration validated, but service was NOT started automatically.
Next commands:
  sudo wardenctl doctor
  sudo systemctl enable --now wardend
  sudo wardenctl status
  sudo wardenctl events -f

Firewall notes:
  - Native base ingress policy: inet lab_filter, loaded by warden-lab-nftables.service.
  - Warden independently manages its inet warden blocklist table; the kit never flushes the global ruleset.
  - 127.0.0.1 is allowlisted for routine checks; ATTACKER_IP deliberately is not.

Keep dry_run = true until false positives, source review, and rollback are tested.
DONE
