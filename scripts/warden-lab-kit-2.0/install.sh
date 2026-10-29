#!/usr/bin/env bash
# First-run installer for Warden Lab Kit 2.0.1 on Ubuntu Server 24.04.
# Installs the LAN profile by default, with an explicit interface/allowlist.
set -Eeuo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE="lan"
IFACE=""
TRUSTED=""
HOSTNAME="lab.local"

usage() {
  cat <<'EOF'
Warden Lab Kit 2.0.1 installer

Usage:
  sudo ./install.sh --profile lan --iface enp0s8 --trusted 192.168.56.1/32
  sudo ./install.sh --profile ci

Options:
  --profile lan|ci   lan is the default; ci binds only to loopback
  --iface IFACE      Interface through which LAN requests reach the server
  --trusted CIDRS    Comma-separated client CIDRs; e.g. 192.168.56.1/32
  --hostname NAME    Lab hostname (default: lab.local)
  -h, --help         Show this help

The LAN profile only allows HTTP/HTTPS from --trusted on --iface. It does not
open microservice ports. Warden is installed pinned to release 0.14.3 and starts
in observe-only/dry-run mode; enforcement is not enabled on first install.
EOF
}

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

while (($#)); do
  case "$1" in
    --profile) PROFILE="${2:?missing value for --profile}"; shift 2 ;;
    --iface|--interface) IFACE="${2:?missing value for --iface}"; shift 2 ;;
    --trusted) TRUSTED="${2:?missing value for --trusted}"; shift 2 ;;
    --hostname) HOSTNAME="${2:?missing value for --hostname}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) fail "unknown argument: $1 (see --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || fail "run as root: sudo ./install.sh ..."
[[ -f /etc/os-release ]] || fail "cannot identify Linux distribution"
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]] || fail "supported target is Ubuntu Server 24.04 LTS; found ${PRETTY_NAME:-unknown}"
[[ "$PROFILE" == lan || "$PROFILE" == ci ]] || fail "--profile must be lan or ci"
ARCH="$(dpkg --print-architecture)"
[[ "$ARCH" == amd64 ]] || fail "the pinned Warden 0.14.3 .deb is published for amd64; current architecture is $ARCH"
if [[ "$PROFILE" == lan ]]; then
  # Fail fast before changing APT state or backing up/replacing a profile.
  [[ -n "$IFACE" ]] || fail "LAN install requires --iface (see ip -br addr)"
  [[ -n "$TRUSTED" ]] || fail "LAN install requires --trusted client CIDR(s); do not use 0.0.0.0/0"
  [[ "$IFACE" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || fail "invalid interface name: $IFACE"
  [[ "$HOSTNAME" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9]$|^[A-Za-z0-9]$ ]] || fail "invalid hostname: $HOSTNAME"
fi

# Preserve an existing operator profile before replacing it with the selected
# generated template. This is intentionally automatic for a non-interactive install.
if [[ -L "$ROOT/lab.toml" ]]; then
  fail "lab.toml is a symlink; refusing to overwrite a target outside the project directory"
fi
if [[ -e "$ROOT/lab.toml" ]]; then
  BACKUP="$ROOT/lab.toml.backup.$(date +%Y%m%d-%H%M%S)"
  cp -a "$ROOT/lab.toml" "$BACKUP"
  printf 'Saved previous lab.toml to %s\n' "$BACKUP"
fi

# Bootstrap only tools required before labctl can install its full dependency set.
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends python3 ca-certificates curl iproute2

if [[ "$PROFILE" == lan ]]; then
  [[ -n "$IFACE" ]] || fail "LAN install requires --iface (see ip -br addr)"
  [[ -n "$TRUSTED" ]] || fail "LAN install requires --trusted client CIDR(s); do not use 0.0.0.0/0"
  [[ "$IFACE" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || fail "invalid interface name: $IFACE"
  ip link show dev "$IFACE" >/dev/null 2>&1 || fail "network interface does not exist: $IFACE"
  [[ "$HOSTNAME" =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}[A-Za-z0-9]$|^[A-Za-z0-9]$ ]] || fail "invalid hostname: $HOSTNAME"

  # Validate/normalize source CIDRs before creating TOML. Python is available on Ubuntu.
  TRUSTED_TOML="$(python3 - "$TRUSTED" <<'PY'
import ipaddress, sys
items = [x.strip() for x in sys.argv[1].split(',') if x.strip()]
if not items:
    raise SystemExit('trusted CIDR list is empty')
parsed=[]
for item in items:
    try:
        parsed.append(str(ipaddress.ip_network(item, strict=False)))
    except ValueError as exc:
        raise SystemExit(f'invalid trusted CIDR {item!r}: {exc}')
if any(x == '0.0.0.0/0' or x == '::/0' for x in parsed):
    raise SystemExit('0.0.0.0/0 and ::/0 are unsafe for the LAN allowlist; specify trusted hosts/subnets')
print(', '.join('"' + x + '"' for x in dict.fromkeys(parsed)))
PY
)" || fail "trusted CIDR validation failed"

  TEMPLATE="$ROOT/profiles/lan-nginx-modsec3.example.toml"
  [[ -f "$TEMPLATE" ]] || fail "LAN template not found: $TEMPLATE"
  python3 - "$TEMPLATE" "$ROOT/lab.toml" "$IFACE" "$TRUSTED_TOML" "$HOSTNAME" <<'PY'
from pathlib import Path
import re, sys
src, dest, iface, trusted, hostname = sys.argv[1:]
text = Path(src).read_text(encoding='utf-8')
replacements = {
    '"__LAN_INTERFACE__"': '"' + iface + '"',
    '__TRUSTED_CIDRS__': trusted,
    '"__LAB_HOSTNAME__"': '"' + hostname + '"',
}
for old, new in replacements.items():
    if old not in text:
        raise SystemExit(f'template token missing: {old}')
    text = text.replace(old, new)
if '__' in text:
    raise SystemExit('unexpanded template token remains; refusing to write lab.toml')
Path(dest).write_text(text, encoding='utf-8')
PY
else
  TEMPLATE="$ROOT/profiles/ci-nginx-modsec3.toml"
  [[ -f "$TEMPLATE" ]] || fail "CI template not found: $TEMPLATE"
  cp "$TEMPLATE" "$ROOT/lab.toml.new"
  mv "$ROOT/lab.toml.new" "$ROOT/lab.toml"
fi

printf '\n==> Selected profile:\n'
grep -E '^(name|front|hostname|mode|external_iface|trusted|source|version|sha256|enforce)\s*=' "$ROOT/lab.toml" || true
printf '\n==> Running dependency-aware plan and apply...\n'
cd "$ROOT"
./labctl doctor
./labctl plan
./labctl apply
./labctl verify

printf '\nInstallation complete.\n'
if [[ "$PROFILE" == lan ]]; then
  HOST_ALIASES="$(python3 - "$ROOT/lab.toml" <<'PYHOSTS'
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    profile = tomllib.load(f)
lab = profile.get("lab", {})
host = lab.get("hostname", "lab.local")
sites = lab.get("sites", [])
aliases = [host] + [f"{site}.{host}" for site in sites if site != "portal"]
print(" ".join(dict.fromkeys(aliases)))
PYHOSTS
)"
  printf 'Add this to the HOST computer hosts file (replace SERVER_IP):\n  SERVER_IP %s\n' "$HOST_ALIASES"
  printf 'Then open: http://%s/\n' "$HOSTNAME"
  printf 'LAN interface: %s; trusted sources: %s\n' "$IFACE" "$TRUSTED"
else
  printf 'Loopback profile: test locally with curl -H "Host: %s" http://127.0.0.1/\n' "$HOSTNAME"
fi
printf 'Warden is pinned to 0.14.3 and remains in observe-only/dry-run mode.\n'
