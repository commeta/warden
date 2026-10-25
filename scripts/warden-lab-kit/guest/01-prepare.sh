#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/lab-common.sh
source "$ROOT/lib/lab-common.sh"
lab_load_config "$ROOT"; lab_validate_config
source /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]] || lab_die "Requires Ubuntu Server 24.04 LTS; found ${PRETTY_NAME:-unknown}."
command -v ip >/dev/null || lab_die "iproute2 is required"
lab_require_loopback
printf 'Local lab preflight passed.\nWeb URL: http://%s/\nReserved active-test source: %s\n' "$LAB_IP" "$ATTACKER_IP"
printf 'No network configuration was changed. Package installation needs repository access.\n'
