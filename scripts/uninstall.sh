#!/usr/bin/env bash
# Warden uninstaller.
#   sudo ./scripts/uninstall.sh [--purge]
# --purge also removes configuration, state (baselines, quarantine) and logs.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "must run as root" >&2; exit 1; }

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

if [ -d /run/systemd/system ]; then
    systemctl disable --now wardend.service 2>/dev/null || true
    rm -f /etc/systemd/system/wardend.service
    systemctl daemon-reload || true
fi

rm -f /usr/sbin/wardend /usr/bin/wardenctl /usr/local/sbin/wardend /usr/local/bin/wardenctl
rm -rf /usr/share/warden

# Remove the runtime nftables table if present.
command -v nft >/dev/null && nft delete table inet warden 2>/dev/null || true

if [ "$PURGE" = 1 ]; then
    echo "Purging configuration, state and logs…"
    rm -rf /etc/warden /var/lib/warden /var/log/warden /run/warden
else
    echo "Kept /etc/warden, /var/lib/warden and /var/log/warden. Use --purge to remove them."
fi
echo "Warden uninstalled."
