#!/usr/bin/env bash
# Install the .deb on a fresh distribution and check that the daemon starts.
# Runs as root inside a container (CI matrix: Debian 12, Ubuntu 22.04, 24.04):
#
#   docker run --rm -v "$PWD:/src:ro" debian:12 \
#       /src/scripts/test-deb-install.sh /src/target/debian/warden_<version>_amd64.deb
#
# There is no systemd as PID 1 in a container, so the daemon is started by
# hand with the unit's command line (the systemd unit itself is exercised by
# the `service` job on a real VM). OFFLINE=1 installs with dpkg alone, for
# images without a reachable mirror (dependencies must already be present).
set -euo pipefail

deb=$(readlink -f "${1:?usage: $0 PATH/TO/warden.deb}")
export DEBIAN_FRONTEND=noninteractive
. /etc/os-release
echo "==> $PRETTY_NAME — $(ldd --version | head -1)"

# 1. The package installs: its dependencies resolve on this release.
if [ "${OFFLINE:-0}" = 1 ]; then
    dpkg -i "$deb"
else
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends "$deb"
fi
dpkg-query -W -f='${Package} ${Version} ${Status}\n' warden | grep -q ' install ok installed$'
wardend --version
wardenctl --version

# The account for daemon.command_user exists and cannot log in.
getent passwd _warden | grep -q ':/usr/sbin/nologin$'

# 2. A fresh install observes only and validates, with every shipped profile.
grep -q '^dry_run = true' /etc/warden/warden.toml
wardend --check-config --config /etc/warden/warden.toml
for profile in /usr/share/warden/examples/conf.d/*.toml; do
    cp "$profile" /etc/warden/conf.d/
    wardend --check-config --config /etc/warden/warden.toml >/dev/null ||
        { echo "profile $(basename "$profile") does not validate" >&2; exit 1; }
    rm "/etc/warden/conf.d/$(basename "$profile")"
done

# 3. The daemon starts, answers on /health and the control socket, and stops cleanly.
mkdir -p /run/warden
log=$(mktemp)
wardend --config /etc/warden/warden.toml >"$log" 2>&1 &
pid=$!
health() { # GET /health without curl (not in minimal images)
    exec 3<>/dev/tcp/127.0.0.1/9184 || return 1
    printf 'GET /health HTTP/1.0\r\nHost: localhost\r\n\r\n' >&3
    local reply
    reply=$(cat <&3) || true
    exec 3<&-
    grep -q '^HTTP/1\.[01] 200' <<<"$reply"
}
up=0
for _ in $(seq 1 60); do
    kill -0 "$pid" 2>/dev/null || { echo "wardend exited during startup:" >&2; cat "$log" >&2; exit 1; }
    if health 2>/dev/null; then up=1; break; fi
    sleep 0.5
done
[ "$up" = 1 ] || { echo "wardend did not answer /health within 30 s:" >&2; cat "$log" >&2; exit 1; }
status=$(wardenctl status)
printf '%s\n' "$status" | sed -n '1,20p'
grep -qi dry <<<"$status"
kill -TERM "$pid"
rc=0; wait "$pid" || rc=$?
if [ "$rc" != 0 ]; then echo "wardend exited with $rc on SIGTERM:" >&2; cat "$log" >&2; exit 1; fi
if grep -qiE 'panicked|SIGSYS|core dumped' "$log"; then cat "$log" >&2; exit 1; fi

# 4. Purge removes what the package made but keeps what the operator wrote.
echo '# operator drop-in' >/etc/warden/conf.d/90-local.toml
dpkg --purge warden
[ ! -e /usr/sbin/wardend ] && [ ! -e /var/lib/warden ]
[ -f /etc/warden/conf.d/90-local.toml ] || { echo "purge deleted an operator file" >&2; exit 1; }
echo "==> OK on $PRETTY_NAME"
