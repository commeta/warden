#!/usr/bin/env bash
# Fail if a binary needs a newer glibc than the releases Warden supports.
#
#   ./scripts/check-glibc.sh target/portable/release/wardend target/portable/release/wardenctl
#
# The dynamic loader refuses to start a program whose version-needs table
# (.gnu.version_r) names a glibc version the installed libc does not define,
# unless that entry is flagged WEAK — and neither lld nor GNU ld sets the flag.
# So a binary linked on Ubuntu 24.04 (glibc 2.39) needs 2.39 even though std
# references pidfd_spawnp/pidfd_getpid only weakly and has fallbacks for them:
# "version `GLIBC_2.39' not found" on Debian 12 (2.36) and Ubuntu 22.04 (2.35).
#
# Release builds therefore link against the oldest supported glibc
# (scripts/build-deb.sh --portable, CI: Ubuntu 22.04), and this script checks
# the result: no needed glibc version above MAX_GLIBC (default 2.34 = RHEL 9,
# the oldest glibc named in the README).
set -euo pipefail

MAX_GLIBC="${MAX_GLIBC:-2.34}"
[ $# -ge 1 ] || { echo "usage: $0 BINARY..." >&2; exit 2; }
command -v readelf >/dev/null || { echo "error: readelf not found (binutils)" >&2; exit 2; }

newer() { # newer A B → true if version A > version B
    [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$1" ]
}

status=0
for bin in "$@"; do
    worst=0
    # "  0x0200:   Name: GLIBC_2.39  Flags: none  Version: 22"
    while read -r ver flags; do
        if newer "$ver" "$MAX_GLIBC"; then
            if [ "$flags" = WEAK ]; then
                echo "$bin: GLIBC_$ver needed weakly (optional at run time)"
                continue
            fi
            echo "$bin: needs GLIBC_$ver > $MAX_GLIBC — it will not start on older releases" >&2
            status=1
        fi
        newer "$ver" "$worst" && worst=$ver
    done < <(readelf -V --wide "$bin" | awk '
                 /Version: [0-9]+ +File:/ { file = $(NF-2) }
                 /Name: GLIBC_[0-9.]+/ && (file ~ /^lib(c|m|pthread|dl|rt)\.so/) {
                     v = $3; sub(/^GLIBC_/, "", v); print v, $5
                 }')
    echo "$bin: needs glibc $worst (supported floor $MAX_GLIBC)"
done
if [ "$status" != 0 ]; then
    echo "build the release on the oldest supported base: ./scripts/build-deb.sh --portable" >&2
fi
exit $status
