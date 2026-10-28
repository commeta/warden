#!/usr/bin/env bash
# Build the Debian package as a NORMAL user (do not use sudo).
#
#   ./scripts/build-deb.sh             → target/debian/warden_<version>_<arch>.deb
#       for this machine: the package needs this machine's glibc (on Ubuntu
#       24.04 that is 2.39, so it does not install on Debian 12 / Ubuntu 22.04)
#   ./scripts/build-deb.sh --portable  → target/portable/debian/warden_<version>_<arch>.deb
#       for every supported release: the binaries are linked inside an Ubuntu
#       22.04 container (docker or podman; WARDEN_BUILD_IMAGE overrides it), so
#       they need glibc 2.34 and install on Debian 12, Ubuntu 22.04 and newer
#
#   sudo apt install ./target/debian/warden_*.deb
set -euo pipefail
cd "$(dirname "$0")/.."

portable=0
case "${1:-}" in
    --portable) portable=1 ;;
    "") ;;
    *) echo "usage: $0 [--portable]" >&2; exit 2 ;;
esac

# ALLOW_ROOT=1 is for build machines where root is the only user.
if [ "$(id -u)" = 0 ] && [ "${ALLOW_ROOT:-0}" != 1 ]; then
    echo "error: run as your normal user, not root (sudo would leave root-owned files in ~/.cargo and target/)." >&2
    exit 1
fi
# Root-owned leftovers from earlier sudo builds cause "Permission denied (os error 13)".
if [ "$(id -u)" != 0 ]; then
    for d in target "$HOME/.cargo" "$HOME/.rustup"; do
        if [ -e "$d" ] && [ -n "$(find "$d" -user root -print -quit 2>/dev/null)" ]; then
            echo "error: root-owned files in $d (from an earlier 'sudo cargo …'). Fix with:" >&2
            echo "  sudo chown -R $(id -un):$(id -gn) $d" >&2
            exit 1
        fi
    done
fi
command -v cargo >/dev/null || { [ -f "$HOME/.cargo/env" ] && . "$HOME/.cargo/env"; }
command -v cargo >/dev/null || { echo "error: cargo not found — install Rust: https://rustup.rs" >&2; exit 1; }

if ! cargo deb --version >/dev/null 2>&1; then
    echo "==> installing cargo-deb (one time)"
    cargo install cargo-deb --locked
fi

if [ "$portable" = 1 ]; then
    engine=$(command -v docker || command -v podman) ||
        { echo "error: --portable needs docker or podman" >&2; exit 1; }
    image="${WARDEN_BUILD_IMAGE:-ubuntu:22.04}"
    export CARGO_TARGET_DIR="$PWD/target/portable"
    cargo_home="${CARGO_HOME:-$HOME/.cargo}"
    sysroot=$(rustc --print sysroot)
    mkdir -p "$CARGO_TARGET_DIR"
    # Sources are fetched here (with this machine's network and proxy settings);
    # the container only compiles, offline, as the invoking user.
    cargo fetch --locked
    echo "==> linking against the glibc of $image"
    "$engine" run --rm \
        -v "$PWD:/src" -v "$cargo_home:/cargo" -v "$sysroot:/toolchain:ro" \
        -e DEBIAN_FRONTEND=noninteractive -w /src "$image" bash -euc '
            apt-get update -qq
            apt-get install -y -qq --no-install-recommends gcc libc6-dev >/dev/null
            exec setpriv --reuid='"$(id -u)"' --regid='"$(id -g)"' --clear-groups \
                env HOME=/tmp CARGO_HOME=/cargo CARGO_TARGET_DIR=/src/target/portable \
                    PATH=/toolchain/bin:/usr/bin:/bin \
                cargo build --release --locked --offline -p wardend -p wardenctl'
    bindir="$CARGO_TARGET_DIR/release"
else
    cargo build --release --locked -p wardend -p wardenctl
    bindir=target/release
fi

if ! ./scripts/check-glibc.sh "$bindir/wardend" "$bindir/wardenctl"; then
    if [ "$portable" = 1 ]; then exit 1; fi
    echo "note: this package installs only where glibc is at least this machine's;" >&2
    echo "      for Debian 12 / Ubuntu 22.04 build it with --portable" >&2
fi
cargo deb -p wardend --no-build
deb=$(ls -1t "${CARGO_TARGET_DIR:-target}"/debian/*.deb | head -1)
echo "depends: $(dpkg-deb -f "$deb" Depends)"
echo "install with:  sudo apt install ./${deb#"$PWD"/}"
