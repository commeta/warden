#!/usr/bin/env bash
# Download Warden source and run the workspace tests on a dedicated Ubuntu Server 24.04 lab.
# The Debian-installed wardend/wardenctl binaries are NOT replaced by this script.
set -Eeuo pipefail
umask 022

readonly REPO_URL="https://github.com/commeta/warden.git"
readonly SOURCE_ROOT="/opt/warden-lab/source"
readonly SOURCE_DIR="${SOURCE_ROOT}/warden"
readonly CACHE_ROOT="/var/cache/warden-lab/source-tests"
readonly TARGET_DIR="/var/tmp/warden-lab-source-target"
readonly LOG_ROOT="/var/log/warden-lab/source-tests"

REF="${WARDEN_SOURCE_REF:-main}"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
note() { printf '\n==> %s\n' "$*"; }

[[ $EUID -eq 0 ]] || die "Run with sudo: sudo env ACK_WARDEN_LAB_SOURCE_TESTS=YES $0"
[[ "${ACK_WARDEN_LAB_SOURCE_TESTS:-}" == "YES" ]] || {
  cat >&2 <<'WARN'
This runs the Warden workspace tests as root. Some tests exercise process control,
filesystem operations, procfs/pidfd/fanotify and end-to-end remediation.

Run only on a dedicated disposable lab server, not a production host.
The script keeps source and build output separate from the Debian-installed Warden.
To acknowledge this, rerun with:
  sudo env ACK_WARDEN_LAB_SOURCE_TESTS=YES ./guest/70-warden-lab-source-tests.sh
Optional source ref (branch/tag/commit):
  WARDEN_SOURCE_REF=main
WARN
  exit 2
}

[[ -r /etc/os-release ]] || die "Cannot identify operating system"
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]] ||
  die "Requires Ubuntu Server 24.04; found ${PRETTY_NAME:-unknown}"

[[ "$REF" =~ ^[A-Za-z0-9._/-]+$ ]] || die "Unsafe WARDEN_SOURCE_REF: $REF"
[[ "$REF" != -* ]] || die "WARDEN_SOURCE_REF must not begin with '-'"

PKG_STATUS="$(dpkg-query -W -f='${Status}' warden 2>/dev/null || true)"
[[ "$PKG_STATUS" == "install ok installed" ]] ||
  die "The Warden .deb package must already be installed on this lab server."

# Find the invoking user's Rust toolchain, but keep Cargo downloads/build outputs
# in root-owned, dedicated directories. This avoids sudo-created files in ~/project/warden.
if [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]]; then
  USER_HOME="$(getent passwd "$SUDO_USER" | cut -d: -f6)"
  [[ -n "$USER_HOME" && -d "$USER_HOME" ]] || die "Cannot locate home for SUDO_USER=$SUDO_USER"
  CARGO_BIN="$(runuser -u "$SUDO_USER" -- env HOME="$USER_HOME" bash -lc 'command -v cargo' 2>/dev/null || true)"
  RUSTUP_HOME_FOUND="$(runuser -u "$SUDO_USER" -- env HOME="$USER_HOME" bash -lc 'rustup show home' 2>/dev/null || true)"
else
  CARGO_BIN="$(command -v cargo || true)"
  RUSTUP_HOME_FOUND="${RUSTUP_HOME:-}"
fi
[[ -n "$CARGO_BIN" && -x "$CARGO_BIN" ]] ||
  die "Cargo was not found for the invoking user. Install Rust via rustup first (Rust >= 1.88)."
[[ -n "$RUSTUP_HOME_FOUND" && -d "$RUSTUP_HOME_FOUND" ]] ||
  die "Rustup toolchain home was not found. Install Rust via rustup for the invoking user first."

# Ensure git/build tools are available. This does not install, remove, or upgrade Warden.
export DEBIAN_FRONTEND=noninteractive
note "Installing source-build prerequisites (not the Warden package)"
apt-get update
apt-get install -y --no-install-recommends git ca-certificates build-essential pkg-config

install -d -o root -g root -m 0755 "$SOURCE_ROOT"
install -d -o root -g root -m 0755 "$CACHE_ROOT"
install -d -o root -g root -m 0755 "$TARGET_DIR"
install -d -o root -g root -m 0750 "$LOG_ROOT"

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_FILE="${LOG_ROOT}/${STAMP}.log"
touch "$LOG_FILE"
chmod 0640 "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

note "Source ref: $REF"
note "Log file: $LOG_FILE"
note "Installed Debian package version: $(dpkg-query -W -f='${Version}' warden)"
note "Installed daemon service state before tests: $(systemctl is-active wardend.service 2>/dev/null || true)"

if [[ -e "$SOURCE_DIR" && ! -d "$SOURCE_DIR/.git" ]]; then
  die "$SOURCE_DIR exists but is not a Git checkout; move it aside manually before retrying."
fi

if [[ -d "$SOURCE_DIR/.git" ]]; then
  note "Updating existing source checkout"
  ORIGIN="$(git -C "$SOURCE_DIR" remote get-url origin 2>/dev/null || true)"
  [[ "$ORIGIN" == "$REPO_URL" ]] ||
    die "Existing checkout origin is '$ORIGIN', expected '$REPO_URL'."
  [[ -z "$(git -C "$SOURCE_DIR" status --porcelain)" ]] ||
    die "Existing checkout has local changes. Preserve them and use a clean checkout before retrying."
  git -C "$SOURCE_DIR" fetch --depth=1 origin "$REF"
  git -C "$SOURCE_DIR" checkout --detach FETCH_HEAD
else
  note "Downloading Warden source"
  git init "$SOURCE_DIR"
  git -C "$SOURCE_DIR" remote add origin "$REPO_URL"
  git -C "$SOURCE_DIR" fetch --depth=1 origin "$REF"
  git -C "$SOURCE_DIR" checkout --detach FETCH_HEAD
fi

COMMIT="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
printf 'Source commit: %s\n' "$COMMIT"
git -C "$SOURCE_DIR" log -1 --format='Commit subject: %s%nCommit date: %cI'

# Use the invoking user's installed rustup toolchain, but isolated root-owned
# Cargo cache and target directories. Do not build inside the .deb's installed paths.
export RUSTUP_HOME="$RUSTUP_HOME_FOUND"
export CARGO_HOME="${CACHE_ROOT}/cargo-home"
export CARGO_TARGET_DIR="$TARGET_DIR"
export PATH="$(dirname "$CARGO_BIN"):/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
install -d -o root -g root -m 0755 "$CARGO_HOME"

RUSTC_BIN="$(dirname "$CARGO_BIN")/rustc"
if [[ ! -x "$RUSTC_BIN" ]]; then
  RUSTC_BIN="$(command -v rustc || true)"
fi
[[ -n "$RUSTC_BIN" && -x "$RUSTC_BIN" ]] || die "rustc was not found next to Cargo."
RUSTC_VERSION="$("$RUSTC_BIN" --version)"
printf 'Rust compiler: %s\n' "$RUSTC_VERSION"
RUSTC_MINOR="$(printf '%s\n' "$RUSTC_VERSION" | sed -nE 's/^rustc 1\.([0-9]+)\..*/\1/p')"
[[ -n "$RUSTC_MINOR" ]] || die "Could not parse rustc version: $RUSTC_VERSION"
(( RUSTC_MINOR >= 88 )) || die "Warden requires Rust 1.88 or newer; found $RUSTC_VERSION"

note "Running full workspace tests as root (single test thread)"
cd "$SOURCE_DIR"
if "$CARGO_BIN" test --workspace --locked -- --test-threads=1; then
  TEST_STATUS=0
else
  TEST_STATUS=$?
fi

note "Finished"
printf 'Source commit: %s\n' "$COMMIT"
printf 'Debian package still installed: %s\n' "$(dpkg-query -W -f='${Version}' warden)"
printf 'Daemon service state after tests: %s\n' "$(systemctl is-active wardend.service 2>/dev/null || true)"
printf 'Full log: %s\n' "$LOG_FILE"
printf 'Cargo target directory: %s\n' "$CARGO_TARGET_DIR"
exit "$TEST_STATUS"
