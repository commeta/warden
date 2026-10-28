#!/usr/bin/env bash
# Run the Warden workspace tests on a dedicated Ubuntu Server 24.04 lab, from
# the GitHub repository or from a source tree you copied to the server
# (a manual update: --source DIR or WARDEN_SOURCE_DIR=DIR).
# The Debian-installed wardend/wardenctl binaries are NOT replaced by this script.
set -Eeuo pipefail
umask 022

readonly REPO_URL="https://github.com/commeta/warden.git"
readonly SOURCE_ROOT="/opt/warden-lab/source"
readonly LOG_ROOT="/var/log/warden-lab/source-tests"
# Cargo's download cache, the build output and the tests' temporary files live
# under one root. Put it on a volume other than / (WARDEN_LAB_BUILD_ROOT=/srv/…):
# a debug build of the workspace takes several GiB, and a full root file system
# was the source of the disk.space warnings in the 0.14.2 lab journal (L2).
BUILD_ROOT="${WARDEN_LAB_BUILD_ROOT:-/var/tmp/warden-lab-build}"
MIN_FREE_GIB="${WARDEN_LAB_MIN_FREE_GIB:-6}"
KEEP_TARGET="${WARDEN_LAB_KEEP_TARGET:-NO}"

REF="${WARDEN_SOURCE_REF:-main}"
LOCAL_SOURCE="${WARDEN_SOURCE_DIR:-}"

die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
note() { printf '\n==> %s\n' "$*"; }

usage() {
  cat <<'USAGE'
Usage: sudo env ACK_WARDEN_LAB_SOURCE_TESTS=YES ./guest/70-warden-lab-source-tests.sh [--source DIR]

  --source DIR   test the Warden source tree in DIR (an unpacked release archive,
                 your working copy) instead of downloading it from GitHub; the same
                 as WARDEN_SOURCE_DIR=DIR. The tree is copied into a root-owned
                 build copy first (without target/ and .git/); DIR is not modified.

Environment:
  WARDEN_SOURCE_REF=main          branch, tag or commit to download (without --source)
  WARDEN_LAB_BUILD_ROOT=DIR       Cargo cache, build output and test temp files
                                  (default /var/tmp/warden-lab-build; prefer a volume other than /)
  WARDEN_LAB_MIN_FREE_GIB=6       refuse to build with less free space there
  WARDEN_LAB_KEEP_TARGET=YES      keep the build output after the run (default: removed)
USAGE
}

while (($#)); do
  case "$1" in
    --source)
      (($# >= 2)) || die "--source needs a directory"
      LOCAL_SOURCE="$2"
      shift 2
      ;;
    --source=*)
      LOCAL_SOURCE="${1#--source=}"
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) die "Unknown argument: $1 (see --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "Run with sudo: sudo env ACK_WARDEN_LAB_SOURCE_TESTS=YES $0"
[[ "${ACK_WARDEN_LAB_SOURCE_TESTS:-}" == "YES" ]] || {
  cat >&2 <<'WARN'
This runs the Warden workspace tests as root. Some tests exercise process control,
filesystem operations, procfs/pidfd/fanotify and end-to-end remediation.

Run only on a dedicated disposable lab server, not a production host.
The script keeps source and build output separate from the Debian-installed Warden.
To acknowledge this, rerun with:
  sudo env ACK_WARDEN_LAB_SOURCE_TESTS=YES ./guest/70-warden-lab-source-tests.sh
To test a source tree already on this server instead of downloading it:
  sudo env ACK_WARDEN_LAB_SOURCE_TESTS=YES ./guest/70-warden-lab-source-tests.sh --source ~/warden-0.14.3
Optional source ref (branch/tag/commit) for the download:
  WARDEN_SOURCE_REF=main
WARN
  exit 2
}

[[ -r /etc/os-release ]] || die "Cannot identify operating system"
# shellcheck disable=SC1091
source /etc/os-release
[[ "${ID:-}" == "ubuntu" && "${VERSION_ID:-}" == "24.04" ]] ||
  die "Requires Ubuntu Server 24.04; found ${PRETTY_NAME:-unknown}"

if [[ -n "$LOCAL_SOURCE" ]]; then
  # A relative path is the invoking user's: resolve it before anything else.
  LOCAL_SOURCE="$(realpath -e -- "$LOCAL_SOURCE" 2>/dev/null)" || die "Source directory not found: ${WARDEN_SOURCE_DIR:-$LOCAL_SOURCE}"
  [[ -d "$LOCAL_SOURCE" ]] || die "Not a directory: $LOCAL_SOURCE"
  [[ -f "$LOCAL_SOURCE/Cargo.toml" && -f "$LOCAL_SOURCE/Cargo.lock" && -f "$LOCAL_SOURCE/crates/wardend/Cargo.toml" ]] ||
    die "$LOCAL_SOURCE is not a Warden source tree (expected Cargo.toml, Cargo.lock and crates/wardend)"
  grep -q '^\[workspace\]' "$LOCAL_SOURCE/Cargo.toml" || die "$LOCAL_SOURCE/Cargo.toml is not the workspace manifest"
  [[ -z "${WARDEN_SOURCE_REF:-}" ]] || note "WARDEN_SOURCE_REF is ignored: testing the local tree $LOCAL_SOURCE"
else
  [[ "$REF" =~ ^[A-Za-z0-9._/-]+$ ]] || die "Unsafe WARDEN_SOURCE_REF: $REF"
  [[ "$REF" != -* ]] || die "WARDEN_SOURCE_REF must not begin with '-'"
fi

[[ "$BUILD_ROOT" == /* && "$BUILD_ROOT" != / && ! "$BUILD_ROOT" =~ [[:space:]] ]] ||
  die "WARDEN_LAB_BUILD_ROOT must be an absolute path without spaces, not /: $BUILD_ROOT"
[[ "$MIN_FREE_GIB" =~ ^[0-9]{1,4}$ ]] || die "WARDEN_LAB_MIN_FREE_GIB must be a number of GiB"
if [[ -n "$LOCAL_SOURCE" ]]; then
  case "$LOCAL_SOURCE/" in
    # the copy below replaces $SOURCE_ROOT/local; a checkout next to it is fine
    "$BUILD_ROOT"/* | "$SOURCE_ROOT/local"/*) die "The source tree must not lie inside $BUILD_ROOT or $SOURCE_ROOT/local" ;;
  esac
fi

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
apt-get install -y --no-install-recommends git rsync ca-certificates build-essential pkg-config

CACHE_ROOT="${BUILD_ROOT}/cargo-home"
TARGET_DIR="${BUILD_ROOT}/target"
TEST_TMP="${BUILD_ROOT}/tmp"
install -d -o root -g root -m 0755 "$SOURCE_ROOT"
install -d -o root -g root -m 0755 "$BUILD_ROOT" "$CACHE_ROOT" "$TARGET_DIR"
# like /tmp: tests that run commands as another user still reach their files
install -d -o root -g root -m 1777 "$TEST_TMP"
install -d -o root -g root -m 0750 "$LOG_ROOT"
# Leftovers of kit revisions before 0.14.3 (on the root file system).
rm -rf /var/tmp/warden-lab-source-target

FREE_GIB="$(df -P -BG --output=avail "$BUILD_ROOT" | tail -1 | tr -dc '0-9')"
[[ -n "$FREE_GIB" ]] || die "Cannot read the free space of $BUILD_ROOT"
(( FREE_GIB >= MIN_FREE_GIB )) ||
  die "Only ${FREE_GIB} GiB free under $BUILD_ROOT (at least ${MIN_FREE_GIB} GiB needed). Point WARDEN_LAB_BUILD_ROOT at a bigger volume."

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
LOG_FILE="${LOG_ROOT}/${STAMP}.log"
touch "$LOG_FILE"
chmod 0640 "$LOG_FILE"
exec > >(tee -a "$LOG_FILE") 2>&1

# The build output is removed when the script ends, however it ends.
# shellcheck disable=SC2317  # invoked by the EXIT trap
cleanup() {
  rm -rf "$TEST_TMP"
  if [[ "$KEEP_TARGET" != YES ]]; then
    rm -rf "$TARGET_DIR"
  fi
}
trap cleanup EXIT

if [[ -n "$LOCAL_SOURCE" ]]; then
  note "Source: local directory $LOCAL_SOURCE"
else
  note "Source ref: $REF"
fi
note "Log file: $LOG_FILE"
note "Build area: $BUILD_ROOT (${FREE_GIB} GiB free; on $(df -P --output=target "$BUILD_ROOT" | tail -1))"
if [[ "$(df -P --output=target "$BUILD_ROOT" | tail -1)" == / ]]; then
  printf 'Note: the build area is on the root file system; WARDEN_LAB_BUILD_ROOT can move it to another volume.\n'
fi
note "Installed Debian package version: $(dpkg-query -W -f='${Version}' warden)"
DAEMON_STATE="$(systemctl is-active wardend.service 2>/dev/null || true)"
note "Installed daemon service state before tests: $DAEMON_STATE"
if [[ "$DAEMON_STATE" == active ]]; then
  cat <<'NOTE'
Note: the installed wardend is running. The tests start processes it may report
(exec from /tmp, test SUID files, a second daemon); expect those events in its
journal for the duration of the run, or stop it first: sudo systemctl stop wardend
NOTE
fi

if [[ -n "$LOCAL_SOURCE" ]]; then
  SOURCE_DIR="${SOURCE_ROOT}/local"
  note "Copying the source tree into $SOURCE_DIR (without target/ and .git/)"
  install -d -o root -g root -m 0755 "$SOURCE_DIR"
  # A root-owned copy: the build never writes into the user's tree, and the
  # tree cannot change under a running build. Links that point outside it
  # are not copied.
  rsync -rlt --delete --safe-links --chmod=D0755,Fu+rw,Fgo-w \
    --exclude='/target/' --exclude='/fuzz/target/' --exclude='/.git/' --exclude='/bench/results/latest/' \
    -- "$LOCAL_SOURCE/" "$SOURCE_DIR/"
  if [[ -d "$LOCAL_SOURCE/.git" ]]; then
    GIT_INFO="$(git -c safe.directory="$LOCAL_SOURCE" -C "$LOCAL_SOURCE" rev-parse HEAD 2>/dev/null || true)"
    if [[ -n "$GIT_INFO" && -n "$(git -c safe.directory="$LOCAL_SOURCE" -C "$LOCAL_SOURCE" status --porcelain 2>/dev/null)" ]]; then
      GIT_INFO="$GIT_INFO (with local changes)"
    fi
    printf 'Source git commit: %s\n' "${GIT_INFO:-unknown}"
  fi
  # What exactly was tested: a digest of every file of the copy.
  SOURCE_ID="$(cd "$SOURCE_DIR" && find . -type f -print0 | LC_ALL=C sort -z | xargs -0 sha256sum | sha256sum | cut -d' ' -f1)"
  printf 'Source tree SHA-256: %s\n' "$SOURCE_ID"
else
  SOURCE_DIR="${SOURCE_ROOT}/warden"
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
  SOURCE_ID="$(git -C "$SOURCE_DIR" rev-parse HEAD)"
  printf 'Source commit: %s\n' "$SOURCE_ID"
  git -C "$SOURCE_DIR" log -1 --format='Commit subject: %s%nCommit date: %cI'
fi
SOURCE_VERSION="$(sed -n '/^\[workspace\.package\]/,/^\[/{s/^version = "\(.*\)"/\1/p}' "$SOURCE_DIR/Cargo.toml" | head -1)"
printf 'Source version: %s\n' "${SOURCE_VERSION:-unknown}"

# Use the invoking user's installed rustup toolchain, but isolated root-owned
# Cargo cache and target directories. Do not build inside the .deb's installed paths.
export RUSTUP_HOME="$RUSTUP_HOME_FOUND"
export CARGO_HOME="$CACHE_ROOT"
export CARGO_TARGET_DIR="$TARGET_DIR"
# Line tables are enough for test backtraces and keep the build a fraction of
# full debug info; no incremental cache for a one-off build.
export CARGO_PROFILE_DEV_DEBUG=line-tables-only
export CARGO_PROFILE_TEST_DEBUG=line-tables-only
export CARGO_INCREMENTAL=0
# The tests' temporary trees go to the build area too, and are removed with it.
export TMPDIR="$TEST_TMP"
CARGO_BIN_DIR="$(dirname "$CARGO_BIN")"
export PATH="${CARGO_BIN_DIR}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

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
if [[ -n "$LOCAL_SOURCE" ]]; then
  printf 'Source: %s (version %s, tree SHA-256 %s)\n' "$LOCAL_SOURCE" "${SOURCE_VERSION:-unknown}" "$SOURCE_ID"
else
  printf 'Source commit: %s (version %s)\n' "$SOURCE_ID" "${SOURCE_VERSION:-unknown}"
fi
printf 'Test status: %s\n' "$([[ $TEST_STATUS == 0 ]] && echo passed || echo "FAILED ($TEST_STATUS)")"
printf 'Debian package still installed: %s\n' "$(dpkg-query -W -f='${Version}' warden)"
printf 'Daemon service state after tests: %s\n' "$(systemctl is-active wardend.service 2>/dev/null || true)"
printf 'Full log: %s\n' "$LOG_FILE"
printf 'Build area: %s (%s)\n' "$BUILD_ROOT" "$(du -sh "$BUILD_ROOT" 2>/dev/null | cut -f1)"
if [[ "$KEEP_TARGET" == YES ]]; then
  printf 'Cargo target directory kept: %s\n' "$CARGO_TARGET_DIR"
else
  printf 'Cargo target directory %s is removed now (WARDEN_LAB_KEEP_TARGET=YES keeps it).\n' "$CARGO_TARGET_DIR"
fi
exit "$TEST_STATUS"
