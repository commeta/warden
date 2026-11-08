#!/usr/bin/env bash
# Bootstrap host packages and Rust tooling for Warden machine-code audits.
set -Eeuo pipefail

fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
info() { printf '\n==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }

[[ ${EUID} -eq 0 ]] || fail 'run as root: sudo ./install-deps.sh'
[[ -r /etc/os-release ]] || fail 'cannot identify operating system'
# shellcheck disable=SC1091
. /etc/os-release
[[ ${ID:-} == ubuntu && ${VERSION_ID:-} == 24.04 ]] || fail "supported OS: Ubuntu Server 24.04; found ${PRETTY_NAME:-unknown}"

TARGET_USER="${SUDO_USER:-root}"
if ! id "$TARGET_USER" >/dev/null 2>&1; then TARGET_USER=root; fi
TARGET_HOME="$(getent passwd "$TARGET_USER" | cut -d: -f6)"
[[ -n $TARGET_HOME && -d $TARGET_HOME ]] || fail "cannot resolve home for $TARGET_USER"
CARGO_BIN="$TARGET_HOME/.cargo/bin"

export DEBIAN_FRONTEND=noninteractive
info 'Refreshing APT metadata'
apt-get update

PACKAGES=(
  build-essential binutils elfutils file git curl ca-certificates pkg-config
  cmake ninja-build python3 python3-venv python3-pip jq iproute2
  llvm llvm-dev clang lld
  strace
  linux-tools-common linux-tools-generic
)
info 'Installing Ubuntu build and inspection packages'
apt-get install -y --no-install-recommends "${PACKAGES[@]}"

run_as_target() {
  if [[ $TARGET_USER == root ]]; then
    env HOME="$TARGET_HOME" CARGO_HOME="$TARGET_HOME/.cargo" RUSTUP_HOME="$TARGET_HOME/.rustup" PATH="$CARGO_BIN:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "$@"
  else
    runuser -u "$TARGET_USER" -- env HOME="$TARGET_HOME" CARGO_HOME="$TARGET_HOME/.cargo" RUSTUP_HOME="$TARGET_HOME/.rustup" PATH="$CARGO_BIN:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" "$@"
  fi
}

if [[ ! -x "$CARGO_BIN/rustup" ]]; then
  info "Installing rustup for $TARGET_USER"
  # mktemp without a template creates a root-owned 0700 directory under /tmp.
  # The installer is intentionally executed as TARGET_USER, so it must not be
  # staged in a directory that TARGET_USER cannot traverse. Create the cache
  # and temporary directory as the target account instead.
  run_as_target mkdir -p "$TARGET_HOME/.cache"
  tmp="$(run_as_target mktemp -d "$TARGET_HOME/.cache/warden-codegen-audit-rustup.XXXXXX")"
  cleanup_rustup_tmp() {
    if [[ -n ${tmp:-} && -d $tmp ]]; then
      rm -rf -- "$tmp"
    fi
  }
  trap cleanup_rustup_tmp EXIT
  run_as_target curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs -o "$tmp/rustup-init.sh"
  run_as_target sh "$tmp/rustup-init.sh" -y --profile minimal --default-toolchain stable --no-modify-path
  cleanup_rustup_tmp
  tmp=''
  trap - EXIT
fi

RUST_TOOLCHAIN="${WARDEN_RUST_TOOLCHAIN:-1.99.1}"
info "Installing the Rust toolchain pinned by upstream CI: $RUST_TOOLCHAIN"
run_as_target "$CARGO_BIN/rustup" toolchain install "$RUST_TOOLCHAIN" --profile minimal
run_as_target "$CARGO_BIN/rustup" component add --toolchain "$RUST_TOOLCHAIN" rustfmt clippy llvm-tools-preview

install_cargo_tool() {
  local crate="$1" executable="$2"
  if [[ -x "$CARGO_BIN/$executable" ]]; then
    printf '  present: %s\n' "$executable"
    return 0
  fi
  info "Installing Cargo tool: $crate"
  if ! run_as_target "$CARGO_BIN/cargo" "+$RUST_TOOLCHAIN" install --locked --jobs 2 "$crate"; then
    warn "optional Cargo tool '$crate' failed to install; the audit runner will record it as unavailable"
  fi
}

install_cargo_tool cargo-bloat cargo-bloat
install_cargo_tool cargo-llvm-lines cargo-llvm-lines
# Not needed for collected evidence; opt-in interactive developer helpers.
if [[ ${WARDEN_EXTRA_TOOLS:-0} == 1 ]]; then
  install_cargo_tool cargo-show-asm cargo-asm
  install_cargo_tool flamegraph cargo-flamegraph
fi

info 'Checking perf for the running kernel'
if ! command -v perf >/dev/null 2>&1 || ! perf --version >/dev/null 2>&1; then
  KERNEL_TOOLS="linux-tools-$(uname -r)"
  if apt-cache show "$KERNEL_TOOLS" >/dev/null 2>&1; then
    info "Installing kernel-matched perf package: $KERNEL_TOOLS"
    apt-get install -y --no-install-recommends "$KERNEL_TOOLS" || warn "could not install $KERNEL_TOOLS; perf stages may be unavailable"
  fi
fi
if ! command -v perf >/dev/null 2>&1 || ! perf --version >/dev/null 2>&1; then
  warn 'perf is not on PATH; install the matching package for the running kernel (linux-tools-$(uname -r))'
else
  perf --version || true
  if ! perf stat -e cycles,instructions -- true >/dev/null 2>&1; then
    warn "perf exists but hardware counters are not accessible (kernel.perf_event_paranoid=$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo unknown)); profiling will be marked unavailable"
  fi
fi

info 'Dependency installation complete'
printf 'Rust user: %s\nRust home: %s\n' "$TARGET_USER" "$TARGET_HOME"
printf 'Pinned Rust toolchain: %s\n' "$RUST_TOOLCHAIN"
printf 'Next: run ./run-audit.sh or ./run-full-audit.sh as the normal user (not via sudo).\n'
