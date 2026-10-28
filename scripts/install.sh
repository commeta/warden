#!/usr/bin/env bash
# Warden installer (source build → system install).
#
#   cargo build --release                                  # as your normal user (recommended)
#   sudo ./scripts/install.sh [options]
#
# Options:
#   --profile webserver|workstation|database   install a conf.d profile (never overwrites an edited one)
#   --enable          enable the service at boot
#   --start           (re)start the service after installing
#   --enforce         set dry_run = false: remediate right away (the shipped default is
#                     dry_run = true — detect & report only; see 'wardenctl dry-run off')
#   --dry-run         set dry_run = true explicitly (the default; kept for older scripts)
#   --no-build        never build; use existing target/release binaries
#   --no-restart      do not restart an already running service after an upgrade
#   --force           install even if the new binary rejects the existing configuration
#
# Upgrades are checked before anything changes: the new wardend validates the
# configuration in place (with its conf.d drop-ins) first, and refuses to
# install if it does not accept it. The previous binaries are kept as
# wardend.old / wardenctl.old; if the restarted service does not come up, they
# are put back and the old version is started again.
#
# Building: when run through sudo, the binaries are built as the *invoking user*
# with that user's Rust toolchain (~/.cargo/bin), so nothing in your home or in
# target/ ends up owned by root. Root-owned leftovers from earlier `sudo cargo`
# runs are detected and handed back to you.
#
# Idempotent: re-running upgrades binaries and the unit, keeps your configuration
# (new reference files are written next to it as *.new), and restarts the service
# if it was running.
set -euo pipefail

PROFILE=""; ENABLE=0; START=0; DRYRUN_CFG=""; BUILD=auto; RESTART=1; FORCE=0
PREFIX="${PREFIX:-/usr}"
SBIN="$PREFIX/sbin"; BIN="$PREFIX/bin"; CONFDIR="/etc/warden"; SHAREDIR="$PREFIX/share/warden"

while [ $# -gt 0 ]; do
    case "$1" in
        --profile) PROFILE="${2:-}"; shift 2 ;;
        --enable) ENABLE=1; shift ;;
        --start) START=1; shift ;;
        --dry-run) DRYRUN_CFG=true; shift ;;
        --enforce) DRYRUN_CFG=false; shift ;;
        --no-build) BUILD=no; shift ;;
        --build) BUILD=yes; shift ;;
        --no-restart) RESTART=0; shift ;;
        --force) FORCE=1; shift ;;
        -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d; s/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1 (see --help)" >&2; exit 2 ;;
    esac
done

die() { echo -e "\033[31merror:\033[0m $*" >&2; exit 1; }
info() { echo -e "\033[32m==>\033[0m $*"; }
note() { echo -e "\033[33m  note:\033[0m $*"; }

[ "$(id -u)" = 0 ] || die "must run as root:  sudo $0 $*"
case "$PROFILE" in ""|webserver|workstation|database) ;; *) die "profile must be webserver, workstation or database" ;; esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# ---------------------------------------------------------------------------
# Who builds? Under sudo: the invoking user, with their own toolchain.
# ---------------------------------------------------------------------------
BUILD_USER=root
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then BUILD_USER="$SUDO_USER"; fi
BUILD_HOME="$(getent passwd "$BUILD_USER" | cut -d: -f6)"
BUILD_GROUP="$(id -gn "$BUILD_USER")"

# Repair root-owned files left by an earlier `sudo cargo ...` / `sudo -E ...`
# (they break later builds and `cargo install` as the normal user).
repair_ownership() {
    [ "$BUILD_USER" = root ] && return 0
    local d fixed=0
    for d in "$ROOT/target" "$ROOT/Cargo.lock" "$BUILD_HOME/.cargo" "$BUILD_HOME/.rustup"; do
        [ -e "$d" ] || continue
        if [ -n "$(find "$d" -user root -print -quit 2>/dev/null)" ]; then
            note "fixing root-owned files in $d (left by an earlier build as root)"
            find "$d" -user root -exec chown -h "$BUILD_USER:$BUILD_GROUP" {} + 2>/dev/null || true
            fixed=1
        fi
    done
    [ "$fixed" = 1 ] && info "Ownership repaired for $BUILD_USER." || true
}

# Find cargo for the build user (rustup puts it in ~/.cargo/bin, which sudo's
# secure_path does not include).
find_cargo() {
    local c
    for c in "$BUILD_HOME/.cargo/bin/cargo" /usr/local/cargo/bin/cargo /usr/local/bin/cargo /usr/bin/cargo; do
        [ -x "$c" ] && { echo "$c"; return 0; }
    done
    if [ "$BUILD_USER" != root ]; then
        c="$(sudo -u "$BUILD_USER" -H bash -lc 'command -v cargo' 2>/dev/null || true)"
    else
        c="$(command -v cargo || true)"
    fi
    [ -n "$c" ] && echo "$c"
}

sources_newer_than_binary() {
    local b="$ROOT/target/release/wardend"
    [ -x "$b" ] && [ -x "$ROOT/target/release/wardenctl" ] || return 0
    [ -n "$(find "$ROOT/crates" "$ROOT/Cargo.toml" "$ROOT/Cargo.lock" -newer "$b" -type f \( -name '*.rs' -o -name 'Cargo.*' \) -print -quit 2>/dev/null)" ]
}

build() {
    local cargo; cargo="$(find_cargo)" || true
    [ -n "$cargo" ] || die "cargo not found for user '$BUILD_USER'.
  Install Rust as that user:  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  then:                       source ~/.cargo/env && rustup default stable
  or build yourself first:    cargo build --release && sudo $0 --no-build"
    local bindir; bindir="$(dirname "$cargo")"
    info "Building release binaries as $BUILD_USER with $cargo (first build takes a few minutes)…"
    local cmd="cd '$ROOT' && export PATH='$bindir':\"\$PATH\" && \
        { rustup show active-toolchain >/dev/null 2>&1 || ! command -v rustup >/dev/null || \
          { echo 'no default Rust toolchain: run  rustup default stable  as $BUILD_USER' >&2; exit 3; }; } && \
        cargo build --release --locked -p wardend -p wardenctl"
    if [ "$BUILD_USER" = root ]; then
        bash -c "$cmd"
    else
        sudo -u "$BUILD_USER" -H bash -c "$cmd"
    fi
}

repair_ownership
case "$BUILD" in
    no) [ -x target/release/wardend ] || die "--no-build given but target/release/wardend does not exist" ;;
    yes) build ;;
    auto)
        if sources_newer_than_binary; then build; else info "Release binaries are up to date — skipping build."; fi ;;
esac
[ -x target/release/wardend ] && [ -x target/release/wardenctl ] || die "build did not produce target/release/{wardend,wardenctl}"

for tool in nft journalctl; do
    command -v "$tool" >/dev/null || note "'$tool' not found — some features will be limited (see 'wardenctl doctor')"
done

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
WAS_ACTIVE=0
if [ -d /run/systemd/system ] && systemctl is-active --quiet wardend.service 2>/dev/null; then WAS_ACTIVE=1; fi

# An upgrade must not leave the host unprotected: the new binary validates the
# configuration that is in place before anything is replaced (N12 of the
# 0.14.1 review — the old installer restarted first and warned afterwards).
if [ -f "$CONFDIR/warden.toml" ]; then
    if ! CHECK_OUT="$(target/release/wardend --check-config --config "$CONFDIR/warden.toml" 2>&1)"; then
        echo "$CHECK_OUT" >&2
        if [ "$FORCE" = 1 ]; then
            note "the new wardend rejects $CONFDIR/warden.toml — installing anyway (--force); the service is not restarted"
            RESTART=0; START=0
        else
            die "the new wardend rejects the configuration in $CONFDIR (above); nothing was changed.
  Fix the configuration, or install anyway with --force (the running service is then left alone)."
        fi
    fi
fi

info "Installing binaries to $SBIN and $BIN"
# keep the previous version for a rollback
[ -x "$SBIN/wardend" ] && cp -p "$SBIN/wardend" "$SBIN/wardend.old"
[ -x "$BIN/wardenctl" ] && cp -p "$BIN/wardenctl" "$BIN/wardenctl.old"
install -D -m 0755 target/release/wardend  "$SBIN/wardend.new" && mv -f "$SBIN/wardend.new" "$SBIN/wardend"
install -D -m 0755 target/release/wardenctl "$BIN/wardenctl.new" && mv -f "$BIN/wardenctl.new" "$BIN/wardenctl"

rollback() {
    [ -x "$SBIN/wardend.old" ] || return 1
    note "putting the previous version back ($SBIN/wardend.old)"
    mv -f "$SBIN/wardend.old" "$SBIN/wardend"
    [ -x "$BIN/wardenctl.old" ] && mv -f "$BIN/wardenctl.old" "$BIN/wardenctl"
    systemctl reset-failed wardend.service 2>/dev/null || true
    systemctl restart wardend.service && sleep 3 && systemctl is-active --quiet wardend.service
}

install -d -m 0700 /var/lib/warden /var/lib/warden/fim /var/lib/warden/quarantine /var/lib/warden/snapshots
# An unprivileged account for hooks and notification commands
# (`daemon.command_user = "_warden"`; unused unless you configure it).
if ! getent passwd _warden >/dev/null && command -v useradd >/dev/null; then
    useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin _warden &&
        info "Created the system user _warden (for daemon.command_user)"
fi
install -d -m 0755 /var/log/warden "$CONFDIR/conf.d" "$CONFDIR/signatures.d" "$SHAREDIR"

# Install a config file without clobbering local edits.
install_conf() {
    local src="$1" dst="$2" mode="$3"
    if [ -f "$dst" ]; then
        if ! cmp -s "$src" "$dst"; then
            install -m "$mode" "$src" "$dst.new"
            note "kept your $dst; the new reference version is $dst.new"
        fi
    else
        install -D -m "$mode" "$src" "$dst"
        info "Installed $dst"
    fi
}

install -D -m 0644 config/warden.toml "$SHAREDIR/warden.toml.reference"
install_conf config/warden.toml "$CONFDIR/warden.toml" 0640
for p in config/conf.d/*.toml; do install -D -m 0644 "$p" "$SHAREDIR/examples/$(basename "$p")"; done
for s in config/signatures/*.toml; do install -D -m 0644 "$s" "$SHAREDIR/signatures/$(basename "$s")"; done
install -D -m 0644 packaging/nftables/warden.nft "$SHAREDIR/warden.nft"
if [ -n "$PROFILE" ]; then
    install_conf "config/conf.d/50-$PROFILE.toml" "$CONFDIR/conf.d/50-$PROFILE.toml" 0644
fi

if [ -n "$DRYRUN_CFG" ] && ! grep -q "^dry_run *= *$DRYRUN_CFG" "$CONFDIR/warden.toml"; then
    if grep -q '^dry_run *=' "$CONFDIR/warden.toml"; then
        sed -i "s/^dry_run *=.*/dry_run = $DRYRUN_CFG/" "$CONFDIR/warden.toml"
    else
        sed -i "0,/^\\[daemon\\]/{s/^\\[daemon\\]/[daemon]\\ndry_run = $DRYRUN_CFG/}" "$CONFDIR/warden.toml"
    fi
    info "dry_run = $DRYRUN_CFG in $CONFDIR/warden.toml"
fi

if [ -d /run/systemd/system ]; then
    install -D -m 0644 packaging/systemd/wardend.service /etc/systemd/system/wardend.service
    systemctl daemon-reload
    # A unit that failed before (e.g. the old seccomp filter) hit the start limit.
    systemctl reset-failed wardend.service 2>/dev/null || true
    info "Installed systemd unit."
else
    note "systemd not detected — start wardend with your init system."
fi

if "$SBIN/wardend" --check-config --config "$CONFDIR/warden.toml" >/dev/null 2>&1; then
    info "Configuration valid."
else
    echo "  warning: configuration did not validate:"
    "$SBIN/wardend" --check-config --config "$CONFDIR/warden.toml" || true
    if [ "$WAS_ACTIVE" = 1 ]; then
        note "the running service is left alone: fix the configuration, then 'systemctl restart wardend'"
        RESTART=0; START=0
    fi
fi

if [ -d /run/systemd/system ]; then
    [ "$ENABLE" = 1 ] && systemctl enable wardend.service && info "Service enabled at boot."
    if [ "$START" = 1 ] || { [ "$WAS_ACTIVE" = 1 ] && [ "$RESTART" = 1 ]; }; then
        systemctl restart wardend.service
        sleep 3
        if systemctl is-active --quiet wardend.service; then
            info "Service running."
        else
            echo -e "\033[31m  wardend failed to start:\033[0m"
            systemctl --no-pager --full status wardend.service | head -15 || true
            if [ "$WAS_ACTIVE" = 1 ] && rollback; then
                note "the previous version is running again; the new one is in target/release"
            fi
            echo "  diagnose with: wardenctl doctor ; journalctl -u wardend -n 50"
            exit 1
        fi
    fi
fi

cat <<EOF

Warden installed.
  Configure : $CONFDIR/warden.toml  and  $CONFDIR/conf.d/*.toml
  Check     : wardenctl doctor
  Start     : systemctl enable --now wardend
  Watch     : wardenctl status ; wardenctl events -f
  Mode      : dry_run = true by default (detect & report only). Review 'wardenctl events',
              then enable remediation: 'wardenctl dry-run off' (kept across reloads and restarts,
              until 'wardenctl dry-run reset') or dry_run = false in the config.
EOF
