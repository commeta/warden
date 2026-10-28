#!/usr/bin/env bash
# Strict parser for lab.env. Never execute lab.env as shell code.
lab_die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
lab_load_config() {
  local root="$1" line key value lineno=0 mode
  declare -A seen_keys=()
  CFG="$root/lab.env"
  [[ -f "$CFG" && ! -L "$CFG" ]] || lab_die "Missing lab.env. Run cp lab.env.example lab.env; chmod 600 lab.env"
  mode="$(stat -c '%a' "$CFG")" || lab_die "Cannot inspect lab.env permissions"
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || lab_die "Unexpected lab.env mode '$mode'"
  (( (8#$mode & 077) == 0 )) || lab_die "lab.env must have no group/other permissions; run chmod 600 lab.env"
  LAB_IP=127.0.0.1 ATTACKER_IP=127.0.0.2
  DB_NAME=wardenlab DB_USER=wardenlab DB_PASSWORD=GENERATE
  # No default release: the version and its SHA-256 pin come from lab.env
  # alone (a default here went stale with every release — L8 of the 0.14.2 review).
  WARDEN_VERSION="" WARDEN_DEB_SHA256=""
  while IFS= read -r line || [[ -n "$line" ]]; do
    ((lineno+=1))
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$line" =~ ^([A-Z][A-Z0-9_]*)=([A-Za-z0-9_./:-]+)$ ]] || lab_die "$CFG:$lineno: expected KEY=value without quotes/spaces"
    key="${BASH_REMATCH[1]}"; value="${BASH_REMATCH[2]}"
    [[ -z "${seen_keys[$key]+x}" ]] || lab_die "$CFG:$lineno: duplicate key '$key'"
    seen_keys[$key]=1
    case "$key" in
      LAB_IP|ATTACKER_IP|DB_NAME|DB_USER|DB_PASSWORD|WARDEN_VERSION|WARDEN_DEB_SHA256) printf -v "$key" '%s' "$value" ;;
      *) lab_die "$CFG:$lineno: unsupported key '$key'" ;;
    esac
  done < "$CFG"
}
lab_validate_config() {
  [[ "$LAB_IP" == 127.0.0.1 ]] || lab_die "LAB_IP must be 127.0.0.1; all requests are local-only"
  [[ "$ATTACKER_IP" =~ ^127\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] || lab_die "ATTACKER_IP must be in 127.0.0.0/8"
  [[ "$ATTACKER_IP" != "$LAB_IP" && "$ATTACKER_IP" != 127.0.0.0 && "$ATTACKER_IP" != 127.255.255.255 ]] || lab_die "ATTACKER_IP must be a distinct usable loopback address"
  command -v python3 >/dev/null || lab_die "python3 is required"
  python3 - "$LAB_IP" "$ATTACKER_IP" <<'PY' || exit 1
import ipaddress, sys
lab, attacker = (ipaddress.IPv4Address(x) for x in sys.argv[1:])
net = ipaddress.IPv4Network('127.0.0.0/8')
if lab != ipaddress.IPv4Address('127.0.0.1') or lab not in net or attacker not in net or lab == attacker:
    raise SystemExit('ERROR: use LAB_IP=127.0.0.1 and a different ATTACKER_IP in 127.0.0.0/8')
PY
  [[ "$DB_NAME" =~ ^[A-Za-z0-9_]{1,32}$ ]] || lab_die "Unsafe DB_NAME"
  [[ "$DB_USER" =~ ^[A-Za-z0-9_]{1,32}$ ]] || lab_die "Unsafe DB_USER"
  [[ "$DB_PASSWORD" == GENERATE || "$DB_PASSWORD" =~ ^[A-Fa-f0-9]{16,128}$ ]] || lab_die "DB_PASSWORD must be GENERATE or 16..128 hex characters"
  [[ -n "$WARDEN_VERSION" && -n "$WARDEN_DEB_SHA256" ]] || lab_die "Set WARDEN_VERSION and WARDEN_DEB_SHA256 in lab.env (see lab.env.example)"
  [[ "$WARDEN_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || lab_die "WARDEN_VERSION must be numeric x.y.z"
  [[ "$WARDEN_DEB_SHA256" =~ ^[A-Fa-f0-9]{64}$ ]] || lab_die "WARDEN_DEB_SHA256 must be 64 hex characters"
}
lab_require_loopback() {
  local output
  output="$(ip -o -4 addr show dev lo 2>/dev/null || true)"
  [[ -n "$output" ]] || lab_die "Loopback interface lo is unavailable"
  grep -Eq '(^|[[:space:]])127\.0\.0\.1/8([[:space:]]|$)' <<< "$output" || lab_die "127.0.0.1/8 is not configured on lo"
}
# The SHA-256 placeholder of lab.env.example: the release is not pinned yet.
lab_sha_unpinned() { [[ "$1" =~ ^0{64}$ ]]; }
