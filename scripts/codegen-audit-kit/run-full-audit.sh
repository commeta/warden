#!/usr/bin/env bash
# One-shot comprehensive Rust/LLVM/ELF + all upstream safe runtime profiles and stress.
set -Eeuo pipefail
ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$ROOT/audit.py" --full "$@"
