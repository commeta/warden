#!/usr/bin/env python3
"""Create a compact, analysis-ready Warden evidence bundle from an audit directory."""
from __future__ import annotations
import argparse
import datetime as dt
import hashlib
import io
import json
import os
import shutil
import zlib
from pathlib import Path
import sys
import tarfile


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def parse_args():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('audit_dir', type=Path)
    p.add_argument('--output', type=Path, help='archive destination; default is next to AUDIT_DIR')
    p.add_argument('--diagnostics-only', action='store_true', help='logs, reports and collector version only; omit source, ELF, MIR, raw LLVM and runtime data')
    p.add_argument('--include-llvm-raw', action='store_true', help='include bulky artifacts/llvm-ir and artifacts/rust-asm')
    p.add_argument('--include-full-disassembly', action='store_true', help='include large full ELF objdump text files')
    p.add_argument('--include-perf-data', action='store_true', help='include raw *.perf.data samples (may be large)')
    p.add_argument('--run-id', action='append', help='include only selected followup run id; may be repeated')
    return p.parse_args()


def main() -> int:
    a = parse_args()
    if a.diagnostics_only and (a.include_llvm_raw or a.include_full_disassembly or a.include_perf_data):
        print('ERROR: --diagnostics-only cannot be combined with raw-data inclusion flags', file=sys.stderr)
        return 2
    if any(not run_id or Path(run_id).name != run_id or run_id in ('.', '..') for run_id in (a.run_id or [])):
        print('ERROR: --run-id must be a single directory name', file=sys.stderr)
        return 2
    root = a.audit_dir.expanduser().resolve()
    if not root.is_dir():
        print(f'ERROR: audit directory not found: {root}', file=sys.stderr)
        return 2
    stamp = dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    mode = 'diagnostics' if a.diagnostics_only else 'analysis'
    out = a.output.expanduser().resolve() if a.output else root.parent / f'{root.name}.{mode}-bundle-{stamp}.tar.gz'
    if out == root or root in out.parents:
        print('ERROR: output archive must be outside AUDIT_DIR', file=sys.stderr)
        return 2
    if out.exists():
        print(f'ERROR: refusing to overwrite existing archive: {out}', file=sys.stderr)
        return 2
    out.parent.mkdir(parents=True, exist_ok=True)

    selected: dict[str, Path] = {}
    excluded: list[str] = []

    def add_file(p: Path):
        if not p.is_file() or p.is_symlink():
            return
        rel = p.relative_to(root).as_posix()
        if rel in selected:
            return
        if p.name.endswith('.perf.data') and not a.include_perf_data:
            excluded.append(rel + ' [raw perf sample; use --include-perf-data]')
            return
        if not a.include_full_disassembly and p.name in ('objdump-disassembly.txt', 'llvm-objdump-disassembly.txt'):
            excluded.append(rel + ' [full disassembly; reproducible from ELF]')
            return
        selected[rel] = p

    def add_tree(rel_root: str, *, skip_git: bool = False, runtime_filter: bool = False):
        base = root / rel_root
        if not base.exists():
            return
        if base.is_file():
            add_file(base)
            return
        for p in sorted(base.rglob('*')):
            if not p.is_file() or p.is_symlink():
                continue
            relparts = p.relative_to(base).parts
            if skip_git and ('.git' in relparts or 'target' in relparts):
                continue
            if runtime_filter:
                # Keep measurements, configs and diagnostic logs, not bulky transient caches.
                if p.name.endswith('.perf.data'):
                    if a.include_perf_data:
                        add_file(p)
                    else:
                        excluded.append(p.relative_to(root).as_posix() + ' [raw perf sample; use --include-perf-data]')
                    continue
                if p.suffix not in ('.json', '.jsonl', '.log', '.txt', '.toml', '.stderr', '.stdout', '.csv') and p.name not in ('events',):
                    continue
            add_file(p)

    if a.diagnostics_only:
        add_tree('reports')
        add_tree('logs')
        add_file(root / 'manifest.json')
        add_file(root / 'artifacts/audit-kit/VERSION')
        run_root = root / 'followup-runs'
        runs = [run_root / name for name in a.run_id] if a.run_id else sorted(run_root.glob('*'))
        for run in runs:
            if run.is_dir() and not run.is_symlink():
                for kind in ('reports', 'logs'):
                    add_tree((run / kind).relative_to(root).as_posix())
        # Inventory omissions explicitly; a diagnostic bundle cannot replace the full audit.
        for path in sorted(root.rglob('*')):
            if path.is_file() and not path.is_symlink():
                rel = path.relative_to(root).as_posix()
                if rel not in selected and not any(row.startswith(rel + ' [') for row in excluded):
                    excluded.append(rel + ' [diagnostics-only]')
    else:
        # Source is necessary to map symbols/lines and to reproduce interpretation.
        add_tree('source/warden', skip_git=True)

        # Keep linked binaries, not intermediate object files/Cargo target trees.
        for name in ('wardend.production', 'wardend.release-unstripped', 'wardend.symbolized'):
            add_file(root / 'artifacts' / name)

        # Reports and build/test logs; discard only enormous full disassemblies by default.
        add_tree('reports')
        add_tree('logs')
        add_file(root / 'SHA256SUMS')

        # Selected raw LLVM outputs are optional because they can add hundreds of MB.
        if a.include_llvm_raw:
            add_tree('artifacts/llvm-ir')
            add_tree('artifacts/rust-asm')
        else:
            for rel in ('artifacts/llvm-ir', 'artifacts/rust-asm'):
                base = root / rel
                if base.exists():
                    for p in base.rglob('*'):
                        if p.is_file():
                            excluded.append(p.relative_to(root).as_posix() + ' [raw LLVM/asm; use --include-llvm-raw]')

        # Rust MIR and static codegen reports are compact and useful for source-to-LLVM tracing.
        add_tree('artifacts/mir')
        add_tree('artifacts/instrumented')
        add_tree('artifacts/audit-kit')
        add_tree('reports/codegen')

        # Runtime evidence from both original run-audit and isolated follow-up runs.
        for rel in ('runtime-profile', 'runtime-profile-preflight', 'profile-preflight-work', 'profile-work', 'profile-syscall-work', 'runtime-profile-syscalls', 'runtime-stress', 'runtime-stress-firewall', 'followup-runs'):
            if a.run_id and rel == 'followup-runs':
                for run_id in a.run_id:
                    add_tree(f'followup-runs/{run_id}', runtime_filter=True)
            else:
                add_tree(rel, runtime_filter=True)

    # Include a small explicit inventory so the receiver knows what was intentionally omitted.
    info = {
        'created_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
        'audit_dir_name': root.name,
        'mode': mode,
        'included_file_count': len(selected),
        'included_bytes_uncompressed': sum(p.stat().st_size for p in selected.values()),
        'options': {
            'diagnostics_only': a.diagnostics_only,
            'include_llvm_raw': a.include_llvm_raw,
            'include_full_disassembly': a.include_full_disassembly,
            'include_perf_data': a.include_perf_data,
            'run_ids': a.run_id or 'all followup-runs',
        },
        'excluded_file_count': len(excluded),
        'excluded_examples': excluded[:500],
        'note': ('Diagnostic evidence only; not a complete machine-code audit. Large logs can still make this bundle exceed transfer limits. ' if a.diagnostics_only else 'Original audit SHA256SUMS is included for provenance; ') + 'BUNDLE-SHA256SUMS covers only files in this bundle.'
    }
    unreadable = []
    for rel, path in selected.items():
        try:
            with path.open('rb') as stream:
                stream.read(1)
        except OSError as exc:
            unreadable.append(f'{rel}: {type(exc).__name__}: {exc}')
    if unreadable:
        print('ERROR: selected bundle files are not readable by the audit user:', file=sys.stderr)
        for row in unreadable[:100]:
            print(f'  {row}', file=sys.stderr)
        print('Restore ownership/read permission only within the corresponding audit output directories, then retry packaging.', file=sys.stderr)
        return 3

    info_bytes = (json.dumps(info, indent=2, ensure_ascii=False) + '\n').encode()
    # Estimate gzip size from bounded samples of the largest inputs. Sampling
    # avoids a false refusal when LLVM text compresses heavily, while binary
    # perf samples naturally estimate close to their original size.
    estimated_payload = 0
    sample_budget = 64 * 1024 * 1024
    for path in sorted(selected.values(), key=lambda item: item.stat().st_size, reverse=True):
        size = path.stat().st_size
        if size <= 0:
            continue
        sample_len = min(size, 1024 * 1024, sample_budget)
        if sample_len > 0:
            with path.open('rb') as stream:
                sample = stream.read(sample_len)
            sample_budget -= len(sample)
            ratio = min(1.0, len(zlib.compress(sample, 6)) / max(1, len(sample)))
        else:
            ratio = 1.0  # Unsampled files are conservatively treated as incompressible.
        estimated_payload += int(size * ratio * 1.15)  # tar headers + estimation margin
    estimated_bytes = estimated_payload + len(info_bytes) + 2 * 1024 * 1024
    free_bytes = shutil.disk_usage(out.parent).free
    reserve_bytes = max(64 * 1024 * 1024, int(estimated_bytes * 0.10))
    if free_bytes < estimated_bytes + reserve_bytes:
        print(f'ERROR: insufficient free space for requested bundle: estimated compressed payload={estimated_bytes:,} bytes, '
              f'free={free_bytes:,} bytes, required with reserve={estimated_bytes + reserve_bytes:,} bytes.', file=sys.stderr)
        return 4

    manifest_lines = [f'{sha256(p)}  {rel}' for rel, p in sorted(selected.items())]
    manifest_lines.append(f'{hashlib.sha256(info_bytes).hexdigest()}  BUNDLE-INFO.json')
    manifest_bytes = ('\n'.join(manifest_lines) + '\n').encode()

    try:
        with tarfile.open(out, 'w:gz', compresslevel=6) as tf:
            for rel, p in sorted(selected.items()):
                tf.add(p, arcname=f'{root.name}/{rel}', recursive=False)
            for name, data in (('BUNDLE-INFO.json', info_bytes), ('BUNDLE-SHA256SUMS', manifest_bytes)):
                ti = tarfile.TarInfo(f'{root.name}/{name}')
                ti.size = len(data)
                ti.mtime = int(dt.datetime.now(dt.timezone.utc).timestamp())
                ti.mode = 0o644
                tf.addfile(ti, io.BytesIO(data))
    except Exception:
        out.unlink(missing_ok=True)
        raise
    digest = sha256(out)
    Path(str(out) + '.sha256').write_text(f'{digest}  {out.name}\n', encoding='utf-8')
    print(f'Bundle: {out}')
    print(f'SHA256: {digest}')
    print(f'Included files: {len(selected) + 2:,}')
    print(f'Uncompressed included bytes: {info["included_bytes_uncompressed"]:,}')
    print(f'Excluded by policy: {len(excluded):,}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
