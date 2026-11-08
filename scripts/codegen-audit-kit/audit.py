#!/usr/bin/env python3
"""Reproducible Rust/LLVM/ELF audit collector for commeta/warden.

The runner is intentionally stdlib-only and should run as an ordinary user.
Root is requested only for opt-in runtime profiles and stress scenarios.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import tarfile
import time
from pathlib import Path
from typing import Any

from test_support import inspect_memory_pressure, wait_for_calm_memory, parse_test_log

KIT = Path(__file__).resolve().parent
VERSION = (KIT / "VERSION").read_text(encoding="utf-8").strip()
MLOCK_TEST = "selfstat::tests::a_peak_is_returned_even_under_mlockall"
REPO_URL = "https://github.com/commeta/warden.git"
PROFILE_ALL_SCENARIOS = (
    "idle", "memory", "cpu", "io", "stall", "limits", "network", "hardware", "kernel",
    "disk", "process", "exec_storm", "integrity", "systemd", "auth", "fim",
    "access_log", "waf", "health", "tuning", "all",
)
STRACE_SCENARIOS = ("process", "exec_storm", "waf", "auth")
STRESS_SAFE_SCENARIOS = ("exec_storm", "waf_v6_unique", "waf_v6_spread", "auth_unique")
MIR_PACKAGES = ("warden-core", "warden-sys", "warden-detect", "warden-respond", "wardend")


def utc_stamp() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", errors="replace")


class Audit:
    def __init__(self, out: Path, args: argparse.Namespace):
        self.out = out.resolve()
        self.args = args
        self.logs = self.out / "logs"
        self.reports = self.out / "reports"
        self.artifacts = self.out / "artifacts"
        self.build = self.out / "build"
        for p in (self.logs, self.reports, self.artifacts, self.build):
            p.mkdir(parents=True, exist_ok=True)
        self.steps: list[dict[str, Any]] = []
        self.started = time.time()
        self.env = os.environ.copy()
        cargo_bin = str(Path.home() / ".cargo" / "bin")
        llvm_bins = sorted(Path("/usr/lib").glob("llvm-*/bin"), reverse=True)
        path_prefix = [str(p) for p in llvm_bins] + [cargo_bin]
        self.env["PATH"] = os.pathsep.join(path_prefix + [self.env.get("PATH", "")])
        # Pin the compiler to the same release used by upstream CI unless explicitly
        # overridden. This makes a clean-machine run reproducible across stable updates.
        self.env["RUSTUP_TOOLCHAIN"] = getattr(args, "toolchain", None) or os.environ.get("WARDEN_RUST_TOOLCHAIN", "1.99.1")
        self.perf_available = False  # both PMU stat and sampled call-graph recording
        self.perf_stat_available = False
        self.perf_record_available = False
        self.perf_hardware_available = False
        self.perf_events_supported: list[str] = []
        self.full_pass_complete: bool | None = None
        # Preserve the exact collector/instrumentation code used for provenance.
        kit_copy = self.artifacts / "audit-kit"
        kit_copy.mkdir(parents=True, exist_ok=True)
        for name in ("audit.py", "test_support.py", "codegen-analysis.py", "instrument-bench.py", "install-deps.sh",
                     "run-audit.sh", "run-full-audit.sh", "continue-audit.sh", "pack-results.sh",
                     "README.md", "README.ru.md", "CHANGELOG.md", "VALIDATION.md"):
            src = KIT / name
            if src.is_file():
                shutil.copy2(src, kit_copy / name)
        for kit_test in sorted((KIT / "tests").glob("*")):
            if not kit_test.is_file() or kit_test.suffix not in (".py", ".sh"):
                continue
            (kit_copy / "tests").mkdir(parents=True, exist_ok=True)
            shutil.copy2(kit_test, kit_copy / "tests" / kit_test.name)
        write_text(kit_copy / "VERSION", VERSION + "\n")

    def log(self, message: str) -> None:
        print(f"\n==> {message}", flush=True)

    def run(self, name: str, argv: list[str], *, cwd: Path | None = None,
            env: dict[str, str] | None = None, timeout: int = 1800,
            required: bool = False, skip_on_failure: bool = False,
            stdout_path: Path | None = None) -> int:
        safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in name)
        log_path = stdout_path or (self.logs / f"{safe}.log")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        merged = self.env.copy()
        if env:
            merged.update({k: str(v) for k, v in env.items()})
        self.log(f"{name}: {shlex.join(argv)}")
        t0 = time.time()
        rc: int
        try:
            with log_path.open("w", encoding="utf-8", errors="replace") as logf:
                logf.write(f"$ {shlex.join(argv)}\n")
                logf.write(f"cwd: {cwd or Path.cwd()}\n\n")
                logf.flush()
                p = subprocess.run(argv, cwd=str(cwd) if cwd else None,
                                   env=merged, stdout=logf, stderr=subprocess.STDOUT,
                                   timeout=timeout, check=False)
                rc = p.returncode
        except FileNotFoundError as e:
            rc = 127
            with log_path.open("a", encoding="utf-8") as f:
                f.write(f"\nERROR: {e}\n")
        except subprocess.TimeoutExpired:
            rc = 124
            with log_path.open("a", encoding="utf-8") as f:
                f.write(f"\nERROR: timeout after {timeout}s\n")
        elapsed = round(time.time() - t0, 2)
        row = {"name": name, "argv": argv, "cwd": str(cwd) if cwd else None,
               "exit_code": rc, "elapsed_s": elapsed, "log": str(log_path.relative_to(self.out))}
        self.steps.append(row)
        status = "ok" if rc == 0 else ("skipped" if skip_on_failure and not required else "failed")
        self.steps[-1]["status"] = status
        state = {"ok": "OK", "skipped": "SKIPPED", "failed": "FAILED"}[status]
        print(f"[{state}] {name} ({elapsed}s; rc={rc})", flush=True)
        if required and rc != 0:
            raise RuntimeError(f"required step failed: {name}; see {log_path}")
        return rc

    def capture(self, name: str, argv: list[str], *, cwd: Path | None = None,
                timeout: int = 300) -> int:
        return self.run(name, argv, cwd=cwd, timeout=timeout)

    def command_exists(self, command: str) -> bool:
        return shutil.which(command, path=self.env.get("PATH")) is not None

    def collect_host(self, repo: Path) -> None:
        self.log("Collecting host and toolchain metadata")
        self.run("host_uname", ["uname", "-a"])
        self.run("host_lscpu", ["lscpu"])
        self.run("host_meminfo", ["bash", "-lc", "cat /proc/meminfo"])
        self.run("host_os_release", ["bash", "-lc", "cat /etc/os-release"])
        self.run("host_disk", ["df", "-hT"])
        self.run("host_mounts", ["findmnt", "-T", str(repo)])
        self.run("host_perf_sysctls", ["bash", "-lc",
                 "for f in /proc/sys/kernel/perf_event_paranoid /proc/sys/kernel/kptr_restrict; do echo \"## $f\"; cat \"$f\" 2>/dev/null || true; done"])
        self.run("host_installed_packages", ["bash", "-lc",
                 "dpkg-query -W -f='${binary:Package}\\t${Version}\\n' | sort"], timeout=300)
        self.run("rustc_version", ["rustc", "-Vv"])
        self.run("cargo_version", ["cargo", "-V"])
        if self.command_exists("rustup"):
            self.run("rustup_show", ["rustup", "show"])
            self.run("rustup_components", ["rustup", "component", "list", "--installed"])
        for name, executable, argv in (
            ("clang_version", "clang", ["clang", "--version"]),
            ("llvm_config", "llvm-config", ["llvm-config", "--version"]),
            ("objdump_version", "objdump", ["objdump", "--version"]),
            ("readelf_version", "readelf", ["readelf", "--version"]),
            ("perf_version", "perf", ["perf", "--version"]),
            ("valgrind_version", "valgrind", ["valgrind", "--version"]),
            ("linker_version", "ld", ["ld", "--version"]),
            ("lld_version", "ld.lld", ["ld.lld", "--version"]),
            ("gcc_version", "gcc", ["gcc", "--version"]),
        ):
            if self.command_exists(executable):
                self.run(name, argv)
        self.run("rust_target_cpus", ["rustc", "--print", "target-cpus"])
        self.run("rust_target_features", ["rustc", "--print", "target-features"])
        self.run("rust_target_cfg", ["rustc", "--print", "cfg"])
        if self.command_exists("perf"):
            self.run("perf_list", ["perf", "list"], timeout=180)
        if self.command_exists("llvm-config"):
            self.run("llvm_config_targets", ["llvm-config", "--targets-built", "--host-target", "--build-mode"])
        llvm_mcas = sorted(Path("/usr/lib").glob("llvm-*/bin/llvm-mca"))
        if self.command_exists("llvm-mca"):
            self.run("llvm_mca_version", ["llvm-mca", "--version"])
        elif llvm_mcas:
            for i, p in enumerate(llvm_mcas):
                self.run(f"llvm_mca_version_{i}", [str(p), "--version"])

        env_keys = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "RUSTUP_TOOLCHAIN", "CARGO_HOME", "RUSTUP_HOME",
                    "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET", "CARGO_INCREMENTAL",
                    "CARGO_PROFILE_RELEASE_LTO", "CARGO_PROFILE_RELEASE_CODEGEN_UNITS",
                    "CARGO_PROFILE_RELEASE_OPT_LEVEL", "CARGO_PROFILE_RELEASE_DEBUG",
                    "CARGO_PROFILE_RELEASE_STRIP", "CARGO_PROFILE_RELEASE_PANIC",
                    "CARGO_PROFILE_RELEASE_RPATH", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER",
                    "SOURCE_DATE_EPOCH", "CC", "CXX", "CFLAGS", "CXXFLAGS", "AR", "LD",
                    "LDFLAGS", "PKG_CONFIG_PATH")
        env_snapshot = {k: os.environ[k] for k in env_keys if k in os.environ}
        write_text(self.reports / "environment.json", json.dumps({
            "python": sys.version, "platform": platform.platform(), "machine": platform.machine(),
            "environment_overrides": env_snapshot,
            "rustup_toolchain_selected": self.env.get("RUSTUP_TOOLCHAIN"),
            "note": "Only selected build-related variables are recorded; the full environment is deliberately not collected."
        }, indent=2) + "\n")

    def prepare_repo(self) -> Path:
        if self.args.repo:
            repo = Path(self.args.repo).expanduser().resolve()
            if not (repo / "Cargo.toml").is_file():
                raise RuntimeError(f"--repo is not a Rust workspace root: {repo}")
        else:
            repo = (self.out / "source" / "warden").resolve()
            if not repo.exists():
                repo.parent.mkdir(parents=True, exist_ok=True)
                self.run("git_init", ["git", "init", str(repo)], required=True)
                self.run("git_remote", ["git", "remote", "add", "origin", REPO_URL], cwd=repo, required=True)
                self.run("git_fetch", ["git", "fetch", "--depth", "1", "origin", self.args.ref],
                         cwd=repo, timeout=900, required=True)
                self.run("git_checkout", ["git", "checkout", "--detach", "FETCH_HEAD"], cwd=repo, required=True)
        # Refuse to silently audit an absent git history; source archives are allowed with a warning.
        rev = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        if rev.returncode == 0:
            self.run("source_git_status", ["git", "status", "--short", "--branch"], cwd=repo)
            self.run("source_git_commit", ["git", "show", "-s", "--format=fuller", "HEAD"], cwd=repo)
            # Record the exact local delta, not only a status summary. Avoid dumping
            # remote URLs, which can contain embedded credentials in private checkouts.
            self.run("source_git_diff_stat", ["git", "diff", "--stat", "HEAD"], cwd=repo)
            self.run("source_git_diff_binary", ["git", "diff", "--binary", "HEAD"], cwd=repo,
                     stdout_path=self.reports / "source-worktree.patch", timeout=300)
            untracked = subprocess.run(["git", "ls-files", "--others", "--exclude-standard", "-z"],
                                       cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            untracked_rows = []
            if untracked.returncode == 0:
                for raw in untracked.stdout.split(b"\0"):
                    if not raw:
                        continue
                    rel = os.fsdecode(raw)
                    candidate = repo / rel
                    if candidate.is_file():
                        try:
                            untracked_rows.append(f"{sha256(candidate)}  {rel}")
                        except OSError:
                            pass
            if untracked_rows:
                write_text(self.reports / "source-untracked.sha256", "\n".join(untracked_rows) + "\n")
            commit = rev.stdout.strip()
        else:
            commit = "not-a-git-checkout"
            print("WARNING: source directory has no Git metadata; source identity will be based on file hashes.")
        requested_ref = self.args.ref if not self.args.repo else "provided-local-checkout"
        write_text(self.reports / "source-identity.txt",
                   f"repository={repo}\nref_requested={requested_ref}\ncommit={commit}\n")
        self.repo = repo
        return repo

    def collect_source_metadata(self, repo: Path) -> None:
        self.run("cargo_metadata", ["cargo", "metadata", "--locked", "--no-deps", "--format-version", "1"],
                 cwd=repo, timeout=300)
        # Capture the resolved feature graph; this is a critical part of codegen provenance.
        self.run("cargo_tree_features", ["cargo", "tree", "--locked", "-e", "features"], cwd=repo, timeout=900)
        self.run("cargo_tree_verbose", ["cargo", "tree", "--locked", "-e", "normal,build,dev", "-v"], cwd=repo, timeout=900)
        for path in ("Cargo.toml", "Cargo.lock", "rust-toolchain", "rust-toolchain.toml", ".cargo/config", ".cargo/config.toml"):
            p = repo / path
            if p.is_file():
                dest = self.reports / "source-config" / path.replace("/", "__")
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(p, dest)
        # Hash tracked source files, including staged/unstaged modifications,
        # ignoring build outputs and Git internals. Untracked files are recorded
        # separately in prepare_repo(); worktree patch is preserved there too.
        r = subprocess.run(["git", "ls-files", "-z"], cwd=repo, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        rows = []
        if r.returncode == 0:
            for raw in r.stdout.split(b"\0"):
                if not raw:
                    continue
                p = repo / os.fsdecode(raw)
                if p.is_file():
                    try:
                        rows.append(f"{sha256(p)}  {os.fsdecode(raw)}")
                    except OSError:
                        pass
        if rows:
            write_text(self.reports / "source-files.sha256", "\n".join(rows) + "\n")

    def build_binaries(self, repo: Path) -> tuple[Path | None, Path | None]:
        prod_target = self.build / "production-target"
        unstripped_target = self.build / "release-unstripped-target"
        sym_target = self.build / "symbolized-target"
        cmd = ["cargo", "build", "--locked", "--release", "--package", "wardend", "--bin", "wardend", "-vv"]

        # 1) The project's actual production release profile.
        self.run("build_production_release", cmd, cwd=repo,
                 env={"CARGO_TARGET_DIR": str(prod_target)}, timeout=7200, required=True)
        prod = prod_target / "release" / "wardend"
        if not prod.is_file():
            raise RuntimeError(f"Cargo returned success but expected binary was not found: {prod}")
        prod_copy = self.artifacts / "wardend.production"
        shutil.copy2(prod, prod_copy)

        # 2) Same optimized release profile, but retain symbols; debug info stays off.
        # This is the controlled comparison against production (not the debug-symbolized build).
        self.run("build_release_unstripped", cmd, cwd=repo,
                 env={"CARGO_TARGET_DIR": str(unstripped_target),
                      "CARGO_PROFILE_RELEASE_STRIP": "none",
                      "CARGO_PROFILE_RELEASE_DEBUG": "0"},
                 timeout=7200, required=True)
        unstripped = unstripped_target / "release" / "wardend"
        if not unstripped.is_file():
            raise RuntimeError(f"Cargo returned success but expected unstripped binary was not found: {unstripped}")
        unstripped_copy = self.artifacts / "wardend.release-unstripped"
        shutil.copy2(unstripped, unstripped_copy)

        # 3) A separately symbolized binary with line tables for source-level inspection.
        self.run("build_release_symbolized", cmd, cwd=repo,
                 env={"CARGO_TARGET_DIR": str(sym_target),
                      "CARGO_PROFILE_RELEASE_STRIP": "none",
                      "CARGO_PROFILE_RELEASE_DEBUG": "line-tables-only"},
                 timeout=7200, required=True)
        sym = sym_target / "release" / "wardend"
        if not sym.is_file():
            raise RuntimeError(f"Cargo returned success but expected symbolized binary was not found: {sym}")
        sym_copy = self.artifacts / "wardend.symbolized"
        shutil.copy2(sym, sym_copy)

        write_text(self.reports / "binary-hashes.txt",
                   f"{sha256(prod_copy)}  artifacts/wardend.production\n"
                   f"{sha256(unstripped_copy)}  artifacts/wardend.release-unstripped\n"
                   f"{sha256(sym_copy)}  artifacts/wardend.symbolized\n")

        sections = {
            "production": self._extract_text_hash(prod_copy, self.reports / "production.text.sha256"),
            "release_unstripped": self._extract_text_hash(unstripped_copy, self.reports / "release-unstripped.text.sha256"),
            "symbolized": self._extract_text_hash(sym_copy, self.reports / "symbolized.text.sha256"),
        }
        available = all(record is not None for record in sections.values())
        identical = (sections["production"]["sha256"] == sections["release_unstripped"]["sha256"]) if available else None
        comparison = {"available": available, "production_vs_release_unstripped_identical": identical,
                      "sections": sections,
                      "note": "Byte equality describes only .text, not semantic equivalence. The symbolized build is a separate source-navigation aid."}
        write_text(self.reports / "text-section-comparison.json", json.dumps(comparison, indent=2) + "\n")
        rows = ["production_vs_release_unstripped_identical=" + (str(identical).lower() if available else "unavailable")]
        for label, record in sections.items():
            rows += [f"{label}_text_bytes={record['bytes'] if record else 'unavailable'}",
                     f"{label}_text_sha256={record['sha256'] if record else 'unavailable'}"]
        rows.append(comparison["note"])
        write_text(self.reports / "text-section-comparison.txt", "\n".join(rows) + "\n")
        print(f"INFO: production/unstripped .text identical={identical}; see text-section-comparison.json", flush=True)

        self.symbol_target = sym_target
        self.unstripped_target = unstripped_target
        self.production_target = prod_target
        self.symbolized_binary = sym_copy
        self.unstripped_binary = unstripped_copy
        write_text(self.reports / "runtime-binary-provenance.json", json.dumps({
            "baseline_profile_binary": {"path": "artifacts/wardend.production", "sha256": sha256(prod_copy),
                                        "purpose": "exact production Release binary for 21 CPU/RSS profiles and strace summaries"},
            "perf_stress_binary": {"path": "artifacts/wardend.release-unstripped", "sha256": sha256(unstripped_copy),
                                   "purpose": "Release strip=none, debug=0 binary retaining symbols; consult measured .text comparison before relating it to production"},
            "source_mapping_binary": {"path": "artifacts/wardend.symbolized", "sha256": sha256(sym_copy),
                                      "purpose": "line-table symbolized ELF for source-interleaved static disassembly and LLVM-MCA input"},
            "note": "Do not treat profile and stress CPU percentages as a single directly comparable data series: profile is production ELF; perf stress runs with the symbol-retaining unstripped ELF."
        }, indent=2) + "\n")
        return prod_copy, sym_copy

    def _extract_text_hash(self, binary: Path, output: Path) -> dict[str, Any] | None:
        section = self.build / (binary.name + ".text")
        rc = self.run(f"extract_text_{binary.name}", ["objcopy", "--dump-section", f".text={section}", str(binary)], timeout=300)
        if rc == 0 and section.is_file():
            record = {"sha256": sha256(section), "bytes": section.stat().st_size}
            write_text(output, f"{record['sha256']}  .text\n")
            section.unlink(missing_ok=True)
            return record
        write_text(output, "unavailable\n")
        return None

    def analyze_elf(self, binary: Path, label: str, *, full_disassembly: bool = True) -> None:
        base = self.reports / "elf" / label
        base.mkdir(parents=True, exist_ok=True)
        self.run(f"{label}_file", ["file", str(binary)])
        self.run(f"{label}_size", ["size", "-A", str(binary)])
        self.run(f"{label}_readelf_header", ["readelf", "-h", "-l", "-S", "-W", str(binary)], stdout_path=base / "readelf-header-sections.txt")
        self.run(f"{label}_readelf_dynamic", ["readelf", "-d", "-Ws", "-W", str(binary)], stdout_path=base / "readelf-dynamic-symbols.txt")
        self.run(f"{label}_readelf_notes", ["readelf", "-n", str(binary)], stdout_path=base / "readelf-notes-buildid.txt")
        self.run(f"{label}_nm_symbols", ["nm", "-C", "--defined-only", "--size-sort", "-r", str(binary)], stdout_path=base / "nm-demangled-size-sorted.txt")
        if full_disassembly:
            disasm = ["objdump", "-d", "-C"]
            if platform.machine().lower() in ("x86_64", "amd64"):
                disasm.append("-Mintel")
            disasm.append(str(binary))
            self.run(f"{label}_objdump", disasm, timeout=1800, stdout_path=base / "objdump-disassembly.txt")
            if self.command_exists("llvm-objdump"):
                llvm_dis = ["llvm-objdump", "--disassemble", "--demangle", str(binary)]
                self.run(f"{label}_llvm_objdump", llvm_dis, timeout=1800, stdout_path=base / "llvm-objdump-disassembly.txt")
        else:
            write_text(base / "disassembly-note.txt",
                       "Full disassembly omitted to avoid duplicating the very large production/symbolized disassemblies. Symbol table and ELF metadata are retained.\n")
        write_text(base / "sha256.txt", f"{sha256(binary)}  {binary.name}\n")

    def _copy_fresh_llvm_outputs(self, label: str, target_dir: Path, started_ns: int) -> dict[str, Any]:
        release_dir = target_dir / "release"
        report: dict[str, Any] = {"label": label, "llvm_ir": [], "assembly": []}
        for suffix, key, base in (("*.ll", "llvm_ir", self.artifacts / "llvm-ir"),
                                  ("*.s", "assembly", self.artifacts / "rust-asm")):
            files = sorted((p for p in release_dir.rglob(suffix)
                            if p.is_file() and p.stat().st_mtime_ns >= started_ns),
                           key=lambda p: p.stat().st_mtime_ns, reverse=True) if release_dir.exists() else []
            if files:
                dest = base / label
                dest.mkdir(parents=True, exist_ok=True)
                for src in files:
                    name = f"{label}-{src.name}"
                    shutil.copy2(src, dest / name)
                    report[key].append(str((dest / name).relative_to(self.out)))
        report["llvm_ir_count"] = len(report["llvm_ir"])
        report["assembly_count"] = len(report["assembly"])
        return report

    def collect_codegen(self, repo: Path, sym: Path) -> None:
        # Emit pre-link crate IR/assembly using the optimized, no-debug Release
        # target. The final Fat-LTO ELF is still authoritative for linked code.
        target = getattr(self, "unstripped_target", sym)
        env = {"CARGO_TARGET_DIR": str(target),
               "CARGO_PROFILE_RELEASE_STRIP": "none",
               "CARGO_PROFILE_RELEASE_DEBUG": "0"}
        package_targets = [("wardend", ["--bin", "wardend"])]
        if getattr(self.args, "full", False):
            package_targets.extend((
                ("warden-core", ["--lib"]),
                ("warden-sys", ["--lib"]),
                ("warden-detect", ["--lib"]),
                ("warden-respond", ["--lib"]),
            ))
        emit_inventory: dict[str, Any] = {}
        for package, target_args in package_targets:
            started_ns = time.time_ns()
            argv = ["cargo", "rustc", "--locked", "--release", "--package", package, *target_args,
                    "--", "--emit=llvm-ir,asm"]
            step_name = "rustc_emit_llvm_ir_asm" if package == "wardend" else f"rustc_emit_llvm_{package.replace('-', '_')}"
            rc = self.run(step_name, argv, cwd=repo, env=env, timeout=3600)
            record = self._copy_fresh_llvm_outputs(package, target, started_ns)
            record["exit_code"] = rc
            record["ok"] = rc == 0 and record["llvm_ir_count"] > 0 and record["assembly_count"] > 0
            emit_inventory[package] = record
        write_text(self.reports / "codegen" / "llvm-emit-inventory.json",
                   json.dumps({"complete": all(x["ok"] for x in emit_inventory.values()),
                               "packages": emit_inventory}, indent=2) + "\n")
        if not all(x["ok"] for x in emit_inventory.values()):
            self.validation_failure("llvm_emit_coverage", "Fresh LLVM IR or assembly missing for a selected crate")

        if self.command_exists("cargo-bloat"):
            self.run("cargo_bloat_crates", ["cargo", "bloat", "--locked", "--release", "--package", "wardend", "--bin", "wardend", "--crates"], cwd=repo, env=env, timeout=1800)
            self.run("cargo_bloat_top200", ["cargo", "bloat", "--locked", "--release", "--package", "wardend", "--bin", "wardend", "-n", "200"], cwd=repo, env=env, timeout=1800)
        else:
            write_text(self.reports / "cargo-bloat-unavailable.txt", "Install with: cargo install cargo-bloat\n")
        if self.command_exists("cargo-llvm-lines"):
            self.run("cargo_llvm_lines", ["cargo", "llvm-lines", "--release", "--package", "wardend", "--bin", "wardend"], cwd=repo, env=env, timeout=1800)
        else:
            write_text(self.reports / "cargo-llvm-lines-unavailable.txt", "Install with: cargo install cargo-llvm-lines (requires rustc-dev on many toolchains).\n")

        if getattr(self.args, "full", False):
            self.collect_mir(repo, sym)

        binary = getattr(self, "symbolized_binary", self.artifacts / "wardend.symbolized")
        codegen_dir = self.reports / "codegen"
        codegen_dir.mkdir(parents=True, exist_ok=True)
        nm_out = codegen_dir / "wardend-symbols-demangled.txt"
        nm_rc = self.run("wardend_final_elf_nm", ["nm", "-C", "-S", "--defined-only", "--size-sort", "-r", str(binary)],
                         stdout_path=nm_out, timeout=600)
        if nm_rc == 0 and nm_out.exists():
            lines = nm_out.read_text(encoding="utf-8", errors="replace").splitlines()
            wanted = {
                "exec_pipeline_on_exec": "ExecPipeline>::on_exec",
                "exec_pipeline_fast_candidate": "ExecPipeline>::fast_candidate",
                "exec_pipeline_fast_checks_pass": "ExecPipeline>::fast_checks_pass",
                "process_scanner_tick": "ProcessScanner::tick",
                "disk_detector_tick": "DiskDetector::tick",
                "responder_run_one": "Responder::run_one",
                "engine_process": "Engine::process",
            }
            for label, needle in wanted.items():
                matches = []
                for line in lines:
                    parts = line.split(maxsplit=3)
                    if len(parts) == 4 and self._symbol_matches(parts[3], needle):
                        try:
                            address = int(parts[0], 16)
                            length = int(parts[1], 16)
                        except ValueError:
                            continue
                        if length:
                            matches.append((parts[3], line, address, length))
                if not matches:
                    write_text(codegen_dir / f"{label}.status.txt",
                               f"NOT_FOUND_AS_INDEPENDENT_SYMBOL\nneedle={needle}\n"
                               "Possible explanations: inlined into a caller, internalized/removed by LTO, or symbol name changed. "
                               "This is not counted as a failed build step.\n")
                    continue
                out = codegen_dir / f"{label}.objdump.txt"
                source_out = codegen_dir / f"{label}.source-interleaved.txt"
                with out.open("w", encoding="utf-8") as f, source_out.open("w", encoding="utf-8") as sf:
                    for symbol, nm_line, address, size_bytes in matches:
                        f.write(f"\n### SYMBOL: {symbol} (address=0x{address:x}; size={size_bytes})\n{nm_line}\n")
                        sf.write(f"\n### SYMBOL: {symbol}\n{nm_line}\n")
                        objdump_cmd = ["objdump", "-d", "-C"]
                        if platform.machine().lower() in ("x86_64", "amd64"):
                            objdump_cmd.append("-Mintel")
                        objdump_cmd.extend([f"--start-address=0x{address:x}",
                                             f"--stop-address=0x{address + size_bytes:x}", str(binary)])
                        proc = subprocess.run(
                            objdump_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace", check=False, cwd=repo)
                        f.write(proc.stdout)
                        if proc.returncode != 0:
                            f.write(f"\nobjdump exit code: {proc.returncode}\n")
                        source_cmd = ["objdump", "-S", "-d", "-C"]
                        if platform.machine().lower() in ("x86_64", "amd64"):
                            source_cmd.append("-Mintel")
                        source_cmd.extend([f"--start-address=0x{address:x}",
                                            f"--stop-address=0x{address + size_bytes:x}", str(binary)])
                        source_proc = subprocess.run(
                            source_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                            encoding="utf-8", errors="replace", check=False, cwd=repo)
                        sf.write(source_proc.stdout)
                        if source_proc.returncode != 0:
                            sf.write(f"\nobjdump -S exit code: {source_proc.returncode}\n")
                write_text(codegen_dir / f"{label}.status.txt",
                           f"FOUND\nmatching_symbols={len(matches)}\nfile={out.relative_to(self.out)}\n"
                           f"source_interleaved={source_out.relative_to(self.out)}\n")
        else:
            write_text(codegen_dir / "symbol-extraction.status.txt",
                       "SKIPPED: nm unavailable or failed; see reports/codegen/wardend-symbols-demangled.txt\n")

    @staticmethod
    def _symbol_matches(name: str, selector: str) -> bool:
        if selector in name:
            return True
        owner, sep, method = selector.rpartition("::")
        if not sep:
            return False
        owner = owner.removesuffix(">")
        return re.search(r"(?:<|::)" + re.escape(owner)
                         + r"(?: as [^>]+)?>::" + re.escape(method) + r"(?:$|<)", name) is not None

    def collect_mir(self, repo: Path, sym: Path) -> None:
        """Collect pre-LLVM MIR from the pinned CI rustc for selected workspace crates.

        MIR is supplemental compiler evidence, not the final post-LTO machine code.
        The final linked ELF remains the source of truth for machine instructions.
        """
        mir_dir = self.artifacts / "mir"
        mir_dir.mkdir(parents=True, exist_ok=True)
        packages = (
            ("warden-core", "--lib"),
            ("warden-sys", "--lib"),
            ("warden-detect", "--lib"),
            ("warden-respond", "--lib"),
            ("wardend", "--bin wardend"),
        )
        for package, target in packages:
            argv = ["cargo", "rustc", "--locked", "--release", "--package", package, *target.split(), "--", "--emit=mir"]
            name = f"rustc_emit_mir_{package.replace('-', '_')}"
            started_ns = time.time_ns()
            rc = self.run(name, argv, cwd=repo, env={"CARGO_TARGET_DIR": str(sym),
                      "CARGO_PROFILE_RELEASE_STRIP": "none",
                      "CARGO_PROFILE_RELEASE_DEBUG": "line-tables-only"}, timeout=1800)
            release_dir = sym / "release"
            candidates = sorted(release_dir.rglob("*.mir"), key=lambda x: x.stat().st_mtime_ns, reverse=True) if release_dir.exists() else []
            # Copy only artifacts actually modified during this invocation. This avoids
            # accidentally attributing stale MIR from a prior build to this crate.
            copied = 0
            if rc == 0:
                for src in candidates:
                    try:
                        if src.stat().st_mtime_ns < started_ns:
                            continue
                        dst = mir_dir / f"{package}-{src.name}"
                        shutil.copy2(src, dst)
                        copied += 1
                    except OSError:
                        pass
            write_text(mir_dir / f"{package}.status.txt",
                       f"command={name}; exit_code={rc}; mir_files_copied={copied}\n"
                       + ("MIR is emitted by rustc before LLVM code generation; compare with final ELF, not as a substitute.\n"
                          if copied else "No fresh MIR file was emitted for this package; inspect the command log.\n"))

    def run_codegen_metrics(self) -> None:
        script = KIT / "codegen-analysis.py"
        if not script.is_file():
            write_text(self.reports / "codegen-analysis-skipped.txt", "SKIPPED: codegen-analysis.py is missing.\n")
            return
        prod = self.artifacts / "wardend.production"
        unstripped = self.artifacts / "wardend.release-unstripped"
        symbolized = self.artifacts / "wardend.symbolized"
        if not all(x.is_file() for x in (prod, unstripped, symbolized)):
            write_text(self.reports / "codegen-analysis-skipped.txt", "SKIPPED: one or more ELF artifacts are missing.\n")
            return
        codegen = self.reports / "codegen"
        mca_cpu = self.resolve_mca_cpu(getattr(self.args, "mca_cpu", "auto"))
        write_text(codegen / "llvm-mca-cpu-model.txt",
                   f"requested={getattr(self.args, 'mca_cpu', 'auto')}\nresolved={mca_cpu}\n"
                   "LLVM-MCA is a static throughput/latency model, not a runtime measurement.\n")
        self.run("static_machine_code_analysis",
                 [sys.executable, str(script), "--production", str(prod), "--unstripped", str(unstripped),
                  "--symbolized", str(symbolized), "--out", str(codegen), "--mca-cpu", mca_cpu],
                 timeout=1800)

    def resolve_mca_cpu(self, requested: str) -> str:
        """Resolve a conservative LLVM-MCA model; never guess a specific Intel core."""
        if requested and requested.lower() not in ("auto", "native"):
            return requested
        try:
            info = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="replace")
            vendor = re.search(r"^vendor_id\s*:\s*(.+)$", info, re.M)
            family = re.search(r"^cpu family\s*:\s*(\d+)$", info, re.M)
            if vendor and family and vendor.group(1).strip() == "AuthenticAMD" and int(family.group(1)) == 23:
                return "znver1"
        except (OSError, ValueError):
            pass
        return "generic"

    def _is_known_fuzz_smoke_timing_failure(self, log_path: Path) -> tuple[bool, dict[str, Any]]:
        """Recognize only the upstream modsecurity cold-start timing guard.

        This is not a blanket retry: any additional failed test, a different
        fuzz target, or a different failure shape remains a hard failure.
        """
        try:
            content = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            return False, {"reason": f"cannot read test log: {exc}"}
        failed_tests = re.findall(r"(?m)^test ([A-Za-z0-9_:]+) \.\.\. FAILED$", content)
        failed_summaries = re.findall(r"(?m)^test result: FAILED\..*$", content)
        timing = re.search(r"(?m)^modsecurity: ([0-9]+\.[0-9]+)s on a ([0-9]+)-byte input$", content)
        elapsed = float(timing.group(1)) if timing else None
        # Only a tiny 50ms overrun of the upstream <1s guard is classified as
        # likely scheduler pre-emption. Larger overruns may signal a real parser issue.
        scheduler_edge = elapsed is not None and 1.0 <= elapsed <= 1.05
        parsed = parse_test_log(content)
        matched = (not parsed["compiler_errors"] and parsed["counts"]["failed"] == 1
                   and failed_tests == ["tests::smoke_run_of_every_target"]
                   and len(failed_summaries) == 1 and timing is not None and scheduler_edge
                   and "thread 'tests::smoke_run_of_every_target'" in content)
        details = {
            "failed_tests": failed_tests,
            "failed_test_summaries": failed_summaries,
            "modsecurity_elapsed_s": elapsed,
            "modsecurity_input_bytes": int(timing.group(2)) if timing else None,
            "scheduler_edge_window_s": [1.0, 1.05],
            "reason": "matches the single upstream libFuzzer smoke-test modsecurity timing guard within the 50ms scheduler-edge window" if matched
                      else "failure does not match the exact, bounded timing-retry signature",
        }
        return matched, details

    def _write_cargo_test_failure_report(self, log_path: Path) -> None:
        try:
            content = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            write_text(self.reports / "cargo-test-failure-analysis.json",
                       json.dumps({"log": str(log_path), "read_error": str(exc)}, indent=2) + "\n")
            return
        failed_tests = re.findall(r"(?m)^test ([A-Za-z0-9_:]+) \.\.\. FAILED$", content)
        summaries = re.findall(r"(?m)^test result: FAILED\..*$", content)
        diagnostics = [line.strip() for line in content.splitlines()
                       if "panicked at" in line or line.lstrip().startswith("error:") or "assertion" in line]
        tail = "\n".join(content.splitlines()[-120:])
        write_text(self.reports / "cargo-test-failure-analysis.json", json.dumps({
            "log": str(log_path.relative_to(self.out)),
            "failed_tests": failed_tests, "failed_test_summaries": summaries,
            "diagnostic_lines": diagnostics[-80:], "tail_120_lines": tail,
            "note": "Failure excerpts are evidence. See test-validation.json and test-memory-pressure.json; no failed assertion is ignored."
        }, indent=2, ensure_ascii=False) + "\n")

    def _retry_known_fuzz_smoke_timing_failure(self, repo: Path, test_target: Path,
                                               prefix: list[str], initial_rc: int) -> None:
        initial_log = self.logs / "cargo_test_ci_root_serial.log"
        matched, details = self._is_known_fuzz_smoke_timing_failure(initial_log)
        report: dict[str, Any] = {"initial_exit_code": initial_rc, "retry_triggered": matched,
                                  "initial_log": str(initial_log.relative_to(self.out)), **details}
        if not matched:
            write_text(self.reports / "cargo-test-retry.json", json.dumps(report, indent=2) + "\n")
            return
        cargo_home = self.env.get("CARGO_HOME", str(Path.home() / ".cargo"))
        rustup_home = self.env.get("RUSTUP_HOME", str(Path.home() / ".rustup"))
        retry_cmd = prefix + ["env", f"PATH={self.env.get('PATH', '')}",
                              f"CARGO_HOME={cargo_home}", f"RUSTUP_HOME={rustup_home}",
                              f"RUSTUP_TOOLCHAIN={self.env.get('RUSTUP_TOOLCHAIN', '1.99.1')}",
                              f"CARGO_TARGET_DIR={test_target}", "CARGO_INCREMENTAL=0",
                              "CARGO_PROFILE_DEV_DEBUG=line-tables-only", "CARGO_PROFILE_TEST_DEBUG=line-tables-only",
                              "cargo", "test", "--package", "warden-fuzz",
                              "--locked", "--lib", "tests::smoke_run_of_every_target", "--", "--exact", "--test-threads=1"]
        time.sleep(1.0)  # let the host return to an idle state after the workspace test suite
        retry_rc = self.run("cargo_test_ci_root_serial_retry", retry_cmd, cwd=repo, timeout=900)
        report["retry_exit_code"] = retry_rc
        report["retry_command"] = retry_cmd
        retry_results = parse_test_log((self.logs / "cargo_test_ci_root_serial_retry.log").read_text())
        recovered = retry_rc == 0 and retry_results["counts"]["passed"] == 1 and retry_results["counts"]["failed"] == 0
        report["recovered"] = recovered
        if recovered:
            # Preserve the original rc=101 in the step record, but represent the
            # narrowly recovered step explicitly so the full-pass gate can reason
            # about it without erasing the first failure.
            for step in reversed(self.steps):
                if step.get("name") == "cargo_test_ci_root_serial":
                    step["status"] = "recovered"
                    step["recovered_by"] = "cargo_test_ci_root_serial_retry"
                    break
        if prefix and test_target.exists():
            owner = f"{os.getuid()}:{os.getgid()}"
            self.run("restore_retry_test_target_ownership",
                     prefix + ["chown", "-R", owner, str(test_target)], timeout=600)
        write_text(self.reports / "cargo-test-retry.json", json.dumps(report, indent=2) + "\n")

    def run_tests(self, repo: Path) -> None:
        if self.args.skip_tests:
            write_text(self.reports / "tests-skipped.txt", "Skipped by --skip-tests; test coverage is not validated.\n")
            return
        self.run("cargo_fmt_check", ["cargo", "fmt", "--all", "--check"], cwd=repo, timeout=900)
        # Missing clippy is a failed selected check, not a successful collection.
        self.run("cargo_clippy_ci_strict",
                 ["cargo", "clippy", "--workspace", "--all-targets", "--locked", "--", "-D", "warnings"],
                 cwd=repo, env={"CARGO_TARGET_DIR": str(self.build / "clippy-target")}, timeout=3600)

        test_target = self.build / "tests-ci-root"
        env = {"CARGO_TARGET_DIR": str(test_target), "CARGO_INCREMENTAL": "0",
               "CARGO_PROFILE_DEV_DEBUG": "line-tables-only", "CARGO_PROFILE_TEST_DEBUG": "line-tables-only"}
        # Compile as the invoking user, then let build pressure settle before the
        # mlock test. These settings mirror upstream's tested lab-kit source runner.
        compiled = self.run("cargo_test_compile", ["cargo", "test", "--workspace", "--locked", "--no-run"],
                            cwd=repo, env=env, timeout=7200)
        prefix = self.root_prefix()
        root_serial = prefix is not None
        report: dict[str, Any] = {"coverage_complete": False, "root_serial": root_serial,
                                  "compile_exit_code": compiled, "sensitive_test": MLOCK_TEST,
                                  "note": "Workspace and the isolated mlock test are separate required checks; no assertions are removed."}
        report_path = self.reports / "test-validation.json"
        if compiled != 0:
            self._write_cargo_test_failure_report(self.logs / "cargo_test_compile.log")
            write_text(report_path, json.dumps(report, indent=2) + "\n")
            return
        if not root_serial:
            write_text(self.reports / "test-mode-note.txt", "Root unavailable: upstream privileged coverage cannot be certified.\n")
            self.validation_failure("test_privileges", "Root unavailable; unprivileged workspace results are supplemental")
        cargo_home = self.env.get("CARGO_HOME", str(Path.home() / ".cargo"))
        rustup_home = self.env.get("RUSTUP_HOME", str(Path.home() / ".rustup"))
        command = (prefix or []) + ["env", f"PATH={self.env.get('PATH', '')}",
                    f"CARGO_HOME={cargo_home}", f"RUSTUP_HOME={rustup_home}",
                    f"RUSTUP_TOOLCHAIN={self.env['RUSTUP_TOOLCHAIN']}",
                    *(f"{k}={v}" for k, v in env.items()), "cargo", "test"]
        workspace_name = "cargo_test_ci_root_serial" if root_serial else "cargo_test_ci_serial_unprivileged"
        # --no-fail-fast is essential: a retry of one test must not hide later
        # unrun workspace binaries/doctests. The process-wide mlock test runs last
        # in a fresh process, under its production PSI precondition.
        workspace_rc = self.run(workspace_name,
            command + ["--workspace", "--locked", "--no-fail-fast", "--", "--test-threads=1", "--skip", MLOCK_TEST],
            cwd=repo, timeout=7200)
        workspace_log = self.logs / f"{workspace_name}.log"
        workspace = parse_test_log(workspace_log.read_text(encoding="utf-8", errors="replace"))
        if workspace_rc != 0:
            self._write_cargo_test_failure_report(workspace_log)
            # Keep the historical bounded fuzz retry, now with no-fail-fast and
            # actual retry test-count validation. Other failures never recover.
            if root_serial:
                self._retry_known_fuzz_smoke_timing_failure(repo, test_target, prefix or [], workspace_rc)
        workspace_ok = workspace_rc == 0 and workspace["counts"]["passed"] > 0 and workspace["counts"]["failed"] == 0
        if not workspace_ok:
            workspace_ok = any(step["name"] == workspace_name and step["status"] == "recovered" for step in self.steps)
        if workspace_rc == 0 and not workspace_ok:
            self.validation_failure("workspace_test_coverage", "Cargo returned success without executed passing workspace tests")

        pressure = wait_for_calm_memory(getattr(self.args, "memory_calm_timeout", 180))
        write_text(self.reports / "test-memory-pressure.json", json.dumps(pressure, indent=2) + "\n")
        isolated_ok = False
        report.update({"workspace_log": str(workspace_log.relative_to(self.out)), "workspace": workspace,
                       "workspace_exit_code": workspace_rc, "workspace_complete": workspace_ok,
                       "memory_ready": pressure["ready"]})
        if pressure["ready"]:
            isolated_rc = self.run("cargo_test_mlock_isolated", command + ["--locked", "--package", "warden-sys", "--lib",
                MLOCK_TEST, "--", "--exact", "--nocapture", "--test-threads=1"], cwd=repo, timeout=300)
            isolated_log = self.logs / "cargo_test_mlock_isolated.log"
            isolated = parse_test_log(isolated_log.read_text(encoding="utf-8", errors="replace"))
            isolated_ok = (isolated_rc == 0 and isolated["counts"]["passed"] == 1 and isolated["counts"]["failed"] == 0
                           and not isolated["internal_skips"])
            report.update({"sensitive_log": str(isolated_log.relative_to(self.out)), "sensitive": isolated,
                           "sensitive_exit_code": isolated_rc, "pressure_after": inspect_memory_pressure()})
            if not isolated_ok:
                self._write_cargo_test_failure_report(isolated_log)
                if isolated_rc == 0:
                    self.validation_failure("mlock_test_coverage", "The exact test did not run once, or mlockall was internally skipped")
        else:
            self.validation_failure("mlock_test_precondition", "Memory PSI unavailable or not calm within timeout; see test-memory-pressure.json")
        report["coverage_complete"] = root_serial and workspace_ok and isolated_ok
        write_text(report_path, json.dumps(report, indent=2) + "\n")
        if prefix and test_target.exists():
            self.run("restore_test_target_ownership", prefix + ["chown", "-R", f"{os.getuid()}:{os.getgid()}", str(test_target)], timeout=600)

    def validation_failure(self, name: str, reason: str) -> None:
        path = self.reports / f"{name}.txt"
        write_text(path, reason + "\n")
        self.steps.append({"name": name, "status": "failed", "exit_code": None,
                           "reason": reason, "log": str(path.relative_to(self.out))})
        print(f"[FAILED] {name}: {reason}", flush=True)

    def root_prefix(self) -> list[str] | None:
        if os.geteuid() == 0:
            return []
        if self.command_exists("sudo"):
            return ["sudo"]
        return None

    @staticmethod
    def _perf_event_valid(report: str, event: str) -> bool:
        """Exit status is insufficient: perf can return 0 for unsupported PMU events.

        Accept only a numeric CSV counter for the exact requested event.
        Never treat '<not supported>', '<not counted>' or 0 elapsed time as evidence.
        """
        if re.search(r"(?i)<not\s+(?:supported|counted)>|permission denied|no permission|unknown event", report):
            return False
        for line in report.splitlines():
            fields = [field.strip() for field in line.split(",")]
            if len(fields) < 3 or fields[2] != event:
                continue
            value = fields[0].replace(" ", "").replace("\u00a0", "")
            if re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", value):
                return True
        return False

    def perf_preflight(self) -> bool:
        """Check each counter's *value*, independent from record availability.

        Running as a VM guest often yields rc=0 and '<not supported>'. Software
        task-clock sampling can still work with no hardware PMU at all.
        """
        self.perf_events_supported = []
        self.perf_stat_available = self.perf_hardware_available = False
        self.perf_record_available = self.perf_available = False
        if not self.command_exists("perf"):
            write_text(self.reports / "perf-preflight.txt", "SKIPPED: perf command unavailable\n")
            write_text(self.reports / "perf-events-supported.json", json.dumps({
                "stat_available": False, "hardware_available": False,
                "record_callgraph_available": False, "events": []}, indent=2) + "\n")
            return False
        prefix = self.root_prefix() or []
        # Use non-trivial CPU work so counters have a meaningful measurement interval.
        workload = [sys.executable, "-c", "import time; t=time.monotonic()+0.35; \nwhile time.monotonic()<t: sum(range(500))"]
        requested = ("cycles", "instructions", "branches", "branch-misses",
                     "cache-references", "cache-misses", "task-clock", "context-switches", "page-faults")
        probes = {}
        for event in requested:
            label = "perf_preflight_" + event.replace("-", "_")
            rc = self.run(label, prefix + ["perf", "stat", "-x,", "-e", event, "--"] + workload,
                          timeout=45, skip_on_failure=True)
            path = self.logs / (label + ".log")
            output = path.read_text(encoding="utf-8", errors="replace") if path.is_file() else ""
            passed = rc == 0 and self._perf_event_valid(output, event)
            probes[event] = {"return_code": rc, "numeric_counter": passed,
                             "log": str(path.relative_to(self.out))}
            if passed:
                self.perf_events_supported.append(event)
        hw = all(event in self.perf_events_supported for event in ("cycles", "instructions"))
        self.perf_hardware_available = hw
        self.perf_stat_available = bool(self.perf_events_supported)
        data = self.build / "perf-preflight.data"
        # Record uses a software event if the PMU is virtualized away.
        record_event = "cycles" if hw else "task-clock"
        record_rc = None
        if record_event in self.perf_events_supported:
            record_rc = self.run("perf_preflight_record_callgraph",
                                 prefix + ["perf", "record", "-e", record_event, "-F", "99", "-g",
                                           "--call-graph", "dwarf", "-o", str(data), "--"] + workload,
                                 timeout=90, skip_on_failure=True)
        script_rc = None
        if record_rc == 0 and data.is_file() and data.stat().st_size > 0:
            script_rc = self.run("perf_preflight_sample_validation",
                                 prefix + ["perf", "script", "-i", str(data)],
                                 timeout=45, skip_on_failure=True)
        script_log = self.logs / "perf_preflight_sample_validation.log"
        samples = (script_log.read_text(encoding="utf-8", errors="replace") if script_log.is_file() else "")
        self.perf_record_available = bool(script_rc == 0 and
                                          any(re.search(r"\b[0-9a-f]+\b", line) for line in samples.splitlines()[3:]))
        self.perf_available = self.perf_record_available or self.perf_stat_available
        note = ("Hardware PMU unavailable in this environment; software perf counters / sampling "
                "may still be usable. Do not derive IPC or branch miss ratio without numeric PMU counters."
                if not hw else "Hardware event cycles and instructions produced numeric values.")
        write_text(self.reports / "perf-preflight.txt",
                   f"stat_available={str(self.perf_stat_available).lower()}\n"
                   f"hardware_available={str(hw).lower()}\n"
                   f"record_callgraph_available={str(self.perf_record_available).lower()}\n"
                   f"record_event={record_event}\n"
                   f"supported_events={','.join(self.perf_events_supported)}\n" + note + "\n")
        write_text(self.reports / "perf-events-supported.json", json.dumps({
            "stat_available": self.perf_stat_available, "hardware_available": hw,
            "record_callgraph_available": self.perf_record_available, "record_event": record_event,
            "events": self.perf_events_supported, "event_probes": probes, "note": note
        }, indent=2) + "\n")
        return self.perf_available

    def metrics_port_free(self, port: int = 19184) -> bool:
        ss = shutil.which("ss", path=self.env.get("PATH"))
        if not ss:
            return True
        result = subprocess.run([ss, "-H", "-ltn"], stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, text=True, check=False)
        if result.returncode != 0:
            return True
        busy = any(re.search(rf":{port}\s*$", line.split()[3])
                   for line in result.stdout.splitlines() if len(line.split()) >= 4)
        if busy:
            write_text(self.reports / f"metrics-port-{port}-busy.txt",
                       f"Skipped benchmark: TCP port {port} is already listening. Stop the conflicting service or use another lab host.\n")
        return not busy

    def _snapshot_worklogs(self, short_dir: Path, dest: Path, prefix: list[str]) -> list[str]:
        """Retain config/daemon evidence without duplicating huge generated FIM sites.

        The benchmark's short working path is deleted after its logs are archived.
        """
        self._restore_output_ownership("restore_short_runtime_ownership", short_dir, prefix)
        preserved = []
        dest.mkdir(parents=True, exist_ok=True)
        for work in sorted(short_dir.glob("wprof-*")):
            target = dest / work.name
            target.mkdir(parents=True, exist_ok=True)
            for relative in ("warden.toml", "wardend.log", "conf.d/50-scenario.toml"):
                original = work / relative
                if original.is_file() and not original.is_symlink():
                    out = target / relative
                    out.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(original, out)
            preserved.append(str(target.relative_to(self.out)))
        return preserved

    @staticmethod
    def _check_control_socket_log(path: Path) -> str | None:
        if not path.is_file():
            return "daemon log missing (control socket startup cannot be verified)"
        content = path.read_text(encoding="utf-8", errors="replace")
        if "cannot create the control socket" in content or "path must be shorter than SUN_LEN" in content:
            return "control socket startup failed (inspect wardend.log)"
        return None

    def _instrument_profile_runner(self, repo: Path) -> Path | None:
        source = repo / "bench" / "profile.py"
        if not source.is_file():
            write_text(self.reports / "profile-runner-unavailable.txt",
                       "SKIPPED: upstream bench/profile.py is unavailable.\n")
            return None
        output = self.artifacts / "instrumented" / "bench-profile-audit.py"
        manifest = self.artifacts / "instrumented" / "bench-profile-audit.patch.json"
        rc = self.run("instrument_profile_runner",
                      [sys.executable, str(KIT / "instrument-bench.py"), "profile",
                       "--source", str(source), "--output", str(output), "--manifest", str(manifest)],
                      timeout=120)
        return output if rc == 0 and output.is_file() else None

    def _restore_output_ownership(self, name: str, path: Path, prefix: list[str]) -> None:
        """Return only dedicated root-written audit outputs to the invoking user."""
        if os.geteuid() == 0 or not path.exists():
            return
        owner = f"{os.getuid()}:{os.getgid()}"
        self.run(name, prefix + ["chown", "-R", owner, str(path)], timeout=900, skip_on_failure=True)

    def _run_strace_profile(self, repo: Path, wardend_binary: Path, prefix: list[str]) -> None:
        """Separate, explicitly perturbed syscall-distribution samples."""
        if not self.command_exists("strace"):
            write_text(self.reports / "strace-profile-note.txt",
                       "SKIPPED: strace is unavailable; baseline profile measurements do not require it.\n")
            return
        script = self._instrument_profile_runner(repo)
        if script is None:
            return
        outdir = self.out / "runtime-profile-syscalls"
        outdir.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="wa-") as short:
            workdir = Path(short)
            scenarios = ",".join(STRACE_SCENARIOS)
            cmd = prefix + ["env", f"WARDEN_AUDIT_STRACE_SCENARIOS={scenarios}",
                            f"WARDEN_AUDIT_STRACE_DIR={outdir}", sys.executable, str(script),
                            "--wardend", str(wardend_binary), "--only", scenarios,
                            "--duration", "40", "--warmup", "10", "--interval", "1",
                            "--out", str(outdir), "--workdir", str(workdir), "--no-drop-caches", "--keep", "--json"]
            rc = self.run("bench_profile_strace_syscall_distribution", cmd, cwd=repo, timeout=900,
                          stdout_path=self.logs / "bench-profile-strace-summary.json")
            self._snapshot_worklogs(workdir, self.out / "profile-syscall-work", prefix)
        inventory = {}
        for scenario in scenarios.split(","):
            summary = outdir / f"{scenario}.strace-summary.txt"
            attach = outdir / f"{scenario}.strace-summary.txt.attach.log"
            inventory[scenario] = {
                "summary_present": summary.is_file() and summary.stat().st_size > 0,
                "attach_log_present": attach.is_file(),
                "summary": str(summary.relative_to(self.out)) if summary.is_file() else None,
                "attach_log": str(attach.relative_to(self.out)) if attach.is_file() else None,
            }
        complete = all(v["summary_present"] for v in inventory.values())
        write_text(self.reports / "strace-profile-inventory.json",
                   json.dumps({"exit_code": rc, "complete": complete,
                               "missing_summaries": [k for k, v in inventory.items() if not v["summary_present"]],
                               "scenarios": inventory}, indent=2) + "\n")
        write_text(self.reports / "strace-profile-note.txt",
                   "Separate instrumented run of process, exec_storm, waf, auth. `strace -f -c` adds ptrace overhead; these syscall distributions are diagnostic and must not be compared as baseline CPU/RSS measurements. Missing summaries or attach errors are recorded in strace-profile-inventory.json and must not be mistaken for zero syscalls.\n")
        self._restore_output_ownership("restore_strace_output_ownership", outdir, prefix)

    @staticmethod
    def _validate_profile_json(path: Path) -> tuple[bool, dict[str, Any]]:
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return False, {"present": path.is_file(), "valid_json": False, "error": str(exc)}
        required = ("cpu_steady_pct", "rss_steady", "rss_peak", "syscalls_per_s", "per_thread")
        missing = [key for key in required if key not in item] if isinstance(item, dict) else list(required)
        error = item.get("error") if isinstance(item, dict) else "result is not a JSON object"
        early = item.get("exited_early") if isinstance(item, dict) else None
        ok = bool(isinstance(item, dict) and not error and early is False and not missing)
        return ok, {"present": True, "valid_json": isinstance(item, dict), "error": error,
                    "exited_early": early, "missing_metrics": missing,
                    "workdir": item.get("workdir") if isinstance(item, dict) else None}

    def _profile_smoke_preflight(self, repo: Path, wardend_binary: Path, prefix: list[str]) -> bool:
        """Run a short idle scenario first and retain its daemon log/config.

        Upstream profile.py deliberately returns zero for some per-scenario
        daemon failures; validate the emitted JSON rather than trusting rc alone.
        """
        outdir = self.out / "runtime-profile-preflight"
        outdir.mkdir(parents=True, exist_ok=True)
        profile_script = self._instrument_profile_runner(repo)
        if profile_script is None:
            report = {"exit_code": None, "ok": False, "scenario": "idle",
                      "result": {"error": "could not create the diagnostic profile runner copy"},
                      "log": "logs/bench-profile-preflight.json", "workdirs": []}
            write_text(self.reports / "profile-preflight.json", json.dumps(report, indent=2) + "\n")
            return False
        with tempfile.TemporaryDirectory(prefix="wa-") as short:
            workdir = Path(short)
            cmd = prefix + [sys.executable, str(profile_script),
                        "--wardend", str(wardend_binary), "--only", "idle",
                        "--duration", "20", "--warmup", "0", "--interval", "1",
                        "--out", str(outdir), "--workdir", str(workdir),
                        "--no-drop-caches", "--keep", "--json"]
            rc = self.run("bench_profile_smoke_preflight", cmd, cwd=repo, timeout=180,
                      stdout_path=self.logs / "bench-profile-preflight.json")
            self._restore_output_ownership("restore_profile_preflight_output_ownership", outdir, prefix)
            self._restore_output_ownership("restore_profile_preflight_workdir_ownership", workdir, prefix)
            workdirs = self._snapshot_worklogs(workdir, self.out / "profile-preflight-work", prefix)
        ok, details = self._validate_profile_json(outdir / "idle.json")
        control_error = next((self._check_control_socket_log(self.out / wd / "wardend.log")
                              for wd in workdirs if self._check_control_socket_log(self.out / wd / "wardend.log")), None)
        if control_error:
            details["control_socket_error"] = control_error
        report = {"exit_code": rc, "ok": bool(rc == 0 and ok and not control_error), "scenario": "idle",
                  "result": details, "log": "logs/bench-profile-preflight.json",
                  "workdirs": workdirs}
        write_text(self.reports / "profile-preflight.json", json.dumps(report, indent=2) + "\n")
        return bool(report["ok"])

    def _write_failed_profile_inventories(self, reason: str) -> None:
        profile_rows = {name: {"present": False, "valid_json": False, "error": reason,
                               "exited_early": None, "missing_metrics": [], "ok": False}
                        for name in PROFILE_ALL_SCENARIOS}
        write_text(self.reports / "profile-all-inventory.json", json.dumps({
            "complete": False, "expected": list(PROFILE_ALL_SCENARIOS),
            "missing_or_failed": list(PROFILE_ALL_SCENARIOS), "preflight_failed": True,
            "scenarios": profile_rows}, indent=2) + "\n")
        strace_rows = {name: {"summary_present": False, "attach_log_present": False,
                              "summary": None, "attach_log": None}
                       for name in STRACE_SCENARIOS}
        write_text(self.reports / "strace-profile-inventory.json", json.dumps({
            "exit_code": None, "complete": False, "preflight_failed": True,
            "reason": reason, "missing_summaries": list(STRACE_SCENARIOS),
            "scenarios": strace_rows}, indent=2) + "\n")
        write_text(self.reports / "strace-profile-note.txt",
                   "SKIPPED because the retained idle profile smoke preflight failed. "
                   "Inspect reports/profile-preflight.json and logs/bench-profile-preflight.json, "
                   "then profile-preflight-work/wprof-*/wardend.log and warden.toml.\n")

    def run_profile(self, repo: Path, wardend_binary: Path) -> None:
        if not self.metrics_port_free():
            self.validation_failure("profile_precondition", "Upstream benchmark metrics port is occupied")
            return
        prefix = self.root_prefix()
        if prefix is None:
            self.validation_failure("profile_precondition", "Needs root or sudo for proc/cgroup access")
            return
        if not self._profile_smoke_preflight(repo, wardend_binary, prefix):
            self.validation_failure("profile_preflight", "Idle profile smoke preflight failed; see retained diagnostic artifacts")
            self._write_failed_profile_inventories("idle profile smoke preflight failed; see retained diagnostic artifacts")
            return
        profile_script = self._instrument_profile_runner(repo)
        if profile_script is None:
            self.validation_failure("profile_runner", "Could not instrument upstream bench/profile.py; inspect instrumentation logs")
            return
        profile_out = self.out / "runtime-profile"
        profile_out.mkdir(exist_ok=True)
        duration = self.args.profile_duration
        warmup = min(self.args.profile_warmup, max(0, duration - 10))
        if getattr(self.args, "profile_scope", "standard") == "all":
            # Upstream profile.py overrides duration for integrity (200s), FIM/access-log
            # (240s) and all-modules (300s); the total timeout includes setup and 20k-file sites.
            scenarios = ",".join(PROFILE_ALL_SCENARIOS)
            step_name = "bench_profile_all_upstream_scenarios"
            timeout = max(5400, int(getattr(self.args, "profile_total_timeout", 5400)))
        else:
            scenarios = "idle,process,waf"
            step_name = "bench_profile_idle_process_waf"
            timeout = duration * 3 + 300
        with tempfile.TemporaryDirectory(prefix="wa-") as short:
            workdir = Path(short)
            cmd = prefix + [sys.executable, str(profile_script),
                            "--wardend", str(wardend_binary),
                            "--only", scenarios, "--duration", str(duration),
                            "--warmup", str(warmup), "--interval", "1",
                            "--out", str(profile_out), "--workdir", str(workdir),
                            "--no-drop-caches"]
            cmd.append("--keep")
            cmd.append("--json")
            profile_rc = self.run(step_name, cmd, cwd=repo, timeout=timeout,
                                  stdout_path=self.logs / "bench-profile-summary.json")
            self._restore_output_ownership("restore_profile_output_ownership", profile_out, prefix)
            self._restore_output_ownership("restore_profile_workdir_ownership", workdir, prefix)
            workdirs = self._snapshot_worklogs(workdir, self.out / "profile-work", prefix)
        summary = self.logs / "bench-profile-summary.json"
        if profile_rc == 0 and summary.exists():
            raw = summary.read_text(encoding="utf-8", errors="replace")
            start_json = raw.rfind("[\n")
            if start_json >= 0:
                try:
                    parsed = json.loads(raw[start_json:])
                    write_text(self.reports / "bench-profile-summary.json", json.dumps(parsed, indent=2) + "\n")
                except json.JSONDecodeError:
                    pass
        inventory = {}
        for scenario in scenarios.split(","):
            result_file = profile_out / f"{scenario}.json"
            record: dict[str, Any] = {"present": result_file.is_file(), "valid_json": False,
                                      "error": None, "exited_early": None}
            if result_file.is_file():
                try:
                    item = json.loads(result_file.read_text(encoding="utf-8"))
                    record["valid_json"] = isinstance(item, dict)
                    record["error"] = item.get("error") if isinstance(item, dict) else "result is not an object"
                    record["exited_early"] = item.get("exited_early") if isinstance(item, dict) else None
                    record["workdir"] = item.get("workdir") if isinstance(item, dict) else None
                    required_metrics = ("cpu_steady_pct", "rss_steady", "rss_peak", "syscalls_per_s", "per_thread")
                    record["missing_metrics"] = [k for k in required_metrics if k not in item] if isinstance(item, dict) else list(required_metrics)
                except (OSError, json.JSONDecodeError) as e:
                    record["error"] = f"invalid result JSON: {e}"
                    record["missing_metrics"] = []
            else:
                record["missing_metrics"] = []
            work_log = next((self.out / wd / "wardend.log" for wd in workdirs
                             if wd.startswith("profile-work/") and wd.split("/")[-1] in str(record.get("workdir", ""))), None)
            # Diagnose the copied run logs even after the short /tmp path has gone.
            if work_log is not None:
                record["control_socket_error"] = self._check_control_socket_log(work_log)
                if record["control_socket_error"]:
                    record["error"] = record["control_socket_error"]
            record["ok"] = bool(record["present"] and record["valid_json"]
                                and not record["error"] and record["exited_early"] is False
                                and not record["missing_metrics"])
            inventory[scenario] = record
        complete = all(item["ok"] for item in inventory.values())
        write_text(self.reports / "profile-all-inventory.json",
                   json.dumps({"complete": complete, "expected": scenarios.split(","),
                               "missing_or_failed": [k for k, v in inventory.items() if not v["ok"]],
                               "scenarios": inventory}, indent=2) + "\n")
        if not complete:
            self.validation_failure("profile_result_validation", "Selected profile JSON results are missing, failed or lack required metrics")
        if getattr(self.args, "full", False):
            # The upstream profile.py syscalls/s counter is based on /proc/<pid>/io
            # syscr+syscw (read/write syscall counts), not a complete syscall histogram.
            # Collect a separate strace -c view for the four hottest input paths.
            self._run_strace_profile(repo, wardend_binary, prefix)

    def _instrument_stress_for_perf(self, repo: Path) -> Path | None:
        source = repo / "bench" / "stress.py"
        if not source.is_file():
            return None
        output = self.artifacts / "instrumented" / "bench-stress-perf.py"
        manifest = self.artifacts / "instrumented" / "bench-stress-perf.patch.json"
        rc = self.run("instrument_stress_for_perf_stat",
                      [sys.executable, str(KIT / "instrument-bench.py"), "stress",
                       "--source", str(source), "--output", str(output), "--manifest", str(manifest)],
                      timeout=120)
        return output if rc == 0 and output.is_file() else None

    def run_stress(self, repo: Path, wardend_binary: Path, firewall: bool = False) -> None:
        if not self.metrics_port_free():
            self.validation_failure("stress_precondition", "Upstream benchmark metrics port is occupied")
            return
        prefix = self.root_prefix()
        if prefix is None:
            self.validation_failure("stress_precondition", "Stress requires root or sudo")
            return
        scenarios = ",".join(STRESS_SAFE_SCENARIOS)
        if firewall:
            # Destructive lab-only path; never selected by --full.
            nft = shutil.which("nft")
            if not nft:
                self.validation_failure("stress_firewall_precondition", "nft command is unavailable")
                return
            existing_cmd = prefix + [nft, "list", "table", "inet", "wbench"]
            existing = subprocess.run(existing_cmd, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL).returncode == 0
            victim = Path("/usr/local/bin/victimsleep")
            if existing or victim.exists():
                raise RuntimeError("refusing firewall stress: inet wbench already exists or /usr/local/bin/victimsleep exists")
            scenarios = "block_storm"
        stress_out = self.out / ("runtime-stress-firewall" if firewall else "runtime-stress")
        stress_out.mkdir(exist_ok=True)
        stress_script = repo / "bench" / "stress.py"
        if getattr(self.args, "full", False) and not firewall:
            instrumented = self._instrument_stress_for_perf(repo)
            if instrumented is not None:
                stress_script = instrumented
        events = ",".join(self.perf_events_supported) if self.perf_events_supported else "cycles,instructions"
        cmd = prefix + ["env", "TMPDIR=/tmp", f"WARDEN_AUDIT_PERF_EVENTS={events}",
                        f"WARDEN_AUDIT_PERF_STAT={'1' if self.perf_stat_available and not firewall else '0'}",
                        f"WARDEN_AUDIT_PERF_RECORD_EVENT={'cycles' if self.perf_hardware_available else 'task-clock'}",
                        sys.executable, str(stress_script), "--wardend", str(wardend_binary),
                        "--only", scenarios, "--duration", str(self.args.stress_duration), "--out", str(stress_out)]
        if self.perf_record_available and not firewall:
            cmd.append("--perf")
        if not self.perf_stat_available and not self.perf_record_available:
            write_text(self.reports / "perf-stress-note.txt",
                       "SKIPPED: perf stat and perf record unavailable; /proc CPU/RSS metrics remain collected.\n")
        elif not self.perf_record_available:
            write_text(self.reports / "perf-stress-note.txt",
                       "Numeric perf stat counters are available but callgraph recording is unavailable.\n")
        try:
            stress_rc = self.run("bench_stress_firewall" if firewall else "bench_stress_safe", cmd,
                                 cwd=repo, timeout=self.args.stress_duration * 4 + 600,
                                 stdout_path=self.logs / ("bench-stress-firewall.log" if firewall else "bench-stress.log"))
            if stress_rc == 0 and self.perf_record_available:
                perf_bin = shutil.which("perf", path=self.env.get("PATH"))
                if perf_bin:
                    perf_dir = self.reports / "perf"
                    perf_dir.mkdir(parents=True, exist_ok=True)
                    for data in sorted(stress_out.rglob("*.perf.data")):
                        stem = data.name.replace(".perf.data", "")
                        self.run(f"perf_report_{stem}", prefix + [perf_bin, "report", "--stdio", "-i", str(data),
                                                                    "--percent-limit", "0.5"],
                                 timeout=300, stdout_path=perf_dir / f"{stem}.report.txt")
                        self.run(f"perf_annotate_{stem}", prefix + [perf_bin, "annotate", "--stdio", "-i", str(data)],
                                 timeout=300, stdout_path=perf_dir / f"{stem}.annotate.txt")
            perf_inventory = {}
            for scenario in scenarios.split(","):
                record = stress_out / f"{scenario}.perf.data"
                stat = stress_out / f"{scenario}.perf-stat.csv"
                perf_inventory[scenario] = {
                    "record_present": record.is_file() and record.stat().st_size > 0,
                    "stat_present": stat.is_file() and stat.stat().st_size > 0,
                    "record_log_present": (stress_out / f"{scenario}.perf.data.log").is_file(),
                    "stat_log_present": (stress_out / f"{scenario}.perf-stat.csv.log").is_file(),
                }
            write_text(self.reports / "perf-stress-inventory.json",
                       json.dumps({"perf_stat_available": self.perf_stat_available,
                                   "perf_hardware_available": self.perf_hardware_available,
                                   "perf_record_available": self.perf_record_available,
                                   "events_requested": self.perf_events_supported,
                                   "scenarios": perf_inventory}, indent=2) + "\n")
            if not firewall:
                summaries = sorted(stress_out.glob("stress-*.json"), key=lambda p: p.stat().st_mtime_ns)
                source_summary = summaries[-1] if summaries else None
                try:
                    raw = json.loads(source_summary.read_text(encoding="utf-8")) if source_summary else {}
                except (OSError, json.JSONDecodeError):
                    raw = {}
                inventory = {}
                for scenario in STRESS_SAFE_SCENARIOS:
                    item = raw.get(scenario) if isinstance(raw, dict) else None
                    record = {"present": isinstance(item, dict),
                              "error": item.get("error") if isinstance(item, dict) else "scenario result missing",
                              "workdir": item.get("workdir") if isinstance(item, dict) else None}
                    required_metrics = ("cpu_load_seconds", "rss_peak_mib", "threads")
                    record["missing_metrics"] = [k for k in required_metrics if k not in item] if isinstance(item, dict) else list(required_metrics)
                    record["ok"] = record["present"] and not record["error"] and not record["missing_metrics"]
                    inventory[scenario] = record
                complete = bool(source_summary and all(item["ok"] for item in inventory.values()))
                write_text(self.reports / "safe-stress-inventory.json",
                           json.dumps({"complete": complete,
                                       "summary": str(source_summary.relative_to(self.out)) if source_summary else None,
                                       "expected": list(STRESS_SAFE_SCENARIOS),
                                       "missing_or_failed": [k for k, v in inventory.items() if not v["ok"]],
                                       "scenarios": inventory}, indent=2) + "\n")
                if not complete:
                    self.validation_failure("stress_result_validation", "Selected stress results are missing, failed or lack required metrics")
        finally:
            if firewall:
                self.run("cleanup_wbench_table", prefix + ["nft", "delete", "table", "inet", "wbench"], timeout=60)
                self.run("cleanup_victimsleep", prefix + ["rm", "-f", "/usr/local/bin/victimsleep"], timeout=60)
            self._restore_output_ownership("restore_stress_output_ownership", stress_out, prefix)

    def finalize(self) -> Path | None:
        self.log("Writing manifest, hashes and archive")

        def refresh_metadata(bundle_mode: str) -> None:
            write_text(self.reports / "steps.json", json.dumps(self.steps, indent=2) + "\n")
            summary = {
                "kit_version": VERSION,
                "started_utc": dt.datetime.fromtimestamp(self.started, dt.timezone.utc).isoformat(),
                "finished_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
                "elapsed_s": round(time.time() - self.started, 2),
                "source": str(getattr(self, "repo", "unknown")),
                "steps_total": len(self.steps),
                "steps_failed": sum(1 for step in self.steps if step.get("status") == "failed"),
                "steps_recovered": sum(1 for step in self.steps if step.get("status") == "recovered"),
                "steps_skipped": sum(1 for step in self.steps if step.get("status") == "skipped"),
                "full_pass_complete": self.full_pass_complete,
                "bundle_mode": bundle_mode,
                "perf_stat_available": self.perf_stat_available,
                "perf_hardware_available": self.perf_hardware_available,
                "perf_record_callgraph_available": self.perf_record_available,
                "options": vars(self.args),
                "machine": platform.machine(),
                "warning": "This is a collection bundle, not an automatic pass/fail security certification."
            }
            write_text(self.reports / "audit-summary.json", json.dumps(summary, indent=2, default=str) + "\n")
            provenance = {"kit_version": VERSION,
                          "source_commit": (self.reports / "source-identity.txt").read_text(encoding="utf-8", errors="replace")
                          if (self.reports / "source-identity.txt").is_file() else None,
                          "rust_toolchain": self.env.get("RUSTUP_TOOLCHAIN"),
                          "rustflags": self.env.get("RUSTFLAGS"),
                          "cargo_lock_sha256": sha256(self.repo / "Cargo.lock")
                          if getattr(self, "repo", None) and (self.repo / "Cargo.lock").is_file() else None,
                          "binaries": {q.name: {"sha256": sha256(q), "bytes": q.stat().st_size}
                                       for q in sorted(self.artifacts.glob("wardend.*")) if q.is_file()},
                          "host": {"kernel": platform.release(), "machine": platform.machine()},
                          "perf": {"hardware_available": self.perf_hardware_available,
                                   "stat_events": self.perf_events_supported,
                                   "sample_record_available": self.perf_record_available}}
            write_text(self.reports / "run-provenance.json", json.dumps(provenance, indent=2) + "\n")
            rows = []
            for path in sorted(self.out.rglob("*")):
                if path.is_file() and path.name != "SHA256SUMS":
                    try:
                        rows.append(f"{sha256(path)}  {path.relative_to(self.out)}")
                    except OSError:
                        pass
            write_text(self.out / "SHA256SUMS", "\n".join(rows) + "\n")

        if getattr(self.args, "full", False):
            archive = self.out.parent / f"{self.out.name}.full-analysis.tar.gz"
            packer = KIT / "pack-results.sh"
            bundle_log = self.out.parent / f"{self.out.name}.bundle.log"
            attempts: list[str] = []

            def pack(command: list[str], label: str) -> tuple[bool, str]:
                try:
                    cp = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                        text=True, check=False)
                    output = cp.stdout or ""
                    attempts.append(f"===== {label}: rc={cp.returncode} =====\n{output}")
                    return cp.returncode == 0 and archive.is_file() and archive.stat().st_size > 0, output
                except Exception as exc:
                    output = f"{type(exc).__name__}: {exc}\n"
                    attempts.append(f"===== {label}: exception =====\n{output}")
                    return False, output

            if not packer.is_file():
                full_ok, full_output = False, "pack-results.sh is missing\n"
                attempts.append("===== full bundle: missing packer =====\n" + full_output)
            else:
                refresh_metadata("full_raw")
                full_cmd = [sys.executable, str(packer), str(self.out),
                            "--include-perf-data", "--include-llvm-raw", "--output", str(archive)]
                full_ok, full_output = pack(full_cmd, "full raw bundle")

            if full_ok:
                archive_hash = sha256(archive)
                write_text(archive.with_suffix(archive.suffix + ".sha256"),
                           f"{archive_hash}  {archive.name}\n")
                write_text(bundle_log, "\n".join(attempts))
                print(f"\nAudit directory: {self.out}")
                print(f"Audit archive:   {archive}")
                print(f"Archive SHA256:  {archive_hash}")
                return archive

            # Preserve a clear record of why the raw bundle failed. The fallback
            # keeps source, ELFs, reports, logs, MIR and runtime metrics, but omits
            # raw LLVM/ASM and raw perf.data; those remain in AUDIT_DIR.
            full_error = "\n".join(attempts) or full_output
            write_text(self.reports / "bundle-full-attempt-failed.txt", full_error + "\n")
            self.full_pass_complete = False
            refresh_metadata("compact_fallback")
            if packer.is_file():
                compact_cmd = [sys.executable, str(packer), str(self.out), "--output", str(archive)]
                compact_ok, compact_output = pack(compact_cmd, "compact fallback bundle")
            else:
                compact_ok, compact_output = False, "pack-results.sh is missing\n"
            write_text(bundle_log, "\n".join(attempts))
            if compact_ok:
                archive_hash = sha256(archive)
                write_text(archive.with_suffix(archive.suffix + ".sha256"),
                           f"{archive_hash}  {archive.name}\n")
                print("WARNING: raw bundle failed; compact fallback archive was created. "
                      "Raw LLVM/ASM and perf.data remain in the audit directory.", file=sys.stderr)
                print(f"\nAudit directory: {self.out}")
                print(f"Audit archive:   {archive}")
                print(f"Archive SHA256:  {archive_hash}")
                return archive

            write_text(self.reports / "bundle-creation-failed.txt",
                       "Both full and compact bundle creation failed. The audit directory is preserved.\n\n"
                       + compact_output + "\n")
            self.full_pass_complete = False
            refresh_metadata("not_created")
            write_text(bundle_log, "\n".join(attempts))
            print(f"WARNING: no archive could be created; audit directory preserved at {self.out}. "
                  f"See {bundle_log} and reports/bundle-creation-failed.txt.", file=sys.stderr)
            return None

        archive = self.out.with_suffix(".tar.gz")
        refresh_metadata("standard")
        try:
            with tarfile.open(archive, "w:gz", compresslevel=6) as tf:
                tf.add(self.out, arcname=self.out.name)
            archive_hash = sha256(archive)
            write_text(archive.with_suffix(archive.suffix + ".sha256"), f"{archive_hash}  {archive.name}\n")
            print(f"\nAudit directory: {self.out}")
            print(f"Audit archive:   {archive}")
            print(f"Archive SHA256:  {archive_hash}")
            return archive
        except Exception as exc:
            write_text(self.reports / "archive-creation-failed.txt", f"{type(exc).__name__}: {exc}\n")
            print(f"WARNING: could not create standard archive; audit directory preserved at {self.out}: {exc}",
                  file=sys.stderr)
            return None


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Collect Rust/LLVM/ELF and optional runtime evidence for Warden")
    p.add_argument("--repo", help="existing Warden source checkout; default clones commeta/warden")
    p.add_argument("--ref", default="main", help="Git ref to fetch when --repo is omitted (default: main)")
    p.add_argument("--output", help="result directory; default ./results/warden-code-audit-<UTC timestamp>")
    p.add_argument("--toolchain", default=os.environ.get("WARDEN_RUST_TOOLCHAIN", "1.99.1"), help="Rust toolchain to use (default: 1.99.1, matching upstream CI)")
    p.add_argument("--full", action="store_true", help="one-shot full source-to-machine-code, MIR/LLVM, all 21 upstream profiles, strace syscall summaries, safe stress/perf; excludes firewall enforcement")
    p.add_argument("--tests-only", action="store_true", help="run validation only, using --repo; no release/codegen rebuilds")
    p.add_argument("--memory-calm-timeout", type=int, default=180, help="maximum wait for the mlock test PSI precondition (default 180 seconds)")
    p.add_argument("--skip-tests", action="store_true", help="skip fmt, clippy and tests; incomplete collection")
    p.add_argument("--profile", action="store_true", help="run upstream bench/profile.py (dry-run workloads; root required)")
    p.add_argument("--profile-scope", choices=("standard", "all"), default="standard", help="standard: idle/process/waf; all: every upstream profile scenario (21 scenarios)")
    p.add_argument("--profile-duration", type=int, default=60, help="seconds per profile scenario unless upstream defines a longer fixed duration (default 60)")
    p.add_argument("--profile-warmup", type=int, default=15, help="seconds ignored for steady-state rates (default 15)")
    p.add_argument("--profile-total-timeout", type=int, default=5400, help="maximum seconds for the all-scenarios profile stage (default 5400)")
    p.add_argument("--mca-cpu", default=os.environ.get("WARDEN_MCA_CPU", "auto"), help="LLVM-MCA CPU model (auto detects AMD family 23 as znver1; otherwise uses generic; explicit model overrides)")
    p.add_argument("--stress", action="store_true", help="run non-firewall upstream stress scenarios; perf recording is enabled only if the hardware-counter preflight succeeds")
    p.add_argument("--stress-firewall", action="store_true", help="run block_storm (real nftables table inet wbench + temporary victim executable)")
    p.add_argument("--ack-lab-impact", action="store_true", help="required acknowledgement for --stress-firewall")
    p.add_argument("--stress-duration", type=int, default=30, help="seconds per stress scenario (default 30)")
    p.add_argument("--keep-build", action="store_true", help="keep Cargo target trees (can add several GB to the bundle)")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    if args.memory_calm_timeout < 0:
        print("ERROR: --memory-calm-timeout must be >=0", file=sys.stderr)
        return 2
    if args.tests_only and (args.full or args.skip_tests or args.profile or args.profile_scope != "standard" or args.stress or args.stress_firewall):
        print("ERROR: --tests-only cannot combine with --full, --skip-tests or runtime stages", file=sys.stderr)
        return 2
    if args.full and args.skip_tests:
        print("ERROR: --full requires tests", file=sys.stderr)
        return 2
    if args.full:
        args.profile = True
        args.stress = True
        args.profile_scope = "all"
    elif args.profile_scope == "all":
        args.profile = True
    if args.profile_total_timeout < 600:
        print("ERROR: --profile-total-timeout must be >=600 seconds", file=sys.stderr)
        return 2
    if args.profile_duration < 20 or args.profile_warmup < 0:
        print("ERROR: profile duration must be >=20 and warmup must be >=0", file=sys.stderr)
        return 2
    if args.stress_duration < 10:
        print("ERROR: stress duration must be >=10 seconds", file=sys.stderr)
        return 2
    if args.stress_firewall and not args.ack_lab_impact:
        print("ERROR: --stress-firewall requires --ack-lab-impact and a disposable VM", file=sys.stderr)
        return 2
    out = Path(args.output).expanduser() if args.output else KIT / "results" / f"warden-code-audit-{utc_stamp()}"
    if out.exists() and any(out.iterdir()):
        print(f"ERROR: output directory is not empty: {out}", file=sys.stderr)
        return 2
    audit = Audit(out, args)
    rc = 0
    try:
        repo = audit.prepare_repo()
        audit.collect_host(repo)
        audit.collect_source_metadata(repo)
        if args.tests_only:
            audit.run_tests(repo)
        else:
            prod, sym = audit.build_binaries(repo)
            if prod:
                audit.analyze_elf(prod, "production-stripped")
            unstripped = getattr(audit, "unstripped_binary", None)
            if unstripped and unstripped.is_file():
                audit.analyze_elf(unstripped, "release-unstripped", full_disassembly=False)
            if sym:
                audit.analyze_elf(sym, "release-symbolized")
                audit.collect_codegen(repo, audit.symbol_target)
                audit.run_codegen_metrics()
            audit.run_tests(repo)
            if args.stress:
                audit.perf_preflight()
            if args.profile and prod:
                audit.run_profile(repo, prod)
            if args.stress and audit.unstripped_binary:
                audit.run_stress(repo, audit.unstripped_binary, firewall=False)
            if args.stress_firewall and prod:
                audit.run_stress(repo, prod, firewall=True)
        if any(step.get("status") == "failed" for step in audit.steps):
            rc = 1
        if args.full:
            full_required_steps = (
                "build_production_release", "build_release_unstripped", "build_release_symbolized",
                "rustc_emit_llvm_ir_asm", "rustc_emit_llvm_warden_core", "rustc_emit_llvm_warden_sys",
                "rustc_emit_llvm_warden_detect", "rustc_emit_llvm_warden_respond",
                "cargo_bloat_crates", "cargo_bloat_top200",
                "cargo_llvm_lines", "wardend_final_elf_nm", "static_machine_code_analysis",
                "rustc_emit_mir_warden_core", "rustc_emit_mir_warden_sys",
                "rustc_emit_mir_warden_detect", "rustc_emit_mir_warden_respond",
                "rustc_emit_mir_wardend",
                "cargo_fmt_check", "cargo_clippy_ci_strict", "cargo_test_compile", "cargo_test_ci_root_serial", "cargo_test_mlock_isolated",
                "bench_profile_smoke_preflight", "bench_profile_all_upstream_scenarios",
                "bench_profile_strace_syscall_distribution",
                "bench_stress_safe",
            )
            for required_name in full_required_steps:
                if not any(step.get("name") == required_name and step.get("status") in ("ok", "recovered")
                           for step in audit.steps):
                    write_text(audit.reports / f"full-required-{required_name}.txt",
                               f"REQUIRED FULL-PASS STAGE DID NOT COMPLETE: {required_name}\n")
                    rc = 1
            try:
                if not json.loads((audit.reports / "test-validation.json").read_text())["coverage_complete"]:
                    rc = 1
            except (OSError, ValueError, KeyError):
                rc = 1
            strace_inventory = audit.reports / "strace-profile-inventory.json"
            try:
                if not json.loads(strace_inventory.read_text(encoding="utf-8")).get("complete", False):
                    write_text(audit.reports / "full-required-strace.txt",
                               "REQUIRED FULL-PASS STAGE INCOMPLETE: one or more strace summaries are missing.\n")
                    rc = 1
            except (OSError, json.JSONDecodeError):
                write_text(audit.reports / "full-required-strace.txt",
                           "REQUIRED FULL-PASS STAGE INCOMPLETE: strace inventory is missing or unreadable.\n")
                rc = 1
            llvm_inventory = audit.reports / "codegen" / "llvm-emit-inventory.json"
            try:
                if not json.loads(llvm_inventory.read_text(encoding="utf-8")).get("complete", False):
                    write_text(audit.reports / "full-required-llvm-emit.txt",
                               "REQUIRED FULL-PASS STAGE INCOMPLETE: fresh LLVM IR and assembly missing for one or more selected crates.\n")
                    rc = 1
            except (OSError, json.JSONDecodeError):
                write_text(audit.reports / "full-required-llvm-emit.txt",
                           "REQUIRED FULL-PASS STAGE INCOMPLETE: LLVM emit inventory is missing or unreadable.\n")
                rc = 1
            mca_dir = audit.reports / "codegen" / "llvm-mca"
            try:
                mca_rows = json.loads((mca_dir / "status.json").read_text(encoding="utf-8"))
                mca_ok = isinstance(mca_rows, list) and any(row.get("status") == "ok" for row in mca_rows)
            except (OSError, json.JSONDecodeError):
                mca_ok = False
            if not mca_ok:
                write_text(audit.reports / "full-required-llvm-mca.txt",
                           "REQUIRED FULL-PASS STAGE INCOMPLETE: llvm-mca did not produce at least one successful hot-function model. Inspect reports/codegen/llvm-mca/.\n")
                rc = 1
            preflight_path = audit.reports / "profile-preflight.json"
            try:
                preflight_ok = json.loads(preflight_path.read_text(encoding="utf-8")).get("ok", False)
            except (OSError, json.JSONDecodeError):
                preflight_ok = False
            if not preflight_ok:
                write_text(audit.reports / "full-required-profile-preflight.txt",
                           "REQUIRED FULL-PASS STAGE INCOMPLETE: production ELF idle profile smoke preflight failed. "
                           "Inspect reports/profile-preflight.json and the retained profile-preflight-work/ directory.\n")
                rc = 1
            for inventory_name, label in (("profile-all-inventory.json", "all 21 profile scenarios"),
                                          ("safe-stress-inventory.json", "all 4 safe stress scenarios")):
                inventory_path = audit.reports / inventory_name
                try:
                    complete = json.loads(inventory_path.read_text(encoding="utf-8")).get("complete", False)
                except (OSError, json.JSONDecodeError):
                    complete = False
                if not complete:
                    write_text(audit.reports / f"full-required-{inventory_name}.txt",
                               f"REQUIRED FULL-PASS STAGE INCOMPLETE: {label}; inspect {inventory_name}.\n")
                    rc = 1
            for package in MIR_PACKAGES:
                status_file = audit.artifacts / "mir" / f"{package}.status.txt"
                try:
                    status = status_file.read_text(encoding="utf-8")
                    copied_match = re.search(r"mir_files_copied=(\d+)", status)
                    copied = int(copied_match.group(1)) if copied_match else 0
                except OSError:
                    copied = 0
                if copied < 1:
                    write_text(audit.reports / f"full-required-mir-{package}.txt",
                               f"REQUIRED FULL-PASS STAGE INCOMPLETE: fresh MIR artifact missing for {package}.\n")
                    rc = 1
    except KeyboardInterrupt:
        rc = 130
        write_text(audit.reports / "interrupted.txt", "Audit interrupted by user (Ctrl-C).\n")
        print("\nAudit interrupted; finalizing collected evidence and cleaning temporary build trees.", file=sys.stderr)
    except Exception as e:
        rc = 1
        write_text(audit.reports / "fatal-error.txt", f"{type(e).__name__}: {e}\n")
        print(f"FATAL: {e}", file=sys.stderr)
    finally:
        if args.full:
            audit.full_pass_complete = (rc == 0)
        if not args.keep_build:
            shutil.rmtree(audit.build, ignore_errors=True)
        try:
            archive = audit.finalize()
            if archive is None or (args.full and not audit.full_pass_complete):
                rc = 1
        except Exception as e:
            rc = 1
            print(f"FINALIZE ERROR: {type(e).__name__}: {e}; audit directory was left in place at {audit.out}",
                  file=sys.stderr)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
