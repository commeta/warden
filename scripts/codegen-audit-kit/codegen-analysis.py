#!/usr/bin/env python3
"""Static machine-code inventory and controlled .text comparison for Warden.

This is a disassembly heuristic. Multiset overlap does not establish instruction
sequence equivalence, control-flow equivalence, or semantic equivalence.
"""
from __future__ import annotations
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys

MCA_SELECTORS = ("ExecPipeline>::on_exec", "ProcessScanner::tick", "DiskDetector::tick",
                 "Responder::run_one", "Engine::process")
MCA_LIMITATIONS = (
    "Exploratory static, *unverified-as-hot* single straight-line basic-block model; "
    "llvm-mca is not a profiler, ignores branch predictor, OS, input data and cache misses. "
    "The selected longest eligible straight-line block does not represent the full function, "
    "its runtime throughput, or latency. Selection is independent of perf hot blocks; do not "
    "interpret the estimate as an end-to-end improvement. Only clean diagnostic output and "
    "exact accounted-for instruction counts are accepted."
)

HEADER = re.compile(r"^\s*([0-9a-fA-F]+)\s+<(.+)>:$")
INSN = re.compile(r"^\s*([0-9a-fA-F]+):\s*([a-zA-Z][a-zA-Z0-9_.]*)\s*(.*?)\s*$")
DIRECT = {"call", "callq", "jmp", "jmpq", "xbegin"}


def normalize(mnemonic: str, operands: str, *, relax_movabs: bool = False) -> str:
    op = operands.split("#", 1)[0].strip().lower()
    op = re.sub(r"\s*<[^>]*>", "", op)
    op = re.sub(r"\brip\s*[+-]\s*(?:0x)?[0-9a-f]+", "rip+REL", op)
    if mnemonic in DIRECT or mnemonic.startswith("j") or mnemonic.startswith("loop"):
        first, sep, rest = op.partition(",")
        if re.fullmatch(r"\s*(?:0x)?[0-9a-f]+\s*", first):
            first = "<TARGET>"
            op = first + (sep + rest if sep else "")
    if relax_movabs and mnemonic == "movabs":
        op = re.sub(r"(,\s*)(?:0x)?[0-9a-f]+$", r"\1<IMM64>", op)
    op = re.sub(r"\s+", " ", op).strip()
    return mnemonic + (" " + op if op else "")


def require_x86_64_elf(binary: Path) -> None:
    """The Intel parser and scheduling model support little-endian x86-64 ELF only."""
    with binary.open("rb") as stream:
        header = stream.read(20)
    if len(header) < 20 or header[:4] != b"\x7fELF":
        raise RuntimeError(f"not an ELF binary: {binary}")
    if header[4] != 2 or header[5] != 1 or int.from_bytes(header[18:20], "little") != 62:
        raise RuntimeError(f"unsupported ELF architecture for Intel disassembly: {binary}; "
                           "this analyzer requires little-endian ELF64 x86-64 (EM_X86_64)")


def analyze(binary: Path):
    require_x86_64_elf(binary)
    cmd = ["objdump", "-d", "-C", "-Mintel", "--no-show-raw-insn", str(binary)]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
    assert proc.stdout is not None
    mnemonics, signatures, relaxed = Counter(), Counter(), Counter()
    by_function = defaultdict(Counter)
    current = "<outside-symbol>"
    last_header = None
    symbol_spans = {}
    instructions = 0
    for line in proc.stdout:
        h = HEADER.match(line.rstrip())
        if h:
            addr, name = int(h.group(1), 16), h.group(2)
            if last_header:
                prev_addr, prev_name = last_header
                if addr >= prev_addr:
                    symbol_spans[prev_name] = addr - prev_addr
            last_header = (addr, name)
            current = name
            continue
        m = INSN.match(line)
        if not m:
            continue
        mnemonic, operands = m.group(2).lower(), m.group(3).split("#", 1)[0].strip()
        sig = normalize(mnemonic, operands)
        relax_sig = normalize(mnemonic, operands, relax_movabs=True)
        instructions += 1
        mnemonics[mnemonic] += 1
        signatures[sig] += 1
        relaxed[relax_sig] += 1
        c = by_function[current]
        c["instructions"] += 1
        c["calls"] += int(mnemonic in ("call", "callq"))
        c["returns"] += int(mnemonic.startswith("ret"))
        c["conditional_branches"] += int((mnemonic.startswith("j") and mnemonic not in ("jmp", "jmpq")) or mnemonic.startswith("loop"))
        c["unconditional_jumps"] += int(mnemonic in ("jmp", "jmpq"))
        c["lock_or_atomic"] += int(mnemonic == "lock" or "lock " in operands.lower() or mnemonic.startswith(("cmpxchg", "xadd")))
        c["memory_operands"] += int("[" in operands)
        c["stack_memory_operands"] += int("[" in operands and bool(re.search(r"\b(rsp|rbp|esp|ebp)\b", operands)))
        c["simd_vector_heuristic"] += int(mnemonic.startswith("v") or bool(re.search(r"\b(xmm|ymm|zmm|mm[0-7])\d*\b", operands)) or mnemonic.startswith(("padd", "psub", "pmul", "pand", "por", "pxor", "punpck", "movdqa", "movdqu", "movaps", "movups", "addps", "subps", "mulps", "divps")))
    proc.stdout.close()
    err = proc.stderr.read() if proc.stderr else ""
    if proc.stderr:
        proc.stderr.close()
    rc = proc.wait()
    if rc:
        raise RuntimeError(f"objdump rc={rc} for {binary}: {err}")
    if not instructions:
        raise RuntimeError(f"objdump produced no decoded instructions for {binary}")
    funcs=[]
    for name,c in by_function.items():
        row={"symbol":name, **{k:int(v) for k,v in c.items()}}
        if name in symbol_spans: row["span_to_next_symbol_bytes"] = symbol_spans[name]
        funcs.append(row)
    funcs.sort(key=lambda x:x["instructions"], reverse=True)
    return {
        "binary":str(binary), "instructions":instructions,
        "distinct_mnemonics":len(mnemonics), "mnemonic_counts":dict(mnemonics.most_common()),
        "totals":{k:sum(c[k] for c in by_function.values()) for k in (
            "calls","returns","conditional_branches","unconditional_jumps","lock_or_atomic",
            "memory_operands","stack_memory_operands","simd_vector_heuristic")},
        "function_count_with_instructions":len(by_function),
        "top_functions_by_instruction_count":funcs[:100],
        "_signatures":signatures, "_relaxed":relaxed,
    }


def overlap(left: Counter, right: Counter):
    common=sum((left & right).values())
    a,b=sum(left.values()),sum(right.values())
    return {"common_occurrences":common,"left_only":sum((left-right).values()),
            "right_only":sum((right-left).values()),"left_total":a,"right_total":b,
            "multiset_overlap_percent_of_larger":round(100*common/max(a,b,1),6)}


def symbol_matches(symbol: str, selector: str) -> bool:
    """Recognize inherent and trait-impl Rust names without matching closures."""
    if selector in symbol:
        return True
    owner, sep, method = selector.rpartition("::")
    if not sep or not method:
        return False
    owner = owner.removesuffix(">")
    pattern = r"(?:<|::)" + re.escape(owner) + r"(?: as [^>]+)?>::" + re.escape(method) + r"(?:$|<)"
    return re.search(pattern, symbol) is not None


def mca_report_valid(report: str, count: int, iterations: int = 20) -> tuple[bool, str]:
    if re.search(r"(?im)(?:^|:)\s*(?:error|warning):|unknown token|invalid operand|unsupported instruction", report):
        return False, "assembler/llvm-mca diagnostic (error or warning)"
    match_instructions = re.search(r"(?m)^\s*Instructions:\s*(\d+)\s*$", report)
    match_iterations = re.search(r"(?m)^\s*Iterations:\s*(\d+)\s*$", report)
    if not match_instructions or not match_iterations or "Total Cycles:" not in report:
        return False, "missing validated instruction/iteration/cycle statistics"
    if int(match_iterations.group(1)) != iterations:
        return False, "unexpected iteration count"
    if int(match_instructions.group(1)) != count * iterations:
        return False, "modeled instruction count does not match submitted input"
    return True, "clean model with fully accounted-for instructions"


def run_mca(symbolized: Path, output: Path, cpu: str) -> bool:
    require_x86_64_elf(symbolized)
    tool = shutil.which("llvm-mca")
    dest = output / "llvm-mca"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / "README.txt").write_text(MCA_LIMITATIONS + "\n", encoding="utf-8")
    if not tool:
        (dest / "status.txt").write_text("SKIPPED: llvm-mca not installed\n", encoding="utf-8")
        (dest / "status.json").write_text(json.dumps([
            {"status": "skipped", "reason": "llvm-mca not installed"}
        ], indent=2) + "\n", encoding="utf-8")
        return True

    # Obtain the *real* disassembly. Never feed objdump's demangled Rust
    # comment/symbol tails to the assembler (previously emitted e.g. 'call 8bfcc1::foo>').
    proc = subprocess.Popen(["objdump", "-d", "-C", "-Mintel", "--no-show-raw-insn", str(symbolized)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, errors="replace")
    assert proc.stdout is not None
    captured = []
    current = None
    decoded = 0
    def flush():
        if current is not None and current["partial"]:
            current["blocks"].append(current["partial"])
            current["partial"] = []
    for line in proc.stdout:
        header = HEADER.match(line.rstrip())
        if header:
            flush()
            address, symbol = header.groups()
            selectors = [sel for sel in MCA_SELECTORS if symbol_matches(symbol, sel)]
            current = ({"symbol": symbol, "address": f"0x{int(address, 16):x}",
                        "selectors": selectors, "partial": [], "blocks": []} if selectors else None)
            if current is not None:
                captured.append(current)
            continue
        instruction = INSN.match(line)
        if not instruction:
            continue
        decoded += 1
        if current is None:
            continue
        mnemonic = instruction.group(2).lower()
        operands = instruction.group(3).split("#", 1)[0].strip()
        # Basic blocks end at branches, call, return, traps and transaction boundaries.
        if (mnemonic in DIRECT or mnemonic.startswith(("j", "loop", "ret", "syscall", "sysenter", "int", "ud2", "xbegin"))):
            flush()
            continue
        # Malformed demangling must not accidentally turn into a valid mnemonic.
        if "<" in operands or ">" in operands:
            flush()
            continue
        current["partial"].append(mnemonic + (" " + operands if operands else ""))
    flush()
    proc.stdout.close()
    error = proc.stderr.read() if proc.stderr else ""
    if proc.stderr:
        proc.stderr.close()
    rc = proc.wait()
    if rc or not decoded:
        reason = f"objdump rc={rc}: {error}" if rc else "objdump produced no decoded instructions"
        (dest / "status.txt").write_text("FAILED: " + reason + "\n", encoding="utf-8")
        (dest / "status.json").write_text(json.dumps([{"status": "failed", "reason": reason}], indent=2) + "\n", encoding="utf-8")
        return False
    rows = []
    for index, item in enumerate(captured, 1):
        blocks = item.pop("blocks")
        item.pop("partial")
        # Pick one compact candidate per independent Rust symbol. Do not claim
        # perf-confirmed hotness; cap size so modeled input isn't a whole CFG.
        blocks = [block[:80] for block in blocks if len(block) >= 1]
        identity = {"function": item["symbol"], **item}
        if not blocks:
            rows.append({**identity, "status": "skipped", "reason": "no usable straight-line instructions"})
            continue
        body = max(blocks, key=len)
        assembly = dest / f"function-{index}.s"
        assembly.write_text("# " + MCA_LIMITATIONS + "\n"
                            + "# Symbol: " + item["symbol"] + " at " + item["address"] + "\n"
                            + ".text\n.intel_syntax noprefix\n" + "\n".join(body) + "\n", encoding="utf-8")
        report = dest / f"function-{index}.txt"
        command = [tool, "-mtriple=x86_64-unknown-linux-gnu", f"-mcpu={cpu}",
                   "-iterations=20", str(assembly)]
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, errors="replace", timeout=300)
            return_code, report_text = result.returncode, result.stdout
        except subprocess.TimeoutExpired as exc:
            return_code = 124
            captured_output = exc.stdout or ""
            if isinstance(captured_output, bytes):
                captured_output = captured_output.decode("utf-8", errors="replace")
            report_text = captured_output + "\nERROR: llvm-mca timed out after 300 seconds\n"
        except OSError as exc:
            return_code, report_text = 127, f"ERROR: {exc}\n"
        report.write_text(report_text, encoding="utf-8")
        valid, reason = mca_report_valid(report_text, len(body))
        rows.append({**identity, "status": "ok" if return_code == 0 and valid else "failed",
                     "reason": reason if return_code == 0 else f"exit code {return_code}: {reason}",
                     "instruction_lines": len(body), "cpu_model": cpu, "assembly": assembly.name,
                     "report": report.name, "exit_code": return_code, "argv": command,
                     "model": "exploratory_straight_line_basic_block_not_perf_verified",
                     "limitations": MCA_LIMITATIONS})
    for selector in MCA_SELECTORS:
        if not any(selector in row["selectors"] for row in rows if "selectors" in row):
            rows.append({"function": selector, "status": "NOT_FOUND_AS_INDEPENDENT_SYMBOL"})
    (dest / "status.json").write_text(json.dumps(rows, indent=2) + "\n", encoding="utf-8")
    return all(row.get("status") != "failed" for row in rows)


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--production",type=Path,required=True); ap.add_argument("--unstripped",type=Path,required=True)
    ap.add_argument("--symbolized",type=Path,required=True); ap.add_argument("--out",type=Path,required=True)
    ap.add_argument("--mca-cpu",default="znver1")
    a=ap.parse_args(); a.out.mkdir(parents=True,exist_ok=True)
    rows=[]
    for name,path in (("production",a.production),("release-unstripped",a.unstripped),("symbolized",a.symbolized)):
        print(f"Analyzing {name}: {path}",file=sys.stderr); rows.append(analyze(path))
    prod,unstrip,sym=rows
    result={"note":"Heuristic disassembly metrics. Multiset overlap ignores instruction order and does not prove semantic equivalence; SIMD/memory categories are heuristics.",
            "production":{k:v for k,v in prod.items() if not k.startswith("_")},
            "release_unstripped":{k:v for k,v in unstrip.items() if not k.startswith("_")},
            "symbolized":{k:v for k,v in sym.items() if not k.startswith("_")},
            "comparisons":{"production_vs_unstripped_signatures":overlap(prod["_signatures"],unstrip["_signatures"]),
                           "production_vs_unstripped_movabs_imm_normalized":overlap(prod["_relaxed"],unstrip["_relaxed"])}}
    (a.out/"static-machine-code-analysis.json").write_text(json.dumps(result,indent=2)+"\n",encoding="utf-8")
    lines=["# Static machine-code analysis","",result["note"],""]
    for title,key in (("Production","production"),("Release unstripped","release_unstripped"),("Symbolized","symbolized")):
        r=result[key]; t=r["totals"]
        lines += [f"## {title}","",f"Instructions: {r['instructions']:,}; distinct mnemonics: {r['distinct_mnemonics']}; functions: {r['function_count_with_instructions']:,}.",
                  "Calls {calls:,}; conditional branches {conditional_branches:,}; unconditional jumps {unconditional_jumps:,}; atomics/lock {lock_or_atomic:,}; memory operands {memory_operands:,}; stack memory operands {stack_memory_operands:,}; SIMD/vector heuristic {simd_vector_heuristic:,}.".format(**t),"",
                  "| Function | Instructions | Calls | Conditional branches | Memory operands |","|---|---:|---:|---:|---:|"]
        for f in r["top_functions_by_instruction_count"][:20]:
            lines.append(f"| `{f['symbol']}` | {f['instructions']:,} | {f['calls']:,} | {f['conditional_branches']:,} | {f['memory_operands']:,} |")
        lines.append("")
    lines += ["## Production vs release-unstripped","","| Normalization | Overlap | Production-only | Unstripped-only |","|---|---:|---:|---:|"]
    for k,label in (("production_vs_unstripped_signatures","RIP-relative/branch addresses normalized"),("production_vs_unstripped_movabs_imm_normalized","Also normalizes movabs immediate values")):
        c=result["comparisons"][k]; lines.append(f"| {label} | {c['multiset_overlap_percent_of_larger']:.6f}% | {c['left_only']:,} | {c['right_only']:,} |")
    (a.out/"static-machine-code-analysis.md").write_text("\n".join(lines)+"\n",encoding="utf-8")
    mca_ok = run_mca(a.symbolized,a.out,a.mca_cpu)
    print(a.out/"static-machine-code-analysis.json"); return 0 if mca_ok else 1

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
