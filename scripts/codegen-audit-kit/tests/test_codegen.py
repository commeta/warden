"""Exercise actual ELF disassembly and independent LLVM-MCA symbol inputs."""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

KIT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("codegen_analysis", KIT / "codegen-analysis.py")
CODEGEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CODEGEN)


@unittest.skipUnless(shutil.which("c++") and shutil.which("objdump")
                     and platform.machine().lower() in ("x86_64", "amd64"),
                     "requires x86-64 C++ compiler and GNU objdump")
class ElfIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="codegen-test-")
        cls.root = Path(cls.temporary.name)
        source = cls.root / "fixture.cpp"
        source.write_text("""
namespace A { struct ProcessScanner { static int tick(int); };
__attribute__((noinline)) int ProcessScanner::tick(int value) { return value + 11; } }
namespace B { struct ProcessScanner { static int tick(int); };
__attribute__((noinline)) int ProcessScanner::tick(int value) { return value * 7; } }
int main(int argc, char**) { return A::ProcessScanner::tick(argc) + B::ProcessScanner::tick(argc); }
""")
        cls.binary = cls.root / "fixture"
        subprocess.run(["c++", "-O1", "-g", str(source), "-o", str(cls.binary)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def test_real_elf_instruction_inventory(self):
        inventory = CODEGEN.analyze(self.binary)
        self.assertGreater(inventory["instructions"], 0)
        selected = [row for row in inventory["top_functions_by_instruction_count"]
                    if "ProcessScanner::tick" in row["symbol"]]
        self.assertEqual(len(selected), 2)
        self.assertTrue(all(row["returns"] == 1 for row in selected))

    def test_non_x86_elf_rejected_before_objdump(self):
        other = self.root / "aarch64-header"
        contents = bytearray(self.binary.read_bytes())
        contents[18:20] = (183).to_bytes(2, "little")
        other.write_bytes(contents)
        with mock.patch.object(CODEGEN.subprocess, "Popen") as popen:
            with self.assertRaisesRegex(RuntimeError, "unsupported ELF architecture"):
                CODEGEN.analyze(other)
            popen.assert_not_called()

    def test_empty_disassembly_is_failure(self):
        source = self.root / "empty.s"
        source.write_text('.section .note.GNU-stack,"",@progbits\n')
        empty = self.root / "empty.o"
        subprocess.run(["c++", "-c", str(source), "-o", str(empty)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with self.assertRaisesRegex(RuntimeError, "no decoded instructions"):
            CODEGEN.analyze(empty)

    def test_mca_matching_symbols_are_separate_external_inputs(self):
        # This fake scheduling tool intentionally does not test LLVM's numerical
        # model. Actual objdump + real process execution tests input segmentation.
        fake = self.root / "fake-llvm-mca"
        fake.write_text(f"#!{sys.executable}\nimport sys, pathlib\np=pathlib.Path(sys.argv[-1])\nn=sum(bool(x.strip()) and not x.startswith(('#', '.')) for x in p.read_text().splitlines())\nprint('Iterations: 20\\nInstructions: '+str(n*20)+'\\nTotal Cycles: 45\\nBlock RThroughput: 1.0')\n")
        fake.chmod(0o755)
        output = self.root / "segmented"
        with mock.patch.object(CODEGEN.shutil, "which", return_value=str(fake)):
            self.assertTrue(CODEGEN.run_mca(self.binary, output, "generic"))
        rows = json.loads((output / "llvm-mca/status.json").read_text())
        modeled = [row for row in rows if row["status"] == "ok"]
        self.assertEqual(len(modeled), 2)
        self.assertEqual(len({row["address"] for row in modeled}), 2)
        self.assertEqual(len({row["symbol"] for row in modeled}), 2)
        for row in modeled:
            text = (output / "llvm-mca" / row["assembly"]).read_text()
            instructions = [line for line in text.splitlines()
                            if line and not line.startswith(("#", "."))]
            self.assertEqual(sum(line.startswith("ret") for line in instructions), 0, text)
            self.assertEqual(len(instructions), row["instruction_lines"])
            self.assertIn("not a profiler", row["limitations"])
            self.assertIn("Instructions:", (output / "llvm-mca" / row["report"]).read_text())

    def test_mca_zero_exit_with_diagnostics_fails(self):
        output = self.root / "mca-warning"
        fake = self.root / "fake-error-mca"
        fake.write_text(f"#!{sys.executable}\nprint('bad.s:7:3: error: unknown token')\n")
        fake.chmod(0o755)
        with mock.patch.object(CODEGEN.shutil, "which", return_value=str(fake)):
            self.assertFalse(CODEGEN.run_mca(self.binary, output, "generic"))
        rows = json.loads((output / "llvm-mca/status.json").read_text())
        self.assertGreaterEqual(sum(row["status"] == "failed" for row in rows), 2)
        self.assertTrue(all(row["reason"].startswith("assembler/llvm-mca") for row in rows if row["status"] == "failed"))

    def test_symbol_matches_trait_and_inherent(self):
        self.assertTrue(CODEGEN.symbol_matches(
            "<warden_detect::process::ProcessScanner as warden_detect::runtime::Detector>::tick", "ProcessScanner::tick"))
        self.assertTrue(CODEGEN.symbol_matches("<warden_respond::Responder>::run_one", "Responder::run_one"))
        self.assertFalse(CODEGEN.symbol_matches("<warden_respond::NotResponder>::run_one", "Responder::run_one"))

    def test_mca_timeout_preserves_per_symbol_failure_status(self):
        output = self.root / "mca-timeout"
        with mock.patch.object(CODEGEN.shutil, "which", return_value="/missing/llvm-mca"), \
                mock.patch.object(CODEGEN.subprocess, "run",
                                  side_effect=subprocess.TimeoutExpired("llvm-mca", 300)):
            self.assertFalse(CODEGEN.run_mca(self.binary, output, "generic"))
        rows = json.loads((output / "llvm-mca/status.json").read_text())
        failed = [row for row in rows if row["status"] == "failed"]
        self.assertEqual(len(failed), 2)
        self.assertTrue(all(row["exit_code"] == 124 for row in failed))

    def test_real_mca_when_installed(self):
        if not shutil.which("llvm-mca"):
            self.skipTest("llvm-mca not installed; actual ELF input tests still run")
        output = self.root / "real-mca"
        self.assertTrue(CODEGEN.run_mca(self.binary, output, "generic"))
        rows = json.loads((output / "llvm-mca/status.json").read_text())
        self.assertEqual(sum(row["status"] == "ok" for row in rows), 2)

    def test_cli_produces_inventory_for_real_elf(self):
        output = self.root / "cli"
        result = subprocess.run(
            [sys.executable, str(KIT / "codegen-analysis.py"),
             "--production", str(self.binary), "--unstripped", str(self.binary),
             "--symbolized", str(self.binary), "--out", str(output), "--mca-cpu", "generic"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        inventory = json.loads((output / "static-machine-code-analysis.json").read_text())
        self.assertGreater(inventory["production"]["instructions"], 0)
        self.assertEqual(inventory["comparisons"]["production_vs_unstripped_signatures"]
                         ["multiset_overlap_percent_of_larger"], 100.0)


class InvalidInputTests(unittest.TestCase):
    def test_text_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "not-elf"
            path.write_text("not a machine-code binary")
            with self.assertRaisesRegex(RuntimeError, "not an ELF binary"):
                CODEGEN.analyze(path)


if __name__ == "__main__":
    unittest.main()
