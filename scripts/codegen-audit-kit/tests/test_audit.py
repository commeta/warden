"""Collector regression tests: real sections and split-test completeness."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location('audit', ROOT / 'audit.py')
audit = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(audit)
SUMMARY = 'test result: ok. {} passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n'


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.args = SimpleNamespace(toolchain='1.99.1', skip_tests=False, full=False, memory_calm_timeout=0)
        self.collector = audit.Audit(self.root / 'out', self.args)
        self.commands = {}

    def simulate_tests(self, *, ready=True, skip=False, zero=False, workspace_rc=0):
        c = self.collector
        def run(name, argv, **kwargs):
            self.commands[name] = argv
            text = SUMMARY.format(10)
            if name == 'cargo_test_mlock_isolated':
                text = SUMMARY.format(0 if zero else 1)
                if skip:
                    text = 'mlockall not permitted here; skipping\n' + text
            (c.logs / (name + '.log')).write_text(text)
            rc = workspace_rc if name == 'cargo_test_ci_root_serial' else 0
            c.steps.append({'name': name, 'status': 'ok' if rc == 0 else 'failed', 'exit_code': rc})
            return rc
        with patch.object(c, 'run', side_effect=run), patch.object(c, 'root_prefix', return_value=[]), \
             patch.object(audit, 'wait_for_calm_memory', return_value={'ready': ready}), \
             patch.object(audit, 'inspect_memory_pressure', return_value={'calm': True}), \
             patch.object(c, '_retry_known_fuzz_smoke_timing_failure'):
            c.run_tests(self.root)
        return json.loads((c.reports / 'test-validation.json').read_text())

    def test_perf_event_csv_requires_numeric_counter_not_only_exit_zero(self):
        ok = "13034,,cycles,100.0,100.0,\n"
        unsupported = "<not supported>,,cycles,0.00,0.00,\n"
        self.assertTrue(audit.Audit._perf_event_valid(ok, "cycles"))
        self.assertFalse(audit.Audit._perf_event_valid(unsupported, "cycles"))
        self.assertFalse(audit.Audit._perf_event_valid("100,,instructions,0,0,", "cycles"))

    def test_rust_trait_symbols_are_identified_without_stripping(self):
        self.assertTrue(audit.Audit._symbol_matches(
            "<warden_detect::disk::DiskDetector as warden_detect::runtime::Detector>::tick", "DiskDetector::tick"))
        self.assertTrue(audit.Audit._symbol_matches("<wardend::engine::Engine>::process", "Engine::process"))

    def test_complete_split_suite_runs_exact_sensitive_test_last(self):
        report = self.simulate_tests()
        self.assertTrue(report['coverage_complete'])
        cmd = self.commands['cargo_test_ci_root_serial']
        self.assertIn('--no-fail-fast', cmd)
        self.assertEqual(cmd[-2:], ['--skip', audit.MLOCK_TEST])
        exact = self.commands['cargo_test_mlock_isolated']
        self.assertIn('--exact', exact)
        self.assertIn('--nocapture', exact)
        self.assertIn('--locked', exact)
        self.assertIn('CARGO_PROFILE_TEST_DEBUG=line-tables-only', exact)
        self.assertLess(list(self.commands).index('cargo_test_ci_root_serial'), list(self.commands).index('cargo_test_mlock_isolated'))

    def test_missing_psi_is_incomplete_and_does_not_run_sensitive_test(self):
        report = self.simulate_tests(ready=False)
        self.assertFalse(report['coverage_complete'])
        self.assertNotIn('cargo_test_mlock_isolated', self.commands)
        self.assertIn('mlock_test_precondition', [s['name'] for s in self.collector.steps if s['status'] == 'failed'])

    def test_self_skip_is_not_validated(self):
        self.assertFalse(self.simulate_tests(skip=True)['coverage_complete'])

    def test_exact_zero_test_run_is_not_validated(self):
        self.assertFalse(self.simulate_tests(zero=True)['coverage_complete'])

    def test_workspace_failure_is_not_hidden_by_isolated_pass(self):
        self.assertFalse(self.simulate_tests(workspace_rc=101)['coverage_complete'])

    def test_missing_command_fails_but_explicit_optional_probe_can_skip(self):
        with contextlib.redirect_stdout(io.StringIO()):
            rc = self.collector.run('missing', ['/definitely/missing/warden-command'])
            self.collector.run('optional', ['/definitely/missing/warden-command'], skip_on_failure=True)
        self.assertEqual(rc, 127)
        self.assertEqual([s['status'] for s in self.collector.steps], ['failed', 'skipped'])

    def test_tests_only_rejects_implicit_all_profiles(self):
        result = subprocess.run([sys.executable, str(ROOT / 'audit.py'), '--tests-only', '--profile-scope', 'all'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn('cannot combine', result.stderr)

    def test_fuzz_retry_cannot_hide_later_compiler_failure(self):
        log = self.root / 'cargo.log'
        log.write_text("""test tests::smoke_run_of_every_target ... FAILED
modsecurity: 1.010s on a 263-byte input
thread 'tests::smoke_run_of_every_target' panicked at fuzz.rs:373:17:
test result: FAILED. 3 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out
error[E0000]: compilation of later workspace target failed
""")
        matched, details = self.collector._is_known_fuzz_smoke_timing_failure(log)
        self.assertFalse(matched, details)

    @unittest.skipUnless(shutil.which('cc') and shutil.which('objcopy'), 'requires C compiler and objcopy')
    def test_section_hash_size_survive_temporary_file_cleanup(self):
        source = self.root / 'tiny.c'
        binary = self.root / 'tiny'
        source.write_text('int main(void) {return 7;}\n')
        subprocess.run(['cc', str(source), '-o', str(binary)], check=True)
        with contextlib.redirect_stdout(io.StringIO()):
            record = self.collector._extract_text_hash(binary, self.collector.reports / 'text.sha256')
        self.assertGreater(record['bytes'], 0)
        self.assertEqual(len(record['sha256']), 64)
        self.assertFalse((self.collector.build / 'tiny.text').exists())
        self.assertIn(record['sha256'], (self.collector.reports / 'text.sha256').read_text())

    def test_standard_profile_with_success_exit_and_bad_json_fails(self):
        c = self.collector
        c.args.profile_duration = 20
        c.args.profile_warmup = 0
        def run(name, argv, **kwargs):
            for scenario in ('idle', 'process', 'waf'):
                (c.out / 'runtime-profile' / (scenario + '.json')).write_text(json.dumps({'error': 'daemon exited'}))
            c.steps.append({'name': name, 'status': 'ok', 'exit_code': 0})
            return 0
        with patch.object(c, 'metrics_port_free', return_value=True), patch.object(c, 'root_prefix', return_value=[]), \
             patch.object(c, '_profile_smoke_preflight', return_value=True), \
             patch.object(c, '_instrument_profile_runner', return_value=self.root / 'profile.py'), \
             patch.object(c, '_restore_output_ownership'), patch.object(c, 'run', side_effect=run):
            c.run_profile(self.root, self.root / 'daemon')
        inventory = json.loads((c.reports / 'profile-all-inventory.json').read_text())
        self.assertFalse(inventory['complete'])
        self.assertIn('profile_result_validation', [s['name'] for s in c.steps if s['status'] == 'failed'])

if __name__ == '__main__':
    unittest.main()
