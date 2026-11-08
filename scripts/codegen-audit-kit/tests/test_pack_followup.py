"""CLI regression coverage for diagnostic bundles and follow-up evidence selection."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.audit = self.base / 'audit'
        for name, data in {
            'logs/cargo_test_ci_root_serial.log': 'one failed assertion',
            'reports/cargo-test-failure-analysis.json': '{}',
            'reports/source-identity.txt': 'commit=abc',
            'artifacts/audit-kit/VERSION': '1.1.0',
            'artifacts/wardend.production': 'ELF',
            'artifacts/mir/a.mir': 'MIR',
            'artifacts/llvm-ir/a.ll': 'LLVM',
            'source/warden/src/lib.rs': 'source',
            'runtime-stress/a.perf.data': 'PMU',
            'reports/elf/objdump-disassembly.txt': 'disassembly',
            'followup-runs/a/logs/run.log': 'followup log',
            'followup-runs/a/runtime-stress/a.perf.data': 'followup PMU',
        }.items():
            p = self.audit / name
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(data)

    def pack(self, *args):
        out = self.base / 'bundle.tar.gz'
        result = subprocess.run([sys.executable, str(ROOT / 'pack-results.sh'), str(self.audit),
                                 '--output', str(out), *args], capture_output=True, text=True)
        return result, out

    def test_diagnostics_omits_code_and_raw_data_and_verifies_hashes(self):
        result, out = self.pack('--diagnostics-only')
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(out) as tf:
            members = {p.name.removeprefix('audit/'): p for p in tf.getmembers()}
            self.assertIn('logs/cargo_test_ci_root_serial.log', members)
            self.assertIn('reports/cargo-test-failure-analysis.json', members)
            self.assertIn('artifacts/audit-kit/VERSION', members)
            self.assertIn('followup-runs/a/logs/run.log', members)
            for name in ('artifacts/wardend.production', 'artifacts/mir/a.mir', 'source/warden/src/lib.rs',
                         'artifacts/llvm-ir/a.ll', 'runtime-stress/a.perf.data',
                         'reports/elf/objdump-disassembly.txt', 'followup-runs/a/runtime-stress/a.perf.data'):
                self.assertNotIn(name, members)
            info = json.load(tf.extractfile('audit/BUNDLE-INFO.json'))
            self.assertEqual(info['mode'], 'diagnostics')
            self.assertTrue(info['options']['diagnostics_only'])
            for line in tf.extractfile('audit/BUNDLE-SHA256SUMS').read().decode().splitlines():
                expected, name = line.split('  ', 1)
                self.assertEqual(expected, hashlib.sha256(tf.extractfile('audit/' + name).read()).hexdigest())

    def test_default_bundle_retains_source_elf_mir(self):
        result, out = self.pack()
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(out) as tf:
            names = tf.getnames()
            for name in ('artifacts/wardend.production', 'artifacts/mir/a.mir', 'source/warden/src/lib.rs'):
                self.assertIn('audit/' + name, names)

    def test_diagnostics_rejects_raw_data_flags(self):
        result, out = self.pack('--diagnostics-only', '--include-perf-data')
        self.assertEqual(result.returncode, 2)
        self.assertFalse(out.exists())

    def test_run_id_cannot_escape_followup_directory(self):
        result, out = self.pack('--run-id', '../outside')
        self.assertEqual(result.returncode, 2)
        self.assertFalse(out.exists())


class FollowupTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.audit = self.base / 'audit'
        (self.audit / 'source/warden').mkdir(parents=True)
        (self.audit / 'source/warden/Cargo.toml').write_text('[workspace]\n')
        (self.audit / 'logs').mkdir()
        self.log = self.audit / 'logs/cargo_test_ci_root_serial.log'
        self.log.write_text('test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n')

    def run_followup(self, *args, env=None):
        return subprocess.run(['bash', str(ROOT / 'continue-audit.sh'), str(self.audit),
                               '--skip-fmt', '--skip-clippy', '--skip-perf-preflight', *args],
                              capture_output=True, text=True, env=env)

    def test_compiler_error_after_passing_group_is_failure(self):
        self.log.write_text(self.log.read_text() + 'error[E0000]: compiler failure in later target\n')
        result = self.run_followup()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_zero_test_log_is_failure(self):
        self.log.write_text('test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n')
        result = self.run_followup()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_aggregate_failure_cannot_fall_back_to_legacy_pass(self):
        (self.audit / 'reports').mkdir()
        (self.audit / 'reports/test-validation.json').write_text(json.dumps({'coverage_complete': False, 'root_serial': True}))
        result = self.run_followup()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_symbolized_binary_is_not_production_fallback(self):
        (self.audit / 'artifacts').mkdir()
        binary = self.audit / 'artifacts/wardend.symbolized'
        binary.write_text('#!/bin/sh\nexit 0\n')
        binary.chmod(0o755)
        result = self.run_followup('--profile')
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn('missing executable production binary', result.stderr)

    def runtime_fixture(self):
        (self.audit / 'artifacts').mkdir()
        for name in ('wardend.production', 'wardend.release-unstripped'):
            binary = self.audit / 'artifacts' / name
            binary.write_text('#!/bin/sh\n# ' + name + '\nexit 0\n')
            binary.chmod(0o755)
        bench = self.audit / 'source/warden/bench'
        bench.mkdir()
        (bench / 'profile.py').write_text('''import argparse, json, os, pathlib
p = argparse.ArgumentParser(); p.add_argument('--wardend'); p.add_argument('--out')
a, _ = p.parse_known_args()
pathlib.Path(a.out, 'selected-binary.txt').write_text(a.wardend)
rows = [dict(name=name, cpu_steady_pct=0.1, rss_steady=100, rss_peak=120,
             syscalls_per_s=1, per_thread={}, exited_early=False) for name in ('idle', 'process', 'waf')]
mode = os.environ.get('FIXTURE_PROFILE')
if mode == 'error': rows[0]['error'] = 'daemon did not run'
if mode == 'early': rows[0]['exited_early'] = True
if mode == 'missing_scenario': rows.pop()
if mode == 'missing_metric': del rows[0]['rss_peak']
if mode == 'duplicate': rows[0]['name'] = 'process'
if mode == 'invalid_json': print('invalid')
else: print(json.dumps(rows))
''')
        (bench / 'stress.py').write_text('''import argparse, json, os, pathlib
p = argparse.ArgumentParser(); p.add_argument('--wardend'); p.add_argument('--out')
a, _ = p.parse_known_args()
pathlib.Path(a.out, 'selected-binary.txt').write_text(a.wardend)
rows = {name: dict(cpu_load_seconds=1, rss_peak_mib=2, threads=3)
        for name in ('exec_storm', 'waf_v6_unique', 'waf_v6_spread', 'auth_unique')}
mode = os.environ.get('FIXTURE_STRESS')
if mode == 'error': rows['exec_storm']['error'] = 'daemon did not run'
if mode == 'missing_scenario': del rows['exec_storm']
if mode == 'missing_metric': del rows['exec_storm']['rss_peak_mib']
if mode != 'missing_summary':
    output = pathlib.Path(a.out, 'stress-1.json')
    output.write_text('invalid' if mode == 'invalid_json' else json.dumps(rows))
    if mode == 'stale': os.utime(output, (1, 1))
''')
        mockbin = self.base / 'bin'; mockbin.mkdir()
        sudo = mockbin / 'sudo'
        sudo.write_text('''#!/bin/sh
if [ "$1" = "-E" ]; then shift; fi
if [ "$1" = "chown" ]; then exit 0; fi
exec "$@"
''')
        sudo.chmod(0o755)
        return dict(os.environ, PATH=str(mockbin) + ':' + os.environ['PATH'])

    def test_runtime_commands_and_provenance_use_expected_binaries(self):
        env = self.runtime_fixture()
        result = self.run_followup('--profile', '--stress', env=env)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        run = next((self.audit / 'followup-runs').iterdir())
        selected = json.loads((run / 'reports/runtime-binary-provenance.json').read_text())
        for label, name in (('profile', 'wardend.production'), ('stress', 'wardend.release-unstripped')):
            binary = self.audit / 'artifacts' / name
            self.assertEqual(selected[label]['path'], str(binary))
            self.assertEqual(selected[label]['sha256'], hashlib.sha256(binary.read_bytes()).hexdigest())
            self.assertEqual((run / ('runtime-' + label) / 'selected-binary.txt').read_text(), str(binary))

    def test_zero_exit_invalid_profile_results_fail(self):
        env = self.runtime_fixture()
        for mode in ('error', 'early', 'missing_scenario', 'missing_metric', 'duplicate', 'invalid_json'):
            with self.subTest(mode=mode):
                result = self.run_followup('--profile', env=dict(env, FIXTURE_PROFILE=mode))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn('missing or invalid profile scenarios', result.stdout)

    def test_zero_exit_invalid_stress_results_fail(self):
        env = self.runtime_fixture()
        for mode in ('error', 'missing_scenario', 'missing_metric', 'missing_summary', 'stale', 'invalid_json'):
            with self.subTest(mode=mode):
                result = self.run_followup('--stress', env=dict(env, FIXTURE_STRESS=mode))
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn('missing or invalid stress scenarios', result.stdout)

    def test_requested_unavailable_clippy_fails(self):
        mockbin = self.base / 'bin'; mockbin.mkdir()
        cargo = mockbin / 'cargo'
        cargo.write_text('#!/bin/sh\nexit 127\n'); cargo.chmod(0o755)
        result = subprocess.run(['bash', str(ROOT / 'continue-audit.sh'), str(self.audit), '--skip-fmt'],
                                capture_output=True, text=True,
                                env=dict(os.environ, PATH=str(mockbin) + ':' + os.environ['PATH']))
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('requested cargo-clippy is unavailable', result.stdout)


if __name__ == '__main__':
    unittest.main()
