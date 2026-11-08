"""Regressions for pressure prerequisites and honest Cargo result accounting."""
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import test_support


def psi(some=0.0, full=0.0):
    text = f"some avg10={some} avg60=0.00 avg300=0.00 total=50\n"
    if full is not None:
        text += f"full avg10={full} avg60=0.00 avg300=0.00 total=10\n"
    return text


class MemoryPressureTests(unittest.TestCase):
    def inspect(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "memory"
            path.write_text(text)
            return test_support.inspect_memory_pressure(path)

    def test_exact_upstream_thresholds_and_optional_full_row(self):
        for some, full, calm in [
            (0.99, 0.09, True), (1.0, 0.0, False), (0.0, 0.1, False),
            (0.99, None, True), (1.0, None, False),
        ]:
            with self.subTest(some=some, full=full):
                result = self.inspect(psi(some, full))
                self.assertEqual(result["calm"], calm)
                self.assertIsNone(result["error"])
                self.assertEqual(result["raw"], psi(some, full))

    def test_missing_file_never_establishes_calm(self):
        with tempfile.TemporaryDirectory() as directory:
            result = test_support.inspect_memory_pressure(Path(directory) / "missing")
        self.assertFalse(result["calm"])
        self.assertIn("FileNotFoundError", result["error"])
        self.assertIsNone(result["raw"])

    def test_malformed_nonfinite_and_incomplete_data_fail_closed(self):
        for text in [
            "", psi().replace("some", "other"), psi().replace("avg10=0.0", "avg10=nan"),
            psi().replace("total=50", "total=-1"), psi().replace("avg60=0.00 ", ""),
            psi() + psi(), psi().replace("avg10=0.0", "avg10=-0.1"),
            psi().replace("avg10=0.0", "avg10=101"),
            psi().replace("total=50", "total=50 total=60"),
        ]:
            with self.subTest(text=text):
                result = self.inspect(text)
                self.assertFalse(result["calm"])
                self.assertIsNotNone(result["error"])
                self.assertEqual(result["raw"], text)

    def test_retains_unknown_future_fields_and_rows(self):
        text = psi().replace("total=50", "total=50 future=whatever") + "future some=thing\n"
        result = self.inspect(text)
        self.assertTrue(result["calm"])
        self.assertEqual(result["raw"], text)

    def test_wait_transitions_to_calm_and_preserves_observations(self):
        observations = [
            {"calm": False, "error": None, "raw": psi(2.0)},
            {"calm": True, "error": None, "raw": psi()},
        ]
        with mock.patch.object(test_support, "inspect_memory_pressure", side_effect=observations), \
             mock.patch.object(test_support.time, "monotonic", side_effect=[10, 10, 12]), \
             mock.patch.object(test_support.time, "sleep") as sleep:
            result = test_support.wait_for_calm_memory(10, interval=2)
        self.assertTrue(result["ready"])
        self.assertEqual(result["reason"], "calm")
        self.assertEqual(len(result["samples"]), 2)
        self.assertEqual(result["elapsed_s"], 2)
        sleep.assert_called_once_with(2)

    def test_wait_clips_last_sleep_to_deadline(self):
        with mock.patch.object(test_support, "inspect_memory_pressure",
                               side_effect=lambda path: {"calm": False, "error": None}), \
             mock.patch.object(test_support.time, "monotonic", side_effect=[0, 0, 2, 3]), \
             mock.patch.object(test_support.time, "sleep") as sleep:
            result = test_support.wait_for_calm_memory(3, interval=2)
        self.assertFalse(result["ready"])
        self.assertEqual(result["reason"], "timeout")
        self.assertEqual(result["elapsed_s"], 3)
        self.assertEqual(sleep.call_args_list, [mock.call(2), mock.call(1)])

    def test_zero_timeout_observes_once_without_sleeping(self):
        with mock.patch.object(test_support, "inspect_memory_pressure",
                               return_value={"calm": False, "error": None}) as inspect, \
             mock.patch.object(test_support.time, "sleep") as sleep:
            result = test_support.wait_for_calm_memory(0)
        self.assertFalse(result["ready"])
        inspect.assert_called_once()
        sleep.assert_not_called()

    def test_unavailable_psi_does_not_wait_or_claim_ready(self):
        with mock.patch.object(test_support, "inspect_memory_pressure",
                               return_value={"calm": False, "error": "not found"}), \
             mock.patch.object(test_support.time, "sleep") as sleep:
            result = test_support.wait_for_calm_memory(300)
        self.assertFalse(result["ready"])
        self.assertEqual(result["reason"], "unavailable_or_invalid")
        sleep.assert_not_called()

    def test_invalid_deadlines_are_rejected(self):
        for timeout, interval in [(-1, 2), (float("inf"), 2), (float("nan"), 2), (1, 0), (1, -1)]:
            with self.subTest(timeout=timeout, interval=interval):
                with self.assertRaises(ValueError):
                    test_support.wait_for_calm_memory(timeout, interval)


class CargoLogTests(unittest.TestCase):
    def test_multiple_completed_binaries_count_pass_failed_ignored_separately(self):
        content = """test unit::one ... ok
test result: ok. 12 passed; 0 failed; 2 ignored; 0 measured; 0 filtered out; finished in 0.01s
test selfstat::tests::a_peak_is_returned_even_under_mlockall ... FAILED
thread 'selfstat::tests::a_peak_is_returned_even_under_mlockall' panicked at src/selfstat.rs:342:9:
release_memory must give the peak back
test result: FAILED. 4 passed; 1 failed; 0 ignored; 0 measured; 3 filtered out; finished in 1.00s
error: test failed, to rerun pass `-p warden-sys --lib`
"""
        result = test_support.parse_test_log(content)
        self.assertEqual(result["counts"], {"passed": 16, "failed": 1, "ignored": 2, "measured": 0, "filtered_out": 3})
        self.assertEqual(result["failed_tests"], ["selfstat::tests::a_peak_is_returned_even_under_mlockall"])
        self.assertEqual(len(result["panics"]), 1)
        self.assertEqual(result["compiler_errors"], [])
        self.assertEqual(len(result["cargo_errors"]), 1)
        self.assertTrue(result["executed"])
        self.assertFalse(result["all_summaries_passed"])

    def test_zero_test_success_is_not_execution(self):
        result = test_support.parse_test_log(
            "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 120 filtered out; finished in 0.00s\n")
        self.assertFalse(result["executed"])
        self.assertEqual(result["counts"]["filtered_out"], 120)

    def test_compiler_error_without_summaries_cannot_validate_tests(self):
        result = test_support.parse_test_log(
            "error[E0603]: module is private\nerror: could not compile `warden-sys` (lib test) due to 1 previous error\n")
        self.assertEqual(len(result["compiler_errors"]), 2)
        self.assertFalse(result["executed"])
        self.assertFalse(result["all_summaries_passed"])

    def test_ansi_and_internal_mlock_skip_are_retained(self):
        result = test_support.parse_test_log(
            "mlockall not permitted here; skipping\n\x1b[32mtest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s\x1b[0m\n")
        self.assertEqual(result["counts"]["passed"], 1)
        self.assertEqual(result["internal_skips"], ["mlockall not permitted here; skipping"])

    def test_a_successful_exact_retry_does_not_erase_previous_failure(self):
        initial = test_support.parse_test_log(
            "test result: FAILED. 1 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.00s\n")
        retry = test_support.parse_test_log(
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 45 filtered out; finished in 0.00s\n")
        self.assertFalse(initial["all_summaries_passed"])
        self.assertTrue(retry["all_summaries_passed"])
        self.assertEqual(initial["counts"]["failed"], 1)
        self.assertEqual(retry["counts"]["filtered_out"], 45)


if __name__ == "__main__":
    unittest.main()
