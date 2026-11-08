"""Evidence helpers for Rust test collection; never change host pressure or tests.

The mlock/trim test in upstream Warden assumes a calm host.  Its production
function refuses to unlock memory when the host's memory PSI is elevated.
These helpers use the same thresholds and retain the observations, so a
prerequisite that never becomes true cannot be mistaken for a successful test.
"""
from __future__ import annotations

import math
from pathlib import Path
import re
import time
from typing import Any


MEMORY_PSI = Path("/proc/pressure/memory")
CALM_THRESHOLDS = {"some_avg10_below": 1.0, "full_avg10_below": 0.1}
_PSI_FIELDS = {"avg10", "avg60", "avg300", "total"}
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_SUMMARY = re.compile(
    r"^test result: (ok|FAILED)\. "
    r"(\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out"
    r"(?:;.*)?$"
)
_COUNT_KEYS = ("passed", "failed", "ignored", "measured", "filtered_out")


def inspect_memory_pressure(path: Path = MEMORY_PSI) -> dict[str, Any]:
    """Read host memory PSI and evaluate Warden's exact calm-host predicate.

    PSI averages are percentages.  A missing ``full`` row is allowed by the
    upstream predicate.  Unreadable or malformed input never establishes calm.
    Every result retains the raw input and an error when it cannot be evaluated.
    """
    result: dict[str, Any] = {
        "path": str(path), "calm": False, "raw": None, "parsed": {},
        "error": None, "thresholds": CALM_THRESHOLDS.copy(),
    }
    try:
        raw = Path(path).read_text(encoding="ascii")
        result["raw"] = raw
        parsed: dict[str, dict[str, int | float]] = {}
        for line in raw.splitlines():
            tokens = line.split()
            if not tokens:
                continue
            kind = tokens[0]
            if kind not in ("some", "full"):
                continue  # retain unknown future rows in raw evidence
            if kind in parsed:
                raise ValueError(f"duplicate PSI row: {kind}")
            fields: dict[str, int | float] = {}
            for token in tokens[1:]:
                key, sep, value = token.partition("=")
                if not sep or not value:
                    raise ValueError(f"malformed PSI field: {token!r}")
                if key not in _PSI_FIELDS:
                    continue
                if key in fields:
                    raise ValueError(f"duplicate PSI field: {kind}.{key}")
                if key == "total":
                    if not value.isascii() or not value.isdecimal():
                        raise ValueError(f"invalid PSI total: {value!r}")
                    fields[key] = int(value)
                else:
                    number = float(value)
                    if not math.isfinite(number) or not 0 <= number <= 100:
                        raise ValueError(f"invalid PSI average: {kind}.{key}={value!r}")
                    fields[key] = number
            if set(fields) != _PSI_FIELDS:
                raise ValueError(f"missing PSI fields in {kind}: {sorted(_PSI_FIELDS - fields.keys())}")
            parsed[kind] = fields
        if "some" not in parsed:
            raise ValueError("PSI 'some' row is missing")
        result["parsed"] = parsed
        result["calm"] = bool(
            parsed["some"]["avg10"] < CALM_THRESHOLDS["some_avg10_below"]
            and ("full" not in parsed or parsed["full"]["avg10"] < CALM_THRESHOLDS["full_avg10_below"])
        )
    except (OSError, UnicodeError, ValueError) as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def wait_for_calm_memory(
    timeout: float, interval: float = 2, path: Path = MEMORY_PSI,
) -> dict[str, Any]:
    """Observe PSI until calm or timeout; retain all observations for reporting.

    Timeout zero performs one immediate observation.  Missing or invalid PSI
    returns immediately because no useful pressure predicate can be established.
    A final sleep is clipped to the deadline, using a monotonic clock throughout.
    """
    if not math.isfinite(timeout) or timeout < 0:
        raise ValueError("timeout must be finite and nonnegative")
    if not math.isfinite(interval) or interval <= 0:
        raise ValueError("interval must be finite and positive")
    start = time.monotonic()
    deadline = start + timeout
    samples: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "ready": False, "samples": samples, "elapsed_s": 0.0,
        "timeout_s": timeout, "interval_s": interval, "reason": "timeout",
    }
    while True:
        sample = inspect_memory_pressure(path)
        now = time.monotonic()
        sample["elapsed_s"] = round(now - start, 6)
        samples.append(sample)
        report["elapsed_s"] = sample["elapsed_s"]
        if sample["calm"]:
            report.update(ready=True, reason="calm")
            return report
        if sample["error"]:
            report["reason"] = "unavailable_or_invalid"
            return report
        remaining = deadline - now
        if remaining <= 0:
            return report
        time.sleep(min(interval, remaining))


def parse_test_log(content: str) -> dict[str, Any]:
    """Extract libtest counts and failure evidence from a Cargo log.

    Counts cover completed result summaries only.  They do not imply that later
    workspace targets executed after a failure.  A zero-test run is explicitly
    distinguished from one which actually exercised tests.  Internal early
    returns that upstream prints as 'skipping' remain visible even with harness
    status ``ok``.
    """
    lines = _ANSI.sub("", content).splitlines()
    summaries: list[dict[str, Any]] = []
    counts = dict.fromkeys(_COUNT_KEYS, 0)
    failed_tests: list[str] = []
    compiler_errors: list[str] = []
    cargo_errors: list[str] = []
    panics: list[str] = []
    internal_skips: list[str] = []
    for line in lines:
        stripped = line.strip()
        summary = _SUMMARY.fullmatch(stripped)
        if summary:
            row = {key: int(value) for key, value in zip(_COUNT_KEYS, summary.groups()[1:])}
            for key in _COUNT_KEYS:
                counts[key] += row[key]
            summaries.append({"status": summary.group(1), **row, "line": stripped})
        failed = re.fullmatch(r"test (\S+) \.\.\. FAILED", stripped)
        if failed and failed.group(1) not in failed_tests:
            failed_tests.append(failed.group(1))
        if re.match(r"^error(?:\[[A-Z]\d+\])?:", stripped):
            cargo_errors.append(stripped)
            if not re.match(r"^error: (?:test failed|\d+ targets? failed|doctest failed)", stripped):
                compiler_errors.append(stripped)
        if "panicked at" in stripped:
            panics.append(stripped)
        if "skipping" in stripped.lower() or "mlockall not permitted" in stripped.lower():
            # Keep the actual line rather than infer a count from arbitrary text.
            internal_skips.append(stripped)
    return {
        "counts": counts, "summaries": summaries, "failed_tests": failed_tests,
        "compiler_errors": compiler_errors, "cargo_errors": cargo_errors,
        "panics": panics, "internal_skips": internal_skips,
        "executed": counts["passed"] + counts["failed"] > 0,
        "all_summaries_passed": bool(summaries) and all(row["status"] == "ok" for row in summaries)
        and counts["failed"] == 0 and not cargo_errors,
    }
