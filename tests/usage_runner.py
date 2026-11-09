"""Usage corpus runner: 100 realistic command-line journeys, executed for real.

Where the red-team corpus measures detection, this corpus measures the product:
every case builds a project tree, runs the shipped console interface as a real
subprocess, and asserts the exit code, the files that must appear, and the
output that must or must not be printed. A command that only works on the happy
path with a clean directory is not shippable, so the cases include spaced paths,
read-only targets, empty trees, repeated runs and unicode filenames.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


@dataclass(frozen=True, slots=True)
class UsageCase:
    """One scripted command-line journey.

    Attributes:
        case_id: Stable identifier used in reports.
        category: Grouping used for the per-area summary.
        description: What the journey exercises.
        build: Callable that populates the project directory.
        argv: Args for the command line, or a callable taking the project root.
        expect_exit: Acceptable process exit codes.
        expect_files: Project-relative paths that must exist afterwards.
        expect_absent: Project-relative paths that must NOT exist afterwards.
        expect_stdout: Substrings that must appear in stdout plus stderr.
        forbid_stdout: Substrings that must not appear anywhere in the output.
        expect_json: When True the stdout must parse as JSON with these keys.
        timeout_s: Per case subprocess budget.
    """

    case_id: str
    category: str
    description: str
    build: Callable[[Path], None]
    argv: Sequence[str] | Callable[[Path], Sequence[str]]
    expect_exit: frozenset[int] = frozenset({0})
    expect_files: tuple[str, ...] = ()
    expect_absent: tuple[str, ...] = ()
    expect_stdout: tuple[str, ...] = ()
    forbid_stdout: tuple[str, ...] = ()
    expect_json: bool = False
    timeout_s: float = 180.0


@dataclass(slots=True)
class UsageOutcome:
    """Result of one usage case."""

    case: UsageCase
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration_ms: float = 0.0
    mismatches: list[str] = field(default_factory=list)
    error: str = ""

    @property
    def output(self) -> str:
        """stdout and stderr combined, which is what a user actually sees."""

        return self.stdout + self.stderr

    @property
    def passed(self) -> bool:
        """True when every expectation held."""

        return not self.error and not self.mismatches


def _python() -> str:
    """Interpreter used for the child processes."""

    return sys.executable


def run_usage_case(case: UsageCase, root: Path) -> UsageOutcome:
    """Build the fixture, run the command, and check the expectations."""

    outcome = UsageOutcome(case=case)
    try:
        case.build(root)
    except Exception as exc:
        outcome.error = f"fixture: {type(exc).__name__}: {exc}"
        return outcome
    argv = case.argv(root) if callable(case.argv) else list(case.argv)
    env = dict(os.environ)
    env["TAUHAULITY_NO_AUTO"] = "1"
    env["PYTHONPATH"] = str(PROJECT_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    started = time.perf_counter()
    try:
        completed = subprocess.run(
            [_python(), "-m", "tauhaulity", *argv],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=case.timeout_s,
            env=env,
            stdin=subprocess.DEVNULL,
        )
    except subprocess.TimeoutExpired:
        outcome.error = f"timeout after {case.timeout_s:.0f}s"
        return outcome
    except OSError as exc:
        outcome.error = f"{type(exc).__name__}: {exc}"
        return outcome
    outcome.duration_ms = (time.perf_counter() - started) * 1000.0
    outcome.exit_code = completed.returncode
    outcome.stdout = completed.stdout
    outcome.stderr = completed.stderr

    if completed.returncode not in case.expect_exit:
        outcome.mismatches.append(f"exit {completed.returncode} not in {sorted(case.expect_exit)}")
    for rel in case.expect_files:
        if not (root / rel).exists():
            outcome.mismatches.append(f"missing file {rel}")
    for rel in case.expect_absent:
        if (root / rel).exists():
            outcome.mismatches.append(f"unexpected file {rel}")
    combined = outcome.output
    for needle in case.expect_stdout:
        if needle not in combined:
            outcome.mismatches.append(f"stdout missing {needle!r}")
    for needle in case.forbid_stdout:
        if needle in combined:
            outcome.mismatches.append(f"stdout must not contain {needle!r}")
    if case.expect_json:
        try:
            json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            outcome.mismatches.append(f"stdout is not JSON: {exc}")
    return outcome


def run_usage_corpus(cases: Sequence[UsageCase]) -> list[UsageOutcome]:
    """Run every case in its own temporary project directory."""

    outcomes: list[UsageOutcome] = []
    for case in cases:
        # The directory name deliberately contains a space: real projects do.
        directory = Path(tempfile.mkdtemp(prefix=f"th usage {case.case_id} "))
        try:
            outcomes.append(run_usage_case(case, directory))
        finally:
            shutil.rmtree(directory, ignore_errors=True)
    return outcomes


def summarize(outcomes: Sequence[UsageOutcome]) -> dict[str, object]:
    """Aggregate outcomes into a per-category pass rate."""

    per_category: dict[str, dict[str, int]] = {}
    failures: list[str] = []
    slowest: list[tuple[str, float]] = []
    for outcome in outcomes:
        bucket = per_category.setdefault(outcome.case.category, {"total": 0, "passed": 0})
        bucket["total"] += 1
        if outcome.passed:
            bucket["passed"] += 1
        else:
            failures.append(outcome.case.case_id)
        slowest.append((outcome.case.case_id, outcome.duration_ms))
    rates = {
        category: (bucket["passed"] / bucket["total"] if bucket["total"] else 0.0)
        for category, bucket in sorted(per_category.items())
    }
    slowest.sort(key=lambda item: item[1], reverse=True)
    durations = [duration for _case, duration in slowest]
    return {
        "cases": len(outcomes),
        "passed": sum(1 for outcome in outcomes if outcome.passed),
        "rates": rates,
        "failures": failures,
        "median_ms": sorted(durations)[len(durations) // 2] if durations else 0.0,
        "slowest": slowest[:5],
    }


def render_table(outcomes: Sequence[UsageOutcome]) -> str:
    """Render a fixed width table for the console."""

    header = f"{'CASE':<32}{'CATEGORY':<20}{'EXIT':>5}{'RESULT':<7}NOTE"
    lines = [header, "-" * len(header)]
    for outcome in outcomes:
        note = outcome.error or "; ".join(outcome.mismatches)
        marker = "PASS" if outcome.passed else "FAIL"
        lines.append(
            f"{outcome.case.case_id:<32}{outcome.case.category:<20}{outcome.exit_code:>5}{marker:<7}{note[:80]}"
        )
    return chr(10).join(lines)


def main(argv: list[str] | None = None) -> int:
    """Run the usage corpus from the command line."""

    from tests.usage_cases import USAGE_CASES

    arguments = list(sys.argv[1:] if argv is None else argv)
    outcomes = run_usage_corpus(USAGE_CASES)
    summary = summarize(outcomes)
    if "--json" in arguments:
        print(json.dumps(summary, indent=2))
    else:
        print(render_table(outcomes))
        print()
        print(f"cases {summary['cases']}, passed {summary['passed']}, median {summary['median_ms']:.0f} ms")
        for category, rate in summary["rates"].items():
            print(f"  pass {category:<24} {rate * 100:.0f}%")
        print("slowest: " + ", ".join(f"{name} {duration:.0f} ms" for name, duration in summary["slowest"]))
        if summary["failures"]:
            print("failures: " + ", ".join(summary["failures"]))
    return 0 if all(outcome.passed for outcome in outcomes) else 1


if __name__ == "__main__":
    sys.exit(main())
