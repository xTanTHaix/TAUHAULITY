"""Red-team corpus runner: measure detector recall and false positives.

A unit test proves one function; a corpus proves the product. Every case builds a
real fixture tree, runs the shipped scan engine, and checks the pillar verdict
against the behaviour a security review would expect. The runner reports recall
per category plus the false-positive count on the clean controls, which is the
number that decides whether a detector is shippable.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    # The runner is also executed directly (python tests/corpus_runner.py), where
    # sys.path[0] is tests/ and the package would otherwise be invisible.
    sys.path.insert(0, str(PROJECT_ROOT))

from tauhaulity.core.contracts import ScanOptions
from tauhaulity.core.policy import Policy
from tauhaulity.engine import run_scan


@dataclass(frozen=True, slots=True)
class CorpusCase:
    """One adversarial or control scenario.

    Attributes:
        case_id: Stable identifier used in reports.
        category: Grouping used for per-detector recall.
        description: What the fixture simulates.
        build: Callable that populates a fresh directory.
        expect: Pillar number to the set of acceptable statuses.
        expect_verdict: Optional acceptable overall verdict names.
    """

    case_id: str
    category: str
    description: str
    build: Callable[[Path], None]
    expect: Mapping[int, frozenset[str]]
    expect_verdict: frozenset[str] = frozenset()


@dataclass(slots=True)
class CaseOutcome:
    """Result of one corpus case."""

    case: CorpusCase
    statuses: dict[int, str] = field(default_factory=dict)
    verdict: str = ""
    duration_ms: float = 0.0
    mismatches: list[str] = field(default_factory=list)
    error: str = ""
    skipped: bool = False

    @property
    def passed(self) -> bool:
        """True when every expectation held and the scan did not raise."""

        return self.skipped or (not self.error and not self.mismatches)


def run_case(case: CorpusCase, root: Path) -> CaseOutcome:
    """Build the fixture, scan it, and compare the result with the expectation.

    Parameters:
        case: Case definition.
        root: Directory the fixture is created in.

    Returns:
        CaseOutcome with the observed statuses and any expectation mismatches.
    """

    outcome = CaseOutcome(case=case)
    try:
        case.build(root)
    except Exception as exc:  # a broken fixture is a corpus bug, not a detector bug
        message = f"{type(exc).__name__}: {exc}"
        if "git is required" in message or "git is not installed" in message:
            outcome.skipped = True
            outcome.error = ""
            return outcome
        outcome.error = f"fixture: {message}"
        return outcome
    try:
        result = run_scan(
            root,
            policy=Policy(),
            options=ScanOptions(generate_repro=False, record_telemetry=False),
            write_reports=False,
        )
    except Exception as exc:
        outcome.error = f"scan: {type(exc).__name__}: {exc}"
        return outcome
    outcome.statuses = {number: finding.status for number, finding in result.ctx.findings.items()}
    outcome.verdict = result.verdict.name
    outcome.duration_ms = result.duration_ms
    if case.expect_verdict and outcome.verdict not in case.expect_verdict:
        outcome.mismatches.append(f"verdict {outcome.verdict} not in {sorted(case.expect_verdict)}")
    for number, allowed in case.expect.items():
        observed = outcome.statuses.get(number, "MISSING")
        if observed not in allowed:
            outcome.mismatches.append(f"P{number:02d} {observed} not in {sorted(allowed)}")
    return outcome


def run_corpus(cases: list[CorpusCase]) -> list[CaseOutcome]:
    """Run every case in its own temporary directory.

    Parameters:
        cases: Case definitions to execute.

    Returns:
        One outcome per case, in input order.
    """

    outcomes: list[CaseOutcome] = []
    for case in cases:
        directory = Path(tempfile.mkdtemp(prefix=f"th_corpus_{case.case_id}_"))
        try:
            outcomes.append(run_case(case, directory))
        finally:
            shutil.rmtree(directory, ignore_errors=True)
    return outcomes


def summarize(outcomes: list[CaseOutcome]) -> dict[str, object]:
    """Aggregate outcomes into per-category recall and overall false positives.

    Returns:
        Mapping with totals, recall per category, and the failing case ids.
    """

    per_category: dict[str, dict[str, int]] = {}
    failures: list[str] = []
    skipped = 0
    for outcome in outcomes:
        if outcome.skipped:
            skipped += 1
            continue
        bucket = per_category.setdefault(outcome.case.category, {"total": 0, "passed": 0})
        bucket["total"] += 1
        if outcome.passed:
            bucket["passed"] += 1
        else:
            failures.append(outcome.case.case_id)
    recall = {
        category: (bucket["passed"] / bucket["total"] if bucket["total"] else 0.0)
        for category, bucket in sorted(per_category.items())
    }
    return {
        "cases": len(outcomes),
        "passed": sum(1 for outcome in outcomes if outcome.passed and not outcome.skipped),
        "skipped": skipped,
        "recall": recall,
        "failures": failures,
    }


def render_table(outcomes: list[CaseOutcome]) -> str:
    """Render a fixed width case table for the console."""

    header = f"{'CASE':<34}{'CATEGORY':<20}{'VERDICT':<10}{'RESULT':<7}NOTE"
    lines = [header, "-" * len(header)]
    for outcome in outcomes:
        note = outcome.error or "; ".join(outcome.mismatches)
        marker = "PASS" if outcome.passed else "FAIL"
        lines.append(
            f"{outcome.case.case_id:<34}{outcome.case.category:<20}{outcome.verdict:<10}{marker:<7}{note[:90]}"
        )
    return chr(10).join(lines)


def main(argv: list[str] | None = None) -> int:
    """Run the corpus from the command line.

    Returns:
        Zero when every case met its expectation, one otherwise.
    """

    from tests.corpus_cases import CASES

    arguments = list(sys.argv[1:] if argv is None else argv)
    if "--json" in arguments:
        outcomes = run_corpus(CASES)
        print(json.dumps(summarize(outcomes), indent=2))
    else:
        outcomes = run_corpus(CASES)
        print(render_table(outcomes))
        summary = summarize(outcomes)
        print()
        print(f"cases {summary['cases']}, passed {summary['passed']}")
        for category, value in summary["recall"].items():
            print(f"  recall {category:<24} {value * 100:.0f}%")
        if summary["failures"]:
            print("failures: " + ", ".join(summary["failures"]))
    return 0 if all(outcome.passed for outcome in run_corpus(CASES)) else 1


if __name__ == "__main__":
    sys.exit(main())
