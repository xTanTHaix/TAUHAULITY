"""Reproducible micro benchmark suite for the Tauhaulity command surface.

The README quotes latency numbers, so they must come from a repeatable harness
instead of a one-off stopwatch. Every measurement below is a real call into the
shipped code paths, with reports written to a temporary directory and telemetry
disabled so a benchmark never mutates the project it measures.
"""

from __future__ import annotations

import json
import os
import statistics
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

MIB = 1024 * 1024


@dataclass(frozen=True, slots=True)
class BenchResult:
    """One measured operation.

    Attributes:
        name: Human readable operation name.
        runs: Number of repetitions behind the statistics.
        best_ms: Fastest run in milliseconds.
        median_ms: Median run in milliseconds.
        worst_ms: Slowest run in milliseconds.
        note: Secondary metric such as throughput or resolved backend.
    """

    name: str
    runs: int
    best_ms: float
    median_ms: float
    worst_ms: float
    note: str = ""

    def as_dict(self) -> dict[str, object]:
        """Return a JSON friendly representation."""

        return {
            "name": self.name,
            "runs": self.runs,
            "best_ms": round(self.best_ms, 2),
            "median_ms": round(self.median_ms, 2),
            "worst_ms": round(self.worst_ms, 2),
            "note": self.note,
        }


def _measure(name: str, call: Callable[[], object], runs: int, note: str = "") -> tuple[BenchResult, object]:
    """Run one callable repeatedly and summarize the wall clock samples.

    Parameters:
        name: Operation label for the table.
        call: Zero argument callable performing the work.
        runs: Repetition count; the first sample is discarded as warm up.
        note: Static note appended to the result.

    Returns:
        The BenchResult plus the last callable return value.
    """

    samples: list[float] = []
    value: object = None
    for _ in range(max(1, runs) + 1):
        start = time.perf_counter()
        value = call()
        samples.append((time.perf_counter() - start) * 1000.0)
    measured = samples[1:] if len(samples) > 1 else samples
    result = BenchResult(
        name=name,
        runs=len(measured),
        best_ms=min(measured),
        median_ms=statistics.median(measured),
        worst_ms=max(measured),
        note=note,
    )
    return result, value


def run_benchmarks(root: Path, *, runs: int = 3) -> list[BenchResult]:
    """Measure the primary command paths on the given project root.

    Parameters:
        root: Existing project directory to scan. It is never modified.
        runs: Repetitions per measurement, clamped to the range one through ten.

    Returns:
        BenchResult rows in presentation order.

    Raises:
        FileNotFoundError: When the target directory does not exist.
    """

    target = Path(root).resolve()
    if not target.is_dir():
        raise FileNotFoundError(f"benchmark target is not a directory: {target}")
    repetitions = max(1, min(int(runs), 10))

    from tauhaulity.core.contracts import ScanOptions
    from tauhaulity.doctor import run_doctor
    from tauhaulity.engine import run_scan
    from tauhaulity.primitives.loader import get_engine

    results: list[BenchResult] = []
    scan_options = ScanOptions(generate_repro=False, record_telemetry=False)

    result, _ = _measure(
        "scan (12 pillars, no reports)",
        lambda: run_scan(target, options=scan_options, write_reports=False),
        repetitions,
    )
    results.append(result)

    with tempfile.TemporaryDirectory(prefix="tauhaulity_bench_") as out_dir:
        result, _ = _measure(
            "scan + dossier (md, txt, json)",
            lambda: run_scan(target, options=scan_options, write_reports=True, out_dir=out_dir),
            repetitions,
        )
        results.append(result)

    result, _ = _measure("doctor self-check", lambda: run_doctor(target), repetitions)
    results.append(result)

    engine = get_engine()
    payload = os.urandom(4 * MIB)
    result, _ = _measure(
        "engine.sha256 (4 MiB)",
        lambda: engine.sha256(payload),
        repetitions,
        note=f"{engine.backend} tier",
    )
    results.append(_with_throughput(result, len(payload)))

    result, _ = _measure(
        "engine.shannon (4 MiB)",
        lambda: engine.shannon(payload),
        repetitions,
        note=f"{engine.backend} tier",
    )
    results.append(_with_throughput(result, len(payload)))

    from tauhaulity.tools.git_sentinel import scan_text

    sample = "token=ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" + chr(10)
    result, _ = _measure(
        "git sentinel scan_text (8 KiB blob)",
        lambda: scan_text(sample * 200, "bench.py"),
        repetitions,
    )
    results.append(result)
    return results


def _with_throughput(result: BenchResult, size_bytes: int) -> BenchResult:
    """Annotate a hashing result with a MiB/s figure derived from the median."""

    seconds = result.median_ms / 1000.0
    throughput = (size_bytes / MIB) / seconds if seconds > 0 else 0.0
    note = f"{throughput:.0f} MiB/s, {result.note}".strip(", ")
    return BenchResult(
        name=result.name,
        runs=result.runs,
        best_ms=result.best_ms,
        median_ms=result.median_ms,
        worst_ms=result.worst_ms,
        note=note,
    )


def render_table(results: list[BenchResult]) -> str:
    """Render benchmark rows as a fixed width plain text table."""

    header = f"{'OPERATION':<42}{'RUNS':>5}{'BEST ms':>10}{'MEDIAN ms':>11}{'WORST ms':>10}  NOTE"
    lines = [header, "-" * len(header)]
    for row in results:
        lines.append(
            f"{row.name:<42}{row.runs:>5}{row.best_ms:>10.1f}{row.median_ms:>11.1f}{row.worst_ms:>10.1f}  {row.note}"
        )
    return chr(10).join(lines)


def render_json(results: list[BenchResult]) -> str:
    """Render benchmark rows as indented JSON."""

    return json.dumps([row.as_dict() for row in results], indent=2)
