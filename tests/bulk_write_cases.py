"""Benign bulk-write corpus: the honest false-positive measurement.

Every detector added in 0.4.0 is judged by one number: how often it fires on a
legitimate heavy operation. This module builds real project trees and performs
the operations a developer actually runs (a build wave, a package install, an
archive extraction, a checkout-like rewrite) with the runtime guard armed, then
measures the burst detector, the entropy radar and canary events.

The burst tracker learns suffixes during a five second warm-up, so each case that
exercises rename volume first performs a small calm phase and then waits out the
warm-up before the heavy operation. That is also how the numbers stay honest: the
heavy operation really does cross the volume threshold, so a zero verdict means
the shape (not the silence) kept the detector quiet.

Run it with:  python -m pytest tests/test_bulk_write_fp.py -m slow -q -s
"""

from __future__ import annotations

import importlib
import os
import random
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

#: Slightly above the default five second burst window, so the heavy phase runs
#: after the tracker's warm-up instead of inside it.
WARMUP_SECONDS = 5.2

#: Fixed seed so the archive case is reproducible byte for byte.
RANDOM_SEED = 20260101

NEWLINE = chr(10)


@dataclass(frozen=True, slots=True)
class BulkCase:
    """One legitimate bulk operation measured against the detectors.

    Attributes:
        case_id: Stable kebab-case identifier.
        description: What legitimate operation the case simulates.
        requires: Phase identifiers whose modules the full assertion needs.
        builder: Callable that performs the operation and returns measurements.
        exercise_burst: True when the case crosses the destructive volume
            threshold, so a zero verdict is meaningful rather than silence.
        exercise_radar: True when the case leaves a file large enough for the
            entropy radar to inspect, so a zero alert count is meaningful.
    """

    case_id: str
    description: str
    requires: tuple[str, ...]
    builder: Callable[[Path], dict]
    exercise_burst: bool = False
    exercise_radar: bool = False


def _rng() -> random.Random:
    """Return the fixed seed generator used by the archive case."""

    return random.Random(RANDOM_SEED)


def _touch(path: Path, payload: str = "") -> None:
    """Write a small UTF-8 file, creating parents as needed."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(payload, encoding="utf-8")


def _calm_suffixes(root: Path, suffixes: tuple[str, ...]) -> None:
    """Create and rename a few files so the tracker learns real suffixes.

    This is the shape of a process that has been running normally before the heavy
    operation starts: the suffixes it uses already exist in the tree.
    """

    calm = root / "calm"
    calm.mkdir(parents=True, exist_ok=True)
    for index, suffix in enumerate(suffixes):
        source = calm / ("seed%d.tmp" % index)
        source.write_text("calm" + NEWLINE, encoding="utf-8")
        os.replace(source, calm / ("seed%d%s" % (index, suffix)))


def _wait_out_warmup() -> None:
    """Wait until the burst tracker's warm-up window has elapsed."""

    time.sleep(WARMUP_SECONDS)


def _build_shape(root: Path) -> dict:
    """A build wave: 5,000 files created, renamed and deleted with known suffixes."""

    _calm_suffixes(root, (".py", ".o", ".tmp"))
    _wait_out_warmup()
    target = root / "build" / "objects"
    target.mkdir(parents=True, exist_ok=True)
    # A real build leaves a captured log at the project root (build/ itself is in
    # the radar's skip list); it is large enough for the entropy radar to inspect,
    # and its low entropy must not look like ciphertext.
    _touch(root / "build-output.log", ("compiled unit successfully" + NEWLINE) * 160)
    started = time.perf_counter()
    created = renamed = deleted = 0
    for index in range(5000):
        source = target / ("unit%05d.tmp" % index)
        source.write_text("object " + str(index) + NEWLINE, encoding="utf-8")
        created += 1
        destination = target / ("unit%05d.py" % index)
        os.replace(source, destination)
        renamed += 1
        if index % 2 == 0:
            destination.unlink()
            deleted += 1
    return {
        "operation_s": round(time.perf_counter() - started, 3),
        "warmup_s": WARMUP_SECONDS,
        "files_created": created,
        "files_renamed": renamed,
        "files_deleted": deleted,
    }


def _install_shape(root: Path) -> dict:
    """A dependency install: 2,000 files written and 200 temp files renamed."""

    _calm_suffixes(root, (".py",))
    _wait_out_warmup()
    site = root / ".venv" / "lib" / "python3.12" / "site-packages"
    started = time.perf_counter()
    created = 0
    for index in range(2000):
        package = site / ("pkg%03d" % (index % 40))
        _touch(package / ("mod%04d.py" % index), "VALUE = " + str(index) + NEWLINE)
        created += 1
    renamed = 0
    for index in range(200):
        source = site / ("tmp%03d.tmp" % index)
        source.write_text("temporary" + NEWLINE, encoding="utf-8")
        os.replace(source, site / ("final%03d.py" % index))
        renamed += 1
    return {
        "operation_s": round(time.perf_counter() - started, 3),
        "warmup_s": WARMUP_SECONDS,
        "files_created": created,
        "files_renamed": renamed,
        "files_deleted": 0,
    }


def _archive_shape(root: Path) -> dict:
    """An archive extraction: 500 high-entropy photo files unzipped."""

    archive = root / "dist" / "assets.zip"
    archive.parent.mkdir(parents=True, exist_ok=True)
    generator = _rng()
    started = time.perf_counter()
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as handle:
        for index in range(500):
            handle.writestr(
                "assets/photo%03d.jpg" % index, generator.randbytes(4096)
            )
    unpacked = root / "dist" / "unpacked"
    with zipfile.ZipFile(archive) as handle:
        handle.extractall(unpacked)
    written = sum(1 for path in unpacked.rglob("*") if path.is_file())
    return {
        "operation_s": round(time.perf_counter() - started, 3),
        "warmup_s": 0.0,
        "files_created": written,
        "files_renamed": 0,
        "files_deleted": 0,
        "archive_entries": 500,
    }


def _gitish_shape(root: Path) -> dict:
    """A checkout-like rewrite: 1,000 tracked files replaced through temp files."""

    _calm_suffixes(root, (".py",))
    worktree = root / "worktree"
    worktree.mkdir(parents=True, exist_ok=True)
    for index in range(1000):
        _touch(worktree / ("module%04d.py" % index), "ORIGINAL = " + str(index) + NEWLINE)
    _touch(worktree / "NOTES.md", ("release notes for the checkout" + NEWLINE) * 120)
    _wait_out_warmup()
    started = time.perf_counter()
    rewritten = 0
    for index in range(1000):
        temporary = worktree / ("module%04d.py.tmp" % index)
        _touch(temporary, "REWRITTEN = " + str(index) + NEWLINE)
        os.replace(temporary, worktree / ("module%04d.py" % index))
        rewritten += 1
    return {
        "operation_s": round(time.perf_counter() - started, 3),
        "warmup_s": WARMUP_SECONDS,
        "files_created": 1000,
        "files_renamed": rewritten,
        "files_deleted": 0,
    }


def _canary_shape(root: Path) -> dict:
    """A legitimate canary-named file the user really created."""

    started = time.perf_counter()
    _touch(root / "canary.txt", "the team writes this file on purpose" + NEWLINE)
    _touch(root / "decoy_notes.txt", "a human named this file by hand" + NEWLINE)
    return {
        "operation_s": round(time.perf_counter() - started, 3),
        "warmup_s": 0.0,
        "files_created": 2,
        "files_renamed": 0,
        "files_deleted": 0,
    }


CASES: tuple[BulkCase, ...] = (
    BulkCase(
        case_id="build-wave",
        description="build: 5,000 files created, renamed and deleted with known suffixes",
        requires=("0.4.0-A",),
        builder=_build_shape,
        exercise_burst=True,
        exercise_radar=True,
    ),
    BulkCase(
        case_id="install-wave",
        description="install: 2,000 site-packages files written, 200 temp files renamed",
        requires=("0.4.0-A",),
        builder=_install_shape,
        exercise_burst=True,
    ),
    BulkCase(
        case_id="archive-extract",
        description="archive: 500 high-entropy photo files unzipped",
        requires=("0.4.0-A",),
        builder=_archive_shape,
    ),
    BulkCase(
        case_id="checkout-rewrite",
        description="checkout: 1,000 tracked files rewritten through temp files",
        requires=("0.4.0-A",),
        builder=_gitish_shape,
        exercise_burst=True,
        exercise_radar=True,
    ),
    BulkCase(
        case_id="legitimate-canary-name",
        description="canary: a canary-named file the user created on purpose",
        requires=("0.4.0-B",),
        builder=_canary_shape,
    ),
)

CASE_BY_ID: dict[str, BulkCase] = {case.case_id: case for case in CASES}


def _canary_farm_module() -> object | None:
    """Return the canary farm module when phase 0.4.0-B has landed, else None."""

    for name in (
        "tauhaulity.daemon.canary_farm",
        "tauhaulity.daemon.farm",
        "tauhaulity.daemon.canary",
    ):
        try:
            module = importlib.import_module(name)
        except ImportError:
            continue
        if hasattr(module, "deploy_canary_farm") and hasattr(module, "load_canary_farm"):
            return module
    return None


def canary_farm_available() -> bool:
    """True when the canary farm API from phase 0.4.0-B is importable."""

    return _canary_farm_module() is not None


def available_features() -> dict[str, bool]:
    """Return which sibling phase APIs are available on this tree."""

    burst = False
    try:
        from tauhaulity.runtime import audit_hook

        burst = "burst_verdicts" in audit_hook.stats()
    except (ImportError, AttributeError, OSError, RuntimeError, ValueError):
        burst = False
    return {
        "0.4.0-A": bool(burst),
        "0.4.0-B": canary_farm_available(),
    }


def run_case(case: BulkCase, root: Path) -> dict:
    """Perform one legitimate bulk operation and measure every detector counter.

    The guard must already be armed by the caller; this function performs the
    operation, then reads the burst counters, samples the entropy radar and
    takes a canary snapshot so a false alarm cannot hide in any of the three.

    Parameters:
        case: Case to run.
        root: Project tree to build inside.

    Returns:
        A JSON friendly measurement dictionary.
    """

    root = Path(root)
    builder_started = time.perf_counter()
    measured = case.builder(root)
    total_s = time.perf_counter() - builder_started

    # Arm the canary farm on the populated tree when phase 0.4.0-B is present, so
    # the analysis below measures the farm itself and not an empty tree. The farm
    # only plants decoys in directories that hold real files, which is why this
    # runs after the legitimate operation populated them.
    farm_module = _canary_farm_module()
    farm_deployed = 0
    farm_includes_user_file = False
    if farm_module is not None:
        try:
            farm_report = farm_module.deploy_canary_farm(root)
            farm_deployed = int(farm_report.count)
            farm_records = farm_module.load_canary_farm(root)
            farm_includes_user_file = any(
                record.rel_path == "canary.txt" for record in farm_records
            )
        except (OSError, RuntimeError, ValueError):
            farm_deployed = 0

    from tauhaulity.daemon.canary import CanaryWatcher
    from tauhaulity.daemon.entropy_radar import scan_with_budget
    from tauhaulity.runtime import audit_hook

    stats = audit_hook.stats()
    summary: dict = {}
    try:
        summary = dict(audit_hook.guard.burst_summary())
    except (AttributeError, OSError, RuntimeError, ValueError):
        summary = {}
    destructive_names = (
        "os.rename",
        "os.replace",
        "os.remove",
        "os.unlink",
        "os.rmdir",
        "os.mkdir",
    )
    counts = stats.get("counts", {})
    destructive_events = sum(int(counts.get(name, 0) or 0) for name in destructive_names)
    radar = scan_with_budget(root, max_files=512)
    watcher = CanaryWatcher(root)
    watcher.snapshot()
    canary_events = watcher.scan()
    # Farm tamper events use the canary_* vocabulary; legacy canary events use
    # created/modified/deleted/encrypted. Split them so the report can attribute a
    # false alarm to the right detector.
    farm_events = [
        event for event in canary_events if str(event.kind).startswith("canary_")
    ]

    return {
        "case_id": case.case_id,
        "description": case.description,
        "requires": list(case.requires),
        "measured": measured,
        "total_s": round(total_s, 3),
        "exercise_burst": bool(case.exercise_burst),
        "exercise_radar": bool(case.exercise_radar),
        "destructive_events": destructive_events,
        "burst_verdicts": int(stats.get("burst_verdicts", 0)),
        "burst_events": int(stats.get("burst_events", 0)),
        "burst_tracker_size": int(stats.get("burst_tracker_size", 0)),
        "burst_window_s": float(summary.get("window_s", 0.0) or 0.0),
        "burst_threshold": int(summary.get("threshold", 0) or 0),
        "known_suffixes": list(summary.get("known_suffixes", [])),
        "last_burst": summary.get("last_verdict"),
        "entropy_alerts": len(radar.alerts),
        "entropy_files": int(radar.files_inspected),
        "entropy_bytes": int(radar.bytes_inspected),
        "canary_events": len(canary_events),
        "canary_watched": int(watcher.watched_count),
        "canary_farm_available": farm_module is not None,
        "canary_farm_deployed": farm_deployed,
        "canary_farm_events": len(farm_events),
        "canary_farm_includes_user_file": farm_includes_user_file,
        "features": available_features(),
    }
