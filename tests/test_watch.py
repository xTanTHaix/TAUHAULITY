"""Watch loop integration tests for the per-directory canary farm.

The farm is only useful if the running watcher reports it: these tests drive a
real watch loop against a fixture that has decoys armed, mutate one decoy, and
assert the event surfaces with the decoy path and the active backend named in
the detail. A negative control drives legitimate bulk writes through the same
loop and asserts no farm event is produced.
"""

from __future__ import annotations

import threading
import time
from pathlib import Path

import pytest

import tauhaulity.daemon.canary as canary
import tauhaulity.daemon.watch as watch


def _tree(root: Path) -> Path:
    for sub in ("src", "docs", "data"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    (root / "src" / "app.py").write_text("print('app')" + chr(10), encoding="utf-8")
    (root / "docs" / "readme.md").write_text("# docs" + chr(10), encoding="utf-8")
    (root / "data" / "values.txt").write_text("value" + chr(10), encoding="utf-8")
    (root / "notes.md").write_text("# project" + chr(10), encoding="utf-8")
    return root


def _wait_for(predicate, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return False


def _run_watch(root: Path, **kwargs):
    events: list[watch.WatchEvent] = []
    errors: list[BaseException] = []
    stop = threading.Event()
    backends: list[str] = []

    def run() -> None:
        try:
            watch.watch_loop(
                root,
                stop=stop,
                on_event=events.append,
                on_backend=backends.append,
                **kwargs,
            )
        except BaseException as exc:  # surface a loop crash instead of hiding it
            errors.append(exc)

    thread = threading.Thread(target=run, name="tauhaulity-farm-watch")
    thread.start()
    return thread, events, errors, stop, backends


def test_watch_reports_a_farm_decoy_change(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    report = canary.deploy_canary_farm(root)
    target = report.deployed[0]
    thread, events, errors, stop, backends = _run_watch(root, interval_s=0.05)
    try:
        time.sleep(0.25)  # arm the baseline and start the backend reader
        (root / target.rel_path).write_text("attacker rewrite" + chr(10), encoding="utf-8")
        assert _wait_for(lambda: any(event.path == target.rel_path for event in events)), (
            "no watch event for " + target.rel_path
        )
    finally:
        stop.set()
        thread.join(5)
    assert errors == []
    assert backends == [watch.watch_backend_name("auto")]
    matching = [event for event in events if event.path == target.rel_path]
    assert matching
    assert matching[0].kind == watch.CANARY_KIND
    assert "backend=" in matching[0].detail


def test_polling_watch_reports_the_farm_event_kind(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    report = canary.deploy_canary_farm(root)
    target = report.deployed[0]
    thread, events, errors, stop, backends = _run_watch(
        root, interval_s=0.05, backend="polling"
    )
    try:
        time.sleep(0.2)
        (root / target.rel_path).write_text("attacker rewrite" + chr(10), encoding="utf-8")
        assert _wait_for(
            lambda: any(
                event.path == target.rel_path and "canary_modified" in event.detail
                for event in events
            )
        ), "polling watch did not report canary_modified for " + target.rel_path
    finally:
        stop.set()
        thread.join(5)
    assert errors == []
    assert backends == [watch.POLLING_BACKEND_NAME]


def test_farm_decoy_deletion_is_reported_by_the_watch_loop(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    report = canary.deploy_canary_farm(root)
    target = report.deployed[1]
    thread, events, errors, stop, backends = _run_watch(
        root, interval_s=0.05, backend="polling"
    )
    try:
        time.sleep(0.2)
        (root / target.rel_path).unlink()
        assert _wait_for(
            lambda: any(
                event.path == target.rel_path and "canary_deleted" in event.detail
                for event in events
            )
        ), "polling watch did not report canary_deleted for " + target.rel_path
    finally:
        stop.set()
        thread.join(5)
    assert errors == []


def test_watch_ignores_legitimate_bulk_writes(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    canary.deploy_canary_farm(root)
    thread, events, errors, stop, backends = _run_watch(
        root, interval_s=0.05, backend="polling"
    )
    try:
        time.sleep(0.2)
        for index in range(120):
            directory = [root / "src", root / "docs", root / "data"][index % 3]
            (directory / ("generated_%03d.txt" % index)).write_text(
                "generated text " + str(index) + chr(10), encoding="utf-8"
            )
        time.sleep(0.5)
    finally:
        stop.set()
        thread.join(5)
    assert errors == []
    farm_events = [event for event in events if event.kind == watch.CANARY_KIND]
    assert farm_events == [], "legitimate bulk writes surfaced canary events: " + str(farm_events)


def test_legacy_canary_still_works_with_a_farm_armed(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    (root / "canary.txt").write_text("legacy decoy" + chr(10), encoding="utf-8")
    report = canary.deploy_canary_farm(root)
    watcher = canary.CanaryWatcher(root)
    watcher.snapshot()
    assert watcher.farm_count == report.count
    assert watcher.watched_count >= report.count + 1
    (root / "canary.txt").write_text("legacy tampered" + chr(10), encoding="utf-8")
    target = report.deployed[0]
    (root / target.rel_path).write_text("farm tampered" + chr(10), encoding="utf-8")
    events = watcher.scan()
    legacy = [event for event in events if event.path == "canary.txt"]
    farm = [event for event in events if event.path == target.rel_path]
    assert legacy and legacy[0].kind == "modified"
    assert farm and farm[0].kind == "canary_modified"


def test_farm_decoys_are_watch_candidates(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    report = canary.deploy_canary_farm(root)
    watcher = canary.CanaryWatcher(root)
    candidates = {path.relative_to(root).as_posix() for path in watcher.candidates()}
    for record in report.deployed:
        assert record.rel_path in candidates


def test_watch_stop_is_prompt_with_a_farm_armed(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    canary.deploy_canary_farm(root)
    stop = threading.Event()
    started = time.perf_counter()
    thread = threading.Thread(
        target=lambda: watch.watch_loop(root, interval_s=0.1, stop=stop),
        name="tauhaulity-farm-stop",
    )
    thread.start()
    time.sleep(0.2)
    stop.set()
    thread.join(3.0)
    assert not thread.is_alive()
    assert time.perf_counter() - started < 1.5
