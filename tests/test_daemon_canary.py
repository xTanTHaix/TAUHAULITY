"""Tests for the canary watcher and the I/O entropy radar.

The watcher is time based, so every timing test is bounded and polls until a
deadline instead of sleeping a fixed amount: a slow CI host must not turn a
correct implementation into a flaky failure.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from tauhaulity.daemon.canary import (
    ENCRYPTION_ENTROPY,
    CanaryEvent,
    CanaryWatcher,
)
from tauhaulity.daemon.entropy_radar import EntropyAlert, scan_for_ransomware, scan_with_budget


def _wait_for_events(watcher: CanaryWatcher, timeout: float = 3.0) -> list[CanaryEvent]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        events = watcher.drain()
        if events:
            return events
        time.sleep(0.01)
    return []


def test_snapshot_discovers_the_canary(sample_project: Path) -> None:
    watcher = CanaryWatcher(sample_project)
    watcher.snapshot()
    assert watcher.watched_count == 1
    assert [path.name for path in watcher.candidates()] == ["canary.txt"]


def test_scan_before_snapshot_is_empty(tmp_path: Path) -> None:
    watcher = CanaryWatcher(tmp_path)
    assert watcher.scan() == []
    assert watcher.watched_count == 0


def test_scan_detects_modified_canary(sample_project: Path) -> None:
    watcher = CanaryWatcher(sample_project)
    watcher.snapshot()
    (sample_project / "canary.txt").write_text("tampered\n", encoding="utf-8")
    events = watcher.scan()
    assert len(events) == 1
    event = events[0]
    assert isinstance(event, CanaryEvent)
    assert (event.path, event.kind) == ("canary.txt", "modified")
    assert isinstance(event.entropy, float)


def test_scan_detects_deleted_canary(sample_project: Path) -> None:
    watcher = CanaryWatcher(sample_project)
    watcher.snapshot()
    (sample_project / "canary.txt").unlink()
    events = watcher.scan()
    assert [event.kind for event in events] == ["deleted"]
    assert events[0].path == "canary.txt"


def test_scan_detects_created_canary(sample_project: Path) -> None:
    watcher = CanaryWatcher(sample_project)
    watcher.snapshot()
    (sample_project / "extra.canary").write_text("new trap", encoding="utf-8")
    events = watcher.scan()
    assert [event.kind for event in events] == ["created"]
    assert events[0].path == "extra.canary"


def test_scan_detects_an_encryption_entropy_jump(sample_project: Path) -> None:
    watcher = CanaryWatcher(sample_project)
    watcher.snapshot()
    (sample_project / "canary.txt").write_bytes(os.urandom(4096))
    events = watcher.scan()
    assert len(events) == 1
    assert events[0].kind == "encrypted"
    assert events[0].entropy >= ENCRYPTION_ENTROPY
    assert "entropy rose" in events[0].detail


def test_scan_is_quiet_when_nothing_changed(sample_project: Path) -> None:
    watcher = CanaryWatcher(sample_project)
    watcher.snapshot()
    assert watcher.scan() == []


def test_explicit_paths_override_discovery(tmp_path: Path) -> None:
    trap = tmp_path / "trap.txt"
    trap.write_text("watched", encoding="utf-8")
    watcher = CanaryWatcher(tmp_path, paths=[trap])
    watcher.snapshot()
    assert watcher.watched_count == 1
    assert watcher.candidates() == [trap]


def test_watch_once_arms_then_reports(sample_project: Path) -> None:
    watcher = CanaryWatcher(sample_project, interval_ms=10)
    assert watcher.watch_once() == []
    (sample_project / "canary.txt").write_text("changed\n", encoding="utf-8")
    assert [event.kind for event in watcher.watch_once()] == ["modified"]


def test_watcher_rejects_a_bad_interval(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        CanaryWatcher(tmp_path, interval_ms=0)


def test_background_thread_reports_tampering(sample_project: Path) -> None:
    watcher = CanaryWatcher(sample_project, interval_ms=10)
    watcher.start()
    try:
        assert watcher.running is True
        (sample_project / "canary.txt").write_text("ransom note", encoding="utf-8")
        events = _wait_for_events(watcher)
        assert events
        assert events[0].kind in {"modified", "encrypted"}
    finally:
        watcher.stop()
    assert watcher.running is False


def test_start_is_idempotent(sample_project: Path) -> None:
    watcher = CanaryWatcher(sample_project, interval_ms=10)
    watcher.start()
    try:
        watcher.start()
        assert watcher.running is True
    finally:
        watcher.stop()


def test_scan_for_ransomware_flags_random_bytes(tmp_path: Path) -> None:
    target = tmp_path / "cipher.bin2"
    target.write_bytes(os.urandom(8192))
    alerts = scan_for_ransomware(tmp_path, max_files=8)
    assert len(alerts) == 1
    alert = alerts[0]
    assert isinstance(alert, EntropyAlert)
    assert alert.rel_path == "cipher.bin2"
    assert alert.entropy >= 7.2
    assert alert.size == 8192
    assert "block(s) above" in alert.detail


def test_scan_for_ransomware_ignores_text(tmp_path: Path) -> None:
    (tmp_path / "notes.txt").write_text(
        "plain words and punctuation. " * 200, encoding="utf-8"
    )
    assert scan_for_ransomware(tmp_path, max_files=8) == []


def test_scan_for_ransomware_skips_compressed_formats(tmp_path: Path) -> None:
    (tmp_path / "photo.png").write_bytes(os.urandom(8192))
    (tmp_path / "archive.zip").write_bytes(os.urandom(8192))
    assert scan_for_ransomware(tmp_path, max_files=8) == []


def test_scan_for_ransomware_skips_small_files(tmp_path: Path) -> None:
    (tmp_path / "tiny.dat2").write_bytes(os.urandom(64))
    assert scan_for_ransomware(tmp_path, max_files=8) == []


def test_scan_for_ransomware_respects_the_file_budget(tmp_path: Path) -> None:
    for index in range(4):
        (tmp_path / ("cipher" + str(index) + ".dat2")).write_bytes(os.urandom(4096))
    unlimited = scan_for_ransomware(tmp_path, max_files=8)
    limited = scan_for_ransomware(tmp_path, max_files=1)
    assert len(unlimited) == 4
    assert len(limited) == 1


def test_scan_for_ransomware_validates_arguments(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        scan_for_ransomware(tmp_path, block_size=0)
    with pytest.raises(ValueError):
        scan_for_ransomware(tmp_path, threshold=9.0)
    with pytest.raises(ValueError):
        scan_for_ransomware(tmp_path, max_files=0)


def test_scan_for_ransomware_on_a_missing_root(tmp_path: Path) -> None:
    assert scan_for_ransomware(tmp_path / "missing") == []


def test_scan_for_ransomware_ignores_the_undo_journal(tmp_path: Path) -> None:
    journal = tmp_path / ".tauhaulity" / "undo"
    journal.mkdir(parents=True)
    (journal / "blob.bin").write_bytes(os.urandom(8192))
    assert scan_for_ransomware(tmp_path, max_files=8) == []

def test_scan_ignores_provisioning_trees(tmp_path: Path) -> None:
    """A bundled interpreter tree must not consume the sampling budget.

    Provisioning directories sort before project sources and can hold tens of
    thousands of files, so without an explicit skip the radar would sample
    vendored interpreter payloads and never see project ciphertext. That failure
    is silent: the scan stays fast and reports zero alerts.
    """

    project = tmp_path / "projects"
    source = project / "src"
    source.mkdir(parents=True)
    (source / "notes.txt").write_text("ordinary project notes" + chr(10) * 20, encoding="utf-8")
    # A .txt file that is now random is exactly the artefact the radar exists
    # for; binary suffixes are skipped on purpose because they are random anyway.
    ciphertext = source / "encrypted.txt"
    ciphertext.write_bytes(os.urandom(64 * 1024))

    provisioning = tmp_path / ".tooling" / "pythons" / "cpython-3.12" / "Lib"
    provisioning.mkdir(parents=True)
    for index in range(700):
        (provisioning / f"vendor_{index:04d}.py").write_text("VALUE = " + str(index), encoding="utf-8")

    report = scan_with_budget(project, max_files=512)
    paths = [alert.rel_path.replace(chr(92), "/") for alert in report.alerts]
    assert "src/encrypted.txt" in paths, paths[:5]
    assert not any(path.startswith(".tooling/") for path in paths)
    assert report.files_inspected <= 512
