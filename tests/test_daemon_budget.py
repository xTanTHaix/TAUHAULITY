"""Tests for the bounded radar and canary scan budgets.

The performance guard exists because the pure Python Shannon estimator is slow,
so these tests assert the bound itself: a scan never reads more than its byte
budget, it stops early instead of walking a large tree, and the canary snapshot is
capped by file count and per file read size.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

import tauhaulity.daemon.entropy_radar as radar
from tauhaulity.daemon.canary import (
    MAX_CANARY_CANDIDATES,
    MAX_CANARY_READ_BYTES,
    MAX_CANARY_SNAPSHOT_BYTES,
    CanaryWatcher,
    _fingerprint,
)

RANDOM = os.urandom


def _random_files(root: Path, count: int, size: int = 4096) -> list[Path]:
    root.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for index in range(count):
        path = root / ("cipher" + str(index) + ".dat2")
        path.write_bytes(RANDOM(size))
        paths.append(path)
    return paths


def test_default_budget_is_32_mib() -> None:
    assert radar.DEFAULT_MAX_TOTAL_BYTES == 32 * 1024 * 1024


def test_budget_stops_the_scan_and_is_reported(tmp_path: Path) -> None:
    _random_files(tmp_path, 8)
    report = radar.scan_with_budget(tmp_path, max_total_bytes=9000, max_files=64)
    assert report.exhausted is True
    assert report.bytes_inspected <= 9000
    assert report.files_inspected < 8
    assert report.max_total_bytes == 9000
    assert report.detail.startswith("inspected ")
    assert "of a 9000 byte budget" in report.detail
    assert "budget exhausted" in report.detail
    assert report.alerts


def test_read_requests_never_exceed_the_remaining_budget(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _random_files(tmp_path, 6)
    original = radar._read_sample
    requests: list[int] = []
    consumed = {"bytes": 0}

    def spy(path: Path, limit: int = radar.MAX_FILE_BYTES) -> bytes:
        requests.append(limit)
        payload = original(path, limit)
        consumed["bytes"] += len(payload)
        return payload

    monkeypatch.setattr(radar, "_read_sample", spy)
    report = radar.scan_with_budget(tmp_path, max_total_bytes=9000, max_files=64)
    assert requests
    assert all(limit <= 9000 for limit in requests)
    assert consumed["bytes"] == report.bytes_inspected <= 9000


def test_scan_within_budget_is_not_truncated(tmp_path: Path) -> None:
    _random_files(tmp_path, 3)
    report = radar.scan_with_budget(tmp_path, max_total_bytes=1024 * 1024, max_files=64)
    assert report.exhausted is False
    assert report.files_inspected == 3
    assert report.bytes_inspected == 3 * 4096
    assert len(report.alerts) == 3
    assert "budget exhausted" not in report.detail
    assert "3 file(s)" in report.detail


def test_scan_for_ransomware_forwards_the_budget(tmp_path: Path) -> None:
    _random_files(tmp_path, 6)
    alerts = radar.scan_for_ransomware(tmp_path, max_total_bytes=4096, max_files=64)
    assert isinstance(alerts, list)
    assert len(alerts) == 1


def test_large_tree_with_a_small_budget_is_fast(tmp_path: Path) -> None:
    root = tmp_path / "large"
    root.mkdir()
    for index in range(40):
        (root / ("big" + str(index) + ".dat2")).write_bytes(b"\x00" * 65536)
    started = time.perf_counter()
    report = radar.scan_with_budget(root, max_total_bytes=64 * 1024, max_files=512)
    elapsed = time.perf_counter() - started
    assert report.exhausted is True
    assert report.bytes_inspected <= 64 * 1024
    assert report.files_inspected == 1
    assert elapsed < 5.0


def test_budget_validation(tmp_path: Path) -> None:
    for value in (0, -1, True):
        with pytest.raises(ValueError):
            radar.scan_with_budget(tmp_path, max_total_bytes=value)
        with pytest.raises(ValueError):
            radar.scan_for_ransomware(tmp_path, max_total_bytes=value)


def test_canary_discovery_is_bounded_by_the_file_cap(tmp_path: Path) -> None:
    for index in range(40):
        (tmp_path / ("canary" + str(index).zfill(2) + ".txt")).write_text(
            "trap" + chr(10), encoding="utf-8"
        )
    watcher = CanaryWatcher(tmp_path)
    candidates = watcher.candidates()
    assert len(candidates) == MAX_CANARY_CANDIDATES
    watcher.snapshot()
    assert watcher.watched_count == MAX_CANARY_CANDIDATES


def test_canary_snapshot_byte_bound_is_a_constant() -> None:
    assert MAX_CANARY_READ_BYTES == 64 * 1024
    assert MAX_CANARY_SNAPSHOT_BYTES == MAX_CANARY_CANDIDATES * MAX_CANARY_READ_BYTES


def test_canary_fingerprint_reads_only_the_bounded_prefix(tmp_path: Path) -> None:
    path = tmp_path / "canary.bin"
    path.write_bytes(b"A" * (MAX_CANARY_READ_BYTES + 4096))
    state = _fingerprint(path)
    assert state.exists is True
    assert state.size == MAX_CANARY_READ_BYTES
