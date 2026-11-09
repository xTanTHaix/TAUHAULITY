"""Slow resilience tests, excluded from the default run with -m slow.

The default suite must stay fast enough to run on every save; this module keeps
the long running pressure checks available for a release verification pass.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from tauhaulity.core.contracts import ScanOptions
from tauhaulity.core.entropy import shannon_entropy
from tauhaulity.core.spsc import SpscRing
from tauhaulity.core.telemetry import TelemetryFrame
from tauhaulity.engine import run_scan

pytestmark = pytest.mark.slow


def test_repeated_frames_stay_valid_under_load() -> None:
    frame = TelemetryFrame(pid=os.getpid(), tid=1)
    for index in range(20_000):
        frame.seqlock = index * 2
        frame.monotonic_ns = index
        payload = frame.to_bytes()
        restored = TelemetryFrame.from_bytes(payload)
        assert restored.pid == frame.pid
        assert restored.monotonic_ns == index


def test_spsc_ring_sustains_backpressure() -> None:
    ring = SpscRing(capacity=1024, slot_bytes=64)
    produced = 0
    consumed = 0
    for index in range(20_000):
        if ring.put(index.to_bytes(8, "little")):
            produced += 1
        item = ring.get()
        if item is not None:
            consumed += 1
    while ring.get() is not None:
        consumed += 1
    assert produced > 0
    assert consumed == produced


def test_entropy_throughput_is_stable() -> None:
    payload = os.urandom(512 * 1024)
    started = time.perf_counter()
    for _ in range(20):
        value = shannon_entropy(payload)
        assert 7.0 <= value <= 8.0
    elapsed = time.perf_counter() - started
    assert elapsed < 30.0


def test_repeated_scans_keep_findings_stable(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("VALUE = 1" + chr(10), encoding="utf-8")
    options = ScanOptions(generate_repro=False, record_telemetry=False)
    baseline = None
    for _ in range(25):
        result = run_scan(root, options=options, write_reports=False)
        snapshot = {number: (finding.status, finding.risk) for number, finding in result.ctx.findings.items()}
        if baseline is None:
            baseline = snapshot
        else:
            assert snapshot == baseline
