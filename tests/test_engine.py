"""Engine tests: target resolution, twelve findings, verdict and telemetry log."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tauhaulity.core.contracts import PILLAR_SPECS, ScanOptions
from tauhaulity.core.policy import Policy
from tauhaulity.engine import PROBE_FAILURE_RISK, ScanError, run_scan, resolve_target, summarize


def test_resolve_target_directory(tmp_path) -> None:
    assert resolve_target(tmp_path) == tmp_path.resolve()


def test_resolve_target_file_uses_parent(tmp_path) -> None:
    child = tmp_path / "app.py"
    child.write_text("x = 1\n", encoding="utf-8")
    assert resolve_target(child) == tmp_path.resolve()


def test_resolve_missing_target_raises(tmp_path) -> None:
    with pytest.raises(ScanError):
        resolve_target(tmp_path / "missing")


def test_scan_without_reports_always_has_twelve_findings(tmp_path) -> None:
    result = run_scan(tmp_path, policy=Policy(), options=ScanOptions(), write_reports=False)
    assert len(result.ctx.findings) == 12
    assert [finding.pillar for finding in (result.ctx.findings[n] for n in range(1, 13))] == list(range(1, 13))
    for spec in PILLAR_SPECS:
        finding = result.ctx.findings[spec.number]
        assert finding.status in spec.statuses
        assert 0.0 <= finding.risk <= spec.risk_scale
    assert result.verdict.name in {"SAFE", "AT_RISK", "CRITICAL"}
    assert result.duration_ms >= 0.0
    assert "risk" in summarize(result)


def test_scan_appends_telemetry_frame(tmp_path) -> None:
    result = run_scan(tmp_path, write_reports=False)
    assert result.telemetry_path is not None
    payload = Path(result.telemetry_path).read_bytes()
    assert len(payload) == 128
    from tauhaulity.core.telemetry import TelemetryFrame

    frame = TelemetryFrame.from_bytes(payload)
    assert frame.verdict == result.verdict.code
    assert frame.pillar_mask == result.verdict.bitmask


def test_scan_is_deterministic_in_findings(tmp_path) -> None:
    first = run_scan(tmp_path, write_reports=False)
    second = run_scan(tmp_path, write_reports=False)
    assert {n: (f.status, f.risk) for n, f in first.ctx.findings.items()} == {
        n: (f.status, f.risk) for n, f in second.ctx.findings.items()
    }


def test_missing_pillars_become_explicit_findings(tmp_path, monkeypatch) -> None:
    import tauhaulity.engine as engine_module

    monkeypatch.setattr(engine_module, "load_pillars", lambda strict=False: [])
    result = run_scan(tmp_path, write_reports=False)
    assert len(result.ctx.findings) == 12
    assert all(finding.risk == PROBE_FAILURE_RISK for finding in result.ctx.findings.values())
    assert any("not installed" in warning for warning in result.warnings)


def test_summary_contains_verdict(tmp_path) -> None:
    result = run_scan(tmp_path, write_reports=False)
    assert result.verdict.name in summarize(result)
