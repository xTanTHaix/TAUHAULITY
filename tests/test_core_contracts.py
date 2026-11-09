"""Contract tests: pillar schema, finding validation and context caching."""

from __future__ import annotations

import pytest

from tauhaulity.core.contracts import (
    CRITICAL_STATUSES,
    PILLAR_SPECS,
    SPEC_BY_KEY,
    ContractError,
    Finding,
    ScanContext,
    ScanOptions,
    make_finding,
    status_severity,
)
from tauhaulity.core.platform_probe import detect_platform
from tauhaulity.core.policy import Policy


def _context(tmp_path) -> ScanContext:
    return ScanContext(
        target=tmp_path,
        platform=detect_platform(),
        policy=Policy(),
        options=ScanOptions(),
    )


def test_twelve_unique_pillars() -> None:
    assert len(PILLAR_SPECS) == 12
    assert [spec.number for spec in PILLAR_SPECS] == list(range(1, 13))
    assert len({spec.key for spec in PILLAR_SPECS}) == 12


def test_illegal_status_is_rejected() -> None:
    spec = SPEC_BY_KEY["aegis_vmi"]
    with pytest.raises(ContractError):
        make_finding(spec, "GENERATED", "wrong token")


def test_risk_outside_scale_is_rejected() -> None:
    spec = SPEC_BY_KEY["aegis_vmi"]
    with pytest.raises(ContractError):
        make_finding(spec, "WARNING", "too risky", risk=11.0)


def test_context_rejects_unknown_pillar() -> None:
    ctx = _context(__import__("pathlib").Path("."))
    with pytest.raises(ContractError):
        ctx.record(Finding(pillar=99, status="SAFE", detail="nope"))


def test_context_records_and_overwrites() -> None:
    ctx = _context(__import__("pathlib").Path("."))
    spec = SPEC_BY_KEY["supply_guard"]
    ctx.record(make_finding(spec, "SAFE", "first"))
    ctx.record(make_finding(spec, "WARNING", "second", risk=2.0))
    assert ctx.findings[6].detail == "second"
    assert ctx.finding(6) is not None and ctx.finding(7) is None


def test_status_severity_mapping() -> None:
    assert status_severity("SAFE") == 0
    assert status_severity("WARNING") == 1
    assert status_severity("CRITICAL") == 2
    assert status_severity("SOMETHING_NEW") == 1
    # IDLE means "nothing to do", not "something to fix": treating it as a
    # warning made every clean project come out AT_RISK.
    assert status_severity("IDLE") == 0
    assert status_severity("GENERATED") == 0
    for status in CRITICAL_STATUSES:
        assert status_severity(status) == 2


def test_artifact_factory_runs_once() -> None:
    ctx = _context(__import__("pathlib").Path("."))
    calls = {"count": 0}

    def factory() -> str:
        calls["count"] += 1
        return "engine"

    assert ctx.artifact("engine", factory) == "engine"
    assert ctx.artifact("engine", factory) == "engine"
    assert calls["count"] == 1
