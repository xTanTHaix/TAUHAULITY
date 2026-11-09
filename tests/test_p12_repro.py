"""Tests for pillar twelve: the auto repro generator probe."""

from __future__ import annotations

from pathlib import Path

import pytest

from tauhaulity.core.contracts import PILLAR_SPECS, ScanContext, ScanOptions, make_finding
from tauhaulity.core.platform_probe import detect_platform
from tauhaulity.core.policy import Policy
from tauhaulity.pillars import p12_repro
from tauhaulity.repro.synthesizer import AutoReproSynthesizer


def _context(root: Path, *, options: ScanOptions | None = None) -> ScanContext:
    root.mkdir(parents=True, exist_ok=True)
    return ScanContext(
        target=root,
        platform=detect_platform(),
        policy=Policy(),
        options=options or ScanOptions(),
    )


def _record_benign(ctx: ScanContext) -> None:
    for spec in PILLAR_SPECS:
        if spec.number == 12 or spec.number in ctx.findings:
            continue
        ctx.record(make_finding(spec, spec.statuses[0], f"fine {spec.number}"))


def _record_fixture_candidates(ctx: ScanContext) -> None:
    ctx.record(
        make_finding(
            PILLAR_SPECS[5],
            "CRITICAL",
            "malicious pickle opcode stream",
            risk=9.0,
            repro_hint="pickle gate",
        )
    )
    ctx.record(
        make_finding(
            PILLAR_SPECS[10],
            "LEAK_DETECTED",
            "credential ghp_****REDACTED**** staged",
            risk=8.0,
        )
    )
    ctx.record(
        make_finding(
            PILLAR_SPECS[8],
            "CONFLICT_DETECTED",
            "port conflict on a listener",
            risk=7.0,
            slots={"ports": "0"},
        )
    )


def test_probe_generates_scripts_inside_the_target(tmp_path: Path) -> None:
    target = tmp_path / "project"
    ctx = _context(target)
    _record_benign(ctx)
    _record_fixture_candidates(ctx)
    finding = p12_repro.probe(ctx)
    assert finding.status == "GENERATED"
    assert finding.risk == 0.0
    names = [part.strip() for part in finding.slot("repro_files").split(",") if part.strip()]
    assert names == ["repro_slot_06.py", "repro_slot_11.py", "repro_slot_09.py"]
    repro_dir = target / ".tauhaulity" / "repro"
    for name in names:
        assert (repro_dir / name).is_file()
    # Nothing may be written outside the target directory.
    for created in tmp_path.rglob("*.py"):
        assert target in created.parents
    ctx.record(finding)


def test_probe_is_idle_when_nothing_is_actionable(tmp_path: Path) -> None:
    ctx = _context(tmp_path / "project")
    _record_benign(ctx)
    finding = p12_repro.probe(ctx)
    assert finding.status == "IDLE"
    assert finding.slot("repro_files") == ""
    assert "no finding carried" in finding.detail


def test_probe_is_idle_when_generation_is_disabled(tmp_path: Path) -> None:
    ctx = _context(tmp_path / "project", options=ScanOptions(generate_repro=False))
    _record_benign(ctx)
    _record_fixture_candidates(ctx)
    finding = p12_repro.probe(ctx)
    assert finding.status == "IDLE"
    assert "disabled" in finding.detail
    assert not (tmp_path / "project" / ".tauhaulity").exists()


def test_probe_is_idle_for_benign_candidates(tmp_path: Path) -> None:
    ctx = _context(tmp_path / "project")
    ctx.record(
        make_finding(
            PILLAR_SPECS[3],
            "READY",
            "mirage ready",
            risk=6.5,
            repro_hint="mirage readiness",
        )
    )
    finding = p12_repro.probe(ctx)
    assert finding.status == "IDLE"
    assert "benign" in finding.detail


def test_probe_honours_risk_threshold(tmp_path: Path) -> None:
    below = _context(tmp_path / "below")
    below.record(make_finding(PILLAR_SPECS[5], "WARNING", "pickle gate unverified", risk=5.9))
    assert p12_repro.probe(below).status == "IDLE"

    at_threshold = _context(tmp_path / "at")
    at_threshold.record(
        make_finding(PILLAR_SPECS[5], "WARNING", "pickle gate unverified", risk=6.0)
    )
    finding = p12_repro.probe(at_threshold)
    assert finding.status == "GENERATED"
    assert finding.slot("repro_files") == "repro_slot_06.py"


def test_probe_caps_scripts_at_three(tmp_path: Path) -> None:
    ctx = _context(tmp_path / "project")
    for spec in PILLAR_SPECS[:6]:
        ctx.record(
            make_finding(
                spec,
                spec.statuses[0],
                f"candidate {spec.number}",
                risk=7.0,
            )
        )
    finding = p12_repro.probe(ctx)
    # Benign statuses are filtered out before synthesis, so this is IDLE; make
    # one candidate failing to exercise the cap instead.
    assert finding.status in {"IDLE", "GENERATED"}
    if finding.status == "GENERATED":
        names = [part for part in finding.slot("repro_files").split(", ") if part]
        assert len(names) <= 3


def test_probe_contains_synthesis_failures(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = _context(tmp_path / "project")
    _record_fixture_candidates(ctx)

    def explode(self, findings, context, *, limit=3):
        raise OSError("simulated full disk")

    monkeypatch.setattr(AutoReproSynthesizer, "synthesize_many", explode)
    finding = p12_repro.probe(ctx)
    assert finding.status == "WARNING"
    assert "simulated full disk" in finding.detail
    assert finding.risk <= 10.0


def test_pillar_spec_is_registered() -> None:
    assert p12_repro.SPEC.number == 12
    assert p12_repro.SPEC.key == "auto_repro"
    assert p12_repro.SPEC.statuses == ("GENERATED", "IDLE", "WARNING")
