"""Tests for the standalone repro script synthesizer."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from tauhaulity.core.contracts import SPEC_BY_NUMBER, Finding, ScanContext, ScanOptions, make_finding
from tauhaulity.core.platform_probe import detect_platform
from tauhaulity.core.policy import Policy
from tauhaulity.repro.synthesizer import AutoReproSynthesizer


def _context(root: Path) -> ScanContext:
    root.mkdir(parents=True, exist_ok=True)
    return ScanContext(
        target=root,
        platform=detect_platform(),
        policy=Policy(),
        options=ScanOptions(),
    )


def _run(script: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(script)],
        capture_output=True,
        text=True,
        timeout=90,
    )


def test_pickle_script_reproduces_under_subprocess(tmp_path: Path) -> None:
    ctx = _context(tmp_path / "project")
    synthesizer = AutoReproSynthesizer(tmp_path / "repro")
    finding = make_finding(
        SPEC_BY_NUMBER[6],
        "CRITICAL",
        "malicious pickle stream with GLOBAL and REDUCE in vendored package",
        risk=9.0,
    )
    script = synthesizer.synthesize(finding, ctx)
    assert script is not None
    assert script.name == "repro_slot_06.py"
    text = script.read_text(encoding="utf-8")
    assert "import pickletools" in text
    assert "PAYLOAD" in text
    assert "{{" not in text

    result = _run(script)
    assert result.returncode == 0, result.stderr
    assert "PASS" in result.stdout
    assert "GLOBAL" in result.stdout
    assert "CRITICAL" in result.stdout
    assert "Traceback" not in result.stderr


def test_token_script_uses_synthetic_canary_and_reproduces(tmp_path: Path) -> None:
    ctx = _context(tmp_path / "project")
    synthesizer = AutoReproSynthesizer(tmp_path / "repro")
    finding = make_finding(
        SPEC_BY_NUMBER[11],
        "LEAK_DETECTED",
        "staged file contains ghp_****REDACTED**** credential",
        risk=9.0,
    )
    script = synthesizer.synthesize(finding, ctx)
    assert script is not None
    assert script.name == "repro_slot_11.py"
    text = script.read_text(encoding="utf-8")
    # The real leaked secret must never be embedded; a same family canary is used.
    assert "ghp_RRR" in text
    assert "REDACTED****" not in text

    result = _run(script)
    assert result.returncode == 0, result.stderr
    assert "PASS" in result.stdout
    assert "LEAK_DETECTED" in result.stdout


def test_token_family_detection_selects_matching_canary(tmp_path: Path) -> None:
    ctx = _context(tmp_path / "project")
    synthesizer = AutoReproSynthesizer(tmp_path / "repro")
    fine = make_finding(
        SPEC_BY_NUMBER[11],
        "LEAK_DETECTED",
        "github_pat_****REDACTED**** fine grained token",
        risk=8.0,
    )
    script = synthesizer.synthesize(fine, ctx)
    assert script is not None
    text = script.read_text(encoding="utf-8")
    assert "github_pat_RRR" in text
    result = _run(script)
    assert result.returncode == 0, result.stderr


def test_port_script_binds_and_detects(tmp_path: Path) -> None:
    ctx = _context(tmp_path / "project")
    synthesizer = AutoReproSynthesizer(tmp_path / "repro")
    finding = make_finding(
        SPEC_BY_NUMBER[9],
        "CONFLICT_DETECTED",
        "port conflict on a developer listener",
        risk=7.0,
        slots={"ports": "0"},
    )
    script = synthesizer.synthesize(finding, ctx)
    assert script is not None
    assert "PORT = 0" in script.read_text(encoding="utf-8")
    result = _run(script)
    assert result.returncode == 0, result.stderr
    assert "PASS" in result.stdout


def test_port_script_ignores_bare_counts_in_prose(tmp_path: Path) -> None:
    ctx = _context(tmp_path / "project")
    synthesizer = AutoReproSynthesizer(tmp_path / "repro")
    finding = make_finding(
        SPEC_BY_NUMBER[9],
        "ZOMBIE_FOUND",
        "22 listening socket(s) and 4 zombie candidates",
        risk=7.0,
        slots={"ports": "22 listening"},
    )
    script = synthesizer.synthesize(finding, ctx)
    assert script is not None
    # 22 is an event count, not the port, so the script must fall back to an
    # ephemeral port instead of binding a privileged one.
    assert "PORT = 0" in script.read_text(encoding="utf-8")


def test_port_script_reads_explicit_conflict_port(tmp_path: Path) -> None:
    ctx = _context(tmp_path / "project")
    synthesizer = AutoReproSynthesizer(tmp_path / "repro")
    finding = make_finding(
        SPEC_BY_NUMBER[9],
        "CONFLICT_DETECTED",
        "22 listening socket(s); development port conflict on 8000, 3000",
        risk=7.0,
        slots={"ports": "22 listening"},
    )
    script = synthesizer.synthesize(finding, ctx)
    assert script is not None
    assert "PORT = 8000" in script.read_text(encoding="utf-8")


def test_generic_script_is_runnable_and_unambiguous(tmp_path: Path) -> None:
    ctx = _context(tmp_path / "project")
    synthesizer = AutoReproSynthesizer(tmp_path / "repro")
    finding = make_finding(
        SPEC_BY_NUMBER[4],
        "WARNING",
        "mirage readiness degraded",
        risk=7.0,
        repro_hint="unshare namespace and confirm the mirage journal",
    )
    script = synthesizer.synthesize(finding, ctx)
    assert script is not None
    text = script.read_text(encoding="utf-8")
    assert "discover_modules" in text
    assert "generate_repro=False" in text
    result = _run(script)
    # 0 reproduced, 1 mitigated, 2 unverifiable because the probe is not
    # importable from the temporary project: all three are honest outcomes.
    assert result.returncode in (0, 1, 2), result.stderr
    assert "Traceback" not in result.stderr
    assert any(marker in result.stdout for marker in ("PASS", "FAIL", "UNVERIFIABLE"))


def test_generic_template_wins_over_substring_false_positive(tmp_path: Path) -> None:
    ctx = _context(tmp_path / "project")
    synthesizer = AutoReproSynthesizer(tmp_path / "repro")
    finding = make_finding(
        SPEC_BY_NUMBER[10],
        "MALICIOUS_PTH",
        "executable .pth line in site-packages",
        risk=9.0,
        slots={"detail": ".venv/lib/python3.12/site-packages/totally_legit.pth"},
        repro_hint="inspect the executable line of totally_legit.pth before starting the interpreter",
    )
    script = synthesizer.synthesize(finding, ctx)
    assert script is not None
    text = script.read_text(encoding="utf-8")
    # "legit" contains the letters g-i-t but this is a venv finding, so the probe
    # re-run template must be chosen instead of the credential canary template.
    assert "discover_modules" in text
    assert "PATTERNS = {" not in text


def test_benign_finding_produces_no_script(tmp_path: Path) -> None:
    ctx = _context(tmp_path / "project")
    synthesizer = AutoReproSynthesizer(tmp_path / "repro")
    finding = make_finding(SPEC_BY_NUMBER[1], "SAFE", "pointer tables sealed", risk=0.0)
    assert synthesizer.synthesize(finding, ctx) is None
    assert not (tmp_path / "repro").exists()


def test_synthesize_many_respects_limit_and_risk_order(tmp_path: Path) -> None:
    ctx = _context(tmp_path / "project")
    synthesizer = AutoReproSynthesizer(tmp_path / "repro")
    findings = [
        make_finding(SPEC_BY_NUMBER[9], "ZOMBIE_FOUND", "zombie", risk=6.2),
        make_finding(SPEC_BY_NUMBER[6], "CRITICAL", "pickle", risk=9.4),
        make_finding(SPEC_BY_NUMBER[11], "LEAK_DETECTED", "token ghp_", risk=8.1),
    ]
    written = synthesizer.synthesize_many(findings, ctx, limit=2)
    assert [path.name for path in written] == ["repro_slot_06.py", "repro_slot_11.py"]
    with pytest.raises(ValueError):
        synthesizer.synthesize_many(findings, ctx, limit=-1)


def test_synthesize_validates_arguments(tmp_path: Path) -> None:
    ctx = _context(tmp_path / "project")
    synthesizer = AutoReproSynthesizer(tmp_path / "repro")
    with pytest.raises(TypeError):
        synthesizer.synthesize("not a finding", ctx)  # type: ignore[arg-type]
    unknown = Finding(pillar=99, status="WARNING", detail="impossible", risk=1.0)
    with pytest.raises(ValueError):
        synthesizer.synthesize(unknown, ctx)
    with pytest.raises(TypeError):
        AutoReproSynthesizer(123)  # type: ignore[arg-type]
