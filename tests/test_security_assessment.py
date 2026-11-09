"""Runs the security assessment harness and guards its measured baseline.

The harness in scripts/assess_security.py is the honest answer to "how much does
this actually protect me". Running it in the suite means a change that quietly
stops detecting a scenario - or that starts claiming prevention it does not have -
fails here instead of shipping.

Marked slow because it spawns git and several subprocesses.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.slow


def _run() -> dict:
    import json

    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "assess_security.py"), "--json"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout)


def test_assessment_detects_the_measured_baseline() -> None:
    payload = _run()
    summary = payload["summary"]
    assert summary["scenarios"] >= 13
    assert summary["detection_rate"] >= 0.7, summary
    assert summary["blocked_or_recovered"] >= 3, summary


def test_assessment_never_claims_prevention_it_lacks() -> None:
    payload = _run()
    for item in payload["results"]:
        # A scenario may only claim prevention when the harness observed a block,
        # a refusal or a recovery; otherwise the column must say so plainly.
        if item["prevention"] == "blocked":
            assert item["detection"] == "detected", item
        assert item["evidence"], item
        assert item["tier"] in {"-", "0 - remediation only"} or item["tier"][0] in "0123", item


def test_assessment_reports_the_new_exposure_check() -> None:
    payload = _run()
    scenarios = {item["scenario"]: item for item in payload["results"]}
    exposure = scenarios["Development service listening on every interface"]
    assert exposure["detection"] == "detected", exposure["evidence"]
    assert "0.0.0.0" in exposure["evidence"] or "reachable" in exposure["evidence"]
