"""Threat-feed coverage check, replayed from the cached sample.

The sample under docs/ is a snapshot of real malicious-package records pulled from
the OpenSSF feed, so this test runs offline and still proves the mapping between
the attack classes the feed reports and the rules this project implements.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / "docs" / "threat-feed-sample.json"
pytestmark = pytest.mark.slow


def _run(*args: str) -> dict:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "threat_feed_check.py"), *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout)


def test_cached_sample_covers_the_reported_attack_classes() -> None:
    payload = _run("--json")
    summary = payload["summary"]
    assert summary["sampled"] >= 10, summary
    assert summary["covered_by_a_rule"] >= 1, summary
    assert summary["coverage_of_tagged"] == 1.0, summary


def test_sample_records_real_campaigns() -> None:
    payload = json.loads(CACHE.read_text(encoding="utf-8"))
    campaigns = {record.get("campaign", "") for record in payload["records"]}
    assert any("0requests" in name for name in campaigns), campaigns
    assert payload.get("captured_at"), "the snapshot must record when it was taken"


def test_offline_behaviour_is_explicit(tmp_path: Path) -> None:
    """A missing cache must say so rather than reporting a clean result."""

    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "threat_feed_check.py"), "--json", "--cache",
         str(tmp_path / "absent.json"), "--allow-offline"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0
    payload = json.loads(completed.stdout)
    assert payload["records"] == []
    assert "no cached sample" in payload["source"]
