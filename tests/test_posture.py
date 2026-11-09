"""Tests for the per-machine posture checklist.

The fixtures are real project trees. Network-backed controls are never required:
the port table is injected through the posture seam and the threat snapshots are
written with the public threat_feed API, so the suite is deterministic on a
machine with no developer services listening.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from tauhaulity.tools import honeytoken, posture, threat_feed


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    return root


def _item(report: posture.PostureReport, name: str) -> posture.PostureItem:
    for item in report.items:
        if item.name == name:
            return item
    raise AssertionError("missing posture item: " + name)


def test_empty_project_is_honest_about_protection_and_outside(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(posture, "_list_listening", lambda: [])
    root = _project(tmp_path)
    report = posture.posture(root)
    protection = [item for item in report.items if item.section == "protection"]
    assert len(protection) == 7
    for item in protection:
        assert item.state in {"off", "missing", "stale"}, item
        if item.state in {"off", "missing", "stale"}:
            assert item.action, item
    outside = [item for item in report.items if item.section == "outside"]
    assert len(outside) == 5
    assert all(item.state == "na" for item in outside)
    assert all(item.action for item in outside)
    assert _item(report, "wildcard_dev_ports").state == "on"
    assert _item(report, "dotenv_files").state == "on"
    assert _item(report, "working_tree_credentials").state == "on"
    assert "outside scope" in report.score_hint
    assert "posture for " + str(root) in report.detail
    assert not [item for item in report.problems() if item.state == "na"]


def test_configured_controls_flip_to_on_and_risk(tmp_path: Path, monkeypatch) -> None:
    root = _project(tmp_path)
    (root / ".git" / "hooks").mkdir(parents=True)
    from tauhaulity.tools.hook_installer import install_hook

    assert install_hook(root).is_file()
    tokens = honeytoken.deploy(root)
    assert tokens.tokens
    threat_feed.record_snapshot(
        "osv",
        root=root,
        source=threat_feed.OSV_ENDPOINT,
        entries=("endpoint=osv status=200 advisory=GHSA-test",),
        detail="posture fixture",
    )
    threat_feed.record_snapshot(
        "malicious",
        root=root,
        source=threat_feed.MALICIOUS_TREE_URL,
        entries=("package=0requests record=MAL-2026-0001 reasons=typosquatting summary=fixture",),
        detail="posture fixture",
    )
    monkeypatch.setattr(
        posture,
        "_list_listening",
        lambda: [
            SimpleNamespace(port=5173, local_address="0.0.0.0", protocol="tcp"),
            SimpleNamespace(port=135, local_address="0.0.0.0", protocol="tcp"),
        ],
    )
    report = posture.posture(root)
    assert _item(report, "pre_commit_hook").state == "on"
    assert _item(report, "honeytoken_decoys").state == "on"
    assert _item(report, "threat_feed").state == "on"
    ports = _item(report, "wildcard_dev_ports")
    assert ports.state == "risk"
    assert "5173" in ports.detail
    assert "135" not in ports.detail, "the pillar rule only lists development ports"
    assert "tauhaulity free" in ports.action
    names = {item.name for item in report.problems()}
    assert "wildcard_dev_ports" in names


def test_broken_probe_degrades_one_item_only(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(posture, "_list_listening", lambda: [])

    def exploding(root: Path) -> posture.PostureItem:
        raise RuntimeError("simulated probe failure")

    monkeypatch.setattr(posture, "_probe_hook", exploding)
    root = _project(tmp_path)
    report = posture.posture(root)
    hook_item = _item(report, "pre_commit_hook")
    assert hook_item.state == "missing"
    assert "RuntimeError" in hook_item.detail
    assert hook_item.action
    assert len(report.items) == 16
    assert _item(report, "threat_feed").state in posture.POSTURE_STATES
    assert _item(report, "dotenv_files").state == "on"
    assert len([item for item in report.items if item.section == "outside"]) == 5


def test_outside_items_never_count_as_failures() -> None:
    outside = posture.PostureItem("outside", "x", "na", "outside scope", "companion control")
    report = posture.PostureReport(items=(outside,), score_hint="", detail="")
    assert report.problems() == []
    mixed = posture.PostureReport(
        items=(
            posture.PostureItem("protection", "hook", "off", "missing gate", "install it"),
            posture.PostureItem("exposure", "ports", "risk", "wildcard port", "bind loopback"),
            outside,
            posture.PostureItem("protection", "feed", "on", "fresh"),
        ),
        score_hint="",
        detail="",
    )
    problems = mixed.problems()
    assert [item.name for item in problems] == ["hook", "ports"]


def test_sections_render_and_serialize(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(posture, "_list_listening", lambda: [])
    report = posture.posture(_project(tmp_path))
    grouped = report.by_section()
    assert list(grouped) == ["protection", "exposure", "outside"]
    assert all(len(grouped[section]) > 0 for section in grouped)
    text = posture.render_text(report)
    assert text.startswith("POSTURE")
    assert "[protection]" in text
    assert "[exposure]" in text
    assert "[outside]" in text
    assert "[NA]" in text
    assert "action:" in text
    payload = posture.as_dict(report)
    assert set(payload["sections"]) == {"protection", "exposure", "outside"}
    assert payload["detail"] == report.detail
    assert payload["score_hint"] == report.score_hint
    json.dumps(payload)
    protection = payload["sections"]["protection"]
    assert all(set(entry) == {"name", "state", "detail", "action"} for entry in protection)


def test_item_state_is_validated() -> None:
    with pytest.raises(ValueError):
        posture.PostureItem("protection", "x", "weird", "detail")
    for state in posture.POSTURE_STATES:
        assert posture.PostureItem("outside", "x", state, "detail").state == state


def test_report_stays_inside_the_cpu_budget(project_root: Path) -> None:
    best = float("inf")
    report = None
    for _ in range(2):
        started = time.process_time()
        report = posture.posture(project_root)
        best = min(best, time.process_time() - started)
    assert report is not None
    assert best < 1.5, f"posture took {best:.3f}s of CPU"
    assert len(report.items) == 16
