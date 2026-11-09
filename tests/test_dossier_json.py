"""JSON dossier tests: field order, encoding and Markdown field alignment."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tauhaulity.core.contracts import PILLAR_SPECS, ScanContext, ScanOptions, make_finding
from tauhaulity.core.platform_probe import detect_platform
from tauhaulity.core.policy import Policy
from tauhaulity.dossier.model import DOSSIER_SCHEMA
from tauhaulity.dossier.render_json import JSON_FIELD_ORDER
from tauhaulity.dossier.report import build_report, render_json, write_reports

# Evidence that mixes a Latin combining sequence (e plus U+0301 COMBINING ACUTE
# ACCENT) with fullwidth Latin letters (U+FF21, U+FF22). It proves that
# ensure_ascii=False keeps non-ASCII evidence readable instead of escaping it.
EVIDENCE_WITH_MARKS = "Cafe\u0301 audit \uff21\uff22 AEGIS-VMI"


def _context(root: Path) -> ScanContext:
    root.mkdir(parents=True, exist_ok=True)
    ctx = ScanContext(target=root, platform=detect_platform(), policy=Policy(), options=ScanOptions())
    for spec in PILLAR_SPECS:
        detail = (
            EVIDENCE_WITH_MARKS if spec.number == 1 else f"evidence for pillar {spec.number}"
        )
        ctx.record(
            make_finding(
                spec,
                spec.statuses[0],
                detail,
                risk=float(spec.number) / 2.0,
                slots={"detail": str(root)},
            )
        )
    return ctx


def test_json_key_order_is_stable_and_documented(tmp_path: Path) -> None:
    report = build_report(_context(tmp_path / "project"))
    payload = json.loads(render_json(report))
    assert list(payload) == list(JSON_FIELD_ORDER)
    assert payload["schema"] == DOSSIER_SCHEMA
    assert len(payload["pillars"]) == 12
    assert [row["pillar"] for row in payload["pillars"]] == list(range(1, 13))


def test_json_matches_markdown_field_vocabulary(tmp_path: Path) -> None:
    report = build_report(_context(tmp_path / "project"))
    payload = json.loads(render_json(report))
    for row, (spec, finding) in zip(payload["pillars"], report.pillar_rows()):
        assert row == {
            "pillar": spec.number,
            "key": spec.key,
            "name": spec.name,
            "status": finding.status,
            "severity": 0,
            "mechanism": spec.mechanism,
            "finding": finding.detail,
            "risk": round(float(finding.risk), 4),
            "repro_hint": "",
            "slots": {"detail": str(report.target)},
        }


def test_json_is_utf8_without_bom_and_has_trailing_newline(tmp_path: Path) -> None:
    report = build_report(_context(tmp_path / "project"))
    text = render_json(report)
    assert EVIDENCE_WITH_MARKS in text  # ensure_ascii=False keeps the marks readable
    # The combining accent and the fullwidth letters stay literal, never escaped.
    assert "\\u0301" not in text
    assert "\\uff21" not in text
    assert text.endswith("\n")
    assert not text.endswith("\n\n")
    raw = text.encode("utf-8")
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert raw.decode("utf-8") == text


def test_json_hmac_and_verdict_are_present(tmp_path: Path) -> None:
    report = build_report(_context(tmp_path / "project"))
    payload = json.loads(render_json(report))
    assert payload["hmac_sha256"] == report.hmac
    assert len(payload["hmac_sha256"]) == 64
    assert payload["verdict"] == report.verdict.name
    assert payload["overall_security_verdict"]["name"] == report.verdict.name
    assert payload["overall_security_verdict"]["risk"] == report.verdict.risk
    assert payload["findings_recorded"] == 12
    assert payload["policy"] == report.policy.to_dict()
    assert payload["repro_files"] == []


def test_render_json_is_deterministic(tmp_path: Path) -> None:
    report = build_report(_context(tmp_path / "project"))
    assert render_json(report) == render_json(report)


def test_json_written_file_is_clean_utf8(tmp_path: Path) -> None:
    out_dir = tmp_path / "reports"
    report = build_report(_context(tmp_path / "project"))
    written = write_reports(report, out_dir, formats=("json",))
    path = written["json"]
    raw = path.read_bytes()
    assert not raw.startswith(b"\xef\xbb\xbf")
    assert raw.endswith(b"\n")
    parsed = json.loads(raw.decode("utf-8"))
    assert parsed["hmac_sha256"] == report.hmac
    assert EVIDENCE_WITH_MARKS in parsed["pillars"][0]["finding"]


def test_json_requires_a_dossier_report() -> None:
    with pytest.raises(AttributeError):
        render_json("not a report")  # type: ignore[arg-type]
