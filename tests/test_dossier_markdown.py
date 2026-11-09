"""Markdown dossier tests: matrix completeness, form keys and atomic writes."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from tauhaulity.core.contracts import PILLAR_SPECS, ScanContext, ScanOptions, make_finding
from tauhaulity.core.platform_probe import detect_platform
from tauhaulity.core.policy import Policy
from tauhaulity.dossier.form_parser import parse_form
from tauhaulity.dossier.model import SECTION_HEADINGS
from tauhaulity.dossier.report import build_report, render_markdown, verify_report, write_reports

PILLAR_ONE_ROW = re.compile(r"^\| (\d{1,2}) \|")


def _context(root: Path, *, policy: Policy | None = None) -> ScanContext:
    root.mkdir(parents=True, exist_ok=True)
    ctx = ScanContext(
        target=root,
        platform=detect_platform(),
        policy=policy or Policy(),
        options=ScanOptions(),
    )
    for spec in PILLAR_SPECS:
        ctx.record(
            make_finding(
                spec,
                spec.statuses[0],
                f"evidence for pillar {spec.number}",
                risk=float(spec.number) / 2.0,
                slots={"detail": str(root)},
                repro_hint="repro hint" if spec.number == 7 else None,
            )
        )
    return ctx


def test_markdown_contains_five_sections_and_twelve_ordered_rows(tmp_path: Path) -> None:
    report = build_report(_context(tmp_path / "project"))
    markdown = render_markdown(report)
    for heading in SECTION_HEADINGS:
        assert heading in markdown
    numbers = [int(match.group(1)) for match in map(PILLAR_ONE_ROW.match, markdown.splitlines()) if match]
    assert numbers == list(range(1, 13))
    assert markdown.endswith("\n")
    assert "\r" not in markdown
    assert markdown.encode("utf-8")[:3] != b"\xef\xbb\xbf"


def test_markdown_rows_carry_status_mechanism_finding_and_risk(tmp_path: Path) -> None:
    report = build_report(_context(tmp_path / "project"))
    markdown = render_markdown(report)
    for spec, finding in report.pillar_rows():
        assert f"[ {finding.status} ]" in markdown
        assert spec.mechanism in markdown
        assert finding.detail in markdown
        assert f"{finding.risk:.1f} / {spec.risk_scale:.1f}" in markdown
    assert report.hmac in markdown
    assert verify_report(report) is True


def test_markdown_form_block_parses_back(tmp_path: Path) -> None:
    policy = Policy(enforce_active=True, undo_ring_mb=128, auditor="Ada")
    report = build_report(_context(tmp_path / "project", policy=policy))
    overrides = parse_form(render_markdown(report))
    merged = policy.with_overrides(overrides)
    assert merged == policy


def test_markdown_marks_missing_pillars_instead_of_hiding_them(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir(parents=True)
    ctx = ScanContext(target=root, platform=detect_platform(), policy=Policy(), options=ScanOptions())
    ctx.record(make_finding(PILLAR_SPECS[0], "SAFE", "only pillar one ran"))
    report = build_report(ctx)
    assert len(report.findings) == 12
    placeholder = report.finding(12)
    assert placeholder.status == PILLAR_SPECS[11].default_status
    assert "did not run" in placeholder.detail
    markdown = render_markdown(report)
    # SEC 2 must mark every placeholder. The wording is also repeated by the
    # scorecard ledger and other tables start with a number, so the pillar table
    # is isolated before its rows are counted.
    assert markdown.count("did not run") >= 11
    pillar_section = markdown.split("SEC 2:")[1].split("SEC 3:")[0]
    numbers = [int(match.group(1)) for match in map(PILLAR_ONE_ROW.match, pillar_section.splitlines()) if match]
    assert numbers == list(range(1, 13))
    for spec in PILLAR_SPECS[1:]:
        assert f"| {spec.number} |" in pillar_section


def test_write_reports_writes_all_formats_and_overwrites_atomically(tmp_path: Path) -> None:
    out_dir = tmp_path / "reports"
    out_dir.mkdir()
    first = build_report(_context(tmp_path / "project-a", policy=Policy(auditor="First Auditor")))
    written = write_reports(first, out_dir)
    assert set(written) == {"md", "txt", "json"}
    assert written["md"].name == "tauhaulity_report.md"
    assert written["txt"].name == "tauhaulity_report.txt"
    assert written["json"].name == "tauhaulity_report.json"
    for path in written.values():
        assert path.is_file()
        assert path.read_text(encoding="utf-8").endswith("\n")
    assert "First Auditor" in written["md"].read_text(encoding="utf-8")

    # A stale placeholder must not survive the second write.
    for path in written.values():
        path.write_text("STALE", encoding="utf-8")
    second = build_report(_context(tmp_path / "project-b", policy=Policy(auditor="Second Auditor")))
    rewritten = write_reports(second, out_dir)
    markdown = rewritten["md"].read_text(encoding="utf-8")
    assert "Second Auditor" in markdown
    assert "STALE" not in markdown
    assert "STALE" not in rewritten["json"].read_text(encoding="utf-8")
    leftovers = [path.name for path in out_dir.iterdir() if path.name.endswith(".tmp")]
    assert leftovers == []
    assert sorted(path.name for path in out_dir.iterdir()) == sorted(
        ["tauhaulity_report.md", "tauhaulity_report.txt", "tauhaulity_report.json"]
    )


def test_write_reports_honours_format_subset_and_creates_directory(tmp_path: Path) -> None:
    out_dir = tmp_path / "nested" / "reports"
    report = build_report(_context(tmp_path / "project"))
    written = write_reports(report, out_dir, formats=("json",))
    assert list(written) == ["json"]
    assert out_dir.is_dir()
    assert sorted(path.name for path in out_dir.iterdir()) == ["tauhaulity_report.json"]


def test_write_reports_rejects_unknown_or_empty_formats(tmp_path: Path) -> None:
    report = build_report(_context(tmp_path / "project"))
    with pytest.raises(ValueError):
        write_reports(report, tmp_path, formats=("pdf",))
    with pytest.raises(ValueError):
        write_reports(report, tmp_path, formats=())
