"""Plain text dossier tests: Unicode display width engine and file trailer."""

from __future__ import annotations

from pathlib import Path

import pytest

from tauhaulity.core.contracts import PILLAR_SPECS, ScanContext, ScanOptions, make_finding
from tauhaulity.core.platform_probe import detect_platform
from tauhaulity.core.policy import Policy
from tauhaulity.dossier.form_parser import parse_form
from tauhaulity.dossier.model import SECTION_HEADINGS
from tauhaulity.dossier.render_txt import (
    display_width,
    pad,
    render_text,
    render_text_with_width,
    table_lines,
    truncate,
)
from tauhaulity.dossier.report import build_report

# A Latin combining sequence: the letter e followed by U+0301 COMBINING ACUTE
# ACCENT. The accent paints over the base letter and costs no extra cell, so the
# cluster occupies exactly one column.
COMBINING = "e\u0301"

# Fullwidth Latin capital A and B (U+FF21, U+FF22). Both have East Asian width F,
# so each one occupies two terminal cells.
FULLWIDTH = "\uff21\uff22"

# Mixed evidence: four cells for "Cafe" plus the accent, one space, four cells for
# the two fullwidth letters, one space and nine cells for "AEGIS-VMI".
MIXED = "Cafe\u0301 \uff21\uff22 AEGIS-VMI"


def _context(root: Path) -> ScanContext:
    root.mkdir(parents=True, exist_ok=True)
    ctx = ScanContext(target=root, platform=detect_platform(), policy=Policy(), options=ScanOptions())
    for spec in PILLAR_SPECS:
        detail = MIXED if spec.number == 1 else f"plain evidence {spec.number}"
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


def _display_columns(line: str, marks: str) -> list[int]:
    """Return the display column of every border mark in a rendered line.

    Character offsets are useless once a cell mixes combining marks or fullwidth
    glyphs with Latin text, because one glyph may occupy several characters or
    several cells. The display column, not the character index, is what must line
    up between the border and every row.
    """

    return [
        display_width(line[:index])
        for index, char in enumerate(line)
        if char in marks
    ]


def _sec2_table(txt: str) -> list[str]:
    lines = txt.splitlines()
    start = lines.index(SECTION_HEADINGS[1])
    block: list[str] = []
    for line in lines[start + 1 :]:
        if line.startswith("+"):
            block.append(line)
        elif line.startswith("|"):
            block.append(line)
        elif block:
            break
    return block


def test_display_width_combining_and_fullwidth_cells() -> None:
    assert display_width(COMBINING) == 1
    assert display_width("e") == 1
    assert display_width(FULLWIDTH) == 4
    assert display_width(MIXED) == 19
    assert display_width("AEGIS-VMI") == 9
    assert display_width("") == 0
    assert display_width("\u200b") == 0  # zero width space
    assert display_width("\ufeff") == 0  # BOM inside text
    assert display_width("abc") == 3


def test_pad_and_truncate_are_exact_in_cells() -> None:
    assert pad(COMBINING, 5) == COMBINING + "    "
    assert display_width(pad(COMBINING, 5)) == 5
    assert pad("abcdef", 3) == "abcdef"
    assert display_width(pad("", 4)) == 4
    # A combining mark travels with its base letter instead of being split off.
    cluster = COMBINING * 3
    trimmed = truncate(cluster, 2)
    assert trimmed == COMBINING * 2
    assert display_width(trimmed) == 2
    # A wide glyph is never split across a border cell.
    assert truncate(FULLWIDTH, 3) == "\uff21"
    assert display_width(truncate(FULLWIDTH, 3)) == 2
    assert truncate("abc", 10) == "abc"
    assert truncate("abc", 0) == ""
    with pytest.raises(ValueError):
        truncate("abc", -1)
    with pytest.raises(ValueError):
        pad("abc", -1)


def test_table_borders_align_for_combining_and_fullwidth_cells() -> None:
    lines = table_lines(["KEY", "VALUE"], [[COMBINING + " AEGIS", FULLWIDTH]])
    border = lines[0]
    # Column one is seven cells wide ("e" plus accent, space, "AEGIS"); column two
    # is five because the header "VALUE" is wider than the four cell fixture.
    assert border == "+" + "-" * 9 + "+" + "-" * 7 + "+"
    assert len({display_width(line) for line in lines}) == 1
    columns = _display_columns(border, "+")
    for line in lines[1:]:
        if not line.startswith("|"):
            continue
        assert _display_columns(line, "|") == columns
    assert lines[1] == "| KEY     | VALUE |"
    assert COMBINING + " AEGIS" in lines[3]
    assert FULLWIDTH in lines[3]


def test_rendered_text_sec2_table_alignment(tmp_path: Path) -> None:
    report = build_report(_context(tmp_path / "project"))
    txt = render_text(report)
    table = _sec2_table(txt)
    assert len(table) == 16  # top border + header + header rule + 12 rows + bottom border
    widths = {display_width(line) for line in table}
    assert len(widths) == 1
    border = table[0]
    columns = _display_columns(border, "+")
    for line in table[1:]:
        if not line.startswith("|"):
            continue
        assert _display_columns(line, "|") == columns
    mixed_row = next(line for line in table if "\uff21" in line)
    assert _display_columns(mixed_row, "|") == columns


def test_render_text_contains_sections_form_and_hmac(tmp_path: Path) -> None:
    report = build_report(_context(tmp_path / "project"))
    txt = render_text(report)
    for heading in SECTION_HEADINGS:
        assert heading in txt
    assert report.hmac in txt
    assert "Protection Mode" in txt
    assert "Auditor Name/Notes" in txt
    assert txt.endswith("\n")
    overrides = parse_form(txt)
    assert overrides.undo_ring_mb == report.policy.undo_ring_mb
    assert overrides.auditor == report.policy.auditor


def test_render_text_ends_with_one_integrity_trailer(tmp_path: Path) -> None:
    report = build_report(_context(tmp_path / "project"))
    txt = render_text(report)
    lines = txt.splitlines()
    assert lines[-1].startswith("INTEGRITY: sha256=")
    assert sum(line.startswith("INTEGRITY:") for line in lines) == 1
    assert not txt.endswith("\n\n")


def test_render_text_with_narrow_width_keeps_the_trailer_intact(tmp_path: Path) -> None:
    report = build_report(_context(tmp_path / "project"))
    txt = render_text_with_width(report, 80)
    lines = txt.splitlines()
    assert lines[-1].startswith("INTEGRITY: sha256=")
    # The body is trimmed to the requested width; the trailer must never be cut.
    body = lines[:-1]
    assert all(display_width(line) <= 80 for line in body)
    with pytest.raises(ValueError):
        render_text_with_width(report, 20)


def test_table_rejects_bad_shapes() -> None:
    with pytest.raises(ValueError):
        table_lines([], [])
    with pytest.raises(ValueError):
        table_lines(["A"], [["x", "y"]])
    with pytest.raises(ValueError):
        table_lines(["A"], [["x"]], max_widths=[-1])
    with pytest.raises(ValueError):
        table_lines(["A"], [["x"]], max_widths=[1, 2])
    with pytest.raises(TypeError):
        display_width(1)  # type: ignore[arg-type]
