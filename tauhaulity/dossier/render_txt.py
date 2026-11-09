"""Plain text dossier renderer with a Unicode display-width engine.

A terminal cell is not a character: combining marks paint over the preceding base
glyph and cost zero columns, while wide and fullwidth glyphs occupy two. Measuring
len() therefore breaks the border alignment as soon as the evidence mixes
combining sequences or wide characters with ordinary Latin text, which is exactly
the case this dossier must survive. Every layout decision below is made in display
cells via unicodedata, and the table renderer is shared by all plain text sections
so one width bug cannot misalign only one table.

The rendered document ends with the format independent INTEGRITY trailer built by
tauhaulity.dossier.integrity.
"""

from __future__ import annotations

import unicodedata
from functools import lru_cache
from typing import Final, Sequence

from tauhaulity.dossier.form_parser import render_form_lines
from tauhaulity.dossier.integrity import stamp_report_text
from tauhaulity.dossier.model import SECTION_HEADINGS, DossierReport

# Width of the plain text dossier. One hundred and twenty cells keeps a six
# column evidence matrix readable while still fitting a maximised terminal.
TXT_WIDTH: Final[int] = 120

# SEC 5 describes the key truthfully. The machine key is reproducible on the host
# and therefore tamper-evident only; an explicit or environment key is a secret.
_KEY_DESCRIPTIONS: Final[dict[str, str]] = {
    "machine": "machine bound (host + user) tamper-evident tie, NOT a secret",
    "env": "explicit secret from the TAUHAULITY_SIGNING_KEY environment value",
    "explicit": "explicit secret supplied by the caller",
    "none": "no key resolved; this digest is unsigned",
}


def _key_description(report: DossierReport) -> str:
    """Return the SEC 5 wording for the key that signed the report."""

    source = getattr(report, "key_source", "machine")
    return _KEY_DESCRIPTIONS.get(source, _KEY_DESCRIPTIONS["machine"])

_BANNER_CHAR: Final[str] = "="
_ASCII_FALLBACK: Final[str] = "?"


@lru_cache(maxsize=4096)
def _char_width(char: str) -> int:
    """Return the number of terminal cells one code point occupies.

    Combining marks (Mn, Me), format characters such as ZWJ and BOM (Cf) and
    control characters cost zero cells because they are painted on top of the
    previous glyph. Wide and fullwidth East Asian glyphs cost two cells.

    Parameters:
        char: A single code point as text.

    Raises:
        TypeError: When the argument is not a one character string.
    """

    if not isinstance(char, str) or len(char) != 1:
        raise TypeError("_char_width expects exactly one code point")
    if char in {"\n", "\r", "\t"}:
        return 0
    category = unicodedata.category(char)
    if category in {"Mn", "Me", "Cf"}:
        return 0
    if unicodedata.combining(char):
        return 0
    if unicodedata.east_asian_width(char) in {"W", "F"}:
        return 2
    return 1


def display_width(text: str) -> int:
    """Return the terminal cell width of a string.

    Parameters:
        text: Arbitrary text; newlines and combining marks cost nothing.

    Raises:
        TypeError: When text is not a string.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    return sum(_char_width(char) for char in text)


def pad(text: str, width: int) -> str:
    """Right pad text with spaces until it occupies width terminal cells.

    The input is never truncated: when it is already wider than the requested
    width it is returned unchanged, so a caller that must preserve content can
    decide separately whether to truncate first.

    Raises:
        ValueError: When width is negative.
        TypeError: When text is not a string.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if width < 0:
        raise ValueError("width must not be negative")
    missing = width - display_width(text)
    return text if missing <= 0 else text + " " * missing


def truncate(text: str, width: int) -> str:
    """Cut text so its display width does not exceed width cells.

    Cutting stops before the first glyph that would overflow, but keeps zero
    width combining marks attached to the already accepted base glyph. Dropping
    a combining mark would change the rendered word, and splitting a wide glyph
    would corrupt the border column it belongs to.

    Raises:
        ValueError: When width is negative.
        TypeError: When text is not a string.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if width < 0:
        raise ValueError("width must not be negative")
    used = 0
    accepted: list[str] = []
    for char in text:
        cost = _char_width(char)
        if cost == 0:
            accepted.append(char)
            continue
        if used + cost > width:
            break
        accepted.append(char)
        used += cost
    return "".join(accepted)


def _sanitise_cell(text: str) -> str:
    """Flatten a cell to one printable line without its column delimiter.

    Newlines would break the row counting and a literal pipe would be mistaken
    for a column separator, so both are replaced with a slash for newlines and a
    fullwidth broken bar for pipes.
    """

    flattened = str(text).replace("\r", " ").replace("\n", " ").replace("\t", " ")
    return flattened.replace("|", "\u00a6")


def table_lines(
    headers: Sequence[str],
    rows: Sequence[Sequence[str]],
    *,
    max_widths: Sequence[int] | None = None,
) -> list[str]:
    """Render an aligned border table.

    Column widths are the widest cell (capped by max_widths) and each cell is
    truncated to that width, so every rendered line has an identical display
    width and every vertical border sits in the same column.

    Parameters:
        headers: Column titles.
        rows: Row cells; each row must have the same length as headers.
        max_widths: Optional per column cap.

    Raises:
        ValueError: When headers are empty, a row has the wrong length, or a
            width cap is negative.
        TypeError: When a cell is not a string.
    """

    count = len(headers)
    if count == 0:
        raise ValueError("table needs at least one column")
    caps = list(max_widths) if max_widths is not None else [0] * count
    if len(caps) != count:
        raise ValueError("max_widths must match the header count")
    for cap in caps:
        if cap < 0:
            raise ValueError("max_widths must not be negative")

    clean_rows: list[list[str]] = []
    for row in rows:
        if len(row) != count:
            raise ValueError(f"row has {len(row)} cells, expected {count}")
        clean_rows.append([_sanitise_cell(cell) for cell in row])
    clean_headers = [_sanitise_cell(header) for header in headers]

    widths: list[int] = []
    for index in range(count):
        widest = max(
            [display_width(clean_headers[index])]
            + [display_width(row[index]) for row in clean_rows]
        )
        if caps[index] > 0:
            widest = min(widest, caps[index])
        widths.append(widest)

    border = "+" + "+".join("-" * (width + 2) for width in widths) + "+"

    def render_row(cells: Sequence[str]) -> str:
        padded = [
            " " + pad(truncate(cell, widths[index]), widths[index]) + " "
            for index, cell in enumerate(cells)
        ]
        return "|" + "|".join(padded) + "|"

    lines = [border, render_row(clean_headers), border]
    lines.extend(render_row(row) for row in clean_rows)
    lines.append(border)
    return lines


def banner(title: str, width: int = TXT_WIDTH, char: str = _BANNER_CHAR) -> list[str]:
    """Render a banner with the title centred by display width.

    Parameters:
        title: Text to centre.
        width: Banner width in cells.
        char: Fill character, single code point.

    Raises:
        ValueError: When width is smaller than the title or char is not one
            code point.
    """

    if len(char) != 1:
        raise ValueError("banner fill must be one code point")
    title_cells = display_width(title)
    if title_cells > width:
        title = truncate(title, width)
        title_cells = display_width(title)
    left = (width - title_cells) // 2
    right = width - title_cells - left
    return [char * width, char * left + title + char * right, char * width]


def _label_row(label: str, value: str, label_width: int = 28) -> str:
    """Render one aligned identity row."""

    return "\u2022 " + pad(label, label_width) + ": " + value


def _slot_rows(report: DossierReport) -> list[list[str]]:
    """Build the actionable slot rows for SEC 3.

    A finding is actionable when its risk reaches four out of ten or when the
    probe attached a reproduction hint; everything else stays out of the fix list
    so the list keeps meaning.
    """

    rows: list[list[str]] = []
    for spec, finding in report.pillar_rows():
        if finding.risk < 4.0 and not finding.repro_hint:
            continue
        location = finding.slot("detail") or report.target
        repro = report.repro_file_for(spec.number) or "not generated"
        action = finding.slot("hotpatch") or finding.repro_hint or "review evidence and re-run"
        rows.append(
            [
                f"#{spec.number:02d}",
                location,
                f"[{finding.status}] {finding.detail}",
                repro,
                action,
            ]
        )
    return rows


def _render_text_body(report: DossierReport) -> str:
    """Render the plain text dossier body without the file trailer."""

    lines: list[str] = []
    lines.extend(banner("TAUHAULITY SECURITY & DAILY DEV-HEALTH DOSSIER (v0.2.0-beta)"))
    lines.append("Generated by: " + report.generated_by)
    lines.append("")

    card = report.scorecard
    lines.append(SECTION_HEADINGS[0])
    lines.append("-" * TXT_WIDTH)
    lines.append(_label_row("Security Score", f"{card.score} / {card.score_max}   (grade {card.grade}, {card.band})"))
    lines.append(_label_row("Aggregate Risk", f"{card.risk_total:.2f} / {card.risk_ceiling:.2f}"))
    lines.append(_label_row("Points Lost", f"{card.total_points_lost:.1f} of {card.score_max} across {len(card.deductions)} pillar(s)"))
    lines.append(_label_row("Headline", card.headline))
    if card.grade_note:
        lines.append(_label_row("Grade Note", card.grade_note))
    lines.append(
        "Score rule: a warning-level pillar loses at most its share (100 / 12) scaled by "
        "risk, floor 4; a critical pillar loses at least 18; an unobserved pillar loses 6. "
        "Bands A 90+, B 80+, C 70+, D 60+, F below; a CRITICAL verdict caps the grade at C."
    )
    lines.append("")
    if card.deductions:
        lines.append("Where the points went:")
        deduction_rows = [
            [
                f"P{pillar.number:02d}",
                pillar.status,
                f"-{pillar.points_lost:.1f}",
                f"{pillar.risk:.1f} / {pillar.risk_ceiling:.1f}",
                pillar.location or "-",
                pillar.evidence,
                pillar.recovery,
            ]
            for pillar in card.deductions
        ]
        lines.extend(
            table_lines(
                ["Pillar", "Status", "Lost", "Risk", "Location", "Evidence (why)", "How to regain"],
                deduction_rows,
                max_widths=[6, 16, 6, 12, 20, 30, 30],
            )
        )
        lines.append("")
    else:
        lines.append("No deductions: every pillar lost nothing.")
        lines.append("")

    lines.append(SECTION_HEADINGS[1])
    lines.append("-" * TXT_WIDTH)
    lines.append(_label_row("Target Name / Path", report.target))
    lines.append(_label_row("Host Operating System", report.os_label))
    lines.append(_label_row("Python Runtime Engine", report.python_label))
    lines.append(_label_row("Active Hardware Primitives", report.hardware_label))
    lines.append(_label_row("Scan Timestamp (UTC)", report.timestamp_utc))
    lines.append(
        _label_row(
            "Overall Security Verdict",
            f"{report.verdict.badge}  risk {report.verdict.risk:.2f} / 10.00",
        )
    )
    lines.append(_label_row("Findings Recorded", f"{len(report.findings)} / 12"))
    for note in report.verdict.notes:
        lines.append(_label_row("Verdict Note", note))
    lines.append("")

    lines.append(SECTION_HEADINGS[2])
    lines.append("-" * TXT_WIDTH)
    rows: list[list[str]] = []
    for spec, finding in report.pillar_rows():
        rows.append(
            [
                str(spec.number),
                spec.name,
                f"[ {finding.status} ]",
                f"{finding.risk:.1f}",
                spec.mechanism,
                finding.detail,
            ]
        )
    lines.extend(
        table_lines(
            ["#", "Pillar", "Status", "Risk", "Mechanism", "Finding"],
            rows,
            max_widths=[2, 28, 15, 6, 24, 26],
        )
    )
    lines.append("")

    lines.append(SECTION_HEADINGS[3])
    lines.append("-" * TXT_WIDTH)
    slot_rows = _slot_rows(report)
    if slot_rows:
        lines.extend(
            table_lines(
                ["Slot", "Location", "Issue", "Repro Test", "Action"],
                slot_rows,
                max_widths=[6, 30, 30, 16, 22],
            )
        )
    else:
        lines.append("No actionable slots: every finding stayed below risk 4.0 and carried no repro hint.")
    lines.append("")

    lines.append(SECTION_HEADINGS[4])
    lines.append("-" * TXT_WIDTH)
    lines.append("(Change [ ] to [x] or supply values in <...>, then run tauhaulity apply <file>)")
    lines.extend(render_form_lines(report.policy))
    lines.append("")

    lines.append(SECTION_HEADINGS[5])
    lines.append("-" * TXT_WIDTH)
    lines.append(_label_row("Algorithm", "HMAC-SHA256 over the canonical report payload"))
    lines.append(_label_row("Key", _key_description(report)))
    lines.append(_label_row("Digest", report.hmac or "UNSIGNED"))
    lines.append(_label_row("File stamp", "sha256 and hmac over every preceding byte, final line"))
    lines.append(
        "Verify with: tauhaulity verify <file>, "
        "tauhaulity.dossier.verify.verify_dossier_file(path)"
    )
    lines.append("")

    actions = report.hardening_actions
    lines.append(SECTION_HEADINGS[6])
    lines.append("-" * TXT_WIDTH)
    try:
        from tauhaulity.remediation import summarize

        lines.append(summarize(actions))
    except ImportError:
        lines.append(f"{len(actions)} action(s)")
    for index, action in enumerate(actions, start=1):
        lines.append(f"{index}. [{action.effort}] {action.title}")
        lines.append(f"   command : {action.command or 'manual step'}")
        lines.append(f"   detail  : {action.detail}")
    lines.append("")

    try:
        from tauhaulity.standards import explain, refs_for
    except ImportError:
        refs_for = None  # type: ignore[assignment]
    if refs_for is not None:
        mapping_rows = []
        for spec, finding in report.pillar_rows():
            refs = refs_for(spec.number, finding.status)
            if refs:
                mapping_rows.append(
                    [f"P{spec.number:02d}", ", ".join(ref.identifier for ref in refs), explain(spec.number)]
                )
        if mapping_rows:
            lines.append("SEC 7: FRAMEWORK MAPPING (MITRE ATT&CK / OWASP)")
            lines.append("-" * TXT_WIDTH)
            lines.append("Mappings of observed evidence, not an attestation of implemented controls.")
            lines.extend(
                table_lines(
                    ["Pillar", "References", "What it observes and what it does not"],
                    mapping_rows,
                    max_widths=[6, 26, 60],
                )
            )
            lines.append("")
    return "\n".join(lines)


def render_text(report: DossierReport, *, signing_key: bytes | None = None) -> str:
    """Render the complete plain text dossier.

    Parameters:
        report: Validated dossier snapshot.
        signing_key: Optional key override for the file trailer; the key stored
            on the report is preferred so a signed snapshot stays self consistent.

    Returns:
        The dossier text, UTF-8 safe, ending with a newline after the INTEGRITY
        trailer.
    """

    return stamp_report_text(_render_text_body(report), report, signing_key)


def render_text_with_width(
    report: DossierReport,
    width: int,
    *,
    signing_key: bytes | None = None,
) -> str:
    """Render the text dossier at a custom width.

    Used by tests and by terminals that are narrower than TXT_WIDTH. The body is
    re-truncated to the requested cell count so the invariants of the default
    renderer still hold; the INTEGRITY trailer is appended afterwards because it
    must never be truncated.

    Raises:
        ValueError: When width is smaller than the widest fixed label.
    """

    if width < 60:
        raise ValueError("text dossier needs at least 60 cells")
    body = _render_text_body(report)
    trimmed: list[str] = [truncate(line, width) for line in body.splitlines()]
    return stamp_report_text("\n".join(trimmed), report, signing_key)
