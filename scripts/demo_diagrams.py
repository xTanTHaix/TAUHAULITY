"""Render the two static demo diagrams as SVG from a real dossier snapshot.

The checked-in diagrams in docs/ are generated, never hand edited: an asset that
can disagree with the tool is a static claim, and this project does not ship
static claims. The scorecard diagram is driven by the same scorecard payload the
dossier exporter writes, and the architecture diagram is driven by the pillar
table below, which a test cross-checks against the pillar registry.

Design contract:

  * standard library only, no external fonts, no scripts, no external references;
  * every label is a text element, so the diagrams stay searchable and editable;
  * deterministic bytes: the same data renders the same characters, floats use a
    fixed number of decimals, the layout comes from module constants and text is
    emitted in a stable order;
  * every colour comes from PALETTE; lighter or darker shades are expressed with
    fill-opacity, stroke-opacity and stop-opacity instead of new hex values, so
    the palette can be audited by listing the hex literals in the emitted files;
  * text coming from a report is collapsed to one line, stripped to printable
    ASCII and truncated on a word boundary, so a hostile or non English evidence
    string cannot corrupt the markup.

Both files are drawn 960 px wide and scale through the viewBox. The files stay
under twelve kilobytes because the font family is declared once per text group
instead of once per label.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

__all__ = [
    "ARCHITECTURE_HEIGHT",
    "ARCHITECTURE_WIDTH",
    "CRITICAL_BAND_START",
    "Deduction",
    "EVIDENCE_CHAR_LIMIT",
    "PALETTE",
    "PALETTE_COLOURS",
    "PILLARS",
    "PillarNode",
    "SCORECARD_HEIGHT",
    "SCORECARD_WIDTH",
    "STAGES",
    "Scorecard",
    "VERSION",
    "coerce_scorecard",
    "render_architecture_svg",
    "render_scorecard_svg",
    "severity_for_points",
    "write_architecture_svg",
    "write_scorecard_svg",
]

#: The shared palette of the demo assets and the dossier terminal theme.
PALETTE: dict[str, str] = {
    "background": "#0b0f14",
    "panel": "#161b22",
    "border": "#30363d",
    "text": "#c9d1d9",
    "dim": "#8b949e",
    "green": "#3fb950",
    "amber": "#d29922",
    "red": "#f85149",
    "blue": "#58a6ff",
    "purple": "#bc8cff",
}

#: Every hex value the writers may emit. Exposed so a test can prove that no ad
#: hoc colour slipped into a diagram.
PALETTE_COLOURS: frozenset[str] = frozenset(PALETTE.values())

#: Release named in the footer when the caller does not pass one.
VERSION = "0.4.0"

SCORECARD_WIDTH = 960
SCORECARD_HEIGHT = 540
ARCHITECTURE_WIDTH = 960
ARCHITECTURE_HEIGHT = 600

#: Aggregate risk at which the gauge is drawn in the critical band. This is a
#: drawing convention, not a verdict rule: the verdict comes from the worst
#: pillar status (see tauhaulity.core.verdict) and the diagram description says
#: so, because a gauge that implied a threshold would be a false claim.
CRITICAL_BAND_START = 7.0

#: Longest evidence fragment that still fits one ledger row.
EVIDENCE_CHAR_LIMIT = 62

MONO_FONT = "ui-monospace, SFMono-Regular, Consolas, Menlo, monospace"
SANS_FONT = "system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif"

CRITICAL = 2
WARNING = 1
INFO = 0

_SEVERITY_ROLE: dict[int, str] = {CRITICAL: "red", WARNING: "amber", INFO: "blue"}
_SEVERITY_LABEL: dict[int, str] = {CRITICAL: "critical", WARNING: "warning", INFO: "info"}
_SEVERITY_ORDER: tuple[int, ...] = (CRITICAL, WARNING, INFO)

#: Deduction thresholds from the scoring contract: a critical pillar loses at
#: least eighteen points and a warning at least four (see
#: tauhaulity.core.scorecard.SEVERITY_FLOOR). A ledger row without an explicit
#: severity can therefore be classified from its own points, not from a guess.
_CRITICAL_POINTS = 18.0
_WARNING_POINTS = 4.0

_WHITESPACE = re.compile(r"\s+")
_NON_PRINTABLE = re.compile(r"[^\x20-\x7e]")


@dataclass(frozen=True, slots=True)
class Deduction:
    """One pillar that cost points, as drawn in the ledger.

    Attributes:
        pillar: Display token such as "P06".
        points: Points lost, one decimal.
        evidence: Finding detail; cleaned and truncated for the row.
        severity: 0 benign, 1 warning, 2 critical. None derives it from the
            points using the documented scoring floors.
    """

    pillar: str
    points: float
    evidence: str = ""
    severity: int | None = None

    @property
    def resolved_severity(self) -> int:
        """Return the severity class, derived from the points when not supplied."""

        if self.severity is not None:
            if self.severity >= CRITICAL:
                return CRITICAL
            return WARNING if self.severity >= WARNING else INFO
        return severity_for_points(self.points)


@dataclass(frozen=True, slots=True)
class Scorecard:
    """The scorecard section of a dossier, ready to be drawn.

    Attributes:
        score: Points kept out of score_max.
        score_max: Score ceiling, one hundred in every shipped release.
        grade: Letter grade, A to F.
        band: Grade band label such as STRONG or WEAK.
        verdict: Verdict name: SAFE, AT_RISK or CRITICAL.
        points_lost: Total points deducted across the ledger.
        risk_total: Aggregate risk on the zero to ten scale.
        risk_ceiling: Risk scale ceiling, ten in every shipped release.
        deductions: Ledger rows, most expensive first.
    """

    score: int
    score_max: int
    grade: str
    band: str
    verdict: str
    points_lost: float
    risk_total: float
    risk_ceiling: float
    deductions: tuple[Deduction, ...] = ()

    @classmethod
    def from_report(cls, payload: Mapping[str, Any]) -> "Scorecard":
        """Build a scorecard from the JSON dossier payload.

        Parameters:
            payload: Either the whole dossier document, in which case its
                "scorecard" section is used, or that section directly. The demo
                pipeline payload (score, grade, band, verdict, risk_total,
                risk_ceiling, total_points_lost, deductions) is accepted too.

        Raises:
            ValueError: When a required field is missing or not a number.
        """

        card = payload.get("scorecard", payload)
        if not isinstance(card, Mapping):
            raise ValueError("report payload has no scorecard mapping")
        for key in ("score", "score_max", "grade", "band", "verdict", "total_points_lost", "risk_total", "risk_ceiling"):
            if key not in card:
                raise ValueError(f"scorecard payload is missing {key!r}")
        rows: list[Deduction] = []
        for row in card.get("deductions") or ():
            if not isinstance(row, Mapping):
                continue
            severity = row.get("severity")
            rows.append(
                Deduction(
                    pillar=_pillar_token(row["pillar"]),
                    points=float(row["points_lost"]),
                    evidence=str(row.get("evidence", "")),
                    severity=int(severity) if isinstance(severity, (int, float)) else None,
                )
            )
        rows.sort(key=lambda item: (-item.points, item.pillar))
        return cls(
            score=int(card["score"]),
            score_max=int(card["score_max"]),
            grade=str(card["grade"]),
            band=str(card["band"]),
            verdict=str(card["verdict"]),
            points_lost=float(card["total_points_lost"]),
            risk_total=float(card["risk_total"]),
            risk_ceiling=float(card["risk_ceiling"]),
            deductions=tuple(rows),
        )

    @classmethod
    def from_digest(
        cls,
        card_lines: Iterable[tuple[str, str]],
        deductions: Iterable[tuple[str, str, str]],
    ) -> "Scorecard":
        """Build a scorecard from the legacy (label, value) and (pillar, points, reason) rows.

        The demo generator has always collected those tuples from a real scan, so
        this bridge keeps that data flow working while the drawing moves into
        this module. Values that cannot be parsed raise ValueError instead of
        silently rendering a zero.

        Parameters:
            card_lines: (label, value) pairs such as ("Security score",
                "63 / 100  (grade D, WEAK)").
            deductions: (pillar, points, evidence) triples such as
                ("P06", "-18.0", "payload.pkl: ...").

        Raises:
            ValueError: When the score line or the risk line is missing.
        """

        fields = {str(label).strip().lower(): str(value).strip() for label, value in card_lines}
        score_line = fields.get("security score", "")
        match = re.search(
            r"(-?\d+)\s*/\s*(\d+)\s*\(\s*grade\s*([A-Fa-f])\s*,\s*([^)]+?)\s*\)",
            score_line,
        )
        if match is None:
            raise ValueError(f"unparsable security score line: {score_line!r}")
        risk_line = fields.get("aggregate risk", "")
        risk_match = re.search(r"(-?\d+(?:\.\d+)?)\s*/\s*(\d+(?:\.\d+)?)", risk_line)
        if risk_match is None:
            raise ValueError(f"unparsable aggregate risk line: {risk_line!r}")
        rows: list[Deduction] = []
        for pillar, points, reason in deductions:
            rows.append(Deduction(pillar=_pillar_token(pillar), points=_as_float(points, "points"), evidence=str(reason)))
        rows.sort(key=lambda item: (-item.points, item.pillar))
        return cls(
            score=int(match.group(1)),
            score_max=int(match.group(2)),
            grade=match.group(3).upper(),
            band=match.group(4).strip().upper(),
            verdict=fields.get("verdict", "UNKNOWN").upper(),
            points_lost=_as_float(fields.get("points lost", "0"), "points lost"),
            risk_total=float(risk_match.group(1)),
            risk_ceiling=float(risk_match.group(2)),
            deductions=tuple(rows),
        )


@dataclass(frozen=True, slots=True)
class PillarNode:
    """One pillar as drawn in the architecture diagram.

    Attributes:
        number: Pillar number, one through twelve.
        key: Machine readable pillar key from the registry.
        stage: Stage group: environment, supply chain, runtime or reporting.
        label: Short label that fits one chip, at most 34 characters.
    """

    number: int
    key: str
    stage: str
    label: str


#: Stage groups in drawing order with their one line captions.
STAGES: tuple[tuple[str, str], ...] = (
    ("environment", "host and interpreter integrity"),
    ("supply chain", "code and dependency trust"),
    ("runtime", "live behaviour in the project"),
    ("reporting", "evidence that leaves the run"),
)

#: The twelve pillars, grouped by stage. The numbers and keys are cross-checked
#: against tauhaulity.core.contracts.PILLAR_SPECS by the static SVG test, so a
#: pillar rename fails the suite instead of silently leaving the diagram stale.
PILLARS: tuple[PillarNode, ...] = (
    PillarNode(1, "aegis_vmi", "environment", "memory and GOT/IAT"),
    PillarNode(2, "hyper_immune", "environment", "syscall boundary"),
    PillarNode(3, "veritas_gate", "environment", "privilege gate"),
    PillarNode(5, "crypto_shield", "environment", "in-memory keys"),
    PillarNode(6, "supply_guard", "supply chain", "package and pickle gate"),
    PillarNode(10, "autonomic_venv", "supply chain", "venv and shard radar"),
    PillarNode(11, "git_dossier", "supply chain", "git sentinel and gate"),
    PillarNode(4, "chrono_deception", "runtime", "mirage readiness"),
    PillarNode(7, "egress_dlp", "runtime", "egress leak detection"),
    PillarNode(8, "ransom_dev_undo", "runtime", "undo ring and canaries"),
    PillarNode(9, "port_sentinel", "runtime", "ports and process lineage"),
    PillarNode(12, "auto_repro", "reporting", "repro synthesis"),
)


def _pillar_token(value: Any) -> str:
    """Return the ledger token for a pillar number or display token.

    Accepts 6, "6", "P06" and "p6" so a caller can pass either the JSON number or
    the rendered token without the writer guessing which one it got.

    Raises:
        ValueError: When the value carries no digits at all.
    """

    digits = re.sub(r"\D", "", str(value))
    if not digits:
        raise ValueError(f"pillar value has no number: {value!r}")
    return f"P{int(digits):02d}"


def severity_for_points(points: float) -> int:
    """Return the severity class implied by a deduction, using the scoring floors."""

    if points >= _CRITICAL_POINTS:
        return CRITICAL
    if points >= _WARNING_POINTS:
        return WARNING
    return INFO


# --------------------------------------------------------------------------- #
# Deterministic text and attribute helpers
# --------------------------------------------------------------------------- #


def _n(value: float) -> str:
    """Format one coordinate or length with at most two decimals."""

    text = f"{float(value):.2f}"
    if text.endswith(".00"):
        return text[:-3]
    return text.rstrip("0").rstrip(".") if "." in text else text


def _escape(text: str) -> str:
    """Escape one text node for XML."""

    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def _clean(text: Any) -> str:
    """Return printable ASCII on one line, with typographic dashes normalised."""

    body = str(text)
    for dash in ("\u2014", "\u2013", "\u2012", "\u2212"):
        body = body.replace(dash, "-")
    body = body.replace("\u2026", "...")
    body = _WHITESPACE.sub(" ", body).strip()
    return _NON_PRINTABLE.sub("?", body)


def _truncate(text: str, limit: int) -> str:
    """Cut text on the last word boundary that fits, adding an ASCII ellipsis."""

    body = _clean(text)
    if len(body) <= limit:
        return body
    head = body[: max(limit - 3, 1)]
    if " " in head:
        head = head.rsplit(" ", 1)[0]
    return head.rstrip(" .,;:") + "..."


def _attrs(**pairs: Any) -> str:
    """Render attributes in call order, skipping None values, underscores to dashes."""

    parts: list[str] = []
    for key, value in pairs.items():
        if value is None:
            continue
        parts.append(f'{key.replace("_", "-")}="{value}"')
    return " ".join(parts)


def _text(
    x: float,
    y: float,
    body: str,
    *,
    size: float,
    fill: str,
    weight: str | None = None,
    anchor: str | None = None,
    spacing: float | None = None,
) -> str:
    """Return one text element, to be placed inside a font family group."""

    attrs = _attrs(
        x=_n(x),
        y=_n(y),
        font_size=_n(size),
        font_weight=weight,
        text_anchor=anchor,
        letter_spacing=None if spacing is None else _n(spacing),
        fill=fill,
    )
    return f"    <text {attrs}>{_escape(_clean(body))}</text>"


def _rect(
    x: float,
    y: float,
    width: float,
    height: float,
    *,
    fill: str,
    rx: float | None = None,
    stroke: str | None = None,
    stroke_width: float | None = None,
    fill_opacity: float | None = None,
) -> str:
    """Return one rectangle element. stroke-width and rx are omitted at defaults."""

    attrs = _attrs(
        x=_n(x),
        y=_n(y),
        width=_n(width),
        height=_n(height),
        rx=None if rx is None else _n(rx),
        fill=fill,
        fill_opacity=fill_opacity,
        stroke=stroke,
        stroke_width=stroke_width,
    )
    return f"  <rect {attrs}/>"


def _document(width: int, height: int, title: str, desc: str, *, shapes: Sequence[str], sans: Sequence[str], mono: Sequence[str]) -> str:
    """Assemble the document with the shared prologue and the two font groups."""

    lines = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" '
        f'width="{width}" height="{height}" role="img" aria-labelledby="diagram-title diagram-desc">',
        f'  <title id="diagram-title">{_escape(_clean(title))}</title>',
        f'  <desc id="diagram-desc">{_escape(_clean(desc))}</desc>',
    ]
    lines.extend(shapes)
    if sans:
        lines.append(f'  <g font-family="{SANS_FONT}">')
        lines.extend(sans)
        lines.append("  </g>")
    if mono:
        lines.append(f'  <g font-family="{MONO_FONT}">')
        lines.extend(mono)
        lines.append("  </g>")
    lines.append("</svg>")
    return chr(10).join(lines)


def _write_svg(path: Path, document: str) -> Path:
    """Write the document with LF line endings and one trailing newline."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(document + chr(10), encoding="utf-8", newline=chr(10))
    return path


# --------------------------------------------------------------------------- #
# Scorecard diagram
# --------------------------------------------------------------------------- #


def render_scorecard_svg(card: Scorecard, *, version: str = VERSION) -> str:
    """Return the scorecard diagram as a deterministic SVG string.

    Parameters:
        card: Scorecard snapshot; every drawn number comes from it.
        version: Release shown in the footer.

    Returns:
        The complete document without a trailing newline, so the caller controls
        the file bytes.
    """

    score_max = card.score_max if card.score_max > 0 else 100
    score_text = str(card.score)
    big_size = 76 if len(score_text) <= 2 else 64
    suffix_x = 58 + len(score_text) * 0.6 * big_size + 14
    risk_ceiling = card.risk_ceiling if card.risk_ceiling > 0 else 10.0
    risk_ratio = min(max(card.risk_total / risk_ceiling, 0.0), 1.0)
    band_fraction = min(max(CRITICAL_BAND_START / risk_ceiling, 0.0), 1.0)

    track_x, track_w, track_h = 480.0, 424.0, 18.0
    band_x = track_x + track_w * band_fraction
    band_w = track_w - track_w * band_fraction
    marker_x = track_x + track_w * risk_ratio
    risk_role = "red" if risk_ratio >= band_fraction else "amber" if risk_ratio >= 0.4 else "green"

    bar_x, bar_y, bar_w, bar_h = 60.0, 304.0, 840.0, 26.0
    deductions = tuple(row for row in card.deductions if row.points > 0)
    segments = _ledger_segments(deductions, bar_x, bar_w)
    severity_present = {row.resolved_severity for row in deductions}
    grade_role = "green" if card.grade.upper() in {"A", "B"} else "amber" if card.grade.upper() in {"C", "D"} else "red"

    shapes: list[str] = []
    sans: list[str] = []
    mono: list[str] = []

    shapes.extend(
        [
            "  <defs>",
            '    <linearGradient id="card-face" x1="0" y1="0" x2="0" y2="1">',
            f'      <stop offset="0" stop-color="{PALETTE["panel"]}" stop-opacity="0.92"/>',
            f'      <stop offset="1" stop-color="{PALETTE["panel"]}" stop-opacity="0.58"/>',
            "    </linearGradient>",
            '    <clipPath id="ledger-clip">',
            "      " + _rect(bar_x, bar_y, bar_w, bar_h, fill=PALETTE["panel"], rx=8).strip(),
            "    </clipPath>",
            "  </defs>",
        ]
    )
    shapes.append(_rect(0, 0, SCORECARD_WIDTH, SCORECARD_HEIGHT, fill=PALETTE["background"]))
    shapes.append(
        _rect(24, 20, 912, 500, fill="url(#card-face)", rx=18, stroke=PALETTE["border"], stroke_width=1.5)
    )
    chip_fill = PALETTE["red"] if card.verdict.upper() == "CRITICAL" else PALETTE["amber"]
    shapes.append(_rect(724, 46, 188, 34, fill=chip_fill, rx=17, fill_opacity=0.12, stroke=chip_fill))
    shapes.append(f'  <circle cx="748" cy="63" r="4" fill="{chip_fill}"/>')
    shapes.append(_rect(56, 116, 848, 1, fill=PALETTE["border"]))
    shapes.append(_rect(250, 164, 132, 44, fill=PALETTE[grade_role], rx=10))
    shapes.append(_rect(track_x, 164, track_w, track_h, fill=PALETTE["panel"], rx=9, stroke=PALETTE["border"]))
    shapes.append(_rect(band_x, 164, band_w, track_h, fill=PALETTE["red"], rx=9, fill_opacity=0.28))
    shapes.append(_rect(marker_x - 3.5, 158, 7, 30, fill=PALETTE[risk_role], rx=3.5))
    shapes.append(_rect(56, 262, 848, 1, fill=PALETTE["border"]))
    shapes.append(_rect(bar_x, bar_y, bar_w, bar_h, fill=PALETTE["panel"], rx=8, stroke=PALETTE["border"]))
    if segments:
        shapes.append('  <g clip-path="url(#ledger-clip)">')
        for index, (segment_x, segment_w, row) in enumerate(segments):
            role = _SEVERITY_ROLE[row.resolved_severity]
            shapes.append("    " + _rect(segment_x, bar_y, segment_w, bar_h, fill=PALETTE[role]).strip())
            if index:
                shapes.append(
                    "    " + _rect(segment_x - 0.75, bar_y, 1.5, bar_h, fill=PALETTE["background"]).strip()
                )
        shapes.append("  </g>")
    for index, row in enumerate(deductions[:3]):
        role = _SEVERITY_ROLE[row.resolved_severity]
        shapes.append(_rect(60, 396 + index * 26 - 9, 11, 11, fill=PALETTE[role], rx=2.5))
    legend_x = 60.0
    for severity in _SEVERITY_ORDER:
        if severity not in severity_present:
            continue
        shapes.append(_rect(legend_x, 339, 10, 10, fill=PALETTE[_SEVERITY_ROLE[severity]], rx=2))
        legend_x += 62 + len(_SEVERITY_LABEL[severity]) * 3
    shapes.append(_rect(56, 464, 848, 1, fill=PALETTE["border"]))

    # Header and score block.
    sans.append(_text(60, 70, "SECURITY SCORECARD", size=22, fill=PALETTE["text"], weight="600", spacing=0.5))
    sans.append(_text(60, 93, "score, grade and the deduction ledger, from one read only scan", size=12.5, fill=PALETTE["dim"]))
    mono.append(_text(762, 67.5, f"VERDICT {card.verdict}", size=12, fill=chip_fill, weight="600", spacing=0.6))
    sans.append(_text(60, 146, "SCORE", size=10.5, fill=PALETTE["dim"], spacing=1.6))
    mono.append(_text(58, 222, score_text, size=big_size, fill=PALETTE["text"], weight="700", spacing=-2))
    mono.append(_text(suffix_x, 220, f"/ {score_max}", size=19, fill=PALETTE["dim"]))
    mono.append(_text(316, 193, f"GRADE {card.grade}", size=19, fill=PALETTE["background"], weight="700", anchor="middle"))
    sans.append(_text(316, 232, card.band.upper(), size=11.5, fill=PALETTE[grade_role], anchor="middle", spacing=2))

    # Aggregate risk gauge.
    sans.append(_text(480, 146, "AGGREGATE RISK", size=10.5, fill=PALETTE["dim"], spacing=1.6))
    mono.append(
        _text(904, 146, f"{card.risk_total:.2f} / {risk_ceiling:.2f}", size=12.5, fill=PALETTE[risk_role], anchor="end")
    )
    mono.append(_text(band_x + band_w / 2, 177.5, "CRITICAL BAND", size=9, fill=PALETTE["red"], anchor="middle", spacing=0.8))
    for value in (0.0, risk_ceiling / 2, risk_ceiling):
        anchor = "start" if value == 0.0 else "middle" if value < risk_ceiling else "end"
        sans.append(_text(track_x + track_w * (value / risk_ceiling), 200, f"{value:g}", size=9.5, fill=PALETTE["dim"], anchor=anchor))

    # Deduction ledger.
    sans.append(_text(60, 290, "DEDUCTION LEDGER", size=11, fill=PALETTE["dim"], spacing=1.6))
    mono.append(
        _text(
            904,
            290,
            f"{card.points_lost:.1f} POINTS LOST ACROSS {len(deductions)} PILLAR(S)",
            size=11,
            fill=PALETTE["dim"],
            anchor="end",
        )
    )
    if segments:
        for segment_x, segment_w, row in segments:
            if segment_w >= 92:
                mono.append(
                    _text(segment_x + 16, 321.5, f"{row.pillar} -{row.points:.1f}", size=12, fill=PALETTE["background"], weight="700")
                )
    else:
        sans.append(_text(bar_x + bar_w / 2, 321.5, "no points lost", size=11, fill=PALETTE["dim"], anchor="middle"))
    if severity_present:
        legend_x = 60.0
        for severity in _SEVERITY_ORDER:
            if severity not in severity_present:
                continue
            sans.append(_text(legend_x + 16, 348, _SEVERITY_LABEL[severity], size=10, fill=PALETTE["dim"]))
            legend_x += 62 + len(_SEVERITY_LABEL[severity]) * 3
    else:
        sans.append(_text(60, 348, "every pillar kept its points", size=10, fill=PALETTE["dim"]))

    # Ledger table.
    sans.append(_text(84, 372, "PILLAR", size=9.5, fill=PALETTE["dim"], spacing=1.2))
    sans.append(_text(176, 372, "POINTS", size=9.5, fill=PALETTE["dim"], anchor="end", spacing=1.2))
    sans.append(_text(200, 372, "SEVERITY", size=9.5, fill=PALETTE["dim"], spacing=1.2))
    sans.append(_text(276, 372, "EVIDENCE", size=9.5, fill=PALETTE["dim"], spacing=1.2))
    for index, row in enumerate(deductions[:3]):
        row_y = 396 + index * 26
        role = _SEVERITY_ROLE[row.resolved_severity]
        mono.append(_text(84, row_y, row.pillar, size=11.5, fill=PALETTE[role], weight="600"))
        mono.append(_text(176, row_y, f"-{row.points:.1f}", size=11.5, fill=PALETTE["text"], anchor="end"))
        sans.append(_text(200, row_y, _SEVERITY_LABEL[row.resolved_severity], size=10.5, fill=PALETTE[role]))
        sans.append(_text(276, row_y, _truncate(row.evidence, EVIDENCE_CHAR_LIMIT), size=10.5, fill=PALETTE["dim"]))
    if not deductions:
        sans.append(_text(60, 400, "no deductions: the ledger is empty for this project", size=10.5, fill=PALETTE["dim"]))

    # Footer.
    mono.append(_text(60, 488, f"TAUHAULITY {_clean(version)}", size=10.5, fill=PALETTE["dim"]))
    sans.append(_text(904, 488, "read only scan of a throwaway project, one bounded score", size=10, fill=PALETTE["dim"], anchor="end"))

    title = (
        f"Tauhaulity security scorecard: {card.score} of {score_max}, grade {card.grade}, "
        f"aggregate risk {card.risk_total:.2f} of {risk_ceiling:.2f}, {len(deductions)} pillar(s) deducted"
    )
    desc = (
        "Generated from a real audit. The card shows the bounded score and letter grade, the "
        "aggregate risk gauge with its critical band, and the deduction ledger as one bar segment "
        "per pillar that lost points, coloured by severity, with the evidence text. The verdict "
        "comes from the worst pillar status; the gauge band is a drawing guide."
    )
    return _document(SCORECARD_WIDTH, SCORECARD_HEIGHT, title, desc, shapes=shapes, sans=sans, mono=mono)


def _ledger_segments(deductions: Sequence[Deduction], x: float, width: float) -> list[tuple[float, float, Deduction]]:
    """Return (x, width, row) bar segments that divide width exactly."""

    total = sum(row.points for row in deductions)
    if total <= 0:
        return []
    segments: list[tuple[float, float, Deduction]] = []
    cursor = x
    for index, row in enumerate(deductions):
        if index == len(deductions) - 1:
            segment_w = x + width - cursor
        else:
            segment_w = round(row.points / total * width, 2)
        segments.append((cursor, segment_w, row))
        cursor += segment_w
    return segments


def coerce_scorecard(data: Scorecard | Mapping[str, Any]) -> Scorecard:
    """Return a Scorecard from either a snapshot or a demo pipeline payload.

    Parameters:
        data: A Scorecard, or a mapping shaped like the dossier JSON (the whole
            document or its scorecard section, as accepted by from_report).

    Raises:
        TypeError: When data is neither a Scorecard nor a mapping.
    """

    if isinstance(data, Scorecard):
        return data
    if isinstance(data, Mapping):
        return Scorecard.from_report(data)
    raise TypeError(f"expected a Scorecard or a mapping, got {type(data).__name__}")


def write_scorecard_svg(path: Path, data: Scorecard | Mapping[str, Any]) -> Path:
    """Write the scorecard diagram to path and return it.

    Parameters:
        path: Destination file; parent directories are created.
        data: A Scorecard snapshot, or a demo pipeline payload mapping containing
            the scorecard fields (optional "version" names the footer; extra keys
            are ignored).
    """

    version = VERSION
    if isinstance(data, Mapping):
        candidate = data.get("version")
        if isinstance(candidate, str) and candidate.strip():
            version = candidate.strip()
    return _write_svg(path, render_scorecard_svg(coerce_scorecard(data), version=version))


# --------------------------------------------------------------------------- #
# Architecture diagram
# --------------------------------------------------------------------------- #


def render_architecture_svg(pillars: Sequence[PillarNode] | None = None, *, version: str = VERSION) -> str:
    """Return the scan flow and containment diagram as a deterministic SVG string.

    Parameters:
        pillars: Optional pillar table override; defaults to PILLARS.
        version: Release shown under the footer strip.

    Raises:
        ValueError: When a pillar names an unknown stage or the table is empty.
    """

    table = tuple(pillars if pillars is not None else PILLARS)
    if not table:
        raise ValueError("the architecture diagram needs at least one pillar")
    known = {name for name, _caption in STAGES}
    unknown = sorted({node.stage for node in table} - known)
    if unknown:
        raise ValueError(f"unknown pillar stage(s): {', '.join(unknown)}")

    stage_role = {"environment": "blue", "supply chain": "amber", "runtime": "green", "reporting": "purple"}
    shapes: list[str] = []
    sans: list[str] = []
    mono: list[str] = []

    shapes.append("  <defs>")
    for name, role in (("delta", "blue"), ("handoff", "green")):
        shapes.append(
            f'    <marker id="arrow-{name}" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="7" markerHeight="7" '
            f'orient="auto"><path d="M0 0 L8 4 L0 8 z" fill="{PALETTE[role]}"/></marker>'
        )
    shapes.append("  </defs>")
    shapes.append(_rect(0, 0, ARCHITECTURE_WIDTH, ARCHITECTURE_HEIGHT, fill=PALETTE["background"]))

    # Header and column headings.
    sans.append(_text(40, 54, "SCAN FLOW AND CONTAINMENT", size=21, fill=PALETTE["text"], weight="600", spacing=0.5))
    sans.append(_text(40, 78, "twelve read only pillar probes, one dossier, a narrow containment layer", size=12, fill=PALETTE["dim"]))
    sans.append(_text(40, 116, "PILLAR SWEEP BY STAGE", size=10, fill=PALETTE["dim"], spacing=1.6))

    # Left column: the pillar sweep, grouped by stage.
    cursor = 140.0
    for stage, caption in STAGES:
        nodes = [node for node in table if node.stage == stage]
        role = stage_role[stage]
        sans.append(_text(40, cursor, stage.upper(), size=9.5, fill=PALETTE[role], weight="600", spacing=1.4))
        sans.append(_text(278, cursor, caption, size=9.5, fill=PALETTE["dim"], anchor="end"))
        cursor += 8
        for node in nodes:
            shapes.append(_rect(40, cursor, 242, 20, fill=PALETTE["panel"], rx=6, stroke=PALETTE["border"]))
            shapes.append(_rect(40, cursor, 4, 20, fill=PALETTE[role], rx=2))
            sans.append(
                _text(
                    54,
                    cursor + 14,
                    f"P{node.number:02d}  {_truncate(node.label, 34)}",
                    size=9.5,
                    fill=PALETTE["text"],
                )
            )
            cursor += 24
        cursor += 10

    # Middle column: target, evidence, dossier.
    flow = (
        (132.0, "blue", "TARGET PROJECT", "the directory you point at", "nothing is written outside it"),
        (288.0, "green", "EVIDENCE", "twelve read only pillar findings", "bounded score and deduction ledger"),
        (414.0, "purple", "DOSSIER", "md, txt and json with an HMAC stamp", "the report you keep and verify"),
    )
    for top, role, title, subtitle, detail in flow:
        shapes.append(_rect(314, top, 312, 78, fill=PALETTE["panel"], rx=12, stroke=PALETTE["border"], stroke_width=1.5))
        shapes.append(_rect(314, top, 5, 78, fill=PALETTE[role], rx=2.5))
        sans.append(_text(332, top + 28, title, size=12.5, fill=PALETTE[role], weight="600", spacing=0.8))
        sans.append(_text(332, top + 48, subtitle, size=10, fill=PALETTE["text"]))
        sans.append(_text(332, top + 64, detail, size=9.5, fill=PALETTE["dim"]))

    # Connectors: target to the sweep, the sweep to evidence, evidence to dossier.
    shapes.append(
        '  <path d="M 314 158 H 284" fill="none" '
        f'stroke="{PALETTE["blue"]}" stroke-width="1.5" marker-end="url(#arrow-delta)"/>'
    )
    shapes.append(
        '  <path d="M 282 476 H 296 Q 306 476 306 466 V 339 Q 306 329 314 329" fill="none" '
        f'stroke="{PALETTE["blue"]}" stroke-width="1.5" marker-end="url(#arrow-delta)"/>'
    )
    shapes.append(
        '  <path d="M 470 366 V 408" fill="none" '
        f'stroke="{PALETTE["green"]}" stroke-width="1.5" marker-end="url(#arrow-handoff)"/>'
    )

    # Right column: the containment layer as its own panel.
    shapes.append(_rect(658, 110, 270, 396, fill=PALETTE["panel"], rx=14, stroke=PALETTE["border"], stroke_width=1.5))
    sans.append(_text(676, 138, "CONTAINMENT LAYER", size=12, fill=PALETTE["text"], weight="600", spacing=0.6))
    sans.append(_text(676, 158, "opt in, reversible, armed by you", size=9.5, fill=PALETTE["dim"]))
    controls = (
        ("blue", "shield", "denies third party sockets", "process spawns and secret reads"),
        ("amber", "quarantine", "moves a dangerous artefact", "out of the load path, reversible"),
        ("red", "commit gate", "blocks a staged credential", "before the commit is created"),
        ("purple", "canary farm", "alerts on the first read", "of a deployed decoy file"),
    )
    for index, (role, name, first, second) in enumerate(controls):
        top = 172 + index * 80
        shapes.append(_rect(674, top, 238, 68, fill=PALETTE["background"], rx=9, stroke=PALETTE["border"]))
        shapes.append(_rect(674, top + 10, 3, 48, fill=PALETTE[role], rx=1.5))
        shapes.append(
            _rect(858, top + 9, 48, 17, fill=PALETTE["amber"], rx=8.5, fill_opacity=0.14, stroke=PALETTE["amber"])
        )
        sans.append(_text(688, top + 22, name, size=11.5, fill=PALETTE[role], weight="600"))
        sans.append(_text(688, top + 38, first, size=9.5, fill=PALETTE["dim"]))
        sans.append(_text(688, top + 52, second, size=9.5, fill=PALETTE["dim"]))
        mono.append(_text(882, top + 20.5, "OPT IN", size=8, fill=PALETTE["amber"], weight="600", anchor="middle", spacing=0.6))

    # Footer strip: the honest boundary.
    shapes.append(_rect(32, 522, 896, 44, fill=PALETTE["panel"], rx=10, stroke=PALETTE["border"]))
    sans.append(_text(480, 549, "Detection is broad, prevention is narrow and opt in.", size=12.5, fill=PALETTE["text"], anchor="middle"))
    mono.append(_text(52, 549, f"TAUHAULITY {_clean(version)}", size=9.5, fill=PALETTE["dim"]))

    title = "Tauhaulity scan flow and containment layer"
    desc = (
        "Generated diagram of one scan. The left column lists the twelve read only pillar probes by "
        "stage: environment, supply chain, runtime and reporting. The middle flow runs from the "
        "target project to evidence and then to the dossier. The right panel is the containment "
        "layer: shield, quarantine, commit gate and canary farm, every one opt in and reversible. "
        "The footer states the boundary: detection is broad, prevention is narrow and opt in."
    )
    return _document(ARCHITECTURE_WIDTH, ARCHITECTURE_HEIGHT, title, desc, shapes=shapes, sans=sans, mono=mono)


def write_architecture_svg(
    path: Path,
    data: Mapping[str, Any] | Sequence[PillarNode] | None = None,
) -> Path:
    """Write the architecture diagram to path and return it.

    Parameters:
        path: Destination file; parent directories are created.
        data: Optional demo pipeline payload. A mapping may carry "version" for
            the footer and is otherwise ignored, because the pillar table is owned
            by this module and cross-checked against the registry by the tests. A
            sequence of PillarNode overrides the table instead.
    """

    pillars: Sequence[PillarNode] | None = None
    version = VERSION
    if isinstance(data, Mapping):
        candidate = data.get("version")
        if isinstance(candidate, str) and candidate.strip():
            version = candidate.strip()
    elif data is not None:
        pillars = data
    return _write_svg(path, render_architecture_svg(pillars, version=version))


def _as_float(value: Any, field: str) -> float:
    """Convert a digest field to float, raising a named error instead of guessing."""

    try:
        return float(str(value).strip())
    except (TypeError, ValueError) as exc:
        raise ValueError(f"unparsable {field} value: {value!r}") from exc
