"""Markdown dossier renderer.

Markdown is the format a developer signs off on, so the twelve pillar matrix and
the SEC 4 checkbox form must stay machine readable while still rendering nicely in
a browser. Cells are escaped for pipes and flattened to one line so a finding
cannot break the table, and the form block is delegated to form_parser so the
parser can round-trip exactly what a reviewer sees.

The rendered document ends with the format independent INTEGRITY trailer built by
tauhaulity.dossier.integrity, so a reader can prove that the bytes they hold are
the bytes that were written.
"""

from __future__ import annotations

from typing import Final

from tauhaulity.dossier.form_parser import render_form_lines
from tauhaulity.dossier.integrity import stamp_report_text
from tauhaulity.dossier.model import SECTION_HEADINGS, DossierReport

_TITLE: Final[str] = "TAUHAULITY SECURITY & DAILY DEV-HEALTH DOSSIER (v0.2.0-beta)"

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


def _cell(text: str) -> str:
    """Flatten text into a single Markdown table cell.

    A raw pipe would split the cell and a newline would end the row, so both are
    replaced. Backslashes are escaped first so an evidence path stays readable.
    """

    flattened = str(text).replace("\\", "\\\\").replace("\r", " ").replace("\n", " ")
    return flattened.replace("|", "\\|")


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    """Render a Markdown table from already built rows."""

    lines = [
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    for row in rows:
        lines.append("| " + " | ".join(row) + " |")
    return lines


def _identity_lines(report: DossierReport) -> list[str]:
    """Render the SEC 1 identity block as a label list."""

    return [
        f"- Target Name / Path        : {report.target}",
        f"- Host Operating System     : {report.os_label}",
        f"- Python Runtime Engine     : {report.python_label}",
        f"- Active Hardware Primitives: {report.hardware_label}",
        f"- Scan Timestamp (UTC)      : {report.timestamp_utc}",
        f"- Overall Security Verdict  : {report.verdict.badge} (risk {report.verdict.risk:.2f} / 10.00)",
        f"- Findings Recorded         : {len(report.findings)} / 12",
    ] + [f"- Verdict Note              : {note}" for note in report.verdict.notes]


def _pillar_table(report: DossierReport) -> list[str]:
    """Render the twelve row pillar matrix."""

    rows: list[list[str]] = []
    for spec, finding in report.pillar_rows():
        rows.append(
            [
                str(spec.number),
                _cell(spec.name),
                f"[ {_cell(finding.status)} ]",
                _cell(spec.mechanism),
                _cell(finding.detail),
                f"{finding.risk:.1f} / {spec.risk_scale:.1f}",
            ]
        )
    return _table(["#", "Pillar", "Status", "Mechanism", "Finding", "Risk"], rows)


def _slot_table(report: DossierReport) -> list[str]:
    """Render the SEC 3 actionable slot table or an explicit empty statement."""

    rows: list[list[str]] = []
    for spec, finding in report.pillar_rows():
        if finding.risk < 4.0 and not finding.repro_hint:
            continue
        rows.append(
            [
                f"#{spec.number:02d}",
                _cell(finding.slot("detail") or report.target),
                _cell(f"[{finding.status}] {finding.detail}"),
                _cell(report.repro_file_for(spec.number) or "not generated"),
                _cell(
                    finding.slot("hotpatch")
                    or finding.repro_hint
                    or "review evidence and re-run"
                ),
            ]
        )
    if not rows:
        return [
            "_No actionable slots: every finding stayed below risk 4.0 and carried no repro hint._"
        ]
    return _table(["Slot", "Location", "Issue", "Repro Test", "Action"], rows)




def _scorecard_lines(report: DossierReport) -> list[str]:
    """Render SEC 0: the score, its ceiling, the grade and the deduction ledger.

    The ledger answers "where did the points go": one row per pillar that cost
    anything, ordered by cost, naming the evidence and the way to earn the points
    back. Pillars that lost nothing are listed separately so credit is visible
    instead of implied by absence.
    """

    card = report.scorecard
    rows: list[list[str]] = []
    for pillar in card.deductions:
        rows.append(
            [
                f"P{pillar.number:02d}",
                _cell(pillar.name),
                f"[ {pillar.status} ]",
                f"{pillar.points_lost:.1f} of {pillar.weight:.1f}",
                f"{pillar.risk:.1f} / {pillar.risk_ceiling:.1f}",
                _cell(pillar.location or "-"),
                _cell(pillar.evidence),
                _cell(pillar.recovery),
            ]
        )
    lines: list[str] = [
        f"- Security score        : {card.score} / {card.score_max}  (grade {card.grade}, {card.band})",
        f"- Aggregate risk        : {card.risk_total:.2f} / {card.risk_ceiling:.2f}",
        f"- Points lost           : {card.total_points_lost:.1f} of {card.score_max} across {len(card.deductions)} pillar(s)",
        f"- Verdict               : {report.verdict.name}",
        f"- Headline              : {card.headline}",
        "",
        "Score rule: every pillar carries a normal share of "
        f"{100 / len(card.pillars):.2f} points. A warning-level pillar loses at most its "
        "share, scaled by risk, with a floor of 4 points; a critical pillar loses at "
        "least 18 points because severity is not proportional to one twelfth; a pillar "
        "that did not run loses 6. Bands: A 90+, B 80+, C 70+, D 60+, F below, and a "
        "CRITICAL verdict caps the grade at C.",
        "",
    ]
    if card.grade_note:
        lines.append(f"- Grade note            : {card.grade_note}")
        lines.append("")
    if rows:
        lines.extend(
            _table(
                ["Pillar", "Name", "Status", "Points lost", "Risk", "Location", "Evidence (why)", "How to regain"],
                rows,
            )
        )
    else:
        lines.append("_No deductions: every pillar lost nothing._")
    lines.append("")
    if card.credit:
        lines.append("Pillars that cost nothing (verified clean or already protected):")
        lines.append("")
        for entry in card.credit[:6]:
            lines.append("- " + _cell(entry))
        extra = len(card.credit) - 6
        if extra > 0:
            lines.append(f"- and {extra} more pillar(s)")
        lines.append("")
    return lines


def _remediation_lines(report: DossierReport) -> list[str]:
    """Render SEC 6: ordered hardening actions, or nothing when unavailable."""

    try:
        from tauhaulity.remediation import render_actions, summarize
    except ImportError:
        # The remediation module is optional in a partial checkout; the section
        # still appears, stating that the plan is unavailable rather than
        # silently looking like there is nothing to do.
        return ["## " + SECTION_HEADINGS[6], "", "_Hardening plan unavailable: tauhaulity.remediation is not installed._", ""]
    actions = report.hardening_actions
    lines = ["## " + SECTION_HEADINGS[6], "", summarize(actions), ""]
    if actions:
        lines.append("| # | Action | Effort | Command | Framework |")
        lines.append("|---|---|---|---|---|")
        for index, action in enumerate(actions, start=1):
            command = "`" + action.command + "`" if action.command else "manual step"
            lines.append(
                f"| {index} | {_cell(action.title)} | {action.effort} | {command} | {action.reference or chr(45)} |"
            )
        lines.append("")
        lines.append("Details:")
        lines.append("")
        for line in render_actions(actions, width=140):
            lines.append("- " + line)
    else:
        lines.append("_No hardening action is required by the current findings._")
    lines.append("")
    return lines


def _standards_lines(report: DossierReport) -> list[str]:
    """Render the framework mapping table, or nothing when the module is absent."""

    try:
        from tauhaulity.standards import explain, refs_for
    except ImportError:
        return []
    rows: list[list[str]] = []
    for spec, finding in report.pillar_rows():
        refs = refs_for(spec.number, finding.status)
        if not refs:
            continue
        rows.append(
            [
                f"P{spec.number:02d}",
                _cell(", ".join(ref.identifier for ref in refs)),
                _cell(explain(spec.number)),
            ]
        )
    if not rows:
        return []
    lines = ["## SEC 7: FRAMEWORK MAPPING (MITRE ATT&CK / OWASP)", ""]
    lines.append(
        "These are mappings of observed evidence to published vocabulary, not an "
        "attestation of implemented controls. Each row states the limit of what the "
        "pillar can see."
    )
    lines.append("")
    lines.extend(_table(["Pillar", "References", "What it observes and what it does not"], rows))
    lines.append("")
    return lines


def _render_markdown_body(report: DossierReport) -> str:
    """Render the Markdown dossier body without the file trailer."""

    lines: list[str] = [f"# {_TITLE}", "", f"Generated by: {report.generated_by}", ""]

    lines.extend(["## " + SECTION_HEADINGS[0], ""])
    lines.extend(_scorecard_lines(report))

    lines.extend(["## " + SECTION_HEADINGS[1], ""])
    lines.extend(_identity_lines(report))
    lines.append("")

    lines.extend(["## " + SECTION_HEADINGS[2], ""])
    lines.extend(_pillar_table(report))
    lines.append("")

    lines.extend(["## " + SECTION_HEADINGS[3], ""])
    lines.extend(_slot_table(report))
    lines.append("")

    lines.extend(["## " + SECTION_HEADINGS[4], ""])
    lines.append(
        "Instructions: change [ ] to [x] or supply values in <...>, then run "
        "tauhaulity apply <file>. The keys below are parsed by "
        "tauhaulity.dossier.form_parser.parse_form."
    )
    lines.append("")
    lines.extend(render_form_lines(report.policy))
    lines.append("")

    lines.extend(["## " + SECTION_HEADINGS[5], ""])
    lines.extend(
        [
            "- Algorithm : HMAC-SHA256 over the canonical report payload",
            "- Key       : " + _key_description(report),
            "- File stamp: sha256 and hmac over every preceding byte, in the final line",
            "- Digest    : " + (report.hmac or "UNSIGNED"),
            "",
            "Verify with tauhaulity verify <file>,",
            "tauhaulity.dossier.verify.verify_dossier_file(path) or",
            "tauhaulity.dossier.report.verify_report(report) for an in memory snapshot.",
        ]
    )
    lines.append("")
    lines.extend(_remediation_lines(report))
    lines.extend(_standards_lines(report))
    return "\n".join(lines)


def render_markdown(report: DossierReport, *, signing_key: bytes | None = None) -> str:
    """Render the complete Markdown dossier.

    Parameters:
        report: Validated dossier snapshot.
        signing_key: Optional key override for the file trailer; the key stored
            on the report is preferred so a signed snapshot stays self consistent.

    Returns:
        Markdown text ending with exactly one newline after the INTEGRITY
        trailer. The SEC 4 block is byte for byte what parse_form expects,
        including the [x] and [ ] markers.
    """

    return stamp_report_text(_render_markdown_body(report), report, signing_key)


def render_markdown_redacted(report: DossierReport, *, signing_key: bytes | None = None) -> str:
    """Render the Markdown dossier with every printable credential redacted.

    The dossier should already contain redacted evidence, but a caller may hand
    over findings from a third party probe; redacting again is cheap and keeps a
    shared report safe. The trailer is computed after redaction so the stamp
    describes the bytes that are actually returned.

    Parameters:
        report: Validated dossier snapshot.
        signing_key: Optional key override for the file trailer.

    Returns:
        Markdown text with credential spans masked and a valid file trailer.
    """

    from tauhaulity.dossier.redactor import redact_text

    redacted, _count = redact_text(_render_markdown_body(report))
    return stamp_report_text(redacted, report, signing_key)