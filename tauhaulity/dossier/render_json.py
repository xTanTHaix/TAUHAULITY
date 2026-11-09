"""Structured JSON dossier renderer.

The JSON document is the machine twin of the Markdown dossier, so it reuses the
same field vocabulary (status, mechanism, finding, risk) instead of inventing
abbreviations. Key order is fixed by construction rather than by sort_keys, and
the output is UTF-8 without a BOM with one trailing newline, because a diff of two
dossiers should only show real changes.
"""

from __future__ import annotations

import json
from typing import Any, Final

from tauhaulity.core.contracts import status_severity
from tauhaulity.dossier.model import DOSSIER_SCHEMA, DossierReport

# Stable top level order. Tests and downstream CI assert this exact sequence so a
# renamed key is a visible contract change, not an accidental reorder.
JSON_FIELD_ORDER: Final[tuple[str, ...]] = (
    "schema",
    "generated_by",
    "hmac_sha256",
    "target",
    "host_operating_system",
    "python_runtime_engine",
    "active_hardware_primitives",
    "scan_timestamp_utc",
    "overall_security_verdict",
    # Flat verdict name kept for the CLI diff command, which compares the two
    # dossiers without walking the nested verdict object.
    "verdict",
    # The scorecard is the answer to "how bad, out of what, and why": it carries
    # the bounded score, the grade, the ceiling and the per-pillar deductions.
    "scorecard",
    "findings_recorded",
    "pillars",
    "actionable_slots",
    "policy",
    "repro_files",
)


def _verdict_payload(report: DossierReport) -> dict[str, Any]:
    """Serialize the verdict with every field needed to explain it."""

    verdict = report.verdict
    return {
        "name": verdict.name,
        "code": verdict.code,
        "badge": verdict.badge,
        "risk": verdict.risk,
        "bitmask": verdict.bitmask,
        "critical_pillars": list(verdict.critical_pillars),
        "warning_pillars": list(verdict.warning_pillars),
        "missing_pillars": list(verdict.missing_pillars),
        "notes": list(verdict.notes),
    }


def _scorecard_payload(report: DossierReport) -> dict[str, Any]:
    """Serialize the scorecard, including every deduction and its recovery hint.

    The ledger is exported in full rather than summarized, because a CI job that
    fails on a score regression needs to name the pillar that moved.
    """

    card = report.scorecard
    return {
        "score": card.score,
        "score_max": card.score_max,
        "grade": card.grade,
        "band": card.band,
        "grade_note": card.grade_note,
        "percentile": card.percentile,
        "total_points_lost": card.total_points_lost,
        "risk_total": card.risk_total,
        "risk_ceiling": card.risk_ceiling,
        "headline": card.headline,
        "verdict": card.verdict_name,
        "deductions": [
            {
                "pillar": pillar.number,
                "key": pillar.key,
                "name": pillar.name,
                "status": pillar.status,
                "severity": pillar.severity,
                "points_lost": pillar.points_lost,
                "weight": pillar.weight,
                "risk": pillar.risk,
                "risk_ceiling": pillar.risk_ceiling,
                "location": pillar.location,
                "evidence": pillar.evidence,
                "recovery": pillar.recovery,
            }
            for pillar in card.deductions
        ],
        "credit": list(card.credit),
    }


def _pillar_payloads(report: DossierReport) -> list[dict[str, Any]]:
    """Serialize the twelve pillar rows in pillar order."""

    payloads: list[dict[str, Any]] = []
    for spec, finding in report.pillar_rows():
        payloads.append(
            {
                "pillar": spec.number,
                "key": spec.key,
                "name": spec.name,
                "status": finding.status,
                "severity": status_severity(finding.status),
                "mechanism": spec.mechanism,
                "finding": finding.detail,
                "risk": round(float(finding.risk), 4),
                "repro_hint": finding.repro_hint or "",
                "slots": {key: str(finding.slots[key]) for key in sorted(finding.slots)},
            }
        )
    return payloads


def _slot_payloads(report: DossierReport) -> list[dict[str, Any]]:
    """Serialize the actionable slots with the same predicate as the text renderer."""

    slots: list[dict[str, Any]] = []
    for spec, finding in report.pillar_rows():
        if finding.risk < 4.0 and not finding.repro_hint:
            continue
        slots.append(
            {
                "slot": f"#{spec.number:02d}",
                "pillar": spec.number,
                "location": finding.slot("detail") or report.target,
                "issue": f"[{finding.status}] {finding.detail}",
                "repro_test": report.repro_file_for(spec.number) or "not generated",
                "action": finding.slot("hotpatch")
                or finding.repro_hint
                or "review evidence and re-run",
            }
        )
    return slots


def report_payload(report: DossierReport) -> dict[str, Any]:
    """Build the ordered JSON payload for a dossier.

    Parameters:
        report: Validated dossier snapshot.

    Returns:
        A mapping whose insertion order equals JSON_FIELD_ORDER.
    """

    identity = report.json_identity()
    payload: dict[str, Any] = {
        "schema": DOSSIER_SCHEMA,
        "generated_by": report.generated_by,
        "hmac_sha256": report.hmac,
        "target": identity["target"],
        "host_operating_system": identity["host_operating_system"],
        "python_runtime_engine": identity["python_runtime_engine"],
        "active_hardware_primitives": identity["active_hardware_primitives"],
        "scan_timestamp_utc": identity["scan_timestamp_utc"],
        "overall_security_verdict": _verdict_payload(report),
        "verdict": report.verdict.name,
        "scorecard": _scorecard_payload(report),
        "findings_recorded": len(report.findings),
        "pillars": _pillar_payloads(report),
        "actionable_slots": _slot_payloads(report),
        "policy": report.policy.to_dict(),
        "repro_files": list(report.repro_files),
    }
    missing = [key for key in JSON_FIELD_ORDER if key not in payload]
    if missing:
        raise ValueError(f"json dossier missing fields: {missing}")
    return {key: payload[key] for key in JSON_FIELD_ORDER}


def render_json(report: DossierReport) -> str:
    """Render the JSON dossier as UTF-8 text.

    Parameters:
        report: Validated dossier snapshot.

    Returns:
        JSON text with ensure_ascii disabled, two space indentation and exactly
        one trailing newline.
    """

    payload = report_payload(report)
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
