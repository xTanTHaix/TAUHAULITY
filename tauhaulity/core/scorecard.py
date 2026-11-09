"""Explainable security scorecard: a bounded score with a grade and an audit trail.

A single "risk 4.5" tells a reader nothing about the ceiling, nothing about which
pillar cost the points, and nothing about what to fix first. This module turns
the twelve recorded findings into a bounded score out of one hundred, a letter
grade, and a per-pillar ledger that names the exact deduction and the evidence
that caused it.

Scoring contract (deliberately simple so a reader can reproduce it by hand):

  * every pillar carries the same normal share, or weight, of 100 / 12 points;
  * a warning-level pillar loses at most its weight, scaled by risk, with a floor
    of four points;
  * a critical pillar is NOT proportional to one twelfth of the risk: it loses at
    least eighteen points, because a live credential leak or a tampered
    environment must move the score more than a single warning does. A pillar can
    therefore lose more than its own weight, and the ledger says so explicitly;
  * a pillar that did not run loses six points, because a blind spot is not a pass;
  * the score is one hundred minus the sum of the losses, clamped to zero, and
    rounded once at the end so the ledger always adds up;
  * the grade bands are A (90+), B (80+), C (70+), D (60+), F below, and a
    CRITICAL verdict caps the grade at C no matter how few pillars were affected:
    a report that a credential is exposed must never read as "A".

Every deduction carries the pillar, the points, the status, the measured risk
against its ceiling, and the evidence string, so the report can answer "where"
and "why" without re-running the scan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from tauhaulity.core.contracts import PILLAR_SPECS, ScanContext, status_severity

SCORE_MAX = 100
GRADE_BANDS: tuple[tuple[int, str, str], ...] = (
    (90, "A", "STRONG"),
    (80, "B", "GOOD"),
    (70, "C", "FAIR"),
    (60, "D", "WEAK"),
    (0, "F", "CRITICAL"),
)

#: Points a pillar can cost at minimum, by severity class. The floor exists so a
#: pillar cannot report a critical status yet cost almost nothing because its
#: numeric risk happens to be small.
SEVERITY_FLOOR: dict[int, float] = {0: 0.0, 1: 4.0, 2: 18.0}
UNOBSERVED_FLOOR = 6.0

#: Grade a CRITICAL verdict may never exceed, and the note that explains it.
CRITICAL_GRADE_CAP = "C"
_GRADE_ORDER: tuple[str, ...] = ("F", "D", "C", "B", "A")

_PATH_PATTERN = re.compile(r"([A-Za-z]:[\\/][^\s;:,()\"']+|(?:[\w.\-]+[\\/])+[\w.\-]+\.[A-Za-z0-9]{1,6})")
_LOCATION_PATTERN = re.compile(r"([\w./\\-]+\.[A-Za-z0-9]{1,6}:\d+)")


@dataclass(frozen=True, slots=True)
class PillarScore:
    """How one pillar contributed to, or protected, the final score.

    Attributes:
        number: Pillar number, one through twelve.
        key: Machine readable pillar key.
        name: Human readable pillar title.
        status: The status the pillar reported.
        severity: 0 benign, 1 warning, 2 critical.
        risk: Measured risk of this pillar.
        risk_ceiling: Maximum risk this pillar may report.
        weight: Points this pillar could have lost at worst.
        points_lost: Points actually deducted, rounded to one decimal.
        evidence: The finding detail, trimmed for one report line.
        location: Best effort path or path:line extracted from the evidence.
        recovery: What to do to regain the points.
        observed: False when the pillar produced no finding at all.
    """

    number: int
    key: str
    name: str
    status: str
    severity: int
    risk: float
    risk_ceiling: float
    weight: float
    points_lost: float
    evidence: str
    location: str
    recovery: str
    observed: bool = True

    @property
    def earned(self) -> float:
        """Points this pillar kept for the project."""

        return round(self.weight - self.points_lost, 1)


@dataclass(frozen=True, slots=True)
class Scorecard:
    """Bounded security score with its full deduction ledger.

    Attributes:
        score: Points earned out of score_max.
        score_max: Ceiling of the score, always one hundred.
        grade: Letter grade derived from the score.
        band: Human label for the grade band.
        percentile: Score expressed as a percentage, for progress display.
        total_points_lost: Sum of every deduction, rounded once.
        risk_total: Sum of the twelve measured risks, clamped to the ten point scale.
        risk_ceiling: Ceiling of the aggregate risk, always ten.
        pillars: One PillarScore per pillar, in pillar order.
        deductions: Pillars that cost points, most expensive first.
        credit: One line per pillar that lost nothing, naming what it verified.
        headline: One line summary suitable for a terminal or a badge.
        verdict_name: The verdict the score was computed from.
        grade_note: Why the grade was clamped, empty when it was not.
    """

    score: int
    score_max: int
    grade: str
    band: str
    percentile: float
    total_points_lost: float
    risk_total: float
    risk_ceiling: float
    pillars: tuple[PillarScore, ...]
    deductions: tuple[PillarScore, ...]
    credit: tuple[str, ...] = field(default_factory=tuple)
    headline: str = ""
    verdict_name: str = ""
    grade_note: str = ""

    @property
    def summary(self) -> str:
        """Compact rendering such as '78 / 100 (grade B, GOOD); 12.0 points lost'."""

        return (
            f"{self.score} / {self.score_max} (grade {self.grade}, {self.band}); "
            f"{self.total_points_lost:.1f} point(s) lost across {len(self.deductions)} pillar(s)"
        )


def _recovery_hint(number: int, status: str, evidence: str) -> str:
    """Return one actionable line describing how to regain the points.

    Parameters:
        number: Pillar number.
        status: Reported status token.
        evidence: The finding detail, used to pick a specific action when the
            evidence already names a fixable object such as a hook or a file.
    """

    lowered = evidence.lower()
    if number == 6 and ("pickle" in lowered or "dangerous" in lowered):
        return "review each call site, then record the accepted ones with tauhaulity suppress"
    if number == 8 and "canary" in lowered:
        return "deploy honeytokens with tauhaulity honeytoken deploy and keep watch running"
    if number == 10 and ("venv" in lowered or ".pth" in lowered):
        return "rebuild the environment from a reviewed lock file, then re-run venv-check"
    if number == 11 and "hook" in lowered:
        return "install the gate with tauhaulity hook install"
    if number == 11:
        return "rotate the credential, purge it from history, then baseline only true fixtures"
    if number == 9 and (".0.0.0" in evidence or "0.0.0.0" in evidence):
        return "bind development services to the loopback address instead of every interface"
    if number == 1 and "baseline" in lowered:
        return "capture a known-good state with tauhaulity baseline --memory, then re-scan"
    if status in {"CRITICAL", "LEAK_DETECTED", "MALICIOUS_PTH"}:
        return "open the dossier slot for this pillar, apply the fix, and re-run the scan"
    if status in {"WARNING", "AT_RISK"}:
        return "review the evidence line and re-run the scan after the change"
    return "keep this pillar in the scan so regressions are detected"


def _extract_location(evidence: str) -> str:
    """Best effort extraction of a location from an evidence string.

    The scanner already formats locations as path:line or path; this only reads
    them back out so the scorecard can group deductions by file.
    """

    match = _LOCATION_PATTERN.search(evidence)
    if match:
        return match.group(1)
    match = _PATH_PATTERN.search(evidence)
    return match.group(1) if match else ""


def _trim(text: str, limit: int = 180) -> str:
    """Trim evidence to one report line without cutting a word in half."""

    condensed = " ".join((text or "").split())
    if len(condensed) <= limit:
        return condensed
    cut = condensed[:limit].rsplit(" ", 1)[0]
    return cut + "..."


def compute_scorecard(ctx: ScanContext, verdict_name: str = "") -> Scorecard:
    """Turn the recorded findings into a bounded, explainable score.

    Parameters:
        ctx: Scan context holding the pillar findings.
        verdict_name: Verdict name to record on the card; the caller usually
            passes the verdict it already computed.

    Returns:
        A Scorecard whose deductions and credit lines fully explain the score.
    """

    count = len(PILLAR_SPECS)
    weight = SCORE_MAX / count if count else 0.0
    pillars: list[PillarScore] = []
    for spec in PILLAR_SPECS:
        finding = ctx.findings.get(spec.number)
        if finding is None:
            pillars.append(
                PillarScore(
                    number=spec.number,
                    key=spec.key,
                    name=spec.name,
                    status=spec.default_status,
                    severity=1,
                    risk=UNOBSERVED_FLOOR,
                    risk_ceiling=spec.risk_scale,
                    weight=round(weight, 2),
                    points_lost=min(weight, UNOBSERVED_FLOOR),
                    evidence="pillar produced no finding",
                    location="",
                    recovery="re-run the scan; a pillar that cannot run is a blind spot, not a pass",
                    observed=False,
                )
            )
            continue
        severity = status_severity(finding.status)
        scaled = weight * (min(finding.risk, spec.risk_scale) / spec.risk_scale if spec.risk_scale else 0.0)
        floor = SEVERITY_FLOOR.get(severity, 0.0)
        # A warning can never cost more than the pillar's own share; a critical
        # finding can, because severity is not proportional to one twelfth.
        lost = max(scaled, floor) if severity == 2 else min(weight, max(scaled, floor))
        pillars.append(
            PillarScore(
                number=spec.number,
                key=spec.key,
                name=spec.name,
                status=finding.status,
                severity=severity,
                risk=round(finding.risk, 2),
                risk_ceiling=spec.risk_scale,
                weight=round(weight, 2),
                points_lost=round(lost, 1),
                evidence=_trim(finding.detail),
                location=_extract_location(finding.detail),
                recovery=_recovery_hint(spec.number, finding.status, finding.detail),
            )
        )

    total_lost = round(sum(p.points_lost for p in pillars), 1)
    score = max(0, min(SCORE_MAX, int(round(SCORE_MAX - total_lost))))
    grade, band = _grade_for(score)
    grade_capped = ""
    if verdict_name.upper() == "CRITICAL" and _GRADE_ORDER.index(grade) > _GRADE_ORDER.index(CRITICAL_GRADE_CAP):
        # A critical verdict means something concrete is exposed, so the grade is
        # clamped and the reason is stated instead of letting the arithmetic
        # produce a comfortable letter.
        grade_capped = (
            f"grade capped at {CRITICAL_GRADE_CAP}: the verdict is CRITICAL, so the "
            f"computed grade {grade} cannot stand"
        )
        grade = CRITICAL_GRADE_CAP
        band = dict((g, b) for _t, g, b in GRADE_BANDS)[grade]
    deductions = tuple(sorted((p for p in pillars if p.points_lost > 0), key=lambda p: (-p.points_lost, p.number)))
    credit = tuple(
        f"P{p.number:02d} {p.name.split('(')[0].strip()}: {p.status} - {p.evidence}" for p in pillars if p.points_lost <= 0
    )
    risk_total = round(min(10.0, sum(p.risk for p in pillars)), 2)
    if deductions:
        leading = deductions[0]
        headline = (
            f"security score {score}/{SCORE_MAX} (grade {grade}); "
            f"biggest deduction: P{leading.number:02d} {leading.points_lost:.1f} point(s) - "
            f"{leading.evidence[:90]}"
        )
    else:
        headline = f"security score {score}/{SCORE_MAX} (grade {grade}); no deductions"

    return Scorecard(
        score=score,
        score_max=SCORE_MAX,
        grade=grade,
        band=band,
        percentile=round(score / SCORE_MAX * 100.0, 1),
        total_points_lost=total_lost,
        risk_total=risk_total,
        risk_ceiling=10.0,
        pillars=tuple(pillars),
        deductions=deductions,
        credit=credit,
        headline=headline,
        verdict_name=verdict_name,
        grade_note=grade_capped,
    )


def _grade_for(score: int) -> tuple[str, str]:
    """Return the letter grade and band label for a score."""

    for threshold, grade, band in GRADE_BANDS:
        if score >= threshold:
            return grade, band
    return "F", "CRITICAL"
