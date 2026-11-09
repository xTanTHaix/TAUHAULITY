"""Aggregation of pillar findings into one dossier verdict.

The verdict must be explainable from the report alone, so it is a pure function
of the recorded findings: severity is driven by the worst status any pillar
reported, and the numeric risk adds a bounded penalty per additional warning so
that a project with many small issues does not outrank a project with one
critical one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from tauhaulity.core.contracts import (
    PILLAR_SPECS,
    ScanContext,
    status_severity,
)

VERDICT_SAFE = "SAFE"
VERDICT_AT_RISK = "AT_RISK"
VERDICT_CRITICAL = "CRITICAL"

_CODE_BY_NAME = {VERDICT_SAFE: 0, VERDICT_AT_RISK: 1, VERDICT_CRITICAL: 2}


@dataclass(frozen=True, slots=True)
class Verdict:
    """Final security verdict derived from all pillar findings.

    Attributes:
        name: SAFE, AT_RISK or CRITICAL.
        code: Numeric code used by the telemetry frame and the JSON dossier.
        risk: Aggregate risk score in the range zero to ten.
        bitmask: Twelve bit mask, bit zero is pillar one, set when not benign.
        critical_pillars: Pillars that reported a critical status.
        warning_pillars: Pillars that reported a warning status.
        missing_pillars: Pillars that never produced a finding.
        notes: Human readable explanation lines for the dossier.
    """

    name: str
    code: int
    risk: float
    bitmask: int
    critical_pillars: tuple[int, ...] = ()
    warning_pillars: tuple[int, ...] = ()
    missing_pillars: tuple[int, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def badge(self) -> str:
        """Bracketed badge string used by the text dossier."""

        return f"[ {self.name} ]"


def compute_verdict(ctx: ScanContext) -> Verdict:
    """Fold every recorded finding into a single verdict.

    Parameters:
        ctx: Scan context holding the findings collected so far.

    Returns:
        An immutable Verdict with the aggregate risk, bitmask and explanation.
    """

    critical: list[int] = []
    warning: list[int] = []
    missing: list[int] = []
    bitmask = 0
    max_risk = 0.0
    total_risk = 0.0

    for spec in PILLAR_SPECS:
        finding = ctx.findings.get(spec.number)
        if finding is None:
            missing.append(spec.number)
            continue
        severity = status_severity(finding.status)
        if severity > 0:
            bitmask |= 1 << (spec.number - 1)
        if severity == 2:
            critical.append(spec.number)
        elif severity == 1:
            warning.append(spec.number)
        scaled = min(finding.risk, max_risk_scale(spec.number))
        max_risk = max(max_risk, scaled)
        total_risk += scaled

    observed = len(ctx.findings)
    mean_risk = total_risk / observed if observed else 0.0
    risk = max_risk
    if critical:
        risk = min(10.0, risk + 0.5 * (len(critical) - 1))
    risk = min(10.0, risk + 0.25 * len(warning))
    if not ctx.findings:
        risk = 0.0
    elif max_risk == 0.0 and mean_risk > 0.0:
        risk = min(10.0, mean_risk)

    if critical:
        name = VERDICT_CRITICAL
    elif warning:
        name = VERDICT_AT_RISK
    elif missing:
        name = VERDICT_AT_RISK
    else:
        name = VERDICT_SAFE

    notes: list[str] = []
    if critical:
        notes.append("critical pillars: " + ", ".join(str(number) for number in critical))
    if warning:
        notes.append("warning pillars: " + ", ".join(str(number) for number in warning))
    if missing:
        notes.append("pillars without a finding: " + ", ".join(str(number) for number in missing))
    if not notes:
        notes.append("all twelve pillars reported a benign status")

    return Verdict(
        name=name,
        code=_CODE_BY_NAME[name],
        risk=round(risk, 2),
        bitmask=bitmask,
        critical_pillars=tuple(critical),
        warning_pillars=tuple(warning),
        missing_pillars=tuple(missing),
        notes=tuple(notes),
    )


def max_risk_scale(number: int) -> float:
    """Return the published risk scale of a pillar so clamping stays exact."""

    for spec in PILLAR_SPECS:
        if spec.number == number:
            return spec.risk_scale
    raise KeyError(f"unknown pillar {number}")
