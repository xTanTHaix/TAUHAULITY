"""Pillar twelve: attack flight recorder and auto repro generator.

The probe is deliberately the last pillar: it reads the findings the other eleven
recorded and turns the riskiest, hint carrying ones into standalone reproduction
scripts. Writing is confined to TARGET/.tauhaulity/repro because a diagnostic tool
that scatters files through a repository is a hazard, and the probe degrades to
IDLE instead of failing a scan when synthesis is disabled or unavailable.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from tauhaulity.core.contracts import (
    SPEC_BY_KEY,
    Finding,
    ScanContext,
    make_finding,
    status_severity,
)
from tauhaulity.core.policy import policy_dir

SPEC = SPEC_BY_KEY["auto_repro"]

# At most three scripts per scan: a dossier with thirty repro files is noise, and
# each script is meant to be read and run by a human.
MAX_REPRO_SCRIPTS: Final[int] = 3

# Risk threshold at which a finding becomes worth a repro script even when the
# probe did not attach an explicit hint.
REPRO_RISK_THRESHOLD: Final[float] = 6.0


def probe(ctx: ScanContext) -> Finding:
    """Synthesize repro scripts for the riskiest recorded findings.

    Parameters:
        ctx: Scan context containing the findings recorded by the earlier
            pillars, the effective policy and the scan options.

    Returns:
        GENERATED with the written script names, IDLE when there is nothing to
        reproduce, or WARNING when a script was expected but could not be
        written. Every branch states its reason in the detail slot.
    """

    if not ctx.options.generate_repro:
        return make_finding(
            SPEC,
            "IDLE",
            "auto repro generation disabled by scan options",
            risk=0.0,
            slots={"repro_files": "", "detail": "generate_repro=false"},
        )

    candidates = [
        finding
        for _number, finding in sorted(ctx.findings.items())
        if finding.repro_hint or finding.risk >= REPRO_RISK_THRESHOLD
    ]
    actionable = [finding for finding in candidates if status_severity(finding.status) > 0]
    if not actionable:
        detail = (
            "no finding carried a repro hint or risk at or above "
            f"{REPRO_RISK_THRESHOLD:.1f}"
        )
        if candidates:
            detail = "repro candidates reported a benign status; nothing to reproduce"
        return make_finding(
            SPEC,
            "IDLE",
            detail,
            risk=0.0,
            slots={"repro_files": "", "detail": detail},
        )

    try:
        from tauhaulity.repro.synthesizer import AutoReproSynthesizer
    except ImportError as exc:
        return make_finding(
            SPEC,
            "WARNING",
            f"repro synthesizer unavailable: {exc}",
            risk=2.0,
            slots={"repro_files": "", "detail": "synthesizer import failed"},
        )

    target = Path(ctx.target)
    repro_dir = policy_dir(target) / "repro"
    if not _inside_target(repro_dir, target):
        return make_finding(
            SPEC,
            "WARNING",
            "refusing to write repro scripts outside the scan target",
            risk=2.0,
            slots={"repro_files": "", "detail": str(repro_dir)},
        )

    synthesizer = AutoReproSynthesizer(repro_dir)
    try:
        written = synthesizer.synthesize_many(actionable, ctx, limit=MAX_REPRO_SCRIPTS)
    except (OSError, ValueError, TypeError) as exc:
        return make_finding(
            SPEC,
            "WARNING",
            f"repro synthesis failed: {exc}",
            risk=2.0,
            slots={"repro_files": "", "detail": str(repro_dir)},
        )

    if not written:
        return make_finding(
            SPEC,
            "WARNING",
            "repro candidates were actionable but no script was written",
            risk=2.0,
            slots={"repro_files": "", "detail": str(repro_dir)},
        )

    names = ", ".join(path.name for path in written)
    return make_finding(
        SPEC,
        "GENERATED",
        f"synthesized {len(written)} repro script(s) under .tauhaulity/repro: {names}",
        risk=0.0,
        slots={
            "repro_files": names,
            "detail": f"{len(written)} script(s) written to .tauhaulity/repro",
        },
        repro_hint=None,
    )


def _inside_target(candidate: Path, target: Path) -> bool:
    """Return True when candidate resolves inside the target directory.

    Paths are resolved before comparison because a symlink or a drive relative
    path could otherwise point outside the project, and repro scripts must never
    leak outside it.

    Parameters:
        candidate: Directory the synthesizer would write into.
        target: Scan target that must contain it.
    """

    try:
        resolved_candidate = candidate.resolve()
        resolved_target = target.resolve()
    except OSError:
        return False
    try:
        return resolved_candidate.is_relative_to(resolved_target)
    except (OSError, ValueError):
        return False


__all__ = ["MAX_REPRO_SCRIPTS", "REPRO_RISK_THRESHOLD", "SPEC", "probe"]
