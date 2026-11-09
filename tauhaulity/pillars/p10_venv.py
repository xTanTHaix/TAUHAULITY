"""Pillar ten: engine tier and virtual environment integrity (AUTONOMIC-VENV-RADAR).

Two independent facts are folded into one verdict: which execution tier the host
actually resolved (native Rust extension versus the ctypes fallback), and what
the virtual environment radar could prove about the installed tree. The engine
tier is reported even when the environment is clean, because a user reading a
lane at fallback tier must not believe they are protected by a native shield
that never loaded.

The status ladder is evidence based:
  * MALICIOUS_PTH only when a high finding is direct execution evidence (.pth
    payload or a sitecustomize/usercustomize startup hook);
  * TAMPERED for any other high finding (for example a RECORD sha256 mismatch)
    and for medium evidence such as path injection, a missing recorded file, a
    broken interpreter path or a typosquat resemblance;
  * CLEAN when only informational findings remain, because a normal venv names a
    base interpreter outside its own root and that must not raise an alarm.
"""

from __future__ import annotations

from pathlib import Path

from tauhaulity.core.contracts import SPEC_BY_KEY, Finding, ScanContext, make_finding

SPEC = SPEC_BY_KEY["autonomic_venv"]

_FALLBACK_TIER = "CTYPES_OS_PRIMITIVE_FALLBACK"

_RISK_BY_STATUS: dict[str, float] = {
    "CLEAN": 0.0,
    "TAMPERED": 6.0,
    "MALICIOUS_PTH": 9.0,
    "WARNING": 3.0,
}

_EVIDENCE_LIMIT = 3


def _engine_tier(ctx: ScanContext) -> str:
    """Return the resolved engine tier without trusting a missing attribute."""

    tier = getattr(ctx.platform, "engine_tier", None)
    if isinstance(tier, str) and tier:
        return tier
    return _FALLBACK_TIER


def _execution_codes() -> frozenset[str]:
    """Return the finding codes that prove attacker code execution.

    The set lives in the radar so the pillar and the scanner cannot disagree
    about what counts as executable evidence; on import failure the scanner is
    unavailable and the caller returns WARNING before reaching this helper.
    """

    from tauhaulity.tools.venv_radar import EXECUTION_CODES

    return EXECUTION_CODES


def _status_from_report(report: object, execution_codes: frozenset[str]) -> str:
    """Fold the radar report into the pillar status ladder."""

    findings = list(getattr(report, "pth_findings", []) or [])
    high = [finding for finding in findings if finding.severity == "high"]
    medium = [finding for finding in findings if finding.severity == "medium"]
    if high:
        if any(finding.code in execution_codes for finding in high):
            return "MALICIOUS_PTH"
        return "TAMPERED"
    if (
        medium
        or getattr(report, "suspicious_binaries", None)
        or getattr(report, "permission_anomalies", None)
    ):
        return "TAMPERED"
    return "CLEAN"


def _compose_detail(tier: str, report: object, status: str) -> str:
    """Build the dossier detail line from counts, evidence paths and budget."""

    findings = list(getattr(report, "pth_findings", []) or [])
    high = sum(1 for finding in findings if finding.severity == "high")
    medium = sum(1 for finding in findings if finding.severity == "medium")
    low = len(findings) - high - medium
    evidence = [finding.rel_path for finding in findings[:_EVIDENCE_LIMIT]]
    parts = [
        "engine tier " + tier,
        status,
        str(high) + " high / " + str(medium) + " medium / " + str(low) + " low",
        "RECORD "
        + str(int(getattr(report, "record_checked", 0) or 0))
        + " checked / "
        + str(int(getattr(report, "record_mismatches", 0) or 0))
        + " mismatch",
        "startup "
        + str(len(getattr(report, "startup_injections", []) or [])),
        "typosquat "
        + str(len(getattr(report, "typosquat_suspects", []) or [])),
        "binaries "
        + str(len(getattr(report, "suspicious_binaries", []) or [])),
        "writable "
        + str(len(getattr(report, "permission_anomalies", []) or [])),
    ]
    if evidence:
        parts.append("top: " + ", ".join(evidence))
    if bool(getattr(report, "truncated", False)):
        parts.append("RECORD verification truncated at the scan budget")
    return "; ".join(parts)


def _repro_hint(
    status: str, report: object, execution_codes: frozenset[str]
) -> str | None:
    """Return a concrete next step for the operator, or None when clean."""

    findings = list(getattr(report, "pth_findings", []) or [])
    if status == "MALICIOUS_PTH":
        executable = next(
            (
                finding
                for finding in findings
                if finding.severity == "high" and finding.code in execution_codes
            ),
            None,
        )
        startup = list(getattr(report, "startup_injections", []) or [])
        if executable is not None:
            location = executable.rel_path
            if executable.line_no > 0:
                location += ":" + str(executable.line_no)
            return (
                "inspect "
                + location
                + " and remove the startup payload before starting this interpreter again"
            )
        if startup:
            return (
                "remove "
                + startup[0]
                + " and reinstall the environment from its lock file"
            )
        return "recreate the virtual environment from its lock file"
    if status == "TAMPERED":
        if int(getattr(report, "record_mismatches", 0) or 0):
            mismatch = next(
                (finding for finding in findings if finding.code == "record_mismatch"),
                None,
            )
            if mismatch is not None:
                return (
                    "reinstall the distribution that owns "
                    + mismatch.rel_path
                    + "; its sha256 no longer matches the RECORD digest"
                )
        if getattr(report, "typosquat_suspects", None):
            return (
                "verify the source of "
                + str(list(report.typosquat_suspects)[0])
                + " before importing it; the name resembles a popular package"
            )
        if findings:
            return "review " + findings[0].rel_path + " inside the environment"
        suspected = (
            list(getattr(report, "suspicious_binaries", []) or [])
            or list(getattr(report, "permission_anomalies", []) or [])
            or [""]
        )[0]
        if suspected:
            return "review unindexed or world writable artifact " + suspected
        return "recreate the virtual environment from the lock file"
    return None


def probe(ctx: ScanContext) -> Finding:
    """Inspect the virtual environment and report the resolved engine tier."""

    tier = _engine_tier(ctx)
    root = Path(ctx.target)
    try:
        from tauhaulity.tools.venv_radar import inspect_venv
    except ImportError:
        detail = "engine tier " + tier + "; virtual environment radar is unavailable"
        return make_finding(
            SPEC,
            "WARNING",
            detail,
            risk=_RISK_BY_STATUS["WARNING"],
            slots={"engine_tier": tier, "venv_status": "UNKNOWN", "detail": detail},
            repro_hint="import tauhaulity.tools.venv_radar to see why the radar is missing",
        )
    try:
        report = inspect_venv(root)
    except (OSError, RuntimeError, ValueError) as exc:
        detail = "engine tier " + tier + "; virtual environment scan failed: " + str(exc)
        return make_finding(
            SPEC,
            "WARNING",
            detail,
            risk=_RISK_BY_STATUS["WARNING"],
            slots={"engine_tier": tier, "venv_status": "UNKNOWN", "detail": detail},
            repro_hint="call tauhaulity.tools.venv_radar.inspect_venv with the project root",
        )

    reported = getattr(report, "status", "")
    if reported == "WARNING":
        status = "WARNING"
    else:
        status = _status_from_report(report, _execution_codes())
        if status not in SPEC.statuses:
            status = "WARNING"
    venv_label = status
    venv_path = getattr(report, "venv_path", None)
    if venv_path is not None:
        try:
            venv_label = venv_path.name + " " + status
        except (AttributeError, TypeError):
            venv_label = status
    detail = _compose_detail(tier, report, status)
    slots = {"engine_tier": tier, "venv_status": venv_label, "detail": detail}
    hint = _repro_hint(status, report, _execution_codes())
    return make_finding(
        SPEC,
        status,
        detail,
        risk=_RISK_BY_STATUS.get(status, _RISK_BY_STATUS["WARNING"]),
        slots=slots,
        repro_hint=hint,
    )
