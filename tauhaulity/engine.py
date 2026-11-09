"""Scan orchestration: platform, policy, twelve pillars, verdict and dossier.

The engine is deliberately the only place that decides execution order and
error containment. A pillar that raises must not abort the other eleven, because
a single broken platform primitive would otherwise hide every other finding; a
failed probe therefore becomes an explicit WARNING finding that names the
exception class, which keeps the dossier honest instead of empty.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from tauhaulity.core.contracts import (
    PILLAR_SPECS,
    SPEC_BY_NUMBER,
    Finding,
    ScanContext,
    ScanOptions,
    make_finding,
)
from tauhaulity.core.platform_probe import detect_platform
from tauhaulity.core.policy import Policy, policy_dir, policy_path
from tauhaulity.core.scorecard import Scorecard, compute_scorecard
from tauhaulity.core.telemetry import TelemetryFrame, pack_score
from tauhaulity.core.verdict import Verdict, compute_verdict
from tauhaulity.pillars import load_pillars

if TYPE_CHECKING:
    from tauhaulity.dossier.report import DossierReport

REPORT_STEM = "tauhaulity_report"
PROBE_FAILURE_RISK = 5.0


class ScanError(RuntimeError):
    """Raised when a scan cannot start, for example a missing target path."""


@dataclass(slots=True)
class ScanResult:
    """Everything a caller needs after a scan completes.

    Attributes:
        ctx: The scan context with the twelve recorded findings.
        verdict: Aggregated verdict derived from those findings.
        report: Dossier report object when the dossier layer is importable.
        report_paths: Written dossier paths keyed by format.
        duration_ms: Wall clock duration of the scan.
        telemetry_path: Appended telemetry frame log, when writable.
        warnings: Non fatal problems encountered while assembling the result.
    """

    ctx: ScanContext
    verdict: Verdict
    scorecard: Scorecard | None = None
    report: "DossierReport | None" = None
    report_paths: dict[str, Path] = field(default_factory=dict)
    duration_ms: float = 0.0
    telemetry_path: Path | None = None
    warnings: tuple[str, ...] = ()

    @property
    def target(self) -> Path:
        """Project root that was scanned."""

        return self.ctx.target

    def finding(self, number: int) -> Finding:
        """Return a finding, or a WARNING placeholder for a pillar that failed."""

        existing = self.ctx.findings.get(number)
        if existing is not None:
            return existing
        spec = SPEC_BY_NUMBER[number]
        return make_finding(spec, spec.default_status, "pillar produced no finding", risk=PROBE_FAILURE_RISK)


def resolve_target(target: str | Path) -> Path:
    """Resolve a scan target to an existing project root.

    Parameters:
        target: Directory to scan, or a file whose parent directory is used.

    Raises:
        ScanError: When the path does not exist or is not accessible.
    """

    path = Path(target).expanduser()
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ScanError(f"scan target does not exist: {path} ({exc})") from exc
    return resolved if resolved.is_dir() else resolved.parent


def _probe_all(ctx: ScanContext) -> tuple[list[str], list[str]]:
    """Run every discovered pillar, containing per pillar failures.

    Returns:
        A tuple of warning lines and of pillar keys that failed, both for the
        dossier and for the console summary.
    """

    warnings: list[str] = []
    failed: list[str] = []
    probes = load_pillars(strict=False)
    seen: set[int] = set()
    for probe in probes:
        spec = probe.spec
        seen.add(spec.number)
        try:
            finding = probe.probe(ctx)
            ctx.record(finding)
        except Exception as exc:  # a broken probe must not abort the scan
            status = spec.default_status
            detail = f"probe failed: {type(exc).__name__}: {exc}"
            ctx.record(make_finding(spec, status, detail, risk=PROBE_FAILURE_RISK))
            warnings.append(f"pillar {spec.number} ({spec.key}) {detail}")
            failed.append(spec.key)
    for spec in PILLAR_SPECS:
        if spec.number in seen:
            continue
        detail = "pillar module not installed"
        ctx.record(make_finding(spec, spec.default_status, detail, risk=PROBE_FAILURE_RISK))
        warnings.append(f"pillar {spec.number} ({spec.key}) {detail}")
        failed.append(spec.key)
    return warnings, failed


def _append_telemetry(root: Path, ctx: ScanContext, verdict: Verdict) -> Path | None:
    """Append one 128 byte verdict frame to the project telemetry log.

    The frame log is an append only audit trail: a later dossier can prove that
    a verdict existed at a given monotonic time without trusting the report file.

    Returns:
        The telemetry log path, or None when the project directory is read-only.
    """

    frame = TelemetryFrame(
        seqlock=0,
        timeout_ms=5,
        monotonic_ns=time.monotonic_ns(),
        mask=int(verdict.bitmask),
        pid=os.getpid(),
        tid=threading.get_ident(),
        pillar_mask=verdict.bitmask,
        verdict=verdict.code,
        risk_q16=pack_score(verdict.risk, 0.0) >> 32,
        slot_id=b"verdict-frame".ljust(24, b" "),
    )
    directory = policy_dir(root)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "telemetry.frames"
        with open(path, "ab") as handle:
            handle.write(frame.to_bytes())
        return path
    except OSError:
        return None


def run_scan(
    target: str | Path = ".",
    *,
    policy: Policy | None = None,
    options: ScanOptions | None = None,
    write_reports: bool = True,
    out_dir: str | Path | None = None,
) -> ScanResult:
    """Run the full twelve pillar scan and optionally render dossiers.

    Parameters:
        target: Directory (or file inside the project) to scan.
        policy: Explicit policy; when omitted the project policy file is loaded.
        options: Scan options controlling depth, formats and repro synthesis.
        write_reports: When False the scan stops after the verdict, which keeps
            programmatic callers from writing files as a side effect.
        out_dir: Report directory; defaults to the project root.

    Returns:
        ScanResult carrying findings, verdict, report object and written paths.

    Raises:
        ScanError: When the target cannot be resolved.
    """

    started = time.monotonic()
    root = resolve_target(target)
    effective_options = options or ScanOptions()
    if policy is None:
        policy = Policy.load(policy_path(root))
    ctx = ScanContext(target=root, platform=detect_platform(), policy=policy, options=effective_options)
    warnings, _failed = _probe_all(ctx)
    verdict = compute_verdict(ctx)
    # The scorecard is computed for every caller, including the ones that never
    # render a dossier, because the console summary and the telemetry frame both
    # quote it.
    scorecard = compute_scorecard(ctx, verdict.name)
    telemetry_path = _append_telemetry(root, ctx, verdict) if effective_options.record_telemetry else None
    result = ScanResult(
        ctx=ctx,
        verdict=verdict,
        scorecard=scorecard,
        duration_ms=(time.monotonic() - started) * 1000.0,
        telemetry_path=telemetry_path,
        warnings=tuple(warnings),
    )
    if not write_reports:
        return result
    try:
        from tauhaulity.dossier.report import build_report, write_reports as write_dossier
    except ImportError as exc:
        result.warnings = result.warnings + (f"dossier layer unavailable: {exc}",)
        return result
    repro_files = _repro_files(ctx)
    report = build_report(ctx, repro_files=repro_files)
    destination = Path(out_dir).resolve() if out_dir is not None else root
    formats = tuple(fmt for fmt in effective_options.export_formats if fmt in {"md", "txt", "json"})
    if not formats:
        raise ScanError("no valid export format requested")
    result.report = report
    result.report_paths = dict(write_dossier(report, destination, formats=formats))
    result.duration_ms = (time.monotonic() - started) * 1000.0
    return result


def _repro_files(ctx: ScanContext) -> tuple[str, ...]:
    """Extract the repro file names recorded by the flight recorder pillar."""

    finding = ctx.findings.get(12)
    if finding is None:
        return ()
    raw = finding.slot("repro_files", "")
    if not raw:
        return ()
    return tuple(part.strip() for part in raw.split(",") if part.strip())


def summarize(result: ScanResult) -> str:
    """Render a single console summary line for a completed scan.

    Returns:
        Text such as 'AT_RISK (risk 4.50) on 12 pillars in 812 ms'.
    """

    base = (
        f"{result.verdict.name} (risk {result.verdict.risk:.2f} / 10.00) on "
        f"{len(result.ctx.findings)} pillars in {result.duration_ms:.0f} ms"
    )
    if result.scorecard is not None:
        base += f" | score {result.scorecard.score}/{result.scorecard.score_max} (grade {result.scorecard.grade})"
    return base
