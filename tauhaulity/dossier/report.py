"""Dossier assembly, signing and atomic persistence.

This module is the only place that turns a ScanContext into a signed snapshot, so
the CLI, the engine and the tests all observe the same timestamp, the same twelve
ordered findings and the same HMAC payload. Persistence goes through a temporary
file in the destination directory followed by os.replace, because a half written
report is worse than no report: reviewers and CI both treat a dossier as evidence.
"""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from tauhaulity.core.contracts import PILLAR_SPECS, Finding, ScanContext
from tauhaulity.core.scorecard import compute_scorecard
from tauhaulity.core.verdict import compute_verdict
from tauhaulity.dossier.model import (
    DOSSIER_SCHEMA,
    REPORT_FILENAMES,
    DossierReport,
)
from tauhaulity.dossier.redactor import (
    hmac_sha256_hex,
    redact_text,
    resolve_signing_key,
    verify_hmac,
)
from tauhaulity.dossier.render_json import render_json
from tauhaulity.dossier.render_md import render_markdown
from tauhaulity.dossier.render_txt import render_text

FORMATS: tuple[str, ...] = ("md", "txt", "json")


def _generated_by() -> str:
    """Return the producer signature embedded in every dossier format."""

    try:
        from tauhaulity import __version__
    except ImportError:  # pragma: no cover - the package always exists in-tree
        return "tauhaulity"
    return f"tauhaulity {__version__}"


def _utc_timestamp() -> str:
    """Return the generation timestamp in ISO-8601 UTC form."""

    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _sanitise_finding(finding: Finding) -> Finding:
    """Return a copy of a finding with credential material masked.

    A dossier is an evidence file that gets committed and shared, so redaction
    happens here rather than trusting every probe to have sanitized its own
    evidence. redact_text is idempotent, so a detail that a pillar already masked
    is passed through unchanged and the HMAC still signs the redacted text.
    """

    detail, _detail_hits = redact_text(finding.detail)
    repro_hint = finding.repro_hint
    if repro_hint is not None:
        repro_hint = redact_text(repro_hint)[0]
    slots = {key: redact_text(str(value))[0] for key, value in finding.slots.items()}
    if (
        detail == finding.detail
        and repro_hint == finding.repro_hint
        and slots == dict(finding.slots)
    ):
        return finding
    return replace(finding, detail=detail, slots=slots, repro_hint=repro_hint)


def _ordered_findings(ctx: ScanContext) -> tuple[Finding, ...]:
    """Return one finding per pillar, in pillar order.

    A pillar that never produced a finding is represented by an explicit
    placeholder carrying that pillar's default warning status and a detail that
    states the probe did not run. Substituting a benign status would secretly
    claim coverage the scan does not have.
    """

    ordered: list[Finding] = []
    for spec in PILLAR_SPECS:
        recorded = ctx.findings.get(spec.number)
        if recorded is not None:
            ordered.append(_sanitise_finding(recorded))
            continue
        ordered.append(
            Finding(
                pillar=spec.number,
                status=spec.default_status,
                detail="pillar did not run in this scan (no finding recorded)",
                risk=0.0,
                slots={},
                repro_hint=None,
            )
        )
    return tuple(ordered)


def _scoring_context(findings: tuple[Finding, ...]) -> object:
    """Wrap sanitised findings in the minimal shape the scorecard reads.

    Only the finding map is used, so no platform probe or policy is required and
    the dossier keeps its narrow dependency surface.
    """

    from types import SimpleNamespace

    return SimpleNamespace(findings={finding.pillar: finding for finding in findings})


def report_hmac_payload(report: DossierReport) -> str:
    """Return the canonical text that the dossier HMAC signs.

    The payload deliberately excludes the hmac field, otherwise the digest would
    have to contain itself. Every other report field is included so an edit to a
    status, a risk score or a policy value invalidates the stamp.

    Parameters:
        report: Dossier snapshot, signed or not.

    Returns:
        A deterministic, newline separated payload.
    """

    lines: list[str] = [
        DOSSIER_SCHEMA,
        "generated_by=" + report.generated_by,
        "target=" + report.target,
        "os_label=" + report.os_label,
        "python_label=" + report.python_label,
        "hardware_label=" + report.hardware_label,
        "timestamp_utc=" + report.timestamp_utc,
        "verdict=" + report.verdict.name + ":" + f"{report.verdict.code}" + ":" + f"{report.verdict.risk:.4f}",
        "risk=" + f"{report.verdict.risk:.4f}",
        "bitmask=" + str(report.verdict.bitmask),
        "score=" + f"{report.scorecard.score}" + "/" + f"{report.scorecard.score_max}",
        "grade=" + report.scorecard.grade,
        "points_lost=" + f"{report.scorecard.total_points_lost:.1f}",
        "deductions="
        + "|".join(
            f"P{pillar.number:02d}:{pillar.status}:{pillar.points_lost:.1f}" for pillar in report.scorecard.deductions
        ),
        "policy=" + json.dumps(report.policy.to_dict(), sort_keys=True, ensure_ascii=False),
        "repro_files=" + "|".join(report.repro_files),
    ]
    for spec, finding in report.pillar_rows():
        slots = json.dumps(
            {key: str(finding.slots[key]) for key in sorted(finding.slots)},
            sort_keys=True,
            ensure_ascii=False,
        )
        lines.append(
            "pillar="
            + "|".join(
                (
                    str(spec.number),
                    spec.key,
                    finding.status,
                    f"{finding.risk:.4f}",
                    finding.detail,
                    finding.repro_hint or "",
                    slots,
                )
            )
        )
    return "\n".join(lines)


def build_report(
    ctx: ScanContext,
    repro_files: tuple[str, ...] = (),
    *,
    signing_key: bytes | None = None,
) -> DossierReport:
    """Build and sign the dossier for a finished scan.

    The signing key is resolved by redactor.resolve_signing_key: an explicit key
    wins, then TAUHAULITY_SIGNING_KEY, then the derived machine key. The resolved
    key and its source travel with the snapshot so every rendered file trailer is
    stamped with the same key, and SEC 5 can state honestly how strong the stamp
    is.

    Parameters:
        ctx: Scan context holding the platform fingerprint, policy and findings.
        repro_files: Names of repro scripts written by pillar twelve, relative to
            the target directory. They are recorded in SEC 3 and in the sign-off
            payload so the dossier cannot point at a script that was never built.
            Accepted positionally for compatibility with earlier callers.
        signing_key: Optional explicit key bytes. When omitted the environment or
            the machine key is used.

    Returns:
        A frozen, HMAC stamped DossierReport.

    Raises:
        TypeError: When signing_key is not bytes-like.
        ValueError: When signing_key is empty or TAUHAULITY_SIGNING_KEY is
            malformed.
    """

    resolved_key, key_source = resolve_signing_key(signing_key)
    findings = _ordered_findings(ctx)
    verdict = compute_verdict(ctx)
    # The scorecard quotes the same evidence the dossier renders, so it is scored
    # from the sanitised findings: otherwise a credential that the dossier
    # redacted would still appear verbatim in the deduction ledger.
    scorecard = compute_scorecard(_scoring_context(findings), verdict.name)
    unsigned = DossierReport(
        target=str(ctx.target),
        os_label=ctx.platform.os_label,
        python_label=ctx.platform.python_label,
        hardware_label=ctx.platform.hardware_label,
        timestamp_utc=_utc_timestamp(),
        verdict=verdict,
        findings=findings,
        scorecard=scorecard,
        policy=ctx.policy,
        repro_files=tuple(str(name) for name in repro_files),
        hmac="",
        generated_by=_generated_by(),
        key_source=key_source,
        signing_key=resolved_key,
    )
    payload = report_hmac_payload(unsigned)
    signature = hmac_sha256_hex(payload, resolved_key)
    return replace(unsigned, hmac=signature)


def verify_report(report: DossierReport, *, key: bytes | None = None) -> bool:
    """Return True when the dossier HMAC still matches its own payload.

    Parameters:
        report: Dossier to verify; an unsigned report always fails.
        key: Optional explicit key. When omitted the key stored on the report is
            used, which keeps an explicitly signed snapshot verifiable without
            the caller having to retain the key separately.
    """

    if not report.hmac:
        return False
    effective = key if key is not None else getattr(report, "signing_key", None)
    return verify_hmac(report_hmac_payload(report), report.hmac, effective)


def _atomic_write(path: Path, text: str) -> None:
    """Write text to a temporary sibling and atomically replace the target.

    The temporary file is created in the destination directory so os.replace
    stays a same-filesystem rename, which is atomic on NTFS and ext4 alike.

    Raises:
        OSError: When the file cannot be written or replaced.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def write_reports(
    report: DossierReport,
    out_dir: Path,
    formats: tuple[str, ...] = FORMATS,
    *,
    signing_key: bytes | None = None,
) -> dict[str, Path]:
    """Persist the dossier in the requested formats.

    Parameters:
        report: Signed dossier snapshot.
        out_dir: Destination directory, created when missing.
        formats: Any subset of md, txt and json.
        signing_key: Optional key override for the md and txt file trailers. The
            key stored on the report is preferred, so normally this stays None.

    Returns:
        A mapping from format token to the absolute path written.

    Raises:
        ValueError: When formats is empty or contains an unknown token.
        OSError: When a file cannot be written.
    """

    requested = tuple(formats)
    if not requested:
        raise ValueError("at least one dossier format is required")
    unknown = sorted(set(requested) - set(FORMATS))
    if unknown:
        raise ValueError(f"unknown dossier formats: {unknown}; expected {FORMATS}")
    # Preserve the caller's order while dropping duplicates so a caller asking
    # for ("md", "md") does not produce two writes of the same artifact.
    ordered = list(dict.fromkeys(requested))

    writers = {
        "md": render_markdown,
        "txt": render_text,
        "json": render_json,
    }
    out_path = Path(out_dir)
    written: dict[str, Path] = {}
    for token in ordered:
        destination = out_path / REPORT_FILENAMES[token]
        if token == "json":
            text = render_json(report)
        else:
            text = writers[token](report, signing_key=signing_key)
        _atomic_write(destination, text)
        written[token] = destination
    return written


def render_reports(
    report: DossierReport,
    formats: Iterable[str] = FORMATS,
    *,
    signing_key: bytes | None = None,
) -> dict[str, str]:
    """Render the dossier in memory without touching the filesystem.

    The engine uses this when the destination is read only, and the tests use it
    to compare formats without creating a project tree.

    Parameters:
        report: Signed dossier snapshot.
        formats: Any subset of md, txt and json.
        signing_key: Optional key override for the md and txt file trailers.

    Raises:
        ValueError: When a format token is unknown.
    """

    writers = {
        "md": render_markdown,
        "txt": render_text,
        "json": render_json,
    }
    rendered: dict[str, str] = {}
    for token in formats:
        if token not in writers:
            raise ValueError(f"unknown dossier format: {token!r}")
        if token == "json":
            rendered[token] = render_json(report)
        else:
            rendered[token] = writers[token](report, signing_key=signing_key)
    return rendered


__all__ = [
    "FORMATS",
    "DossierReport",
    "build_report",
    "render_json",
    "render_markdown",
    "render_reports",
    "render_text",
    "report_hmac_payload",
    "verify_report",
    "write_reports",
]
