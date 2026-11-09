"""Integrity verification for the three dossier formats.

A dossier is evidence, so the reader needs a way to ask one question: are these
the bytes that were signed? The answer differs per format, and pretending
otherwise would be dishonest:

* The JSON dossier keeps the canonical hmac_sha256 field. Verification rebuilds
  the DossierReport from the payload, recomputes report.report_hmac_payload and
  compares the two digests in constant time.
* The Markdown and plain text dossiers carry the format independent INTEGRITY
  trailer described in tauhaulity.dossier.integrity. Verification recomputes
  sha256 over every preceding byte (checkable without a key) and the HMAC over
  the same bytes with the resolved key.

Every failure is reported as a value, never as an exception, for any file that can
be read: a verification helper that crashes on a corrupted dossier cannot be used
to triage one.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from tauhaulity.core.contracts import PILLAR_SPECS, Finding
from tauhaulity.core.policy import Policy, PolicyError
from tauhaulity.core.scorecard import compute_scorecard
from tauhaulity.core.verdict import Verdict
from tauhaulity.dossier.integrity import (
    FILE_STAMP_SCHEME,
    StampError,
    split_file_stamp,
)
from tauhaulity.dossier.model import DOSSIER_SCHEMA, DossierReport
from tauhaulity.dossier.redactor import resolve_signing_key
from tauhaulity.dossier.report import report_hmac_payload

# Scheme token reported for a JSON dossier verified through its canonical payload.
JSON_SCHEME: Final[str] = "canonical-json"

# Scheme and key source tokens used when nothing could be verified.
NO_SCHEME: Final[str] = "none"
NO_KEY_SOURCE: Final[str] = "none"

_SCHEME_BY_SUFFIX: Final[dict[str, str]] = {
    ".md": FILE_STAMP_SCHEME,
    ".txt": FILE_STAMP_SCHEME,
    ".json": JSON_SCHEME,
}

# Human readable list used in the unsupported extension message.
_SUPPORTED_EXTENSIONS: Final[str] = ".md, .txt or .json"

_NO_KEY_REASON: Final[str] = (
    "no signing key available: pass an explicit key or enable the machine key fallback"
)


class _PayloadError(ValueError):
    """Internal: the JSON payload lacks a field needed to rebuild the report."""


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Outcome of verifying one dossier file.

    Attributes:
        valid: True only when every check for the detected format passed.
        scheme: Detection result: 'file-stamp', 'canonical-json' or 'none'.
        digest: Recomputed digest that was compared, or an empty string when no
            digest could be computed.
        reason: One line English explanation, always populated.
        key_source: Origin of the key used for verification: 'explicit', 'env',
            'machine' or 'none'.
    """

    valid: bool
    scheme: str
    digest: str
    reason: str
    key_source: str


def _resolve_verification_key(
    key: bytes | None,
    *,
    use_machine_key: bool,
) -> tuple[bytes | None, str, str]:
    """Resolve the key used to check a file, without raising for bad configuration.

    Returns:
        A tuple of the key (None when unavailable), the key source token and an
        empty reason or one explaining why no key could be resolved.
    """

    if key is not None:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("verification key must be bytes")
        if not key:
            raise ValueError("verification key must not be empty")
        return bytes(key), "explicit", ""
    try:
        candidate, source = resolve_signing_key()
    except ValueError as exc:
        return None, NO_KEY_SOURCE, f"cannot resolve signing key: {exc}"
    if source == "machine" and not use_machine_key:
        return None, NO_KEY_SOURCE, _NO_KEY_REASON
    return candidate, source, ""


def _read_bytes(path: Path) -> tuple[bytes | None, str]:
    """Read a dossier file, returning bytes plus an empty reason or an error."""

    try:
        return path.read_bytes(), ""
    except OSError as exc:
        detail = exc.strerror or exc.__class__.__name__
        return None, f"cannot read dossier file: {detail}"


def _verify_file_stamp(
    path: Path,
    key: bytes | None,
    key_source: str,
    key_reason: str,
) -> VerificationResult:
    """Verify a Markdown or plain text dossier through its INTEGRITY trailer."""

    raw, read_error = _read_bytes(path)
    if raw is None:
        return VerificationResult(False, FILE_STAMP_SCHEME, "", read_error, key_source)
    if raw.startswith(b"\xef\xbb\xbf"):
        return VerificationResult(
            False,
            FILE_STAMP_SCHEME,
            "",
            "dossier file starts with a byte order mark",
            key_source,
        )
    try:
        stamp = split_file_stamp(raw)
    except StampError as exc:
        return VerificationResult(False, FILE_STAMP_SCHEME, "", exc.reason, key_source)
    digest = hashlib.sha256(stamp.payload).hexdigest()
    if not hmac.compare_digest(digest, stamp.sha256_hex):
        return VerificationResult(
            False,
            FILE_STAMP_SCHEME,
            digest,
            "sha256 mismatch: file bytes changed after the INTEGRITY trailer was written",
            key_source,
        )
    if key is None:
        return VerificationResult(
            False,
            FILE_STAMP_SCHEME,
            digest,
            key_reason or _NO_KEY_REASON,
            key_source,
        )
    expected = hmac.new(key, stamp.payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, stamp.hmac_hex):
        return VerificationResult(
            False,
            FILE_STAMP_SCHEME,
            digest,
            "hmac mismatch: the file was signed with a different key",
            key_source,
        )
    return VerificationResult(
        True,
        FILE_STAMP_SCHEME,
        digest,
        "INTEGRITY trailer matches the file bytes",
        key_source,
    )


def _text_field(payload: dict[str, Any], name: str) -> str:
    """Return a required string field of the JSON dossier."""

    value = payload.get(name)
    if not isinstance(value, str):
        raise _PayloadError(f"field {name!r} must be a string")
    return value


def _number_field(value: object, name: str) -> float:
    """Return a required numeric field of the JSON dossier."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise _PayloadError(f"field {name!r} must be a number")
    return float(value)


def _int_field(value: object, name: str) -> int:
    """Return a required integer field of the JSON dossier."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise _PayloadError(f"field {name!r} must be an integer")
    return value


def _pillar_findings(payload: dict[str, Any]) -> tuple[Finding, ...]:
    """Rebuild the twelve ordered findings from the JSON pillar rows."""

    rows = payload.get("pillars")
    if not isinstance(rows, list) or len(rows) != len(PILLAR_SPECS):
        raise _PayloadError(f"json dossier must list exactly {len(PILLAR_SPECS)} pillars")
    findings: list[Finding] = []
    for spec, row in zip(PILLAR_SPECS, rows):
        if not isinstance(row, dict):
            raise _PayloadError(f"pillar {spec.number} row must be an object")
        number = _int_field(row.get("pillar"), f"pillar {spec.number} number")
        if number != spec.number:
            raise _PayloadError(f"pillar rows must be ordered 1..{len(PILLAR_SPECS)}")
        status = row.get("status")
        detail = row.get("finding")
        if not isinstance(status, str) or not isinstance(detail, str):
            raise _PayloadError(f"pillar {spec.number} needs string status and finding fields")
        slots_raw = row.get("slots") or {}
        if not isinstance(slots_raw, dict):
            raise _PayloadError(f"pillar {spec.number} slots must be an object")
        repro_hint = row.get("repro_hint") or None
        if repro_hint is not None and not isinstance(repro_hint, str):
            raise _PayloadError(f"pillar {spec.number} repro_hint must be a string")
        findings.append(
            Finding(
                pillar=spec.number,
                status=status,
                detail=detail,
                risk=_number_field(row.get("risk"), f"pillar {spec.number} risk"),
                slots={str(slot): str(value) for slot, value in slots_raw.items()},
                repro_hint=repro_hint,
            )
        )
    return tuple(findings)


def _context_from_findings(findings: tuple[Finding, ...], policy: Policy) -> object:
    """Return a minimal scan context so the scorecard can be recomputed.

    Only the findings and the policy are needed to score a snapshot, so this
    avoids importing the engine and its platform probe into the verifier.
    """

    from types import SimpleNamespace

    return SimpleNamespace(findings={finding.pillar: finding for finding in findings}, policy=policy)


def _report_from_payload(payload: dict[str, Any]) -> DossierReport:
    """Rebuild a DossierReport from a JSON dossier payload.

    The canonical HMAC payload is derived from the report object, so a JSON file
    can only be verified by reconstructing the snapshot it was rendered from.
    Every field read here is covered by report_hmac_payload, which is why a
    missing or retyped field is reported as a verification failure rather than
    ignored.

    Raises:
        _PayloadError: When a required field is absent or has the wrong type.
    """

    findings = _pillar_findings(payload)
    verdict_raw = payload.get("overall_security_verdict")
    if not isinstance(verdict_raw, dict):
        raise _PayloadError("field 'overall_security_verdict' must be an object")
    verdict_name = verdict_raw.get("name")
    if not isinstance(verdict_name, str):
        raise _PayloadError("verdict name must be a string")
    verdict = Verdict(
        name=verdict_name,
        code=_int_field(verdict_raw.get("code"), "verdict code"),
        risk=_number_field(verdict_raw.get("risk"), "verdict risk"),
        bitmask=_int_field(verdict_raw.get("bitmask"), "verdict bitmask"),
    )
    policy_raw = payload.get("policy")
    if not isinstance(policy_raw, dict):
        raise _PayloadError("field 'policy' must be an object")
    try:
        policy = Policy.from_dict(policy_raw)
    except PolicyError as exc:
        raise _PayloadError(f"policy is invalid: {exc}") from None
    repro_raw = payload.get("repro_files") or []
    if not isinstance(repro_raw, list):
        raise _PayloadError("field 'repro_files' must be a list")
    # The scorecard is derived from the findings, so it is recomputed here rather
    # than read from the document. That is what makes a tampered score detectable:
    # the canonical payload includes the recomputed score, so an edited score in
    # the file no longer matches the signature.
    scorecard = compute_scorecard(_context_from_findings(findings, policy), verdict_name)
    return DossierReport(
        target=_text_field(payload, "target"),
        os_label=_text_field(payload, "host_operating_system"),
        python_label=_text_field(payload, "python_runtime_engine"),
        hardware_label=_text_field(payload, "active_hardware_primitives"),
        timestamp_utc=_text_field(payload, "scan_timestamp_utc"),
        verdict=verdict,
        findings=findings,
        scorecard=scorecard,
        policy=policy,
        repro_files=tuple(str(name) for name in repro_raw),
        hmac="",
        generated_by=_text_field(payload, "generated_by"),
    )


def _verify_json(
    path: Path,
    key: bytes | None,
    key_source: str,
    key_reason: str,
) -> VerificationResult:
    """Verify a JSON dossier through its canonical payload HMAC."""

    raw, read_error = _read_bytes(path)
    if raw is None:
        return VerificationResult(False, JSON_SCHEME, "", read_error, key_source)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return VerificationResult(
            False, JSON_SCHEME, "", "json dossier is not valid UTF-8", key_source
        )
    if text.startswith("\ufeff"):
        return VerificationResult(
            False, JSON_SCHEME, "", "json dossier starts with a byte order mark", key_source
        )
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return VerificationResult(
            False, JSON_SCHEME, "", "json dossier is not valid JSON", key_source
        )
    if not isinstance(payload, dict):
        return VerificationResult(
            False, JSON_SCHEME, "", "json dossier must contain a top level object", key_source
        )
    schema = payload.get("schema")
    if schema != DOSSIER_SCHEMA:
        return VerificationResult(
            False,
            JSON_SCHEME,
            "",
            f"unsupported dossier schema {schema!r}; expected {DOSSIER_SCHEMA}",
            key_source,
        )
    stored = payload.get("hmac_sha256")
    if not isinstance(stored, str) or not stored:
        return VerificationResult(
            False,
            JSON_SCHEME,
            "",
            "json dossier is missing the hmac_sha256 signature",
            key_source,
        )
    try:
        report = _report_from_payload(payload)
    except _PayloadError as exc:
        return VerificationResult(
            False, JSON_SCHEME, "", f"json dossier is not a verifiable report: {exc}", key_source
        )
    canonical = report_hmac_payload(report)
    if key is None:
        return VerificationResult(
            False,
            JSON_SCHEME,
            "",
            key_reason or _NO_KEY_REASON,
            key_source,
        )
    expected = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, stored.strip().lower()):
        return VerificationResult(
            False,
            JSON_SCHEME,
            expected,
            "hmac mismatch: the canonical payload was changed or the key is wrong",
            key_source,
        )
    return VerificationResult(
        True,
        JSON_SCHEME,
        expected,
        "canonical json payload hmac matches",
        key_source,
    )


def verify_dossier_file(
    path: str | Path,
    *,
    key: bytes | None = None,
    use_machine_key: bool = True,
) -> VerificationResult:
    """Verify one dossier file and report the outcome.

    The format is chosen by extension so a reader never has to say which scheme
    applies. JSON dossiers are checked through their canonical payload HMAC;
    Markdown and plain text dossiers are checked through the format independent
    INTEGRITY trailer.

    Parameters:
        path: Dossier file path.
        key: Optional explicit verification key bytes.
        use_machine_key: When False, an unset key and an unset
            TAUHAULITY_SIGNING_KEY do not fall back to the derived machine key,
            because the machine key is tamper-evident only. The result then
            reports that no key was available.

    Returns:
        A VerificationResult. Malformed, tampered and unsupported files are
        reported as invalid; only a programming error raises.

    Raises:
        TypeError: When key is not bytes-like.
        ValueError: When key is empty bytes.
    """

    target = Path(path)
    suffix = target.suffix.lower()
    scheme = _SCHEME_BY_SUFFIX.get(suffix, NO_SCHEME)
    if not target.exists():
        return VerificationResult(
            False, scheme, "", f"dossier file does not exist: {target}", NO_KEY_SOURCE
        )
    if not target.is_file():
        return VerificationResult(
            False, scheme, "", f"path is not a regular file: {target}", NO_KEY_SOURCE
        )
    if scheme == NO_SCHEME:
        label = suffix or "(no extension)"
        return VerificationResult(
            False,
            NO_SCHEME,
            "",
            f"unsupported dossier extension {label}; expected {_SUPPORTED_EXTENSIONS}",
            NO_KEY_SOURCE,
        )
    resolved_key, key_source, key_reason = _resolve_verification_key(
        key, use_machine_key=use_machine_key
    )
    if suffix == ".json":
        return _verify_json(target, resolved_key, key_source, key_reason)
    return _verify_file_stamp(target, resolved_key, key_source, key_reason)


__all__ = [
    "JSON_SCHEME",
    "VerificationResult",
    "verify_dossier_file",
]
