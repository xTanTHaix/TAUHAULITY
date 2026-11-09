"""Pillar eleven: git credential sentinel and signed dossier form (GIT-DOSSIER).

The probe reports what a push would expose: credential candidates in staged
blobs and project files, credentials embedded in remote URLs, credentials left in
recent commit history, and whether the pre-commit gate is installed to stop the
next one. Candidates accepted in the project allowlist are subtracted from the
active count, and the detail line always states how many were suppressed so a
clean report can never hide an allowlist that accepts more than the operator
believes it does.

A clean project is reported as SECURE with risk zero: a repository cannot be
expected to carry the gate before anything is wrong, and a missing hook must not
turn an otherwise safe verdict into AT_RISK. The detail still names the hook
state and the exact install command, so the suggestion stays visible without
driving the verdict.

Each active finding contributes a revocation hint, so the detail tells the reader
what to revoke and not only that something was found. The detail is sanitized
through the dossier redactor when that sibling module is importable and is then
HMAC signed, so a reader can tell an untouched report from an edited one.

The signing key is derived from machine identity, not from a shared secret: it
proves the detail was produced on this host for this project path, and it is
reported as an integrity fingerprint rather than a cryptographic proof of
authorship, because no secret key exchange exists in a zero dependency tool.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import platform
from pathlib import Path

from tauhaulity.core.contracts import SPEC_BY_KEY, Finding, ScanContext, make_finding

SPEC = SPEC_BY_KEY["git_dossier"]

_KEY_PREFIX = "tauhaulity-dossier-v1"
_HMAC_SLOT_CHARS = 32

_RISK_BY_STATUS: dict[str, float] = {
    "LEAK_DETECTED": 9.0,
    "WARNING": 4.0,
}

#: A clean project must not drive the overall verdict, so it carries no risk.
_RISK_CLEAN = 0.0

#: Everything found is already accepted by the baseline: honest, but worth a
#: small non-zero risk so a reader knows the allowlist is doing work.
_RISK_BASELINE_ONLY = 0.5

#: Hard bound for the history walk. A dossier probe runs on every audit, so it
#: deliberately inspects less history than a manual scan_history call would.
_HISTORY_MAX_COMMITS = 60

#: Number of distinct revocation hints rendered into the detail line.
_HINT_LIMIT = 3


def _machine_key(root: Path) -> bytes:
    """Derive a stable per machine, per project signing key.

    The material is public by design; the point is reproducibility, so that the
    same report regenerated on the same host for the same project yields the same
    digest while a copy pasted from another machine does not.
    """

    try:
        host = platform.node()
    except (OSError, RuntimeError):
        host = ""
    try:
        user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    except (OSError, TypeError):
        user = ""
    try:
        resolved = str(root.resolve())
    except (OSError, RuntimeError):
        resolved = str(root)
    material = "|".join(
        (_KEY_PREFIX, host, platform.platform(), resolved, user)
    )
    return hashlib.sha256(material.encode("utf-8", errors="replace")).digest()


def _local_redact(text: str) -> tuple[str, int]:
    """Mask credential patterns with the sentinel scanner as a last resort.

    This is the safety net for the redaction step: if the dossier redactor is
    missing or violates its contract, the detail must still not carry raw
    credential material.
    """

    try:
        from tauhaulity.tools.git_sentinel import redact_text
    except ImportError:
        return text, 0
    try:
        return redact_text(text)
    except (TypeError, ValueError, RuntimeError):
        return text, 0


def _redact_detail(text: str) -> tuple[str, int]:
    """Sanitize a detail line, returning the redacted text and a hit count.

    The dossier redactor returns a (text, count) pair. Any other return shape is
    treated as a contract violation - never as "nothing to redact" - because
    falling back to the raw text would put a credential into the dossier, which
    is the exact failure this pillar exists to prevent.
    """

    try:
        from tauhaulity.dossier.redactor import redact_text as dossier_redact
    except ImportError:
        return _local_redact(text)
    try:
        result = dossier_redact(text)
    except (TypeError, ValueError, AttributeError, RuntimeError, OSError):
        return _local_redact(text)
    if isinstance(result, tuple) and len(result) >= 2 and isinstance(result[0], str):
        if isinstance(result[1], int):
            return result[0], int(result[1])
        masked, count = _local_redact(text)
        return result[0], count
    if isinstance(result, str):
        _masked, count = _local_redact(text)
        return result, count
    return _local_redact(text)


def _dossier_machine_key() -> bytes | None:
    """Return the dossier signing key as bytes when that helper is importable."""

    try:
        from tauhaulity.dossier.redactor import machine_key
    except ImportError:
        return None
    for args in ((), (None,)):
        try:
            value = machine_key(*args)
        except (TypeError, ValueError, AttributeError, RuntimeError, OSError):
            continue
        if isinstance(value, bytes) and value:
            return value
        if isinstance(value, str) and value:
            return value.encode("utf-8", errors="replace")
        return None
    return None


def _sign(text: str, root: Path) -> str:
    """Sign the detail line with the dossier HMAC helper or a local HMAC.

    The dossier helper expects a bytes key, so a hex string key would raise a
    TypeError and silently leave the report unsigned; both the explicit key and
    the helper's own machine_key() derivation are tried with bytes only.
    """

    try:
        from tauhaulity.dossier.redactor import hmac_sha256_hex
    except ImportError:
        return hmac.new(
            _machine_key(root), text.encode("utf-8", errors="replace"), hashlib.sha256
        ).hexdigest()
    key = _dossier_machine_key()
    if key is not None:
        try:
            value = hmac_sha256_hex(text, key)
        except (TypeError, ValueError, AttributeError, RuntimeError, OSError):
            value = None
        if isinstance(value, str) and value:
            return value
    try:
        value = hmac_sha256_hex(text)
    except (TypeError, ValueError, AttributeError, RuntimeError, OSError):
        value = None
    if isinstance(value, str) and value:
        return value
    return hmac.new(
        _machine_key(root), text.encode("utf-8", errors="replace"), hashlib.sha256
    ).hexdigest()


def _hook_label(installed: bool) -> str:
    """Return the dossier slot token for the hook state."""

    return "INSTALLED" if installed else "MISSING"


def _first_evidence(report: object) -> str:
    """Return the masked location of the first finding, or an empty string.

    Current findings win over history findings because they are the ones a push
    would expose right now; remote URL credentials come last because they are
    already masked as a whole URL. Only masked text is ever returned.
    """

    secrets = list(getattr(report, "secrets", []) or [])
    if secrets:
        first = secrets[0]
        return (
            "; first: "
            + first.masked
            + " in "
            + first.rel_path
            + ":"
            + str(first.line_no)
        )
    history = list(getattr(report, "history_secrets", []) or [])
    if history:
        first = history[0]
        return (
            "; first history: "
            + first.masked
            + " in "
            + first.rel_path
            + ":"
            + str(first.line_no)
        )
    credentials = list(getattr(report, "remote_credentials", []) or [])
    if credentials:
        return "; first remote URL: " + credentials[0]
    return ""


def _hint_text(report: object) -> str:
    """Render the revocation hints of the active findings for the detail line.

    The hints are short actions such as "revoke the GitHub token ..."; they are
    distinct and capped, because a dossier detail is a single readable line and
    not a remediation manual.
    """

    raw = list(getattr(report, "revoked_hints", []) or [])
    hints: list[str] = []
    for value in raw:
        hint = str(value).strip()
        if hint and hint not in hints:
            hints.append(hint)
        if len(hints) >= _HINT_LIMIT:
            break
    if not hints:
        return ""
    return "; " + "; ".join(hints)


def probe(ctx: ScanContext) -> Finding:
    """Report credential exposure, history leaks and gate state for the project."""

    root = Path(ctx.target)
    try:
        from tauhaulity.tools.git_sentinel import inspect_repository
    except ImportError:
        detail = "git sentinel module is unavailable"
        return make_finding(
            SPEC,
            "WARNING",
            detail,
            risk=_RISK_BY_STATUS["WARNING"],
            slots={
                "hook_status": "UNKNOWN",
                "token_status": "UNKNOWN",
                "redacted_count": "0",
                "suppressed": "0",
                "history_count": "0",
                "hmac": "",
                "detail": detail,
            },
            repro_hint="import tauhaulity.tools.git_sentinel to see why the scanner is missing",
        )
    try:
        report = inspect_repository(
            root,
            check_hook=True,
            history=True,
            history_max_commits=_HISTORY_MAX_COMMITS,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        detail = "repository inspection failed: " + str(exc)
        return make_finding(
            SPEC,
            "WARNING",
            detail,
            risk=_RISK_BY_STATUS["WARNING"],
            slots={
                "hook_status": "UNKNOWN",
                "token_status": "UNKNOWN",
                "redacted_count": "0",
                "suppressed": "0",
                "history_count": "0",
                "hmac": _sign(detail, root)[:_HMAC_SLOT_CHARS],
                "detail": detail,
            },
            repro_hint="call tauhaulity.tools.git_sentinel.inspect_repository with the project root",
        )

    findings_text = report.findings_text or "repository inspected"
    current_hits = len(report.secrets) + len(report.remote_credentials)
    history_hits = int(getattr(report, "history_hits", 0) or 0)
    active_hits = current_hits + history_hits
    suppressed = int(getattr(report, "suppressed", 0) or 0)
    baseline_entries = int(getattr(report, "baseline_entries", 0) or 0)
    history_truncated = bool(getattr(report, "history_truncated", False))
    history_scanned = int(getattr(report, "history_scanned", 0) or 0)

    raw_detail = (
        "hook gate "
        + _hook_label(report.hook_installed)
        + "; "
        + str(current_hits)
        + " credential candidate(s) redacted; "
        + str(history_hits)
        + " in git history"
        + (" (truncated at bound)" if history_truncated else "")
        + "; "
        + str(suppressed)
        + " candidate(s) suppressed by the baseline ("
        + str(baseline_entries)
        + " accepted fingerprint(s))"
        + "; history scanned "
        + str(history_scanned)
        + " commit(s)"
        + _hint_text(report)
        + "; "
        + findings_text
        + _first_evidence(report)
    )
    if active_hits == 0 and not report.hook_installed:
        # The suggestion stays visible but is only text: it must not make a clean
        # project look unsafe to the verdict calculator.
        raw_detail += "; run tauhaulity hook install to add the pre-commit gate"
    # The redactor sees a summary that is already masked by the scanner, so its
    # own count can legitimately be lower than the scanner hit count; taking the
    # maximum reports how many credentials were actually kept out of the report.
    detail, redactor_count = _redact_detail(raw_detail)
    redacted_count = max(active_hits, int(redactor_count))
    signature = _sign(detail + "|" + str(redacted_count), root)[:_HMAC_SLOT_CHARS]
    slots = {
        "hook_status": _hook_label(report.hook_installed),
        "token_status": "CLEAN" if active_hits == 0 else str(active_hits) + " SECRETS",
        "redacted_count": str(redacted_count),
        "suppressed": str(suppressed),
        "history_count": str(history_hits),
        "hmac": signature,
        "detail": detail,
    }

    if active_hits:
        first = report.secrets[0] if report.secrets else None
        history_first = (
            report.history_secrets[0]
            if getattr(report, "history_secrets", None)
            else None
        )
        target = first if first is not None else history_first
        hint = (
            "inspect staged content with tauhaulity.tools.git_sentinel.scan_staged, "
            "history with scan_history, then rotate "
            + (
                target.kind + " in " + target.rel_path
                if target is not None
                else "the reported credentials"
            )
        )
        return make_finding(
            SPEC,
            "LEAK_DETECTED",
            detail,
            risk=_RISK_BY_STATUS["LEAK_DETECTED"],
            slots=slots,
            repro_hint=hint,
        )

    if suppressed:
        return make_finding(
            SPEC,
            "SECURE",
            detail,
            risk=_RISK_BASELINE_ONLY,
            slots=slots,
        )

    return make_finding(SPEC, "SECURE", detail, risk=_RISK_CLEAN, slots=slots)
