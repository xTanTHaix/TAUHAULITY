"""Reviewable finding suppression for the artifact scanner.

A scanner that cannot be run on its own codebase is not shippable, but a blanket
exemption for the tool's own files would be dishonest. This module implements the
narrow middle ground: an operator reviews the current findings, records a written
reason for the ones that are intentional, and every other finding keeps firing.
Four properties make that decision reviewable instead of silent:

* the unit of suppression is a fingerprint over kind, rel_path and symbol, where
  symbol is the enclosing function or class resolved from the AST. The line
  number is deliberately excluded, so inserting an import or moving a call inside
  the same function does not resurrect an accepted finding; renaming the
  enclosing function or class does change the fingerprint and forces a fresh
  review, because the reviewed code is no longer the same code;
* every entry carries the reviewer's reason and add() refuses an empty one, so a
  suppression can never be an anonymous mute;
* the file is tolerant on read: a missing, corrupt or hand edited store degrades
  to "no suppressions", never to a crash and never to a silent acceptance;
* the file is written atomically with 0600 permissions and carries a schema
  version plus generator stamp, mirroring .tauhaulity/allowlist.json.

The store lives at <project>/.tauhaulity/suppressions.json. The artifact scanner
imports filter_findings lazily, and this module imports the scanner lazily too, so
neither module creates an import cycle or breaks a partial checkout.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

SUPPRESS_DIRNAME = ".tauhaulity"
SUPPRESS_FILENAME = "suppressions.json"
SUPPRESS_VERSION = 1
GENERATOR = "tauhaulity.tools.suppress"


class SuppressionError(ValueError):
    """Raised when a suppression or the store cannot be written."""


class SuppressibleFinding(Protocol):
    """Structural type shared by ArtifactFinding and FindingKey."""

    rel_path: str
    kind: str
    symbol: str


def _utc_now() -> str:
    """Return an ISO 8601 UTC timestamp with second precision."""

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _normalize_rel_path(value: object) -> str:
    """Render a path as forward slash separated text without raising."""

    return str(value or "").replace(chr(92), "/")


def suppression_path(root: Path) -> Path:
    """Return the conventional suppression store path for a project root."""

    return Path(root) / SUPPRESS_DIRNAME / SUPPRESS_FILENAME


def fingerprint_finding(rel_path: str, kind: str, symbol: str) -> str:
    """Return the stable fingerprint of one suppressible finding.

    The material is exactly kind, rel_path and symbol joined by a pipe. The line
    number is deliberately absent: a fingerprint that moves when code above a
    call site is reflowed would turn every refactor into a resurrected finding and
    pressure the operator toward a broader grant. The enclosing symbol is present
    because moving a call into a different function or class does change what is
    being accepted, so the grant must be reviewed again.

    Parameters:
        rel_path: Project relative path, forward slash separated.
        kind: Finding family such as dangerous_api or pickle_unsafe.
        symbol: Enclosing function or class name, empty for file level findings.

    Returns:
        Lower case hexadecimal SHA-256 digest, 64 characters wide.
    """

    material = "|".join(
        (
            str(kind or ""),
            _normalize_rel_path(rel_path),
            str(symbol or ""),
        )
    )
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()


@dataclass(frozen=True, slots=True)
class FindingKey:
    """Identity of one finding as a reviewer sees it.

    Attributes:
        rel_path: Project relative path, forward slash separated.
        kind: Finding family reported by the scanner.
        line_no: One based source line, or None for file level findings.
        symbol: Enclosing function or class name, empty for file level findings.
    """

    rel_path: str
    kind: str
    line_no: int | None
    symbol: str

    @property
    def fingerprint(self) -> str:
        """Stable suppression fingerprint; independent of line_no."""

        return fingerprint_finding(self.rel_path, self.kind, self.symbol)


@dataclass(frozen=True, slots=True)
class SuppressionEntry:
    """One reviewed suppression recorded in the store.

    Attributes:
        fingerprint: Stored SHA-256 hex digest, recomputed on load.
        kind: Finding family this entry accepts.
        rel_path: Project relative path, forward slash separated.
        symbol: Enclosing function or class name, empty for file level findings.
        reason: Reviewer supplied justification; never empty.
        created_at: UTC ISO timestamp of the first acceptance.
    """

    fingerprint: str
    kind: str
    rel_path: str
    symbol: str
    reason: str
    created_at: str


def _entry_from(raw: object, fallback_stamp: str) -> SuppressionEntry | None:
    """Coerce one JSON record into a SuppressionEntry, or None when unusable.

    The fingerprint is recomputed from kind, rel_path and symbol instead of being
    trusted from the file: a hand edited or truncated digest can therefore never
    suppress a finding that its own fields do not name. An entry without a reason
    is dropped because an anonymous suppression is exactly what this mechanism
    must not allow.
    """

    if not isinstance(raw, Mapping):
        return None
    kind = raw.get("kind")
    rel_path = raw.get("rel_path")
    reason = raw.get("reason")
    symbol = raw.get("symbol")
    if not isinstance(kind, str) or not kind:
        return None
    if not isinstance(rel_path, str) or not rel_path:
        return None
    if not isinstance(reason, str) or not reason.strip():
        return None
    normalized_path = _normalize_rel_path(rel_path)
    symbol_text = symbol if isinstance(symbol, str) else ""
    stamp = raw.get("created_at")
    created_at = stamp if isinstance(stamp, str) and stamp else fallback_stamp
    return SuppressionEntry(
        fingerprint=fingerprint_finding(normalized_path, kind, symbol_text),
        kind=kind,
        rel_path=normalized_path,
        symbol=symbol_text,
        reason=reason.strip(),
        created_at=created_at,
    )


def _sort_entries(entries: Iterable[SuppressionEntry]) -> list[SuppressionEntry]:
    """Order entries deterministically for a reviewable diff."""

    return sorted(
        entries,
        key=lambda entry: (entry.rel_path, entry.kind, entry.symbol, entry.fingerprint),
    )


class SuppressionStore:
    """Read and write the reviewed suppression list of one project.

    Attributes:
        path: Conventional store path, even when the file is absent.
    """

    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._path = suppression_path(self._root)

    @property
    def root(self) -> Path:
        """Project root this store belongs to."""

        return self._root

    @property
    def path(self) -> Path:
        """Conventional suppression file path, even when the file is absent."""

        return self._path

    def load(self) -> list[SuppressionEntry]:
        """Load every valid suppression for the project.

        Every failure path returns an empty list rather than raising: the scanner
        must not crash because the store is unreadable, and it must not suppress
        anything it could not parse. Missing, unreadable, non JSON, wrong shaped
        and per-entry malformed stores all degrade to the same honest answer.
        """

        try:
            text = self._path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return []
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return []
        fallback_stamp = ""
        if isinstance(payload, Mapping):
            stamp = payload.get("created_at")
            fallback_stamp = stamp if isinstance(stamp, str) else ""
            candidate = payload.get("entries")
            raw_entries = candidate if isinstance(candidate, list) else []
        elif isinstance(payload, list):
            # A plain list is the obvious hand written shape for a small store.
            raw_entries = payload
        else:
            return []
        entries: dict[str, SuppressionEntry] = {}
        for raw in raw_entries:
            entry = _entry_from(raw, fallback_stamp)
            if entry is None or entry.fingerprint in entries:
                continue
            entries[entry.fingerprint] = entry
        return _sort_entries(entries.values())

    def add(self, entries: Iterable[SuppressibleFinding], reason: str) -> int:
        """Record reviewed suppressions, keeping existing grants intact.

        Parameters:
            entries: Findings the reviewer accepted, usually produced by
                list_suppression_candidates().
            reason: Non-empty justification stored on every new entry.

        Returns:
            Number of fingerprints that were not in the store before this call.

        Raises:
            SuppressionError: When the reason is empty or an entry is unusable.
        """

        clean_reason = " ".join(str(reason or "").split())
        if not clean_reason:
            raise SuppressionError("a suppression requires a non-empty reason")
        previous = {entry.fingerprint: entry for entry in self.load()}
        now = _utc_now()
        added = 0
        for item in entries:
            rel_path = _normalize_rel_path(getattr(item, "rel_path", ""))
            kind = str(getattr(item, "kind", "") or "")
            symbol = str(getattr(item, "symbol", "") or "")
            if not rel_path or not kind:
                raise SuppressionError("a suppression requires a kind and a relative path")
            fingerprint = fingerprint_finding(rel_path, kind, symbol)
            if fingerprint in previous:
                continue
            previous[fingerprint] = SuppressionEntry(
                fingerprint=fingerprint,
                kind=kind,
                rel_path=rel_path,
                symbol=symbol,
                reason=clean_reason,
                created_at=now,
            )
            added += 1
        if added:
            self._write(_sort_entries(previous.values()))
        return added

    def remove_all(self) -> bool:
        """Delete the stored suppression list.

        Returns:
            True when a file was removed, False when nothing was there.
        """

        try:
            if not self._path.is_file():
                return False
            self._path.unlink()
            return True
        except OSError:
            return False

    def _write(self, entries: list[SuppressionEntry]) -> None:
        """Write the store atomically with owner only permissions.

        Raises:
            SuppressionError: When the directory or the file cannot be written.
        """

        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise SuppressionError(
                "cannot create suppression directory " + str(self._path.parent) + ": " + str(exc)
            ) from exc
        payload = {
            "version": SUPPRESS_VERSION,
            "generator": GENERATOR,
            "created_at": _utc_now(),
            "entries": [
                {
                    "fingerprint": entry.fingerprint,
                    "kind": entry.kind,
                    "rel_path": entry.rel_path,
                    "symbol": entry.symbol,
                    "reason": entry.reason,
                    "created_at": entry.created_at,
                }
                for entry in entries
            ],
        }
        text = json.dumps(payload, indent=2, sort_keys=False) + chr(10)
        tmp = self._path.with_suffix(self._path.suffix + ".tmp")
        try:
            with tmp.open("w", encoding="utf-8", newline=chr(10)) as handle:
                handle.write(text)
            os.replace(tmp, self._path)
        except OSError as exc:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise SuppressionError(
                "cannot write suppression store " + str(self._path) + ": " + str(exc)
            ) from exc
        try:
            os.chmod(self._path, 0o600)
        except OSError:
            # A filesystem without POSIX mode bits is not a reason to fail.
            pass


def filter_findings(findings: Iterable[Any], store: SuppressionStore) -> tuple[list[Any], int]:
    """Split findings into the ones still active and the reviewed suppressions.

    Parameters:
        findings: ArtifactFinding objects, or anything with rel_path, kind and an
            optional symbol attribute.
        store: Reviewed suppression store for the scanned project.

    Returns:
        A (active_findings, suppressed_count) pair. Ordering of the active
        findings is preserved so the caller keeps reporting the first finding.
    """

    accepted = {entry.fingerprint for entry in store.load()}
    findings = list(findings)
    if not accepted:
        return findings, 0
    active: list[Any] = []
    suppressed = 0
    for finding in findings:
        try:
            fingerprint = fingerprint_finding(
                getattr(finding, "rel_path", ""),
                getattr(finding, "kind", ""),
                str(getattr(finding, "symbol", "") or ""),
            )
        except (TypeError, ValueError, AttributeError):
            active.append(finding)
            continue
        if fingerprint in accepted:
            suppressed += 1
        else:
            active.append(finding)
    return active, suppressed


def list_suppression_candidates(root: Path) -> list[FindingKey]:
    """Return the current scanner findings as reviewable suppression keys.

    This is the CLI hook: call it, show the keys (path, kind, line, symbol) to the
    operator, then pass the accepted subset to SuppressionStore.add() with a
    reason. Keys are deduplicated by fingerprint because the fingerprint excludes
    the line number, so two call sites inside the same function share one review
    decision.

    Raises:
        SuppressionError: When the artifact scanner is unavailable or the tree
            cannot be scanned.
    """

    try:
        from tauhaulity.tools import artifact_scan
    except ImportError as exc:
        raise SuppressionError("artifact scanner is unavailable: " + str(exc)) from exc
    root = Path(root)
    try:
        report = artifact_scan.scan_source_tree(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise SuppressionError("cannot scan " + str(root) + ": " + str(exc)) from exc
    seen: set[str] = set()
    keys: list[FindingKey] = []
    for finding in report.findings:
        key = FindingKey(
            rel_path=str(getattr(finding, "rel_path", "") or ""),
            kind=str(getattr(finding, "kind", "") or ""),
            line_no=getattr(finding, "line_no", None),
            symbol=str(getattr(finding, "symbol", "") or ""),
        )
        if key.fingerprint in seen:
            continue
        seen.add(key.fingerprint)
        keys.append(key)
    keys.sort(key=lambda item: (item.rel_path, item.kind, item.symbol, item.line_no or 0))
    return keys
