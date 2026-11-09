"""Accepted finding baseline for the credential scanner.

A scanner that repeats the same accepted finding on every run trains its reader
to ignore it, so the operator needs a documented way to say "this candidate is
known and accepted". The baseline stores one fingerprint per accepted candidate
instead of the raw secret: the fingerprint is derived from the detector family,
the project relative path and the masked rendering, and never from the line
number, because inserting an import must not resurrect a known candidate while a
genuinely new secret in the same file must still be reported.

Two properties are load bearing:

  * the file is tolerant on read. A missing, truncated, hand edited or
    permission denied allowlist degrades to an empty baseline, so a broken
    allowlist can never turn the scanner into a crash and can never silently
    accept anything it did not record;
  * the file never contains secret material. Only the masked rendering travels
    into .tauhaulity/allowlist.json, so the allowlist itself is not a second
    leak that a scanner would have to find.

The baseline covers file candidates and credentials embedded in remote URLs.
Remote credentials are recorded under the synthetic path .git/config because
that is where git keeps them and because the scanner deliberately parses that
file instead of scanning it as ordinary source.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tauhaulity.tools.git_sentinel import SecretHit

ALLOWLIST_DIRNAME = ".tauhaulity"
ALLOWLIST_FILENAME = "allowlist.json"
BASELINE_VERSION = 1
GENERATOR = "tauhaulity.tools.allowlist"

#: Synthetic path and detector family recorded for credentials embedded in a
#: remote URL, which the scanner reports separately from file candidates.
REMOTE_CREDENTIAL_PATH = ".git/config"
REMOTE_CREDENTIAL_KIND = "remote_url"

#: Fingerprints are truncated to 128 bits. That is far shorter than a full
#: SHA-256 digest while remaining collision free for a project wide allowlist,
#: and it keeps the JSON file readable by a human reviewer.
_FINGERPRINT_CHARS = 32

#: Number of added entries rendered into BaselineReport.active_preview.
PREVIEW_LIMIT = 10


class AllowlistError(RuntimeError):
    """Raised when the baseline cannot be scanned or written."""


@dataclass(frozen=True, slots=True)
class BaselineEntry:
    """One accepted credential candidate.

    Attributes:
        fingerprint: Stable hash of kind, relative path and masked rendering.
        kind: Detector family such as github_token or remote_url.
        rel_path: Project relative path, forward slash separated.
        masked: Renderable form of the candidate; never the secret itself.
        created_at: UTC ISO timestamp of the first acceptance.
    """

    fingerprint: str
    kind: str
    rel_path: str
    masked: str
    created_at: str


@dataclass(frozen=True, slots=True)
class Baseline:
    """The accepted finding set loaded from one project.

    Attributes:
        entries: Accepted candidates ordered by path, kind and fingerprint.
        path: Conventional allowlist path, even when the file is absent.
        created_at: Timestamp recorded by the last write, empty when unknown.
    """

    entries: tuple[BaselineEntry, ...] = ()
    path: Path | None = None
    created_at: str = ""

    def __len__(self) -> int:
        """Number of accepted candidates."""

        return len(self.entries)

    @property
    def is_empty(self) -> bool:
        """True when no candidate has been accepted."""

        return not self.entries

    @property
    def fingerprints(self) -> frozenset[str]:
        """Accepted fingerprints, ready for membership tests."""

        return frozenset(entry.fingerprint for entry in self.entries)


@dataclass(frozen=True, slots=True)
class BaselineReport:
    """Outcome of recording the current findings as accepted.

    Attributes:
        path: Allowlist file that was written.
        added: Candidates that were not accepted before this write.
        total: Total accepted candidates after the write.
        active_preview: Masked renderings of the added candidates, bounded by
            PREVIEW_LIMIT, so a caller can show what was just accepted without
            touching secret material.
    """

    path: Path
    added: int
    total: int
    active_preview: list[str]


def baseline_path(root: Path) -> Path:
    """Return the conventional allowlist path for a project root."""

    return Path(root) / ALLOWLIST_DIRNAME / ALLOWLIST_FILENAME


def _utc_now() -> str:
    """Return an ISO 8601 UTC timestamp with second precision."""

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _normalize_rel_path(value: object) -> str:
    """Render a path as forward slash separated text without raising."""

    text = str(value or "")
    return text.replace(chr(92), "/")


def fingerprint_hit(hit: "SecretHit") -> str:
    """Return the stable fingerprint of one credential candidate.

    The fingerprint deliberately ignores the line number: refactoring a file
    moves lines around constantly, and a baseline that forgets a known token
    after an inserted import is worse than no baseline at all. The masked
    rendering is part of the material so a rotated value in the same file is a
    new candidate, and the detector family is part of it so a token reclassified
    by a future scanner version stays visible as a change.

    Parameters:
        hit: Credential candidate; only kind, rel_path and masked are read.

    Returns:
        Lower case hexadecimal fingerprint, 32 characters wide.
    """

    material = "|".join(
        (
            str(getattr(hit, "kind", "") or ""),
            _normalize_rel_path(getattr(hit, "rel_path", "")),
            str(getattr(hit, "masked", "") or ""),
        )
    )
    return hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[
        :_FINGERPRINT_CHARS
    ]


def _entry_from(raw: object, created_at: str) -> BaselineEntry | None:
    """Coerce one JSON record into a BaselineEntry, or None when unusable.

    Unknown keys are ignored instead of rejected so a newer writer that adds a
    field does not break an older reader, and a record without a fingerprint is
    dropped because such an entry could suppress nothing anyway.
    """

    if not isinstance(raw, Mapping):
        return None
    fingerprint = raw.get("fingerprint")
    if not isinstance(fingerprint, str) or not fingerprint:
        return None
    kind = raw.get("kind")
    rel_path = raw.get("rel_path")
    masked = raw.get("masked")
    stamp = raw.get("created_at")
    return BaselineEntry(
        fingerprint=fingerprint,
        kind=str(kind) if isinstance(kind, str) else "",
        rel_path=_normalize_rel_path(rel_path),
        masked=str(masked) if isinstance(masked, str) else "",
        created_at=str(stamp) if isinstance(stamp, str) and stamp else created_at,
    )


def load_baseline(root: Path) -> Baseline:
    """Load the accepted finding set for a project.

    Every failure path returns an empty baseline rather than raising: a security
    gate must not crash because the allowlist is unreadable, and it must not
    suppress anything it could not parse. An empty result is therefore both the
    "no baseline yet" and the "broken baseline" answer, which is the fail open on
    suppression and fail closed on blocking combination.

    Parameters:
        root: Project root containing .tauhaulity/allowlist.json.

    Returns:
        The parsed baseline, or an empty baseline when the file is absent,
        unreadable, not JSON, or shaped differently than expected.
    """

    path = baseline_path(root)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return Baseline((), path, "")
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return Baseline((), path, "")

    created_at = ""
    if isinstance(payload, Mapping):
        stamp = payload.get("created_at")
        created_at = stamp if isinstance(stamp, str) else ""
        candidate = payload.get("entries")
        raw_entries = candidate if isinstance(candidate, list) else []
    elif isinstance(payload, list):
        # A plain list is accepted because it is the obvious hand written shape
        # for a small allowlist; it carries no creation stamp.
        raw_entries = payload
    else:
        raw_entries = []

    entries: list[BaselineEntry] = []
    seen: set[str] = set()
    for raw in raw_entries:
        entry = _entry_from(raw, created_at)
        if entry is None or entry.fingerprint in seen:
            continue
        seen.add(entry.fingerprint)
        entries.append(entry)
    entries.sort(key=lambda entry: (entry.rel_path, entry.kind, entry.fingerprint))
    return Baseline(tuple(entries), path, created_at)


def filter_hits(
    hits: list["SecretHit"], baseline: Baseline
) -> tuple[list["SecretHit"], int]:
    """Split candidates into still active hits and baseline suppressed ones.

    Parameters:
        hits: Candidates in scanner order.
        baseline: Accepted fingerprint set.

    Returns:
        A (active_hits, suppressed_count) pair. Ordering of the active hits is
        preserved so a caller can keep reporting the first finding by path.
    """

    accepted = baseline.fingerprints
    if not accepted:
        return list(hits), 0
    active: list["SecretHit"] = []
    suppressed = 0
    for hit in hits:
        try:
            fingerprint = fingerprint_hit(hit)
        except (TypeError, ValueError, AttributeError):
            active.append(hit)
            continue
        if fingerprint in accepted:
            suppressed += 1
        else:
            active.append(hit)
    return active, suppressed


def _scan_candidates(root: Path) -> list["SecretHit"]:
    """Collect every candidate the scanner reports, including remote URLs.

    The scanner keeps remote URL credentials in a separate list because they are
    parsed from git metadata rather than matched inside source text. The baseline
    needs one uniform candidate shape, so they are materialized as synthetic hits
    under the path git actually stores them in.
    """

    try:
        from tauhaulity.tools.git_sentinel import SecretHit, inspect_repository
    except ImportError as exc:
        raise AllowlistError("credential scanner is unavailable: " + str(exc)) from exc
    try:
        # History is included so that an accepted legacy leak can be baselined
        # too; without it "tauhaulity baseline" would report the same historical
        # credential on every scan with no way to acknowledge it.
        report = inspect_repository(root, check_hook=False, use_baseline=False, history=True)
    except (OSError, RuntimeError, ValueError) as exc:
        raise AllowlistError("cannot scan " + str(root) + ": " + str(exc)) from exc
    hits: list[SecretHit] = list(report.secrets) + list(report.history_secrets)
    for credential in report.remote_credentials:
        hits.append(
            SecretHit(REMOTE_CREDENTIAL_PATH, 0, REMOTE_CREDENTIAL_KIND, credential)
        )
    return hits


def _write_baseline_file(path: Path, payload: dict) -> None:
    """Write the allowlist atomically, surfacing write failures."""

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise AllowlistError(
            "cannot create allowlist directory " + str(path.parent) + ": " + str(exc)
        ) from exc
    tmp = path.with_suffix(path.suffix + ".tmp")
    text = json.dumps(payload, indent=2, sort_keys=False) + chr(10)
    try:
        with tmp.open("w", encoding="utf-8", newline=chr(10)) as handle:
            handle.write(text)
        os.replace(tmp, path)
    except OSError as exc:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise AllowlistError("cannot write allowlist " + str(path) + ": " + str(exc)) from exc
    try:
        os.chmod(path, 0o600)
    except OSError:
        # A filesystem without POSIX mode bits is not a reason to fail the write.
        pass


def write_baseline(root: Path) -> BaselineReport:
    """Scan the project and record every current candidate as accepted.

    Candidates that were already accepted keep their original timestamp, so
    refreshing the baseline after fixing one secret does not rewrite the history
    of the others and the diff of the allowlist stays reviewable. Candidates that
    are no longer present are dropped, so the allowlist never accumulates grants
    for content that no longer exists.

    Parameters:
        root: Project root to scan and to write the allowlist into.

    Returns:
        The written path, how many candidates were newly added and a masked
        preview of those additions.

    Raises:
        AllowlistError: When the scanner is unavailable or the file cannot be
            written.
    """

    root = Path(root)
    try:
        is_directory = root.is_dir()
    except OSError:
        is_directory = False
    if not is_directory:
        # Writing an empty allowlist would also create the missing directory tree,
        # which turns a typo in a path into a new project on disk.
        raise AllowlistError("baseline root is not a directory: " + str(root))
    path = baseline_path(root)
    previous = load_baseline(root)
    stamps = {entry.fingerprint: entry.created_at for entry in previous.entries}
    now = _utc_now()

    entries: dict[str, BaselineEntry] = {}
    for hit in _scan_candidates(root):
        fingerprint = fingerprint_hit(hit)
        if fingerprint in entries:
            continue
        entries[fingerprint] = BaselineEntry(
            fingerprint=fingerprint,
            kind=str(getattr(hit, "kind", "") or ""),
            rel_path=_normalize_rel_path(getattr(hit, "rel_path", "")),
            masked=str(getattr(hit, "masked", "") or ""),
            created_at=stamps.get(fingerprint) or now,
        )

    ordered = sorted(
        entries.values(), key=lambda entry: (entry.rel_path, entry.kind, entry.fingerprint)
    )
    added = [entry for entry in ordered if entry.fingerprint not in stamps]
    payload = {
        "version": BASELINE_VERSION,
        "generator": GENERATOR,
        "created_at": now,
        "entries": [
            {
                "fingerprint": entry.fingerprint,
                "kind": entry.kind,
                "rel_path": entry.rel_path,
                "masked": entry.masked,
                "created_at": entry.created_at,
            }
            for entry in ordered
        ],
    }
    _write_baseline_file(path, payload)
    preview = [
        entry.kind + " " + entry.masked + " in " + entry.rel_path
        for entry in added[:PREVIEW_LIMIT]
    ]
    return BaselineReport(path=path, added=len(added), total=len(ordered), active_preview=preview)


def remove_baseline(root: Path) -> bool:
    """Delete the stored allowlist.

    Parameters:
        root: Project root containing the allowlist.

    Returns:
        True when a file was removed, False when nothing was there.
    """

    path = baseline_path(root)
    try:
        if not path.is_file():
            return False
        path.unlink()
        return True
    except OSError:
        return False
