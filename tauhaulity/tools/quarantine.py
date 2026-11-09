"""Quarantine: neutralise a detected artifact by moving it out of the load path.

Detection without prevention leaves the dangerous file exactly where the
interpreter will load it. Quarantine is the one prevention step that is honest,
reversible and needs no kernel access: the bytes leave the project, the original
mode bits and content are recorded so the decision can be undone, and every
refusal is reported instead of silently ignored.

Safety rules that are load bearing:

* the stored copy is written with owner only permissions inside the store, and
  the original is removed only after the stored copy has been verified by
  SHA-256; a failed copy leaves the original untouched;
* the manifest is one atomically written JSON file (temporary file plus
  os.replace), versioned, and carries a digest over the record set, so a corrupt
  or hand edited manifest degrades to an empty store instead of a crash;
* restore never deletes the stored copy on failure, and refuses to overwrite an
  existing file unless the content hash is identical (a real file the operator
  created at the old path wins);
* a path outside the quarantine root, an unreadable file, a symlink and a
  directory are refused with a reason in the report, never silently ignored;
* purge is explicit and only removes the records it was asked about.

The store lives at <root>/.tauhaulity/quarantine, one stored payload per item
and a quarantine.json manifest beside it. Nothing here imports a sibling module
at import time: the eligibility helper loads the scanner lazily.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

STORE_DIRNAME: Final[str] = "quarantine"
MANIFEST_FILENAME: Final[str] = "quarantine.json"
MANIFEST_VERSION: Final[int] = 1
GENERATOR: Final[str] = "tauhaulity.tools.quarantine"

STORE_DIR_MODE: Final[int] = 0o700
STORE_FILE_MODE: Final[int] = 0o600
DEFAULT_MODE: Final[int] = 0o600
COPY_CHUNK_BYTES: Final[int] = 1024 * 1024

#: Kinds whose evidence IS the artifact, so moving the file out of the load path
#: neutralises it without changing any source code. See ArtifactFinding.
ELIGIBLE_KINDS: Final[frozenset[str]] = frozenset(
    {
        "pickle_unsafe",
        "pickle_malformed",
        "pyc_mismatch",
        "pyc_invalid",
        "install_time_execution",
    }
)


class QuarantineError(ValueError):
    """Raised when a quarantine request is invalid and nothing may be written."""


@dataclass(frozen=True, slots=True)
class QuarantinedItem:
    """One artifact that was moved into the quarantine store.

    Attributes:
        item_id: Stable identifier of this quarantine event.
        original_path: Absolute path the artifact was removed from.
        stored_path: Absolute path of the verified copy inside the store.
        kind: Scanner finding kind that made the artifact eligible, or unknown.
        sha256: Lower case hexadecimal digest of the stored bytes.
        bytes: Size of the stored copy in bytes.
        quarantined_at: UTC ISO timestamp of the quarantine event.
        reason: Reviewer supplied justification; never empty.
        mode: Permission bits recorded from the original, applied on restore.
    """

    item_id: str
    original_path: str
    stored_path: str
    kind: str
    sha256: str
    bytes: int
    quarantined_at: str
    reason: str
    mode: int = DEFAULT_MODE


@dataclass(frozen=True, slots=True)
class QuarantineReport:
    """Outcome of one quarantine request.

    Attributes:
        items: Artifacts that are now stored in the quarantine directory.
        skipped: One line per refused or failed path, with the reason.
        store_path: Quarantine directory, even when nothing was written.
        detail: One line summary for the CLI and the dossier.
    """

    items: list[QuarantinedItem] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    store_path: Path | None = None
    detail: str = ""


def _utc_now() -> str:
    """Return an ISO 8601 UTC timestamp with second precision."""

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _one_line(text: object, limit: int = 200) -> str:
    """Collapse arbitrary text to one printable ASCII line."""

    cleaned = "".join(char if 32 <= ord(char) < 127 else " " for char in str(text))
    return " ".join(cleaned.split())[:limit]


def _sha256_file(path: Path) -> tuple[str, int]:
    """Return (hex digest, byte count) of a file, read in bounded chunks."""

    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(COPY_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _copy_file(source: Path, destination: Path) -> None:
    """Copy one file, creating the destination with owner only permissions.

    Exposed as a module level function so a test can monkeypatch it to verify
    that a failed copy leaves the original untouched.
    """

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    descriptor = os.open(destination, flags, STORE_FILE_MODE)
    try:
        with source.open("rb") as reader, os.fdopen(descriptor, "wb") as writer:
            while True:
                chunk = reader.read(COPY_CHUNK_BYTES)
                if not chunk:
                    break
                writer.write(chunk)
            writer.flush()
            os.fsync(writer.fileno())
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        raise
    try:
        os.chmod(destination, STORE_FILE_MODE)
    except OSError:
        # A filesystem without POSIX mode bits is not a reason to fail the copy.
        pass


def _safe_unlink(path: Path) -> None:
    """Remove a file, ignoring a missing file or a permission error."""

    try:
        path.unlink()
    except OSError:
        pass


def _inside(root: Path, candidate: Path) -> bool:
    """True when candidate is root itself or a descendant of root."""

    try:
        candidate.relative_to(root)
        return True
    except ValueError:
        return False


def _stored_name(item_id: str, original_name: str) -> str:
    """Build a store file name that keeps a small, safe suffix of the original."""

    suffix = Path(original_name).suffix.lower()
    safe_suffix = "".join(char for char in suffix if char.isalnum() or char == ".")[:12]
    return item_id + safe_suffix


def _item_id(original_path: Path, digest: str, taken: set[str]) -> str:
    """Derive a unique item identifier for one quarantine event."""

    material = str(original_path) + "|" + digest + "|" + _utc_now()
    base = hashlib.sha256(material.encode("utf-8", errors="replace")).hexdigest()[:16]
    candidate = base
    counter = 1
    while candidate in taken:
        counter += 1
        candidate = hashlib.sha256((material + "|" + str(counter)).encode("utf-8")).hexdigest()[:16]
    return candidate


def _record_from_item(item: QuarantinedItem) -> dict[str, object]:
    """Serialize one item for the manifest."""

    return {
        "item_id": item.item_id,
        "original_path": item.original_path,
        "stored_path": item.stored_path,
        "kind": item.kind,
        "sha256": item.sha256,
        "bytes": item.bytes,
        "quarantined_at": item.quarantined_at,
        "reason": item.reason,
        "mode": item.mode,
    }


def _item_from_record(raw: object) -> QuarantinedItem | None:
    """Coerce one manifest record into an item, or None when unusable."""

    if not isinstance(raw, Mapping):
        return None
    item_id = raw.get("item_id")
    original_path = raw.get("original_path")
    stored_path = raw.get("stored_path")
    digest = raw.get("sha256")
    if not all(isinstance(value, str) and value for value in (item_id, original_path, stored_path, digest)):
        return None
    try:
        size = int(raw.get("bytes", 0))
        mode = int(raw.get("mode", DEFAULT_MODE))
    except (TypeError, ValueError):
        return None
    kind = raw.get("kind")
    reason = raw.get("reason")
    stamp = raw.get("quarantined_at")
    return QuarantinedItem(
        item_id=item_id,
        original_path=original_path,
        stored_path=stored_path,
        kind=kind if isinstance(kind, str) and kind else "unknown",
        sha256=digest,
        bytes=size,
        quarantined_at=stamp if isinstance(stamp, str) else "",
        reason=reason if isinstance(reason, str) else "",
        mode=mode,
    )


def _records_digest(records: Sequence[Mapping[str, object]]) -> str:
    """Digest the record set so a hand edited manifest is detected."""

    canonical = json.dumps(list(records), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class QuarantineStore:
    """Move artifacts out of a project into a verified, reversible store.

    Attributes:
        path: Quarantine directory, even when it does not exist yet.
    """

    def __init__(self, root: Path) -> None:
        self._root = Path(root).resolve()
        self._path = self._root / ".tauhaulity" / STORE_DIRNAME
        self._manifest = self._path / MANIFEST_FILENAME

    @property
    def root(self) -> Path:
        """Project root this store belongs to."""

        return self._root

    @property
    def path(self) -> Path:
        """Quarantine directory, even when it does not exist yet."""

        return self._path

    @property
    def manifest_path(self) -> Path:
        """Manifest file path, even when it does not exist yet."""

        return self._manifest

    def quarantine(
        self,
        paths: Sequence[Path],
        *,
        reason: str,
        kinds: Mapping[str, str] | None = None,
        dry_run: bool = False,
    ) -> QuarantineReport:
        """Move the given files into the store after verifying every copy.

        Parameters:
            paths: Files to quarantine; each must resolve inside the project root.
            reason: Non-empty reviewer justification recorded on every item.
            kinds: Optional mapping from a path spelling (absolute, project
                relative or bare name) to the scanner kind that made it eligible.
            dry_run: When True, validate and report what would move without
                writing or deleting anything.

        Returns:
            A QuarantineReport naming every stored item and every refusal.

        Raises:
            QuarantineError: When the reason is empty.
        """

        reason_text = _one_line(reason, 240)
        if not reason_text:
            raise QuarantineError("quarantine requires a non-empty reason")
        skipped: list[str] = []
        if not self._root.is_dir():
            return QuarantineReport(
                items=[],
                skipped=[f"{self._root}: project root is not a readable directory"],
                store_path=self._path,
                detail="project root is not a readable directory, nothing was quarantined",
            )
        records = [dict(raw) for raw in self._read_records()]
        taken = {str(raw.get("item_id", "")) for raw in records}
        staged: list[tuple[QuarantinedItem, Path]] = []
        seen: set[str] = set()
        for raw_path in paths:
            item, problem = self._prepare(raw_path, reason_text, kinds, taken, seen)
            if item is None:
                skipped.append(problem)
                continue
            original = Path(item.original_path)
            if dry_run:
                staged.append((item, original))
                continue
            try:
                self._ensure_store_directory()
                _copy_file(original, Path(item.stored_path))
                stored_digest, stored_size = _sha256_file(Path(item.stored_path))
            except OSError as exc:
                _safe_unlink(Path(item.stored_path))
                skipped.append(f"{raw_path}: copy failed ({type(exc).__name__}), original kept")
                continue
            if stored_digest != item.sha256 or stored_size != item.bytes:
                _safe_unlink(Path(item.stored_path))
                skipped.append(f"{raw_path}: copy verification failed (sha256 mismatch), original kept")
                continue
            taken.add(item.item_id)
            staged.append((item, original))
        if dry_run:
            planned = [item for item, _ in staged]
            detail = (
                f"dry run: would quarantine {len(planned)} item(s), {len(skipped)} skipped; "
                f"store {self._path}"
            )
            return QuarantineReport(
                items=planned, skipped=skipped, store_path=self._path, detail=detail
            )
        if not staged:
            detail = f"nothing quarantined, {len(skipped)} path(s) skipped; store {self._path}"
            return QuarantineReport(items=[], skipped=skipped, store_path=self._path, detail=detail)
        pending_records = records + [_record_from_item(item) for item, _ in staged]
        try:
            self._write_manifest(pending_records)
        except OSError as exc:
            for item, _ in staged:
                _safe_unlink(Path(item.stored_path))
            skipped.extend(
                f"{item.original_path}: manifest write failed ({type(exc).__name__}), original kept"
                for item, _ in staged
            )
            return QuarantineReport(
                items=[],
                skipped=skipped,
                store_path=self._path,
                detail="manifest write failed, nothing was quarantined and every original was kept",
            )
        items: list[QuarantinedItem] = []
        kept_records = list(pending_records)
        for item, original in staged:
            try:
                original.unlink()
            except OSError as exc:
                _safe_unlink(Path(item.stored_path))
                kept_records = [
                    record
                    for record in kept_records
                    if str(record.get("item_id", "")) != item.item_id
                ]
                skipped.append(
                    f"{item.original_path}: cannot remove original ({type(exc).__name__}), copy discarded"
                )
                continue
            items.append(item)
        if len(items) != len(staged):
            try:
                self._write_manifest(kept_records)
            except OSError:
                pass
        detail = (
            f"{len(items)} item(s) quarantined, {len(skipped)} skipped; store {self._path}"
        )
        return QuarantineReport(
            items=items, skipped=skipped, store_path=self._path, detail=detail
        )

    def restore(self, item_id: str) -> bool:
        """Restore one quarantined artifact byte for byte with its mode bits.

        The stored copy is verified before and after the copy, and it is only
        deleted after the restore succeeds. An existing file at the original path
        is overwritten only when its digest equals the stored digest.

        Returns:
            True when the artifact was restored, False when anything refused it.
        """

        records = [dict(raw) for raw in self._read_records()]
        record = next(
            (raw for raw in records if str(raw.get("item_id", "")) == str(item_id)), None
        )
        if record is None:
            return False
        item = _item_from_record(record)
        if item is None:
            return False
        stored = Path(item.stored_path)
        if not _inside(self._path, stored):
            return False
        try:
            if not stored.is_file():
                return False
            stored_digest, stored_size = _sha256_file(stored)
        except OSError:
            return False
        if stored_digest != item.sha256 or stored_size != item.bytes:
            return False
        target = Path(item.original_path)
        if not _inside(self._root, target):
            return False
        if target.is_symlink() or target.exists():
            try:
                if not target.is_file():
                    return False
                existing_digest, _ = _sha256_file(target)
            except OSError:
                return False
            if existing_digest != item.sha256:
                return False
        temporary = target.parent / (target.name + ".quarantine-restore.tmp")
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            _copy_file(stored, temporary)
            restored_digest, restored_size = _sha256_file(temporary)
            if restored_digest != item.sha256 or restored_size != item.bytes:
                _safe_unlink(temporary)
                return False
            os.replace(temporary, target)
        except OSError:
            _safe_unlink(temporary)
            return False
        try:
            os.chmod(target, item.mode)
        except OSError:
            # A filesystem without POSIX mode bits restores content only.
            pass
        remaining = [
            raw for raw in records if str(raw.get("item_id", "")) != item.item_id
        ]
        try:
            self._write_manifest(remaining)
        except OSError:
            # The bytes are already back; keeping the record is the safe failure
            # direction because the stored copy is still present for a retry.
            return True
        _safe_unlink(stored)
        return True

    def list_items(self) -> list[QuarantinedItem]:
        """Return every manifest record, ordered by timestamp and identifier."""

        items: list[QuarantinedItem] = []
        for raw in self._read_records():
            item = _item_from_record(raw)
            if item is not None:
                items.append(item)
        items.sort(key=lambda item: (item.quarantined_at, item.item_id))
        return items

    def purge(self, item_id: str | None = None) -> int:
        """Delete stored copies explicitly.

        Parameters:
            item_id: One record to purge, or None to purge every record.

        Returns:
            Number of manifest records removed. Purge is never automatic.
        """

        records = [dict(raw) for raw in self._read_records()]
        if item_id is None:
            targets = records
        else:
            targets = [raw for raw in records if str(raw.get("item_id", "")) == str(item_id)]
        if not targets:
            return 0
        target_ids = {str(raw.get("item_id", "")) for raw in targets}
        remaining = [raw for raw in records if str(raw.get("item_id", "")) not in target_ids]
        try:
            self._write_manifest(remaining)
        except OSError:
            return 0
        for raw in targets:
            stored = raw.get("stored_path")
            if isinstance(stored, str) and stored:
                _safe_unlink(Path(stored))
        return len(targets)

    def usage_bytes(self) -> int:
        """Total stored payload bytes recorded in the manifest."""

        total = 0
        for raw in self._read_records():
            try:
                total += int(raw.get("bytes", 0))
            except (TypeError, ValueError):
                continue
        return max(total, 0)

    def _ensure_store_directory(self) -> None:
        """Create the store directory with owner only permissions."""

        self._path.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self._path, STORE_DIR_MODE)
        except OSError:
            pass

    def _read_records(self) -> list[dict[str, object]]:
        """Load the manifest records, degrading to an empty list when unusable."""

        try:
            text = self._manifest.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            return []
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return []
        if not isinstance(payload, Mapping):
            return []
        if payload.get("version") != MANIFEST_VERSION:
            return []
        raw_items = payload.get("items")
        if not isinstance(raw_items, list):
            return []
        records = [dict(raw) for raw in raw_items if isinstance(raw, Mapping)]
        expected = payload.get("records_digest")
        if not isinstance(expected, str) or _records_digest(records) != expected:
            return []
        return records

    def _write_manifest(self, records: Sequence[Mapping[str, object]]) -> None:
        """Write the manifest atomically with owner only permissions."""

        self._ensure_store_directory()
        payload = {
            "version": MANIFEST_VERSION,
            "generator": GENERATOR,
            "created_at": _utc_now(),
            "records_digest": _records_digest(records),
            "items": [dict(record) for record in records],
        }
        text = json.dumps(payload, indent=2, sort_keys=False) + chr(10)
        temporary = self._path / (MANIFEST_FILENAME + ".tmp")
        with temporary.open("w", encoding="utf-8", newline=chr(10)) as handle:
            handle.write(text)
        os.replace(temporary, self._manifest)
        try:
            os.chmod(self._manifest, STORE_FILE_MODE)
        except OSError:
            pass

    def _prepare(
        self,
        raw_path: Path,
        reason: str,
        kinds: Mapping[str, str] | None,
        taken: set[str],
        seen: set[str],
    ) -> tuple[QuarantinedItem | None, str]:
        """Validate one requested path and build its item, or return a refusal."""

        display = str(raw_path)
        path = Path(raw_path)
        try:
            if path.is_symlink():
                target = path.resolve(strict=False)
                if not _inside(self._root, target):
                    return None, f"{display}: symlink points outside the quarantine root"
                return None, f"{display}: symlink is refused, quarantine the target path explicitly"
            resolved = path.resolve(strict=True)
        except OSError as exc:
            return None, f"{display}: unreadable ({type(exc).__name__})"
        if not _inside(self._root, resolved):
            return None, f"{display}: path is outside the quarantine root"
        try:
            if not resolved.is_file():
                return None, f"{display}: not a regular file (directory or special file)"
        except OSError as exc:
            return None, f"{display}: unreadable ({type(exc).__name__})"
        key = str(resolved)
        if key in seen:
            return None, f"{display}: duplicate path in the same request"
        seen.add(key)
        try:
            digest, size = _sha256_file(resolved)
            mode = stat.S_IMODE(resolved.stat().st_mode)
        except OSError as exc:
            return None, f"{display}: unreadable ({type(exc).__name__})"
        identifier = _item_id(resolved, digest, taken)
        stored = self._path / _stored_name(identifier, resolved.name)
        item = QuarantinedItem(
            item_id=identifier,
            original_path=str(resolved),
            stored_path=str(stored),
            kind=self._kind_for(resolved, kinds),
            sha256=digest,
            bytes=size,
            quarantined_at=_utc_now(),
            reason=reason,
            mode=mode,
        )
        return item, ""

    def _kind_for(self, resolved: Path, kinds: Mapping[str, str] | None) -> str:
        """Look up the scanner kind for one path, tolerating any key spelling."""

        if not kinds:
            return "unknown"
        candidates = [str(resolved), resolved.name]
        try:
            candidates.append(resolved.relative_to(self._root).as_posix())
        except ValueError:
            pass
        for candidate in candidates:
            value = kinds.get(candidate)
            if isinstance(value, str) and value:
                return value
        return "unknown"


def suggest_quarantine(root: Path) -> tuple[Path, ...]:
    """Return the currently eligible files that still exist under a project root.

    This is the CLI hook: display the tuple, let the operator decide, then pass
    the accepted subset to QuarantineStore.quarantine() with a reason. Only the
    scanner kinds whose evidence is the file itself are suggested; source call
    sites and dependency declarations are code to review, not files to remove.
    """

    try:
        from tauhaulity.tools import artifact_scan
    except ImportError:
        return ()
    root_path = Path(root)
    try:
        report = artifact_scan.scan_source_tree(root_path)
    except (OSError, RuntimeError, ValueError):
        return ()
    store_directory = (root_path / ".tauhaulity").resolve()
    suggested: list[Path] = []
    seen: set[str] = set()
    for finding in report.findings:
        if not getattr(finding, "quarantine_eligible", False):
            continue
        if not finding.rel_path:
            continue
        candidate = root_path / finding.rel_path
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)
        try:
            resolved = candidate.resolve()
        except OSError:
            continue
        if resolved == store_directory or _inside(store_directory, resolved):
            # Already quarantined material is inert; never suggest it again.
            continue
        try:
            if candidate.is_file():
                suggested.append(candidate)
        except OSError:
            continue
    return tuple(sorted(suggested))
