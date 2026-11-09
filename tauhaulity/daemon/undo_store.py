"""Bounded, byte exact undo journal for destructive operations.

The undo store is the rollback half of pillar eight: it copies what is about to
be deleted into a project local journal before the operation runs, so a mistaken
cleanup or a ransomware burst can be reverted without a version control commit.

Design constraints that shape the implementation:
  * the journal is a FIFO ring bounded by a byte budget, so it can never fill a
    developer disk even if the tool is left running for months;
  * capture is byte exact and preserves POSIX mode bits, because restoring a
    file with the wrong permissions is a second incident;
  * one directory tree becomes one entry, so a whole deleted folder restores in
    a single action;
  * index updates are atomic and serialized with an exclusive lock file, because
    two concurrent commands (a watch loop and a manual delete) must not corrupt
    the journal.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

UNDO_DIRNAME = ".tauhaulity"
UNDO_SUBDIR = "undo"
INDEX_FILENAME = "index.json"
ENTRIES_DIRNAME = "entries"
LOCK_FILENAME = ".lock"
DATA_DIRNAME = "data"

# Manifest and blob metadata cost disk space that is not part of the payload
# budget. Accounting one block per entry keeps the real journal size below the
# configured ring instead of a few kilobytes over it.
ENTRY_OVERHEAD_BYTES = 4096

_STALE_LOCK_SECONDS = 120.0


class UndoStoreError(RuntimeError):
    """Raised when the journal cannot be initialized or written."""


@dataclass(frozen=True, slots=True)
class UndoEntry:
    """One captured restore point.

    Attributes:
        entry_id: Sortable unique identifier.
        created_at: UTC ISO timestamp of the capture.
        paths: Absolute paths captured by this entry.
        bytes: Payload bytes stored for this entry.
        journal_path: Directory holding the manifest and blobs.
    """

    entry_id: str
    created_at: str
    paths: tuple[str, ...]
    bytes: int
    journal_path: Path


@dataclass(frozen=True, slots=True)
class RestoreResult:
    """Outcome of restoring one entry.

    Attributes:
        entry_id: Entry that was restored, empty when the journal was empty.
        restored: Number of filesystem items recreated.
        message: Human readable explanation including any failures.
    """

    entry_id: str
    restored: int
    message: str


@dataclass(frozen=True, slots=True)
class _Item:
    """One manifest record inside a journal entry."""

    path: str
    rel: str
    kind: str
    mode: int
    size: int = 0
    data: str | None = None
    target: str | None = None


def _utc_now() -> str:
    """Return an ISO 8601 UTC timestamp with second precision."""

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _rank(item: _Item) -> int:
    """Order restoration so parents exist before their children."""

    return {"dir": 0, "file": 1, "symlink": 2}.get(item.kind, 3)


class UndoStore:
    """FIFO journal of captured files and directory trees.

    Attributes:
        ring_mb: Byte budget in megabytes; older entries are evicted first.
    """

    def __init__(self, root: Path, ring_mb: int = 512) -> None:
        """Bind the store to a project root without touching the disk.

        Construction performs only validation, because pillar eight builds a
        store during a read-only probe; the journal directory is created by the
        first capture.

        Raises:
            UndoStoreError: When the root is missing, not writable, or the ring
                budget is not a positive integer.
        """

        root_path = Path(root)
        if isinstance(ring_mb, bool) or not isinstance(ring_mb, int):
            raise UndoStoreError("ring_mb must be an integer")
        if ring_mb <= 0:
            raise UndoStoreError("ring_mb must be positive")
        try:
            if not root_path.is_dir():
                raise UndoStoreError("project root is not a directory: " + str(root_path))
            if not os.access(root_path, os.W_OK):
                raise UndoStoreError("project root is not writable: " + str(root_path))
        except OSError as exc:
            raise UndoStoreError("cannot inspect project root " + str(root_path) + ": " + str(exc)) from exc
        self._root = root_path.resolve()
        self.ring_mb = int(ring_mb)
        self._state_dir = self._root / UNDO_DIRNAME
        self._base = self._state_dir / UNDO_SUBDIR
        self._index_path = self._base / INDEX_FILENAME
        self._entries_dir = self._base / ENTRIES_DIRNAME
        self._lock_path = self._base / LOCK_FILENAME

    @property
    def root(self) -> Path:
        """Project root this store belongs to."""

        return self._root

    @property
    def journal_dir(self) -> Path:
        """Directory holding the index and the entry blobs."""

        return self._base

    @property
    def budget_bytes(self) -> int:
        """Configured ring budget in bytes."""

        return self.ring_mb * 1024 * 1024

    def is_initialized(self) -> bool:
        """True when the journal directory already exists on disk."""

        try:
            return self._base.is_dir()
        except OSError:
            return False

    def _ensure_dirs(self) -> None:
        """Create the journal directory tree, surfacing permission problems."""

        try:
            self._entries_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            raise UndoStoreError("cannot create undo journal " + str(self._entries_dir) + ": " + str(exc)) from exc

    @contextmanager
    def _mutex(self, timeout_s: float = 10.0) -> Iterator[None]:
        """Serialize journal mutations with an exclusive lock file.

        fcntl and msvcrt locking differ enough that a create-exclusive file is
        the only portable primitive in the standard library. A lock older than
        the staleness window is broken so a crashed process cannot wedge the
        journal forever.
        """

        self._ensure_dirs()
        deadline = time.monotonic() + max(0.1, timeout_s)
        handle = None
        while True:
            try:
                handle = os.open(self._lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                break
            except FileExistsError:
                try:
                    age = time.time() - self._lock_path.stat().st_mtime
                except OSError:
                    age = 0.0
                if age > _STALE_LOCK_SECONDS:
                    try:
                        self._lock_path.unlink()
                    except OSError:
                        pass
                    continue
                if time.monotonic() >= deadline:
                    raise UndoStoreError("undo journal is locked by another process")
                time.sleep(0.01)
            except OSError as exc:
                raise UndoStoreError("cannot lock undo journal: " + str(exc)) from exc
        try:
            yield
        finally:
            try:
                os.close(handle)
            except OSError:
                pass
            try:
                self._lock_path.unlink()
            except OSError:
                pass

    def _read_index(self) -> list[dict]:
        """Read the index, treating a missing or corrupt file as empty."""

        try:
            raw = json.loads(self._index_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        if not isinstance(raw, list):
            return []
        records: list[dict] = []
        for record in raw:
            if isinstance(record, dict) and isinstance(record.get("entry_id"), str):
                records.append(record)
        return records

    def _write_index(self, records: list[dict]) -> None:
        """Atomically replace the index file.

        The temporary file plus os.replace pattern guarantees a reader never
        observes a half written index, which matters because a status command may
        run while a capture is in progress in another process.
        """

        self._ensure_dirs()
        tmp = self._index_path.with_suffix(".json.tmp")
        payload = json.dumps(records, indent=2, sort_keys=True) + "\n"
        try:
            tmp.write_text(payload, encoding="utf-8")
            os.replace(tmp, self._index_path)
        except OSError as exc:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise UndoStoreError("cannot write undo index: " + str(exc)) from exc

    def _display_path(self, path: Path) -> str:
        """Return a project relative path when possible, absolute otherwise."""

        try:
            return path.relative_to(self._root).as_posix()
        except ValueError:
            return path.as_posix()

    def _inside_journal(self, path: Path) -> bool:
        """True when a path belongs to the state directory that holds the journal.

        Capturing the journal would copy the entry being written, so the whole
        .tauhaulity state tree is refused, not only the inner undo directory.
        """

        try:
            path.resolve().relative_to(self._state_dir.resolve())
            return True
        except (ValueError, OSError):
            return False

    def _symlink_item(self, path: Path) -> _Item | None:
        """Record a symbolic link by its target instead of following it."""

        try:
            target = os.readlink(path)
            mode = stat.S_IMODE(path.lstat().st_mode)
        except OSError:
            return None
        return _Item(str(path), self._display_path(path), "symlink", mode, 0, None, target)

    def _file_item(self, path: Path, data_dir: Path, index: int) -> _Item | None:
        """Copy one regular file into the entry blob directory."""

        try:
            info = path.lstat()
        except OSError:
            return None
        if stat.S_ISLNK(info.st_mode):
            return self._symlink_item(path)
        if not stat.S_ISREG(info.st_mode):
            # Devices, FIFOs and sockets have no restorable content.
            return None
        blob_name = str(index).zfill(5) + ".bin"
        blob = data_dir / blob_name
        try:
            shutil.copyfile(path, blob)
            os.chmod(blob, 0o600)
        except OSError:
            try:
                blob.unlink()
            except OSError:
                pass
            return None
        return _Item(
            str(path),
            self._display_path(path),
            "file",
            stat.S_IMODE(info.st_mode),
            int(info.st_size),
            blob_name,
            None,
        )

    def _collect_items(self, target: Path, data_dir: Path) -> list[_Item]:
        """Capture a file, a symlink or a whole directory tree."""

        items: list[_Item] = []
        if target.is_symlink():
            item = self._symlink_item(target)
            return [item] if item is not None else []
        if target.is_dir():
            for current, dirnames, filenames in os.walk(target, followlinks=False):
                base = Path(current)
                try:
                    mode = stat.S_IMODE(base.lstat().st_mode)
                except OSError:
                    mode = 0o755
                items.append(_Item(str(base), self._display_path(base), "dir", mode))
                dirnames.sort()
                filenames.sort()
                for dirname in list(dirnames):
                    child = base / dirname
                    if child.is_symlink():
                        dirnames.remove(dirname)
                        item = self._symlink_item(child)
                        if item is not None:
                            items.append(item)
                for filename in filenames:
                    item = self._file_item(base / filename, data_dir, len(items))
                    if item is not None:
                        items.append(item)
            return items
        item = self._file_item(target, data_dir, 0)
        return [item] if item is not None else []

    def _capture_one(self, target: Path, label: str) -> UndoEntry | None:
        """Create one journal entry for a single path.

        Returns None when there is nothing to capture (the path does not exist),
        which is the normal case for "delete this directory" flows that run after
        the deletion happened.
        """

        # Symlinks must be captured as links, never followed. Path.resolve()
        # would dereference the last component and the manifest would record the
        # link target instead of the link, so the restore would materialise a
        # regular file where a symlink used to be. abspath normalizes the path
        # without touching the filesystem.
        resolved = Path(os.path.abspath(str(target)))
        if self._inside_journal(resolved):
            return None
        # lexists covers a broken symlink, which has no target to stat but is
        # still a restorable item.
        try:
            if not os.path.lexists(resolved):
                return None
        except OSError:
            return None

        entry_id = str(time.time_ns()).zfill(20) + "-" + uuid.uuid4().hex[:8]
        entry_dir = self._entries_dir / entry_id
        data_dir = entry_dir / DATA_DIRNAME
        try:
            data_dir.mkdir(parents=True)
        except OSError as exc:
            raise UndoStoreError("cannot create journal entry " + str(entry_dir) + ": " + str(exc)) from exc
        try:
            items = self._collect_items(resolved, data_dir)
            if not items:
                shutil.rmtree(entry_dir, ignore_errors=True)
                return None
            total = sum(item.size for item in items if item.kind == "file")
            if total > self.budget_bytes:
                shutil.rmtree(entry_dir, ignore_errors=True)
                raise UndoStoreError(
                    "cannot capture "
                    + str(resolved)
                    + ": "
                    + str(total)
                    + " bytes exceeds the "
                    + str(self.ring_mb)
                    + " MB undo ring"
                )
            manifest = {
                "entry_id": entry_id,
                "created_at": _utc_now(),
                "root": str(self._root),
                "label": label,
                "bytes": total,
                "items": [
                    {
                        "path": item.path,
                        "rel": item.rel,
                        "kind": item.kind,
                        "mode": item.mode,
                        "size": item.size,
                        "data": item.data,
                        "target": item.target,
                    }
                    for item in items
                ],
            }
            self._write_json(entry_dir / "manifest.json", manifest)
        except UndoStoreError:
            shutil.rmtree(entry_dir, ignore_errors=True)
            raise
        except OSError:
            shutil.rmtree(entry_dir, ignore_errors=True)
            raise
        return UndoEntry(entry_id, str(manifest["created_at"]), (str(resolved),), total, entry_dir)

    @staticmethod
    def _write_json(path: Path, payload: dict) -> None:
        """Write a JSON document atomically inside an entry directory."""

        tmp = path.with_suffix(".json.tmp")
        try:
            tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
            os.replace(tmp, path)
        except OSError as exc:
            try:
                tmp.unlink()
            except OSError:
                pass
            raise UndoStoreError("cannot write journal manifest " + str(path) + ": " + str(exc)) from exc

    def _evict(self, records: list[dict]) -> int:
        """Drop oldest records until the ring fits its budget.

        The budget counts payload bytes plus a per entry overhead, so a journal
        full of tiny entries cannot hide disk use behind manifests.
        """

        total = sum(int(record.get("bytes", 0) or 0) + ENTRY_OVERHEAD_BYTES for record in records)
        removed = 0
        while records and total > self.budget_bytes:
            record = records.pop(0)
            entry_id = str(record.get("entry_id", ""))
            if entry_id:
                shutil.rmtree(self._entries_dir / entry_id, ignore_errors=True)
            total -= int(record.get("bytes", 0) or 0) + ENTRY_OVERHEAD_BYTES
            removed += 1
        return removed

    def capture(self, paths: list[Path]) -> list[UndoEntry]:
        """Copy paths into the journal before they are destroyed.

        Parameters:
            paths: Files or directory trees to capture.

        Returns:
            The entries that survived FIFO eviction, newest last. An empty list
            means nothing existed to capture (or everything was immediately
            evicted by a tiny ring).

        Raises:
            UndoStoreError: When the journal cannot be written or a single path
                exceeds the whole ring budget.
        """

        targets = [Path(item) for item in paths]
        if not targets:
            return []
        created: list[UndoEntry] = []
        created_dirs: list[Path] = []
        with self._mutex():
            records = self._read_index()
            try:
                for target in targets:
                    entry = self._capture_one(target, self._display_path(target))
                    if entry is None:
                        continue
                    created.append(entry)
                    created_dirs.append(entry.journal_path)
                    records.append(
                        {
                            "entry_id": entry.entry_id,
                            "created_at": entry.created_at,
                            "paths": list(entry.paths),
                            "bytes": entry.bytes,
                            "journal_path": str(entry.journal_path),
                        }
                    )
                if self._evict(records):
                    self._write_index(records)
                    alive = {str(record.get("entry_id")) for record in records}
                else:
                    alive = {str(record.get("entry_id")) for record in records}
                    self._write_index(records)
            except UndoStoreError:
                for directory in created_dirs:
                    shutil.rmtree(directory, ignore_errors=True)
                raise
        return [entry for entry in created if entry.entry_id in alive]

    def preview(self, paths: list[Path]) -> list[str]:
        """List what capture would journal, without writing anything.

        A destructive command should be reversible and predictable: the operator
        sees which paths would be journaled, how many bytes they hold and whether
        the ring can take them before the deletion runs. The preview performs only
        stat, walk and readlink calls, so it never creates the journal directory,
        never copies a blob and never takes the journal lock.

        Parameters:
            paths: Files or directory trees that a delete would capture.

        Returns:
            One line per requested path in input order, plus a summary line when
            at least one path was requested. An empty input yields no lines.
        """

        targets = [Path(item) for item in paths]
        if not targets:
            return []
        lines: list[str] = []
        capturable = 0
        total_bytes = 0
        for target in targets:
            try:
                line, size, is_capturable = self._preview_one(target)
            except (OSError, ValueError) as exc:
                line, size, is_capturable = (
                    "skipped " + str(target) + ": " + type(exc).__name__ + ": " + str(exc),
                    0,
                    False,
                )
            lines.append(line)
            if is_capturable:
                capturable += 1
                total_bytes += size
        summary = (
            "journal preview: "
            + str(capturable)
            + " of "
            + str(len(targets))
            + " path(s) capturable, "
            + str(total_bytes)
            + " byte(s) against a "
            + str(self.ring_mb)
            + " MB ring"
        )
        if total_bytes > self.budget_bytes:
            summary += "; over budget, capture would raise instead of journaling"
        else:
            summary += "; within budget"
        lines.append(summary)
        return lines

    def _preview_one(self, target: Path) -> tuple[str, int, bool]:
        """Describe one preview path as (line, payload bytes, capturable)."""

        resolved = Path(os.path.abspath(str(target)))
        display = self._display_path(resolved)
        if self._inside_journal(resolved):
            return (
                "skipped " + display + ": inside the tauhaulity state directory",
                0,
                False,
            )
        try:
            exists = os.path.lexists(resolved)
        except (OSError, ValueError):
            exists = False
        if not exists:
            return ("missing " + display + ": nothing would be journaled", 0, False)
        if resolved.is_symlink():
            try:
                link_target = os.readlink(resolved)
            except OSError:
                return ("skipped " + display + ": symlink target is unreadable", 0, False)
            # A symlink is recorded by its target, never by the bytes behind it.
            return ("symlink " + display + " -> " + link_target + " (0 bytes)", 0, True)
        try:
            if resolved.is_dir():
                items, size = self._measure_tree(resolved)
                return (
                    "directory "
                    + display
                    + ": "
                    + str(items)
                    + " item(s), "
                    + str(size)
                    + " byte(s)",
                    size,
                    True,
                )
            if resolved.is_file():
                size = int(resolved.lstat().st_size)
                return ("file " + display + ": " + str(size) + " byte(s)", size, True)
        except (OSError, ValueError) as exc:
            return (
                "skipped " + display + ": " + type(exc).__name__ + ": " + str(exc),
                0,
                False,
            )
        return ("skipped " + display + ": not a regular file, directory or symlink", 0, False)

    @staticmethod
    def _measure_tree(target: Path) -> tuple[int, int]:
        """Count items and payload bytes below a directory without copying them."""

        items = 0
        size = 0
        for current, dirnames, filenames in os.walk(target, followlinks=False):
            base = Path(current)
            items += 1
            dirnames.sort()
            filenames.sort()
            for dirname in list(dirnames):
                if (base / dirname).is_symlink():
                    dirnames.remove(dirname)
                    items += 1
            for filename in filenames:
                child = base / filename
                items += 1
                if child.is_symlink():
                    continue
                try:
                    if child.is_file():
                        size += int(child.lstat().st_size)
                except OSError:
                    continue
        return items, size

    def restore(self, entry_id: str | None = None) -> RestoreResult:
        """Recreate everything recorded in one entry.

        A successful restore consumes the entry: the journal is a rollback ring,
        not an archive, and keeping restored blobs would evict useful future
        restore points.

        Parameters:
            entry_id: Entry to restore; None restores the most recent one.

        Returns:
            The outcome including how many items were recreated.
        """

        with self._mutex():
            records = self._read_index()
            if entry_id is None and not records:
                return RestoreResult("", 0, "undo journal is empty")
            if entry_id is None:
                record = records[-1]
            else:
                record = next(
                    (item for item in records if str(item.get("entry_id")) == str(entry_id)),
                    None,
                )
            if record is None:
                return RestoreResult(str(entry_id or ""), 0, "unknown undo entry: " + str(entry_id))
            identifier = str(record.get("entry_id", ""))
            entry_dir = self._entries_dir / identifier
            manifest = self._read_manifest(entry_dir)
            if manifest is None:
                return RestoreResult(identifier, 0, "journal entry is unreadable: " + identifier)

            items: list[_Item] = []
            for raw in manifest.get("items", []):
                if not isinstance(raw, dict) or not raw.get("path"):
                    continue
                items.append(
                    _Item(
                        path=str(raw.get("path")),
                        rel=str(raw.get("rel") or raw.get("path")),
                        kind=str(raw.get("kind") or "file"),
                        mode=int(raw.get("mode", 0o644) or 0o644),
                        size=int(raw.get("size", 0) or 0),
                        data=raw.get("data"),
                        target=raw.get("target"),
                    )
                )
            restored = 0
            failures: list[str] = []
            for item in sorted(items, key=_rank):
                if self._restore_item(item, entry_dir):
                    restored += 1
                else:
                    failures.append(item.rel)
            if restored:
                shutil.rmtree(entry_dir, ignore_errors=True)
                records = [record for record in records if str(record.get("entry_id")) != identifier]
                self._write_index(records)
            message = (
                "restored "
                + str(restored)
                + " of "
                + str(len(items))
                + " item(s) from "
                + identifier
            )
            if failures:
                message += "; failed: " + ", ".join(failures[:8])
                if len(failures) > 8:
                    message += " (+" + str(len(failures) - 8) + " more)"
            return RestoreResult(identifier, restored, message)

    def _read_manifest(self, entry_dir: Path) -> dict | None:
        """Read one entry manifest, returning None when it is unusable."""

        try:
            raw = json.loads((entry_dir / "manifest.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        return raw if isinstance(raw, dict) else None

    def _restore_item(self, item: _Item, entry_dir: Path) -> bool:
        """Recreate one manifest item, preserving its recorded mode bits."""

        path = Path(item.path)
        try:
            if item.kind == "dir":
                path.mkdir(parents=True, exist_ok=True)
                os.chmod(path, item.mode)
                return True
            if item.kind == "symlink":
                parent = path.parent
                parent.mkdir(parents=True, exist_ok=True)
                if path.is_symlink() or path.is_file():
                    path.unlink()
                elif path.is_dir():
                    return False
                if item.target is None:
                    return False
                os.symlink(item.target, path)
                return True
            if item.data is None:
                return False
            blob = entry_dir / DATA_DIRNAME / item.data
            if not blob.is_file():
                return False
            path.parent.mkdir(parents=True, exist_ok=True)
            if path.is_dir():
                return False
            shutil.copyfile(blob, path)
            os.chmod(path, item.mode)
            return True
        except OSError:
            return False

    def list_entries(self, limit: int = 20) -> list[UndoEntry]:
        """Return journal entries, newest first.

        Parameters:
            limit: Maximum number of entries to return; non positive yields none.
        """

        if limit <= 0:
            return []
        records = self._read_index()
        selected = records[-int(limit) :]
        entries: list[UndoEntry] = []
        for record in reversed(selected):
            identifier = str(record.get("entry_id", ""))
            raw_paths = record.get("paths")
            paths: tuple[str, ...] = ()
            if isinstance(raw_paths, list):
                paths = tuple(str(item) for item in raw_paths)
            entries.append(
                UndoEntry(
                    entry_id=identifier,
                    created_at=str(record.get("created_at", "")),
                    paths=paths,
                    bytes=int(record.get("bytes", 0) or 0),
                    journal_path=self._entries_dir / identifier,
                )
            )
        return entries

    def prune(self) -> int:
        """Evict over budget entries and delete orphaned entry directories.

        Returns:
            Number of journal entries removed.
        """

        removed = 0
        with self._mutex():
            records = self._read_index()
            alive: list[dict] = []
            for record in records:
                identifier = str(record.get("entry_id", ""))
                if identifier and (self._entries_dir / identifier).is_dir():
                    alive.append(record)
                else:
                    removed += 1
            removed += self._evict(alive)
            self._write_index(alive)
            referenced = {str(record.get("entry_id")) for record in alive}
            try:
                children = list(self._entries_dir.iterdir())
            except OSError:
                children = []
            for child in children:
                if child.is_dir() and child.name not in referenced:
                    shutil.rmtree(child, ignore_errors=True)
                    removed += 1
        return removed

    def usage_bytes(self) -> int:
        """Return the real on disk size of the journal.

        The walk is intentional: the index can be stale after a crash and the
        reported number must never understate how much disk the ring holds.
        """

        total = 0
        try:
            if not self._entries_dir.is_dir():
                return 0
        except OSError:
            return 0
        for current, _dirnames, filenames in os.walk(self._entries_dir):
            for filename in filenames:
                try:
                    total += os.lstat(os.path.join(current, filename)).st_size
                except OSError:
                    continue
        return total
