"""Canary trap watcher for early ransomware and mass-delete detection.

A canary is a small decoy file whose only purpose is to be observed. Ransomware
and runaway scripts traverse a project and modify everything they can reach, so
the first canary hit is a high fidelity signal that arrives before the damage is
complete: legitimate editors do not rewrite a file named canary.txt.

The watcher keeps its baseline in memory instead of on disk. A persisted
baseline is itself a file the attacker will encrypt, and re-baselining after a
restart is exactly what an operator wants anyway.

One snapshot is bounded by construction: discovery visits at most three directory
levels, keeps at most MAX_CANARY_CANDIDATES files and reads at most
MAX_CANARY_READ_BYTES from each of them, so a poll never scales with the size of
the project and a watch loop can keep a one second cadence on a large checkout.

The second half of this module is a canary farm. A handful of decoys at the
project root is only hit if the attacker starts walking from the root; decoys
spread through the real source directories are reached within the first few dozen
files of any traversal, which is the time the user needs. Every farm decoy is
marked as a decoy, fingerprinted (size, sha256, mtime, inode) and recorded in an
atomically written, versioned manifest with a digest over the record set. Change
detection distinguishes three outcomes: canary_modified (content or size
changed), canary_deleted (the path is gone) and canary_replaced (the inode
changed or the path is now a different kind of object). Removal only ever deletes
a file whose fingerprint and marker still match the manifest, so a hand edited
manifest cannot turn cleanup into arbitrary file deletion.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import stat
import threading
import time
import zipfile
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, Sequence

from tauhaulity.core.entropy import shannon_entropy

_MAX_CANDIDATES = 24

# Suffixes that are code rather than decoy data. The tool's own modules carry
# decoy-like names in places, and a canary count inflated by source files would
# misreport the tamper coverage of a project.
_CODE_SUFFIXES: tuple[str, ...] = (".py", ".pyc", ".pyo", ".pyi", ".so", ".dll", ".pyd", ".rs")
_MAX_DISCOVERY_DEPTH = 3
_MAX_READ_BYTES = 64 * 1024
_MAX_EVENT_QUEUE = 512

#: Public statement of the snapshot bound, because a watcher that walks a project
#: tree must be able to answer "how expensive is one poll" with a constant.
#: Discovery is capped at MAX_CANARY_CANDIDATES files, each fingerprint reads at
#: most MAX_CANARY_READ_BYTES, so one snapshot reads at most
#: MAX_CANARY_SNAPSHOT_BYTES (about 1.5 MiB) no matter how large the project is.
MAX_CANARY_CANDIDATES = _MAX_CANDIDATES
MAX_CANARY_READ_BYTES = _MAX_READ_BYTES
MAX_CANARY_SNAPSHOT_BYTES = _MAX_CANDIDATES * _MAX_READ_BYTES

# A canary that was readable prose and is now near random is the signature of an
# encryption pass, which is worth distinguishing from an ordinary edit.
ENCRYPTION_ENTROPY = 7.0
LOW_ENTROPY_BASELINE = 6.0

_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        "site-packages",
        "dist",
        "build",
        "target",
        ".tauhaulity",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tooling",
        ".toolchains",
        "toolchains",
        ".pyenv",
        ".asdf",
    }
)


@dataclass(frozen=True, slots=True)
class CanaryEvent:
    """One observed change to a canary trap.

    Attributes:
        path: Project relative path, forward slash separated.
        kind: created, modified, deleted or encrypted.
        entropy: Shannon entropy of the canary content after the change.
        detail: Human readable explanation shown in the dossier.
    """

    path: str
    kind: str
    entropy: float
    detail: str
    """kind is one of created, modified, deleted, encrypted for legacy decoys,
    or canary_modified, canary_deleted, canary_replaced for farm decoys."""


@dataclass(frozen=True, slots=True)
class _State:
    """Fingerprint of one canary file at one instant."""

    exists: bool
    size: int
    mtime_ns: int
    digest: str
    entropy: float


_ABSENT = _State(False, 0, 0, "", 0.0)


def _fingerprint(path: Path) -> _State:
    """Read a canary and summarize it without ever raising.

    The digest covers the content so an edit that preserves the size and the
    timestamp is still caught; entropy is measured on the first block because a
    whole file estimate is not needed to tell prose from ciphertext.
    """

    try:
        info = path.stat()
    except OSError:
        return _ABSENT
    try:
        if not path.is_file():
            return _ABSENT
        with path.open("rb") as handle:
            payload = handle.read(_MAX_READ_BYTES)
    except OSError:
        # The file exists but cannot be read: report presence with no digest so
        # the comparison still flags a disappearance instead of crashing.
        return _State(True, int(getattr(info, "st_size", 0) or 0), int(info.st_mtime_ns), "", 0.0)
    return _State(
        True,
        len(payload),
        int(info.st_mtime_ns),
        hashlib.sha256(payload).hexdigest(),
        shannon_entropy(payload[:4096]),
    )


class CanaryWatcher:
    """Snapshot and poll a set of decoy files for tampering.

    Attributes:
        interval_ms: Poll interval in milliseconds used by watch_once and the
            background thread.
    """

    def __init__(
        self,
        root: Path,
        paths: Sequence[Path] | None = None,
        interval_ms: int = 250,
    ) -> None:
        """Create a watcher bound to a project root.

        Parameters:
            root: Project root used for discovery and relative path display.
            paths: Explicit canary paths; None enables shallow discovery.
            interval_ms: Poll interval; must be positive.

        Raises:
            ValueError: When interval_ms is not positive.
        """

        if isinstance(interval_ms, bool) or int(interval_ms) <= 0:
            raise ValueError("interval_ms must be a positive integer")
        self._root = Path(root)
        self._explicit: tuple[Path, ...] = tuple(Path(item) for item in paths) if paths else ()
        self.interval_ms = int(interval_ms)
        self._lock = threading.RLock()
        self._baseline: dict[str, _State] | None = None
        self._farm_baseline = {}
        self._farm_seen: set[tuple[str, str]] = set()
        self._events: deque[CanaryEvent] = deque(maxlen=_MAX_EVENT_QUEUE)
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @property
    def root(self) -> Path:
        """Project root this watcher observes."""

        return self._root

    @property
    def watched_count(self) -> int:
        """Number of canaries in the current baseline, or zero before snapshot."""

        with self._lock:
            return len(self._baseline or {}) + len(self._farm_baseline)

    @property
    def farm_count(self) -> int:
        """Number of farm decoys in the current baseline, or zero before snapshot."""

        with self._lock:
            return len(self._farm_baseline)

    @property
    def running(self) -> bool:
        """True while the background polling thread is alive."""

        thread = self._thread
        return bool(thread is not None and thread.is_alive())

    def _key(self, path: Path) -> str:
        """Return the stable key used for baseline lookups."""

        try:
            return path.relative_to(self._root).as_posix()
        except ValueError:
            return path.as_posix()

    def _resolve(self, key: str) -> Path:
        """Rebuild a path from a baseline key."""

        candidate = Path(key)
        if candidate.is_absolute():
            return candidate
        return self._root / key

    def candidates(self) -> list[Path]:
        """Return the canary files this watcher observes.

        Explicit paths always win. Otherwise a shallow walk picks up the common
        decoy names (canary.txt, *.canary, any file with canary in its name) and
        stops at a depth that keeps a probe fast on a real checkout.
        """

        if self._explicit:
            return list(self._explicit)
        found: list[Path] = []
        if not self._root.is_dir():
            return found
        for current, dirnames, filenames in os.walk(self._root):
            base = Path(current)
            try:
                depth = len(base.relative_to(self._root).parts)
            except ValueError:
                depth = 0
            dirnames[:] = sorted(
                name for name in dirnames if name.lower() not in _SKIP_DIRS
            )
            if depth >= _MAX_DISCOVERY_DEPTH:
                dirnames[:] = []
            for filename in sorted(filenames):
                if len(found) >= _MAX_CANDIDATES:
                    break
                lowered = filename.lower()
                # Only names that are themselves decoy shaped count. A bare
                # substring match would treat "test_daemon_canary.py" as a trap
                # and report tamper coverage that does not exist.
                if not (
                    lowered.startswith("canary")
                    or lowered.endswith(".canary")
                    or lowered.startswith("decoy")
                ):
                    continue
                # A canary is a decoy data file. Source modules that merely carry
                # the name, such as this package's own canary.py, are code and
                # reporting them as traps would invent coverage that does not
                # exist.
                if lowered.endswith(_CODE_SUFFIXES):
                    continue
                found.append(base / filename)
            if len(found) >= _MAX_CANDIDATES:
                break
        # Farm decoys carry ordinary looking names, so discovery cannot find them;
        # the manifest is the only honest source. Including them here is what makes
        # the event based watch loop classify a decoy change as a canary event.
        try:
            for record in load_canary_farm(self._root):
                path = self._root / record.rel_path
                if path not in found:
                    found.append(path)
        except (OSError, RuntimeError, ValueError):
            pass
        return found

    def snapshot(self) -> None:
        """Record the current state of every candidate as the baseline.

        Calling it again re-arms the traps and discards prior state, which is the
        documented way to accept an intentional change.
        """

        farm: dict[str, "_FarmState"] = {}
        try:
            records = load_canary_farm(self._root)
        except (OSError, RuntimeError, ValueError):
            records = ()
        for record in records:
            farm[record.rel_path] = _FarmState(
                True,
                True,
                record.size,
                record.mtime_ns,
                record.inode,
                record.sha256,
            )
        # Farm decoys are compared by the farm detector, which knows about inodes
        # and replacement; feeding them to the legacy content differ as well would
        # report every farm change twice with two different kind vocabularies.
        states = {
            self._key(path): _fingerprint(path)
            for path in self.candidates()
            if self._key(path) not in farm
        }
        with self._lock:
            self._baseline = states
            self._farm_baseline = farm
            self._farm_seen = set()

    def scan(self) -> list[CanaryEvent]:
        """Compare the current state against the baseline.

        Returns:
            One event per observed change. An empty list is returned before the
            first snapshot, because there is no baseline to compare against.
        """

        with self._lock:
            baseline = None if self._baseline is None else dict(self._baseline)
            farm_keys = set(self._farm_baseline)
        if baseline is None:
            return []
        current: dict[str, _State] = {}
        for key in baseline:
            if key in farm_keys:
                continue
            current[key] = _fingerprint(self._resolve(key))
        for path in self.candidates():
            key = self._key(path)
            if key in farm_keys:
                continue
            if key not in current:
                current[key] = _fingerprint(path)

        events: list[CanaryEvent] = []
        for key in sorted(current):
            after = current[key]
            before = baseline.get(key, _ABSENT)
            if not before.exists:
                if after.exists:
                    events.append(
                        CanaryEvent(key, "created", after.entropy, "canary trap created after snapshot")
                    )
                continue
            if not after.exists:
                events.append(CanaryEvent(key, "deleted", 0.0, "canary trap deleted"))
                continue
            if after.digest != before.digest:
                if after.entropy >= ENCRYPTION_ENTROPY and before.entropy < LOW_ENTROPY_BASELINE:
                    events.append(
                        CanaryEvent(
                            key,
                            "encrypted",
                            after.entropy,
                            "content entropy rose from "
                            + format(before.entropy, ".2f")
                            + " to "
                            + format(after.entropy, ".2f")
                            + " bits per byte",
                        )
                    )
                else:
                    events.append(
                        CanaryEvent(key, "modified", after.entropy, "canary content changed")
                    )
                continue
            if after.mtime_ns != before.mtime_ns:
                events.append(
                    CanaryEvent(key, "modified", after.entropy, "canary metadata changed")
                )
        events.extend(self._scan_farm())
        return events

    def _scan_farm(self) -> list[CanaryEvent]:
        """Compare the farm decoys against the fingerprints they were armed with.

        Three outcomes are distinct because they mean different things: content
        changed, the path disappeared, or the path is now a different filesystem
        object (an editor style atomic replace changes the inode). Reporting all
        three as "modified" would hide a deletion behind an edit and lose the
        rename signature of a bulk writer.
        """

        with self._lock:
            baseline = dict(self._farm_baseline)
            seen = set(self._farm_seen)
        if not baseline:
            return []
        events: list[CanaryEvent] = []
        for rel_path in sorted(baseline):
            record = baseline[rel_path]
            state = _farm_state(self._resolve(rel_path))
            kind = ""
            detail = ""
            if not state.exists:
                kind = "canary_deleted"
                detail = "canary farm decoy deleted"
            elif not state.is_regular:
                kind = "canary_replaced"
                detail = "canary farm decoy replaced by a different filesystem object"
            elif record.inode and state.inode and state.inode != record.inode:
                kind = "canary_replaced"
                detail = "canary farm decoy inode changed (atomic replace)"
            elif state.size != record.size or state.sha256 != record.sha256:
                kind = "canary_modified"
                detail = "canary farm decoy content changed"
            if not kind:
                continue
            key = (rel_path, kind)
            if key in seen:
                continue
            seen.add(key)
            events.append(CanaryEvent(rel_path, kind, 0.0, detail))
        with self._lock:
            self._farm_seen = seen
        return events

    def _append(self, events: Iterable[CanaryEvent]) -> None:
        """Add observed events to the bounded queue drained by the caller."""

        with self._lock:
            for event in events:
                self._events.append(event)

    def farm_tick(self) -> list[CanaryEvent]:
        """Run one farm-only integrity check.

        A watch loop that already receives kernel events only needs the farm
        fingerprints; running the full legacy discovery walk on every tick would
        spend most of its budget re-listing directories that did not change.
        """

        return self._scan_farm()

    def drain(self) -> list[CanaryEvent]:
        """Remove and return every queued event, oldest first."""

        with self._lock:
            drained = list(self._events)
            self._events.clear()
        return drained

    def watch_once(self) -> list[CanaryEvent]:
        """Arm the traps if needed, wait one interval and compare.

        The interval wait is part of the contract: a scan started in the same
        instant as the snapshot can only ever report an empty result, which would
        make the daemon look healthy while doing nothing.
        """

        with self._lock:
            needs_arm = self._baseline is None
        if needs_arm:
            self.snapshot()
        self._stop_event.wait(self.interval_ms / 1000.0)
        return self.scan()

    def _loop(self) -> None:
        """Background poll loop; never raises into the host thread."""

        interval = self.interval_ms / 1000.0
        while not self._stop_event.is_set():
            try:
                events = self.scan()
            except (OSError, RuntimeError):
                events = []
            if events:
                self._append(events)
            self._stop_event.wait(interval)

    def start(self) -> None:
        """Start the background polling thread; a second call is a no-op."""

        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            if self._baseline is None:
                self._baseline = {
                    self._key(path): _fingerprint(path) for path in self.candidates()
                }
            self._stop_event.clear()
            thread = threading.Thread(target=self._loop, name="tauhaulity-canary", daemon=True)
            self._thread = thread
        thread.start()

    def stop(self) -> None:
        """Stop the background thread and wait for it to finish.

        The join happens outside the state lock: the loop takes that same lock on
        every poll, so joining while holding it would deadlock the watcher.
        """

        with self._lock:
            thread = self._thread
        self._stop_event.set()
        if thread is not None:
            thread.join(timeout=max(2.0, self.interval_ms / 1000.0 * 4))
        with self._lock:
            self._thread = None


# --------------------------------------------------------------- canary farm

#: Marker string embedded in every farm decoy. It is a property of the content,
#: so ownership survives a moved checkout and does not depend on the manifest.
CANARY_FARM_MARKER = "TAUHAULITY-CANARY-DECOY"

#: Directory and file name of the farm manifest. The state directory is already
#: excluded from every walk, so the manifest never becomes its own canary.
FARM_STATE_DIRNAME = ".tauhaulity"
FARM_MANIFEST_FILENAME = "canary_farm.json"
FARM_MANIFEST_VERSION = 1
FARM_GENERATOR = "tauhaulity.daemon.canary"

#: Decoy families and the file names a finance or management team would actually
#: keep. Names are chosen deterministically from the directory path, so a second
#: deploy produces the same farm instead of scattering duplicates.
FARM_KINDS: tuple[str, ...] = ("sheet", "document", "pdf", "notes")

_FARM_NAMES: dict[str, tuple[str, ...]] = {
    "sheet": (
        "payroll_2026.xlsx",
        "invoices_Q4.xlsx",
        "budget_2026.xlsx",
        "vendor_payments.xlsx",
        "headcount_2026.xlsx",
    ),
    "document": (
        "board_notes_2026.docx",
        "salary_review_2026.docx",
        "merger_memo.docx",
        "employee_reviews_2026.docx",
    ),
    "pdf": (
        "contracts_2026.pdf",
        "insurance_policy_2026.pdf",
        "audit_report_2026.pdf",
    ),
    "notes": (
        "team_notes_2026.txt",
        "credentials_backup.txt",
        "onboarding_notes_2026.txt",
    ),
}

#: Directories a farm never enters, on top of the shared skip list. Build output
#: and package caches are rewritten by every install, so a decoy there would be
#: deleted by a legitimate npm ci and turn into a false alarm.
_FARM_SKIP_DIRS: frozenset[str] = _SKIP_DIRS | frozenset(
    {
        "coverage",
        "htmlcov",
        ".next",
        ".nuxt",
        ".svelte-kit",
        ".parcel-cache",
        ".turbo",
        ".cache",
        "out",
        "release",
        "Debug",
        "Release",
        "x64",
        "x86",
        "obj",
        ".eggs",
        "eggs",
    }
)

#: Deepest directory the farm will place a decoy in. Deeper trees are still
#: watched, but a decoy at the bottom of a generated fixture tree protects
#: nothing and only bloats the manifest.
_FARM_MAX_DEPTH = 8

#: Cap on bytes read when fingerprinting or deleting a decoy. Decoys are small by
#: construction, so a larger file at the same path is not ours.
_FARM_READ_BYTES = 256 * 1024

#: Zip entry timestamp for generated OOXML decoys. A fixed timestamp keeps the
#: bytes deterministic, so a redeploy cannot rewrite the file just because time
#: passed.
_FARM_ZIP_TIME = (2026, 1, 1, 0, 0, 0)

#: Farm events are reported once per change kind and path so a persistent tamper
#: does not flood the loop every tick.
_FARM_EVENT_KINDS = ("canary_modified", "canary_deleted", "canary_replaced")


class CanaryFarmError(RuntimeError):
    """Raised when a farm cannot be deployed or removed safely."""


@dataclass(frozen=True, slots=True)
class CanaryFarmRecord:
    """One deployed decoy and the fingerprint it had when deployed.

    Attributes:
        rel_path: Project relative path with forward slashes.
        kind: Decoy family: sheet, document, pdf or notes.
        size: Content size in bytes at deployment time.
        sha256: Hex sha256 of the content at deployment time.
        mtime_ns: Modification time in nanoseconds at deployment time.
        inode: Filesystem inode (or Windows file index); zero when unavailable.
        marker: Unique marker embedded in the file content.
        created_at: UTC ISO timestamp of the original deployment.
    """

    rel_path: str
    kind: str
    size: int
    sha256: str
    mtime_ns: int
    inode: int
    marker: str
    created_at: str


@dataclass(frozen=True, slots=True)
class CanaryFarmReport:
    """Result of one deployment.

    Attributes:
        root: Absolute project root.
        deployed: Decoys armed now, ordered by relative path.
        skipped_directories: Directories where every candidate name was already
            occupied by a foreign file, so nothing was planted.
        manifest_path: Absolute path of the farm manifest.
        digest: sha256 over the canonical record set.
        created_at: UTC ISO timestamp recorded by this deployment.
    """

    root: Path
    deployed: tuple[CanaryFarmRecord, ...]
    skipped_directories: tuple[str, ...]
    manifest_path: Path
    digest: str
    created_at: str

    @property
    def count(self) -> int:
        """Number of decoys armed by this deployment."""

        return len(self.deployed)


@dataclass(frozen=True, slots=True)
class _FarmState:
    """Fingerprint of a farm decoy at one instant."""

    exists: bool
    is_regular: bool
    size: int
    mtime_ns: int
    inode: int
    sha256: str


_FARM_ABSENT = _FarmState(False, False, 0, 0, 0, "")

def _utc_now() -> str:
    """Return an ISO 8601 UTC timestamp with second precision."""

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _abspath(value: Path) -> Path:
    """Return an absolute path without resolving symlinks."""

    return Path(os.path.abspath(str(value)))


def _relative_posix(root: Path, path: Path) -> str:
    """Return a project relative forward slash path without raising."""

    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def farm_manifest_path(root: Path) -> Path:
    """Return the conventional farm manifest path for a project root."""

    return _abspath(Path(root)) / FARM_STATE_DIRNAME / FARM_MANIFEST_FILENAME


def _farm_marker(rel_path: str) -> str:
    """Return the deterministic marker for one decoy path.

    Determinism is the point: a redeploy of the same tree must produce the same
    bytes, otherwise every run would look like tampering to the watcher and to a
    duplicate scan.
    """

    digest = hashlib.sha256(rel_path.encode("utf-8", errors="replace")).hexdigest()
    return CANARY_FARM_MARKER + "-" + digest[:16]


def _farm_digest(records: Sequence["CanaryFarmRecord"]) -> str:
    """Return the sha256 digest over a canonical record set."""

    payload = json.dumps(
        [
            {
                "rel_path": record.rel_path,
                "kind": record.kind,
                "size": record.size,
                "sha256": record.sha256,
                "mtime_ns": record.mtime_ns,
                "inode": record.inode,
                "marker": record.marker,
                "created_at": record.created_at,
            }
            for record in sorted(records, key=lambda item: item.rel_path)
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _zip_member(name: str) -> zipfile.ZipInfo:
    """Return a deterministic zip entry for generated OOXML content."""

    info = zipfile.ZipInfo(name, date_time=_FARM_ZIP_TIME)
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = 0o644 << 16
    return info


def _ooxml_content(marker: str, sheet: bool) -> bytes:
    """Build a small but structurally plausible OOXML decoy.

    A decoy has to look like the spreadsheet or document an attacker hopes for,
    so office tools see a normal zip container; the marker lives in the archive
    comment and in the document properties so the file is always identifiable as
    a decoy.
    """

    buffer = io.BytesIO()
    core = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties"'
        ' xmlns:dc="http://purl.org/dc/elements/1.1/">'
        "<dc:title>Tauhaulity canary decoy</dc:title>"
        "<dc:description>" + marker + " not real data</dc:description>"
        "</cp:coreProperties>"
    )
    content_types = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        "</Types>"
    )
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.comment = marker.encode("ascii")
        archive.writestr(_zip_member("[Content_Types].xml"), content_types.encode("utf-8"))
        archive.writestr(_zip_member("docProps/core.xml"), core.encode("utf-8"))
        if sheet:
            workbook = (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                '<sheets><sheet name="payroll" sheetId="1"/></sheets></workbook>'
            )
            sheet_xml = (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
                '<sheetData><row r="1"><c r="A1" t="inlineStr"><is><t>'
                + marker
                + " not real data</t></is></c></row></sheetData></worksheet>"
            )
            archive.writestr(_zip_member("xl/workbook.xml"), workbook.encode("utf-8"))
            archive.writestr(_zip_member("xl/worksheets/sheet1.xml"), sheet_xml.encode("utf-8"))
        else:
            document = (
                '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                "<w:body><w:p><w:r><w:t>"
                + marker
                + " decoy document, not real data</w:t></w:r></w:p></w:body></w:document>"
            )
            archive.writestr(_zip_member("word/document.xml"), document.encode("utf-8"))
    return buffer.getvalue()


def _pdf_content(marker: str) -> bytes:
    """Build a minimal PDF decoy that carries the marker in its comment stream."""

    body = (
        "%PDF-1.4" + chr(10)
        + "% " + marker + " not real data" + chr(10)
        + "1 0 obj" + chr(10)
        + "<< /Type /Catalog /Pages 2 0 R >>" + chr(10)
        + "endobj" + chr(10)
        + "2 0 obj" + chr(10)
        + "<< /Type /Pages /Kids [3 0 R] /Count 1 >>" + chr(10)
        + "endobj" + chr(10)
        + "3 0 obj" + chr(10)
        + "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>" + chr(10)
        + "endobj" + chr(10)
        + "4 0 obj" + chr(10)
        + "<< /Length 58 >>" + chr(10)
        + "stream" + chr(10)
        + "BT /F1 12 Tf 72 720 Td (" + marker + ") Tj ET" + chr(10)
        + "endstream" + chr(10)
        + "endobj" + chr(10)
        + "trailer" + chr(10)
        + "<< /Root 1 0 R /Info << /Title (" + marker + " decoy) /Producer (tauhaulity) >> >>" + chr(10)
        + "%%EOF" + chr(10)
    )
    return body.encode("ascii", errors="replace")


def _farm_content(kind: str, marker: str) -> bytes:
    """Render one decoy file for a family, deterministic for a given marker."""

    if kind == "sheet":
        return _ooxml_content(marker, sheet=True)
    if kind == "document":
        return _ooxml_content(marker, sheet=False)
    if kind == "pdf":
        return _pdf_content(marker)
    if kind == "notes":
        text = (
            "# Tauhaulity canary decoy; " + marker + "; not real data." + chr(10)
            + "Meeting notes, quarterly planning and staffing figures." + chr(10)
            + "This file exists so that mass tampering is detected early." + chr(10)
        )
        return text.encode("utf-8")
    raise CanaryFarmError("unknown canary farm kind: " + str(kind))


def _farm_state(path: Path) -> _FarmState:
    """Fingerprint one path for farm change detection, never raising."""

    try:
        info = os.lstat(path)
    except OSError:
        return _FARM_ABSENT
    if not stat.S_ISREG(info.st_mode):
        return _FarmState(True, False, 0, int(info.st_mtime_ns), int(info.st_ino), "")
    try:
        with path.open("rb") as handle:
            payload = handle.read(_FARM_READ_BYTES)
    except OSError:
        return _FarmState(True, True, int(info.st_size), int(info.st_mtime_ns), int(info.st_ino), "")
    return _FarmState(
        True,
        True,
        len(payload),
        int(info.st_mtime_ns),
        int(info.st_ino),
        hashlib.sha256(payload).hexdigest(),
    )


def _farm_owned(path: Path, marker: str) -> bool:
    """Return True when a file still carries our decoy marker."""

    try:
        with path.open("rb") as handle:
            payload = handle.read(_FARM_READ_BYTES)
    except OSError:
        return False
    return marker.encode("ascii") in payload


def _safe_farm_rel(value: object) -> str | None:
    """Return a normalized project relative path, or None when it escapes root."""

    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace(chr(92), "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        return None
    parts = [part for part in normalized.split("/") if part and part != "."]
    if not parts or any(part == ".." for part in parts):
        return None
    return "/".join(parts)


def _policy_ignored(root: Path) -> "Callable[[str], bool]":
    """Return a predicate for project ignored paths, degrading to never-ignored.

    The policy module is imported lazily, so the daemon package stays importable
    while the core package is being restructured, and a broken policy file can
    only make the farm plant a decoy in a slightly busier directory, never fail
    the deployment.
    """

    try:
        from tauhaulity.core.policy import Policy, policy_path
    except ImportError:
        return lambda rel: False
    try:
        policy = Policy.load(policy_path(root))
    except (OSError, ValueError, RuntimeError):
        return lambda rel: False

    def ignored(rel_path: str) -> bool:
        try:
            return bool(policy.is_ignored(rel_path))
        except (OSError, ValueError, RuntimeError):
            return False

    return ignored


def _farm_directories(root: Path, is_ignored: "Callable[[str], bool]") -> list[Path]:
    """Return the real source directories the farm may place a decoy in.

    A directory is eligible when it exists, is not a skipped or ignored path, and
    already contains at least one regular file that is not a decoy. That keeps the
    farm in directories a traversal will reach early and out of empty scaffolding.
    """

    directories: list[Path] = []
    for current, dirnames, filenames in os.walk(root):
        base = Path(current)
        rel_dir = _relative_posix(root, base)
        rel_dir = "" if rel_dir == "." else rel_dir
        depth = 0 if not rel_dir else len(rel_dir.split("/"))
        kept: list[str] = []
        for name in sorted(dirnames):
            child_rel = (rel_dir + "/" + name) if rel_dir else name
            if name.lower() in _FARM_SKIP_DIRS:
                continue
            if is_ignored(child_rel):
                continue
            kept.append(name)
        dirnames[:] = kept if depth < _FARM_MAX_DEPTH else []
        has_file = False
        for name in sorted(filenames):
            try:
                if (base / name).is_file():
                    has_file = True
                    break
            except OSError:
                continue
        if has_file:
            directories.append(base)
    return directories


def _candidate_sequence(rel_dir: str, kinds: Sequence[str]) -> Iterator[tuple[str, str]]:
    """Yield deterministic (kind, name) candidates for one directory.

    The seed is the hash of the relative directory path, so the same tree always
    receives the same farm and a second deploy cannot scatter duplicates. The
    sequence keeps yielding more candidates so an occupied path can be skipped
    without giving up on the directory.
    """

    seed = int(hashlib.sha256(rel_dir.encode("utf-8")).hexdigest(), 16)
    total = sum(len(_FARM_NAMES[kind]) for kind in kinds)
    emitted = 0
    offset = 0
    while emitted < total * 2:
        index = seed + offset
        kind = kinds[index % len(kinds)]
        pool = _FARM_NAMES[kind]
        name = pool[(index // len(kinds)) % len(pool)]
        emitted += 1
        offset += 1
        yield kind, name


def _write_farm_file(path: Path, payload: bytes) -> None:
    """Write a decoy atomically so a crashed deploy never leaves a half file."""

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CanaryFarmError("cannot create " + str(path.parent) + ": " + str(exc)) from exc
    tmp = path.with_name(path.name + ".canary-tmp")
    try:
        with tmp.open("wb") as handle:
            handle.write(payload)
        try:
            os.chmod(tmp, 0o644)
        except OSError:
            pass
        os.replace(tmp, path)
    except OSError as exc:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise CanaryFarmError("cannot write decoy " + str(path) + ": " + str(exc)) from exc
    try:
        os.chmod(path, 0o644)
    except OSError:
        pass


def _record_from_state(
    rel_path: str, kind: str, marker: str, state: _FarmState, created_at: str
) -> CanaryFarmRecord:
    """Build a manifest record from a just written or already correct decoy."""

    return CanaryFarmRecord(
        rel_path=rel_path,
        kind=kind,
        size=state.size,
        sha256=state.sha256,
        mtime_ns=state.mtime_ns,
        inode=state.inode,
        marker=marker,
        created_at=created_at or _utc_now(),
    )


def _normalize_farm_kinds(kinds: Sequence[str] | None) -> tuple[str, ...]:
    """Validate and deduplicate the requested decoy families."""

    if kinds is None:
        return FARM_KINDS
    selected: list[str] = []
    for value in kinds:
        kind = str(value)
        if kind not in FARM_KINDS:
            raise CanaryFarmError(
                "unknown canary farm kind: " + kind + " (expected " + ", ".join(FARM_KINDS) + ")"
            )
        if kind not in selected:
            selected.append(kind)
    if not selected:
        raise CanaryFarmError("at least one canary farm kind is required")
    return tuple(selected)


def deploy_canary_farm(
    root: Path,
    *,
    per_directory: int = 1,
    max_files: int = 40,
    kinds: Sequence[str] | None = None,
) -> CanaryFarmReport:
    """Plant deterministic decoy files across the real source directories.

    The deployment is idempotent: a second call finds its own decoys (they carry
    the marker), keeps their fingerprints and timestamps, and rewrites only the
    manifest. A path occupied by a foreign file is skipped, never overwritten.

    Parameters:
        root: Project root to deploy into.
        per_directory: Decoys per eligible directory; must be positive.
        max_files: Hard cap on decoys in the whole tree; must be positive.
        kinds: Decoy families to use; None uses FARM_KINDS.

    Returns:
        A report with the deployed records, the skipped directories, the manifest
        path and the digest over the record set.

    Raises:
        CanaryFarmError: When the root is unusable or an argument is invalid.
    """

    if isinstance(per_directory, bool) or int(per_directory) <= 0:
        raise CanaryFarmError("per_directory must be a positive integer")
    if isinstance(max_files, bool) or int(max_files) <= 0:
        raise CanaryFarmError("max_files must be a positive integer")
    root_path = _abspath(Path(root))
    try:
        if not root_path.is_dir():
            raise CanaryFarmError("canary farm root is not a directory: " + str(root_path))
    except OSError as exc:
        raise CanaryFarmError("cannot inspect " + str(root_path) + ": " + str(exc)) from exc

    selected = _normalize_farm_kinds(kinds)
    previous = load_canary_farm(root_path)
    previous_by_rel = {record.rel_path: record for record in previous}
    is_ignored = _policy_ignored(root_path)
    created_at = _utc_now()
    deployed: list[CanaryFarmRecord] = []
    skipped: list[str] = []

    for directory in _farm_directories(root_path, is_ignored):
        if len(deployed) >= int(max_files):
            break
        rel_dir = _relative_posix(root_path, directory)
        rel_dir = "" if rel_dir == "." else rel_dir
        planned = 0
        seen_names: set[str] = set()
        for kind, name in _candidate_sequence(rel_dir, selected):
            if planned >= int(per_directory) or len(deployed) >= int(max_files):
                break
            if name in seen_names:
                continue
            seen_names.add(name)
            rel_path = (rel_dir + "/" + name) if rel_dir else name
            path = root_path / rel_path
            marker = _farm_marker(rel_path)
            prior = previous_by_rel.get(rel_path)
            state = _farm_state(path)
            if state.exists and _farm_owned(path, marker):
                # Our decoy is already here: keep the bytes and the original
                # timestamp so a second deploy is byte for byte inert.
                created = prior.created_at if prior is not None else created_at
                deployed.append(_record_from_state(rel_path, kind, marker, state, created))
                planned += 1
                continue
            if state.exists:
                # A foreign file owns this name; try the next deterministic name.
                continue
            payload = _farm_content(kind, marker)
            _write_farm_file(path, payload)
            written = _farm_state(path)
            if not written.exists or not written.sha256:
                continue
            created = prior.created_at if prior is not None else created_at
            deployed.append(_record_from_state(rel_path, kind, marker, written, created))
            planned += 1
        if planned == 0:
            skipped.append(rel_dir)

    deployed.sort(key=lambda record: record.rel_path)
    digest = _farm_digest(deployed)
    manifest = {
        "version": FARM_MANIFEST_VERSION,
        "generator": FARM_GENERATOR,
        "created_at": created_at,
        "digest": digest,
        "decoys": [
            {
                "rel_path": record.rel_path,
                "kind": record.kind,
                "size": record.size,
                "sha256": record.sha256,
                "mtime_ns": record.mtime_ns,
                "inode": record.inode,
                "marker": record.marker,
                "created_at": record.created_at,
            }
            for record in deployed
        ],
    }
    manifest_path = farm_manifest_path(root_path)
    try:
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise CanaryFarmError(
            "cannot create farm state directory " + str(manifest_path.parent) + ": " + str(exc)
        ) from exc
    tmp = manifest_path.with_name(manifest_path.name + ".tmp")
    try:
        with tmp.open("w", encoding="utf-8", newline=chr(10)) as handle:
            handle.write(json.dumps(manifest, indent=2, sort_keys=True) + chr(10))
        os.replace(tmp, manifest_path)
    except OSError as exc:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise CanaryFarmError("cannot write farm manifest " + str(manifest_path) + ": " + str(exc)) from exc
    return CanaryFarmReport(
        root=root_path,
        deployed=tuple(deployed),
        skipped_directories=tuple(sorted(skipped)),
        manifest_path=manifest_path,
        digest=digest,
        created_at=created_at,
    )


def load_canary_farm(root: Path) -> tuple[CanaryFarmRecord, ...]:
    """Load the deployed farm, degrading to an empty tuple on any bad state.

    A missing file, invalid JSON, a wrong version, a malformed record or a digest
    that does not match the record set all yield an empty farm. That is the safe
    direction: a damaged manifest must disable the extra traps, never raise inside
    a watch loop and never authorise a deletion.
    """

    root_path = _abspath(Path(root))
    path = farm_manifest_path(root_path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return ()
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return ()
    if not isinstance(payload, dict):
        return ()
    try:
        version = int(payload.get("version", 0) or 0)
    except (TypeError, ValueError):
        return ()
    if version != FARM_MANIFEST_VERSION:
        return ()
    raw_decoys = payload.get("decoys")
    if not isinstance(raw_decoys, list):
        return ()
    records: list[CanaryFarmRecord] = []
    for item in raw_decoys:
        if not isinstance(item, dict):
            continue
        rel_path = _safe_farm_rel(item.get("rel_path"))
        kind = item.get("kind")
        sha256 = item.get("sha256")
        marker = item.get("marker")
        if (
            rel_path is None
            or not isinstance(kind, str)
            or kind not in FARM_KINDS
            or not isinstance(sha256, str)
            or not sha256
            or not isinstance(marker, str)
            or not marker
        ):
            continue
        try:
            size = int(item.get("size", 0) or 0)
            mtime_ns = int(item.get("mtime_ns", 0) or 0)
            inode = int(item.get("inode", 0) or 0)
        except (TypeError, ValueError):
            continue
        stamp = item.get("created_at")
        records.append(
            CanaryFarmRecord(
                rel_path=rel_path,
                kind=kind,
                size=size,
                sha256=sha256,
                mtime_ns=mtime_ns,
                inode=inode,
                marker=marker,
                created_at=stamp if isinstance(stamp, str) else "",
            )
        )
    if raw_decoys and not records:
        return ()
    if _farm_digest(records) != str(payload.get("digest", "")):
        return ()
    records.sort(key=lambda record: record.rel_path)
    return tuple(records)


def remove_canary_farm(root: Path) -> int:
    """Delete only decoys this tool created, verified by fingerprint and marker.

    A file whose size, sha256 or embedded marker no longer matches the manifest is
    treated as user data and left alone, so a hand edited manifest cannot turn
    cleanup into arbitrary file deletion.

    Returns:
        Number of decoy files removed.
    """

    root_path = _abspath(Path(root))
    records = load_canary_farm(root_path)
    removed = 0
    for record in records:
        path = root_path / record.rel_path
        state = _farm_state(path)
        if not state.exists or not state.is_regular:
            continue
        if state.size != record.size or state.sha256 != record.sha256:
            continue
        if not _farm_owned(path, record.marker):
            continue
        try:
            path.unlink()
            removed += 1
        except OSError:
            continue
    manifest = farm_manifest_path(root_path)
    try:
        if manifest.is_file():
            manifest.unlink()
    except OSError:
        pass
    return removed


def canary_farm_status(root: Path) -> str:
    """Return one English line describing the armed farm for a command line."""

    records = load_canary_farm(root)
    if not records:
        return "canary farm: none armed"
    families: dict[str, int] = {}
    for record in records:
        families[record.kind] = families.get(record.kind, 0) + 1
    listing = ", ".join(
        kind + (" x" + str(count) if count > 1 else "")
        for kind, count in sorted(families.items())
    )
    return (
        "canary farm: "
        + str(len(records))
        + " decoy(s) armed ("
        + listing
        + ") under "
        + str(_abspath(Path(root)))
    )



