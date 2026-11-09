"""Real-time filesystem watching with kernel event backends and a poll fallback.

The dossier is a point in time measurement; the watch loop is the same detectors
running continuously, which is what actually catches a ransomware burst while it
is happening. Polling every second is honest but weak: an attacker that finishes
in 800 ms is invisible, and a one second poll reads entire trees just to prove
nothing changed. This module therefore prefers kernel notifications:

  * Linux: inotify through ctypes (inotify_init1, inotify_add_watch, read of
    struct inotify_event). Kernel queues events, one reader thread drains them.
  * Windows: ReadDirectoryChangesW through ctypes on a directory handle opened
    with FILE_LIST_DIRECTORY and FILE_FLAG_BACKUP_SEMANTICS, one recursive
    subtree watch per project, parsed from FILE_NOTIFY_INFORMATION records.
  * Anywhere the primitive is missing: the original poll loop, reported as a
    documented fallback with the exact reason, because a silent downgrade would
    make an operator believe kernel level coverage exists when it does not.

Every backend emits FileChange records. The loop translates them into the
existing WatchEvent(kind, path, detail, at) shape, so downstream consumers do not
change: a change to a canary file becomes kind "canary", a burst of high entropy
writes inside the window becomes kind "entropy", and a freeze attempt becomes
kind "freeze". Each detail names the backend that produced the evidence.

Freezing a writer is the only mutating action and it stays doubly gated: the
caller must pass freeze=True and the project policy must enable canary_freeze.
On Linux the writer is attributed through /proc/<pid>/fd and suspended with
SIGSTOP. On Windows the handle table is not enumerable from the standard
library, so the writer cannot be attributed; the loop emits a freeze event that
states exactly that and never guesses a pid. Suspension itself is implemented
with ntdll NtSuspendProcess/NtResumeProcess when a pid is known, but there is no
automatic resume: an operator decides when a frozen process runs again.
"""

from __future__ import annotations

import ctypes
import os
import select
import struct
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol, Sequence, runtime_checkable

from tauhaulity.core.entropy import shannon_entropy
from tauhaulity.daemon.canary import CanaryWatcher
from tauhaulity.daemon.entropy_radar import scan_with_budget

DEFAULT_INTERVAL_S = 1.0

#: Radar budget for one sweep. The default scan budget is right for a one shot
#: dossier probe, but a watcher that spends two seconds per sweep cannot keep a
#: one second cadence, so a sweep spends at most a quarter of it.
WATCH_RADAR_MAX_FILES = 64
WATCH_RADAR_MAX_TOTAL_BYTES = 8 * 1024 * 1024

#: Event families emitted by the loop.
CANARY_KIND = "canary"
ENTROPY_KIND = "entropy"
FREEZE_KIND = "freeze"

#: Backend selector values and the names reported to callers.
BACKEND_AUTO = "auto"
BACKEND_LINUX = "linux"
BACKEND_WINDOWS = "windows"
BACKEND_POLLING = "polling"

LINUX_BACKEND_NAME = "linux-inotify"
WINDOWS_BACKEND_NAME = "windows-rdcw"
POLLING_BACKEND_NAME = "polling"

#: Smallest accepted poll interval, so a caller cannot turn the loop into a busy
#: spin that starves the process it is supposed to protect.
_MIN_INTERVAL_S = 0.01

#: Bound on the procfs descriptor scan used to identify a canary writer.
_MAX_FDS_PER_PROC = 256

#: Bound on the directories an inotify backend will watch for one project. A
#: tree above this size still works, but deeper directories are reported as
#: unwatched instead of exhausting the kernel watch descriptor supply.
MAX_WATCHED_DIRECTORIES = 4096

#: The reader waits in slices so a stop request is honoured promptly even when
#: the kernel API has no cancelable wait on this platform.
_WAIT_SLICE_S = 0.05

#: Entropy classification of a single write: a changed file is sampled and, when
#: it looks like ciphertext, contributes to a burst. Three high entropy writes
#: inside the window is the smallest count that distinguishes an encryption pass
#: from a developer saving one compressed artefact.
_EVENT_SAMPLE_BYTES = 64 * 1024
_EVENT_MIN_BYTES = 512
_EVENT_ENTROPY_THRESHOLD = 7.2
_ENTROPY_BURST_WINDOW_S = 2.0
_ENTROPY_BURST_HITS = 3

#: Duplicate suppression for identical (kind, path, action) observations, so a
#: single write that the kernel reports twice does not print two lines.
_DEDUPE_WINDOW_S = 0.1

#: ntdll status code for success.
_STATUS_SUCCESS = 0

#: Windows access rights and flags used by the directory and process handles.
_FILE_LIST_DIRECTORY = 0x0001
_FILE_SHARE_ALL = 0x0007
_OPEN_EXISTING = 3
_FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
_NOTIFY_FILE_NAME = 0x0001
_NOTIFY_DIR_NAME = 0x0002
_NOTIFY_ATTRIBUTES = 0x0004
_NOTIFY_SIZE = 0x0008
_NOTIFY_LAST_WRITE = 0x0010
_PROCESS_SUSPEND_RESUME = 0x0800

#: inotify constants from <sys/inotify.h>.
_IN_MODIFY = 0x00000002
_IN_ATTRIB = 0x00000004
_IN_MOVED_FROM = 0x00000040
_IN_MOVED_TO = 0x00000080
_IN_CREATE = 0x00000100
_IN_DELETE = 0x00000200
_IN_DELETE_SELF = 0x00000400
_IN_MOVE_SELF = 0x00000800
_IN_ISDIR = 0x40000000
_IN_NONBLOCK = 0x00000800
_IN_CLOEXEC = 0x00080000
_INOTIFY_WATCH_MASK = (
    _IN_MODIFY
    | _IN_ATTRIB
    | _IN_MOVED_FROM
    | _IN_MOVED_TO
    | _IN_CREATE
    | _IN_DELETE
    | _IN_DELETE_SELF
    | _IN_MOVE_SELF
)

#: struct inotify_event is { int wd; uint32 mask; uint32 cookie; uint32 len; }
#: followed by len bytes of NUL padded name. The size assertion below is the
#: guard that keeps the parser and the kernel ABI in sync.
_INOTIFY_EVENT = struct.Struct("<iIII")
_INOTIFY_EVENT_SIZE = struct.calcsize("<iIII")
if _INOTIFY_EVENT_SIZE != 16:
    raise RuntimeError("inotify_event must be 16 bytes, got " + str(_INOTIFY_EVENT_SIZE))

#: FILE_NOTIFY_INFORMATION header: DWORD NextEntryOffset, DWORD Action, DWORD
#: FileNameLength followed by UTF-16LE FileName. The offsets inside a record are
#: DWORD aligned and the parser trusts the kernel supplied NextEntryOffset only
#: after validating it.
_NOTIFY_HEADER = struct.Struct("<III")
_NOTIFY_HEADER_SIZE = struct.calcsize("<III")
if _NOTIFY_HEADER_SIZE != 12:
    raise RuntimeError("FILE_NOTIFY_INFORMATION header must be 12 bytes")

#: One ReadDirectoryChangesW buffer, generously sized so a burst arrives in one
#: read instead of overflowing and forcing a rescan.
_RDCW_BUFFER_BYTES = 65536

#: Windows FILE_ACTION_* values mapped to the action vocabulary used here.
_WINDOWS_ACTIONS = {
    1: "created",
    2: "deleted",
    3: "modified",
    4: "moved",
    5: "moved",
}

#: Pids that must never be suspended: 0 is the idle process, 4 is System (on
#: Windows), and the watch loop itself (or its parent) must survive its own
#: defensive action.
_PROTECTED_PIDS: frozenset[int] = frozenset({0, 4})


def _utc_now() -> str:
    """Return an ISO 8601 UTC timestamp with second precision."""

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _validate_interval(value: float) -> float:
    """Return a usable poll interval or raise ValueError."""

    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("interval_s must be a number")
    interval = float(value)
    if interval != interval or interval in (float("inf"), float("-inf")):
        raise ValueError("interval_s must be a finite number")
    if interval <= 0:
        raise ValueError("interval_s must be positive")
    return max(interval, _MIN_INTERVAL_S)


def _validate_duration(value: float | None) -> float | None:
    """Return a usable duration in seconds or raise ValueError."""

    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("duration_s must be a number or None")
    duration = float(value)
    if duration != duration or duration < 0:
        raise ValueError("duration_s must not be negative")
    return duration


def _validate_backend(value: str) -> str:
    """Return a normalized backend selector or raise ValueError."""

    if not isinstance(value, str):
        raise ValueError("backend must be a string")
    normalized = value.strip().lower()
    if normalized not in {BACKEND_AUTO, BACKEND_LINUX, BACKEND_WINDOWS, BACKEND_POLLING}:
        raise ValueError("backend must be one of: auto, linux, windows, polling")
    return normalized


def _relative(root: Path, path: Path) -> str:
    """Return a project relative forward slash path without raising."""

    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _is_canary_rel(root: Path, rel_path: str, known: frozenset[str]) -> bool:
    """Return True when a changed path is one of the decoy files.

    The naming rule mirrors the CanaryWatcher discovery rule so a decoy created
    after the loop armed is still recognised, and every canary that existed at
    arm time is accepted verbatim regardless of its name.
    """

    if rel_path in known:
        return True
    name = Path(rel_path).name.lower()
    return name.startswith("canary") or name.endswith(".canary") or name.startswith("decoy")


@dataclass(frozen=True, slots=True)
class WatchEvent:
    """One observation produced by the watch loop.

    Attributes:
        kind: Event family: "canary", "entropy" or "freeze".
        path: Project relative path the event concerns.
        detail: Human readable explanation including the active backend.
        at: UTC ISO 8601 timestamp with second precision.
    """

    kind: str
    path: str
    detail: str
    at: str


@dataclass(frozen=True, slots=True)
class FileChange:
    """One raw filesystem change reported by a backend.

    Attributes:
        rel_path: Project relative forward slash path.
        action: created, modified, deleted or moved.
        is_dir: True when the changed entry is a directory.
        entropy: Entropy already measured by the backend (0.0 when unknown); the
            polling backend uses it to forward radar alerts without re-reading.
    """

    rel_path: str
    action: str
    is_dir: bool = False
    entropy: float = 0.0


@runtime_checkable
class WatchBackend(Protocol):
    """Structural contract every watch backend implements.

    Attributes:
        name: Backend identifier reported to callers.
    """

    name: str

    def start(self) -> None:
        """Begin delivering changes; may raise when the primitive is unusable."""

    def stop(self) -> None:
        """Stop delivering changes and release every kernel resource."""

    def wait(self, timeout_s: float) -> bool:
        """Wait up to timeout_s; True when events may be available."""

    def events(self) -> list[FileChange]:
        """Drain and return the changes observed since the previous call."""


class _BackendBase:
    """Shared queue, readiness signal and lifecycle helpers for backends."""

    name = POLLING_BACKEND_NAME

    def __init__(self, root: Path, *, interval_s: float = DEFAULT_INTERVAL_S) -> None:
        self._root = Path(root)
        self._interval_s = interval_s
        self._queue: deque[FileChange] = deque(maxlen=4096)
        self._lock = threading.Lock()
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = False

    @property
    def root(self) -> Path:
        """Project root this backend watches."""

        return self._root

    def _push(self, change: FileChange) -> None:
        """Add one change to the queue and wake a waiting consumer."""

        with self._lock:
            self._queue.append(change)
        self._ready.set()

    def _push_many(self, changes: Sequence[FileChange]) -> None:
        """Add several changes under one lock acquisition."""

        if not changes:
            return
        with self._lock:
            self._queue.extend(changes)
        self._ready.set()

    def wait(self, timeout_s: float) -> bool:
        """Wait until changes are queued, the timeout expires or stop is set."""

        timeout = max(0.0, float(timeout_s))
        deadline = time.monotonic() + timeout
        while True:
            if self._ready.is_set():
                return True
            if self._stop.is_set():
                return False
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            self._ready.wait(min(remaining, _WAIT_SLICE_S))
            if not self._ready.is_set() and deadline <= time.monotonic():
                return False

    def events(self) -> list[FileChange]:
        """Drain the queue; safe to call from the consumer thread only."""

        with self._lock:
            drained = list(self._queue)
            self._queue.clear()
            self._ready.clear()
        return drained

    def _spawn(self, target: Callable[[], None], name: str) -> None:
        """Start the single reader thread, refusing a double start."""

        if self._started:
            raise RuntimeError(self.name + " backend is already started")
        self._started = True
        thread = threading.Thread(target=target, name=name, daemon=True)
        self._thread = thread
        thread.start()

    def _join(self, timeout_s: float = 1.0) -> None:
        """Join the reader thread, tolerating a thread that already died."""

        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout_s)

    def stop(self) -> None:
        """Set the stop flag and release the reader thread."""

        self._stop.set()
        self._ready.set()
        self._join()
        self._started = False


def _inotify_action(mask: int) -> str:
    """Translate one inotify mask into the shared action vocabulary."""

    if mask & (_IN_DELETE | _IN_MOVED_FROM):
        return "deleted"
    if mask & (_IN_CREATE | _IN_MOVED_TO):
        return "created"
    if mask & (_IN_MODIFY | _IN_ATTRIB):
        return "modified"
    return "modified"


def _linux_inotify_available() -> bool:
    """Return True when libc exposes the inotify entry points."""

    if not sys.platform.startswith("linux"):
        return False
    try:
        libc = ctypes.CDLL(None, use_errno=True)
    except (OSError, TypeError):
        return False
    return hasattr(libc, "inotify_init1") and hasattr(libc, "inotify_add_watch")


def _windows_rdcw_available() -> bool:
    """Return True when kernel32 exposes ReadDirectoryChangesW."""

    if os.name != "nt":
        return False
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except (OSError, AttributeError, TypeError):
        return False
    return hasattr(kernel32, "ReadDirectoryChangesW")


class PollingBackend(_BackendBase):
    """Interval based fallback built on the canary watcher and entropy radar.

    This is the original loop, kept as an explicit fallback: on platforms without
    a kernel notification API it is the only way to observe changes, and reporting
    it as such is more honest than claiming real-time coverage.
    """

    name = POLLING_BACKEND_NAME

    def __init__(
        self,
        root: Path,
        *,
        interval_s: float = DEFAULT_INTERVAL_S,
        reason: str = "",
    ) -> None:
        super().__init__(root, interval_s=interval_s)
        self.reason = reason or "polling was requested"
        self._watcher: CanaryWatcher | None = None

    def start(self) -> None:
        """Snapshot the canaries and start the poll thread."""

        watcher = CanaryWatcher(self._root, interval_ms=max(1, int(self._interval_s * 1000)))
        try:
            watcher.snapshot()
        except (OSError, RuntimeError, ValueError):
            # A tree that cannot be walked yet arms an empty baseline; later polls
            # simply report nothing until the tree appears.
            pass
        self._watcher = watcher
        radar_every = max(self._interval_s, 0.05)
        self._spawn(lambda: self._loop(radar_every), "tauhaulity-watch-poll")

    def _loop(self, radar_every: float) -> None:
        """Poll canaries and the bounded radar until stopped."""

        watcher = self._watcher
        last_radar = 0.0
        while not self._stop.is_set():
            changes: list[FileChange] = []
            if watcher is not None:
                try:
                    events = watcher.scan()
                except (OSError, RuntimeError, ValueError):
                    events = []
                for event in events:
                    changes.append(FileChange(event.path, event.kind))
            now = time.monotonic()
            if now - last_radar >= radar_every:
                last_radar = now
                try:
                    report = scan_with_budget(
                        self._root,
                        max_files=WATCH_RADAR_MAX_FILES,
                        max_total_bytes=WATCH_RADAR_MAX_TOTAL_BYTES,
                    )
                except (OSError, ValueError):
                    report = None
                if report is not None:
                    for alert in report.alerts:
                        changes.append(
                            FileChange(alert.rel_path, "modified", False, float(alert.entropy))
                        )
            self._push_many(changes)
            self._stop.wait(self._interval_s)

    def stop(self) -> None:
        """Stop the poll thread."""

        super().stop()


class LinuxBackend(_BackendBase):
    """inotify backend: kernel queued events, one reader thread, no polling."""

    name = LINUX_BACKEND_NAME

    def __init__(self, root: Path, *, interval_s: float = DEFAULT_INTERVAL_S) -> None:
        super().__init__(root, interval_s=interval_s)
        self._fd = -1
        self._wd_paths: dict[int, Path] = {}
        self._add_watch = None
        self._failure_reason = ""

    @property
    def failure_reason(self) -> str:
        """Why the kernel backend refused to start, empty while healthy."""

        return self._failure_reason

    def start(self) -> None:
        """Create the inotify instance, watch the tree and start the reader."""

        try:
            libc = ctypes.CDLL(None, use_errno=True)
            init = libc.inotify_init1
            init.argtypes = [ctypes.c_int]
            init.restype = ctypes.c_int
            add = libc.inotify_add_watch
            add.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
            add.restype = ctypes.c_int
            fd = int(init(_IN_NONBLOCK | _IN_CLOEXEC))
        except (OSError, AttributeError, TypeError) as exc:
            self._failure_reason = "inotify is unavailable: " + type(exc).__name__
            raise RuntimeError(self._failure_reason) from exc
        if fd < 0:
            self._failure_reason = "inotify_init1 failed with errno " + str(ctypes.get_errno())
            raise RuntimeError(self._failure_reason)
        self._fd = fd
        self._add_watch = add
        self._add_tree(self._root)
        if not self._wd_paths:
            self._close_fd()
            self._failure_reason = "inotify refused every directory under " + str(self._root)
            raise RuntimeError(self._failure_reason)
        self._spawn(self._loop, "tauhaulity-inotify")

    def _add_tree(self, start: Path) -> None:
        """Add watches for a directory and its descendants under the bound."""

        if len(self._wd_paths) >= MAX_WATCHED_DIRECTORIES:
            return
        if not start.is_dir():
            return
        for current, dirnames, _filenames in os.walk(start):
            dirnames[:] = sorted(name for name in dirnames if name != "__pycache__")
            if len(self._wd_paths) >= MAX_WATCHED_DIRECTORIES:
                return
            self._add_one(Path(current))

    def _add_one(self, directory: Path) -> bool:
        """Add one watch descriptor and remember which directory it belongs to."""

        if self._add_watch is None or self._fd < 0:
            return False
        try:
            wd = int(self._add_watch(self._fd, str(directory).encode("utf-8"), _INOTIFY_WATCH_MASK))
        except (OSError, ValueError, TypeError):
            return False
        if wd < 0:
            return False
        self._wd_paths[wd] = directory
        return True

    def _loop(self) -> None:
        """Drain the inotify descriptor until stopped."""

        while not self._stop.is_set():
            if self._fd < 0:
                return
            try:
                readable, _, _ = select.select([self._fd], [], [], _WAIT_SLICE_S)
            except (OSError, ValueError):
                return
            if self._stop.is_set():
                return
            if not readable:
                continue
            try:
                payload = os.read(self._fd, 65536)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                return
            if not payload:
                continue
            changes = self._parse(payload)
            self._push_many(changes)

    def _parse(self, payload: bytes) -> list[FileChange]:
        """Parse a buffer of inotify_event records into FileChange entries."""

        changes: list[FileChange] = []
        offset = 0
        total = len(payload)
        while offset + _INOTIFY_EVENT_SIZE <= total:
            wd, mask, _cookie, name_len = _INOTIFY_EVENT.unpack_from(payload, offset)
            name_start = offset + _INOTIFY_EVENT_SIZE
            name_end = name_start + int(name_len)
            if name_end > total:
                break
            raw_name = payload[name_start:name_end]
            offset = name_end
            directory = self._wd_paths.get(wd)
            if directory is None:
                continue
            name = raw_name.split(b"\x00", 1)[0].decode("utf-8", "replace")
            if not name:
                # A self event on a watched directory: the directory itself moved
                # or vanished, which is a directory change we do not classify.
                continue
            is_dir = bool(mask & _IN_ISDIR)
            target = directory / name
            if is_dir and (mask & (_IN_CREATE | _IN_MOVED_TO)):
                self._add_tree(target)
            changes.append(
                FileChange(_relative(self._root, target), _inotify_action(mask), is_dir)
            )
        return changes

    def _close_fd(self) -> None:
        """Close the inotify descriptor once."""

        if self._fd >= 0:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = -1

    def stop(self) -> None:
        """Stop the reader and close the descriptor."""

        self._stop.set()
        self._ready.set()
        self._join(2.0)
        self._close_fd()
        self._started = False


class WindowsBackend(_BackendBase):
    """ReadDirectoryChangesW backend on one recursive directory handle."""

    name = WINDOWS_BACKEND_NAME

    def __init__(self, root: Path, *, interval_s: float = DEFAULT_INTERVAL_S) -> None:
        super().__init__(root, interval_s=interval_s)
        self._handle: object | None = None
        self._kernel32: object | None = None
        self._failure_reason = ""

    @property
    def failure_reason(self) -> str:
        """Why the kernel backend refused to start, empty while healthy."""

        return self._failure_reason

    def start(self) -> None:
        """Open the directory handle and start the one reader thread."""

        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        except (OSError, AttributeError, TypeError) as exc:
            self._failure_reason = "kernel32 is unavailable: " + type(exc).__name__
            raise RuntimeError(self._failure_reason) from exc
        kernel32.CreateFileW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
        ]
        kernel32.CreateFileW.restype = ctypes.c_void_p
        kernel32.ReadDirectoryChangesW.argtypes = [
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_void_p,
            ctypes.c_void_p,
        ]
        kernel32.ReadDirectoryChangesW.restype = ctypes.c_int
        kernel32.CancelIoEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
        kernel32.CancelIoEx.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        handle = kernel32.CreateFileW(
            str(self._root),
            _FILE_LIST_DIRECTORY,
            _FILE_SHARE_ALL,
            None,
            _OPEN_EXISTING,
            _FILE_FLAG_BACKUP_SEMANTICS,
            None,
        )
        invalid = ctypes.c_void_p(-1).value
        if not handle or int(handle) == invalid:
            self._failure_reason = (
                "CreateFileW could not open the directory (error "
                + str(ctypes.get_last_error())
                + ")"
            )
            raise RuntimeError(self._failure_reason)
        self._handle = handle
        self._kernel32 = kernel32
        self._spawn(self._loop, "tauhaulity-rdcw")

    def _loop(self) -> None:
        """Read batches of FILE_NOTIFY_INFORMATION records until stopped."""

        kernel32 = self._kernel32
        handle = self._handle
        if kernel32 is None or handle is None:
            return
        buffer = ctypes.create_string_buffer(_RDCW_BUFFER_BYTES)
        notify_filter = (
            _NOTIFY_FILE_NAME
            | _NOTIFY_DIR_NAME
            | _NOTIFY_ATTRIBUTES
            | _NOTIFY_SIZE
            | _NOTIFY_LAST_WRITE
        )
        while not self._stop.is_set():
            returned = ctypes.c_uint32(0)
            try:
                ok = kernel32.ReadDirectoryChangesW(
                    ctypes.c_void_p(handle),
                    ctypes.c_void_p(ctypes.addressof(buffer)),
                    _RDCW_BUFFER_BYTES,
                    1,
                    notify_filter,
                    ctypes.byref(returned),
                    None,
                    None,
                )
            except (OSError, ValueError, TypeError):
                return
            if not ok:
                # ERROR_OPERATION_ABORTED (995) is the normal cancel path, an
                # invalid handle means stop already closed it; both end quietly.
                return
            if self._stop.is_set():
                return
            if returned.value:
                changes = self._parse(buffer.raw[: returned.value])
                self._push_many(changes)

    def _parse(self, payload: bytes) -> list[FileChange]:
        """Parse FILE_NOTIFY_INFORMATION records with DWORD aligned offsets."""

        changes: list[FileChange] = []
        offset = 0
        total = len(payload)
        while offset + _NOTIFY_HEADER_SIZE <= total:
            next_offset, action, name_len = _NOTIFY_HEADER.unpack_from(payload, offset)
            name_start = offset + _NOTIFY_HEADER_SIZE
            name_end = name_start + int(name_len)
            if name_end > total:
                break
            raw_name = payload[name_start:name_end]
            try:
                name = raw_name.decode("utf-16-le", "replace")
            except (UnicodeDecodeError, ValueError):
                break
            rel = name.replace("\\", "/")
            if rel.startswith("./"):
                rel = rel[2:]
            action_name = _WINDOWS_ACTIONS.get(int(action), "modified")
            if rel:
                changes.append(FileChange(rel, action_name, False))
            if int(next_offset) == 0:
                break
            # A malformed offset would loop forever, so it is validated before
            # it is trusted; the kernel pads records to DWORD alignment.
            if next_offset < _NOTIFY_HEADER_SIZE or int(next_offset) % 4 != 0:
                break
            offset += int(next_offset)
        return changes

    def _close_handle(self) -> None:
        """Cancel pending IO and close the directory handle once."""

        kernel32 = self._kernel32
        handle = self._handle
        if kernel32 is None or handle is None:
            return
        try:
            kernel32.CancelIoEx(ctypes.c_void_p(handle), None)
        except (OSError, ValueError, TypeError):
            pass
        try:
            kernel32.CloseHandle(ctypes.c_void_p(handle))
        except (OSError, ValueError, TypeError):
            pass
        self._handle = None

    def stop(self) -> None:
        """Cancel the blocking read and close the handle."""

        self._stop.set()
        self._ready.set()
        self._close_handle()
        self._join(2.0)
        self._started = False


def watch_backend_name(backend: str = BACKEND_AUTO) -> str:
    """Return the backend name that would be selected on this host.

    Parameters:
        backend: auto, linux, windows or polling.

    Returns:
        linux-inotify, windows-rdcw or polling. An explicitly requested kernel
        backend that is unavailable on this host reports polling, which is the
        same decision create_backend makes.

    Raises:
        ValueError: When the selector is not one of the documented values.
    """

    normalized = _validate_backend(backend)
    if normalized == BACKEND_POLLING:
        return POLLING_BACKEND_NAME
    if normalized == BACKEND_LINUX:
        return LINUX_BACKEND_NAME if _linux_inotify_available() else POLLING_BACKEND_NAME
    if normalized == BACKEND_WINDOWS:
        return WINDOWS_BACKEND_NAME if _windows_rdcw_available() else POLLING_BACKEND_NAME
    if os.name == "nt":
        return WINDOWS_BACKEND_NAME if _windows_rdcw_available() else POLLING_BACKEND_NAME
    if sys.platform.startswith("linux") and _linux_inotify_available():
        return LINUX_BACKEND_NAME
    return POLLING_BACKEND_NAME


def create_backend(
    root: Path,
    *,
    backend: str = BACKEND_AUTO,
    interval_s: float = DEFAULT_INTERVAL_S,
    fallback_reason: str = "",
) -> WatchBackend:
    """Create the best available backend without starting it.

    Parameters:
        root: Project root to watch.
        backend: auto, linux, windows or polling.
        interval_s: Poll cadence for the polling backend.
        fallback_reason: Human readable note attached to a polling fallback.

    Returns:
        A backend instance whose name reports what it is.

    Raises:
        ValueError: When the selector or interval is invalid.
    """

    interval = _validate_interval(interval_s)
    normalized = _validate_backend(backend)
    selected = watch_backend_name(normalized)
    if selected == LINUX_BACKEND_NAME:
        return LinuxBackend(root, interval_s=interval)
    if selected == WINDOWS_BACKEND_NAME:
        return WindowsBackend(root, interval_s=interval)
    reason = fallback_reason
    if not reason:
        if normalized == BACKEND_AUTO:
            reason = "no kernel notification interface is available on this host"
        elif normalized == BACKEND_POLLING:
            reason = "polling was requested"
        else:
            reason = normalized + " backend is not available on this host"
    return PollingBackend(root, interval_s=interval, reason=reason)


def _wait(interval: float, stop: object | None, deadline: float | None) -> bool:
    """Wait one slice, returning False when the loop must stop.

    The wait is capped by the remaining duration so a loop with a duration shorter
    than the interval never overshoots its budget by a whole slice.
    """

    timeout = min(interval, _WAIT_SLICE_S)
    if deadline is not None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        timeout = min(timeout, remaining)
    if stop is None:
        time.sleep(timeout)
        return True
    try:
        stop.wait(timeout)
    except (OSError, RuntimeError):
        time.sleep(timeout)
    try:
        return not bool(stop.is_set())
    except (OSError, RuntimeError):
        return True


def _emit(event: WatchEvent, on_event: Callable[[WatchEvent], None] | None) -> int:
    """Deliver one event to the optional callback and count it as emitted."""

    if on_event is not None:
        try:
            on_event(event)
        except (OSError, RuntimeError, ValueError, TypeError):
            # The observation still happened and stays counted; a broken consumer
            # must not take the guard loop down with it.
            pass
    return 1


def _policy_freeze_allowed(root: Path) -> tuple[bool, str]:
    """Return whether the project policy allows freezing a writer.

    The policy module is imported lazily so the daemon package stays importable
    even when the core package is being restructured by a sibling change.
    """

    try:
        from tauhaulity.core.policy import Policy, policy_path
    except ImportError:
        return False, "policy module is unavailable"
    try:
        policy = Policy.load(policy_path(root))
    except (OSError, ValueError, RuntimeError) as exc:
        return False, "policy cannot be loaded: " + type(exc).__name__ + ": " + str(exc)
    if not bool(getattr(policy, "canary_freeze", False)):
        return False, "policy canary_freeze is disabled"
    return True, ""


def _protected_pids() -> set[int]:
    """Return pids the freeze primitive must never suspend.

    The loop itself and its parent are included so a defensive action cannot
    freeze the process that is supposed to keep watching.
    """

    protected = set(_PROTECTED_PIDS)
    protected.add(os.getpid())
    try:
        parent = os.getppid()
    except (OSError, AttributeError):
        parent = 0
    if parent > 0:
        protected.add(parent)
    return protected


def _pid_is_suspendable(pid: int) -> bool:
    """Return True when a pid is a positive integer outside the protected set."""

    if isinstance(pid, bool) or not isinstance(pid, int):
        return False
    if pid <= 0:
        return False
    return pid not in _protected_pids()


def _windows_open_for_suspend(pid: int) -> int | None:
    """Open a process handle with PROCESS_SUSPEND_RESUME, or None."""

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel32.OpenProcess.restype = ctypes.c_void_p
        handle = kernel32.OpenProcess(_PROCESS_SUSPEND_RESUME, 0, int(pid))
        if not handle:
            return None
        return int(handle)
    except (OSError, AttributeError, TypeError):
        return None


def _windows_close_handle(handle: int) -> None:
    """Close a process handle, ignoring a handle the OS already invalidated."""

    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
        kernel32.CloseHandle.restype = ctypes.c_int
        kernel32.CloseHandle(ctypes.c_void_p(handle))
    except (OSError, AttributeError, TypeError):
        pass


def _windows_nt_process_call(name: str, pid: int) -> bool:
    """Invoke NtSuspendProcess or NtResumeProcess on one pid."""

    handle = _windows_open_for_suspend(pid)
    if handle is None:
        return False
    try:
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)
        operation = getattr(ntdll, name, None)
        if operation is None:
            return False
        operation.argtypes = [ctypes.c_void_p]
        operation.restype = ctypes.c_long
        status = int(operation(ctypes.c_void_p(handle)))
        return status == _STATUS_SUCCESS
    except (OSError, AttributeError, TypeError, ValueError):
        return False
    finally:
        _windows_close_handle(handle)


def suspend_process(pid: int) -> bool:
    """Suspend one process, returning True when the kernel accepted the request.

    Linux uses SIGSTOP, which is uncatchable and keeps the process resident for
    inspection. Windows uses ntdll NtSuspendProcess on a handle opened with
    PROCESS_SUSPEND_RESUME. There is deliberately no automatic resume anywhere:
    the operator decides when the frozen process runs again.
    """

    if not _pid_is_suspendable(pid):
        return False
    if os.name == "nt":
        return _windows_nt_process_call("NtSuspendProcess", pid)
    try:
        import signal

        os.kill(int(pid), signal.SIGSTOP)
        return True
    except (OSError, AttributeError, ValueError):
        return False


def resume_process(pid: int) -> bool:
    """Resume a process suspended by suspend_process.

    Linux uses SIGCONT. Windows uses ntdll NtResumeProcess, which decrements the
    suspension count exactly like the Task Manager resume action.
    """

    if not _pid_is_suspendable(pid):
        return False
    if os.name == "nt":
        return _windows_nt_process_call("NtResumeProcess", pid)
    try:
        import signal

        os.kill(int(pid), signal.SIGCONT)
        return True
    except (OSError, AttributeError, ValueError):
        return False


#: Backwards compatible hook: existing callers and tests replace this name to
#: observe the freeze path without touching a real process.
_suspend_process = suspend_process


def _writer_pids(root: Path, paths: Sequence[str]) -> tuple[list[int], str]:
    """Return pids that hold one of the given files open.

    procfs exposes every descriptor as a symlink whose target names the open file,
    which is the only standard library way to answer "who is writing this" on
    Linux. Windows does not expose an equivalent without an undocumented ntdll
    call, so the honest answer there is that the writer cannot be identified and
    no pid may be guessed.
    """

    if not paths:
        return [], "there is no canary path to match"
    if os.name == "nt":
        return [], "the Windows handle table is not enumerable from the standard library"
    if not Path("/proc").is_dir():
        return [], "procfs is unavailable on this host"
    wanted: set[str] = set()
    for value in paths:
        candidate = Path(value)
        if not candidate.is_absolute():
            candidate = root / value
        try:
            wanted.add(os.path.realpath(candidate))
        except OSError:
            continue
    if not wanted:
        return [], "no canary path could be resolved"
    try:
        entries = list(os.scandir("/proc"))
    except OSError:
        return [], "procfs is unreadable from this process"
    found: list[int] = []
    for entry in entries:
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid in _protected_pids():
            continue
        fd_dir = "/proc/" + entry.name + "/fd"
        try:
            descriptors = os.listdir(fd_dir)
        except OSError:
            continue
        for descriptor in descriptors[:_MAX_FDS_PER_PROC]:
            try:
                target = os.readlink(os.path.join(fd_dir, descriptor))
            except OSError:
                continue
            if target in wanted:
                found.append(pid)
                break
    if not found:
        return [], "no live process holds the canary open"
    return sorted(set(found)), ""


def _freeze_writer(
    root: Path,
    paths: Sequence[str],
    on_event: Callable[[WatchEvent], None] | None,
    backend_name: str = "",
) -> int:
    """Try to suspend the writer that touched a canary and report the outcome."""

    if not paths:
        return 0
    primary = paths[0]
    suffix = " [backend=" + backend_name + "]" if backend_name else ""
    allowed, reason = _policy_freeze_allowed(root)
    if not allowed:
        return _emit(
            WatchEvent(FREEZE_KIND, primary, "not frozen: " + reason + suffix, _utc_now()),
            on_event,
        )
    pids, reason = _writer_pids(root, paths)
    if not pids:
        return _emit(
            WatchEvent(
                FREEZE_KIND,
                primary,
                "not frozen: " + (reason or "no writer could be identified") + suffix,
                _utc_now(),
            ),
            on_event,
        )
    suspended = [pid for pid in pids if _suspend_process(pid)]
    if not suspended:
        detail = "not frozen: suspension was refused for pid(s) " + ", ".join(
            str(pid) for pid in pids
        )
    else:
        detail = "suspended pid(s) " + ", ".join(str(pid) for pid in suspended)
        detail += " holding " + ", ".join(paths[:3])
        detail += "; resume with resume_process(pid)"
        refused = [pid for pid in pids if pid not in suspended]
        if refused:
            detail += "; refused for pid(s) " + ", ".join(str(pid) for pid in refused)
    return _emit(WatchEvent(FREEZE_KIND, primary, detail + suffix, _utc_now()), on_event)


def _quick_entropy(root: Path, rel_path: str) -> float | None:
    """Measure the entropy of a just written file under a small byte budget."""

    candidate = Path(rel_path)
    path = candidate if candidate.is_absolute() else root / rel_path
    try:
        if path.is_symlink() or not path.is_file():
            return None
        if path.stat().st_size < _EVENT_MIN_BYTES:
            return None
        with path.open("rb") as handle:
            payload = handle.read(_EVENT_SAMPLE_BYTES)
    except OSError:
        return None
    if len(payload) < _EVENT_MIN_BYTES:
        return None
    return shannon_entropy(payload)


class EntropyBurstTracker:
    """Sliding window of high entropy writes used to classify a burst.

    One compressed artefact saved by a developer is normal; three high entropy
    writes inside a couple of seconds is the signature of an encryption pass. The
    tracker keeps only the window so memory is bounded by the hit count and not by
    project size.
    """

    def __init__(
        self,
        window_s: float = _ENTROPY_BURST_WINDOW_S,
        hits: int = _ENTROPY_BURST_HITS,
    ) -> None:
        if not isinstance(window_s, (int, float)) or isinstance(window_s, bool) or window_s <= 0:
            raise ValueError("window_s must be positive")
        if not isinstance(hits, int) or isinstance(hits, bool) or hits <= 0:
            raise ValueError("hits must be a positive integer")
        self._window_s = float(window_s)
        self._hits = int(hits)
        self._items: list[tuple[float, str, float]] = []

    @property
    def hits(self) -> int:
        """Number of writes that constitute a burst."""

        return self._hits

    def add(self, now: float, rel_path: str, entropy: float) -> list[tuple[str, float]]:
        """Record one high entropy write and return the burst members when hot.

        Returns:
            The (path, entropy) pairs inside the window once the hit count is
            reached, otherwise an empty list.
        """

        self._items.append((float(now), rel_path, float(entropy)))
        cutoff = float(now) - self._window_s
        self._items = [item for item in self._items if item[0] >= cutoff]
        if len(self._items) < self._hits:
            return []
        return [(path, value) for _stamp, path, value in self._items]

    def reset(self) -> None:
        """Forget the current window."""

        self._items.clear()


def watch_loop(
    root: Path,
    *,
    interval_s: float = DEFAULT_INTERVAL_S,
    duration_s: float | None = None,
    freeze: bool = False,
    on_event: Callable[[WatchEvent], None] | None = None,
    stop: object | None = None,
    backend: str = BACKEND_AUTO,
    on_backend: Callable[[str], None] | None = None,
) -> int:
    """Watch a project for canary, entropy and freeze events until stopped.

    A kernel notification backend is started when available; otherwise the
    documented polling fallback runs. The chosen backend is reported through the
    optional on_backend callback and inside every event detail.

    The canaries are snapshotted before the loop starts, so only changes that
    happen during the loop are reported; a bounded radar sweep runs once per
    interval so a ciphertext file that predates the loop is still reported.

    Parameters:
        root: Project root to watch.
        interval_s: Radar sweep cadence; must be positive.
        duration_s: Stop after this many seconds; None runs until stopped.
        freeze: Attempt to suspend the writer of a tampered canary when the
            project policy allows it.
        on_event: Callback invoked with each WatchEvent; exceptions raised by it
            are contained.
        stop: Optional threading.Event; its wait is used so a stop request ends
            the current wait immediately.
        backend: auto, linux, windows or polling.
        on_backend: Optional callback invoked once with the active backend name.

    Returns:
        The number of events emitted.

    Raises:
        ValueError: When the interval, duration, callback, stop object or backend
            selector is not usable.
    """

    interval = _validate_interval(interval_s)
    duration = _validate_duration(duration_s)
    selector = _validate_backend(backend)
    if on_event is not None and not callable(on_event):
        raise ValueError("on_event must be callable or None")
    if on_backend is not None and not callable(on_backend):
        raise ValueError("on_backend must be callable or None")
    if stop is not None and not callable(getattr(stop, "is_set", None)):
        raise ValueError("stop must be a threading.Event or None")

    root_path = Path(root)
    if duration is not None and duration <= 0:
        return 0
    if stop is not None:
        try:
            if stop.is_set():
                return 0
        except (OSError, RuntimeError):
            pass

    implementation = create_backend(
        root_path, backend=selector, interval_s=interval
    )
    backend_name = implementation.name
    started = False
    fallback_reason = ""
    try:
        implementation.start()
        started = True
    except (OSError, RuntimeError) as exc:
        fallback_reason = type(exc).__name__ + ": " + str(exc)
    if not started:
        implementation = PollingBackend(
            root_path, interval_s=interval, reason="kernel backend failed: " + fallback_reason
        )
        try:
            implementation.start()
            started = True
        except (OSError, RuntimeError) as exc:
            # A polling backend that cannot even snapshot still runs: the loop
            # then reports nothing until the tree becomes readable.
            backend_name = POLLING_BACKEND_NAME
        backend_name = implementation.name
    if on_backend is not None:
        try:
            on_backend(backend_name)
        except (OSError, RuntimeError, ValueError, TypeError):
            pass

    watcher = CanaryWatcher(root_path, interval_ms=max(1, int(interval * 1000)))
    known_canaries: frozenset[str] = frozenset()
    try:
        watcher.snapshot()
        known_canaries = frozenset(
            path.relative_to(root_path).as_posix()
            for path in watcher.candidates()
            if path.is_file()
        )
    except (OSError, RuntimeError, ValueError):
        known_canaries = frozenset()

    deadline = None if duration is None else time.monotonic() + duration
    seen_entropy: set[tuple[str, str]] = set()
    burst = EntropyBurstTracker()
    dedupe: dict[tuple[str, str, str], float] = {}
    emitted = 0
    last_radar = float("-inf")

    try:
        while True:
            if stop is not None:
                try:
                    if stop.is_set():
                        break
                except (OSError, RuntimeError):
                    pass
            if deadline is not None and time.monotonic() >= deadline:
                break
            timeout = min(interval, _WAIT_SLICE_S)
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                timeout = min(timeout, remaining)
            try:
                implementation.wait(timeout)
            except (OSError, RuntimeError):
                time.sleep(timeout)
            try:
                changes = implementation.events()
            except (OSError, RuntimeError):
                changes = []

            touched: list[str] = []
            now = time.monotonic()
            for change in changes:
                if change.is_dir:
                    continue
                rel_path = change.rel_path
                key = (change.action, rel_path, "")
                previous = dedupe.get(key)
                if previous is not None and now - previous < _DEDUPE_WINDOW_S:
                    continue
                dedupe[key] = now
                if change.entropy >= _EVENT_ENTROPY_THRESHOLD:
                    entropy_key = (rel_path, format(float(change.entropy), ".2f"))
                    if entropy_key in seen_entropy:
                        continue
                    seen_entropy.add(entropy_key)
                    emitted += _emit(
                        WatchEvent(
                            ENTROPY_KIND,
                            rel_path,
                            change.action
                            + ": "
                            + format(float(change.entropy), ".2f")
                            + " bits per byte [backend="
                            + backend_name
                            + "]",
                            _utc_now(),
                        ),
                        on_event,
                    )
                    continue
                if _is_canary_rel(root_path, rel_path, known_canaries):
                    emitted += _emit(
                        WatchEvent(
                            CANARY_KIND,
                            rel_path,
                            change.action + " [backend=" + backend_name + "]",
                            _utc_now(),
                        ),
                        on_event,
                    )
                    touched.append(rel_path)
                    continue
                if change.action not in ("modified", "created"):
                    continue
                value = _quick_entropy(root_path, rel_path)
                if value is None or value < _EVENT_ENTROPY_THRESHOLD:
                    continue
                for burst_path, burst_value in burst.add(now, rel_path, value):
                    entropy_key = (burst_path, format(float(burst_value), ".2f"))
                    if entropy_key in seen_entropy:
                        continue
                    seen_entropy.add(entropy_key)
                    emitted += _emit(
                        WatchEvent(
                            ENTROPY_KIND,
                            burst_path,
                            "high entropy write burst: "
                            + format(float(burst_value), ".2f")
                            + " bits per byte [backend="
                            + backend_name
                            + "]",
                            _utc_now(),
                        ),
                        on_event,
                    )

            if freeze and touched:
                emitted += _freeze_writer(
                    root_path, sorted(set(touched)), on_event, backend_name
                )

            if now - last_radar >= interval:
                last_radar = now
                try:
                    report = scan_with_budget(
                        root_path,
                        max_files=WATCH_RADAR_MAX_FILES,
                        max_total_bytes=WATCH_RADAR_MAX_TOTAL_BYTES,
                    )
                except (OSError, ValueError):
                    report = None
                if report is not None:
                    for alert in report.alerts:
                        entropy_key = (alert.rel_path, format(float(alert.entropy), ".2f"))
                        if entropy_key in seen_entropy:
                            continue
                        seen_entropy.add(entropy_key)
                        emitted += _emit(
                            WatchEvent(
                                ENTROPY_KIND,
                                alert.rel_path,
                                alert.detail + " [backend=" + backend_name + "]",
                                _utc_now(),
                            ),
                            on_event,
                        )
    finally:
        try:
            implementation.stop()
        except (OSError, RuntimeError):
            pass
    return emitted
