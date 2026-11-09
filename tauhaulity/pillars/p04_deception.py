"""Pillar 4 - CHRONO-DECEPTION: in-memory PhantomFS and mirage capability.

The pillar has two jobs that must not be confused:

1. PhantomFS is a complete in-memory filesystem. It implements the file lifecycle
   (open, read, write, unlink, mkdir, listdir, stat) over plain dictionaries and a
   bytearray per file, with path normalization that accepts both separators. It
   never touches the real disk: a redirected deletion inside the mirage removes a
   dictionary entry, and that is the whole point of the deception layer.
2. MirageReadiness reports which kernel bifurcation primitive exists on this host.
   On Linux it reads /proc/self/ns/* and checks the unshare symbol plus the
   privilege needed to use it, but it never calls unshare during a scan because
   leaving a namespace transition half-applied would alter the scanner process.
   On Windows it asks for the Job Object exports and queries IsProcessInJob, which
   is read-only.

A capability report that lies is worse than no report: "DISABLED" always carries
the exact reason, and a kernel primitive that is only half reachable degrades the
status to WARNING instead of claiming READY.
"""

from __future__ import annotations

import ctypes
import os
import stat as stat_module
import time
from dataclasses import dataclass, field
from typing import Callable, Final, Iterable, Mapping

from tauhaulity.core.contracts import Finding, PillarSpec, ScanContext, SPEC_BY_KEY, make_finding

SPEC: PillarSpec = SPEC_BY_KEY["chrono_deception"]

_WINDOWS_JOB_EXPORTS: Final[tuple[str, ...]] = (
    "CreateJobObjectW",
    "AssignProcessToJobObject",
    "SetInformationJobObject",
    "QueryInformationJobObject",
    "IsProcessInJob",
)
_LINUX_NS_DIR: Final[str] = "/proc/self/ns"
_LINUX_UNSHARE_SYMBOL: Final[str] = "unshare"


class PhantomFSError(OSError):
    """Raised for PhantomFS path and mode violations."""


def normalize_path(path: str | os.PathLike[str], *, cwd: str = "/") -> str:
    """Return a canonical absolute POSIX style path for the mirage namespace.

    Both separators are accepted because the same mirage must behave identically
    for Windows style attacker paths and POSIX ones. Drive letters are mapped under
    /drive so a path such as C:\\Windows\\Temp cannot escape the in-memory root.

    Raises:
        PhantomFSError: When the path is empty, contains a NUL byte or is not a
            string or path-like value.
    """

    try:
        raw = os.fspath(path)
    except TypeError as exc:
        raise PhantomFSError("path must be a string or path-like object") from exc
    if isinstance(raw, bytes):
        try:
            text_value = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PhantomFSError("path bytes must be valid UTF-8") from exc
    else:
        text_value = str(raw)
    if "\x00" in text_value:
        raise PhantomFSError("path must not contain a NUL byte")
    text_value = text_value.strip().replace("\\", "/")
    if not text_value:
        raise PhantomFSError("path must not be empty")
    drive_prefix = ""
    if len(text_value) >= 2 and text_value[1] == ":" and text_value[0].isalpha():
        drive_prefix = "/drive/" + text_value[0].lower()
        text_value = text_value[2:]
    if not text_value.startswith("/"):
        base = cwd.replace("\\", "/")
        if not base.startswith("/"):
            base = "/" + base
        text_value = base.rstrip("/") + "/" + text_value
    parts: list[str] = []
    for part in text_value.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    canonical = "/" + "/".join(parts)
    if drive_prefix:
        canonical = drive_prefix + ("" if canonical == "/" else canonical)
    return canonical or "/"


@dataclass(slots=True)
class _Node:
    """One in-memory file or directory node."""

    kind: str
    data: bytearray = field(default_factory=bytearray)
    mode: int = 0o644
    inode: int = 0
    created_ns: int = 0
    modified_ns: int = 0


class PhantomFile:
    """File handle over a PhantomFS node with the usual text/binary semantics.

    The handle is intentionally small: it holds a position and delegates storage to
    the owning filesystem, so a redirected attacker sees normal file behaviour while
    nothing reaches the real disk.
    """

    def __init__(self, filesystem: "PhantomFS", path: str, mode: str) -> None:
        self._filesystem = filesystem
        self.path = path
        self.mode = mode
        self.closed = False
        self._binary = "b" in mode
        self._append = "a" in mode
        self._position = 0
        node = filesystem._node(path)
        if node is None:
            raise FileNotFoundError(path)
        if node.kind == "dir":
            raise IsADirectoryError(path)
        if self._append:
            self._position = len(node.data)
        self._node = node

    def __enter__(self) -> "PhantomFile":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def _ensure_open(self) -> None:
        if self.closed:
            raise ValueError("I/O operation on a closed mirage file")

    def read(self, size: int = -1) -> bytes | str:
        """Read from the current position, text or bytes depending on the mode."""

        self._ensure_open()
        if self.mode.startswith("w") or self.mode.startswith("a"):
            raise OSError("file not open for reading")
        data = bytes(self._node.data)
        if size is None or size < 0:
            chunk = data[self._position :]
            self._position = len(data)
        else:
            chunk = data[self._position : self._position + size]
            self._position += len(chunk)
        self._filesystem._reads += 1
        if self._binary:
            return chunk
        return chunk.decode("utf-8", "replace")

    def readline(self, size: int = -1) -> bytes | str:
        """Read up to and including the next newline."""

        self._ensure_open()
        data = bytes(self._node.data)
        start = self._position
        end = data.find(b"\n", start)
        if end < 0:
            end = len(data)
        else:
            end += 1
        if size is not None and size >= 0:
            end = min(end, start + size)
        chunk = data[start:end]
        self._position = end
        self._filesystem._reads += 1
        if self._binary:
            return chunk
        return chunk.decode("utf-8", "replace")

    def write(self, data: bytes | bytearray | memoryview | str) -> int:
        """Write at the current position and return the number of bytes stored."""

        self._ensure_open()
        if "r" in self.mode and "+" not in self.mode:
            raise OSError("file not open for writing")
        if isinstance(data, str):
            if self._binary:
                raise TypeError("binary mirage file does not accept str data")
            payload = data.encode("utf-8")
        else:
            if not self._binary:
                raise TypeError("text mirage file does not accept bytes data")
            try:
                payload = bytes(data)
            except (TypeError, ValueError) as exc:
                raise TypeError("write() expects bytes-like data") from exc
        material = self._node.data
        end = self._position + len(payload)
        if self._position > len(material):
            material.extend(bytes(self._position - len(material)))
        material[self._position : end] = payload
        self._position = end
        self._node.modified_ns = self._filesystem._now_ns()
        self._filesystem._writes += 1
        self._filesystem._bytes_written += len(payload)
        return len(payload)

    def writelines(self, lines: Iterable[bytes | str]) -> None:
        """Write an iterable of lines."""

        for line in lines:
            self.write(line)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        """Move the read/write position."""

        self._ensure_open()
        length = len(self._node.data)
        if whence == os.SEEK_SET:
            target = offset
        elif whence == os.SEEK_CUR:
            target = self._position + offset
        elif whence == os.SEEK_END:
            target = length + offset
        else:
            raise ValueError(f"unsupported whence {whence}")
        if target < 0:
            raise ValueError("negative seek position")
        self._position = target
        return self._position

    def tell(self) -> int:
        """Return the current position."""

        self._ensure_open()
        return self._position

    def flush(self) -> None:
        """No-op: PhantomFS stores writes immediately in memory."""

        self._ensure_open()

    def close(self) -> None:
        """Close the handle; later operations raise ValueError."""

        if not self.closed:
            self._node.modified_ns = self._filesystem._now_ns()
            self.closed = True

    def __iter__(self):
        return iter(self.readline, b"" if self._binary else "")

    @property
    def name(self) -> str:
        """Absolute mirage path this handle operates on."""

        return self.path


class PhantomFS:
    """In-memory virtual filesystem used to absorb attacker file operations.

    Invariants:
        * The root directory always exists and cannot be removed.
        * Every stored path is canonical because all entry points normalize first.
        * Directory nodes never hold bytes and file nodes always have a parent
          directory, so listdir/stat can answer without scanning the whole map.
    """

    def __init__(self, *, clock: Callable[[], int] | None = None, uid: int = 0, gid: int = 0) -> None:
        self._now_ns = clock or time.time_ns
        self._nodes: dict[str, _Node] = {}
        self._next_inode = 1
        self._uid = int(uid)
        self._gid = int(gid)
        self._reads = 0
        self._writes = 0
        self._bytes_written = 0
        self._mkdirs = 0
        self._unlinks = 0
        self._root = self._allocate("/", "dir", 0o755)

    def _allocate(self, path: str, kind: str, mode: int) -> _Node:
        node = _Node(kind=kind, mode=mode, inode=self._next_inode, created_ns=self._now_ns(), modified_ns=self._now_ns())
        self._next_inode += 1
        self._nodes[path] = node
        return node

    def _node(self, path: str) -> _Node | None:
        return self._nodes.get(path)

    def _parent(self, path: str) -> str:
        if path == "/":
            return "/"
        parent, _separator, _name = path.rpartition("/")
        return parent or "/"

    def _require_parent(self, path: str) -> None:
        parent = self._node(self._parent(path))
        if parent is None:
            raise FileNotFoundError(f"parent directory of {path} does not exist")
        if parent.kind != "dir":
            raise NotADirectoryError(f"parent of {path} is not a directory")

    def mkdir(self, path: str | os.PathLike[str], mode: int = 0o755, *, parents: bool = True) -> str:
        """Create a directory and return its canonical path.

        Raises:
            FileExistsError: When the path already exists.
            FileNotFoundError: When parents is False and the parent is missing.
        """

        canonical = normalize_path(path)
        if canonical == "/":
            raise FileExistsError("/")
        if canonical in self._nodes:
            raise FileExistsError(canonical)
        if parents:
            current = self._parent(canonical)
            missing: list[str] = []
            while current != "/" and current not in self._nodes:
                missing.append(current)
                current = self._parent(current)
            for directory in reversed(missing):
                self._allocate(directory, "dir", mode)
            self._mkdirs += len(missing)
        self._require_parent(canonical)
        self._allocate(canonical, "dir", mode)
        self._mkdirs += 1
        return canonical

    def rmdir(self, path: str | os.PathLike[str]) -> None:
        """Remove an empty directory."""

        canonical = normalize_path(path)
        node = self._node(canonical)
        if node is None:
            raise FileNotFoundError(canonical)
        if node.kind != "dir":
            raise NotADirectoryError(canonical)
        if canonical == "/":
            raise PermissionError("cannot remove the mirage root")
        if any(self._parent(child) == canonical for child in self._nodes if child != canonical):
            raise OSError(f"directory not empty: {canonical}")
        del self._nodes[canonical]

    def open(self, path: str | os.PathLike[str], mode: str = "r", *, encoding: str = "utf-8") -> PhantomFile:
        """Open a mirage file, creating it for write/append modes.

        Raises:
            FileNotFoundError: When reading a missing file or writing under a
                missing parent directory.
            IsADirectoryError: When the path is a directory.
            ValueError: When the mode is unsupported.
        """

        canonical = normalize_path(path)
        cleaned = mode.replace("t", "").replace("+", "")
        if cleaned not in {"r", "w", "a", "rb", "wb", "ab"}:
            raise ValueError(f"unsupported mirage mode {mode!r}")
        if "b" not in cleaned and encoding.lower() not in {"utf-8", "utf8"}:
            raise ValueError("PhantomFS text mode only supports UTF-8")
        node = self._node(canonical)
        if node is not None and node.kind == "dir":
            raise IsADirectoryError(canonical)
        if node is None:
            if cleaned.startswith("r"):
                raise FileNotFoundError(canonical)
            self._require_parent(canonical)
            node = self._allocate(canonical, "file", 0o644)
        if cleaned.startswith("w"):
            node.data = bytearray()
            node.modified_ns = self._now_ns()
        return PhantomFile(self, canonical, cleaned)

    def read_bytes(self, path: str | os.PathLike[str]) -> bytes:
        """Read a whole file as bytes."""

        with self.open(path, "rb") as handle:
            return handle.read()

    def read_text(self, path: str | os.PathLike[str]) -> str:
        """Read a whole file as UTF-8 text."""

        with self.open(path, "r") as handle:
            return handle.read()

    def write_bytes(self, path: str | os.PathLike[str], data: bytes) -> int:
        """Write a whole file as bytes and return the number of bytes stored."""

        with self.open(path, "wb") as handle:
            return handle.write(data)

    def write_text(self, path: str | os.PathLike[str], text: str) -> int:
        """Write a whole file as UTF-8 text and return the number of bytes stored."""

        with self.open(path, "w") as handle:
            return handle.write(text)

    def unlink(self, path: str | os.PathLike[str]) -> None:
        """Delete a mirage file, absorbing the deletion in memory.

        Raises:
            FileNotFoundError: When the file does not exist.
            IsADirectoryError: When the path is a directory.
        """

        canonical = normalize_path(path)
        node = self._node(canonical)
        if node is None:
            raise FileNotFoundError(canonical)
        if node.kind == "dir":
            raise IsADirectoryError(canonical)
        del self._nodes[canonical]
        self._unlinks += 1

    def listdir(self, path: str | os.PathLike[str] = "/") -> list[str]:
        """Return the sorted entry names of a directory."""

        canonical = normalize_path(path)
        node = self._node(canonical)
        if node is None:
            raise FileNotFoundError(canonical)
        if node.kind != "dir":
            raise NotADirectoryError(canonical)
        prefix = "/" if canonical == "/" else canonical + "/"
        names = {
            entry[len(prefix) :]
            for entry in self._nodes
            if entry != canonical and entry.startswith(prefix) and "/" not in entry[len(prefix) :]
        }
        return sorted(names)

    def stat(self, path: str | os.PathLike[str]) -> os.stat_result:
        """Return a real os.stat_result describing a mirage node."""

        canonical = normalize_path(path)
        node = self._node(canonical)
        if node is None:
            raise FileNotFoundError(canonical)
        type_bits = stat_module.S_IFDIR if node.kind == "dir" else stat_module.S_IFREG
        size = len(node.data)
        return os.stat_result(
            (
                type_bits | node.mode,
                node.inode,
                0,
                1,
                self._uid,
                self._gid,
                size,
                node.created_ns / 1_000_000_000,
                node.modified_ns / 1_000_000_000,
                node.created_ns / 1_000_000_000,
            )
        )

    def exists(self, path: str | os.PathLike[str]) -> bool:
        """True when the path resolves to a mirage node."""

        try:
            canonical = normalize_path(path)
        except PhantomFSError:
            return False
        return canonical in self._nodes

    def isdir(self, path: str | os.PathLike[str]) -> bool:
        """True when the path is a mirage directory."""

        try:
            canonical = normalize_path(path)
        except PhantomFSError:
            return False
        node = self._node(canonical)
        return node is not None and node.kind == "dir"

    def isfile(self, path: str | os.PathLike[str]) -> bool:
        """True when the path is a mirage file."""

        try:
            canonical = normalize_path(path)
        except PhantomFSError:
            return False
        node = self._node(canonical)
        return node is not None and node.kind == "file"

    def snapshot(self) -> dict[str, dict[str, object]]:
        """Return a serialisable view of every node for forensic cataloguing."""

        return {
            path: {
                "kind": node.kind,
                "size": len(node.data),
                "mode": node.mode,
                "inode": node.inode,
                "modified_ns": node.modified_ns,
            }
            for path, node in sorted(self._nodes.items())
        }

    def total_bytes(self) -> int:
        """Total bytes currently held in the mirage."""

        return sum(len(node.data) for node in self._nodes.values())

    def stats(self) -> dict[str, int]:
        """Operational counters used by the probe and by tests."""

        return {
            "nodes": len(self._nodes),
            "files": sum(1 for node in self._nodes.values() if node.kind == "file"),
            "directories": sum(1 for node in self._nodes.values() if node.kind == "dir"),
            "reads": self._reads,
            "writes": self._writes,
            "bytes_written": self._bytes_written,
            "mkdirs": self._mkdirs,
            "unlinks": self._unlinks,
            "total_bytes": self.total_bytes(),
        }


@dataclass(frozen=True, slots=True)
class MirageCapability:
    """Resolved deception capability of the current host.

    Attributes:
        platform: win32, linux or the raw platform name.
        namespaces: Namespace names visible under /proc/self/ns on Linux.
        namespace_view: True when the namespace view could be read.
        unshare_symbol: True when libc exposes unshare().
        unshare_usable: True when this process could actually call unshare().
        job_objects: True when the Windows Job Object API is fully exported.
        in_job: Result of IsProcessInJob, or None when not queried.
        phantomfs: True when PhantomFS passed its functional self-test.
        primitives: Names of the bifurcation primitives that are usable.
        detail: One line explanation for the dossier.
    """

    platform: str
    namespaces: tuple[str, ...]
    namespace_view: bool
    unshare_symbol: bool
    unshare_usable: bool
    job_objects: bool
    in_job: bool | None
    phantomfs: bool
    primitives: tuple[str, ...]
    detail: str

    @property
    def kernel_primitive(self) -> bool:
        """True when at least one kernel level bifurcation primitive is usable."""

        return self.namespace_view or self.unshare_usable or self.job_objects

    @property
    def partial(self) -> bool:
        """True when a kernel primitive exists but is not fully usable."""

        if self.platform == "linux":
            return (self.namespace_view or self.unshare_symbol) and not self.unshare_usable
        if self.platform == "win32":
            return not self.job_objects
        return True


class MirageCapabilityProbe:
    """Read the host bifurcation capability without applying a namespace change."""

    def probe(self, *, phantomfs: bool = True) -> MirageCapability:
        """Return the resolved capability for the current host."""

        platform_name = "win32" if os.name == "nt" else ("linux" if os.sys.platform.startswith("linux") else os.sys.platform)
        if os.name == "nt":
            return self._probe_windows(platform_name, phantomfs)
        if os.sys.platform.startswith("linux"):
            return self._probe_linux(platform_name, phantomfs)
        return MirageCapability(
            platform_name,
            (),
            False,
            False,
            False,
            False,
            None,
            phantomfs,
            ("phantomfs",) if phantomfs else (),
            f"no kernel bifurcation primitive on {platform_name}; phantomfs={phantomfs}",
        )

    def _probe_linux(self, platform_name: str, phantomfs: bool) -> MirageCapability:
        namespaces: tuple[str, ...] = ()
        namespace_view = False
        try:
            namespaces = tuple(sorted(os.listdir(_LINUX_NS_DIR)))
            namespace_view = bool(namespaces)
        except OSError:
            namespace_view = False
        unshare_symbol = False
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            unshare_symbol = hasattr(libc, _LINUX_UNSHARE_SYMBOL)
        except OSError:
            unshare_symbol = False
        privileged = getattr(os, "geteuid", lambda: 1)() == 0
        # Two kernel knobs decide whether an unprivileged unshare can succeed:
        # /proc/sys/user/max_user_namespaces (generic) and, on some distros,
        # /proc/sys/kernel/unprivileged_userns_clone. A missing knob is not proof
        # of permission, so it is only trusted when the generic limit is positive.
        userns_limit = _read_int("/proc/sys/user/max_user_namespaces")
        unprivileged_clone = _read_int("/proc/sys/kernel/unprivileged_userns_clone")
        if privileged:
            unshare_usable = unshare_symbol
        elif unprivileged_clone == 0:
            unshare_usable = False
        elif unprivileged_clone == 1:
            unshare_usable = unshare_symbol
        else:
            unshare_usable = unshare_symbol and bool(userns_limit and userns_limit > 0)
        primitives: list[str] = []
        if namespace_view:
            primitives.append("namespace-view")
        if unshare_usable:
            primitives.append("unshare")
        if phantomfs:
            primitives.append("phantomfs")
        detail = (
            f"namespace view={'yes' if namespace_view else 'no'} ({len(namespaces)} ns), "
            f"unshare={'usable' if unshare_usable else ('symbol-only' if unshare_symbol else 'missing')}, "
            f"euid={os.geteuid() if hasattr(os, 'geteuid') else 'n/a'}, "
            f"userns_limit={userns_limit if userns_limit is not None else 'unknown'}"
        )
        return MirageCapability(
            platform_name,
            namespaces,
            namespace_view,
            unshare_symbol,
            unshare_usable,
            False,
            None,
            phantomfs,
            tuple(primitives),
            detail,
        )

    def _probe_windows(self, platform_name: str, phantomfs: bool) -> MirageCapability:
        job_objects = False
        in_job: bool | None = None
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            job_objects = all(hasattr(kernel32, name) for name in _WINDOWS_JOB_EXPORTS)
            if job_objects:
                kernel32.GetCurrentProcess.restype = ctypes.c_void_p
                kernel32.IsProcessInJob.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.POINTER(ctypes.c_int),
                ]
                kernel32.IsProcessInJob.restype = ctypes.c_int
                flag = ctypes.c_int(0)
                if kernel32.IsProcessInJob(kernel32.GetCurrentProcess(), None, ctypes.byref(flag)):
                    in_job = bool(flag.value)
        except (OSError, AttributeError, ValueError):
            job_objects = False
        primitives: list[str] = []
        if job_objects:
            primitives.append("job-object")
        if phantomfs:
            primitives.append("phantomfs")
        detail = (
            f"job objects={'available' if job_objects else 'missing'}, "
            f"in_job={in_job if in_job is not None else 'unknown'}"
        )
        return MirageCapability(
            platform_name,
            (),
            False,
            False,
            False,
            job_objects,
            in_job,
            phantomfs,
            tuple(primitives),
            detail,
        )


def _read_int(path: str) -> int | None:
    """Read an integer from a procfs file, None when unavailable."""

    try:
        with open(path, "r", encoding="utf-8") as handle:
            return int(handle.read().strip())
    except (OSError, ValueError):
        return None


def _phantomfs_self_test() -> tuple[bool, str]:
    """Exercise the full PhantomFS lifecycle and return (healthy, reason)."""

    mirage = PhantomFS()
    try:
        mirage.mkdir("/mirage/payloads", mode=0o700)
        written = mirage.write_text("/mirage/payloads/note.txt", "captured payload\n")
        if written != len("captured payload\n"):
            return False, "write returned a wrong byte count"
        if mirage.read_text("/mirage/payloads/note.txt") != "captured payload\n":
            return False, "read back mismatch"
        if mirage.listdir("/mirage/payloads") != ["note.txt"]:
            return False, "listdir did not report the created file"
        info = mirage.stat("/mirage/payloads/note.txt")
        if not stat_module.S_ISREG(info.st_mode) or info.st_size != written:
            return False, "stat did not describe a regular file"
        mirage.unlink("/mirage/payloads/note.txt")
        if mirage.exists("/mirage/payloads/note.txt"):
            return False, "unlink did not remove the node"
        mirage.rmdir("/mirage/payloads")
        if mirage.exists("/mirage/payloads"):
            return False, "rmdir did not remove the directory"
        return True, "phantomfs lifecycle verified in memory"
    except (OSError, ValueError) as exc:
        return False, f"{type(exc).__name__}: {exc}"


def probe(ctx: ScanContext) -> Finding:
    """Report mirage readiness: PhantomFS lifecycle plus kernel bifurcation.

    WARNING is reserved for a genuinely partial capability: PhantomFS works but the
    kernel primitive that would make a real jail is only half reachable. A broken
    PhantomFS is DISABLED with the exact reason, because pretending the deception
    layer works would be the worst possible outcome.
    """

    healthy, reason = _phantomfs_self_test()
    capability = MirageCapabilityProbe().probe(phantomfs=healthy)

    if not healthy:
        status = "DISABLED"
        risk = 0.0
        detail = f"phantomfs unavailable: {reason}"
    elif capability.partial:
        status = "WARNING"
        risk = 2.0
        detail = f"partial mirage capability: {capability.detail}; phantomfs lifecycle verified"
    elif capability.primitives:
        status = "READY"
        risk = 0.0
        detail = (
            f"mirage ready: {', '.join(capability.primitives)}; {capability.detail}; "
            "phantomfs lifecycle verified in memory"
        )
    else:
        status = "DISABLED"
        risk = 0.0
        detail = f"no bifurcation primitive: {capability.detail}"

    mirage_summary = " | ".join(
        (
            f"phantomfs:{'ready' if healthy else 'disabled'}",
            "ns:" + (",".join(capability.namespaces) if capability.namespaces else "none"),
            f"primitives:{','.join(capability.primitives) if capability.primitives else 'none'}",
        )
    )
    return make_finding(
        SPEC,
        status,
        detail,
        risk=risk,
        slots={"mirage": mirage_summary, "detail": detail},
        repro_hint="Write, list and delete a file inside PhantomFS and confirm the host disk is untouched.",
    )
