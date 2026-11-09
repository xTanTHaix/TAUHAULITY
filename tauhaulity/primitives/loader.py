"""Kernel and native primitives behind one cached engine handle.

Tauhaulity promises a full shield on a normal developer laptop and a graceful
fallback everywhere else, so every primitive is served by the fastest tier that
is actually available on the running host:

1. 'rust' - the tauhaulity_silicon_shield cdylib built from
   rust_silicon_shield/. SHA-256, CRC-64, Shannon entropy and the monotonic
   counter leave the interpreter entirely.
2. 'ctypes' - the same primitives from the standard library (hashlib, the
   shared 256 entry CRC table, the shared entropy LUT) plus direct OS calls
   through tauhaulity.primitives.win32 or tauhaulity.primitives.posix for page
   locking and the counter.
3. 'python' - pure Python only, selected by TAUHAULITY_NO_NATIVE=1 or on an
   exotic platform. Page locking reports failure instead of pretending.

The native library is never trusted blindly: at load time it must reproduce
hashlib.sha256, the Python CRC-64 table and the Python entropy value for a
handful of vectors. A stale or wrong-architecture build therefore degrades to
the ctypes tier instead of returning silently wrong digests into a dossier.

The engine contract is deliberately total: get_engine() never raises and never
returns None, and the lookup methods fall back per call, because a scan of an
untrusted project must not abort just because a platform primitive misbehaved.
"""

from __future__ import annotations

import ctypes
import hashlib
import mmap
import os
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from tauhaulity.core.entropy import shannon_entropy as _python_entropy
from tauhaulity.core.telemetry import crc64 as _python_crc64

#: Environment variable that forces the pure Python backend for testing.
DISABLE_NATIVE_ENV: Final[str] = "TAUHAULITY_NO_NATIVE"
#: Environment variable pointing at a specific native library file or directory.
LIBRARY_ENV: Final[str] = "TAUHAULITY_SILICON_SHIELD"
#: Older alias kept working so an existing shell profile does not silently
#: select a different backend after the rename.
LEGACY_LIBRARY_ENV: Final[str] = "TAUHAULITY_NATIVE_LIB"

_LIBRARY_STEM: Final[str] = "tauhaulity_silicon_shield"
_TRUTHY: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})
_SHA256_SIZE: Final[int] = 32
_VERSION_LIMIT: Final[int] = 64
_ENTROPY_TOLERANCE: Final[float] = 1e-9
_MASK64: Final[int] = 0xFFFFFFFFFFFFFFFF

#: Vectors the native library must reproduce before it is accepted.
_SHA_VECTORS: Final[tuple[bytes, ...]] = (
    b"",
    b"abc",
    bytes(range(256)),
    b"tauhaulity-silicon-shield",
    b"x" * 4096,
)
_CRC_VECTORS: Final[tuple[bytes, ...]] = (
    b"",
    b"123456789",
    bytes(range(64)),
    b"tauhaulity",
    b"y" * 1024,
)
_ENTROPY_VECTORS: Final[tuple[bytes, ...]] = (
    b"",
    b"abc",
    bytes(range(256)),
    bytes(range(256)) * 8,
)

_ENGINE_LOCK: Final[threading.Lock] = threading.Lock()


@dataclass(frozen=True, slots=True)
class PortEntry:
    """One row of the kernel TCP table.

    The record is deliberately immutable and backend neutral: the Windows
    MIB_TCPROW_OWNER_PID row and a Linux /proc/net/tcp line have almost nothing
    in common, so both normalise into this shape before the port sweeper pillar
    sees them.

    Attributes:
        protocol: 'tcp' for IPv4 rows, 'tcp6' for IPv6 rows.
        local_address: Dotted quad or compressed IPv6 text for the bound
            address. Unspecified addresses appear as 0.0.0.0 or ::.
        local_port: Bound port in host byte order.
        pid: Owning process id, or None when the kernel reports zero or the
            owner cannot be resolved (for example in a restricted container).
        state: Kernel state name such as LISTEN or ESTABLISHED.
    """

    protocol: str
    local_address: str
    local_port: int
    pid: int | None
    state: str

    @property
    def endpoint(self) -> str:
        """Return the address as host:port with IPv6 bracketed.

        A bare IPv6 address contains colons, so '::1:8080' would be ambiguous;
        bracketing keeps the rendering parseable by humans and by the dossier
        tooling.
        """

        if ":" in self.local_address:
            return f"[{self.local_address}]:{self.local_port}"
        return f"{self.local_address}:{self.local_port}"

    @property
    def is_listening(self) -> bool:
        """True when the row is a listening socket."""

        return self.state == "LISTEN"


class _NativeRejected(RuntimeError):
    """Internal signal that a candidate native library must not be used."""


def _as_bytes(data: Any) -> bytes:
    """Return a bytes copy of any buffer-protocol object.

    bytes is returned unchanged so the common case (a file read or a socket
    buffer) stays zero copy; every other buffer is materialised once.

    Raises:
        TypeError: When the object does not expose the buffer protocol. A str
            is rejected on purpose: silently re-encoding text would shift the
            byte offsets that the secret scanners report.
    """

    if isinstance(data, bytes):
        return data
    try:
        return bytes(memoryview(data))
    except TypeError as exc:
        raise TypeError(
            f"engine primitives expect a bytes-like object, got {type(data).__name__}"
        ) from exc


def _buffer_region(buffer: Any, size: int | None = None) -> tuple[int, int] | None:
    """Resolve a buffer or raw address into an (address, length) pair.

    The memory primitives accept three shapes because callers differ: pillars
    pass a bytearray or mmap they already own, the seqlock layer may pass a raw
    ctypes address, and a probe may pass an address plus an explicit length.
    Returning None instead of raising keeps the public lock_pages contract
    boolean: an unusable argument is a failed lock, not an exception during a
    scan.

    Read-only buffers are rejected because locking or protecting a copy would
    mislead the caller about which pages are actually pinned.
    """

    if isinstance(buffer, int) and not isinstance(buffer, bool):
        if buffer <= 0 or size is None or int(size) <= 0:
            return None
        return buffer, int(size)
    try:
        view = memoryview(buffer)
    except TypeError:
        try:
            address = int(ctypes.addressof(buffer))
            length = int(ctypes.sizeof(buffer))
        except (TypeError, AttributeError):
            return None
        if size is not None:
            length = int(size)
        if address <= 0 or length <= 0:
            return None
        return address, length
    if view.readonly or not view.contiguous or view.nbytes == 0:
        return None
    length = int(size) if size is not None else int(view.nbytes)
    if length <= 0 or length > view.nbytes:
        return None
    try:
        shared = (ctypes.c_char * view.nbytes).from_buffer(view)
    except (TypeError, ValueError):
        return None
    return int(ctypes.addressof(shared)), length


def _library_filenames() -> tuple[str, ...]:
    """Return the native library names expected on this platform.

    Only names for the running platform are considered: a Linux .so lying in a
    Windows checkout is a cross-compilation artifact, and attempting to load it
    would produce a confusing OSError instead of a clean 'not built here'
    degradation.
    """

    if os.name == "nt":
        return (f"{_LIBRARY_STEM}.dll",)
    if sys.platform == "darwin":
        return (f"lib{_LIBRARY_STEM}.dylib", f"{_LIBRARY_STEM}.dylib")
    return (f"lib{_LIBRARY_STEM}.so", f"{_LIBRARY_STEM}.so")


def _explicit_library_value() -> str:
    """Return the library override from the environment, if any."""

    for name in (LIBRARY_ENV, LEGACY_LIBRARY_ENV):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return ""


def _project_root() -> Path | None:
    """Return the checkout root when the package runs from source.

    loader.py lives at <root>/tauhaulity/primitives/loader.py while a wheel
    install lives at <site-packages>/tauhaulity/primitives/loader.py where
    parents[2] is not a source root. Checking that the candidate contains the
    crate manifest keeps the search honest instead of guessing.
    """

    candidates = [Path(__file__).resolve().parents[2], Path.cwd()]
    for candidate in candidates:
        try:
            if (candidate / "rust_silicon_shield" / "Cargo.toml").is_file():
                return candidate
        except OSError:
            continue
    return None


def _crate_target_directories(root: Path) -> list[Path]:
    """Return the crate output directories under one checkout root, best first.

    A plain host build writes its artifact to target/release, while a
    cross-compiled build writes to target/<triple>/release. The Windows host this
    project targets has no Visual Studio linker, so the cdylib is produced for
    x86_64-pc-windows-gnu and only the triple directory ever receives a DLL.
    Every triple directory that contains a release subdirectory is therefore
    enumerated instead of hard coding a target name, because the triple is host
    and toolchain specific; a wrong-architecture or corrupt library is rejected
    by the load-time verification and the search continues.

    Debug directories are last: they are stale far more often than release ones,
    and only the parity check makes them safe to trust.
    """

    target = root / "rust_silicon_shield" / "target"
    directories: list[Path] = [target / "release"]
    try:
        children = sorted(target.iterdir(), key=lambda entry: entry.name)
    except OSError:
        children = []
    for child in children:
        if child.name in {"release", "debug"}:
            continue
        try:
            if child.is_dir() and (child / "release").is_dir():
                directories.append(child / "release")
        except OSError:
            continue
    directories.append(target / "debug")
    return directories


def _candidate_directories() -> tuple[Path, ...]:
    """Return the directories searched for a native library, most preferred first."""

    directories: list[Path] = []
    root = _project_root()
    if root is not None:
        directories.extend(_crate_target_directories(root))
    directories.append(Path(__file__).resolve().parent / "_native")
    directories.extend(_crate_target_directories(Path.cwd()))
    return tuple(dict.fromkeys(directories))


def native_candidates() -> list[Path]:
    """Return every native library candidate for this platform, in load order.

    An explicit TAUHAULITY_SILICON_SHIELD value is authoritative: when the
    operator names a file or a directory, only that location is considered. A
    broken override therefore degrades to the platform tier and says so in the
    engine detail, instead of silently loading a different build from
    rust_silicon_shield/target and making the override look effective.

    Without an override the default build directories are searched first
    (target/release), then every cross-compilation output directory that exists
    (target/<triple>/release). The latter is what makes the native tier work on a
    Windows host without Visual Studio, where the only build that can be produced
    is x86_64-pc-windows-gnu.

    Exposed because the doctor command and the test suite must be able to say
    'the crate was not built here' without instantiating the engine.
    """

    explicit = _explicit_library_value()
    if explicit:
        target = Path(explicit).expanduser()
        if target.is_file():
            return [target]
        if target.is_dir():
            return [
                target / filename
                for filename in _library_filenames()
                if (target / filename).is_file()
            ]
        return []

    found: list[Path] = []
    for directory in _candidate_directories():
        for filename in _library_filenames():
            candidate = directory / filename
            try:
                if candidate.is_file():
                    found.append(candidate)
            except OSError:
                continue
    return list(dict.fromkeys(found))


def find_native_library() -> Path | None:
    """Return the first native library candidate, or None when absent."""

    candidates = native_candidates()
    return candidates[0] if candidates else None


def _configure_symbols(lib: Any) -> None:
    """Declare the C prototypes of every exported symbol.

    ctypes defaults to int for both arguments and return values, which silently
    truncates a 64 bit checksum or a 32 byte pointer on 64 bit hosts. Every
    prototype is therefore explicit.

    CDLL (cdecl) is used on Windows too instead of WinDLL: the Rust exports are
    extern "C", and using stdcall would only work by accident on x64 and corrupt
    the stack on 32 bit Windows.

    Raises:
        AttributeError: When the library is missing one of the symbols, which
            means the candidate is not the shield crate.
    """

    lib.tauhaulity_version.argtypes = []
    lib.tauhaulity_version.restype = ctypes.c_char_p
    lib.tauhaulity_crc64.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    lib.tauhaulity_crc64.restype = ctypes.c_uint64
    lib.tauhaulity_sha256.argtypes = [ctypes.c_char_p, ctypes.c_size_t, ctypes.c_void_p]
    lib.tauhaulity_sha256.restype = ctypes.c_int
    lib.tauhaulity_shannon.argtypes = [ctypes.c_char_p, ctypes.c_size_t]
    lib.tauhaulity_shannon.restype = ctypes.c_double
    lib.tauhaulity_qpc.argtypes = []
    lib.tauhaulity_qpc.restype = ctypes.c_uint64


def _load_library(path: Path) -> tuple[Any, str]:
    """Load and verify one candidate library.

    Returns:
        (library, version) when the candidate is the verified shield crate.

    Raises:
        _NativeRejected: When the file cannot be loaded, lacks an export or
            fails the cross-verification vectors.
    """

    try:
        lib = ctypes.CDLL(str(path))
    except (OSError, TypeError) as exc:
        raise _NativeRejected(f"{path.name}: load failed ({type(exc).__name__}: {exc})") from exc
    try:
        _configure_symbols(lib)
        raw_version = lib.tauhaulity_version()
        if not raw_version:
            raise _NativeRejected(f"{path.name}: version export returned NULL")
        version = raw_version.decode("ascii", "strict")
        if not version or len(version) > _VERSION_LIMIT or not version.isprintable():
            raise _NativeRejected(f"{path.name}: implausible version string {version!r}")
        _verify_parity(lib, path)
    except _NativeRejected:
        raise
    except Exception as exc:  # a foreign shared object can fail in arbitrary ways
        raise _NativeRejected(f"{path.name}: {type(exc).__name__}: {exc}") from exc
    return lib, version


def _verify_parity(lib: Any, path: Path) -> None:
    """Prove the native library matches the Python reference before trusting it.

    A shared library loaded by file name can be stale after a cargo clean or can
    belong to a different architecture build of the same project. The only cheap
    way to catch that is to compare against hashlib and the shared Python tables
    on a representative set of inputs.

    Raises:
        _NativeRejected: On the first mismatch.
    """

    out = ctypes.create_string_buffer(_SHA256_SIZE)
    for payload in _SHA_VECTORS:
        status = int(lib.tauhaulity_sha256(payload, len(payload), ctypes.cast(out, ctypes.c_void_p)))
        if status != 0:
            raise _NativeRejected(f"{path.name}: sha256 returned status {status}")
        if out.raw != hashlib.sha256(payload).digest():
            raise _NativeRejected(f"{path.name}: sha256 mismatch on a {len(payload)} byte vector")
    for payload in _CRC_VECTORS:
        measured = int(lib.tauhaulity_crc64(payload, len(payload))) & _MASK64
        if measured != int(_python_crc64(payload)) & _MASK64:
            raise _NativeRejected(f"{path.name}: crc64 mismatch on a {len(payload)} byte vector")
    for payload in _ENTROPY_VECTORS:
        measured = float(lib.tauhaulity_shannon(payload, len(payload)))
        expected = float(_python_entropy(payload))
        if measured != measured or abs(measured - expected) > _ENTROPY_TOLERANCE:
            raise _NativeRejected(
                f"{path.name}: entropy mismatch on a {len(payload)} byte vector "
                f"({measured!r} vs {expected!r})"
            )
    previous = int(lib.tauhaulity_qpc())
    for _ in range(32):
        current = int(lib.tauhaulity_qpc())
        if current < previous:
            raise _NativeRejected(f"{path.name}: performance counter is not monotonic")
        previous = current


class ShieldEngine:
    """Handle on the fastest usable primitive implementation.

    Attributes:
        available: True only when the verified Rust cdylib is backing this
            engine; the platform fingerprint uses it to choose the engine tier.
        backend: One of 'rust', 'ctypes' or 'python'.
        version: Native crate version, or a short tier label for fallbacks.
        detail: Human readable explanation of how the backend was chosen. The
            doctor command prints it, so it must never claim more than the
            process can actually do.
    """

    def __init__(self) -> None:
        self.available: bool = False
        self.backend: str = "python"
        self.version: str = "stdlib"
        self.detail: str = "engine not initialised"
        self._lib: Any = None
        self._lib_path: str = ""
        self._retired_libraries: list[Any] = []
        self._platform: Any = None
        self._platform_checked: bool = False
        self._use_os: bool = True
        self._closed: bool = False
        self._qpc_floor: int = 0
        self._lock: threading.Lock = threading.Lock()
        try:
            self._bootstrap()
        except Exception as exc:  # bootstrap may fail, it must never be fatal
            self._downgrade(f"bootstrap failed: {type(exc).__name__}: {exc}")

    # ------------------------------------------------------------------ setup

    def _bootstrap(self) -> None:
        """Select and verify the best backend available on this host."""

        if os.environ.get(DISABLE_NATIVE_ENV, "").strip().lower() in _TRUTHY:
            self._use_os = False
            self.backend = "python"
            self.version = "stdlib"
            self.available = False
            self.detail = f"{DISABLE_NATIVE_ENV} is set; pure Python primitives selected"
            return

        rejection = "no native library found for this platform"
        for candidate in native_candidates():
            try:
                lib, version = _load_library(candidate)
            except _NativeRejected as exc:
                rejection = str(exc)
                continue
            self._lib = lib
            self._lib_path = str(candidate)
            self.backend = "rust"
            self.available = True
            self.version = version
            self.detail = f"verified native cdylib {candidate.name} at {candidate}"
            return

        module = self._platform_module()
        if module is not None:
            self.backend = "ctypes"
            self.version = "os-primitives"
            self.available = False
            self.detail = f"{rejection}; ctypes OS primitives selected"
        else:
            self.backend = "python"
            self.version = "stdlib"
            self.available = False
            self.detail = f"{rejection}; pure Python primitives selected"

    def _platform_module(self) -> Any:
        """Return the platform ctypes module, or None on an unsupported host.

        The import is lazy so that a Windows process never imports the procfs
        parser and a Linux process never imports the iphlpapi structures.
        """

        if self._platform_checked:
            return self._platform
        self._platform_checked = True
        module: Any = None
        try:
            if os.name == "nt":
                from tauhaulity.primitives import win32 as module  # noqa: F401
            elif sys.platform.startswith("linux"):
                from tauhaulity.primitives import posix as module  # noqa: F401
        except (ImportError, OSError):
            module = None
        self._platform = module
        return module

    def _downgrade(self, reason: str) -> None:
        """Retire the native handle after a runtime failure and re-tier.

        A native call that fails once must not be retried forever: the handle is
        moved to _retired_libraries (never unloaded, because another thread may
        still be inside it) and every later call uses the fallback.
        """

        with self._lock:
            if self._lib is not None:
                self._retired_libraries.append(self._lib)
                self._lib = None
            self.available = False
            module = self._platform_module()
            if module is not None:
                self.backend = "ctypes"
                self.version = "os-primitives"
            else:
                self.backend = "python"
                self.version = "stdlib"
            self.detail = f"{self.detail} | downgraded: {reason}"

    def __enter__(self) -> "ShieldEngine":
        """Return self so the engine can be used as a context manager."""

        return self

    def __exit__(self, *_exc_info: object) -> None:
        """Close the engine when leaving a context manager block."""

        self.close()

    # ------------------------------------------------------------- primitives

    def sha256(self, data: bytes) -> bytes:
        """Return the SHA-256 digest of data, matching hashlib.sha256.

        Parameters:
            data: Bytes-like payload. bytes is used without a copy.

        Returns:
            Exactly 32 bytes.

        Raises:
            TypeError: When data does not support the buffer protocol.
        """

        payload = _as_bytes(data)
        # Measured on this project: hashlib (OpenSSL SIMD) sustains roughly
        # 1.9 GiB/s while the dependency free Rust implementation reaches about
        # 0.15 to 0.27 GiB/s on the same 4 MiB buffer. The native tier therefore
        # keeps the entropy, CRC and counter work, and the digest stays on the
        # standard library implementation. hashlib is not a third party
        # dependency, so this costs nothing in portability. The native sha256
        # export is still exercised at load time to prove the library is genuine.
        try:
            return hashlib.sha256(payload).digest()
        except (ValueError, TypeError):
            pass
        lib = self._lib
        if lib is not None:
            try:
                out = ctypes.create_string_buffer(_SHA256_SIZE)
                status = int(lib.tauhaulity_sha256(payload, len(payload), ctypes.cast(out, ctypes.c_void_p)))
                if status == 0:
                    return out.raw
                self._downgrade(f"native sha256 returned status {status}")
            except Exception as exc:  # foreign call failures are not all OSError
                self._downgrade(f"native sha256 failed: {type(exc).__name__}: {exc}")
        return hashlib.sha256(payload).digest()

    def crc64(self, data: bytes) -> int:
        """Return the reflected CRC-64 of data, matching the telemetry table.

        Parameters:
            data: Bytes-like payload.

        Returns:
            Unsigned 64 bit checksum.

        Raises:
            TypeError: When data does not support the buffer protocol.
        """

        payload = _as_bytes(data)
        lib = self._lib
        if lib is not None:
            try:
                return int(lib.tauhaulity_crc64(payload, len(payload))) & _MASK64
            except Exception as exc:
                self._downgrade(f"native crc64 failed: {type(exc).__name__}: {exc}")
        return int(_python_crc64(payload)) & _MASK64

    def shannon(self, data: bytes) -> float:
        """Return the Shannon entropy of data in bits per byte.

        The native result is range checked before it is returned: a corrupted
        library that produced NaN would otherwise poison every risk score in the
        dossier instead of triggering the fallback.

        Parameters:
            data: Bytes-like payload.

        Returns:
            Entropy between zero and eight.

        Raises:
            TypeError: When data does not support the buffer protocol.
        """

        payload = _as_bytes(data)
        lib = self._lib
        if lib is not None:
            try:
                value = float(lib.tauhaulity_shannon(payload, len(payload)))
                if value == value and 0.0 <= value <= 8.0:
                    return value
                self._downgrade(f"native shannon returned an impossible value {value!r}")
            except Exception as exc:
                self._downgrade(f"native shannon failed: {type(exc).__name__}: {exc}")
        return float(_python_entropy(payload))

    def qpc(self) -> int:
        """Return a monotonically non-decreasing counter value.

        The unit is platform specific (QPC ticks on Windows, nanoseconds on
        Linux); callers may only subtract two values taken from the same
        process. A monotonic floor guarantees the contract even when a tier
        switch mid-process would otherwise produce a smaller value.
        """

        value: int | None = None
        lib = self._lib
        if lib is not None:
            try:
                value = int(lib.tauhaulity_qpc())
            except Exception as exc:
                self._downgrade(f"native qpc failed: {type(exc).__name__}: {exc}")
        if value is None and self._use_os:
            module = self._platform_module()
            if module is not None:
                try:
                    value = int(module.qpc())
                except Exception:
                    value = None
        if value is None:
            value = time.perf_counter_ns()
        if value < self._qpc_floor:
            value = self._qpc_floor + 1
        self._qpc_floor = value
        return value

    # ------------------------------------------------------------- OS surface

    def port_table(self) -> list[PortEntry]:
        """Return the kernel TCP table as normalised port entries.

        Never spawns netstat, lsof or ss: a process spawn is an audited event
        and is usually blocked inside a security tool's own sandbox. Any kernel
        level failure degrades to an empty list.
        """

        try:
            from tauhaulity.primitives.port_table import collect_ports

            return collect_ports()
        except Exception:
            return []

    def lock_pages(self, buffer: Any, size: int | None = None) -> bool:
        """Pin the pages backing buffer in physical memory.

        Parameters:
            buffer: Writable buffer, ctypes object, or raw address.
            size: Optional explicit length when buffer is a raw address.

        Returns:
            True when the kernel locked every page. False is a normal outcome
            for unprivileged processes whose working set quota is exhausted, so
            the caller must treat it as a capability hint, not an error.
        """

        return self._run_page_call("lock_pages", buffer, size)

    def unlock_pages(self, buffer: Any, size: int | None = None) -> bool:
        """Release a pin taken by lock_pages.

        Returns:
            True when the kernel released every page.
        """

        return self._run_page_call("unlock_pages", buffer, size)

    def _run_page_call(self, name: str, buffer: Any, size: int | None) -> bool:
        """Invoke a platform page primitive defensively."""

        if not self._use_os:
            return False
        module = self._platform_module()
        if module is None:
            return False
        operation = getattr(module, name, None)
        if not callable(operation):
            return False
        try:
            if size is None:
                return bool(operation(buffer))
            return bool(operation(buffer, size))
        except (OSError, ValueError, TypeError, ctypes.ArgumentError):
            return False

    def dirty_pages(self, pid: int) -> int:
        """Count the pages currently marked soft-dirty for pid.

        Parameters:
            pid: Target process id. Zero or a negative value is normalised to
                the calling process.

        Returns:
            Number of pages whose soft-dirty bit is set, or -1 when the
            mechanism is unavailable on this platform or the kernel denies
            access (/proc/<pid>/pagemap needs CAP_SYS_ADMIN for other
            processes). The count is a snapshot: the kernel only clears the bits
            when a monitor writes 4 into clear_refs.
        """

        try:
            value = int(pid)
        except (TypeError, ValueError):
            return -1
        if value <= 0:
            value = os.getpid()
        if not self._use_os:
            return -1
        module = self._platform_module()
        if module is None:
            return -1
        try:
            measured = int(module.dirty_pages(value))
        except Exception:
            return -1
        return measured if measured >= 0 else -1

    def page_seal_status(self) -> dict[str, str]:
        """Probe the page sealing machinery and report every result as text.

        The dossier needs to state which memory protections are real on this
        host, so each primitive is exercised on an anonymous mmap that the
        engine owns. Using a private mapping matters: mprotect and
        VirtualProtect work on whole pages, and protecting a page that the
        allocator shares with unrelated Python objects would corrupt the
        interpreter. A dedicated mapping has no neighbours to damage.

        Returns:
            Mapping from capability name to a human readable status string.
        """

        module = None if not self._use_os else self._platform_module()
        status: dict[str, str] = {
            "backend": self.backend,
            "native_library": self._lib_path or "not loaded",
            "page_size": str(_page_size()),
            "qpc": "native" if self._lib is not None else ("ctypes" if module is not None else "stdlib"),
        }
        if module is None:
            status["lock_pages"] = "disabled (no OS primitive layer)"
            status["unlock_pages"] = "disabled (no OS primitive layer)"
            status["protect_pages"] = "disabled (no OS primitive layer)"
            status["dirty_pages"] = "disabled (no OS primitive layer)"
            return status

        page = _page_size()
        try:
            region = mmap.mmap(-1, page)
        except (OSError, ValueError) as exc:
            reason = f"unavailable (anonymous mapping failed: {type(exc).__name__})"
            status["lock_pages"] = reason
            status["unlock_pages"] = reason
            status["protect_pages"] = reason
            status["dirty_pages"] = self._dirty_status(module)
            return status
        try:
            locked = self.lock_pages(region)
            status["lock_pages"] = "available" if locked else "denied (kernel refused the page pin)"
            if locked:
                status["unlock_pages"] = (
                    "available" if self.unlock_pages(region) else "denied (kernel refused the unpin)"
                )
            else:
                status["unlock_pages"] = "not probed (lock failed first)"
            status["protect_pages"] = self._probe_protect(module, region)
        finally:
            try:
                region.close()
            except (OSError, ValueError):
                pass
        status["dirty_pages"] = self._dirty_status(module)
        return status

    def _probe_protect(self, module: Any, region: mmap.mmap) -> str:
        """Exercise mprotect/VirtualProtect on an engine owned mapping."""

        operation = getattr(module, "protect_pages", None)
        readonly = getattr(module, "PROT_READ", None)
        readwrite = getattr(module, "PROT_READ_WRITE", None)
        if not callable(operation) or readonly is None or readwrite is None:
            return "unsupported on this platform"
        try:
            if not operation(region, readonly):
                return "denied (read-only transition failed)"
            if not operation(region, readwrite):
                return "degraded (read-only transition worked, restore failed)"
            return "available"
        except (OSError, ValueError, TypeError):
            return "error while probing the protection primitive"

    def _dirty_status(self, module: Any) -> str:
        """Return the dirty page capability description for the platform module."""

        return str(getattr(module, "DIRTY_PAGES_STATUS", "unknown"))

    def close(self) -> None:
        """Retire the native handle.

        The ctypes handle is not unloaded: another thread may still be inside
        the library, and FreeLibrary underneath it would crash the process.
        Keeping the reference alive until interpreter shutdown is the safe trade.
        The engine stays usable afterwards on the fallback tier.
        """

        with self._lock:
            self._closed = True
            if self._lib is not None:
                self._retired_libraries.append(self._lib)
                self._lib = None
            self.available = False
            module = self._platform_module()
            if module is not None:
                self.backend = "ctypes"
                self.version = "os-primitives"
            else:
                self.backend = "python"
                self.version = "stdlib"
            if "engine closed" not in self.detail:
                self.detail = f"{self.detail} | engine closed, native handle retired"

    @property
    def closed(self) -> bool:
        """True once close() has retired the native handle."""

        return self._closed


def _page_size() -> int:
    """Return the OS page size without touching ctypes."""

    try:
        return int(mmap.PAGESIZE)
    except (AttributeError, ValueError):
        return 4096


_ENGINE: ShieldEngine | None = None


def _emergency_engine(exc: BaseException) -> ShieldEngine:
    """Build a usable engine when construction itself failed.

    ShieldEngine.__init__ already swallows bootstrap errors, so this path only
    triggers for something like a broken dynamic loader. The contract (never
    raises, never None) still has to hold, so the object is assembled field by
    field on the pure Python tier.
    """

    engine = ShieldEngine.__new__(ShieldEngine)
    engine.available = False
    engine.backend = "python"
    engine.version = "stdlib"
    engine.detail = f"engine construction failed: {type(exc).__name__}: {exc}"
    engine._lib = None
    engine._lib_path = ""
    engine._retired_libraries = []
    engine._platform = None
    engine._platform_checked = True
    engine._use_os = False
    engine._closed = True
    engine._qpc_floor = 0
    engine._lock = threading.Lock()
    return engine


def get_engine() -> ShieldEngine:
    """Return the process wide engine, creating and caching it on first use.

    The singleton is what makes the engine cheap enough to reference from every
    pillar: the native library is loaded and verified once, and the platform
    modules are imported once.

    Returns:
        The cached ShieldEngine. Never None and never raised through, because a
        broken optional primitive must not take down a scan.
    """

    global _ENGINE
    engine = _ENGINE
    if engine is not None:
        return engine
    with _ENGINE_LOCK:
        if _ENGINE is None:
            try:
                _ENGINE = ShieldEngine()
            except Exception as exc:
                _ENGINE = _emergency_engine(exc)
        return _ENGINE


def _reset_engine() -> None:
    """Drop the cached engine so the next get_engine rebuilds it.

    Test support only: the tier decision depends on environment variables and on
    files on disk, and the suite has to be able to observe a forced fallback
    without spawning a second interpreter.
    """

    global _ENGINE
    with _ENGINE_LOCK:
        engine = _ENGINE
        _ENGINE = None
    if engine is not None:
        try:
            engine.close()
        except Exception:
            pass
