"""Platform fingerprint used by every pillar and by the dossier header.

Pillars need to know whether they run on Windows, WSL Ubuntu or WSL Debian and
which kernel primitives are actually reachable before they promise a mechanism
in the report. Probing once and caching keeps the reported capabilities honest:
a capability is marked available only when the primitive could be resolved, not
because the platform is nominally supposed to have it.
"""

from __future__ import annotations

import functools
import os
import platform
import sys
import sysconfig
from dataclasses import dataclass
from typing import Mapping

_PROC_VERSION = "/proc/version"
_OS_RELEASE = "/etc/os-release"


def _read_text(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError:
        return ""


def _parse_os_release() -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in _read_text(_OS_RELEASE).splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        parsed[key.strip()] = value.strip().strip('"').strip("'")
    return parsed


def _ctypes_available() -> bool:
    try:
        import ctypes  # noqa: F401
    except (ImportError, OSError):
        return False
    return True


def _probe_mlock(os_family: str) -> bool:
    if not _ctypes_available():
        return False
    try:
        import ctypes

        if os_family == "windows":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            return hasattr(kernel32, "VirtualLock")
        libc = ctypes.CDLL(None, use_errno=True)
        return hasattr(libc, "mlock")
    except (OSError, AttributeError):
        return False


def _probe_seccomp() -> bool:
    for line in _read_text("/proc/self/status").splitlines():
        if line.startswith("Seccomp:"):
            return line.split(":", 1)[1].strip() not in {"", "0"}
    return False


def _probe_rust_engine() -> bool:
    try:
        from tauhaulity.primitives.loader import get_engine
    except ImportError:
        return False
    try:
        return bool(get_engine().available)
    except (OSError, RuntimeError, ImportError):
        return False


def _probe_privileged(os_family: str) -> bool:
    if os_family == "windows":
        if not _ctypes_available():
            return False
        try:
            import ctypes

            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (OSError, AttributeError):
            return False
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    try:
        return geteuid() == 0
    except OSError:
        return False


def _probe_primitives(os_family: str) -> dict[str, bool]:
    flags: dict[str, bool] = {
        "win32": os_family == "windows",
        "ctypes": _ctypes_available(),
        "mlock": _probe_mlock(os_family),
        "pagemap": os.path.exists("/proc/self/pagemap"),
        "procfs_net": os.path.exists("/proc/net/tcp"),
        "inotify": os_family == "linux",
        "ptrace": os_family == "linux",
        "seccomp": _probe_seccomp(),
        "pep578": hasattr(sys, "addaudithook"),
        "pep669": hasattr(sys, "monitoring"),
        "qpc": os_family == "windows",
        "rdtsc": _ctypes_available(),
        "rust_native": _probe_rust_engine(),
    }
    return flags


@dataclass(frozen=True, slots=True)
class PlatformInfo:
    """Immutable fingerprint of the running host and interpreter.

    Attributes:
        os_family: One of windows, linux or a raw sys.platform fallback.
        distro: Distribution identifier (ubuntu, debian) or windows.
        is_wsl: True when running under the Windows Subsystem for Linux.
        kernel: Kernel release string from the platform module.
        arch: Machine architecture reported by the platform module.
        python_version: Interpreter version as a dotted string.
        implementation: Interpreter implementation name.
        gil_enabled: False on a free-threaded build running without the GIL.
        free_threaded_build: True when the interpreter was compiled without the GIL.
        privileged: True when the process runs as root or elevated administrator.
        primitives: Resolved capability flags keyed by primitive name.
    """

    os_family: str
    distro: str
    is_wsl: bool
    kernel: str
    arch: str
    python_version: str
    implementation: str
    gil_enabled: bool
    free_threaded_build: bool
    privileged: bool
    primitives: Mapping[str, bool]

    def has(self, primitive: str) -> bool:
        """Return True when the named primitive resolved on this host."""

        return bool(self.primitives.get(primitive, False))

    @property
    def python_label(self) -> str:
        """Interpreter label used in the dossier header."""

        suffix = "t (free-threaded)" if self.free_threaded_build and not self.gil_enabled else ""
        if self.free_threaded_build and self.gil_enabled:
            suffix = "t (free-threaded build, GIL forced on)"
        return f"{self.implementation} {self.python_version}{suffix}"

    @property
    def os_label(self) -> str:
        """Operating system label used in the dossier header."""

        if self.os_family == "windows":
            return "Win32-Native"
        if self.is_wsl:
            return f"WSL2-{self.distro.title()}"
        if self.os_family == "linux":
            return f"Linux-{self.distro.title()}"
        return f"{self.os_family.title()}-Native"

    @property
    def hardware_label(self) -> str:
        """Comma separated list of resolved low level primitives."""

        names = sorted(name for name, enabled in self.primitives.items() if enabled)
        return ", ".join(names) if names else "none"

    @property
    def engine_tier(self) -> str:
        """Engine tier used by pillar ten and the dossier."""

        return "FULL_RUST_PY_SHIELD" if self.has("rust_native") else "CTYPES_OS_PRIMITIVE_FALLBACK"


@functools.lru_cache(maxsize=1)
def detect_platform() -> PlatformInfo:
    """Fingerprint the host once per process and cache the result.

    Returns:
        A PlatformInfo describing the OS, interpreter and resolved primitives.
    """

    os_family = "windows" if os.name == "nt" else ("linux" if sys.platform.startswith("linux") else sys.platform)
    kernel = platform.release()
    is_wsl = os_family == "linux" and "microsoft" in (_read_text(_PROC_VERSION) + kernel).lower()
    release_data = _parse_os_release() if os_family == "linux" else {}
    if os_family == "windows":
        distro = "windows"
    else:
        distro = (release_data.get("ID") or ("wsl" if is_wsl else "linux")).lower()
    free_threaded = sysconfig.get_config_var("Py_GIL_DISABLED")
    gil_enabled_flag = getattr(sys, "_is_gil_enabled", None)
    gil_enabled = bool(gil_enabled_flag()) if callable(gil_enabled_flag) else True
    return PlatformInfo(
        os_family=os_family,
        distro=distro,
        is_wsl=is_wsl,
        kernel=kernel,
        arch=platform.machine(),
        python_version=".".join(str(part) for part in sys.version_info[:3]),
        implementation=platform.python_implementation(),
        gil_enabled=gil_enabled,
        free_threaded_build=bool(free_threaded == 1 and not gil_enabled),
        privileged=_probe_privileged(os_family),
        primitives=_probe_primitives(os_family),
    )
