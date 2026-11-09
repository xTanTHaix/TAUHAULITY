"""Win32 primitives reached through ctypes: TCP table, page pins, counter.

Everything here is deliberately hand bound instead of pulled from pywin32
because the project ships with zero runtime dependencies. Two platform traps
shape the implementation:

* GetExtendedTcpTable needs an explicit buffer and a size that is re-queried on
  every call, because the kernel table can grow between the size probe and the
  fetch. That race is normal on a busy machine, not an error.
* VirtualProtect and VirtualLock operate on whole pages. Calling them on an
  address that comes from a small Python allocation protects or pins pages that
  the allocator shares with unrelated objects. lock_pages is harmless in that
  case (it only affects residency) but protect_pages is documented as requiring
  a page aligned mapping owned by the caller.

The module imports cleanly on non-Windows hosts so that test collection and the
parity checks can inspect its structure without a Win32 kernel present; every
API entry point fails soft instead of raising.
"""

from __future__ import annotations

import ctypes
import os
import socket
import struct
from typing import Any, Final

from tauhaulity.primitives.loader import PortEntry, _buffer_region

DWORD = ctypes.c_uint32
ULONG = ctypes.c_uint32
BOOL = ctypes.c_int32
PVOID = ctypes.c_void_p
SIZE_T = ctypes.c_size_t

AF_INET: Final[int] = 2
AF_INET6: Final[int] = 23
TCP_TABLE_OWNER_PID_ALL: Final[int] = 5
ERROR_INSUFFICIENT_BUFFER: Final[int] = 122

#: Memory protection constants from WinNT.h.
PAGE_NOACCESS: Final[int] = 0x01
PAGE_READONLY: Final[int] = 0x02
PAGE_READWRITE: Final[int] = 0x04
PAGE_EXECUTE_READ: Final[int] = 0x20
PAGE_EXECUTE_READWRITE: Final[int] = 0x40

#: Portable aliases used by the engine probe on every platform.
PROT_READ: Final[int] = PAGE_READONLY
PROT_READ_WRITE: Final[int] = PAGE_READWRITE
PROT_EXECUTE: Final[int] = PAGE_EXECUTE_READ

#: Win32 reports a per-process dirty page count only for memory the calling
#: process allocated with MEM_WRITE_WATCH, so a pid argument cannot be honoured.
DIRTY_PAGES_STATUS: Final[str] = (
    "unsupported on Win32: GetWriteWatch only reports MEM_WRITE_WATCH memory "
    "of the calling process, not an arbitrary pid"
)

#: MIB_TCP_STATE values from Iprtrmib.h.
_STATE_NAMES: Final[dict[int, str]] = {
    1: "CLOSED",
    2: "LISTEN",
    3: "SYN_SENT",
    4: "SYN_RCVD",
    5: "ESTABLISHED",
    6: "FIN_WAIT1",
    7: "FIN_WAIT2",
    8: "CLOSE_WAIT",
    9: "CLOSING",
    10: "LAST_ACK",
    11: "TIME_WAIT",
    12: "DELETE_TCB",
}


class MIB_TCPROW_OWNER_PID(ctypes.Structure):
    """One IPv4 row of the owner-pid TCP table (24 bytes on every Win32 ABI)."""

    _fields_ = [
        ("dwState", DWORD),
        ("dwLocalAddr", DWORD),
        ("dwLocalPort", DWORD),
        ("dwRemoteAddr", DWORD),
        ("dwRemotePort", DWORD),
        ("dwOwningPid", DWORD),
    ]


class MIB_TCPTABLE_OWNER_PID(ctypes.Structure):
    """Header plus trailing row array; the array starts at offset 4."""

    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_TCPROW_OWNER_PID * 1),
    ]


class MIB_TCP6ROW_OWNER_PID(ctypes.Structure):
    """One IPv6 row of the owner-pid TCP table (56 bytes on every Win32 ABI)."""

    _fields_ = [
        ("ucLocalAddr", ctypes.c_ubyte * 16),
        ("dwLocalScopeId", DWORD),
        ("dwLocalPort", DWORD),
        ("ucRemoteAddr", ctypes.c_ubyte * 16),
        ("dwRemoteScopeId", DWORD),
        ("dwRemotePort", DWORD),
        ("dwState", DWORD),
        ("dwOwningPid", DWORD),
    ]


class MIB_TCP6TABLE_OWNER_PID(ctypes.Structure):
    """IPv6 table header plus trailing row array; the array starts at offset 4."""

    _fields_ = [
        ("dwNumEntries", DWORD),
        ("table", MIB_TCP6ROW_OWNER_PID * 1),
    ]


def _validate_layout() -> str:
    """Assert the ctypes layouts against the documented Win32 sizes.

    A silently padded structure would shift every field after the padding and
    produce plausible looking but wrong ports, addresses and pids. The check
    runs at import time but its failure is captured in _LAYOUT_ERROR instead of
    raised: importing the module must never crash a scan.

    Returns:
        Empty string when the layout is correct, otherwise the failure reason.
    """

    checks = (
        ("MIB_TCPROW_OWNER_PID", ctypes.sizeof(MIB_TCPROW_OWNER_PID), 24),
        ("MIB_TCPTABLE_OWNER_PID", ctypes.sizeof(MIB_TCPTABLE_OWNER_PID), 28),
        ("MIB_TCP6ROW_OWNER_PID", ctypes.sizeof(MIB_TCP6ROW_OWNER_PID), 56),
        ("MIB_TCP6TABLE_OWNER_PID", ctypes.sizeof(MIB_TCP6TABLE_OWNER_PID), 60),
        ("MIB_TCPTABLE_OWNER_PID.table offset", MIB_TCPTABLE_OWNER_PID.table.offset, 4),
        ("MIB_TCP6TABLE_OWNER_PID.table offset", MIB_TCP6TABLE_OWNER_PID.table.offset, 4),
    )
    for name, measured, expected in checks:
        if measured != expected:
            return f"{name} is {measured} bytes, expected {expected}"
    if ctypes.alignment(MIB_TCPROW_OWNER_PID) != 4 or ctypes.alignment(MIB_TCP6ROW_OWNER_PID) != 4:
        return "row structures must be 4 byte aligned"
    return ""


_LAYOUT_ERROR: Final[str] = _validate_layout()


def layout_error() -> str:
    """Return the structure layout failure, or an empty string when it is valid."""

    return _LAYOUT_ERROR


_KERNEL32: Any = None
_KERNEL32_ERROR: str = ""
_KERNEL32_ATTEMPTED: bool = False
_IPHLPAPI: Any = None
_IPHLPAPI_ERROR: str = ""
_IPHLPAPI_ATTEMPTED: bool = False


def _kernel32() -> Any:
    """Load and bind kernel32.dll once, returning None when it is unavailable."""

    global _KERNEL32, _KERNEL32_ERROR, _KERNEL32_ATTEMPTED
    if _KERNEL32_ATTEMPTED:
        return _KERNEL32
    _KERNEL32_ATTEMPTED = True
    if os.name != "nt":
        _KERNEL32_ERROR = "not running on Windows"
        return None
    try:
        lib = ctypes.WinDLL("kernel32", use_last_error=True)  # type: ignore[attr-defined]
        lib.VirtualLock.argtypes = [PVOID, SIZE_T]
        lib.VirtualLock.restype = BOOL
        lib.VirtualUnlock.argtypes = [PVOID, SIZE_T]
        lib.VirtualUnlock.restype = BOOL
        lib.VirtualProtect.argtypes = [PVOID, SIZE_T, DWORD, ctypes.POINTER(DWORD)]
        lib.VirtualProtect.restype = BOOL
        lib.QueryPerformanceCounter.argtypes = [ctypes.POINTER(ctypes.c_int64)]
        lib.QueryPerformanceCounter.restype = BOOL
    except (OSError, AttributeError) as exc:
        _KERNEL32_ERROR = f"{type(exc).__name__}: {exc}"
        return None
    _KERNEL32 = lib
    return lib


def _iphlpapi() -> Any:
    """Load and bind iphlpapi.dll once, returning None when it is unavailable."""

    global _IPHLPAPI, _IPHLPAPI_ERROR, _IPHLPAPI_ATTEMPTED
    if _IPHLPAPI_ATTEMPTED:
        return _IPHLPAPI
    _IPHLPAPI_ATTEMPTED = True
    if os.name != "nt":
        _IPHLPAPI_ERROR = "not running on Windows"
        return None
    try:
        lib = ctypes.WinDLL("iphlpapi", use_last_error=True)  # type: ignore[attr-defined]
        lib.GetExtendedTcpTable.argtypes = [
            PVOID,
            ctypes.POINTER(DWORD),
            BOOL,
            ULONG,
            ctypes.c_int,
            ULONG,
        ]
        lib.GetExtendedTcpTable.restype = DWORD
    except (OSError, AttributeError) as exc:
        _IPHLPAPI_ERROR = f"{type(exc).__name__}: {exc}"
        return None
    _IPHLPAPI = lib
    return lib


def capability_report() -> dict[str, str]:
    """Return the resolution status of every Win32 primitive as text.

    The doctor command uses this to explain a fallback without guessing, and the
    tests use it to assert the module degrades instead of raising off Windows.
    """

    kernel32 = _kernel32()
    iphlpapi = _iphlpapi()
    return {
        "kernel32": "available" if kernel32 is not None else (_KERNEL32_ERROR or "unavailable"),
        "iphlpapi": "available" if iphlpapi is not None else (_IPHLPAPI_ERROR or "unavailable"),
        "tcp_table": "available" if iphlpapi is not None and not _LAYOUT_ERROR else (_LAYOUT_ERROR or "unavailable"),
        "lock_pages": "available" if kernel32 is not None else "unavailable",
        "protect_pages": "available" if kernel32 is not None else "unavailable",
        "qpc": "available" if kernel32 is not None else "unavailable",
        "dirty_pages": DIRTY_PAGES_STATUS,
    }


def _query_table(family: int, row_type: Any, table_offset: int, decoder: Any) -> list[PortEntry]:
    """Fetch and decode one address family's TCP table.

    The size is queried first, then the buffer is allocated and the call is
    retried up to three times because rows can be added between the two calls.
    """

    lib = _iphlpapi()
    if lib is None or _LAYOUT_ERROR:
        return []
    size = DWORD(0)
    try:
        status = int(lib.GetExtendedTcpTable(None, ctypes.byref(size), False, family, TCP_TABLE_OWNER_PID_ALL, 0))
    except (OSError, AttributeError, ctypes.ArgumentError):
        return []
    if status not in (0, ERROR_INSUFFICIENT_BUFFER):
        return []
    buffer: Any = None
    for _attempt in range(3):
        buffer = ctypes.create_string_buffer(max(int(size.value), 4))
        try:
            status = int(
                lib.GetExtendedTcpTable(
                    buffer, ctypes.byref(size), False, family, TCP_TABLE_OWNER_PID_ALL, 0
                )
            )
        except (OSError, AttributeError, ctypes.ArgumentError):
            return []
        if status == 0:
            break
        if status != ERROR_INSUFFICIENT_BUFFER:
            return []
    if status != 0 or buffer is None:
        return []
    raw = buffer.raw
    if len(raw) < 4:
        return []
    declared = int(struct.unpack_from("<I", raw, 0)[0])
    row_size = ctypes.sizeof(row_type)
    available = max(0, (len(raw) - table_offset) // row_size)
    if declared > available:
        declared = available
    entries: list[PortEntry] = []
    for index in range(declared):
        try:
            row = row_type.from_buffer_copy(raw, table_offset + index * row_size)
        except (ValueError, TypeError):
            break
        entries.append(decoder(row))
    return entries


def _decode_ipv4(row: Any) -> PortEntry:
    """Convert one MIB_TCPROW_OWNER_PID into a PortEntry."""

    address = socket.inet_ntoa(struct.pack("<L", int(row.dwLocalAddr) & 0xFFFFFFFF))
    port = socket.ntohs(int(row.dwLocalPort) & 0xFFFF)
    pid = int(row.dwOwningPid)
    state = _STATE_NAMES.get(int(row.dwState), f"STATE_{int(row.dwState)}")
    return PortEntry("tcp", address, port, pid if pid > 0 else None, state)


def _decode_ipv6(row: Any) -> PortEntry:
    """Convert one MIB_TCP6ROW_OWNER_PID into a PortEntry.

    The scope id is dropped on purpose: PortEntry has no scope field and
    appending %scope to the address text would break the dossier formatter and
    the comparisons the port sweeper performs. Two link-local sockets on
    different interfaces therefore render identically, which is a documented
    limitation rather than an accident.
    """

    address = socket.inet_ntop(socket.AF_INET6, bytes(row.ucLocalAddr))
    port = socket.ntohs(int(row.dwLocalPort) & 0xFFFF)
    pid = int(row.dwOwningPid)
    state = _STATE_NAMES.get(int(row.dwState), f"STATE_{int(row.dwState)}")
    return PortEntry("tcp6", address, port, pid if pid > 0 else None, state)


def tcp_table() -> list[PortEntry]:
    """Return every IPv4 and IPv6 TCP row from the kernel owner-pid table.

    Returns:
        PortEntry records in kernel order, IPv4 first. Both tables are read in
        a single pass each; no external process is spawned.
    """

    if _LAYOUT_ERROR:
        return []
    entries = _query_table(AF_INET, MIB_TCPROW_OWNER_PID, MIB_TCPTABLE_OWNER_PID.table.offset, _decode_ipv4)
    entries.extend(
        _query_table(AF_INET6, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID.table.offset, _decode_ipv6)
    )
    return entries


def lock_pages(buffer: Any, size: int | None = None) -> bool:
    """Pin the pages backing buffer with VirtualLock.

    Returns:
        True when the kernel locked every page. False when the buffer is not
        usable or the process working set quota is exhausted; that is a normal
        unprivileged outcome.
    """

    region = _buffer_region(buffer, size)
    if region is None:
        return False
    lib = _kernel32()
    if lib is None:
        return False
    try:
        return bool(lib.VirtualLock(PVOID(region[0]), SIZE_T(region[1])))
    except (OSError, AttributeError, ctypes.ArgumentError):
        return False


def unlock_pages(buffer: Any, size: int | None = None) -> bool:
    """Release a pin taken by lock_pages with VirtualUnlock."""

    region = _buffer_region(buffer, size)
    if region is None:
        return False
    lib = _kernel32()
    if lib is None:
        return False
    try:
        return bool(lib.VirtualUnlock(PVOID(region[0]), SIZE_T(region[1])))
    except (OSError, AttributeError, ctypes.ArgumentError):
        return False


def protect_pages(buffer: Any, protection: int, size: int | None = None) -> bool:
    """Change the page protection of the region backing buffer.

    Only call this for a page aligned mapping that the caller owns (an mmap, a
    ctypes array allocated for this purpose). Protecting a page that came from a
    small Python allocation also protects whatever else the allocator placed on
    that page, and the interpreter will crash on the next write.

    Parameters:
        buffer: Writable buffer, ctypes object or raw address.
        protection: One of the PAGE_* constants.
        size: Optional explicit length when buffer is a raw address.

    Returns:
        True when VirtualProtect accepted the change.
    """

    region = _buffer_region(buffer, size)
    if region is None:
        return False
    lib = _kernel32()
    if lib is None:
        return False
    previous = DWORD(0)
    try:
        accepted = lib.VirtualProtect(
            PVOID(region[0]), SIZE_T(region[1]), DWORD(int(protection) & 0xFFFFFFFF), ctypes.byref(previous)
        )
        return bool(accepted)
    except (OSError, AttributeError, ctypes.ArgumentError, ValueError):
        return False


def qpc() -> int:
    """Return the QueryPerformanceCounter value in ticks.

    Raises:
        OSError: When kernel32 or the counter is unavailable. The engine treats
            that as a reason to fall back, not as a scan failure.
    """

    lib = _kernel32()
    if lib is None:
        raise OSError(_KERNEL32_ERROR or "kernel32 is unavailable")
    counter = ctypes.c_int64(0)
    try:
        accepted = lib.QueryPerformanceCounter(ctypes.byref(counter))
    except AttributeError as exc:
        raise OSError("QueryPerformanceCounter is unavailable") from exc
    if not accepted:
        raise OSError(ctypes.get_last_error(), "QueryPerformanceCounter failed")
    return int(counter.value)


def dirty_pages(pid: int) -> int:
    """Report that a per-pid dirty page count is not available on Win32.

    The only Win32 dirty page primitive is GetWriteWatch, which observes pages
    that the calling process allocated with MEM_WRITE_WATCH. There is no
    documented per-page dirty bit readable for an arbitrary process, so this
    function returns -1 rather than inventing a number.

    Returns:
        Always -1.
    """

    return -1
