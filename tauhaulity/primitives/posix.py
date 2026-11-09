"""POSIX/Linux primitives: procfs TCP tables, page pins, pagemap soft-dirty.

The Linux tier never shells out to netstat, lsof or ss. It reads the kernel
socket tables directly from /proc/net/tcp and /proc/net/tcp6, then resolves the
owning pid by inode through /proc/<pid>/fd. That keeps the port sweeper usable
inside a sandbox where process creation is audited or blocked.

Three platform traps are handled explicitly:

* /proc/net/tcp prints IPv4 addresses as four little-endian bytes and IPv6
  addresses as four little-endian 32 bit words, so both need a per-word byte
  reversal before inet_ntoa/inet_ntop.
* mlock and mprotect work on whole pages; mprotect on a page that the Python
  allocator shares with unrelated objects crashes the interpreter, so
  protect_pages is documented for caller owned mappings only and the engine
  probes it on a private anonymous mapping.
* /proc/<pid>/pagemap exposes the soft-dirty bit (bit 55) only where the kernel
  permits access, which for another process usually means CAP_SYS_ADMIN. When
  access is denied the function reports -1 instead of a fabricated count.

The module imports cleanly on Windows so the parity checks can inspect it;
every API entry point fails soft instead of raising.
"""

from __future__ import annotations

import ctypes
import mmap
import os
import socket
import sys
import time
from typing import Any, Callable, Final

from tauhaulity.primitives.loader import PortEntry, _buffer_region

PROC_NET_TCP: Final[str] = "/proc/net/tcp"
PROC_NET_TCP6: Final[str] = "/proc/net/tcp6"
PROC_ROOT: Final[str] = "/proc"

#: Portable memory protection bits from sys/mman.h.
PROT_NONE: Final[int] = 0
PROT_READ: Final[int] = 1
PROT_WRITE: Final[int] = 2
PROT_EXEC: Final[int] = 4
PROT_READ_WRITE: Final[int] = PROT_READ | PROT_WRITE

#: The soft-dirty bit in a pagemap entry, see Documentation/admin-guide/mm/pagemap.
SOFT_DIRTY_BIT: Final[int] = 55

#: Page cap for one dirty_pages call. A pathological mapping list would
#: otherwise read gigabytes of pagemap; the cap is documented so a truncated
#: count is never mistaken for a complete one.
MAX_DIRTY_PAGES: Final[int] = 8_000_000

#: File descriptor read budget for the inode to pid resolution. A host with
#: hundreds of processes can otherwise turn one port table read into a
#: multi-hundred millisecond /proc walk.
MAX_FD_SCAN: Final[int] = 200_000

#: /proc/net/tcp* state codes (kernel enum, hexadecimal in the table).
_TCP_STATES: Final[dict[int, str]] = {
    0x01: "ESTABLISHED",
    0x02: "SYN_SENT",
    0x03: "SYN_RECV",
    0x04: "FIN_WAIT1",
    0x05: "FIN_WAIT2",
    0x06: "TIME_WAIT",
    0x07: "CLOSE",
    0x08: "CLOSE_WAIT",
    0x09: "LAST_ACK",
    0x0A: "LISTEN",
    0x0B: "CLOSING",
    0x0C: "NEW_SYN_RECV",
}

#: Human readable capability line consumed by the engine page seal status.
DIRTY_PAGES_STATUS: Final[str] = (
    "soft-dirty bit 55 of /proc/<pid>/pagemap "
    "(other processes require CAP_SYS_ADMIN; count is a snapshot)"
)


class _Timespec(ctypes.Structure):
    """struct timespec for the 64 bit Linux ABI (time_t and long are 8 bytes)."""

    _fields_ = [("tv_sec", ctypes.c_int64), ("tv_nsec", ctypes.c_int64)]


def _validate_timespec() -> str:
    """Return an empty string when the timespec layout is the 64 bit Linux one."""

    if ctypes.sizeof(_Timespec) != 16:
        return f"timespec is {ctypes.sizeof(_Timespec)} bytes, expected 16"
    if ctypes.alignment(_Timespec) != 8:
        return "timespec must be 8 byte aligned"
    return ""


_TIMESPEC_ERROR: Final[str] = _validate_timespec()
_CLOCK_MONOTONIC: Final[int] = 1

_LIBC: Any = None
_LIBC_ERROR: str = ""
_LIBC_ATTEMPTED: bool = False


def _page_size() -> int:
    """Return the system page size, preferring the POSIX query."""

    try:
        return int(os.sysconf("SC_PAGE_SIZE"))
    except (AttributeError, ValueError, OSError):
        try:
            return int(mmap.PAGESIZE)
        except (AttributeError, ValueError):
            return 4096


def _libc() -> Any:
    """Load the C library once and bind mlock, munlock, mprotect and clock_gettime."""

    global _LIBC, _LIBC_ERROR, _LIBC_ATTEMPTED
    if _LIBC_ATTEMPTED:
        return _LIBC
    _LIBC_ATTEMPTED = True
    if not sys.platform.startswith("linux"):
        _LIBC_ERROR = "not running on Linux"
        return None
    try:
        lib = ctypes.CDLL(None, use_errno=True)
        lib.mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        lib.mlock.restype = ctypes.c_int
        lib.munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        lib.munlock.restype = ctypes.c_int
        lib.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
        lib.mprotect.restype = ctypes.c_int
        if not _TIMESPEC_ERROR and sys.maxsize > 2**32:
            lib.clock_gettime.argtypes = [ctypes.c_int, ctypes.POINTER(_Timespec)]
            lib.clock_gettime.restype = ctypes.c_int
        else:
            lib.clock_gettime = None
    except (OSError, AttributeError) as exc:
        _LIBC_ERROR = f"{type(exc).__name__}: {exc}"
        return None
    _LIBC = lib
    return lib


def capability_report() -> dict[str, str]:
    """Return the resolution status of every POSIX primitive as text."""

    lib = _libc()
    return {
        "libc": "available" if lib is not None else (_LIBC_ERROR or "unavailable"),
        "procfs_tcp": "available" if os.path.exists(PROC_NET_TCP) else "unavailable",
        "lock_pages": "available" if lib is not None else "unavailable",
        "protect_pages": "available" if lib is not None else "unavailable",
        "qpc": "available" if lib is not None or hasattr(time, "clock_gettime_ns") else "unavailable",
        "dirty_pages": "available" if os.path.exists(f"{PROC_ROOT}/self/pagemap") else DIRTY_PAGES_STATUS,
    }


def _decode_ipv4_address(text: str) -> str:
    """Decode the /proc/net/tcp IPv4 representation into dotted quad text.

    The kernel prints the address in network byte order, which on a little
    endian host means the printed hex bytes are already in memory order. Reading
    them as int.from_bytes and re-ordering would double reverse the address; a
    straight reversal of the four bytes is correct.

    Raises:
        ValueError: When the field is not a four byte address.
    """

    raw = bytes.fromhex(text)
    if len(raw) != 4:
        raise ValueError(f"IPv4 address field must be 4 bytes, got {len(raw)}")
    return socket.inet_ntoa(raw[::-1])


def _decode_ipv6_address(text: str) -> str:
    """Decode the /proc/net/tcp6 representation into compressed IPv6 text.

    Each of the four 32 bit words is printed in host byte order, so every word
    needs its own reversal. Reversing the whole 16 byte field instead produces
    a syntactically valid but completely wrong address.

    Raises:
        ValueError: When the field is not a sixteen byte address.
    """

    raw = bytes.fromhex(text)
    if len(raw) != 16:
        raise ValueError(f"IPv6 address field must be 16 bytes, got {len(raw)}")
    reordered = b"".join(raw[index : index + 4][::-1] for index in range(0, 16, 4))
    return socket.inet_ntop(socket.AF_INET6, reordered)


def parse_tcp_rows(text: str, protocol: str, *, ipv6: bool = False) -> list[tuple[str, str, int, str, str]]:
    """Parse one /proc/net/tcp or /proc/net/tcp6 table body.

    The parser is separated from the file read so it can be exercised on any
    host with synthetic kernel output, including Windows, which is where the
    main test suite runs.

    Parameters:
        text: Complete file contents, including the header line.
        protocol: Backend label stored in the PortEntry ('tcp' or 'tcp6').
        ipv6: Select the IPv6 address decoder.

    Returns:
        Tuples of (protocol, address, port, state, inode). The inode is an empty
        string when the row does not carry one.
    """

    decoder: Callable[[str], str] = _decode_ipv6_address if ipv6 else _decode_ipv4_address
    rows: list[tuple[str, str, int, str, str]] = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10 or not fields[0].endswith(":"):
            continue
        try:
            address_text, port_text = fields[1].rsplit(":", 1)
            address = decoder(address_text)
            port = int(port_text, 16)
            state_code = int(fields[3], 16)
        except (ValueError, IndexError):
            continue
        if not 0 < port <= 65535:
            continue
        state = _TCP_STATES.get(state_code, f"STATE_{state_code:02X}")
        inode = fields[9] if fields[9].isdigit() else ""
        rows.append((protocol, address, port, state, inode))
    return rows


def _read_table(path: str, protocol: str, *, ipv6: bool) -> list[tuple[str, str, int, str, str]]:
    """Read and parse a procfs TCP table, returning no rows on any OS error."""

    try:
        with open(path, "r", encoding="ascii", errors="replace") as handle:
            return parse_tcp_rows(handle.read(), protocol, ipv6=ipv6)
    except OSError:
        return []


def _socket_owners(wanted: set[str]) -> dict[str, int]:
    """Map socket inodes to owning pids by scanning /proc/<pid>/fd.

    The calling process is scanned first because that is the common case for a
    diagnostic tool inspecting its own test sockets, and because /proc/self/fd is
    always readable even inside a restricted container. Other processes can
    vanish mid-scan (their /proc entry disappears), which is expected and
    skipped rather than logged.
    """

    owners: dict[str, int] = {}
    if not wanted:
        return owners
    try:
        pid_names = [name for name in os.listdir(PROC_ROOT) if name.isdigit()]
    except OSError:
        return owners
    own = str(os.getpid())
    pid_names.sort(key=lambda name: (name != own, int(name)))
    budget = MAX_FD_SCAN
    for pid_name in pid_names:
        if len(owners) >= len(wanted) or budget <= 0:
            break
        descriptor_dir = os.path.join(PROC_ROOT, pid_name, "fd")
        try:
            descriptors = os.listdir(descriptor_dir)
        except OSError:
            continue
        for descriptor in descriptors:
            if budget <= 0:
                break
            budget -= 1
            try:
                target = os.readlink(os.path.join(descriptor_dir, descriptor))
            except OSError:
                continue
            if not target.startswith("socket:["):
                continue
            inode = target[8:-1]
            if inode in wanted and inode not in owners:
                owners[inode] = int(pid_name)
        if len(owners) >= len(wanted):
            break
    return owners


def tcp_table() -> list[PortEntry]:
    """Return every IPv4 and IPv6 TCP row from the procfs kernel tables.

    Returns:
        PortEntry records with pid attribution where /proc allowed it and None
        where the owning process could not be resolved.
    """

    rows = _read_table(PROC_NET_TCP, "tcp", ipv6=False)
    rows.extend(_read_table(PROC_NET_TCP6, "tcp6", ipv6=True))
    if not rows:
        return []
    wanted = {row[4] for row in rows if row[4] and row[4] != "0"}
    owners = _socket_owners(wanted)
    entries: list[PortEntry] = []
    for protocol, address, port, state, inode in rows:
        pid = owners.get(inode) if inode else None
        entries.append(PortEntry(protocol, address, port, pid, state))
    return entries


def lock_pages(buffer: Any, size: int | None = None) -> bool:
    """Pin the pages backing buffer with mlock.

    Returns:
        True when mlock accepted the range. False when the process is not
        privileged enough or RLIMIT_MEMLOCK is exhausted, which is a normal
        outcome on a default Linux desktop.
    """

    region = _buffer_region(buffer, size)
    if region is None:
        return False
    lib = _libc()
    if lib is None:
        return False
    try:
        return int(lib.mlock(ctypes.c_void_p(region[0]), ctypes.c_size_t(region[1]))) == 0
    except (OSError, AttributeError, ctypes.ArgumentError):
        return False


def unlock_pages(buffer: Any, size: int | None = None) -> bool:
    """Release a pin taken by lock_pages with munlock."""

    region = _buffer_region(buffer, size)
    if region is None:
        return False
    lib = _libc()
    if lib is None:
        return False
    try:
        return int(lib.munlock(ctypes.c_void_p(region[0]), ctypes.c_size_t(region[1]))) == 0
    except (OSError, AttributeError, ctypes.ArgumentError):
        return False


def protect_pages(buffer: Any, protection: int, size: int | None = None) -> bool:
    """Change the page protection of a caller owned memory mapping.

    mprotect requires a page aligned start address, so the range is expanded
    outwards to page boundaries. Expand outwards, never inwards: shrinking the
    protected range would leave part of the buffer writable while the caller
    believes it is sealed.

    Only pass a mapping the caller owns (mmap, ctypes array). Protecting a page
    from a small Python allocation also protects every object the allocator
    placed on that page.

    Parameters:
        buffer: Writable buffer, ctypes object or raw address.
        protection: Bit mask of PROT_READ, PROT_WRITE, PROT_EXEC.
        size: Optional explicit length when buffer is a raw address.

    Returns:
        True when mprotect accepted the change.
    """

    region = _buffer_region(buffer, size)
    if region is None:
        return False
    lib = _libc()
    if lib is None:
        return False
    page = _page_size()
    if page <= 0:
        return False
    address, length = region
    start = address - (address % page)
    end = ((address + length + page - 1) // page) * page
    if end <= start:
        return False
    try:
        accepted = int(lib.mprotect(ctypes.c_void_p(start), ctypes.c_size_t(end - start), ctypes.c_int(int(protection))))
        return accepted == 0
    except (OSError, AttributeError, ctypes.ArgumentError, ValueError):
        return False


def qpc() -> int:
    """Return a monotonic nanosecond timestamp.

    time.clock_gettime_ns is preferred because it is a thin, well tested wrapper
    around clock_gettime; the ctypes call is the fallback for a stripped
    interpreter and is only attempted on a 64 bit build where the timespec layout
    is known.

    Raises:
        OSError: Never; the final fallback is time.perf_counter_ns.
    """

    clock_ns = getattr(time, "clock_gettime_ns", None)
    clock_id = getattr(time, "CLOCK_MONOTONIC", None)
    if callable(clock_ns) and clock_id is not None:
        try:
            return int(clock_ns(clock_id))
        except (OSError, ValueError):
            pass
    lib = _libc()
    if lib is not None and getattr(lib, "clock_gettime", None) is not None:
        try:
            stamp = _Timespec()
            if int(lib.clock_gettime(_CLOCK_MONOTONIC, ctypes.byref(stamp))) == 0:
                if stamp.tv_sec >= 0 and 0 <= stamp.tv_nsec < 1_000_000_000:
                    return int(stamp.tv_sec) * 1_000_000_000 + int(stamp.tv_nsec)
        except (OSError, AttributeError, ctypes.ArgumentError):
            pass
    return int(time.perf_counter_ns())


def dirty_pages(pid: int) -> int:
    """Count pages whose soft-dirty bit is set for one process.

    The soft-dirty bit is the kernel's own write tracking: it is set when a page
    is written and cleared only when a monitor writes 4 into /proc/<pid>/clear_refs.
    This function never clears the bits, because doing so would break any other
    monitor in the system and requires write access to the target's procfs.

    Parameters:
        pid: Target process id; zero or negative means the calling process.

    Returns:
        Number of present pages with bit 55 set, or -1 when pagemap or maps
        cannot be read. The count is capped at MAX_DIRTY_PAGES and is therefore
        a lower bound for a process with an extremely large address space.
    """

    if not sys.platform.startswith("linux"):
        return -1
    try:
        value = int(pid)
    except (TypeError, ValueError):
        return -1
    if value <= 0:
        value = os.getpid()
    page = _page_size()
    if page <= 0:
        return -1
    maps_path = f"{PROC_ROOT}/{value}/maps"
    pagemap_path = f"{PROC_ROOT}/{value}/pagemap"
    try:
        maps_handle = open(maps_path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return -1
    try:
        pagemap_handle = open(pagemap_path, "rb")
    except OSError:
        maps_handle.close()
        return -1
    total = 0
    try:
        with maps_handle, pagemap_handle:
            for line in maps_handle:
                if total >= MAX_DIRTY_PAGES:
                    break
                fields = line.split(None, 2)
                if len(fields) < 2:
                    continue
                bounds = fields[0].split("-")
                if len(bounds) != 2:
                    continue
                try:
                    start = int(bounds[0], 16)
                    end = int(bounds[1], 16)
                except ValueError:
                    continue
                if end <= start:
                    continue
                count = min((end - start + page - 1) // page, MAX_DIRTY_PAGES - total)
                if count <= 0:
                    continue
                try:
                    pagemap_handle.seek((start // page) * 8)
                    payload = pagemap_handle.read(count * 8)
                except OSError:
                    return -1
                usable = len(payload) // 8
                for index in range(usable):
                    entry = int.from_bytes(payload[index * 8 : index * 8 + 8], "little")
                    if entry and (entry >> SOFT_DIRTY_BIT) & 1:
                        total += 1
    except OSError:
        return -1
    return total
