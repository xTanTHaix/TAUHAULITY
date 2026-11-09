"""Listening socket enumeration and bounded port reaping.

Pillar nine must answer two questions without side effects: which ports are
bound, and which owner is a leftover process. Enumeration therefore prefers the
native engine when it is importable and falls back to the kernel's own tables
(procfs on Linux, the IP helper API on Windows) so the module works even when
the Rust extension was never built.

free_port is the only mutating entry point and it is deliberately explicit:
nothing in probe() ever calls it, a dry run is available for the dossier, and
the current process (and pid 0/1) can never be signalled.
"""

from __future__ import annotations

import os
import socket
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Sequence

DEV_PORTS: tuple[int, ...] = (3000, 8000, 5432, 8080)

_MIB_TCP_STATE_LISTEN = 2
_MAX_PROC_SCAN = 4096
_MAX_FDS_PER_PROC = 512


@dataclass(frozen=True, slots=True)
class PortOwner:
    """One process observed holding a local port.

    Attributes:
        port: Local port number.
        pid: Owning process id, zero when the kernel did not expose it.
        process_name: Executable name when resolvable, empty otherwise.
        protocol: Transport protocol, tcp or tcp6.
    """

    port: int
    pid: int
    process_name: str
    protocol: str = "tcp"


@dataclass(frozen=True, slots=True)
class PortEntry:
    """One listening socket row.

    Attributes:
        port: Local port number.
        protocol: Transport protocol label.
        pid: Owning process id, zero when unknown.
        process_name: Executable name when resolvable.
        local_address: Bound address in printable form, empty when unknown.
        state: Socket state token, LISTEN for every row this module returns.
    """

    port: int
    protocol: str = "tcp"
    pid: int = 0
    process_name: str = ""
    local_address: str = ""
    state: str = "LISTEN"

    @property
    def owner(self) -> PortOwner:
        """Return the owner view of this entry."""

        return PortOwner(self.port, self.pid, self.process_name, self.protocol)

    @property
    def local_port(self) -> int:
        """Alias matching the primitives engine row shape.

        The CLI and the dossier expect a row with local_port; exposing the alias
        here keeps one PortEntry type usable by both layers instead of forcing
        every caller to know which module produced the row.
        """

        return self.port

    @property
    def endpoint(self) -> str:
        """Return the bound endpoint as host:port with IPv6 bracketed."""

        if ":" in self.local_address:
            return "[" + self.local_address + "]:" + str(self.port)
        return self.local_address + ":" + str(self.port)

    @property
    def is_listening(self) -> bool:
        """True when the socket state is a listener."""

        return self.state == "LISTEN"


@dataclass(frozen=True, slots=True)
class PortFreeResult:
    """Outcome of a port reaping attempt.

    Attributes:
        released: True when the port is no longer bound after the attempt.
        killed: Process ids that were signalled and confirmed gone.
        message: Human readable explanation of what happened.
    """

    released: bool
    killed: list[int]
    message: str


def backend_name() -> str:
    """Return the enumeration backend that would be used on this host.

    The name is reported by the dossier so a user can tell a genuinely clean
    machine from one where the platform tables were unreachable.
    """

    if os.name == "nt":
        return "windows-iphlpapi"
    if Path("/proc/net/tcp").exists():
        return "procfs"
    return "unsupported"


def _engine_entries() -> list[PortEntry] | None:
    """Return entries from the native engine, or None when it is unavailable.

    The engine is an optional sibling component: importing it lazily keeps this
    module importable on a fresh checkout, and any failure inside it degrades to
    the kernel table fallback instead of failing the sweep.
    """

    try:
        from tauhaulity.primitives.loader import get_engine
    except ImportError:
        return None
    try:
        table = get_engine().port_table()
    except (OSError, RuntimeError, ValueError, TypeError, AttributeError):
        return None
    if table is None:
        return None
    entries: list[PortEntry] = []
    for raw in list(table)[:8192]:
        entry = _coerce_entry(raw)
        if entry is not None:
            entries.append(entry)
    return entries


#: Rows the last enumeration could not interpret; exposed for diagnostics so a
#: backend shape drift is visible instead of silently dropping sockets.
_uncoerced_rows: int = 0


def uncoerced_rows() -> int:
    """Return how many backend rows the last enumeration could not interpret."""

    return _uncoerced_rows


def _field(raw: object, *names: str, default: object = None) -> object:
    """Read the first present mapping key or attribute, never raising.

    A missing attribute and a broken property both have to degrade to the next
    candidate: the engine is a sibling component whose row shape may drift, and a
    diagnostic tool must not crash because one row carries a different field name.
    """

    for name in names:
        if isinstance(raw, Mapping):
            if name in raw:
                return raw[name]
            continue
        try:
            return getattr(raw, name)
        except AttributeError:
            continue
    return default


def _text(value: object, default: str = "") -> str:
    """Return a printable string for a possibly missing field value."""

    if value is None:
        return default
    text = str(value)
    return text if text else default


def _coerce_entry(raw: object) -> PortEntry | None:
    """Best effort conversion of one backend row into a PortEntry.

    Two shapes must survive the boundary: the native engine row
    (protocol, local_address, local_port, pid, state) and simple duck typed rows
    that only carry port and pid. The reader tries both spellings, never raises
    on a malformed row, and returns None so the caller can count it.
    """

    if isinstance(raw, PortEntry):
        return raw
    try:
        if isinstance(raw, (tuple, list)):
            values = list(raw)
            if len(values) < 2:
                return None
            port_raw = values[0]
            pid_raw = values[1]
            protocol_raw = values[2] if len(values) > 2 else "tcp"
            name_raw = values[3] if len(values) > 3 else ""
            address_raw = values[4] if len(values) > 4 else ""
            state_raw = values[5] if len(values) > 5 else "LISTEN"
        else:
            port_raw = _field(raw, "local_port", "port", default=0)
            pid_raw = _field(raw, "pid", "owning_pid", default=0)
            protocol_raw = _field(raw, "protocol", "proto", default="tcp")
            name_raw = _field(raw, "process_name", "name", default="")
            address_raw = _field(raw, "local_address", "address", default="")
            state_raw = _field(raw, "state", default="LISTEN")
        port = int(port_raw or 0)
        pid = int(pid_raw or 0)
    except (TypeError, ValueError, OverflowError):
        return None
    if not 0 < port < 65536:
        return None
    state = _text(state_raw, "LISTEN").upper()
    # The native engine can expose the whole TCP table, not only listeners;
    # keeping established rows here would make every active client connection
    # look like a port conflict.
    if state not in {"LISTEN", "LISTENING"}:
        return None
    return PortEntry(
        port=port,
        protocol=_text(protocol_raw, "tcp").lower() or "tcp",
        pid=max(0, pid),
        process_name=_text(name_raw),
        local_address=_text(address_raw),
        state="LISTEN",
    )


def _decode_linux_address(raw: bytes, protocol: str) -> str:
    """Render a procfs address word sequence into printable form.

    procfs stores IPv4 as one little endian word and IPv6 as four little endian
    words, so both need a per word byte swap before inet_ntoa/inet_ntop agree
    with what the application sees.
    """

    try:
        if len(raw) == 4 and protocol == "tcp":
            return socket.inet_ntoa(raw[::-1])
        if len(raw) == 16 and protocol == "tcp6":
            swapped = b"".join(raw[index : index + 4][::-1] for index in range(0, 16, 4))
            return socket.inet_ntop(socket.AF_INET6, swapped)
    except (OSError, ValueError):
        return ""
    return ""


def _read_proc_comm(pid: int) -> str:
    """Return the short process name from procfs, or an empty string."""

    try:
        return Path("/proc/" + str(pid) + "/comm").read_text(
            encoding="utf-8", errors="replace"
        ).strip()
    except OSError:
        return ""


def _linux_socket_owners(inodes: set[str]) -> dict[str, int]:
    """Map socket inodes to pids by scanning procfs file descriptor links.

    The kernel does not expose a pid in /proc/net/tcp, only the socket inode, so
    ownership has to be reconstructed from /proc/PID/fd. Unprivileged scans only
    see their own processes; unknown ownership is reported as pid zero instead of
    being guessed, because a wrong pid would let free_port signal the wrong
    process.
    """

    owners: dict[str, int] = {}
    if not inodes:
        return owners
    try:
        entries = list(os.scandir("/proc"))
    except OSError:
        return owners
    scanned = 0
    for entry in entries:
        # Stop as soon as every wanted socket has an owner: a busy container can
        # hold thousands of processes and the probe budget is under two seconds.
        if len(owners) >= len(inodes):
            break
        name = entry.name
        if not name.isdigit():
            continue
        scanned += 1
        if scanned > _MAX_PROC_SCAN:
            break
        pid = int(name)
        fd_dir = "/proc/" + name + "/fd"
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds[:_MAX_FDS_PER_PROC]:
            try:
                target = os.readlink(os.path.join(fd_dir, fd))
            except OSError:
                continue
            if not target.startswith("socket:["):
                continue
            inode = target[8:-1]
            if inode in inodes and inode not in owners:
                owners[inode] = pid
    return owners


def _linux_entries() -> list[PortEntry]:
    """Enumerate listening TCP sockets from procfs."""

    rows: list[tuple[str, str, int, str]] = []
    for proc_path, protocol in (("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6")):
        try:
            text = Path(proc_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10:
                continue
            local, state, inode = fields[1], fields[3], fields[9]
            if state != "0A":
                continue
            _, _, port_hex = local.rpartition(":")
            try:
                port = int(port_hex, 16)
            except ValueError:
                continue
            rows.append((protocol, local.rpartition(":")[0], port, inode))
    owners = _linux_socket_owners({inode for _, _, _, inode in rows if inode != "0"})
    entries: list[PortEntry] = []
    for protocol, address_hex, port, inode in rows:
        pid = owners.get(inode, 0)
        entries.append(
            PortEntry(
                port=port,
                protocol=protocol,
                pid=pid,
                process_name=_read_proc_comm(pid) if pid else "",
                local_address=_decode_linux_address(bytes.fromhex(address_hex) if address_hex else b"", protocol),
                state="LISTEN",
            )
        )
    return entries


def _windows_process_name(pid: int) -> str:
    """Return the full image path of a Windows process, or an empty string."""

    if pid <= 0:
        return ""
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.QueryFullProcessImageNameW.argtypes = [
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.LPWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return ""
        try:
            size = wintypes.DWORD(32768)
            buffer = ctypes.create_unicode_buffer(size.value)
            if not kernel32.QueryFullProcessImageNameW(
                handle, 0, buffer, ctypes.byref(size)
            ):
                return ""
            return buffer.value
        finally:
            kernel32.CloseHandle(handle)
    except (OSError, AttributeError, ImportError):
        return ""


def _windows_table(family: int, protocol: str) -> list[PortEntry]:
    """Read one GetExtendedTcpTable owner listener table.

    dwLocalPort is documented as a network byte order value in the low word, so
    it must be byte swapped before use; skipping that step reports port 20480 for
    every port 80 listener, which looks plausible enough to survive review.
    """

    entries: list[PortEntry] = []
    try:
        import ctypes
        from ctypes import wintypes

        iphlpapi = ctypes.WinDLL("iphlpapi", use_last_error=True)
    except (OSError, AttributeError, ImportError):
        return entries

    tcp_table_owner_pid_listener = 3
    error_insufficient_buffer = 122
    call = iphlpapi.GetExtendedTcpTable
    call.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        wintypes.BOOL,
        wintypes.ULONG,
        ctypes.c_int,
        wintypes.ULONG,
    ]
    call.restype = wintypes.DWORD
    size = wintypes.DWORD(0)
    status = call(None, ctypes.byref(size), False, family, tcp_table_owner_pid_listener, 0)
    if status not in (0, error_insufficient_buffer):
        return entries
    if size.value == 0:
        return entries
    try:
        buffer = ctypes.create_string_buffer(size.value)
        status = call(
            buffer, ctypes.byref(size), False, family, tcp_table_owner_pid_listener, 0
        )
        if status != 0:
            return entries
        count = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
        offset = ctypes.sizeof(wintypes.DWORD)
        names: dict[int, str] = {}
        if family == socket.AF_INET:
            class Row(ctypes.Structure):
                _fields_ = [
                    ("dwState", wintypes.DWORD),
                    ("dwLocalAddr", wintypes.DWORD),
                    ("dwLocalPort", wintypes.DWORD),
                    ("dwRemoteAddr", wintypes.DWORD),
                    ("dwRemotePort", wintypes.DWORD),
                    ("dwOwningPid", wintypes.DWORD),
                ]
        else:
            class Row(ctypes.Structure):
                _fields_ = [
                    ("ucLocalAddr", ctypes.c_ubyte * 16),
                    ("dwLocalScopeId", wintypes.DWORD),
                    ("dwLocalPort", wintypes.DWORD),
                    ("ucRemoteAddr", ctypes.c_ubyte * 16),
                    ("dwRemotePort", wintypes.DWORD),
                    ("dwState", wintypes.DWORD),
                    ("dwOwningPid", wintypes.DWORD),
                ]
        row_size = ctypes.sizeof(Row)
        raw_buffer = buffer.raw
        for index in range(count):
            start = offset + index * row_size
            if start + row_size > len(raw_buffer):
                break
            row = Row.from_buffer_copy(raw_buffer[start : start + row_size])
            port = socket.ntohs(row.dwLocalPort & 0xFFFF)
            if not 0 < port < 65536:
                continue
            pid = int(row.dwOwningPid)
            if family == socket.AF_INET:
                packed = int(row.dwLocalAddr).to_bytes(4, "little")
                address = socket.inet_ntoa(packed)
            else:
                address = socket.inet_ntop(socket.AF_INET6, bytes(row.ucLocalAddr))
            if pid not in names:
                names[pid] = _windows_process_name(pid)
            entries.append(
                PortEntry(
                    port=port,
                    protocol=protocol,
                    pid=pid,
                    process_name=names[pid],
                    local_address=address,
                    state="LISTEN",
                )
            )
    except (OSError, AttributeError, ValueError, ctypes.ArgumentError):
        return entries
    return entries


def _windows_entries() -> list[PortEntry]:
    """Enumerate listening TCP sockets through the IP helper API."""

    entries = _windows_table(socket.AF_INET, "tcp")
    entries.extend(_windows_table(socket.AF_INET6, "tcp6"))
    return entries


def list_listening() -> list[PortEntry]:
    """Return every listening TCP socket visible to this process.

    The native engine is preferred because it can resolve owners the platform
    tables hide, and the kernel fallback keeps the sweep useful without it.

    Returns:
        Entries sorted by port, protocol and pid; an empty list when no backend
        could enumerate sockets on this host.
    """

    global _uncoerced_rows
    raw_entries: list = _engine_entries() or []
    # An engine that answers with an empty table is treated like an unavailable
    # one: the kernel tables are authoritative, and trusting an empty engine
    # result would let a stub or partially built extension hide every listener.
    if not raw_entries:
        if os.name == "nt":
            raw_entries = list(_windows_entries())
        elif Path("/proc/net/tcp").exists():
            raw_entries = list(_linux_entries())
        else:
            raw_entries = []
    unique: dict[tuple[int, str, int, str], PortEntry] = {}
    skipped = 0
    for raw in raw_entries:
        entry = _coerce_entry(raw)
        if entry is None:
            skipped += 1
            continue
        unique.setdefault(
            (entry.port, entry.protocol, entry.pid, entry.local_address), entry
        )
    _uncoerced_rows = skipped
    return sorted(unique.values(), key=lambda item: (item.port, item.protocol, item.pid))


def find_port_owners(port: int) -> list[PortOwner]:
    """Return every process observed listening on one port.

    Parameters:
        port: Local port number to look up.

    Returns:
        Owner rows; pid zero means the kernel would not reveal the owner.

    Raises:
        ValueError: When the port is outside the valid range.
    """

    port = int(port)
    if not 0 < port < 65536:
        raise ValueError("port must be within 1..65535")
    owners: list[PortOwner] = []
    seen: set[tuple[int, str]] = set()
    for entry in list_listening():
        if entry.port != port:
            continue
        key = (entry.pid, entry.protocol)
        if key in seen:
            continue
        seen.add(key)
        owners.append(entry.owner)
    return owners


def describe_port_action(port: int) -> str:
    """Describe what free_port would do to one port, without doing it.

    Freeing a port is destructive and irreversible for the owning process, so an
    operator must be able to see which pids would receive a termination request,
    and which rows are protected, before committing to it. This function only
    enumerates owners; it never signals, terminates or suspends anything, and it
    is the preview the CLI prints before asking for confirmation.

    Parameters:
        port: Local port number to describe.

    Returns:
        A one paragraph human readable summary of the action that would be taken.

    Raises:
        ValueError: When the port is outside the valid range.
    """

    port = int(port)
    if not 0 < port < 65536:
        raise ValueError("port must be within 1..65535")
    try:
        owners = find_port_owners(port)
    except (OSError, RuntimeError) as exc:
        return (
            "port "
            + str(port)
            + ": the listening socket table is unavailable ("
            + type(exc).__name__
            + ": "
            + str(exc)
            + "); free_port would signal nothing"
        )
    if not owners:
        return "port " + str(port) + " is not bound; free_port would signal nothing"

    protected = {0, 1, os.getpid()}
    signalled: list[str] = []
    skipped: list[str] = []
    for owner in owners:
        label = "pid " + str(owner.pid)
        if owner.process_name:
            label += " (" + owner.process_name + ")"
        if owner.pid <= 0:
            # An unprivileged procfs scan cannot see other users' descriptors, and
            # guessing a pid here would target an innocent process.
            skipped.append(
                owner.protocol + " listener with unknown owner (kernel did not expose a pid)"
            )
        elif owner.pid in protected:
            skipped.append(label + " is protected and would never be signalled")
        else:
            signalled.append(label)

    held = ", ".join(signalled + skipped)
    if not signalled:
        return "port " + str(port) + " is held by " + held + "; free_port would signal nothing"

    summary = (
        "freeing port "
        + str(port)
        + " would signal "
        + ", ".join(signalled)
        + " (graceful request first, then a forced termination if the process "
        "survives the grace period)"
    )
    if skipped:
        summary += "; protected or unknown owners left alone: " + ", ".join(skipped)
    return summary


def conflicting_ports(
    entries: Iterable[PortEntry], dev_ports: Sequence[int] = DEV_PORTS
) -> dict[int, list[PortEntry]]:
    """Return development ports that more than one process is serving.

    A single listener on 3000 is normal. Two processes bound to the same
    development port through SO_REUSEPORT is the failure mode developers
    actually hit, because requests are then split across two code versions, so
    that is what this check reports rather than every busy dev port.
    """

    wanted = set(int(port) for port in dev_ports)
    grouped: dict[int, list[PortEntry]] = {}
    for entry in entries:
        if entry.port not in wanted:
            continue
        grouped.setdefault(entry.port, []).append(entry)
    conflicts: dict[int, list[PortEntry]] = {}
    for port, rows in grouped.items():
        pids = {row.pid for row in rows if row.pid > 0}
        if len(pids) > 1:
            conflicts[port] = rows
    return conflicts


def _windows_exit_code(pid: int) -> int | None:
    """Return a process exit code, or None when the process cannot be queried.

    OpenProcess with PROCESS_QUERY_LIMITED_INFORMATION fails for protected
    processes, and Windows reports two different errors (access denied and
    invalid parameter) for perfectly live pids, so a failed open can never be
    read as "dead".
    """

    if pid <= 0:
        return None
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.GetExitCodeProcess.argtypes = [
            wintypes.HANDLE,
            ctypes.POINTER(wintypes.DWORD),
        ]
        handle = kernel32.OpenProcess(0x1000, False, pid)
        if not handle:
            return None
        try:
            code = wintypes.DWORD(0)
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return None
            return int(code.value)
        finally:
            kernel32.CloseHandle(handle)
    except (OSError, AttributeError, ImportError):
        return None


def _process_alive(pid: int) -> bool:
    """Return True when a pid still names a running process.

    The shared process_alive helper calls os.kill(pid, 0), which raises
    ERROR_INVALID_PARAMETER for many live Windows processes owned by another
    user. Reporting those as dead would manufacture zombie listeners on a
    healthy machine, so Windows uses the process exit code and treats an
    unopenable handle as "alive but unverifiable".
    """

    if pid <= 0:
        return False
    if os.name == "nt":
        code = _windows_exit_code(pid)
        if code is None:
            return True
        return code == 259
    from tauhaulity.core.seqlock import process_alive

    try:
        return process_alive(pid)
    except (OSError, ValueError):
        return False


def _is_defunct(pid: int) -> bool:
    """Return True when a pid still exists but has already terminated.

    Linux keeps a zombie until its parent reaps it and Windows keeps a process
    object until every handle closes; both still own kernel resources but can no
    longer serve a socket, which is exactly the leftover this pillar reports.
    """

    if pid <= 0:
        return False
    if os.name == "nt":
        code = _windows_exit_code(pid)
        return code is not None and code != 259
    try:
        stat = Path("/proc/" + str(pid) + "/stat").read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        return False
    closing = stat.rfind(")")
    fields = stat[closing + 2 :].split() if closing >= 0 else []
    return bool(fields) and fields[0] == "Z"


def zombie_entries(entries: Iterable[PortEntry]) -> list[PortEntry]:
    """Return listening rows whose owner process is gone or defunct.

    Ownership is unknown for rows with pid zero (an unprivileged procfs scan
    cannot see other users' descriptors); those are reported as unknown rather
    than as zombies so the pillar never accuses a healthy service.
    """

    zombies: list[PortEntry] = []
    for entry in entries:
        if entry.pid <= 0:
            continue
        if not _process_alive(entry.pid) or _is_defunct(entry.pid):
            zombies.append(entry)
    return zombies


def _wait_gone(pid: int, timeout_ms: int) -> bool:
    """Poll until a process disappears or the deadline expires."""

    deadline = time.monotonic() + max(0, timeout_ms) / 1000.0
    while True:
        if not _process_alive(pid):
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.02)


def _terminate_graceful(pid: int) -> bool:
    """Ask a process to exit, returning True when a request was delivered.

    POSIX gets SIGTERM. Windows has no portable polite signal without a console
    handle, so a WM_CLOSE is posted to the process's top level windows; a
    process without windows cannot be asked politely and must be forced
    directly.
    """

    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            user32 = ctypes.WinDLL("user32", use_last_error=True)
            posted: list[int] = []
            enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

            def callback(hwnd, _lparam):
                owner = wintypes.DWORD(0)
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner))
                if int(owner.value) == pid:
                    if user32.PostMessageW(hwnd, 0x0010, 0, 0):
                        posted.append(int(hwnd))
                return True

            callback_ref = enum_proc(callback)
            user32.EnumWindows(callback_ref, 0)
            return bool(posted)
        except (OSError, AttributeError, ImportError):
            return False
    try:
        import signal

        os.kill(pid, signal.SIGTERM)
        return True
    except (OSError, AttributeError):
        return False


def _terminate_force(pid: int) -> bool:
    """Terminate a process unconditionally, returning True when accepted."""

    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.TerminateProcess.argtypes = [wintypes.HANDLE, wintypes.UINT]
            kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
            handle = kernel32.OpenProcess(0x0001, False, pid)
            if not handle:
                return False
            try:
                return bool(kernel32.TerminateProcess(handle, 1))
            finally:
                kernel32.CloseHandle(handle)
        except (OSError, AttributeError, ImportError):
            return False
    try:
        import signal

        os.kill(pid, signal.SIGKILL)
        return True
    except (OSError, AttributeError):
        return False


def free_port(
    port: int,
    *,
    force_after_ms: int = 500,
    dry_run: bool = False,
) -> PortFreeResult:
    """Reap the processes holding one port, gracefully then forcefully.

    Parameters:
        port: Local port number to free.
        force_after_ms: Grace period in milliseconds before a forced kill.
        dry_run: Report what would be killed without signalling anything.

    Returns:
        The outcome, including the pids that were confirmed gone.

    Raises:
        ValueError: When the port is outside the valid range.
    """

    port = int(port)
    if not 0 < port < 65536:
        raise ValueError("port must be within 1..65535")
    owners = find_port_owners(port)
    if not owners:
        return PortFreeResult(True, [], "port " + str(port) + " is not bound")

    self_pid = os.getpid()
    protected = {0, 1, self_pid}
    candidates: list[int] = []
    for owner in owners:
        if owner.pid <= 0:
            continue
        if owner.pid in protected:
            continue
        if owner.pid not in candidates:
            candidates.append(owner.pid)

    described = ", ".join(
        str(owner.pid) + (" " + owner.process_name if owner.process_name else "")
        for owner in owners
    )
    if not candidates:
        return PortFreeResult(
            False,
            [],
            "port "
            + str(port)
            + " is held by "
            + described
            + "; owner cannot be reaped from this process",
        )
    if dry_run:
        return PortFreeResult(
            False,
            [],
            "dry run: would terminate "
            + ", ".join(str(pid) for pid in candidates)
            + " holding port "
            + str(port),
        )

    killed: list[int] = []
    notes: list[str] = []
    for pid in candidates:
        graceful = _terminate_graceful(pid)
        if not graceful:
            notes.append("pid " + str(pid) + " refused a graceful request")
        if _wait_gone(pid, force_after_ms):
            killed.append(pid)
            continue
        if _terminate_force(pid) and _wait_gone(pid, force_after_ms):
            killed.append(pid)
        else:
            notes.append("pid " + str(pid) + " survived the forced termination")

    remaining = find_port_owners(port)
    released = not remaining
    message = (
        ("port " + str(port) + " released")
        if released
        else ("port " + str(port) + " still bound by " + ", ".join(str(row.pid) for row in remaining))
    )
    if killed:
        message += "; killed " + ", ".join(str(pid) for pid in killed)
    if notes:
        message += "; " + "; ".join(notes)
    return PortFreeResult(released, killed, message)
