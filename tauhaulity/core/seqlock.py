"""PID verified sequence lock for publishing telemetry frames safely.

A plain seqlock is enough when every writer is guaranteed to finish, but a
crashed or descheduled writer leaves an odd ticket behind and readers spin
forever. This implementation therefore records the writer PID/TID and, once the
odd ticket is older than the timeout, verifies holder liveness with the kernel
before reclaiming the lock. The reclaim path is the only one that takes a mutex,
so the common read path stays allocation free and retry bounded.
"""

from __future__ import annotations

import os
import threading
import time
from typing import Final

TICKET_MASK: Final[int] = 0xFFFFFFFF


_WIN_KERNEL32: object | None = None
_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_STILL_ACTIVE = 259
_ERROR_INVALID_PARAMETER = 87


def _win_kernel32() -> object:
    """Load kernel32 once for the liveness probe.

    ctypes is imported lazily so that importing this module stays cheap on hosts
    that never query a PID.
    """

    global _WIN_KERNEL32
    if _WIN_KERNEL32 is None:
        import ctypes

        _WIN_KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    return _WIN_KERNEL32


def _windows_process_alive(pid: int) -> bool:
    """Return True when Win32 proves a PID still owns a running process.

    Why not os.kill(pid, 0): on Windows that call opens the process with
    PROCESS_ALL_ACCESS semantics and fails with WinError 87 for perfectly live
    processes whose access mask it cannot satisfy, which would make the seqlock
    reclaim a live writer's lock. OpenProcess with query-only rights is the
    documented, least-privilege liveness check.
    """

    import ctypes
    from ctypes import wintypes

    kernel32 = _win_kernel32()
    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        # ERROR_INVALID_PARAMETER means the PID does not exist. Anything else
        # (typically ERROR_ACCESS_DENIED) means the process exists but cannot be
        # inspected, and a lock must never be reclaimed on unverifiable evidence.
        return error != _ERROR_INVALID_PARAMETER
    try:
        exit_code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
            return True
        return exit_code.value == _STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


def process_alive(pid: int) -> bool:
    """Return True when a process id still refers to a running process.

    On POSIX the zero-signal probe is authoritative; on Windows the kernel
    query path above is used because the POSIX trick is unreliable there.

    Parameters:
        pid: Process id to probe. Non positive values are never alive.

    Returns:
        True when the process is known to exist, False only when it is proven
        gone. Unverifiable processes report True so a lock is never stolen.
    """

    if pid <= 0:
        return False
    if os.name == "nt":
        return _windows_process_alive(pid)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


class SeqLockTimeout(RuntimeError):
    """Raised when a reader cannot obtain a consistent snapshot in time."""


class PidVerifiedSeqLock:
    """Sequence lock with death detection and bounded reader retries.

    Attributes:
        timeout_ms: Age after which an odd ticket is considered abandoned.
        recoveries: Number of times the lock was reclaimed from a dead writer.
    """

    def __init__(self, timeout_ms: float = 5.0, max_retries: int = 64) -> None:
        if timeout_ms <= 0:
            raise ValueError("timeout_ms must be positive")
        if max_retries <= 0:
            raise ValueError("max_retries must be positive")
        self._timeout_ms = float(timeout_ms)
        self._max_retries = int(max_retries)
        self._mutex = threading.Lock()
        self._ticket = 0
        self._payload = b""
        self._has_written = False
        self._writer_pid = 0
        self._writer_tid = 0
        self._last_write_ns = time.monotonic_ns()
        self._recoveries = 0

    @property
    def ticket(self) -> int:
        """Current sequence ticket; odd means a writer owns the lock."""

        return self._ticket

    @property
    def recoveries(self) -> int:
        """Number of abandoned writers reclaimed so far."""

        return self._recoveries

    @property
    def timeout_ms(self) -> float:
        """Configured abandonment deadline in milliseconds."""

        return self._timeout_ms

    def write(self, payload: bytes) -> int:
        """Publish a payload under an odd then even ticket transition.

        Parameters:
            payload: Bytes snapshot to publish.

        Returns:
            The even ticket value visible after the write completes.

        Raises:
            ValueError: When the payload is not bytes-like.
        """

        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise ValueError("payload must be bytes-like")
        material = bytes(payload)
        pid = os.getpid()
        tid = threading.get_ident()
        with self._mutex:
            self._ticket = (self._ticket + 1) & TICKET_MASK
            self._writer_pid = pid
            self._writer_tid = tid
            try:
                self._payload = material
                self._has_written = True
            finally:
                self._last_write_ns = time.monotonic_ns()
                self._ticket = (self._ticket + 1) & TICKET_MASK
            return self._ticket

    def read(self) -> bytes | None:
        """Return a consistent snapshot, or None when no writer ever published.

        The reader never blocks on a mutex: it retries when the ticket changes
        underneath it and asks the reclaim path for help when the lock looks
        abandoned.

        Raises:
            SeqLockTimeout: When a live writer keeps the lock beyond the retry
                budget, which signals a genuine stall rather than a crash.
        """

        for _ in range(self._max_retries):
            first = self._ticket
            if first & 1:
                if self._maybe_recover():
                    continue
                time.sleep(0)
                continue
            payload = self._payload
            if first == self._ticket:
                return payload if self._has_written else None
        raise SeqLockTimeout("writer did not publish within the retry budget")

    def try_read(self) -> bytes | None:
        """Return a snapshot or None without raising on contention."""

        try:
            return self.read()
        except SeqLockTimeout:
            return None

    def snapshot(self) -> tuple[int, bytes]:
        """Return the ticket and payload pair for diagnostics."""

        return self._ticket, self._payload

    def reset(self) -> None:
        """Force the lock back to an even ticket.

        This exists for teardown and for tests that inject a torn state; normal
        operation only clears an odd ticket after proving the writer is gone.
        """

        with self._mutex:
            if self._ticket & 1:
                self._ticket = (self._ticket + 1) & TICKET_MASK
            self._writer_pid = 0
            self._writer_tid = 0
            self._last_write_ns = time.monotonic_ns()

    def inject_torn_state(self, writer_pid: int, age_ms: float = 0.0) -> None:
        """Simulate an abandoned writer for recovery testing.

        Parameters:
            writer_pid: PID recorded as the holder; use a dead PID to exercise
                reclaim, or the current PID to exercise the stall path.
            age_ms: Artificial age of the last write in milliseconds.
        """

        with self._mutex:
            self._ticket = (self._ticket | 1) & TICKET_MASK
            self._writer_pid = int(writer_pid)
            self._writer_tid = 0
            self._last_write_ns = time.monotonic_ns() - int(age_ms * 1_000_000)

    def _maybe_recover(self) -> bool:
        """Reclaim an abandoned odd ticket when the holder is provably gone.

        Returns:
            True when the lock was reclaimed, False when the writer is alive or
            the timeout has not elapsed yet.
        """

        age_ns = time.monotonic_ns() - self._last_write_ns
        if age_ns < self._timeout_ms * 1_000_000:
            return False
        holder = self._writer_pid
        if holder == os.getpid() or process_alive(holder):
            return False
        with self._mutex:
            if not self._ticket & 1:
                return True
            self._ticket = (self._ticket + 1) & TICKET_MASK
            self._writer_pid = 0
            self._writer_tid = 0
            self._last_write_ns = time.monotonic_ns()
            self._recoveries += 1
            return True
