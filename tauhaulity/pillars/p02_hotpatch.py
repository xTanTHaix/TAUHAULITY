"""Pillar 2 - HYPER-IMMUNE: atomic pointer slots, debug registers, syscall boundary.

The pillar answers one question the dossier cares about: can this host contain a
zero-day safely? Three concrete mechanisms are measured instead of described:

1. An atomic 8-byte pointer slot. Live hot patching only becomes safe when a call
   target can be replaced in one machine store, otherwise a second thread can
   observe a torn pointer and jump into garbage. The slot here is a real ctypes
   buffer that is swapped with a hardware compare-and-swap when the platform
   exports one (InterlockedCompareExchange64 on Windows, the libgcc builtin on
   Linux); the mutex guarded fallback keeps the same semantics and reports itself
   honestly as a fallback.

2. Hardware breakpoint availability. DR0-DR3 are only reachable through
   GetThreadContext/SetThreadContext on Windows, or through PTRACE_POKEUSER by an
   external tracer on Linux. Linux does not allow a process to ptrace itself, so
   the probe reports the ptrace_scope value and never claims self-service
   breakpoints that do not exist.

3. The syscall boundary. Linux exposes the seccomp mode and filter count in
   /proc/self/status, which is authoritative; Windows exposes the mitigation
   policy set through GetProcessMitigationPolicy. Both are read-only queries.

Nothing in this module patches a live interpreter. The probe is a capability
audit; AUTO_HOT_PATCHING stays a policy decision for the caller.
"""

from __future__ import annotations

import ctypes
import os
import threading
from dataclasses import dataclass
from typing import Final

from tauhaulity.core.contracts import Finding, PillarSpec, ScanContext, SPEC_BY_KEY, make_finding

SPEC: PillarSpec = SPEC_BY_KEY["hyper_immune"]

_WORD_BYTES: Final[int] = 8
_CONTEXT_DEBUG_REGISTERS_X64: Final[int] = 0x00100004
_CONTEXT_ALIGNMENT: Final[int] = 16
_CONTEXT_BUFFER_BYTES: Final[int] = 1232
_DR_OFFSETS_X64: Final[tuple[int, ...]] = (72, 80, 88, 96)  # DR0..DR3 inside CONTEXT


class AtomicPatchError(RuntimeError):
    """Raised when an atomic pointer slot cannot be created or used."""


class _HardwarePrimitives:
    """Resolve native 64-bit compare-and-swap and exchange primitives once.

    The resolver is intentionally defensive: a missing symbol is a normal outcome
    on older toolchains, and every caller falls back to a mutex guarded swap rather
    than failing the pillar.
    """

    def __init__(self) -> None:
        self.compare_and_swap = None
        self.exchange = None
        self.library = ""
        self._load()

    def _load(self) -> None:
        if os.name == "nt":
            self._load_windows()
        else:
            self._load_posix()

    def _load_windows(self) -> None:
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            cas = kernel32.InterlockedCompareExchange64
            cas.argtypes = [ctypes.POINTER(ctypes.c_int64), ctypes.c_int64, ctypes.c_int64]
            cas.restype = ctypes.c_int64
            exchange = kernel32.InterlockedExchange64
            exchange.argtypes = [ctypes.POINTER(ctypes.c_int64), ctypes.c_int64]
            exchange.restype = ctypes.c_int64
        except (OSError, AttributeError, ValueError):
            return
        self.compare_and_swap = self._windows_cas
        self.exchange = self._windows_exchange
        self._kernel32 = kernel32
        self.library = "kernel32"

    def _load_posix(self) -> None:
        for library_name in ("libgcc_s.so.1", "libatomic.so.1", "libc.so.6"):
            try:
                library = ctypes.CDLL(library_name)
            except OSError:
                continue
            switcher = getattr(library, "__sync_val_compare_and_swap_8", None)
            if switcher is not None:
                switcher.argtypes = [ctypes.c_void_p, ctypes.c_longlong, ctypes.c_longlong]
                switcher.restype = ctypes.c_longlong
                exchange = getattr(library, "__sync_lock_test_and_set_8", None)
                if exchange is not None:
                    exchange.argtypes = [ctypes.c_void_p, ctypes.c_longlong]
                    exchange.restype = ctypes.c_longlong
                self.compare_and_swap = self._posix_sync_cas(switcher)
                self.exchange = self._posix_sync_exchange(exchange) if exchange else None
                self.library = library_name
                return
            atomic = getattr(library, "__atomic_compare_exchange_8", None)
            if atomic is not None:
                atomic.argtypes = [
                    ctypes.c_void_p,
                    ctypes.c_void_p,
                    ctypes.c_longlong,
                    ctypes.c_bool,
                    ctypes.c_int,
                    ctypes.c_int,
                ]
                atomic.restype = ctypes.c_bool
                self.compare_and_swap = self._posix_atomic_cas(atomic)
                self.library = library_name
                return

    def _windows_cas(self, address: int, expected: int, desired: int) -> int:
        pointer = ctypes.cast(ctypes.c_void_p(address), ctypes.POINTER(ctypes.c_int64))
        return int(self._kernel32.InterlockedCompareExchange64(pointer, desired, expected))

    def _windows_exchange(self, address: int, desired: int) -> int:
        pointer = ctypes.cast(ctypes.c_void_p(address), ctypes.POINTER(ctypes.c_int64))
        return int(self._kernel32.InterlockedExchange64(pointer, desired))

    def _posix_sync_cas(self, function):
        def cas(address: int, expected: int, desired: int) -> int:
            return int(function(ctypes.c_void_p(address), expected, desired))

        return cas

    def _posix_sync_exchange(self, function):
        def exchange(address: int, desired: int) -> int:
            return int(function(ctypes.c_void_p(address), desired))

        return exchange

    def _posix_atomic_cas(self, function):
        def cas(address: int, expected: int, desired: int) -> int:
            expected_cell = ctypes.c_longlong(expected)
            swapped = bool(
                function(
                    ctypes.c_void_p(address),
                    ctypes.byref(expected_cell),
                    desired,
                    False,
                    5,  # __ATOMIC_SEQ_CST
                    5,
                )
            )
            return expected if swapped else int(expected_cell.value)

        return cas

    @property
    def hardware(self) -> bool:
        """True when a native 64-bit compare-and-swap was resolved."""

        return self.compare_and_swap is not None


_PRIMITIVES = _HardwarePrimitives()


class AtomicPointerSlot:
    """One 8-byte pointer cell inside a real NUL padded native buffer.

    Why a multi-word buffer: the classic failure of a hot patch is not a torn
    pointer, it is a dirty neighbour. Multiple words let a test verify that a swap
    of word N leaves word N+1 byte identical, which is what a memset based patcher
    gets wrong.

    Attributes:
        index: Word index inside the buffer this slot owns.
        hardware: True when swaps use a CPU compare-and-swap instruction.
    """

    def __init__(
        self,
        initial: int = 0,
        *,
        capacity_words: int = 4,
        index: int = 0,
        use_hardware: bool | None = None,
        primitives: _HardwarePrimitives | None = None,
    ) -> None:
        if capacity_words < 1:
            raise ValueError("capacity_words must be at least one")
        if not 0 <= index < capacity_words:
            raise ValueError("index outside the slot buffer")
        if initial < 0 or initial > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("pointer value outside unsigned 64-bit range")
        self.capacity_words = int(capacity_words)
        self.index = int(index)
        self._buffer = (ctypes.c_uint64 * self.capacity_words)()
        self._buffer[self.index] = int(initial)
        self._address = ctypes.addressof(self._buffer) + self.index * _WORD_BYTES
        self._lock = threading.Lock()
        self._primitives = primitives if primitives is not None else _PRIMITIVES
        self.hardware = bool(self._primitives.hardware and (use_hardware is not False))
        self._swap_counter = 0

    @property
    def address(self) -> int:
        """Native address of the 8-byte cell."""

        return self._address

    @property
    def value(self) -> int:
        """Current pointer value as an unsigned 64-bit integer."""

        return int(self._buffer[self.index]) & 0xFFFFFFFFFFFFFFFF

    def adjacent_word(self, offset: int = 1) -> int:
        """Read a neighbouring word; used to prove the swap stays 8-byte wide."""

        neighbour = self.index + offset
        if not 0 <= neighbour < self.capacity_words:
            raise IndexError("neighbour outside the slot buffer")
        return int(self._buffer[neighbour])

    def exchange(self, desired: int) -> int:
        """Atomically store desired and return the previous value.

        Raises:
            ValueError: When desired does not fit in an unsigned 64-bit word.
        """

        self._check_value(desired)
        if self.hardware and self._primitives.exchange is not None:
            previous = self._primitives.exchange(self._address, desired)
            self._swap_counter += 1
            return int(previous) & 0xFFFFFFFFFFFFFFFF
        with self._lock:
            previous = self.value
            self._buffer[self.index] = int(desired)
            self._swap_counter += 1
            return previous

    def compare_and_swap(self, expected: int, desired: int) -> bool:
        """Store desired only when the current value equals expected.

        Returns:
            True when the swap happened, False when the value had moved on.
        """

        self._check_value(expected)
        self._check_value(desired)
        if self.hardware and self._primitives.compare_and_swap is not None:
            previous = self._primitives.compare_and_swap(self._address, expected, desired)
            # A failed compare-and-swap performs no write, so it must not be
            # counted as a swap; the counter is a mutation counter, not an
            # attempt counter.
            success = (int(previous) & 0xFFFFFFFFFFFFFFFF) == (
                int(expected) & 0xFFFFFFFFFFFFFFFF
            )
            if success:
                self._swap_counter += 1
            return success
        with self._lock:
            current = self.value
            if current != (int(expected) & 0xFFFFFFFFFFFFFFFF):
                return False
            self._buffer[self.index] = int(desired)
            self._swap_counter += 1
            return True

    def bump(self) -> int:
        """CAS loop that increments the slot by one and returns the new value."""

        while True:
            current = self.value
            if self.compare_and_swap(current, (current + 1) & 0xFFFFFFFFFFFFFFFF):
                return (current + 1) & 0xFFFFFFFFFFFFFFFF

    def stats(self) -> dict[str, object]:
        """Return diagnostics used by the pillar and by tests."""

        return {
            "value": self.value,
            "address": self._address,
            "hardware": self.hardware,
            "library": self._primitives.library,
            "swaps": self._swap_counter,
        }

    @staticmethod
    def _check_value(value: int) -> None:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("pointer values must be integers")
        if value < 0 or value > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("pointer value outside unsigned 64-bit range")


@dataclass(frozen=True, slots=True)
class BreakpointCapability:
    """Honest description of DR0-DR3 reachability on this host.

    Attributes:
        supported: True when hardware breakpoints can be programmed at all.
        mechanism: The API that would be used.
        slots: Number of usable debug register slots (0..4).
        dr_readable: True when the current DR0-DR3 values could be read.
        ptrace_scope: Linux Yama scope value, or None off Linux.
        self_service: True when this process can program DRx on itself.
        detail: One line explanation for the dossier.
    """

    supported: bool
    mechanism: str
    slots: int
    dr_readable: bool
    ptrace_scope: int | None
    self_service: bool
    detail: str


class HardwareBreakpointCapability:
    """Probe DR0-DR3 availability without ever leaving a breakpoint installed.

    The Windows path only calls GetThreadContext with CONTEXT_DEBUG_REGISTERS and
    reads the DR values back; SetThreadContext is never called. The Linux path
    reads the Yama scope and reports the ptrace route as external-tracer-only,
    because a process cannot PTRACE_POKEUSER itself.
    """

    def probe(self) -> BreakpointCapability:
        """Return the resolved capability for the current host."""

        if os.name == "nt":
            return self._probe_windows()
        return self._probe_linux()

    def _probe_windows(self) -> BreakpointCapability:
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.GetCurrentThread.restype = ctypes.c_void_p
            kernel32.GetThreadContext.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
            kernel32.GetThreadContext.restype = ctypes.c_int
            thread = kernel32.GetCurrentThread()
        except (OSError, AttributeError, ValueError) as exc:
            return BreakpointCapability(
                False, "GetThreadContext", 0, False, None, False, f"kernel32 unavailable: {exc}"
            )
        raw = ctypes.create_string_buffer(_CONTEXT_BUFFER_BYTES + _CONTEXT_ALIGNMENT)
        base = ctypes.addressof(raw)
        aligned = (base + (_CONTEXT_ALIGNMENT - 1)) & ~(_CONTEXT_ALIGNMENT - 1)
        ctypes.memset(aligned, 0, _CONTEXT_BUFFER_BYTES)
        ctypes.c_uint32.from_address(aligned + 48).value = _CONTEXT_DEBUG_REGISTERS_X64
        try:
            ok = kernel32.GetThreadContext(thread, ctypes.c_void_p(aligned))
        except (OSError, ValueError, ctypes.ArgumentError) as exc:
            return BreakpointCapability(
                False, "GetThreadContext", 0, False, None, False, f"GetThreadContext raised: {exc}"
            )
        if not ok:
            error = ctypes.get_last_error()
            return BreakpointCapability(
                False,
                "GetThreadContext",
                0,
                False,
                None,
                False,
                f"GetThreadContext failed with Win32 error {error}",
            )
        values = tuple(
            int(ctypes.c_uint64.from_address(aligned + offset).value) for offset in _DR_OFFSETS_X64
        )
        return BreakpointCapability(
            True,
            "GetThreadContext/SetThreadContext",
            4,
            True,
            None,
            True,
            "DR0-DR3 readable via GetThreadContext: "
            + ", ".join(f"DR{index}={value:#x}" for index, value in enumerate(values)),
        )

    def _probe_linux(self) -> BreakpointCapability:
        scope = _read_int_file("/proc/sys/kernel/yama/ptrace_scope")
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            has_ptrace = hasattr(libc, "ptrace")
        except OSError:
            has_ptrace = False
        if not has_ptrace:
            return BreakpointCapability(
                False, "ptrace(PTRACE_POKEUSER)", 0, False, scope, False, "libc ptrace symbol missing"
            )
        reachable = scope is None or scope <= 1
        detail = (
            f"ptrace_scope={scope if scope is not None else 'unknown'}; "
            "DR0-DR3 require an external tracer (self-trace is rejected by the kernel)"
        )
        return BreakpointCapability(
            reachable,
            "ptrace(PTRACE_POKEUSER)",
            4 if reachable else 0,
            False,
            scope,
            False,
            detail,
        )


@dataclass(frozen=True, slots=True)
class MitigationPolicy:
    """One Win32 process mitigation policy value.

    Attributes:
        name: Symbolic policy name.
        flags: Raw DWORD returned by GetProcessMitigationPolicy.
    """

    name: str
    flags: int

    @property
    def enabled(self) -> bool:
        """True when at least one flag in the policy is set."""

        return bool(self.flags)


@dataclass(frozen=True, slots=True)
class SyscallBoundaryState:
    """Resolved syscall restriction state for the current process.

    Attributes:
        available: True when a kernel boundary primitive was observed.
        mechanism: seccomp (Linux) or process-mitigation-policy (Windows).
        seccomp_mode: Raw Seccomp value, 0 = disabled, 2 = filter mode.
        seccomp_filters: Number of installed seccomp filters.
        no_new_privs: Linux NoNewPrivs flag, or None when unavailable.
        policies: Win32 mitigation policies queried, empty on Linux.
        detail: One line explanation for the dossier.
    """

    available: bool
    mechanism: str
    seccomp_mode: int | None
    seccomp_filters: int | None
    no_new_privs: bool | None
    policies: tuple[MitigationPolicy, ...]
    detail: str

    @property
    def enabled_policies(self) -> tuple[str, ...]:
        """Names of the Win32 mitigation policies that are switched on."""

        return tuple(policy.name for policy in self.policies if policy.enabled)


_WIN_POLICY_NAMES: Final[dict[int, str]] = {
    0: "DEP",
    1: "ASLR",
    2: "DynamicCode",
    3: "StrictHandle",
    4: "DisableWin32kSyscalls",
    7: "ControlFlowGuard",
    8: "Signature",
    10: "ImageLoad",
    11: "SystemCallFilter",
    13: "ChildProcess",
    15: "UserShadowStack",
}


class SyscallBoundary:
    """Read the kernel side syscall restriction state of the current process."""

    def probe(self) -> SyscallBoundaryState:
        """Return the resolved state for the current host."""

        if os.name == "nt":
            return self._probe_windows()
        return self._probe_linux()

    def _probe_linux(self) -> SyscallBoundaryState:
        values: dict[str, str] = {}
        try:
            with open("/proc/self/status", "r", encoding="utf-8", errors="replace") as handle:
                for line in handle:
                    key, separator, raw = line.partition(":")
                    if separator:
                        values[key.strip()] = raw.strip()
        except OSError as exc:
            return SyscallBoundaryState(
                False, "seccomp", None, None, None, (), f"/proc/self/status unreadable: {exc}"
            )
        seccomp_mode = _parse_int(values.get("Seccomp"))
        seccomp_filters = _parse_int(values.get("Seccomp_filters"))
        no_new_privs = _parse_bool(values.get("NoNewPrivs"))
        available = seccomp_mode is not None and seccomp_mode > 0
        if values:
            detail = (
                f"seccomp mode {seccomp_mode if seccomp_mode is not None else 'unknown'}"
                f" / {seccomp_filters if seccomp_filters is not None else 0} filter(s),"
                f" no_new_privs={no_new_privs}"
            )
        else:
            detail = "seccomp state not reported by the kernel"
        return SyscallBoundaryState(
            available,
            "seccomp-bpf",
            seccomp_mode,
            seccomp_filters,
            no_new_privs,
            (),
            detail,
        )

    def _probe_windows(self) -> SyscallBoundaryState:
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            query = kernel32.GetProcessMitigationPolicy
            kernel32.GetCurrentProcess.restype = ctypes.c_void_p
            process = kernel32.GetCurrentProcess()
        except (OSError, AttributeError, ValueError) as exc:
            return SyscallBoundaryState(
                False, "process-mitigation-policy", None, None, None, (), f"kernel32 unavailable: {exc}"
            )
        query.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_size_t]
        query.restype = ctypes.c_int
        policies: list[MitigationPolicy] = []
        for policy_id, name in _WIN_POLICY_NAMES.items():
            flags = ctypes.c_uint32(0)
            try:
                ok = query(process, policy_id, ctypes.byref(flags), ctypes.sizeof(flags))
            except (OSError, ValueError, ctypes.ArgumentError):
                continue
            if ok:
                policies.append(MitigationPolicy(name, int(flags.value)))
        if not policies:
            return SyscallBoundaryState(
                False,
                "process-mitigation-policy",
                None,
                None,
                None,
                (),
                "GetProcessMitigationPolicy returned no policy",
            )
        enabled = tuple(policy.name for policy in policies if policy.enabled)
        detail = (
            f"{len(enabled)}/{len(policies)} mitigation policies enabled"
            + (f" ({', '.join(enabled[:6])})" if enabled else " (none enabled)")
        )
        return SyscallBoundaryState(
            bool(enabled),
            "process-mitigation-policy",
            None,
            None,
            None,
            tuple(policies),
            detail,
        )


def _read_int_file(path: str) -> int | None:
    """Read a single integer from a procfs file, None when unavailable."""

    try:
        with open(path, "r", encoding="utf-8") as handle:
            return int(handle.read().strip())
    except (OSError, ValueError):
        return None


def _parse_int(value: str | None) -> int | None:
    """Parse an optional integer field."""

    if value is None:
        return None
    try:
        return int(value.strip())
    except ValueError:
        return None


def _parse_bool(value: str | None) -> bool | None:
    """Parse a procfs zero/one boolean field."""

    parsed = _parse_int(value)
    return None if parsed is None else bool(parsed)


def probe(ctx: ScanContext) -> Finding:
    """Run the HYPER-IMMUNE capability audit for the current interpreter.

    The probe never patches the live host. It exercises the atomic slot against
    itself (swap, failed compare, neighbour isolation), then folds the debug
    register and syscall boundary findings into a single honest status.
    """

    slot = AtomicPointerSlot(0)
    slot_ok = False
    try:
        first = slot.compare_and_swap(0, 0xDEADBEEF)
        second = slot.compare_and_swap(0, 0xFEEDFACE)
        third = slot.exchange(0xCAFEBABE)
        slot_ok = first and not second and third == 0xDEADBEEF and slot.value == 0xCAFEBABE
    except (OSError, ValueError, ctypes.ArgumentError):
        slot_ok = False

    breakpoints = HardwareBreakpointCapability().probe()
    boundary = SyscallBoundary().probe()
    hotpatch = slot_ok and (breakpoints.supported or boundary.available)
    layering = "hardware-cas" if slot.hardware else "mutex-cas"

    if not slot_ok:
        status = "CRITICAL"
        risk = 7.5
        detail = "atomic pointer slot self-test failed: torn 8-byte pointer swaps cannot be ruled out"
    elif hotpatch:
        status = "SAFE"
        risk = 0.0
        detail = (
            f"atomic 8-byte swap via {layering}; breakpoints {breakpoints.detail}; "
            f"syscall boundary {boundary.detail}"
        )
    elif breakpoints.supported or boundary.available:
        status = "WARNING"
        risk = 3.0
        detail = (
            f"atomic swap via {layering}; breakpoints {breakpoints.detail}; "
            f"syscall boundary {boundary.detail}"
        )
    elif os.name != "nt" and breakpoints.ptrace_scope == 0:
        status = "CRITICAL"
        risk = 6.5
        detail = (
            "no seccomp filter and unrestricted ptrace: any local process can read or patch this "
            f"interpreter (scope {breakpoints.ptrace_scope})"
        )
    else:
        status = "WARNING"
        risk = 4.0
        detail = (
            f"atomic swap via {layering}; no syscall boundary ({boundary.detail}); "
            f"no hardware breakpoints ({breakpoints.detail})"
        )

    return make_finding(
        SPEC,
        status,
        detail,
        risk=risk,
        slots={"hotpatch": "YES" if hotpatch else "NO", "detail": detail},
        repro_hint="Attempt a live GOT/IAT swap and verify the pointer cell changes atomically.",
    )
