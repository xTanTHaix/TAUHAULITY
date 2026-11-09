"""Pillar 5 - CRYPTO-SHIELD: pinned secret pages, rotating masks, constant time gates.

Three mechanisms, each of which is measured by the probe instead of asserted:

1. Page pinning. A secret lives in a real ctypes buffer so the page can be pinned
   with mlock (Linux) or VirtualLock (Windows). The native engine is asked first so
   the same code paths work when the Rust core is present; the ctypes fallback is
   the documented zero dependency path. A failed pin is reported as EXPOSED rather
   than hidden, because an unpinned secret may be written to swap or to a crash
   dump.

2. A rotating XOR mask. The buffer never holds the plaintext: it holds
   plaintext XOR mask, and every rotation rewrites the stored bytes with a fresh
   os.urandom mask. A memory dump therefore shows different bytes depending on when
   it was taken, while retrieve() still returns the same secret. The rotation thread
   is a daemon so a forgotten vault can never block interpreter shutdown.

3. Constant time comparison and a quantized response bucket. The comparison folds
   every differing byte into one accumulator with no early exit, and the quantized
   variant pads the measured latency up to a fixed bucket so an attacker cannot
   distinguish "wrong length" from "wrong byte" by timing alone. QueryPerformanceCounter
   is used through the engine when available; the standard library monotonic clock
   is the fallback.

Nothing here claims tamper proof memory: an attacker with kernel or debugger access
can read the process regardless. The pillar reports whether the cheap protections
are actually in place.
"""

from __future__ import annotations

import ctypes
import os
import threading
import time
from dataclasses import dataclass
from typing import Final

from tauhaulity.core.contracts import Finding, PillarSpec, ScanContext, SPEC_BY_KEY, make_finding

SPEC: PillarSpec = SPEC_BY_KEY["crypto_shield"]

DEFAULT_ROTATE_MS: Final[float] = 10.0
DEFAULT_BUCKET_NS: Final[int] = 50_000
_PROBE_SECRET_BYTES: Final[int] = 32


class KeyVaultError(RuntimeError):
    """Raised when a secret cannot be stored, locked or retrieved."""


def _load_engine():
    """Import the optional native engine; None when it is absent or unusable."""

    try:
        from tauhaulity.primitives.loader import get_engine
    except (ImportError, OSError, RuntimeError):
        return None
    try:
        engine = get_engine()
    except (ImportError, OSError, RuntimeError, ValueError):
        return None
    # The handle is returned for every tier: even without the Rust cdylib the
    # ctypes tier can pin pages and read the performance counter, and the direct
    # ctypes fallbacks in this module cover the pure Python tier.
    return engine


class PageLocker:
    """Pin and unpin native buffers through the engine or the OS directly.

    Attributes:
        mechanism: Which layer resolved the primitive (engine, VirtualLock, mlock).
        available: True when a working pin primitive was resolved.
    """

    def __init__(self) -> None:
        self.mechanism = "unavailable"
        self.available = False
        self._engine = _load_engine()
        self._engine_lock = None
        self._engine_unlock = None
        self._engine_backend = ""
        if self._engine is not None:
            self._engine_backend = str(getattr(self._engine, "backend", "")).lower()
            lock = getattr(self._engine, "lock_pages", None)
            unlock = getattr(self._engine, "unlock_pages", None)
            if callable(lock) and callable(unlock) and self._engine_backend != "python":
                self._engine_lock = lock
                self._engine_unlock = unlock
                self.mechanism = "native-engine" if self._engine_backend == "rust" else "engine-ctypes"
                self.available = True
        self._virtual_lock = None
        self._virtual_unlock = None
        self._mlock = None
        self._munlock = None
        if os.name == "nt":
            self._resolve_windows()
        else:
            self._resolve_posix()
        if not self.available and self._virtual_lock is not None:
            self.mechanism = "VirtualLock"
            self.available = True
        if not self.available and self._mlock is not None:
            self.mechanism = "mlock"
            self.available = True

    def _resolve_windows(self) -> None:
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            virtual_lock = kernel32.VirtualLock
            virtual_lock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            virtual_lock.restype = ctypes.c_int
            virtual_unlock = kernel32.VirtualUnlock
            virtual_unlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            virtual_unlock.restype = ctypes.c_int
        except (OSError, AttributeError, ValueError):
            return
        self._virtual_lock = virtual_lock
        self._virtual_unlock = virtual_unlock

    def _resolve_posix(self) -> None:
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            mlock = libc.mlock
            mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            mlock.restype = ctypes.c_int
            munlock = libc.munlock
            munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
            munlock.restype = ctypes.c_int
        except (OSError, AttributeError, ValueError):
            return
        self._mlock = mlock
        self._munlock = munlock

    def lock(self, buffer: ctypes.Array, size: int) -> bool:
        """Pin the buffer in physical memory, returning True on success."""

        if size <= 0:
            return False
        address = ctypes.addressof(buffer)
        if self._engine_lock is not None:
            try:
                result = self._engine_lock(buffer, size)
            except TypeError:
                try:
                    result = self._engine_lock(address, size)
                except (OSError, RuntimeError, ValueError):
                    result = False
            except (OSError, RuntimeError, ValueError):
                result = False
            if result:
                return True
        if self._virtual_lock is not None:
            return bool(self._virtual_lock(ctypes.c_void_p(address), size))
        if self._mlock is not None:
            return self._mlock(ctypes.c_void_p(address), size) == 0
        return False

    def unlock(self, buffer: ctypes.Array, size: int) -> bool:
        """Release the pin, returning True on success."""

        if size <= 0:
            return False
        address = ctypes.addressof(buffer)
        if self._engine_unlock is not None:
            try:
                result = self._engine_unlock(buffer, size)
            except TypeError:
                try:
                    result = self._engine_unlock(address, size)
                except (OSError, RuntimeError, ValueError):
                    result = False
            except (OSError, RuntimeError, ValueError):
                result = False
            if result:
                return True
        if self._virtual_unlock is not None:
            return bool(self._virtual_unlock(ctypes.c_void_p(address), size))
        if self._munlock is not None:
            return self._munlock(ctypes.c_void_p(address), size) == 0
        return False


@dataclass(slots=True)
class _Secret:
    """One stored secret: obfuscated bytes plus the mask that decodes them."""

    buffer: ctypes.Array
    mask: bytearray
    length: int
    locked: bool = False


class KeyVault:
    """Secret store with rotating masks and optional page pinning.

    Attributes:
        rotate_ms: Cadence of the mask rotation thread in milliseconds.
    """

    def __init__(self, *, rotate_ms: float = DEFAULT_ROTATE_MS, locker: PageLocker | None = None) -> None:
        if rotate_ms <= 0:
            raise ValueError("rotate_ms must be positive")
        self.rotate_ms = float(rotate_ms)
        self._locker = locker if locker is not None else PageLocker()
        self._secrets: dict[str, _Secret] = {}
        self._mutex = threading.RLock()
        self._rotations = 0
        self._rotation_thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._shredded = 0

    @property
    def locker(self) -> PageLocker:
        """The page locker used by this vault."""

        return self._locker

    @property
    def locked(self) -> bool:
        """True when every stored secret is currently pinned."""

        with self._mutex:
            return bool(self._secrets) and all(secret.locked for secret in self._secrets.values())

    @property
    def rotations(self) -> int:
        """Number of completed mask rotations."""

        with self._mutex:
            return self._rotations

    def __enter__(self) -> "KeyVault":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def store(self, name: str, secret: bytes) -> None:
        """Store a secret under an obfuscated buffer, replacing any previous value.

        Raises:
            KeyVaultError: When the secret is empty or the name is blank.
        """

        if not name:
            raise KeyVaultError("secret name must not be empty")
        material = bytes(secret)
        if not material:
            raise KeyVaultError("secret must not be empty")
        mask = bytearray(os.urandom(len(material)))
        obfuscated = bytes(left ^ right for left, right in zip(material, mask))
        buffer = (ctypes.c_ubyte * len(material)).from_buffer_copy(obfuscated)
        with self._mutex:
            previous = self._secrets.get(name)
            if previous is not None:
                self._release(previous)
            self._secrets[name] = _Secret(buffer=buffer, mask=mask, length=len(material))

    def retrieve(self, name: str) -> bytes:
        """Decode and return a stored secret.

        Raises:
            KeyError: When the name is unknown.
        """

        with self._mutex:
            secret = self._secrets.get(name)
            if secret is None:
                raise KeyError(name)
            return bytes(cell ^ mask for cell, mask in zip(secret.buffer, secret.mask))

    def stored_bytes(self, name: str) -> bytes:
        """Return the raw obfuscated bytes currently held in memory.

        This exists so the probe can prove that a rotation changed the resident
        bytes without learning the plaintext.
        """

        with self._mutex:
            secret = self._secrets.get(name)
            if secret is None:
                raise KeyError(name)
            return bytes(secret.buffer)

    def delete(self, name: str) -> bool:
        """Remove and shred a secret, returning True when it existed."""

        with self._mutex:
            secret = self._secrets.get(name)
            if secret is None:
                return False
            self._release(secret)
            del self._secrets[name]
            return True

    def shred(self, name: str) -> bool:
        """Alias for delete kept because zeroization is a named operation."""

        return self.delete(name)

    def _release(self, secret: _Secret) -> None:
        """Zeroize a secret buffer, unpin it and drop its mask."""

        try:
            for index in range(secret.length):
                secret.buffer[index] = 0
            if secret.locked:
                self._locker.unlock(secret.buffer, secret.length)
        except (OSError, ValueError, ctypes.ArgumentError):
            pass
        for index in range(len(secret.mask)):
            secret.mask[index] = 0
        secret.locked = False
        self._shredded += 1

    def rotate_once(self) -> int:
        """Re-mask every stored secret and return the new rotation counter.

        The plaintext is decoded inside the lock, re-encoded with a fresh
        os.urandom mask and written back, so an observer never sees a window where
        the buffer holds plaintext.
        """

        with self._mutex:
            for secret in self._secrets.values():
                plain = bytes(cell ^ mask for cell, mask in zip(secret.buffer, secret.mask))
                new_mask = bytearray(os.urandom(secret.length))
                for index in range(secret.length):
                    secret.buffer[index] = plain[index] ^ new_mask[index]
                secret.mask = new_mask
            self._rotations += 1
            return self._rotations

    def start_rotation(self) -> None:
        """Start the daemon rotation thread; idempotent."""

        with self._mutex:
            if self._rotation_thread is not None and self._rotation_thread.is_alive():
                return
            self._stop_event.clear()
            thread = threading.Thread(
                target=self._rotation_loop,
                name="tauhaulity-mask-rotator",
                daemon=True,
            )
            self._rotation_thread = thread
            thread.start()

    def stop_rotation(self, timeout: float = 2.0) -> None:
        """Stop the rotation thread and wait for it to exit."""

        self._stop_event.set()
        thread = self._rotation_thread
        if thread is not None and thread.is_alive():
            thread.join(timeout)

    def _rotation_loop(self) -> None:
        """Rotate on the configured cadence until the stop event fires."""

        interval = self.rotate_ms / 1000.0
        while not self._stop_event.wait(interval):
            try:
                self.rotate_once()
            except (OSError, RuntimeError, ValueError):
                # A failed rotation must not kill the daemon: keep the thread
                # alive and retry on the next tick so a transient allocation
                # failure cannot silently disable mask refreshing.
                continue

    def lock_pages(self) -> bool:
        """Pin every stored secret; returns True when all of them are pinned."""

        with self._mutex:
            if not self._secrets:
                return False
            success = True
            for secret in self._secrets.values():
                if secret.locked:
                    continue
                secret.locked = self._locker.lock(secret.buffer, secret.length)
                success = success and secret.locked
            return success and all(secret.locked for secret in self._secrets.values())

    def unlock_pages(self) -> bool:
        """Release every pin; returns True when all secrets are unpinned."""

        with self._mutex:
            if not self._secrets:
                return False
            success = True
            for secret in self._secrets.values():
                if not secret.locked:
                    continue
                unpinned = self._locker.unlock(secret.buffer, secret.length)
                if unpinned:
                    secret.locked = False
                success = success and unpinned
            return success

    def close(self) -> None:
        """Stop rotation, shred every secret and release the vault."""

        self.stop_rotation()
        with self._mutex:
            for secret in list(self._secrets.values()):
                self._release(secret)
            self._secrets.clear()

    def stats(self) -> dict[str, object]:
        """Operational diagnostics for the probe and for tests."""

        with self._mutex:
            return {
                "secrets": len(self._secrets),
                "rotations": self._rotations,
                "shredded": self._shredded,
                "locked": self.locked,
                "locker": self._locker.mechanism,
                "locker_available": self._locker.available,
                "rotate_ms": self.rotate_ms,
                "rotation_thread": bool(
                    self._rotation_thread is not None and self._rotation_thread.is_alive()
                ),
            }


def constant_time_compare(left: bytes, right: bytes) -> bool:
    """Compare two byte strings without a data dependent early exit.

    Every byte of the shorter input is folded into one accumulator, and the length
    difference is folded in as well. The loop trip count depends on the length, not
    on the content, which is the property a remote timing attacker would need to
    break the compare.
    """

    first = bytes(left)
    second = bytes(right)
    length_difference = len(first) ^ len(second)
    limit = min(len(first), len(second))
    accumulator = length_difference
    for index in range(limit):
        accumulator |= first[index] ^ second[index]
    return accumulator == 0


class TimeBucketEnforcer:
    """Quantize comparison latency so the response time carries no signal.

    The clock is QueryPerformanceCounter through the engine when present, otherwise
    the standard library monotonic nanosecond clock. Bucket padding only waits; it
    never changes the comparison result.

    Attributes:
        bucket_ns: Minimum latency every comparison is padded up to.
    """

    def __init__(self, bucket_ns: int = DEFAULT_BUCKET_NS, *, clock=None) -> None:
        if bucket_ns <= 0:
            raise ValueError("bucket_ns must be positive")
        self.bucket_ns = int(bucket_ns)
        self._clock, self.clock_name = _resolve_clock(clock)
        self.last_elapsed_ns = 0

    def quantized_compare(self, left: bytes, right: bytes, *, budget_ns: int = 5_000_000) -> bool:
        """Compare in constant time and pad the latency up to one bucket.

        Raises:
            ValueError: When budget_ns is not positive.
        """

        if budget_ns <= 0:
            raise ValueError("budget_ns must be positive")
        start = self._clock()
        result = constant_time_compare(left, right)
        deadline = start + self.bucket_ns
        while True:
            now = self._clock()
            if now >= deadline or now - start >= budget_ns:
                break
            if deadline - now > 250_000:
                time.sleep(0)
        self.last_elapsed_ns = max(0, self._clock() - start)
        return result


def _resolve_clock(clock):
    """Resolve the timestamp source: engine qpc first, monotonic ns otherwise."""

    if clock is not None:
        name = getattr(clock, "__name__", "custom")
        return clock, name
    engine = _load_engine()
    if engine is not None and str(getattr(engine, "backend", "")).lower() != "python":
        qpc = getattr(engine, "qpc", None)
        if callable(qpc):
            try:
                first = int(qpc())
                second = int(qpc())
            except (OSError, RuntimeError, ValueError, TypeError):
                first = second = None
            if first is not None and second is not None and second >= first:
                return (lambda: int(qpc())), "engine-qpc"
    return time.perf_counter_ns, "perf_counter_ns"


def probe(ctx: ScanContext) -> Finding:
    """Pin a temporary secret, prove mask rotation and report the protection state.

    The temporary secret is shredded before the function returns, and no rotation
    thread is started, so the probe has no side effects on the host process.
    """

    vault = KeyVault()
    enforcer = TimeBucketEnforcer()
    secret = os.urandom(_PROBE_SECRET_BYTES)
    try:
        vault.store("probe", secret)
        before = vault.stored_bytes("probe")
        vault.rotate_once()
        after = vault.stored_bytes("probe")
        recovered = vault.retrieve("probe")
        pinned = vault.lock_pages()
        pinned_state = vault.locked
        if pinned:
            vault.unlock_pages()
        compare_ok = constant_time_compare(secret, recovered) and not constant_time_compare(
            secret, bytes(_PROBE_SECRET_BYTES)
        )
        bucket_ok = enforcer.quantized_compare(secret, recovered)
        stats = vault.stats()
    except (OSError, RuntimeError, ValueError, KeyError, ctypes.ArgumentError) as exc:
        detail = f"key vault self-test raised {type(exc).__name__}: {exc}"
        return make_finding(
            SPEC,
            "WARNING",
            detail,
            risk=4.0,
            slots={"detail": detail},
            repro_hint="Store a 32 byte secret in KeyVault and rotate the mask once.",
        )
    finally:
        vault.close()

    rotated = before != after
    recovered_ok = recovered == secret
    mechanism = stats["locker"]
    if not rotated or not recovered_ok or not compare_ok or not bucket_ok:
        status = "WARNING"
        risk = 5.0
        detail = (
            "mask rotation or constant time compare failed "
            f"(rotated={rotated}, recovered={recovered_ok}, compare={compare_ok}, bucket={bucket_ok})"
        )
    elif pinned_state:
        status = "SAFE"
        risk = 0.0
        detail = (
            f"{_PROBE_SECRET_BYTES} byte secret pinned via {mechanism}; rotating XOR mask verified "
            f"({stats['rotations']} rotation), branchless compare and {enforcer.clock_name} bucket active"
        )
    else:
        status = "EXPOSED"
        risk = 6.5
        detail = (
            f"mlock/VirtualLock unavailable via {mechanism}: secret pages may reach swap or a crash "
            "dump even though the rotating mask works"
        )
    return make_finding(
        SPEC,
        status,
        detail,
        risk=risk,
        slots={"detail": detail},
        repro_hint="Dump the vault buffer before and after one rotation and compare the resident bytes.",
    )
