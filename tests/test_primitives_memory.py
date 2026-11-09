"""Memory primitive tests: page pins, protection probes, dirty pages, counter.

These tests must hold on both Windows and Linux without administrator rights.
A refused page pin is a legitimate answer (RLIMIT_MEMLOCK, working set quota),
so the assertions are about safety and shape: booleans, no exceptions, and a
dirty page count that is either a real count or the documented -1.
"""

from __future__ import annotations

import ctypes
import mmap
import os

import pytest

from tauhaulity.primitives import loader


@pytest.fixture()
def engine():
    """Return a freshly constructed engine and drop the cache afterwards."""

    loader._reset_engine()
    built = loader.get_engine()
    try:
        yield built
    finally:
        loader._reset_engine()


def test_lock_and_unlock_round_trip(engine) -> None:
    buffer = bytearray(4096)
    locked = engine.lock_pages(buffer)
    assert isinstance(locked, bool)
    if locked:
        assert engine.unlock_pages(buffer) is True


def test_lock_round_trip_on_a_page_owned_mapping(engine) -> None:
    region = mmap.mmap(-1, mmap.PAGESIZE)
    try:
        locked = engine.lock_pages(region)
        assert isinstance(locked, bool)
        if locked:
            assert engine.unlock_pages(region) is True
    finally:
        region.close()


def test_lock_round_trip_on_a_ctypes_buffer(engine) -> None:
    buffer = ctypes.create_string_buffer(4096)
    locked = engine.lock_pages(buffer)
    assert isinstance(locked, bool)
    if locked:
        assert engine.unlock_pages(buffer) is True


def test_lock_accepts_a_raw_address_with_an_explicit_size(engine) -> None:
    buffer = ctypes.create_string_buffer(4096)
    address = ctypes.addressof(buffer)
    locked = engine.lock_pages(address, 4096)
    assert isinstance(locked, bool)
    if locked:
        assert engine.unlock_pages(address, 4096) is True


def test_lock_rejects_read_only_and_degenerate_inputs(engine) -> None:
    assert engine.lock_pages(b"immutable bytes") is False
    assert engine.lock_pages(b"") is False
    assert engine.lock_pages(bytearray()) is False
    assert engine.lock_pages(None) is False
    assert engine.lock_pages(object()) is False
    assert engine.lock_pages({"not": "a buffer"}) is False
    assert engine.lock_pages(0) is False
    assert engine.lock_pages(bytearray(64), 4096) is False
    assert engine.unlock_pages(b"immutable bytes") is False


def test_protection_probe_reports_supported_surface(engine) -> None:
    status = engine.page_seal_status()
    assert isinstance(status, dict) and status
    for key, value in status.items():
        assert isinstance(key, str) and key
        assert isinstance(value, str) and value
    assert status["backend"] == engine.backend
    for key in ("lock_pages", "unlock_pages", "protect_pages", "dirty_pages", "qpc"):
        assert key in status
    assert status["qpc"] in {"native", "ctypes", "stdlib"}


def test_dirty_pages_returns_a_count_or_minus_one(engine) -> None:
    measured = engine.dirty_pages(os.getpid())
    assert isinstance(measured, int)
    assert measured == -1 or measured >= 0


def test_dirty_pages_normalises_bad_pids(engine) -> None:
    for pid in (0, -1, -999, "nonsense", None):
        measured = engine.dirty_pages(pid)  # type: ignore[arg-type]
        assert isinstance(measured, int)
        assert measured == -1 or measured >= 0
    missing = engine.dirty_pages(2_000_000_000)
    assert missing == -1 or missing >= 0


def test_qpc_is_monotonic_over_a_thousand_calls(engine) -> None:
    previous = engine.qpc()
    assert isinstance(previous, int)
    for _ in range(1000):
        current = engine.qpc()
        assert isinstance(current, int)
        assert current >= previous
        previous = current


def test_qpc_agrees_with_the_platform_module(engine) -> None:
    module = engine._platform_module()
    if module is None:
        pytest.skip("this host exposes no ctypes hardware counter")
    if engine._lib is not None:
        # A verified native build was selected on this host, so the ctypes
        # counter tier would otherwise never be exercised here. Retiring the
        # handle on purpose is what the tier switch does at runtime anyway, and
        # it keeps this assertion honest on Windows where the rust tier is now
        # the default.
        engine._downgrade("test: retire the native handle on purpose")
    assert engine.backend == "ctypes"
    assert engine._lib is None
    assert abs(engine.qpc() - int(module.qpc())) < 10_000_000_000_000


def test_close_twice_leaves_the_engine_usable(engine) -> None:
    engine.close()
    engine.close()
    assert engine.closed is True
    assert engine.available is False
    assert isinstance(engine.qpc(), int)
    assert engine.dirty_pages(os.getpid()) == -1 or engine.dirty_pages(os.getpid()) >= 0


def test_forced_python_backend_disables_page_primitives(monkeypatch) -> None:
    monkeypatch.setenv(loader.DISABLE_NATIVE_ENV, "1")
    loader._reset_engine()
    try:
        engine = loader.get_engine()
        assert engine.lock_pages(bytearray(4096)) is False
        assert engine.unlock_pages(bytearray(4096)) is False
        assert engine.dirty_pages(os.getpid()) == -1
        status = engine.page_seal_status()
        assert status["lock_pages"].startswith("disabled")
        assert status["qpc"] == "stdlib"
        assert isinstance(engine.qpc(), int)
    finally:
        loader._reset_engine()


def test_page_operations_do_not_corrupt_neighbouring_memory(engine) -> None:
    keeper = bytearray(b"neighbour data" * 64)
    buffer = bytearray(b"page data" * 512)
    locked = engine.lock_pages(buffer)
    assert isinstance(locked, bool)
    if locked:
        engine.unlock_pages(buffer)
    assert keeper.startswith(b"neighbour data")
    assert buffer.startswith(b"page data")