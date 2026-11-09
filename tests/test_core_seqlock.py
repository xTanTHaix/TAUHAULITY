"""Sequence lock tests: consistent reads, dead writer recovery and stall detection."""

from __future__ import annotations

import os
import sys
import threading
import time

import pytest

from tauhaulity.core.seqlock import PidVerifiedSeqLock, SeqLockTimeout, process_alive


def test_read_before_write_returns_none() -> None:
    lock = PidVerifiedSeqLock()
    assert lock.read() is None


def test_write_then_read_returns_snapshot() -> None:
    lock = PidVerifiedSeqLock()
    lock.write(b"hello")
    assert lock.read() == b"hello"
    lock.write(b"world")
    assert lock.read() == b"world"


def test_non_bytes_payload_rejected() -> None:
    lock = PidVerifiedSeqLock()
    with pytest.raises(ValueError):
        lock.write("text")  # type: ignore[arg-type]


def test_process_alive_sees_current_process() -> None:
    assert process_alive(os.getpid()) is True


def test_process_alive_reports_missing_pid() -> None:
    assert process_alive(999_999_999) is False
    assert process_alive(0) is False
    assert process_alive(-5) is False


def test_process_alive_tracks_a_real_child() -> None:
    import subprocess

    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
    try:
        assert process_alive(child.pid) is True
    finally:
        child.terminate()
        child.wait(timeout=30)
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline and process_alive(child.pid):
        time.sleep(0.02)
    assert process_alive(child.pid) is False


def test_dead_writer_is_reclaimed() -> None:
    lock = PidVerifiedSeqLock(timeout_ms=1)
    lock.write(b"payload")
    dead_pid = 999_999_999
    assert not process_alive(dead_pid)
    lock.inject_torn_state(dead_pid, age_ms=25)
    assert lock.read() == b"payload"
    assert lock.recoveries >= 1


def test_live_writer_stall_raises_timeout() -> None:
    lock = PidVerifiedSeqLock(timeout_ms=1, max_retries=8)
    lock.inject_torn_state(os.getpid(), age_ms=25)
    with pytest.raises(SeqLockTimeout):
        lock.read()
    assert lock.try_read() is None


def test_reset_clears_odd_ticket() -> None:
    lock = PidVerifiedSeqLock()
    lock.write(b"x")
    lock.inject_torn_state(1234)
    assert lock.ticket % 2 == 1
    lock.reset()
    assert lock.ticket % 2 == 0


def test_concurrent_readers_never_observe_torn_payload() -> None:
    lock = PidVerifiedSeqLock(timeout_ms=50)
    stop = threading.Event()
    failures: list[str] = []

    def writer() -> None:
        for index in range(400):
            lock.write(f"{index:08d}".encode("ascii"))
        stop.set()

    def reader() -> None:
        while not stop.is_set():
            payload = lock.read()
            if payload is None:
                continue
            if len(payload) != 8 or not payload.isdigit():
                failures.append(repr(payload))
                return
            time.sleep(0)

    threads = [threading.Thread(target=writer) for _ in range(1)]
    threads += [threading.Thread(target=reader) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert not failures
    assert lock.read() is not None
