"""SPSC ring tests: FIFO order, backpressure accounting and contract violations."""

from __future__ import annotations

import threading

import pytest

from tauhaulity.core.spsc import (
    ConsumerViolation,
    PayloadTooLarge,
    ProducerViolation,
    SpscRing,
)


def test_fifo_order_and_drain() -> None:
    ring = SpscRing(capacity=4, slot_bytes=8)
    for index in range(3):
        assert ring.put(bytes([index]))
    assert [int.from_bytes(item, "little") for item in ring.drain()] == [0, 1, 2]
    assert ring.empty


def test_full_ring_drops_and_counts() -> None:
    ring = SpscRing(capacity=2, slot_bytes=4)
    assert ring.put(b"a")
    assert ring.put(b"b")
    assert not ring.put(b"c")
    stats = ring.stats()
    assert stats.dropped == 1
    assert stats.high_water == 2
    assert len(ring) == 2


def test_oversized_payload_rejected() -> None:
    ring = SpscRing(capacity=2, slot_bytes=2)
    with pytest.raises(PayloadTooLarge):
        ring.put(b"toolarge")


def test_closed_ring_rejects_use() -> None:
    ring = SpscRing(capacity=2)
    ring.close()
    with pytest.raises(RuntimeError):
        ring.put(b"x")
    with pytest.raises(RuntimeError):
        ring.get()


def test_producer_thread_violation_detected() -> None:
    ring = SpscRing(capacity=4)
    ring.put(b"main")
    errors: list[BaseException] = []

    def produce() -> None:
        try:
            ring.put(b"other")
        except BaseException as exc:  # capture for the assertion below
            errors.append(exc)

    thread = threading.Thread(target=produce)
    thread.start()
    thread.join(timeout=5)
    assert errors and isinstance(errors[0], ProducerViolation)


def test_consumer_thread_violation_detected() -> None:
    ring = SpscRing(capacity=4)
    ring.put(b"main")
    assert ring.get() == b"main"
    ring.put(b"again")
    errors: list[BaseException] = []

    def consume() -> None:
        try:
            ring.get()
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=consume)
    thread.start()
    thread.join(timeout=5)
    assert errors and isinstance(errors[0], ConsumerViolation)


def test_single_producer_single_consumer_stream() -> None:
    ring = SpscRing(capacity=64, slot_bytes=8)
    received: list[bytes] = []
    done = threading.Event()

    def producer() -> None:
        for index in range(500):
            while not ring.put(index.to_bytes(8, "little")):
                pass
        done.set()

    def consumer() -> None:
        while not done.is_set() or not ring.empty:
            item = ring.get()
            if item is not None:
                received.append(item)

    threads = [threading.Thread(target=producer), threading.Thread(target=consumer)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
    assert len(received) == 500
    assert [int.from_bytes(item, "little") for item in received] == list(range(500))
