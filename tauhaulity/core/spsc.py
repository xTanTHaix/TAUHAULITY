"""Single producer single consumer ring buffer for high rate pillar events.

The engine must ingest far more events than it renders into a dossier. A ring
with monotonic head and tail counters gives constant time append and drain
without locks, provided the documented single-producer and single-consumer
contract is respected. Violations are detected and reported instead of silently
corrupting the stream.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Final

DEFAULT_CAPACITY: Final[int] = 1024
DEFAULT_SLOT_BYTES: Final[int] = 128


class PayloadTooLarge(ValueError):
    """Raised when a payload does not fit into one ring slot."""


class ProducerViolation(RuntimeError):
    """Raised when a second thread attempts to produce concurrently."""


class ConsumerViolation(RuntimeError):
    """Raised when a second thread attempts to consume concurrently."""


@dataclass(slots=True)
class RingStats:
    """Counters describing ring utilisation and losses."""

    capacity: int
    produced: int
    consumed: int
    dropped: int
    high_water: int


class SpscRing:
    """Fixed capacity byte ring implementing the SPSC contract.

    Attributes:
        capacity: Usable number of slots; one extra slot separates full from empty.
    """

    def __init__(self, capacity: int = DEFAULT_CAPACITY, slot_bytes: int = DEFAULT_SLOT_BYTES) -> None:
        if capacity < 2:
            raise ValueError("capacity must be at least two")
        if slot_bytes < 1:
            raise ValueError("slot_bytes must be positive")
        self._capacity = int(capacity)
        self._slot_bytes = int(slot_bytes)
        self._slots: list[bytes] = [b""] * (capacity + 1)
        self._head = 0
        self._tail = 0
        self._produced = 0
        self._consumed = 0
        self._dropped = 0
        self._high_water = 0
        self._producer_thread: int | None = None
        self._consumer_thread: int | None = None
        self._closed = False

    def __len__(self) -> int:
        """Return the number of queued items."""

        return (self._head - self._tail) % (self._capacity + 1)

    @property
    def full(self) -> bool:
        """Return True when the next put would fail."""

        return (self._head + 1) % (self._capacity + 1) == self._tail

    @property
    def empty(self) -> bool:
        """Return True when no item is queued."""

        return self._head == self._tail

    @property
    def slot_bytes(self) -> int:
        """Maximum payload size accepted per slot."""

        return self._slot_bytes

    def put(self, payload: bytes) -> bool:
        """Append a payload, returning False when the ring is full.

        Raises:
            PayloadTooLarge: When the payload exceeds the slot size.
            ProducerViolation: When called by a thread other than the first producer.
            RuntimeError: When the ring has been closed.
        """

        if self._closed:
            raise RuntimeError("ring is closed")
        current = threading.get_ident()
        if self._producer_thread is None:
            self._producer_thread = current
        elif self._producer_thread != current:
            raise ProducerViolation("ring has a single producer by contract")
        material = bytes(payload)
        if len(material) > self._slot_bytes:
            raise PayloadTooLarge(f"payload of {len(material)} bytes exceeds slot of {self._slot_bytes}")
        if self.full:
            self._dropped += 1
            return False
        self._slots[self._head] = material
        self._head = (self._head + 1) % (self._capacity + 1)
        self._produced += 1
        depth = len(self)
        if depth > self._high_water:
            self._high_water = depth
        return True

    def get(self) -> bytes | None:
        """Pop the oldest payload or return None when empty.

        Raises:
            ConsumerViolation: When called by a thread other than the first consumer.
            RuntimeError: When the ring has been closed.
        """

        if self._closed:
            raise RuntimeError("ring is closed")
        current = threading.get_ident()
        if self._consumer_thread is None:
            self._consumer_thread = current
        elif self._consumer_thread != current:
            raise ConsumerViolation("ring has a single consumer by contract")
        if self.empty:
            return None
        payload = self._slots[self._tail]
        self._slots[self._tail] = b""
        self._tail = (self._tail + 1) % (self._capacity + 1)
        self._consumed += 1
        return payload

    def drain(self, limit: int | None = None) -> list[bytes]:
        """Remove up to limit payloads and return them oldest first."""

        drained: list[bytes] = []
        while limit is None or len(drained) < limit:
            item = self.get()
            if item is None:
                break
            drained.append(item)
        return drained

    def stats(self) -> RingStats:
        """Return the current counters as an immutable record."""

        return RingStats(
            capacity=self._capacity,
            produced=self._produced,
            consumed=self._consumed,
            dropped=self._dropped,
            high_water=self._high_water,
        )

    def close(self) -> None:
        """Release references and reject further use."""

        self._closed = True
        self._slots = []
