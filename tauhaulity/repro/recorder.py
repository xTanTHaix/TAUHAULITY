"""Bounded attack flight recorder that stores shared 128 byte telemetry frames.

The recorder deliberately does not keep arbitrary Python objects: every event is
packed into the same TelemetryFrame the pillars publish, so the flight recorder
cannot quietly drift from the wire format the rest of the engine depends on. The
frame digest holds a SHA-256 of the payload, which keeps replay evidence
verifiable without storing the payload twice.
"""

from __future__ import annotations

import hashlib
import os
import struct
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Final

from tauhaulity.core.entropy import shannon_entropy
from tauhaulity.core.telemetry import FRAME_SIZE, TelemetryFrame

_DIGEST_CHARS: Final[int] = 32


def _pack_frame(seq: int, kind: str, payload: bytes, entropy: float) -> bytes:
    """Pack one event into a verified 128 byte telemetry frame.

    The digest is the SHA-256 of the payload, the identifier carries the sequence
    number and payload length, and the slot id carries the event kind, so a reader
    can identify an event from the frame alone without the recorder object.
    """

    frame = TelemetryFrame(
        seqlock=0,
        timeout_ms=0,
        monotonic_ns=time.monotonic_ns(),
        # The mask field is reserved for OS/runtime primitive flags; a replay
        # event has none, and borrowing the field for a payload length would
        # misreport it to any reader that decodes the frame.
        mask=0,
        pid=os.getpid() & 0xFFFFFFFF,
        tid=threading.get_ident() & 0xFFFFFFFF,
        digest=hashlib.sha256(payload).digest(),
        identifier=struct.pack("<QQ", seq & 0xFFFFFFFFFFFFFFFF, len(payload)),
        pillar_mask=0,
        verdict=0,
        risk_q16=0,
        entropy_q16=int(round(entropy * 65536.0)) & 0xFFFFFFFF,
        slot_id=kind.encode("utf-8", errors="replace")[:24],
    )
    packed = frame.to_bytes()
    if len(packed) != FRAME_SIZE:
        raise RuntimeError(f"telemetry frame must be {FRAME_SIZE} bytes, got {len(packed)}")
    return packed


@dataclass(frozen=True, slots=True)
class ReplayEvent:
    """One recorded event, stored both as payload bytes and as a telemetry frame.

    Attributes:
        seq: One based sequence number assigned by the recorder.
        kind: Short event category such as "open", "pickle" or "socket".
        payload: Raw event bytes, truncated to the recorder payload limit.
        entropy: Shannon entropy of the payload in bits per byte.
        frame: The 128 byte TelemetryFrame serialization of this event.
    """

    seq: int
    kind: str
    payload: bytes
    entropy: float
    frame: bytes = b""

    @classmethod
    def create(cls, seq: int, kind: str, payload: bytes) -> "ReplayEvent":
        """Build an event including its telemetry frame.

        Parameters:
            seq: Sequence number.
            kind: Event category.
            payload: Raw payload bytes.

        Returns:
            A ReplayEvent with entropy and frame populated.
        """

        entropy = shannon_entropy(payload) if payload else 0.0
        return cls(
            seq=seq,
            kind=kind,
            payload=payload,
            entropy=entropy,
            frame=_pack_frame(seq, kind, payload, entropy),
        )

    def telemetry(self) -> TelemetryFrame:
        """Decode and integrity check the stored frame.

        Raises:
            FrameIntegrityError: When the stored frame was corrupted.
        """

        return TelemetryFrame.from_bytes(self.frame)

    def digest_hex(self) -> str:
        """Return the payload digest as stored inside the frame."""

        return hashlib.sha256(self.payload).hexdigest()


@dataclass(frozen=True, slots=True)
class ReplayCase:
    """An ordered set of events that reproduces one failure.

    Attributes:
        case_id: Stable identifier derived from the event digests.
        events: Events in sequence order. A minimized case keeps the original
            case_id so its lineage stays traceable.
        target: Project root the events were recorded against.
    """

    case_id: str
    events: tuple[ReplayEvent, ...]
    target: str = ""


class ReplayRecorder:
    """Bounded ring recorder for replayable attack evidence.

    Attributes:
        capacity: Maximum number of retained events.
        max_payload: Maximum payload bytes stored per event.
        target: Project root recorded into cases.
    """

    def __init__(self, capacity: int = 256, max_payload: int = 4096, *, target: str = "") -> None:
        """Create a recorder.

        Raises:
            ValueError: When capacity or max_payload is not positive.
        """

        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity <= 0:
            raise ValueError("capacity must be a positive integer")
        if isinstance(max_payload, bool) or not isinstance(max_payload, int) or max_payload <= 0:
            raise ValueError("max_payload must be a positive integer")
        self.capacity = capacity
        self.max_payload = max_payload
        self.target = str(target)
        self._events: deque[ReplayEvent] = deque()
        self._seq = 0
        self._recorded = 0
        self._evicted = 0
        self._truncated = 0

    def record(self, kind: str, payload: bytes) -> ReplayEvent:
        """Record one event, evicting the oldest event when the ring is full.

        Parameters:
            kind: Short event category, encoded into the frame slot id.
            payload: Raw bytes. Bytearray and memoryview are accepted and
                truncated to max_payload.

        Returns:
            The recorded ReplayEvent.

        Raises:
            TypeError: When kind is empty or payload is not bytes-like.
        """

        if not isinstance(kind, str) or not kind:
            raise TypeError("kind must be a non empty string")
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError("payload must be bytes-like")
        material = bytes(payload)
        if len(material) > self.max_payload:
            material = material[: self.max_payload]
            self._truncated += 1
        self._seq += 1
        event = ReplayEvent.create(self._seq, kind, material)
        if len(self._events) >= self.capacity:
            self._events.popleft()
            self._evicted += 1
        self._events.append(event)
        self._recorded += 1
        return event

    def case(self) -> ReplayCase:
        """Return the retained events as an immutable replay case.

        The case id is derived from the payload digests and the target, so two
        runs that observed the same event sequence produce the same identifier.
        """

        events = tuple(self._events)
        digest = hashlib.sha256()
        digest.update(self.target.encode("utf-8", errors="replace"))
        for event in events:
            # Hash the semantic event, not the frame trailer: the frame carries a
            # monotonic timestamp and a pid, which would make identical event
            # sequences hash differently on every run.
            digest.update(struct.pack("<Q", event.seq & 0xFFFFFFFFFFFFFFFF))
            digest.update(event.kind.encode("utf-8", errors="replace"))
            digest.update(hashlib.sha256(event.payload).digest())
        return ReplayCase(
            case_id=digest.hexdigest()[:_DIGEST_CHARS],
            events=events,
            target=self.target,
        )

    def reset(self) -> None:
        """Drop retained events and restart sequence numbering."""

        self._events.clear()
        self._seq = 0
        self._recorded = 0
        self._evicted = 0
        self._truncated = 0

    def stats(self) -> dict[str, float | int]:
        """Return recorder counters for diagnostics and the dossier slots.

        mean_entropy is the average payload entropy of the retained window, which
        a reviewer uses to spot high entropy payloads without opening the case.
        """

        stored = len(self._events)
        payload_bytes = sum(len(event.payload) for event in self._events)
        mean_entropy = (
            sum(event.entropy for event in self._events) / stored if stored else 0.0
        )
        return {
            "capacity": self.capacity,
            "max_payload": self.max_payload,
            "recorded": self._recorded,
            "stored": stored,
            "evicted": self._evicted,
            "truncated": self._truncated,
            "payload_bytes": payload_bytes,
            "mean_entropy": round(mean_entropy, 6),
            "last_seq": self._seq,
        }


__all__ = ["ReplayCase", "ReplayEvent", "ReplayRecorder"]
