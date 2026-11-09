"""Fixed 128 byte telemetry frame shared by the pillars and the flight recorder.

The frame is a cache line sized record so that a writer can publish one pillar
event with a single 128 byte store. Integrity is self contained: a CRC64 over
the 120 byte body plus a parity byte lets a reader reject a half written or bit
rotted frame without trusting any external source of truth.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Final

FRAME_SIZE: Final[int] = 128
FRAME_BODY_SIZE: Final[int] = 120
FRAME_BODY_FORMAT: Final[str] = "<IIQQII32s16sIB3xQ24s"

_checked = struct.calcsize(FRAME_BODY_FORMAT)
if _checked != FRAME_BODY_SIZE:
    raise RuntimeError(f"telemetry body must be {FRAME_BODY_SIZE} bytes, got {_checked}")

_CRC_POLY: Final[int] = 0x42F0E1EBA9EA3693
_CRC_MASK56: Final[int] = (1 << 56) - 1


def _build_crc_table() -> tuple[int, ...]:
    table: list[int] = []
    for index in range(256):
        value = index
        for _ in range(8):
            value = (value >> 1) ^ _CRC_POLY if value & 1 else value >> 1
        table.append(value & 0xFFFFFFFFFFFFFFFF)
    return tuple(table)


_CRC_TABLE: Final[tuple[int, ...]] = _build_crc_table()


def crc64(data: bytes) -> int:
    """Return the reflected CRC64 of a byte string.

    The table driven form is used because frames are produced on every pillar
    event and a bitwise loop would be an order of magnitude slower.
    """

    value = 0
    for byte in data:
        value = _CRC_TABLE[(value ^ byte) & 0xFF] ^ (value >> 8)
    return value & 0xFFFFFFFFFFFFFFFF


def parity_byte(data: bytes) -> int:
    """Return the XOR parity of every byte in the buffer.

    A parity check catches an even number of flipped bits that a CRC could in
    principle mask when the frame is copied through a lossy channel.
    """

    parity = 0
    for byte in data:
        parity ^= byte
    return parity & 0xFF


class FrameIntegrityError(ValueError):
    """Raised when a serialized frame fails its CRC or parity verification."""


@dataclass(slots=True)
class TelemetryFrame:
    """One cache aligned telemetry record.

    Attributes:
        seqlock: Even when stable, odd while a writer owns the frame.
        timeout_ms: Millisecond deadline after which a reader may reclaim the lock.
        monotonic_ns: Writer side monotonic timestamp in nanoseconds.
        mask: Bitmask of OS, runtime and hardware primitives.
        pid: Writer process id used for liveness verification.
        tid: Writer thread id used for liveness verification.
        digest: 256 bit digest of the recorded page or capability set.
        identifier: 128 bit address, inode or port identifier.
        pillar_mask: Bitmask of pillar verdicts.
        verdict: Dossier verdict code (0 safe, 1 at risk, 2 critical).
        risk_q16: Risk score scaled to Q16.16 precision.
        entropy_q16: Sliding window entropy scaled to Q16.16 precision.
        slot_id: 192 bit dossier slot, repro script and remediation template id.
    """

    seqlock: int = 0
    timeout_ms: int = 0
    monotonic_ns: int = 0
    mask: int = 0
    pid: int = 0
    tid: int = 0
    digest: bytes = field(default_factory=lambda: bytes(32))
    identifier: bytes = field(default_factory=lambda: bytes(16))
    pillar_mask: int = 0
    verdict: int = 0
    risk_q16: int = 0
    entropy_q16: int = 0
    slot_id: bytes = field(default_factory=lambda: bytes(24))

    def to_bytes(self) -> bytes:
        """Serialize the frame including its integrity trailer.

        Returns:
            Exactly 128 bytes.
        """

        body = self.pack_body()
        return body + self._trailer(body)

    def pack_body(self) -> bytes:
        """Serialize the 120 byte body without the integrity trailer."""

        return struct.pack(
            FRAME_BODY_FORMAT,
            self.seqlock & 0xFFFFFFFF,
            self.timeout_ms & 0xFFFFFFFF,
            self.monotonic_ns & 0xFFFFFFFFFFFFFFFF,
            self.mask & 0xFFFFFFFFFFFFFFFF,
            self.pid & 0xFFFFFFFF,
            self.tid & 0xFFFFFFFF,
            self._pad(self.digest, 32),
            self._pad(self.identifier, 16),
            self.pillar_mask & 0xFFFFFFFF,
            self.verdict & 0xFF,
            (self.risk_q16 & 0xFFFFFFFF) << 32 | (self.entropy_q16 & 0xFFFFFFFF),
            self._pad(self.slot_id, 24),
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> "TelemetryFrame":
        """Deserialize and verify a frame.

        Raises:
            FrameIntegrityError: When the length, CRC or parity does not match.
        """

        if len(data) != FRAME_SIZE:
            raise FrameIntegrityError(f"frame must be {FRAME_SIZE} bytes, got {len(data)}")
        body, trailer = data[:FRAME_BODY_SIZE], data[FRAME_BODY_SIZE:]
        if trailer != cls._trailer(body):
            raise FrameIntegrityError("frame CRC64 or parity mismatch")
        return cls.parse_unchecked(body)

    @classmethod
    def parse_unchecked(cls, body: bytes) -> "TelemetryFrame":
        """Deserialize the 120 byte body without verifying the trailer.

        Raises:
            FrameIntegrityError: When the body has the wrong length.
        """

        if len(body) != FRAME_BODY_SIZE:
            raise FrameIntegrityError(f"frame body must be {FRAME_BODY_SIZE} bytes, got {len(body)}")
        (
            seqlock,
            timeout_ms,
            monotonic_ns,
            mask,
            pid,
            tid,
            digest,
            identifier,
            pillar_mask,
            verdict,
            packed,
            slot_id,
        ) = struct.unpack(FRAME_BODY_FORMAT, body)
        return cls(
            seqlock=seqlock,
            timeout_ms=timeout_ms,
            monotonic_ns=monotonic_ns,
            mask=mask,
            pid=pid,
            tid=tid,
            digest=digest,
            identifier=identifier,
            pillar_mask=pillar_mask,
            verdict=verdict,
            risk_q16=(packed >> 32) & 0xFFFFFFFF,
            entropy_q16=packed & 0xFFFFFFFF,
            slot_id=slot_id,
        )

    @staticmethod
    def _trailer(body: bytes) -> bytes:
        crc = crc64(body) & _CRC_MASK56
        stamp = (crc << 8) | parity_byte(body)
        return struct.pack("<Q", stamp)

    @staticmethod
    def _pad(value: bytes, size: int) -> bytes:
        material = bytes(value or b"")
        if len(material) == size:
            return material
        if len(material) > size:
            return material[:size]
        return material + bytes(size - len(material))

    def is_stable(self) -> bool:
        """Return True when no writer holds the frame."""

        return self.seqlock % 2 == 0


def pack_score(risk: float, entropy: float) -> int:
    """Pack a risk score and an entropy score into one 64 bit Q16.16 integer.

    Raises:
        ValueError: When either score is negative.
    """

    if risk < 0 or entropy < 0:
        raise ValueError("scores must not be negative")
    risk_q16 = int(round(risk * 65536.0)) & 0xFFFFFFFF
    entropy_q16 = int(round(entropy * 65536.0)) & 0xFFFFFFFF
    return (risk_q16 << 32) | entropy_q16


def unpack_score(packed: int) -> tuple[float, float]:
    """Split a packed score word back into risk and entropy floats."""

    packed &= 0xFFFFFFFFFFFFFFFF
    return (packed >> 32) / 65536.0, (packed & 0xFFFFFFFF) / 65536.0
