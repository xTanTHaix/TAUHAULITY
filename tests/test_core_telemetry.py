"""Telemetry frame tests: exact size, roundtrip fidelity and tamper rejection."""

from __future__ import annotations

import struct

import pytest

from tauhaulity.core.telemetry import (
    FRAME_BODY_SIZE,
    FRAME_SIZE,
    FrameIntegrityError,
    TelemetryFrame,
    crc64,
    pack_score,
    parity_byte,
    unpack_score,
)


def test_frame_is_exactly_one_cache_line() -> None:
    assert FRAME_SIZE == 128
    assert FRAME_BODY_SIZE == 120
    frame = TelemetryFrame()
    assert len(frame.to_bytes()) == 128


def test_roundtrip_preserves_every_field() -> None:
    frame = TelemetryFrame(
        seqlock=2,
        timeout_ms=5,
        monotonic_ns=123456789,
        mask=0b1010,
        pid=4321,
        tid=99,
        digest=bytes(range(32)),
        identifier=b"identifier-16byt",
        pillar_mask=0b101010101010,
        verdict=2,
        risk_q16=65536 * 4,
        entropy_q16=65536 * 7,
        slot_id=b"slot-24-bytes-exactly-ok",
    )
    restored = TelemetryFrame.from_bytes(frame.to_bytes())
    assert restored.seqlock == frame.seqlock
    assert restored.timeout_ms == frame.timeout_ms
    assert restored.monotonic_ns == frame.monotonic_ns
    assert restored.mask == frame.mask
    assert restored.pid == frame.pid
    assert restored.tid == frame.tid
    assert restored.digest == frame.digest
    assert restored.identifier == frame.identifier
    assert restored.pillar_mask == frame.pillar_mask
    assert restored.verdict == frame.verdict
    assert restored.risk_q16 == frame.risk_q16
    assert restored.entropy_q16 == frame.entropy_q16
    assert restored.slot_id == frame.slot_id


def test_corrupted_body_is_rejected() -> None:
    raw = bytearray(TelemetryFrame(pid=7, tid=8).to_bytes())
    raw[40] ^= 0xFF
    with pytest.raises(FrameIntegrityError):
        TelemetryFrame.from_bytes(bytes(raw))


def test_bad_length_is_rejected() -> None:
    with pytest.raises(FrameIntegrityError):
        TelemetryFrame.from_bytes(b"short")
    with pytest.raises(FrameIntegrityError):
        TelemetryFrame.parse_unchecked(b"short")


def test_trailer_combines_crc_and_parity() -> None:
    body = bytes(range(120))
    trailer = struct.unpack("<Q", TelemetryFrame._trailer(body))[0]
    assert (trailer >> 8) == (crc64(body) & ((1 << 56) - 1))
    assert (trailer & 0xFF) == parity_byte(body)


def test_default_frame_is_stable() -> None:
    assert TelemetryFrame().is_stable()
    assert not TelemetryFrame(seqlock=1).is_stable()


def test_score_packing_roundtrip() -> None:
    packed = pack_score(4.5, 7.25)
    risk, entropy = unpack_score(packed)
    assert abs(risk - 4.5) < 1e-4
    assert abs(entropy - 7.25) < 1e-4
    with pytest.raises(ValueError):
        pack_score(-1.0, 0.0)
