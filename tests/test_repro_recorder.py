"""Tests for the replay recorder and the delta debugging minimizer."""

from __future__ import annotations

import hashlib

import pytest

from tauhaulity.core.telemetry import FRAME_SIZE, TelemetryFrame
from tauhaulity.repro.minimizer import MinimizedCase, delta_minimize
from tauhaulity.repro.recorder import ReplayCase, ReplayEvent, ReplayRecorder


def test_recorded_event_carries_a_valid_128_byte_frame() -> None:
    recorder = ReplayRecorder()
    event = recorder.record("socket", b"hello telemetry")
    assert isinstance(event, ReplayEvent)
    assert event.seq == 1
    assert event.kind == "socket"
    assert len(event.frame) == FRAME_SIZE
    frame = TelemetryFrame.from_bytes(event.frame)
    assert frame.digest == hashlib.sha256(b"hello telemetry").digest()
    assert frame.identifier[:8] == (1).to_bytes(8, "little")
    assert frame.slot_id.startswith(b"socket")
    assert event.digest_hex() == hashlib.sha256(b"hello telemetry").hexdigest()


def test_case_is_deterministic_for_the_same_events_and_target() -> None:
    first = ReplayRecorder(target="project")
    second = ReplayRecorder(target="project")
    for recorder in (first, second):
        recorder.record("open", b"/etc/passwd")
        recorder.record("exec", b"python")
    assert first.case().case_id == second.case().case_id
    assert first.case().case_id != ReplayRecorder(target="other").case().case_id
    assert len(first.case().case_id) == 32


def test_capacity_evicts_oldest_events_and_keeps_sequence_numbers() -> None:
    recorder = ReplayRecorder(capacity=2)
    for index in range(4):
        recorder.record("log", bytes([index]))
    case = recorder.case()
    assert [event.seq for event in case.events] == [3, 4]
    stats = recorder.stats()
    assert stats["recorded"] == 4
    assert stats["evicted"] == 2
    assert stats["stored"] == 2
    assert stats["last_seq"] == 4


def test_max_payload_truncates_and_counts() -> None:
    recorder = ReplayRecorder(max_payload=4)
    event = recorder.record("blob", b"0123456789")
    assert event.payload == b"0123"
    assert recorder.stats()["truncated"] == 1
    assert recorder.stats()["payload_bytes"] == 4


def test_stats_report_entropy_of_retained_window() -> None:
    recorder = ReplayRecorder()
    recorder.record("text", b"aaaa")
    stats = recorder.stats()
    assert stats["mean_entropy"] == 0.0
    recorder.record("random", bytes(range(256)))
    assert recorder.stats()["mean_entropy"] > 0.0


def test_reset_clears_events_and_restarts_sequence() -> None:
    recorder = ReplayRecorder()
    recorder.record("log", b"one")
    recorder.reset()
    assert recorder.case().events == ()
    assert recorder.stats()["last_seq"] == 0
    assert recorder.record("log", b"two").seq == 1


def test_record_validates_arguments() -> None:
    recorder = ReplayRecorder()
    with pytest.raises(TypeError):
        recorder.record("", b"payload")
    with pytest.raises(TypeError):
        recorder.record("kind", "text")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        ReplayRecorder(capacity=0)
    with pytest.raises(ValueError):
        ReplayRecorder(max_payload=0)
    with pytest.raises(ValueError):
        ReplayRecorder(capacity=True)  # type: ignore[arg-type]


def _case(payloads: list[bytes]) -> ReplayCase:
    events = tuple(
        ReplayEvent.create(index + 1, "log", payload)
        for index, payload in enumerate(payloads)
    )
    return ReplayCase(case_id="case-1", events=events, target="project")


def test_ddmin_reduces_synthetic_failure_to_single_trigger() -> None:
    case = _case([b"noise", b"noise", b"TRIGGER", b"noise", b"noise"])
    result = delta_minimize(
        case,
        lambda candidate: any(b"TRIGGER" in event.payload for event in candidate.events),
    )
    assert isinstance(result, MinimizedCase)
    assert [event.payload for event in result.case.events] == [b"TRIGGER"]
    assert result.removed == 4
    assert result.iterations > 0
    assert result.case.case_id == "case-1"


def test_ddmin_keeps_both_events_when_the_failure_needs_a_pair() -> None:
    case = _case([b"noise", b"A", b"noise", b"B", b"noise", b"noise"])

    def reproduces(candidate: ReplayCase) -> bool:
        payloads = [event.payload for event in candidate.events]
        return b"A" in payloads and b"B" in payloads

    result = delta_minimize(case, reproduces)
    payloads = [event.payload for event in result.case.events]
    assert payloads == [b"A", b"B"]
    assert result.removed == 4


def test_ddmin_returns_single_event_unchanged() -> None:
    case = _case([b"only"])
    result = delta_minimize(case, lambda candidate: bool(candidate.events))
    assert [event.payload for event in result.case.events] == [b"only"]
    assert result.removed == 0
    assert result.iterations == 0


def test_ddmin_validates_inputs() -> None:
    with pytest.raises(TypeError):
        delta_minimize(_case([b"x"]), "not callable")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        delta_minimize(_case([]), lambda candidate: True)


def test_ddmin_predicate_receives_cases_not_lists() -> None:
    seen: list[ReplayCase] = []

    def predicate(candidate: ReplayCase) -> bool:
        seen.append(candidate)
        return True

    delta_minimize(_case([b"a", b"b", b"c"]), predicate)
    assert seen
    assert all(isinstance(candidate, ReplayCase) for candidate in seen)
