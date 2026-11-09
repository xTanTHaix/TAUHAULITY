"""Cross backend parity: rust, ctypes and python must be indistinguishable.

The dossier prints digests and entropy values, so a tier switch must never
change a verdict. Every backend is compared against hashlib, the shared CRC-64
table and the shared entropy implementation, and the golden values below pin the
Python reference itself.
"""

from __future__ import annotations

import hashlib
import random

import pytest

from tauhaulity.core.entropy import shannon_entropy
from tauhaulity.core.telemetry import crc64
from tauhaulity.primitives import loader

#: Golden SHA-256 digests from FIPS 180-4.
SHA_GOLDEN = {
    b"": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    b"abc": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq": (
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
    ),
}

#: Golden reflected CRC-64 values produced by tauhaulity.core.telemetry.crc64.
CRC_GOLDEN = {
    b"": 0x0,
    b"a": 0x6E77A179CB48B4D6,
    b"abc": 0x4E585630ADB2B002,
    b"123456789": 0x4DB9A9F87EC10C59,
    b"The quick brown fox jumps over the lazy dog": 0x7801C8EB84EC729C,
    bytes(range(256)): 0x2389D28AD35EEED9,
    b"hello world": 0x296DF20E6A9984C1,
}

#: Deterministic payloads shared by every parity comparison.
PAYLOADS = (
    b"",
    b"a",
    b"abc",
    b"hello world",
    bytes(range(256)),
    bytes(range(256)) * 8,
    b"x" * 55,
    b"x" * 56,
    b"x" * 64,
    b"x" * 65,
    b"x" * 1000,
)


@pytest.fixture(autouse=True)
def _reset_engine_between_tests():
    """Keep the cached singleton from leaking a forced tier into the next test."""

    loader._reset_engine()
    yield
    loader._reset_engine()


def _engine() -> loader.ShieldEngine:
    """Return a freshly constructed default engine."""

    loader._reset_engine()
    return loader.get_engine()


def _python_engine(monkeypatch):
    """Return an engine forced onto the pure Python tier."""

    monkeypatch.setenv(loader.DISABLE_NATIVE_ENV, "1")
    loader._reset_engine()
    return loader.get_engine()


def test_golden_digests_and_checksums(monkeypatch) -> None:
    engine = _python_engine(monkeypatch)
    for payload, expected in SHA_GOLDEN.items():
        assert engine.sha256(payload).hex() == expected
    for payload, expected in CRC_GOLDEN.items():
        assert engine.crc64(payload) == expected
    assert engine.shannon(b"") == 0.0
    assert abs(engine.shannon(bytes(range(256))) - 8.0) <= 1e-9
    assert abs(engine.shannon(b"abcd") - 2.0) <= 1e-9


def test_python_tier_matches_the_standard_library(monkeypatch) -> None:
    engine = _python_engine(monkeypatch)
    assert engine.backend == "python"
    for payload in PAYLOADS:
        assert engine.sha256(payload) == hashlib.sha256(payload).digest()
        assert engine.crc64(payload) == crc64(payload)
        assert abs(engine.shannon(payload) - shannon_entropy(payload)) <= 1e-9


def test_default_tier_matches_the_forced_python_tier(monkeypatch) -> None:
    reference = _python_engine(monkeypatch)
    reference_values = [
        (reference.sha256(payload), reference.crc64(payload), reference.shannon(payload))
        for payload in PAYLOADS
    ]
    # monkeypatch.delenv restores the default selection before the second build.
    monkeypatch.delenv(loader.DISABLE_NATIVE_ENV)
    candidate = _engine()
    for payload, expected in zip(PAYLOADS, reference_values):
        measured = (candidate.sha256(payload), candidate.crc64(payload), candidate.shannon(payload))
        assert measured[0] == expected[0]
        assert measured[1] == expected[1]
        assert abs(measured[2] - expected[2]) <= 1e-9


def test_random_payloads_match_across_tiers(monkeypatch) -> None:
    generator = random.Random(987654321)
    payloads = [bytes(generator.getrandbits(8) for _ in range(length)) for length in range(0, 200, 7)]
    payloads.append(bytes(generator.getrandbits(8) for _ in range(65536)))
    reference = _python_engine(monkeypatch)
    reference_values = [(reference.sha256(payload), reference.crc64(payload)) for payload in payloads]
    monkeypatch.delenv(loader.DISABLE_NATIVE_ENV)
    candidate = _engine()
    for payload, (expected_sha, expected_crc) in zip(payloads, reference_values):
        assert candidate.sha256(payload) == expected_sha
        assert candidate.crc64(payload) == expected_crc
        assert abs(candidate.shannon(payload) - shannon_entropy(payload)) <= 1e-9


def test_native_tier_matches_the_python_reference(monkeypatch) -> None:
    if loader.find_native_library() is None:
        pytest.skip("tauhaulity_silicon_shield is not built for this platform")
    monkeypatch.delenv(loader.DISABLE_NATIVE_ENV, raising=False)
    loader._reset_engine()
    native = _engine()
    assert native.backend == "rust"
    monkeypatch.setenv(loader.DISABLE_NATIVE_ENV, "1")
    loader._reset_engine()
    pure = loader.get_engine()
    assert pure.backend == "python"
    for payload in PAYLOADS:
        assert native.sha256(payload) == pure.sha256(payload)
        assert native.crc64(payload) == pure.crc64(payload)
        assert abs(native.shannon(payload) - pure.shannon(payload)) <= 1e-9


def test_backend_selection_respects_the_environment(monkeypatch) -> None:
    native = loader.find_native_library()

    monkeypatch.setenv(loader.DISABLE_NATIVE_ENV, "1")
    loader._reset_engine()
    forced = loader.get_engine()
    assert forced.backend == "python"
    assert forced.available is False

    monkeypatch.delenv(loader.DISABLE_NATIVE_ENV)
    if native is None:
        loader._reset_engine()
        fallback = loader.get_engine()
        assert fallback.backend in {"ctypes", "python"}
        assert fallback.available is False
        return

    monkeypatch.setenv(loader.LIBRARY_ENV, str(native))
    loader._reset_engine()
    selected = loader.get_engine()
    assert selected.backend == "rust"
    assert selected.available is True


def test_qpc_is_deterministically_monotonic_across_tiers(monkeypatch) -> None:
    engine = _python_engine(monkeypatch)
    previous = engine.qpc()
    for _ in range(200):
        current = engine.qpc()
        assert current >= previous
        previous = current
    assert isinstance(previous, int)


def test_engine_reports_honest_availability() -> None:
    engine = _engine()
    status = engine.page_seal_status()
    assert status["backend"] == engine.backend
    if engine.available:
        assert status["qpc"] == "native"
        assert status["native_library"] != "not loaded"
    else:
        assert status["qpc"] in {"ctypes", "stdlib"}
        assert status["native_library"] == "not loaded"