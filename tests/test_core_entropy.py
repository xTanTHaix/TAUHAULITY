"""Entropy tests: boundary values, base64 heuristic and gate decisions."""

from __future__ import annotations

import os

import pytest

from tauhaulity.core.entropy import (
    EntropyGate,
    LOG2_LUT,
    block_entropies,
    entropy_of_sequence,
    is_high_entropy,
    looks_like_base64,
    shannon_entropy,
)


def test_lut_shape() -> None:
    assert len(LOG2_LUT) >= 256
    assert LOG2_LUT[0] == 0.0
    assert LOG2_LUT[1] == 0.0


def test_uniform_bytes_reach_eight_bits() -> None:
    assert shannon_entropy(bytes(range(256))) == pytest.approx(8.0)
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"a" * 4096) == 0.0


def test_two_symbols_give_one_bit() -> None:
    assert shannon_entropy(b"ab" * 512) == pytest.approx(1.0, abs=1e-9)


def test_random_payload_is_high_entropy() -> None:
    payload = os.urandom(4096)
    assert is_high_entropy(payload)
    assert not is_high_entropy(b"normal log line " * 64)


def test_block_entropies_cover_input() -> None:
    data = bytes(range(256)) * 4
    blocks = block_entropies(data, block_size=256)
    assert len(blocks) == 4
    assert all(block == pytest.approx(8.0) for block in blocks)
    with pytest.raises(ValueError):
        block_entropies(data, block_size=0)


def test_base64_heuristic() -> None:
    import base64
    import hashlib

    assert not looks_like_base64("plain english sentence that is not base64 at all")
    payload = base64.b64encode(hashlib.sha256(b"tauhaulity").digest()).decode("ascii")
    assert len(payload) % 4 == 0
    assert looks_like_base64(payload)


def test_gate_allows_short_and_blocks_dense() -> None:
    gate = EntropyGate(threshold=7.2, min_length=16)
    short = gate.evaluate(b"tiny")
    assert short.allowed
    dense = gate.evaluate(os.urandom(4096))
    assert not dense.allowed
    assert "entropy" in dense.reason
    quiet = gate.evaluate(b"the quick brown fox jumps over the lazy dog" * 4)
    assert quiet.allowed
    verdicts = gate.scan_blocks(os.urandom(16384), block_size=4096)
    assert len(verdicts) == 4 and all(not verdict.allowed for verdict in verdicts)


def test_sequence_entropy_matches_bytes() -> None:
    values = [0, 1, 2, 3] * 64
    assert entropy_of_sequence(values) == shannon_entropy(bytes(values))
    with pytest.raises(ValueError):
        entropy_of_sequence([300])
