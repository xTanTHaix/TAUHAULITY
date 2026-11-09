"""Tests for pillar five: rotating mask vault, pinning and constant time helpers.

The mask rotation tests read the resident bytes, which is exactly what an attacker
doing a memory dump would see, and assert they changed while retrieve() still
returns the original secret.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from tauhaulity.core.contracts import ScanContext, ScanOptions
from tauhaulity.pillars import p05_crypto as pillar


def _make_ctx(target: Path, platform_info, policy) -> ScanContext:
    return ScanContext(target=Path(target), platform=platform_info, policy=policy, options=ScanOptions())


def test_constant_time_compare() -> None:
    assert pillar.constant_time_compare(b"secret", b"secret") is True
    assert pillar.constant_time_compare(b"secret", b"secreT") is False
    assert pillar.constant_time_compare(b"secret", b"secret-longer") is False
    assert pillar.constant_time_compare(b"", b"") is True
    assert pillar.constant_time_compare(b"", b"x") is False


def test_store_and_retrieve_obfuscates_resident_bytes() -> None:
    secret = b"0123456789abcdef"
    vault = pillar.KeyVault()
    try:
        vault.store("token", secret)
        assert vault.retrieve("token") == secret
        resident = vault.stored_bytes("token")
        assert resident != secret
        assert len(resident) == len(secret)
        assert vault.stats()["secrets"] == 1
    finally:
        vault.close()
    with pytest.raises(KeyError):
        vault.retrieve("token")


def test_mask_rotation_changes_resident_bytes() -> None:
    secret = b"correct horse battery staple"
    with pillar.KeyVault() as vault:
        vault.store("k", secret)
        first = vault.stored_bytes("k")
        assert vault.rotate_once() == 1
        second = vault.stored_bytes("k")
        assert first != second
        assert vault.retrieve("k") == secret
        assert vault.rotate_once() == 2
        third = vault.stored_bytes("k")
        assert third not in {first, second}
        assert vault.retrieve("k") == secret


def test_lock_and_unlock_pages() -> None:
    with pillar.KeyVault() as vault:
        vault.store("k", b"x" * 32)
        pinned = vault.lock_pages()
        assert isinstance(pinned, bool)
        if pinned:
            assert vault.locked is True
            assert vault.unlock_pages() is True
            assert vault.locked is False
        else:
            assert vault.locked is False
            assert vault.stats()["locker_available"] in {True, False}


def test_rejects_empty_inputs() -> None:
    vault = pillar.KeyVault()
    try:
        with pytest.raises(pillar.KeyVaultError):
            vault.store("", b"value")
        with pytest.raises(pillar.KeyVaultError):
            vault.store("name", b"")
        with pytest.raises(ValueError):
            pillar.KeyVault(rotate_ms=0)
    finally:
        vault.close()


def test_shred_zeroizes_and_forgets() -> None:
    vault = pillar.KeyVault()
    vault.store("k", b"abcdefgh")
    assert vault.shred("k") is True
    assert vault.shred("k") is False
    assert vault.delete("missing") is False
    with pytest.raises(KeyError):
        vault.retrieve("k")
    assert vault.stats()["shredded"] >= 1
    vault.close()
    vault.close()


def test_rotation_thread_refreshes_masks() -> None:
    with pillar.KeyVault(rotate_ms=10.0) as vault:
        vault.store("k", b"thread-rotated-secret")
        before = vault.stored_bytes("k")
        vault.start_rotation()
        deadline = time.monotonic() + 2.0
        while vault.rotations < 2 and time.monotonic() < deadline:
            time.sleep(0.005)
        vault.stop_rotation()
        assert vault.rotations >= 2
        assert vault.stats()["rotation_thread"] is False
        assert vault.stored_bytes("k") != before
        assert vault.retrieve("k") == b"thread-rotated-secret"
        frozen = vault.rotations
        time.sleep(0.03)
        assert vault.rotations == frozen


def test_quantized_compare_pads_latency() -> None:
    enforcer = pillar.TimeBucketEnforcer(bucket_ns=3000)
    assert enforcer.quantized_compare(b"same", b"same") is True
    assert enforcer.last_elapsed_ns >= 3000
    assert enforcer.quantized_compare(b"left", b"right") is False
    assert enforcer.last_elapsed_ns >= 3000
    assert enforcer.clock_name


def test_probe_returns_legal_finding(sample_project: Path, platform_info, default_policy) -> None:
    ctx = _make_ctx(sample_project, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.pillar == 5
    assert finding.status in pillar.SPEC.statuses
    assert 0.0 <= finding.risk <= pillar.SPEC.risk_scale
    assert "secret" in finding.slot("detail")
    ctx.record(finding)
