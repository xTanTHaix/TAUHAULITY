"""Policy tests: validation, persistence, override merge and ignore matching."""

from __future__ import annotations

import json

import pytest

from tauhaulity.core.policy import (
    MAX_UNDO_RING_MB,
    Policy,
    PolicyError,
    PolicyOverrides,
    policy_path,
)


def test_default_policy_is_valid() -> None:
    policy = Policy().validate()
    assert policy.undo_ring_mb == 512
    assert policy.block_git_secrets is True
    assert policy.enforce_active is False


def test_invalid_ring_size_rejected() -> None:
    with pytest.raises(PolicyError):
        Policy(undo_ring_mb=0).validate()
    with pytest.raises(PolicyError):
        Policy(undo_ring_mb=MAX_UNDO_RING_MB + 1).validate()
    with pytest.raises(PolicyError):
        Policy(undo_ring_mb="big").validate()  # type: ignore[arg-type]


def test_ignored_paths_normalized() -> None:
    policy = Policy(ignored_paths=("\\build", "node_modules/", ".", "")).validate()
    assert policy.ignored_paths == ("build", "node_modules")


def test_save_and_load_roundtrip(tmp_path) -> None:
    path = policy_path(tmp_path)
    policy = Policy(enforce_active=True, undo_ring_mb=128, ignored_paths=("vendor",), auditor="lead")
    written = policy.save(path)
    assert written == path and path.is_file()
    loaded = Policy.load(path)
    assert loaded.to_dict() == policy.to_dict()


def test_load_missing_and_malformed(tmp_path) -> None:
    assert Policy.load(tmp_path / "absent.json").undo_ring_mb == 512
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    assert Policy.load(broken).undo_ring_mb == 512
    with pytest.raises(PolicyError):
        Policy.load(broken, strict=True)
    wrong_type = tmp_path / "wrong.json"
    wrong_type.write_text(json.dumps({"against": 1, "enforce_active": "yes"}), encoding="utf-8")
    assert Policy.load(wrong_type).enforce_active is False


def test_overrides_only_apply_provided_fields() -> None:
    base = Policy(auditor="old", undo_ring_mb=256)
    merged = base.with_overrides(PolicyOverrides(enforce_active=True, auditor="new"))
    assert merged.enforce_active is True
    assert merged.auditor == "new"
    assert merged.undo_ring_mb == 256


def test_ignore_matching() -> None:
    policy = Policy(ignored_paths=("vendor", "*.log"))
    assert policy.is_ignored("vendor/lib.py")
    assert policy.is_ignored("logs/app.log")
    assert not policy.is_ignored("src/app.py")
