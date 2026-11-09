"""Tests for the quarantine store.

The fixtures are real files inside a temporary project root. Every test drives
the shipped API and checks the filesystem afterwards, because the promise of
quarantine is a filesystem promise: the original leaves the load path only after
a verified copy exists, restore is byte exact and reversible, and every refusal
is reported instead of silently ignored.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from tauhaulity.tools import artifact_scan, quarantine

POSIX_ONLY = pytest.mark.skipif(
    os.name == "nt", reason="NTFS exposes only the read-only bit, not POSIX mode bits"
)


def _build_project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "payloads").mkdir(parents=True)
    (root / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    return root


def _payload(root: Path, name: str, data: bytes = None) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if data is not None else b"\x80\x04\x95payload-bytes")
    return path


def _kinds(path: Path, kind: str = "pickle_unsafe") -> dict[str, str]:
    return {str(path): kind}


def test_round_trip_byte_exact_and_reversible(tmp_path: Path) -> None:
    root = _build_project(tmp_path)
    original = _payload(root, "payloads/cache.pkl", b"\x80\x04benign-looking-pickle")
    store = quarantine.QuarantineStore(root)
    assert store.path == root / ".tauhaulity" / "quarantine"
    assert store.manifest_path == store.path / "quarantine.json"
    report = store.quarantine(
        [original],
        reason="unsafe pickle removed from the import path after review",
        kinds=_kinds(original),
    )
    assert report.skipped == []
    assert len(report.items) == 1
    item = report.items[0]
    assert not original.exists()
    stored = Path(item.stored_path)
    assert stored.is_file()
    assert stored.read_bytes() == b"\x80\x04benign-looking-pickle"
    assert item.original_path == str(original.resolve())
    assert item.kind == "pickle_unsafe"
    assert item.sha256 == quarantine._sha256_file(stored)[0]
    assert item.bytes == len(stored.read_bytes())
    assert item.reason.startswith("unsafe pickle")
    assert item.mode > 0
    assert "1 item(s) quarantined" in report.detail
    assert report.store_path == store.path

    manifest = json.loads(store.manifest_path.read_text(encoding="utf-8"))
    assert manifest["version"] == quarantine.MANIFEST_VERSION == 1
    assert manifest["generator"] == "tauhaulity.tools.quarantine"
    assert manifest["records_digest"]
    assert len(manifest["items"]) == 1
    assert manifest["items"][0]["item_id"] == item.item_id

    reloaded = quarantine.QuarantineStore(root)
    assert reloaded.list_items() == report.items
    assert reloaded.usage_bytes() == item.bytes

    assert store.restore(item.item_id) is True
    assert original.is_file()
    assert original.read_bytes() == b"\x80\x04benign-looking-pickle"
    assert not stored.exists()
    assert store.list_items() == []
    assert store.usage_bytes() == 0
    assert store.restore(item.item_id) is False


@POSIX_ONLY
def test_store_copy_is_owner_only_and_original_mode_is_restored(tmp_path: Path) -> None:
    root = _build_project(tmp_path)
    original = _payload(root, "payloads/mode.pkl")
    os.chmod(original, 0o640)
    store = quarantine.QuarantineStore(root)
    report = store.quarantine([original], reason="mode preservation check")
    item = report.items[0]
    assert stat.S_IMODE(Path(item.stored_path).stat().st_mode) == 0o600
    assert stat.S_IMODE(store.path.stat().st_mode) == 0o700
    assert item.mode == 0o640
    assert store.restore(item.item_id) is True
    assert stat.S_IMODE(original.stat().st_mode) == 0o640


def test_failed_copy_leaves_the_original_untouched(tmp_path: Path, monkeypatch) -> None:
    root = _build_project(tmp_path)
    original = _payload(root, "payloads/copy-fail.pkl")
    content = original.read_bytes()
    store = quarantine.QuarantineStore(root)

    def exploding_copy(source: Path, destination: Path) -> None:
        raise OSError("simulated copy failure")

    monkeypatch.setattr(quarantine, "_copy_file", exploding_copy)
    report = store.quarantine([original], reason="copy failure must not lose the original")
    assert report.items == []
    assert original.is_file()
    assert original.read_bytes() == content
    assert any("copy failed" in line and str(original) in line for line in report.skipped)
    assert store.list_items() == []
    stored = [path for path in store.path.glob("*.pkl")] if store.path.exists() else []
    assert stored == []


def test_refuses_paths_outside_the_root_symlinks_and_directories(tmp_path: Path) -> None:
    root = _build_project(tmp_path)
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    outside = _payload(outside_dir, "outside.pkl")
    inside_dir = root / "folder"
    inside_dir.mkdir()
    store = quarantine.QuarantineStore(root)
    requested = [outside, inside_dir]
    link = root / "outside-link.pkl"
    try:
        link.symlink_to(outside)
        requested.append(link)
    except (OSError, NotImplementedError):
        pass
    report = store.quarantine(requested, reason="refusal probe")
    assert report.items == []
    assert outside.is_file(), "a refused path must never be touched"
    assert inside_dir.is_dir()
    reasons = "\n".join(report.skipped)
    assert "outside the quarantine root" in reasons
    assert "not a regular file" in reasons
    if link.exists() or link.is_symlink():
        assert "symlink" in reasons
    assert "0 item(s) quarantined" in report.detail or "nothing quarantined" in report.detail


def test_restore_refuses_a_different_file_and_accepts_a_matching_one(tmp_path: Path) -> None:
    root = _build_project(tmp_path)
    original = _payload(root, "payloads/conflict.pkl", b"original-bytes")
    store = quarantine.QuarantineStore(root)
    item = store.quarantine([original], reason="restore conflict probe").items[0]
    original.write_bytes(b"operator-authored-different-content")
    assert store.restore(item.item_id) is False
    assert original.read_bytes() == b"operator-authored-different-content"
    assert Path(item.stored_path).is_file(), "restore failure must keep the stored copy"
    original.write_bytes(b"original-bytes")
    assert store.restore(item.item_id) is True
    assert original.read_bytes() == b"original-bytes"
    assert not Path(item.stored_path).exists()


def test_purge_is_explicit_and_usage_bytes_is_accurate(tmp_path: Path) -> None:
    root = _build_project(tmp_path)
    first = _payload(root, "payloads/first.pkl", b"a" * 10)
    second = _payload(root, "payloads/second.pkl", b"b" * 25)
    store = quarantine.QuarantineStore(root)
    report = store.quarantine([first, second], reason="purge probe")
    assert len(report.items) == 2
    assert store.usage_bytes() == 35
    assert store.purge("missing-id") == 0
    assert store.purge(report.items[0].item_id) == 1
    assert not Path(report.items[0].stored_path).exists()
    assert Path(report.items[1].stored_path).is_file()
    assert store.usage_bytes() == 25
    assert len(store.list_items()) == 1
    assert store.purge() == 1
    assert store.list_items() == []
    assert store.usage_bytes() == 0
    assert store.purge() == 0


def test_corrupt_or_tampered_manifest_degrades_to_empty(tmp_path: Path) -> None:
    root = _build_project(tmp_path)
    original = _payload(root, "payloads/corrupt.pkl")
    store = quarantine.QuarantineStore(root)
    item = store.quarantine([original], reason="manifest corruption probe").items[0]
    store.manifest_path.write_text("{ this is not json", encoding="utf-8")
    assert store.list_items() == []
    assert store.usage_bytes() == 0
    assert store.restore(item.item_id) is False
    store.manifest_path.unlink()
    assert store.list_items() == []


def test_tampered_digest_degrades_to_empty_store(tmp_path: Path) -> None:
    root = _build_project(tmp_path)
    original = _payload(root, "payloads/digest.pkl")
    store = quarantine.QuarantineStore(root)
    store.quarantine([original], reason="digest tamper probe")
    payload = json.loads(store.manifest_path.read_text(encoding="utf-8"))
    payload["items"][0]["sha256"] = "0" * 64
    store.manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    assert store.list_items() == []


def test_dry_run_reports_without_touching_anything(tmp_path: Path) -> None:
    root = _build_project(tmp_path)
    original = _payload(root, "payloads/dry.pkl")
    store = quarantine.QuarantineStore(root)
    report = store.quarantine(
        [original], reason="dry run review", kinds=_kinds(original), dry_run=True
    )
    assert len(report.items) == 1
    assert original.is_file()
    assert not store.path.exists()
    assert "dry run" in report.detail


def test_empty_reason_is_refused(tmp_path: Path) -> None:
    root = _build_project(tmp_path)
    original = _payload(root, "payloads/noreason.pkl")
    store = quarantine.QuarantineStore(root)
    with pytest.raises(quarantine.QuarantineError):
        store.quarantine([original], reason="")
    with pytest.raises(ValueError):
        store.quarantine([original], reason="   " + chr(10))
    assert original.is_file()
    assert not (store.path / "quarantine.json").exists()


def test_missing_root_is_reported_not_raised(tmp_path: Path) -> None:
    store = quarantine.QuarantineStore(tmp_path / "absent")
    report = store.quarantine([tmp_path / "whatever.pkl"], reason="missing root probe")
    assert report.items == []
    assert report.skipped
    assert "not a readable directory" in report.detail


def test_kind_mapping_accepts_absolute_relative_and_bare_names(tmp_path: Path) -> None:
    root = _build_project(tmp_path)
    absolute = _payload(root, "payloads/absolute.pkl")
    relative = _payload(root, "payloads/relative.pkl")
    bare = _payload(root, "payloads/bare.pkl")
    store = quarantine.QuarantineStore(root)
    report = store.quarantine(
        [absolute, relative, bare],
        reason="kind lookup probe",
        kinds={
            str(absolute.resolve()): "pyc_mismatch",
            "payloads/relative.pkl": "pickle_malformed",
            "bare.pkl": "pyc_invalid",
        },
    )
    kinds = {Path(item.original_path).name: item.kind for item in report.items}
    assert kinds["absolute.pkl"] == "pyc_mismatch"
    assert kinds["relative.pkl"] == "pickle_malformed"
    assert kinds["bare.pkl"] == "pyc_invalid"


def test_quarantine_keeps_the_store_inside_the_project(tmp_path: Path) -> None:
    root = _build_project(tmp_path)
    original = _payload(root, "payloads/store.pkl")
    store = quarantine.QuarantineStore(root)
    item = store.quarantine([original], reason="store location probe").items[0]
    stored = Path(item.stored_path)
    assert store.path.is_dir()
    stored.resolve().relative_to(root.resolve())
    with pytest.raises(ValueError):
        stored.resolve().relative_to((tmp_path / "elsewhere").resolve())


def test_eligibility_drives_the_suggestion_list(tmp_path: Path) -> None:
    root = _build_project(tmp_path)
    (root / "cache.pkl").write_bytes(b"\x80\x04\x95\x00\x00\x00\x00")
    (root / "handlers.py").write_text(
        "import pickle\ndef load(blob):\n    return pickle.loads(blob)\n", encoding="utf-8"
    )
    report = artifact_scan.scan_source_tree(root)
    eligible = {finding.rel_path for finding in report.findings if finding.quarantine_eligible}
    assert "cache.pkl" in eligible
    assert "handlers.py" not in eligible
    suggested = quarantine.suggest_quarantine(root)
    assert suggested == (root / "cache.pkl",)
    store = quarantine.QuarantineStore(root)
    assert store.quarantine(suggested, reason="suggested payload reviewed").items
    assert quarantine.suggest_quarantine(root) == ()

@POSIX_ONLY
def test_unreadable_file_is_refused_and_kept(tmp_path: Path) -> None:
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        pytest.skip("root can read a mode 000 file, so the refusal path cannot be exercised")
    root = _build_project(tmp_path)
    original = _payload(root, "payloads/locked.pkl")
    os.chmod(original, 0o000)
    try:
        store = quarantine.QuarantineStore(root)
        report = store.quarantine([original], reason="unreadable file probe")
        assert report.items == []
        assert any("unreadable" in line for line in report.skipped)
        assert original.is_file()
    finally:
        os.chmod(original, 0o600)
