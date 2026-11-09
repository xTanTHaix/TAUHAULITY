"""Tests for the bounded undo journal.

The journal is the only module in this build that destroys and recreates real
files, so the tests cover byte exactness, POSIX mode bits, whole tree restore,
FIFO eviction under a one megabyte ring and the failure paths.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
from pathlib import Path

import pytest

from tauhaulity.daemon.undo_store import (
    RestoreResult,
    UndoEntry,
    UndoStore,
    UndoStoreError,
)


def _root(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir()
    return root


def test_capture_and_restore_a_file_byte_exact(tmp_path: Path) -> None:
    root = _root(tmp_path)
    source = root / "notes.bin"
    payload = bytes(range(256)) * 8
    source.write_bytes(payload)
    store = UndoStore(root, ring_mb=16)
    entries = store.capture([source])
    assert len(entries) == 1
    entry = entries[0]
    assert isinstance(entry, UndoEntry)
    assert entry.bytes == len(payload)
    assert entry.paths == (str(source.resolve()),)
    assert entry.journal_path.is_dir()
    index = root / ".tauhaulity" / "undo" / "index.json"
    assert index.is_file()
    assert json.loads(index.read_text(encoding="utf-8"))[0]["entry_id"] == entry.entry_id

    source.unlink()
    result = store.restore()
    assert isinstance(result, RestoreResult)
    assert result.restored == 1
    assert result.entry_id == entry.entry_id
    assert source.read_bytes() == payload


def test_restore_consumes_the_entry(tmp_path: Path) -> None:
    root = _root(tmp_path)
    source = root / "one.txt"
    source.write_text("payload", encoding="utf-8")
    store = UndoStore(root, ring_mb=16)
    store.capture([source])
    source.unlink()
    store.restore()
    assert store.list_entries() == []
    assert store.usage_bytes() == 0


@pytest.mark.skipif(os.name == "nt", reason="Win32 does not store POSIX mode bits")
def test_restore_preserves_the_mode_bits(tmp_path: Path) -> None:
    root = _root(tmp_path)
    script = root / "run.sh"
    script.write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    os.chmod(script, 0o750)
    store = UndoStore(root, ring_mb=16)
    store.capture([script])
    script.unlink()
    store.restore()
    assert stat.S_IMODE(script.stat().st_mode) == 0o750


def test_capture_and_restore_a_directory_tree(tmp_path: Path) -> None:
    root = _root(tmp_path)
    tree = root / "data"
    (tree / "nested").mkdir(parents=True)
    (tree / "alpha.txt").write_text("alpha", encoding="utf-8")
    (tree / "nested" / "beta.bin").write_bytes(b"\x00\x01\x02\xff")
    store = UndoStore(root, ring_mb=16)
    entries = store.capture([tree])
    assert len(entries) == 1
    shutil.rmtree(tree)
    result = store.restore(entries[0].entry_id)
    assert result.restored >= 3
    assert (tree / "alpha.txt").read_text(encoding="utf-8") == "alpha"
    assert (tree / "nested" / "beta.bin").read_bytes() == b"\x00\x01\x02\xff"


@pytest.mark.skipif(os.name == "nt", reason="creating symlinks needs developer mode on Win32")
def test_restore_recreates_a_symlink(tmp_path: Path) -> None:
    root = _root(tmp_path)
    target = root / "real.txt"
    target.write_text("real", encoding="utf-8")
    link = root / "link.txt"
    os.symlink(target, link)
    store = UndoStore(root, ring_mb=16)
    entries = store.capture([link])
    assert len(entries) == 1
    link.unlink()
    result = store.restore()
    assert result.restored == 1
    assert link.is_symlink()
    assert os.readlink(link) == str(target)


def test_capture_of_missing_path_returns_no_entries(tmp_path: Path) -> None:
    root = _root(tmp_path)
    store = UndoStore(root, ring_mb=16)
    assert store.capture([root / "missing.txt"]) == []
    assert store.capture([]) == []
    assert store.list_entries() == []


def test_capture_skips_the_journal_itself(tmp_path: Path) -> None:
    root = _root(tmp_path)
    source = root / "keep.txt"
    source.write_text("data", encoding="utf-8")
    store = UndoStore(root, ring_mb=16)
    store.capture([source])
    journal = root / ".tauhaulity"
    assert store.capture([journal]) == []


def test_list_entries_is_newest_first_and_limited(tmp_path: Path) -> None:
    root = _root(tmp_path)
    store = UndoStore(root, ring_mb=16)
    for index in range(3):
        path = root / ("file" + str(index) + ".txt")
        path.write_text(str(index) * 20, encoding="utf-8")
        store.capture([path])
    entries = store.list_entries(limit=2)
    assert len(entries) == 2
    assert entries[0].entry_id > entries[1].entry_id
    assert store.list_entries(limit=0) == []
    assert len(store.list_entries()) == 3


def test_fifo_eviction_keeps_the_journal_within_budget(tmp_path: Path) -> None:
    root = _root(tmp_path)
    store = UndoStore(root, ring_mb=1)
    first = root / "first.bin"
    first.write_bytes(b"A" * 700_000)
    store.capture([first])
    second = root / "second.bin"
    second.write_bytes(b"B" * 700_000)
    store.capture([second])
    assert store.usage_bytes() <= 1024 * 1024
    kept = [entry.paths[0] for entry in store.list_entries()]
    assert any("second.bin" in path for path in kept)
    assert all("first.bin" not in path for path in kept)
    assert store.list_entries(limit=1)[0].paths[0].endswith("second.bin")


def test_capture_refuses_a_path_larger_than_the_ring(tmp_path: Path) -> None:
    root = _root(tmp_path)
    store = UndoStore(root, ring_mb=1)
    huge = root / "huge.bin"
    huge.write_bytes(b"H" * (1024 * 1024 + 64))
    with pytest.raises(UndoStoreError):
        store.capture([huge])
    # The failed capture must not leave a partial entry behind.
    assert store.list_entries() == []


def test_prune_removes_orphaned_entries(tmp_path: Path) -> None:
    root = _root(tmp_path)
    store = UndoStore(root, ring_mb=16)
    source = root / "tracked.txt"
    source.write_text("tracked", encoding="utf-8")
    store.capture([source])
    orphan = store.journal_dir / "entries" / "00000000000000000000-deadbeef"
    orphan.mkdir(parents=True)
    (orphan / "manifest.json").write_text("{}", encoding="utf-8")
    removed = store.prune()
    assert removed >= 1
    assert not orphan.exists()


def test_restore_unknown_entry_reports_zero(tmp_path: Path) -> None:
    root = _root(tmp_path)
    store = UndoStore(root, ring_mb=16)
    result = store.restore("does-not-exist")
    assert result.restored == 0
    assert result.entry_id == "does-not-exist"
    assert "unknown" in result.message


def test_restore_empty_journal_reports_zero(tmp_path: Path) -> None:
    root = _root(tmp_path)
    store = UndoStore(root, ring_mb=16)
    result = store.restore()
    assert result.restored == 0
    assert result.entry_id == ""
    assert "empty" in result.message


def test_store_construction_validates_arguments(tmp_path: Path) -> None:
    with pytest.raises(UndoStoreError):
        UndoStore(tmp_path / "missing", ring_mb=16)
    not_a_directory = tmp_path / "plain.txt"
    not_a_directory.write_text("x", encoding="utf-8")
    with pytest.raises(UndoStoreError):
        UndoStore(not_a_directory, ring_mb=16)
    root = _root(tmp_path)
    with pytest.raises(UndoStoreError):
        UndoStore(root, ring_mb=0)
    with pytest.raises(UndoStoreError):
        UndoStore(root, ring_mb=True)


def test_store_does_not_touch_the_disk_before_the_first_capture(tmp_path: Path) -> None:
    root = _root(tmp_path)
    store = UndoStore(root, ring_mb=16)
    assert store.is_initialized() is False
    assert store.usage_bytes() == 0
    assert store.list_entries() == []


def test_journal_stays_inside_the_project_state_directory(tmp_path: Path) -> None:
    root = _root(tmp_path)
    source = root / "inside.txt"
    source.write_text("inside", encoding="utf-8")
    store = UndoStore(root, ring_mb=16)
    entries = store.capture([source])
    journal = entries[0].journal_path.resolve()
    assert str(journal).startswith(str((root / ".tauhaulity" / "undo").resolve()))
    assert (journal / "manifest.json").is_file()
