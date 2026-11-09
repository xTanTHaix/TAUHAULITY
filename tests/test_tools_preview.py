"""Tests for the destructive-action previews.

Both previews exist so an operator can see the consequences of a destructive
command before it runs: describe_port_action must enumerate owners without ever
signalling one, and UndoStore.preview must list what would be journaled without
creating the journal. Those two "never" clauses are the assertions that matter
most here.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

import tauhaulity.tools.port_sweeper as port_sweeper
from tauhaulity.daemon.undo_store import UndoStore


def _owners(*rows: tuple[int, str]) -> list[port_sweeper.PortOwner]:
    return [port_sweeper.PortOwner(3000, pid, name) for pid, name in rows]


def test_describe_unbound_port(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(port_sweeper, "find_port_owners", lambda port: [])
    text = port_sweeper.describe_port_action(3000)
    assert "3000" in text
    assert "not bound" in text
    assert "signal nothing" in text


def test_describe_names_the_pids_that_would_be_signalled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        port_sweeper, "find_port_owners", lambda port: _owners((111, "alpha"), (222, "beta"))
    )
    text = port_sweeper.describe_port_action(3000)
    assert "111" in text and "222" in text
    assert "alpha" in text and "beta" in text
    assert "would signal" in text
    assert "graceful" in text


def test_describe_marks_the_current_process_as_protected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owners = _owners((os.getpid(), "self"), (333, "other"))
    monkeypatch.setattr(port_sweeper, "find_port_owners", lambda port: owners)
    text = port_sweeper.describe_port_action(3000)
    assert "protected" in text
    assert "333" in text


def test_describe_with_only_protected_owners_signals_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        port_sweeper, "find_port_owners", lambda port: _owners((os.getpid(), "self"))
    )
    text = port_sweeper.describe_port_action(3000)
    assert "protected" in text
    assert "signal nothing" in text


def test_describe_marks_an_unknown_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        port_sweeper, "find_port_owners", lambda port: _owners((0, ""))
    )
    text = port_sweeper.describe_port_action(3000)
    assert "unknown owner" in text
    assert "signal nothing" in text


def test_describe_degrades_when_the_table_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def explode(port: int) -> list[port_sweeper.PortOwner]:
        raise OSError("kernel denied the socket table")

    monkeypatch.setattr(port_sweeper, "find_port_owners", explode)
    text = port_sweeper.describe_port_action(3000)
    assert "unavailable" in text
    assert "signal nothing" in text


def test_describe_validates_the_port() -> None:
    with pytest.raises(ValueError):
        port_sweeper.describe_port_action(0)
    with pytest.raises(ValueError):
        port_sweeper.describe_port_action(65536)


def test_describe_never_signals_a_process(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        port_sweeper, "find_port_owners", lambda port: _owners((111, "alpha"))
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("a preview must never signal or terminate a process")

    monkeypatch.setattr(port_sweeper, "free_port", forbidden)
    monkeypatch.setattr(port_sweeper, "_terminate_graceful", forbidden)
    monkeypatch.setattr(port_sweeper, "_terminate_force", forbidden)
    text = port_sweeper.describe_port_action(3000)
    assert "111" in text


def test_preview_lists_a_file_without_creating_the_journal(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "notes.txt").write_text("hello", encoding="utf-8")
    store = UndoStore(root, ring_mb=16)
    lines = store.preview([root / "notes.txt"])
    assert lines[0] == "file notes.txt: 5 byte(s)"
    assert "journal preview: 1 of 1 path(s) capturable" in lines[-1]
    assert "within budget" in lines[-1]
    assert not (root / ".tauhaulity").exists()


def test_preview_reports_missing_paths(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    store = UndoStore(root, ring_mb=16)
    lines = store.preview([root / "gone.txt"])
    assert lines[0].startswith("missing gone.txt")
    assert "nothing would be journaled" in lines[0]
    assert "0 of 1 path(s) capturable" in lines[-1]


def test_preview_measures_a_directory_tree(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / "tree" / "nested").mkdir(parents=True)
    (root / "tree" / "one.txt").write_text("abc", encoding="utf-8")
    (root / "tree" / "nested" / "two.txt").write_text("defgh", encoding="utf-8")
    store = UndoStore(root, ring_mb=16)
    lines = store.preview([root / "tree"])
    assert lines[0].startswith("directory tree:")
    assert "4 item(s)" in lines[0]
    assert "8 byte(s)" in lines[0]
    assert not (root / ".tauhaulity").exists()


def test_preview_skips_the_journal_itself(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "notes.txt").write_text("hello", encoding="utf-8")
    store = UndoStore(root, ring_mb=16)
    store.capture([root / "notes.txt"])
    lines = store.preview([root / ".tauhaulity"])
    assert lines[0].startswith("skipped")
    assert "inside the tauhaulity state directory" in lines[0]


def test_preview_flags_a_tree_over_the_ring_budget(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "big.bin").write_bytes(b"\x00" * (2 * 1024 * 1024))
    store = UndoStore(root, ring_mb=1)
    lines = store.preview([root / "big.bin"])
    assert "over budget" in lines[-1]
    assert "capture would raise" in lines[-1]
    assert not (root / ".tauhaulity").exists()


def test_preview_of_a_symlink_never_follows_it(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    target = root / "target.txt"
    target.write_text("payload", encoding="utf-8")
    link = root / "link.txt"
    try:
        os.symlink(target.name, link)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("symlinks are not available on this host")
    store = UndoStore(root, ring_mb=16)
    lines = store.preview([link])
    assert lines[0].startswith("symlink link.txt -> target.txt")
    assert "0 bytes" in lines[0]


def test_preview_with_no_paths_returns_nothing(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    assert UndoStore(root, ring_mb=16).preview([]) == []
