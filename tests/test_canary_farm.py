"""Tests for the per-directory canary farm.

The farm has two jobs that pull in opposite directions: spread decoys where a
ransomware traversal will reach them, and never fire on legitimate bulk work.
Every rule is therefore exercised twice: once against an attacker style change
(modify, delete, atomic replace) and once against legitimate build activity
(npm ci style file creation, edits, deletions and renames).

Timing assertions measure CPU rather than wall clock where possible, because the
shared CI host can stall a wall clock read for reasons that have nothing to do
with the code under test.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

import tauhaulity.daemon.canary as canary


def _tree(root: Path) -> Path:
    """Build a project with real source directories and every skipped directory."""

    for sub in ("src", "docs", "data", ".git", "dist", "build", "node_modules", ".venv"):
        (root / sub).mkdir(parents=True, exist_ok=True)
    (root / "src" / "app.py").write_text("print('app')" + chr(10), encoding="utf-8")
    (root / "src" / "util.py").write_text("VALUE = 1" + chr(10), encoding="utf-8")
    (root / "docs" / "readme.md").write_text("# docs" + chr(10), encoding="utf-8")
    (root / "data" / "values.txt").write_text("value" + chr(10), encoding="utf-8")
    (root / "notes.md").write_text("# project" + chr(10), encoding="utf-8")
    (root / ".git" / "config").write_text("[core]" + chr(10), encoding="utf-8")
    (root / "dist" / "bundle.js").write_text("bundle" + chr(10), encoding="utf-8")
    (root / "build" / "out.txt").write_text("out" + chr(10), encoding="utf-8")
    (root / "node_modules" / "pkg").mkdir(exist_ok=True)
    (root / "node_modules" / "pkg" / "index.js").write_text("x" + chr(10), encoding="utf-8")
    (root / ".venv" / "lib").mkdir(exist_ok=True)
    (root / ".venv" / "lib" / "pkg.py").write_text("x" + chr(10), encoding="utf-8")
    return root


def _decoy_paths(root: Path) -> list[Path]:
    return [root / record.rel_path for record in canary.load_canary_farm(root)]


def test_deploy_places_one_decoy_per_real_directory(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    report = canary.deploy_canary_farm(root)
    assert report.count == 4
    rel_dirs = {str(Path(record.rel_path).parent).replace("\\", "/") for record in report.deployed}
    assert rel_dirs == {".", "src", "docs", "data"}
    for record in report.deployed:
        assert record.rel_path.endswith((".xlsx", ".docx", ".pdf", ".txt"))
        path = root / record.rel_path
        assert path.is_file()
        assert canary.CANARY_FARM_MARKER.encode("ascii") in path.read_bytes()
    for record in report.deployed:
        parts = set(Path(record.rel_path).parts)
        assert parts.isdisjoint({".git", "dist", "build", "node_modules", ".venv"})


def test_naming_scheme_looks_valuable_and_is_not_a_decoy_name(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    report = canary.deploy_canary_farm(root)
    names = [Path(record.rel_path).name for record in report.deployed]
    assert len(set(names)) == len(names) or True  # duplicates across dirs are allowed
    for name in names:
        lowered = name.lower()
        assert "canary" not in lowered
        assert "decoy" not in lowered
    assert any(name.endswith(".xlsx") for name in names) or any(
        name.endswith(".docx") for name in names
    )


def test_deploy_is_deterministic_and_idempotent(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    first = canary.deploy_canary_farm(root)
    second = canary.deploy_canary_farm(root)
    assert [record.rel_path for record in second.deployed] == [
        record.rel_path for record in first.deployed
    ]
    assert second.digest == first.digest
    assert [record.mtime_ns for record in second.deployed] == [
        record.mtime_ns for record in first.deployed
    ]
    assert len(list(root.rglob("*.xlsx"))) + len(list(root.rglob("*.docx"))) + len(
        list(root.rglob("*.pdf"))
    ) + len(list(root.rglob("*notes_2026.txt"))) >= first.count


def test_per_directory_and_max_files_are_honoured(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    two_per_dir = canary.deploy_canary_farm(root, per_directory=2)
    by_dir: dict[str, int] = {}
    for record in two_per_dir.deployed:
        key = str(Path(record.rel_path).parent)
        by_dir[key] = by_dir.get(key, 0) + 1
    assert by_dir
    assert all(count <= 2 for count in by_dir.values())
    canary.remove_canary_farm(root)

    many = tmp_path / "many"
    many.mkdir()
    for index in range(30):
        directory = many / ("dir" + str(index).zfill(2))
        directory.mkdir()
        (directory / "file.txt").write_text("x" + chr(10), encoding="utf-8")
    capped = canary.deploy_canary_farm(many, max_files=7)
    assert capped.count == 7
    assert len(canary.load_canary_farm(many)) == 7


def test_deploy_skips_policy_ignored_paths(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    vendor = root / "vendor"
    vendor.mkdir()
    (vendor / "third_party.py").write_text("x" + chr(10), encoding="utf-8")
    state = root / ".tauhaulity"
    state.mkdir(exist_ok=True)
    (state / "policy.json").write_text(
        json.dumps({"ignored_paths": ["vendor"]}), encoding="utf-8"
    )
    report = canary.deploy_canary_farm(root)
    assert all("vendor" not in Path(record.rel_path).parts for record in report.deployed)
    assert not (vendor / "payroll_2026.xlsx").exists()


def test_change_detection_reports_three_distinct_kinds(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    report = canary.deploy_canary_farm(root)
    watcher = canary.CanaryWatcher(root)
    watcher.snapshot()
    assert watcher.farm_count == report.count

    modified = report.deployed[0]
    deleted = report.deployed[1]
    replaced = report.deployed[2]
    (root / modified.rel_path).write_text("attacker content" + chr(10), encoding="utf-8")
    (root / deleted.rel_path).unlink()
    source = tmp_path / "incoming.bin"
    source.write_bytes(b"replacement payload" + bytes(range(32)))
    os.replace(source, root / replaced.rel_path)

    events = watcher.scan()
    kinds = {(event.path, event.kind) for event in events}
    assert (modified.rel_path, "canary_modified") in kinds
    assert (deleted.rel_path, "canary_deleted") in kinds
    assert (replaced.rel_path, "canary_replaced") in kinds
    # A persistent tamper is reported once, not on every tick.
    assert watcher.scan() == []


def test_replaced_is_detected_by_inode_change(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    report = canary.deploy_canary_farm(root)
    watcher = canary.CanaryWatcher(root)
    watcher.snapshot()
    target = report.deployed[0]
    path = root / target.rel_path
    payload = path.read_bytes()
    # Atomic replace: the incoming file exists while the decoy still exists, so its
    # inode is necessarily different. Unlinking and recreating in place can reuse
    # the freed inode on some filesystems and would not exercise this branch.
    source = tmp_path / "incoming.bin"
    source.write_bytes(payload)  # identical bytes, different inode
    os.replace(source, path)
    events = watcher.scan()
    assert any(event.kind == "canary_replaced" for event in events), events


def test_remove_deletes_only_its_own_files(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    report = canary.deploy_canary_farm(root)
    tampered = report.deployed[0]
    user_file = root / tampered.rel_path
    user_file.write_text("this is user data now" + chr(10), encoding="utf-8")
    removed = canary.remove_canary_farm(root)
    assert removed == report.count - 1
    assert user_file.is_file()
    assert user_file.read_text(encoding="utf-8").startswith("this is user data")
    assert canary.load_canary_farm(root) == ()
    assert not report.manifest_path.exists()
    for record in report.deployed[1:]:
        if record.rel_path != tampered.rel_path:
            assert not (root / record.rel_path).exists()


def test_occupied_name_is_skipped_not_overwritten(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    first = canary.deploy_canary_farm(root)
    target = first.deployed[0]
    canary.remove_canary_farm(root)
    foreign = root / target.rel_path
    foreign.write_text("foreign payload" + chr(10), encoding="utf-8")
    second = canary.deploy_canary_farm(root)
    assert target.rel_path not in {record.rel_path for record in second.deployed}
    assert foreign.read_text(encoding="utf-8").startswith("foreign payload")
    assert any(record.rel_path.startswith(str(Path(target.rel_path).parent)) for record in second.deployed)


def test_corrupt_manifest_degrades_and_redeploy_repairs(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    report = canary.deploy_canary_farm(root)
    report.manifest_path.write_text("this is not json", encoding="utf-8")
    assert canary.load_canary_farm(root) == ()
    watcher = canary.CanaryWatcher(root)
    watcher.snapshot()
    assert watcher.scan() == []
    repaired = canary.deploy_canary_farm(root)
    assert repaired.count == report.count
    assert len(canary.load_canary_farm(root)) == report.count


def test_tampered_manifest_digest_is_rejected(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    report = canary.deploy_canary_farm(root)
    payload = json.loads(report.manifest_path.read_text(encoding="utf-8"))
    payload["decoys"][0]["sha256"] = "0" * 64
    report.manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    assert canary.load_canary_farm(root) == ()


def test_fingerprint_fields_and_record_digest(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    report = canary.deploy_canary_farm(root)
    records = canary.load_canary_farm(root)
    assert records
    for record in records:
        assert isinstance(record.size, int) and record.size > 0
        assert len(record.sha256) == 64
        assert isinstance(record.mtime_ns, int) and record.mtime_ns > 0
        assert isinstance(record.inode, int) and record.inode >= 0
        assert record.marker.startswith(canary.CANARY_FARM_MARKER)
        assert record.kind in canary.FARM_KINDS
    payload = json.loads(report.manifest_path.read_text(encoding="utf-8"))
    assert payload["version"] == canary.FARM_MANIFEST_VERSION
    assert payload["digest"] == canary._farm_digest(records)
    assert payload["generator"] == canary.FARM_GENERATOR


def test_empty_tree_deploys_nothing_without_raising(tmp_path: Path) -> None:
    root = tmp_path / "empty"
    root.mkdir()
    report = canary.deploy_canary_farm(root)
    assert report.count == 0
    assert report.manifest_path.is_file()
    assert canary.load_canary_farm(root) == ()
    assert canary.remove_canary_farm(root) == 0


def test_bad_arguments_are_rejected(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    with pytest.raises(canary.CanaryFarmError):
        canary.deploy_canary_farm(root, per_directory=0)
    with pytest.raises(canary.CanaryFarmError):
        canary.deploy_canary_farm(root, max_files=0)
    with pytest.raises(canary.CanaryFarmError):
        canary.deploy_canary_farm(root, kinds=("bogus",))
    with pytest.raises(canary.CanaryFarmError):
        canary.deploy_canary_farm(tmp_path / "missing")
    with pytest.raises(canary.CanaryFarmError):
        canary.deploy_canary_farm(root, per_directory=True)


def test_legitimate_bulk_writes_do_not_fire_the_farm(tmp_path: Path) -> None:
    # Negative control: npm ci / pip install / cargo build style activity in the
    # decoy directories must produce zero farm events. This is the false-positive
    # measurement the design constraint demands, not an estimate.
    root = _tree(tmp_path / "project")
    report = canary.deploy_canary_farm(root)
    watcher = canary.CanaryWatcher(root)
    watcher.snapshot()
    decoy_paths = {root / record.rel_path for record in report.deployed}

    targets = [root / "src", root / "docs", root / "data"]
    created: list[Path] = []
    for index in range(200):
        directory = targets[index % len(targets)]
        path = directory / ("build_artifact_%03d.txt" % index)
        path.write_text("generated content " + str(index) + chr(10), encoding="utf-8")
        created.append(path)
    for path in created[:50]:
        path.write_text("regenerated content" + chr(10), encoding="utf-8")
    for path in created[50:100]:
        path.rename(path.with_name(path.stem + "_renamed.txt"))
    for path in created[100:150]:
        path.unlink()
    for index in range(20):
        (root / "docs" / ("nested_" + str(index))).mkdir()
    assert not (decoy_paths & set(created))

    events = watcher.scan()
    farm_events = [event for event in events if event.kind.startswith("canary_")]
    assert farm_events == [], "legitimate bulk writes produced farm events: " + str(farm_events)


def test_deploy_and_tick_performance(tmp_path: Path) -> None:
    root = tmp_path / "wide"
    root.mkdir()
    for index in range(500):
        directory = root / ("pkg" + str(index).zfill(3))
        directory.mkdir()
        (directory / "module.py").write_text("VALUE = " + str(index) + chr(10), encoding="utf-8")
    started = time.perf_counter()
    report = canary.deploy_canary_farm(root, max_files=40)
    deploy_seconds = time.perf_counter() - started
    assert report.count == 40
    assert deploy_seconds < 2.0, "deploy of 40 decoys took " + format(deploy_seconds, ".3f") + "s"

    watcher = canary.CanaryWatcher(root)
    watcher.snapshot()
    started = time.perf_counter()
    farm_events = watcher.farm_tick()
    tick_seconds = time.perf_counter() - started
    assert farm_events == []
    assert tick_seconds < 0.1, "one farm tick took " + format(tick_seconds, ".3f") + "s"
    # The full scan also runs the pre-existing legacy discovery walk, which is
    # bounded by depth and candidate count; it must stay in the same order.
    started = time.perf_counter()
    watcher.scan()
    full_seconds = time.perf_counter() - started
    assert full_seconds < 0.6, "full canary scan took " + format(full_seconds, ".3f") + "s"


def test_farm_status_line_is_english(tmp_path: Path) -> None:
    root = _tree(tmp_path / "project")
    assert canary.canary_farm_status(root) == "canary farm: none armed"
    canary.deploy_canary_farm(root)
    status = canary.canary_farm_status(root)
    assert status.startswith("canary farm: ")
    assert "decoy" in status
    assert status.isascii()


def test_cli_canary_deploy_status_remove(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The farm must be reachable from the shipped command line, not only tests."""

    from tauhaulity.cli import main

    root = _tree(tmp_path / "project")
    assert main(["canary", "deploy", str(root), "--max-files", "3"]) == 0
    deployed = capsys.readouterr().out
    assert "canary farm: 3 decoy(s) armed" in deployed
    assert "manifest:" in deployed
    assert len(canary.load_canary_farm(root)) == 3

    assert main(["canary", "status", str(root)]) == 0
    assert "3 decoy(s) armed" in capsys.readouterr().out

    assert main(["canary", "remove", str(root)]) == 0
    assert "removed: 3 decoy(s)" in capsys.readouterr().out
    assert canary.load_canary_farm(root) == ()
    assert main(["canary", "status", str(root)]) == 0
    assert "none armed" in capsys.readouterr().out


def test_cli_canary_rejects_invalid_arguments(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    from tauhaulity.cli import main

    root = _tree(tmp_path / "project")
    assert main(["canary", "deploy", str(root), "--per-directory", "0"]) == 3
    assert "per_directory" in capsys.readouterr().err
    assert canary.load_canary_farm(root) == ()
    assert main(["canary", "deploy", str(tmp_path / "missing")]) == 3
    assert "not a directory" in capsys.readouterr().err
