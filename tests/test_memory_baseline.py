"""Tests for the S6 memory tamper baseline.

The live capture needs the current interpreter, so the deterministic mechanics
(store format, compare semantics, budgets) are exercised with synthetic module
files, while the live capture is covered by a separate round-trip and timing test.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

import pytest

from tauhaulity.pillars import p01_memory as pillar

_PAGE_SIZE = 512
_BUDGET = pillar.BaselineBudget(
    total_bytes=1 << 20,
    per_module_bytes=1 << 20,
    page_size=_PAGE_SIZE,
    max_modules=16,
)


def _image(pages: int = 3, page_size: int = _PAGE_SIZE) -> bytes:
    """Deterministic byte image whose pages all differ from each other."""

    return bytes((index * 37 + 11) % 251 for index in range(pages * page_size))


def _module_file(directory: Path, name: str, pages: int = 3) -> Path:
    path = directory / name
    path.write_bytes(_image(pages))
    return path


def _baseline(path: Path, name: str) -> pillar.ModuleBaseline:
    return pillar.hash_module_file(name, path, budget=_BUDGET)


def test_capture_and_compare_round_trip(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    path = _module_file(tmp_path, "tiny_extension.pyd")
    module = _baseline(path, "tiny_extension")
    assert module.size == 3 * _PAGE_SIZE
    assert len(module.pages) == 3
    assert module.truncated is False
    assert module.path == str(path.resolve())

    record = pillar.make_record(project, [module], budget=_BUDGET)
    written = pillar.save_baseline(project, record)
    assert written == pillar.baseline_path(project)
    assert written.is_file()

    loaded = pillar.load_baseline(project)
    assert loaded == record
    assert loaded is not None
    assert loaded.digest == record.digest
    assert loaded.schema == pillar.BASELINE_SCHEMA
    assert pillar.baseline_exists(project) is True
    assert pillar.compare_baseline(loaded, record) == []

    # The store carries an integrity digest of the whole record set.
    document = json.loads(written.read_text(encoding="utf-8"))
    assert document["schema"] == pillar.BASELINE_SCHEMA
    assert document["digest"] == pillar._record_digest(document["payload"])


def test_modified_byte_flips_page_digest(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    path = _module_file(tmp_path, "changed_extension.pyd")
    module = _baseline(path, "changed_extension")
    record = pillar.make_record(project, [module], budget=_BUDGET)
    pillar.save_baseline(project, record)

    data = bytearray(path.read_bytes())
    data[_PAGE_SIZE + 7] ^= 0xFF
    path.write_bytes(bytes(data))
    changed_module = _baseline(path, "changed_extension")
    assert changed_module.pages[1] != module.pages[1]
    assert changed_module.pages[0] == module.pages[0]
    current = pillar.make_record(project, [changed_module], budget=_BUDGET)

    deltas = pillar.compare_baseline(current, record)
    assert len(deltas) == 1
    delta = deltas[0]
    assert delta.kind == "changed"
    assert delta.module == "changed_extension"
    assert delta.page_offset == _PAGE_SIZE
    assert delta.digest_changed is True
    assert delta.detail
    assert "page offset" in delta.detail


def test_deleted_module_is_missing(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    path = _module_file(tmp_path, "vanishing_extension.pyd")
    record = pillar.make_record(project, [_baseline(path, "vanishing_extension")], budget=_BUDGET)
    empty_current = pillar.make_record(project, [], budget=_BUDGET)
    deltas = pillar.compare_baseline(empty_current, record)
    assert len(deltas) == 1
    assert deltas[0].kind == "missing"
    assert deltas[0].module == "vanishing_extension"
    assert deltas[0].page_offset is None
    assert deltas[0].digest_changed is False


def test_extra_module_is_new(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    first = _baseline(_module_file(tmp_path, "first_extension.pyd"), "first_extension")
    second = _baseline(_module_file(tmp_path, "second_extension.so"), "second_extension")
    previous = pillar.make_record(project, [first], budget=_BUDGET)
    current = pillar.make_record(project, [first, second], budget=_BUDGET)
    deltas = pillar.compare_baseline(current, previous)
    assert len(deltas) == 1
    assert deltas[0].kind == "new"
    assert deltas[0].module == "second_extension"
    assert deltas[0].digest_changed is False


def test_changed_modules_sort_before_missing_and_new(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    kept = _baseline(_module_file(tmp_path, "kept_extension.pyd"), "kept_extension")
    gone = _baseline(_module_file(tmp_path, "gone_extension.pyd"), "gone_extension")
    fresh = _baseline(_module_file(tmp_path, "fresh_extension.pyd"), "fresh_extension")
    previous = pillar.make_record(project, [kept, gone], budget=_BUDGET)
    changed_kept = pillar.ModuleBaseline(
        module=kept.module,
        path=kept.path,
        size=kept.size,
        digest=hashlib.sha256(b"mutated").hexdigest(),
        pages=(hashlib.sha256(b"mutated-page").hexdigest(),) + kept.pages[1:],
        captured_at=kept.captured_at,
    )
    current = pillar.make_record(project, [changed_kept, fresh], budget=_BUDGET)
    kinds = [delta.kind for delta in pillar.compare_baseline(current, previous)]
    assert kinds == ["changed", "missing", "new"]


def test_missing_store_degrades_gracefully(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    assert pillar.load_baseline(project) is None
    result = pillar.load_baseline_ex(project)
    assert result.record is None
    assert result.present is False
    assert result.reason
    assert pillar.baseline_exists(project) is False


def test_corrupt_store_reports_explicit_reason(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    store = pillar.baseline_path(project)
    store.parent.mkdir(parents=True, exist_ok=True)

    store.write_text("{ this is not json", encoding="utf-8")
    result = pillar.load_baseline_ex(project)
    assert result.record is None
    assert result.present is True
    assert "corrupt" in result.reason.lower()
    assert pillar.load_baseline(project) is None

    path = _module_file(tmp_path, "valid_extension.pyd")
    record = pillar.make_record(project, [_baseline(path, "valid_extension")], budget=_BUDGET)
    pillar.save_baseline(project, record)
    document = json.loads(store.read_text(encoding="utf-8"))
    document["payload"]["modules"][0]["digest"] = "0" * 64
    store.write_text(json.dumps(document), encoding="utf-8")
    result = pillar.load_baseline_ex(project)
    assert result.record is None
    assert "digest mismatch" in result.reason.lower()

    document["schema"] = 999
    store.write_text(json.dumps(document), encoding="utf-8")
    result = pillar.load_baseline_ex(project)
    assert result.record is None
    assert "schema" in result.reason.lower()

    payload = {
        "target": str(project),
        "captured_at": "2026-01-01T00:00:00Z",
        "page_size": _PAGE_SIZE,
        "total_bytes": 1 << 20,
        "per_module_bytes": 1 << 20,
        "max_modules": 16,
        "refused": [],
        "modules": [
            {
                "module": "broken",
                "path": "/virtual/broken.pyd",
                "size": 512,
                "digest": "f" * 64,
                "pages": [123],
                "captured_at": "2026-01-01T00:00:00Z",
                "truncated": False,
            }
        ],
    }
    store.write_text(
        json.dumps({"schema": pillar.BASELINE_SCHEMA, "digest": pillar._record_digest(payload), "payload": payload}),
        encoding="utf-8",
    )
    result = pillar.load_baseline_ex(project)
    assert result.record is None
    assert "invalid" in result.reason.lower()


def test_budget_truncates_a_40_mib_module(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    path = tmp_path / "huge_extension.pyd"
    path.write_bytes(b"\x00" * (40 * 1024 * 1024))
    budget = pillar.BaselineBudget(
        total_bytes=16 * 1024 * 1024,
        per_module_bytes=4 * 1024 * 1024,
        page_size=4096,
        max_modules=8,
    )
    modules, refused = pillar.hash_module_files([("huge_extension", path)], budget=budget)
    assert refused == ()
    assert len(modules) == 1
    module = modules[0]
    assert module.truncated is True
    assert module.size == 4 * 1024 * 1024
    assert len(module.pages) == 1024
    assert module.size < path.stat().st_size
    assert len(b"\x00" * 0) == 0


def test_total_budget_is_shared_across_modules(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    alpha = tmp_path / "alpha_extension.pyd"
    beta = tmp_path / "beta_extension.pyd"
    alpha.write_bytes(b"\x01" * (3 * 1024 * 1024))
    beta.write_bytes(b"\x02" * (3 * 1024 * 1024))
    budget = pillar.BaselineBudget(
        total_bytes=4 * 1024 * 1024,
        per_module_bytes=4 * 1024 * 1024,
        page_size=4096,
        max_modules=8,
    )
    modules, refused = pillar.hash_module_files(
        [("alpha", alpha), ("beta", beta)], budget=budget
    )
    assert refused == ()
    by_name = {module.module: module for module in modules}
    assert by_name["alpha"].size == 3 * 1024 * 1024
    assert by_name["alpha"].truncated is False
    assert by_name["beta"].size == 1 * 1024 * 1024
    assert by_name["beta"].truncated is True
    assert sum(module.size for module in modules) == 4 * 1024 * 1024


def test_module_limit_refuses_extra_images(tmp_path: Path) -> None:
    first = _module_file(tmp_path, "first_extension.pyd")
    second = _module_file(tmp_path, "second_extension.pyd")
    budget = pillar.BaselineBudget(
        total_bytes=1 << 20,
        per_module_bytes=1 << 20,
        page_size=_PAGE_SIZE,
        max_modules=1,
    )
    modules, refused = pillar.hash_module_files([("first", first), ("second", second)], budget=budget)
    assert len(modules) == 1
    assert len(refused) == 1
    assert "module limit" in refused[0]


def test_non_module_paths_are_refused(tmp_path: Path) -> None:
    notes = tmp_path / "notes.txt"
    notes.write_text("plain text", encoding="utf-8")
    modules, refused = pillar.hash_module_files([("notes", notes)], budget=_BUDGET)
    assert modules == ()
    assert len(refused) == 1
    assert "outside sys.prefix" in refused[0]
    with pytest.raises(ValueError):
        pillar.hash_module_file("notes", notes, budget=_BUDGET)


def test_live_capture_round_trip_and_performance(tmp_path: Path) -> None:
    started = time.perf_counter()
    record = pillar.capture_baseline(tmp_path)
    capture_seconds = time.perf_counter() - started
    assert capture_seconds < 5.0, f"capture took {capture_seconds:.2f}s"
    assert record.modules, "the interpreter must expose executable module images"
    assert record.schema == pillar.BASELINE_SCHEMA
    assert len(record.digest) == 64
    for module in record.modules:
        assert module.module
        assert module.digest
        # A module can be recorded with zero hashed bytes when the total budget
        # was exhausted before it; that state is always marked truncated.
        assert module.pages or module.truncated
        assert module.size >= 0
    loaded = pillar.load_baseline(tmp_path)
    assert loaded is not None
    assert loaded.digest == record.digest
    assert pillar.baseline_exists(tmp_path) is True

    line = pillar.memory_baseline_capture(tmp_path)
    assert line.startswith("memory baseline:")
    assert "\n" not in line
    assert "stored at" in line
    assert pillar.baseline_exists(tmp_path) is True


def test_capture_is_append_only(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    ghost = pillar.ModuleBaseline(
        module="ghost.module",
        path="/virtual/ghost.module.pyd",
        size=_PAGE_SIZE,
        digest=hashlib.sha256(b"ghost").hexdigest(),
        pages=(hashlib.sha256(b"ghost-page").hexdigest(),),
        captured_at="2026-01-01T00:00:00Z",
    )
    pillar.save_baseline(
        project,
        pillar.make_record(project, [ghost], budget=_BUDGET, captured_at="2026-01-01T00:00:00Z"),
    )
    record = pillar.capture_baseline(project)
    names = {module.module for module in record.modules}
    assert "ghost.module" in names, "an append-only capture must keep known modules"
    assert len(names) > 1


def test_probe_is_fast_with_a_baseline_present(tmp_path: Path, platform_info, default_policy) -> None:
    from tauhaulity.core.contracts import ScanContext, ScanOptions

    ctx = ScanContext(
        target=tmp_path,
        platform=platform_info,
        policy=default_policy,
        options=ScanOptions(),
    )
    pillar.capture_baseline(tmp_path)
    store = pillar.baseline_path(tmp_path)
    before = store.read_bytes()
    started = time.perf_counter()
    finding = pillar.probe(ctx)
    probe_seconds = time.perf_counter() - started
    assert probe_seconds < 1.5, f"probe took {probe_seconds:.2f}s"
    assert finding.status in pillar.SPEC.statuses
    assert finding.status == "SAFE", finding.detail
    assert "module(s) verified against the baseline captured at" in finding.slot("detail")
    assert store.read_bytes() == before, "a scan must never rewrite the baseline"
