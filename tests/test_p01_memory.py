"""Tests for pillar one: live memory map, page digests and pointer table checks.

The map itself is host specific, so the parsing logic is exercised on a synthetic
/proc/self/maps sample and the live inspector is only required to return a
self-consistent view of the running process.
"""

from __future__ import annotations

import dataclasses
import hashlib
import os
import struct
from pathlib import Path

import pytest

from tauhaulity.core.contracts import ScanContext, ScanOptions
from tauhaulity.pillars import p01_memory as pillar

_SAMPLE_MAPS = """\
55d4a0f00000-55d4a0f12000 r--p 00000000 08:02 1234 /usr/bin/python3
55d4a0f12000-55d4a0f6f000 r-xp 00012000 08:02 1234 /usr/bin/python3
55d4a0f6f000-55d4a0f71000 r--p 0006f000 08:02 1234 /usr/bin/python3
55d4a0f71000-55d4a0f72000 rw-p 00071000 08:02 1234 /usr/bin/python3
7f2a00000000-7f2a00021000 rw-p 00000000 00:00 0
7f2a00100000-7f2a00120000 r-xp 00000000 08:02 5678 /usr/lib/libpython3.12.so.1.0
7f2a00a00000-7f2a00a04000 rwxp 00000000 00:00 0
broken line without the expected layout
ff0000000000-ff0000001000 r-xp 00000000 00:00 0 [vdso]
"""


def _make_ctx(target: Path, platform_info, policy) -> ScanContext:
    return ScanContext(
        target=Path(target),
        platform=platform_info,
        policy=policy,
        options=ScanOptions(),
    )


def test_parse_proc_maps_skips_malformed_lines() -> None:
    regions = pillar.parse_proc_maps(_SAMPLE_MAPS)
    assert len(regions) == 8
    first = regions[0]
    assert (first.start, first.end) == (0x55D4A0F00000, 0x55D4A0F12000)
    assert first.perms == "r--p"
    assert first.path == "/usr/bin/python3"
    assert not first.executable and first.readable and first.private
    text_region = regions[1]
    assert text_region.executable and not text_region.writable
    assert text_region.offset == 0x12000
    writable_exec = regions[6]
    assert writable_exec.perms == "rwxp"
    assert writable_exec.executable and writable_exec.writable
    assert writable_exec.anonymous
    assert writable_exec.path == ""
    vdso = regions[7]
    assert vdso.anonymous


def test_memory_inspector_reads_live_process() -> None:
    inspector = pillar.MemoryInspector()
    regions = inspector.regions()
    assert regions, f"no memory map: {inspector.error}"
    executable = inspector.executable_regions()
    assert executable, "the interpreter must own at least one executable mapping"
    for region in executable:
        assert "x" in region.perms
    private_executable = inspector.executable_private_regions()
    assert isinstance(private_executable, list)
    sample = regions[0]
    containing = inspector.find_region(sample.start)
    assert containing is not None
    assert containing.start <= sample.start < containing.end
    assert inspector.permissions_at(sample.start) == sample.perms
    assert inspector.permissions_at(-1) is None


def test_page_digests_cover_executable_pages() -> None:
    report = pillar.MemoryInspector().page_digests(max_pages=8, max_bytes=64 * 1024)
    assert report.method in {"native", "hashlib"}
    assert report.pages >= 1, "at least one executable page must be readable"
    assert report.total_bytes > 0
    assert len(report.sample) == 64
    assert all(len(digest) == 64 for digest in report.digests)
    assert report.failures >= 0


def test_dirty_executable_page_report() -> None:
    report = pillar.MemoryInspector().dirty_executable_pages(max_pages=32)
    assert report.method
    assert report.detail
    assert report.sampled_pages >= 0
    assert report.dirty_pages == report.anonymous_dirty + report.file_backed_dirty
    assert report.dirty_pages <= report.sampled_pages
    if os.name == "nt":
        assert report.available is False
        assert "MEM_WRITE_WATCH" in report.detail
    elif report.available:
        assert report.sampled_pages > 0


def test_pointer_table_is_resolved_or_honest() -> None:
    table = pillar.MemoryInspector().pointer_table()
    assert table.detail
    assert table.source
    if table.resolved:
        assert table.address is not None and table.address > 0
        if "unmapped" in table.detail:
            # Honest degraded contract: the entry was found in the ELF but the
            # computed address is not mapped, so no protection claim is made.
            assert table.readable is False
            assert table.writable is False
            assert table.sealed is False
        else:
            assert table.readable
            assert table.sealed == (not table.writable)
    else:
        assert table.address is None
        assert table.sealed is False


def _build_elf64_with_got(got_vaddr: int) -> bytes:
    """Build a minimal ELF64 image carrying PT_LOAD and PT_DYNAMIC/DT_PLTGOT."""

    phoff = 64
    phentsize = 56
    dynamic_offset = 0x180
    # The virtual address must map back to the file offset through the PT_LOAD
    # segment, otherwise the parser correctly refuses to locate the table.
    dynamic_vaddr = 0x400180
    buffer = bytearray(dynamic_offset + 32)
    # ELF header
    struct.pack_into(
        "<4sBBBBB7xHHIQQQIHHHHHH",
        buffer,
        0,
        b"\x7fELF",
        2,
        1,
        1,
        0,
        0,
        2,
        0x3E,
        1,
        0x400000,
        phoff,
        0,
        0,
        64,
        phentsize,
        2,
        0,
        0,
        0,
    )
    # PT_LOAD covering the whole file image
    struct.pack_into(
        "<IIQQQQQQ",
        buffer,
        phoff,
        1,
        5,
        0,
        0x400000,
        0x400000,
        len(buffer),
        len(buffer),
        0x1000,
    )
    # PT_DYNAMIC pointing at the dynamic table
    struct.pack_into(
        "<IIQQQQQQ",
        buffer,
        phoff + phentsize,
        2,
        6,
        dynamic_offset,
        dynamic_vaddr,
        dynamic_vaddr,
        32,
        32,
        8,
    )
    struct.pack_into("<qQ", buffer, dynamic_offset, 3, got_vaddr)  # DT_PLTGOT
    struct.pack_into("<qQ", buffer, dynamic_offset + 16, 0, 0)  # DT_NULL
    return bytes(buffer)


def test_elf_got_parser_reads_pltgot() -> None:
    image = _build_elf64_with_got(0x4001A0)
    assert pillar._elf_got_offset(image) == 0x4001A0


def test_elf_load_bias_handles_pie_and_exec() -> None:
    assert pillar._elf_load_bias(2, 0x400000, 0) == 0
    assert pillar._elf_load_bias(3, 0x55D4A0F00000, 0x2000) == 0x55D4A0F00000 - 0x2000
    assert pillar._elf_load_bias(None, 0x55D4A0F00000, 0) is None
    assert pillar._elf_load_bias(1, 0x55D4A0F00000, 0) is None


def test_elf_got_parser_rejects_non_elf() -> None:
    with pytest.raises(ValueError):
        pillar._elf_got_offset(b"not an elf image at all")


def test_jit_executable_memory_is_not_reported_critical(
    sample_project: Path, platform_info, default_policy
) -> None:
    if not pillar._jit_executable_expected():
        pytest.skip("this interpreter does not run a JIT")
    finding = pillar.probe(_make_ctx(sample_project, platform_info, default_policy))
    assert finding.status == "SAFE", finding.detail
    assert finding.risk <= 1.0


def test_probe_returns_legal_finding(sample_project: Path, platform_info, default_policy) -> None:
    ctx = _make_ctx(sample_project, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.pillar == 1
    assert finding.status in pillar.SPEC.statuses
    assert 0.0 <= finding.risk <= pillar.SPEC.risk_scale
    assert finding.slot("detail")
    ctx.record(finding)
    assert ctx.finding(1) is finding

# ---------------------------------------------------------------------------
# S6 memory tamper baseline probe ladder
# ---------------------------------------------------------------------------


def _fake_module(name: str, *, pages: int = 3, page_size: int = 512) -> pillar.ModuleBaseline:
    seed = name.encode("utf-8")
    page_digests = tuple(
        hashlib.sha256(seed + bytes([index])).hexdigest() for index in range(pages)
    )
    return pillar.ModuleBaseline(
        module=name,
        path=f"/virtual/{name}.pyd",
        size=pages * page_size,
        digest=hashlib.sha256(seed).hexdigest(),
        pages=page_digests,
        captured_at="2026-01-01T00:00:00Z",
    )


def _save_synthetic_baseline(
    target: Path, modules: list[pillar.ModuleBaseline]
) -> pillar.BaselineRecord:
    budget = pillar.BaselineBudget(
        total_bytes=1 << 20,
        per_module_bytes=1 << 20,
        page_size=512,
        max_modules=16,
    )
    record = pillar.make_record(
        target, modules, budget=budget, captured_at="2026-01-01T00:00:00Z"
    )
    pillar.save_baseline(target, record)
    return record


def test_probe_reports_absent_baseline_without_writing(
    sample_project: Path, platform_info, default_policy
) -> None:
    finding = pillar.probe(_make_ctx(sample_project, platform_info, default_policy))
    assert finding.status in pillar.SPEC.statuses
    assert "no baseline recorded (run tauhaulity baseline --memory)" in finding.slot("detail")
    assert not pillar.baseline_path(sample_project).exists()


def test_probe_clean_baseline_is_safe(
    tmp_path: Path, platform_info, default_policy, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _fake_module("clean.module")
    _save_synthetic_baseline(tmp_path, [module])
    monkeypatch.setattr(pillar, "_capture_for_probe", lambda previous: (module,))
    finding = pillar.probe(_make_ctx(tmp_path, platform_info, default_policy))
    assert finding.status == "SAFE"
    assert finding.risk == 0.0
    assert "module(s) verified against the baseline captured at" in finding.slot("detail")


def test_probe_changed_module_is_critical(
    tmp_path: Path, platform_info, default_policy, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = _fake_module("changed.module")
    _save_synthetic_baseline(tmp_path, [module])
    mutated = dataclasses.replace(
        module,
        digest=hashlib.sha256(b"mutated").hexdigest(),
        pages=(module.pages[0], hashlib.sha256(b"mutated-page").hexdigest(), module.pages[2]),
    )
    monkeypatch.setattr(pillar, "_capture_for_probe", lambda previous: (mutated,))
    finding = pillar.probe(_make_ctx(tmp_path, platform_info, default_policy))
    assert finding.status == "CRITICAL"
    assert finding.risk == 8.0
    detail = finding.slot("detail")
    assert "baseline mismatch" in detail
    assert "changed.module" in detail
    assert "page offset 512" in detail
    # The detail names the offset; it never dumps page bytes or page digests.
    assert module.pages[1] not in detail
    assert mutated.pages[1] not in detail


def test_probe_missing_module_is_warning(
    tmp_path: Path, platform_info, default_policy, monkeypatch: pytest.MonkeyPatch
) -> None:
    kept = _fake_module("kept.module")
    gone = _fake_module("gone.module")
    _save_synthetic_baseline(tmp_path, [kept, gone])
    monkeypatch.setattr(pillar, "_capture_for_probe", lambda previous: (kept,))
    finding = pillar.probe(_make_ctx(tmp_path, platform_info, default_policy))
    assert finding.status == "WARNING"
    assert finding.risk == 4.0
    detail = finding.slot("detail")
    assert "missing from the current image" in detail
    assert "gone.module" in detail


def test_probe_new_module_is_warning(
    tmp_path: Path, platform_info, default_policy, monkeypatch: pytest.MonkeyPatch
) -> None:
    known = _fake_module("known.module")
    appeared = _fake_module("appeared.module")
    _save_synthetic_baseline(tmp_path, [known])
    monkeypatch.setattr(pillar, "_capture_for_probe", lambda previous: (known, appeared))
    finding = pillar.probe(_make_ctx(tmp_path, platform_info, default_policy))
    assert finding.status == "WARNING"
    assert finding.risk == 3.0
    detail = finding.slot("detail")
    assert "appeared after the baseline" in detail
    assert "appeared.module" in detail


def test_probe_comparison_failure_is_honest(
    tmp_path: Path, platform_info, default_policy, monkeypatch: pytest.MonkeyPatch
) -> None:
    _save_synthetic_baseline(tmp_path, [_fake_module("known.module")])

    def explode(previous: pillar.BaselineRecord) -> tuple[pillar.ModuleBaseline, ...]:
        raise RuntimeError("synthetic capture failure")

    monkeypatch.setattr(pillar, "_capture_for_probe", explode)
    finding = pillar.probe(_make_ctx(tmp_path, platform_info, default_policy))
    assert finding.status == "WARNING"
    assert "RuntimeError" in finding.slot("detail")
    assert "baseline comparison unavailable" in finding.slot("detail")


def test_probe_corrupt_baseline_degrades_with_reason(
    tmp_path: Path, platform_info, default_policy
) -> None:
    store = pillar.baseline_path(tmp_path)
    store.parent.mkdir(parents=True, exist_ok=True)
    store.write_text("{ broken json", encoding="utf-8")
    finding = pillar.probe(_make_ctx(tmp_path, platform_info, default_policy))
    assert finding.status in pillar.SPEC.statuses
    assert "memory baseline unreadable" in finding.slot("detail")
    assert "corrupt" in finding.slot("detail").lower()

