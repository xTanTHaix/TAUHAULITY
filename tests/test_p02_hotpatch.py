"""Tests for pillar two: atomic pointer slots and capability reporting.

The pointer slot is real memory: the tests verify compare-and-swap semantics, that
a swap never dirties a neighbouring word, and that a concurrent CAS loop loses and
retries correctly. The capability probes are checked for internal consistency
rather than for a specific host answer.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

import pytest

from tauhaulity.core.contracts import ScanContext, ScanOptions
from tauhaulity.pillars import p02_hotpatch as pillar


def _make_ctx(target: Path, platform_info, policy) -> ScanContext:
    return ScanContext(target=Path(target), platform=platform_info, policy=policy, options=ScanOptions())


@pytest.mark.parametrize("use_hardware", [False, True])
def test_atomic_slot_compare_and_swap(use_hardware: bool) -> None:
    slot = pillar.AtomicPointerSlot(0, capacity_words=4, index=1, use_hardware=use_hardware)
    assert slot.value == 0
    assert slot.adjacent_word(-1) == 0
    assert slot.adjacent_word(1) == 0
    assert slot.compare_and_swap(0, 0xDEADBEEF) is True
    assert slot.value == 0xDEADBEEF
    assert slot.compare_and_swap(0, 0xFEEDFACE) is False
    assert slot.value == 0xDEADBEEF
    previous = slot.exchange(0xCAFEBABE)
    assert previous == 0xDEADBEEF
    assert slot.value == 0xCAFEBABE
    # The swap touched eight bytes only: the neighbouring words are still zero.
    assert slot.adjacent_word(-1) == 0
    assert slot.adjacent_word(1) == 0
    stats = slot.stats()
    assert stats["address"] > 0
    # One successful CAS plus one exchange; the failed CAS never wrote.
    assert stats["swaps"] == 2
    assert isinstance(stats["hardware"], bool)


def test_atomic_slot_rejects_invalid_values() -> None:
    with pytest.raises(ValueError):
        pillar.AtomicPointerSlot(-1)
    with pytest.raises(ValueError):
        pillar.AtomicPointerSlot(0, capacity_words=0)
    with pytest.raises(ValueError):
        pillar.AtomicPointerSlot(0, capacity_words=2, index=2)
    slot = pillar.AtomicPointerSlot(0)
    with pytest.raises(ValueError):
        slot.exchange(1 << 64)
    with pytest.raises(ValueError):
        slot.compare_and_swap(-1, 0)
    with pytest.raises(IndexError):
        slot.adjacent_word(5)


def test_atomic_slot_cas_loop_is_thread_safe() -> None:
    slot = pillar.AtomicPointerSlot(0, capacity_words=2)
    threads = 4
    increments = 100

    def worker() -> None:
        for _ in range(increments):
            slot.bump()

    workers = [threading.Thread(target=worker) for _ in range(threads)]
    for worker in workers:
        worker.start()
    for worker in workers:
        worker.join(timeout=10)
    assert slot.value == threads * increments


def test_breakpoint_capability_is_honest() -> None:
    capability = pillar.HardwareBreakpointCapability().probe()
    assert capability.mechanism
    assert capability.detail
    assert capability.slots in {0, 4}
    if capability.supported:
        assert capability.slots == 4
    if os.name != "nt":
        assert capability.self_service is False
        assert capability.dr_readable is False
        assert capability.ptrace_scope is None or isinstance(capability.ptrace_scope, int)
    else:
        assert capability.ptrace_scope is None


def test_syscall_boundary_state() -> None:
    state = pillar.SyscallBoundary().probe()
    assert state.detail
    assert state.mechanism in {"seccomp-bpf", "process-mitigation-policy"}
    if os.name == "nt":
        assert state.seccomp_mode is None
        assert state.available == bool(state.enabled_policies)
    else:
        assert state.available == (state.seccomp_mode is not None and state.seccomp_mode > 0)
        assert state.no_new_privs is None or isinstance(state.no_new_privs, bool)


def test_probe_returns_legal_finding(sample_project: Path, platform_info, default_policy) -> None:
    ctx = _make_ctx(sample_project, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.pillar == 2
    assert finding.status in pillar.SPEC.statuses
    assert 0.0 <= finding.risk <= pillar.SPEC.risk_scale
    assert finding.slot("hotpatch") in {"YES", "NO"}
    assert finding.slot("detail")
    ctx.record(finding)
