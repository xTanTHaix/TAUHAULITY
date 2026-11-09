"""Tests for pillar three: the 32 opcode copy-on-write register VM.

Every test executes real bytecode assembled by the module itself. The invariants
are checked through observable state (balances, base map, shadow map, gas counter)
rather than through internal attributes.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tauhaulity.core.contracts import ScanContext, ScanOptions
from tauhaulity.pillars import p03_veritas as pillar


def _make_ctx(target: Path, platform_info, policy) -> ScanContext:
    return ScanContext(target=Path(target), platform=platform_info, policy=policy, options=ScanOptions())


def test_opcode_table_has_exactly_thirty_two_unique_codes() -> None:
    assert len(pillar.OPCODES) == 32
    assert len(set(pillar.OPCODES.values())) == 32
    assert sorted(pillar.OPCODES.values()) == list(range(32))
    assert set(pillar.MNEMONICS) == set(range(32))


def test_assembler_emits_fixed_width_words() -> None:
    code = pillar.assemble("LOADI r0, 30\nXFER 0x10, 0x11, r0\nCOMMIT\n")
    assert len(code) % 4 == 0
    assert len(code) == 12
    opcodes = [code[index] for index in range(0, len(code), 4)]
    assert opcodes == [pillar.OPCODES["LOADI"], pillar.OPCODES["XFER"], pillar.OPCODES["COMMIT"]]


def test_valid_transfer_commits_and_preserves_conservation() -> None:
    vm = pillar.VeritasVM(accounts={0x10: 100, 0x11: 0})
    code = pillar.assemble("LOADI r0, 30\nXFER 0x10, 0x11, r0\nCOMMIT\n")
    result = vm.run(code, gas=64)
    assert result.status == "SAFE"
    assert result.committed is True
    assert result.accounts[0] == 70
    assert result.accounts[1] == 30
    assert result.base_memory == {0x10: 100, 0x11: 0}
    assert result.shadow_memory == {0x10: 70, 0x11: 30}
    assert result.gas_used == 3
    assert result.steps == 3
    assert vm.base[0x10] == 100
    assert vm.read_memory(0x10) == 70


def test_overdraft_is_rejected_without_partial_write() -> None:
    vm = pillar.VeritasVM(accounts={0x10: 100})
    code = pillar.assemble("LOADI r0, 500\nXFER 0x10, 0x11, r0\nCOMMIT\n")
    result = vm.run(code, gas=64)
    assert result.status == "VIOLATION"
    assert "INSUFFICIENT_BALANCE" in result.violations
    assert result.committed is False
    assert result.accounts[0] == 100
    assert result.shadow_memory == {}
    assert result.base_memory == {0x10: 100}


def test_negative_balance_invariant_catches_direct_store() -> None:
    program = """
LOADI r0, 1
LOADI r1, 5
SUB r0, r1
STORE r0, 0x10
COMMIT
"""
    result = pillar.VeritasVM().run(pillar.assemble(program), gas=64)
    assert result.status == "VIOLATION"
    assert "NEGATIVE_BALANCE" in result.violations
    assert result.accounts[0] == -4


def test_balance_conservation_invariant() -> None:
    program = """
LOADI r0, 100
STORE r0, 0x11
COMMIT
"""
    result = pillar.VeritasVM(accounts={0x10: 100}).run(pillar.assemble(program), gas=64)
    assert result.status == "VIOLATION"
    assert "BALANCE_CONSERVATION" in result.violations


def test_uid_escalation_requires_capability() -> None:
    code = pillar.assemble("SETUID 0\nCOMMIT\n")
    rejected = pillar.VeritasVM(accounts={0x10: 1}).run(code, gas=16)
    assert rejected.status == "VIOLATION"
    assert "UID_ESCALATION_DENIED" in rejected.violations
    assert rejected.uid == 1000
    allowed = pillar.VeritasVM(accounts={0x10: 1}, allow_uid0=True).run(code, gas=16)
    assert allowed.status == "SAFE"
    assert allowed.uid == 0
    assert allowed.committed is True


def test_gas_meter_stops_infinite_loop() -> None:
    result = pillar.run(pillar.assemble("loop:\nJMP loop\n"), gas=10)
    assert result.status == "GAS_EXHAUSTED"
    assert result.steps == 10
    assert result.gas_used == 10
    assert "GAS_EXHAUSTED" in result.violations


def test_gas_instruction_charges_extra_budget() -> None:
    result = pillar.run(pillar.assemble("GAS 20\nCOMMIT\n"), gas=10)
    assert result.status == "VIOLATION"
    assert "GAS_EXHAUSTED" in result.violations


def test_branches_and_calls() -> None:
    program = """
LOADI r0, 1
LOADI r1, 2
CMP r0, r1
JNZ skip
LOADI r2, 42
skip:
CALL sub
HALT
sub:
LOADI r3, 7
RET
"""
    result = pillar.VeritasVM().run(pillar.assemble(program), gas=64)
    assert result.status == "SAFE"
    assert result.registers[2] == 0
    assert result.registers[3] == 7
    assert result.committed is False


def test_division_by_zero_is_a_violation() -> None:
    result = pillar.run(pillar.assemble("DIV r0, r0\nHALT\n"), gas=8)
    assert result.status == "VIOLATION"
    assert "DIVISION_BY_ZERO" in result.violations


def test_stack_and_register_bounds() -> None:
    underflow = pillar.run(pillar.assemble("POP r0\nHALT\n"), gas=8)
    assert underflow.status == "VIOLATION"
    assert "STACK_UNDERFLOW" in underflow.violations
    bad_register = pillar.run(bytes((pillar.OPCODES["MOV"], 9, 0, 0)), gas=8)
    assert bad_register.status == "VIOLATION"
    assert "BAD_REGISTER" in bad_register.violations


def test_assembler_rejects_bad_programs() -> None:
    with pytest.raises(pillar.AssemblyError):
        pillar.assemble("NOT_AN_OPCODE r0\n")
    with pytest.raises(pillar.AssemblyError):
        pillar.assemble("MOV r0\n")
    with pytest.raises(pillar.AssemblyError):
        pillar.assemble("JMP nowhere\n")
    with pytest.raises(pillar.AssemblyError):
        pillar.assemble("loop:\nNOP\nloop:\nNOP\n")
    with pytest.raises(pillar.AssemblyError):
        pillar.assemble("LOADI r9, 1\n")
    with pytest.raises(pillar.AssemblyError):
        pillar.assemble("LOADI r0, 0xFFFFF\n")


def test_vm_rejects_bad_bytecode_length() -> None:
    vm = pillar.VeritasVM()
    with pytest.raises(pillar.AssemblyError):
        vm.load(b"\x00\x00\x00")


def test_probe_returns_legal_finding(sample_project: Path, platform_info, default_policy) -> None:
    ctx = _make_ctx(sample_project, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.pillar == 3
    assert finding.status in pillar.SPEC.statuses
    assert 0.0 <= finding.risk <= pillar.SPEC.risk_scale
    assert "32-opcode" in finding.slot("detail")
    ctx.record(finding)
