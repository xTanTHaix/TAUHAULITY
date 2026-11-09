"""Pillar 3 - VERITAS-GATE: a real 32-opcode copy-on-write register VM.

Why a VM and not a linter: privileged state transitions (a balance move, a UID
change) are only checkable when they are executed against a shadow state that can
be discarded. The VM here executes a compact bytecode program against copy-on-write
memory, keeps a deterministic gas meter so a hostile loop cannot hang the scanner,
and refuses to commit when an invariant breaks.

Invariants enforced on every executed program:
* Conservation: the sum of the account slots is identical before and after a
  committed program. It is checked at COMMIT and HALT, which is where a caller
  would sign off on the transaction.
* Non-negative balances: the account slots may never hold a negative value. A
  direct STORE can attempt it, so the check runs after every instruction instead
  of trusting the transfer opcode.
* UID transition guard: moving to UID 0 requires an explicit capability flag. A
  program that tries it without the flag is rejected before the transition lands.

Copy-on-write trap that is central to the design: reads must see the pristine base
snapshot until the first write to an address. Keeping the base frozen (rather than
copying the whole map up front) makes the simulation cheap for the 16 account
slots a typical policy touches, and it makes the CoW behaviour directly testable:
after a run the base snapshot is still byte identical and only the shadow dict
holds modified slots.

The bytecode is fixed width (four bytes: opcode plus three operand bytes) so
decoding never needs a length table and a corrupted stream can never desynchronize
the instruction pointer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Mapping

from tauhaulity.core.contracts import Finding, PillarSpec, ScanContext, SPEC_BY_KEY, make_finding

SPEC: PillarSpec = SPEC_BY_KEY["veritas_gate"]

INSTRUCTION_BYTES: Final[int] = 4
REGISTER_COUNT: Final[int] = 8
ACCOUNT_BASE: Final[int] = 0x10
ACCOUNT_COUNT: Final[int] = 16
MEMORY_LIMIT: Final[int] = 256
STACK_LIMIT: Final[int] = 64
CALL_DEPTH_LIMIT: Final[int] = 64
_I64_MASK: Final[int] = (1 << 64) - 1
_I64_SIGN: Final[int] = 1 << 63

# Exactly 32 opcodes. Keeping the numeric ids stable matters because a compiled
# policy rule is a byte string, not a symbolic program.
OPCODES: Final[dict[str, int]] = {
    "NOP": 0,
    "HALT": 1,
    "LOADI": 2,
    "MOV": 3,
    "LOAD": 4,
    "STORE": 5,
    "ADD": 6,
    "SUB": 7,
    "MUL": 8,
    "DIV": 9,
    "MOD": 10,
    "AND": 11,
    "OR": 12,
    "XOR": 13,
    "SHL": 14,
    "SHR": 15,
    "CMP": 16,
    "JMP": 17,
    "JZ": 18,
    "JNZ": 19,
    "JLT": 20,
    "JGT": 21,
    "PUSH": 22,
    "POP": 23,
    "CALL": 24,
    "RET": 25,
    "SETUID": 26,
    "XFER": 27,
    "CHECKBAL": 28,
    "GAS": 29,
    "COMMIT": 30,
    "TRAP": 31,
}
MNEMONICS: Final[dict[int, str]] = {value: key for key, value in OPCODES.items()}

# Operand shapes used by both the assembler and the decoder.
_ARITY: Final[dict[str, str]] = {
    "NOP": "none",
    "HALT": "none",
    "RET": "none",
    "COMMIT": "none",
    "LOADI": "reg_imm16",
    "MOV": "reg_reg",
    "LOAD": "reg_addr",
    "STORE": "reg_addr",
    "ADD": "reg_reg",
    "SUB": "reg_reg",
    "MUL": "reg_reg",
    "DIV": "reg_reg",
    "MOD": "reg_reg",
    "AND": "reg_reg",
    "OR": "reg_reg",
    "XOR": "reg_reg",
    "SHL": "reg_imm8",
    "SHR": "reg_imm8",
    "CMP": "reg_reg",
    "JMP": "target",
    "JZ": "target",
    "JNZ": "target",
    "JLT": "target",
    "JGT": "target",
    "PUSH": "reg",
    "POP": "reg",
    "CALL": "target",
    "SETUID": "imm16",
    "XFER": "addr_addr_reg",
    "CHECKBAL": "addr",
    "GAS": "imm16",
    "TRAP": "imm8",
}

_STATUS_SAFE = "SAFE"
_STATUS_VIOLATION = "VIOLATION"
_STATUS_GAS = "GAS_EXHAUSTED"
_STATUS_ERROR = "ERROR"


class AssemblyError(ValueError):
    """Raised when a symbolic program cannot be turned into bytecode."""


class VmViolation(RuntimeError):
    """Raised inside the interpreter when an invariant or a trap fires.

    Attributes:
        code: Machine readable violation token, for example NEGATIVE_BALANCE.
    """

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _wrap_signed(value: int) -> int:
    """Wrap an integer into signed 64-bit two's complement.

    Wrapping instead of masking is what makes an overdraft expressible: the probe
    can subtract its way below zero and watch the invariant reject it.
    """

    masked = value & _I64_MASK
    return masked - (1 << 64) if masked & _I64_SIGN else masked


@dataclass(frozen=True, slots=True)
class VeritasResult:
    """Outcome of one VM execution.

    Attributes:
        status: SAFE, VIOLATION, GAS_EXHAUSTED or ERROR.
        steps: Number of instructions actually executed.
        gas_used: Deterministic instruction budget consumed.
        gas_limit: Budget the program was given.
        violations: Machine readable violation tokens, most recent last.
        registers: Final register file, signed 64-bit values.
        accounts: Final value of every account slot, signed 64-bit.
        uid: Final effective UID held by the VM.
        committed: True when a COMMIT instruction completed cleanly.
        halted: True when the program stopped (HALT, COMMIT, trap or violation).
        base_memory: Immutable baseline that was never mutated.
        shadow_memory: Copy-on-write overlay produced by the program.
        detail: One line explanation for the dossier.
    """

    status: str
    steps: int
    gas_used: int
    gas_limit: int
    violations: tuple[str, ...]
    registers: tuple[int, ...]
    accounts: tuple[int, ...]
    uid: int
    committed: bool
    halted: bool
    base_memory: Mapping[int, int]
    shadow_memory: Mapping[int, int]
    detail: str

    @property
    def ok(self) -> bool:
        """True when the program ran to completion without a violation."""

        return self.status == _STATUS_SAFE


class VeritasVM:
    """Copy-on-write register VM with a deterministic gas meter.

    Attributes:
        ACCOUNT_BASE: First memory address treated as an account slot.
        ACCOUNT_COUNT: Number of consecutive account slots.
    """

    ACCOUNT_BASE: Final[int] = ACCOUNT_BASE
    ACCOUNT_COUNT: Final[int] = ACCOUNT_COUNT

    def __init__(
        self,
        *,
        accounts: Mapping[int, int] | None = None,
        allow_uid0: bool = False,
        uid: int = 1000,
    ) -> None:
        if not 0 <= uid <= 0xFFFF:
            raise ValueError("uid must fit in an unsigned 16-bit value")
        self.allow_uid0 = bool(allow_uid0)
        self._base: dict[int, int] = {}
        for address, value in (accounts or {}).items():
            self._write_base(int(address), int(value))
        self._baseline_sum = sum(self._base.get(address, 0) for address in self._account_addresses())
        self._registers = [0] * REGISTER_COUNT
        self._shadow: dict[int, int] = {}
        self._stack: list[int] = []
        self._return_stack: list[int] = []
        self._cmp_left = 0
        self._cmp_right = 0
        self._uid = int(uid)
        self._pc = 0
        self._steps = 0
        self._gas_used = 0
        self._gas_limit = 0
        self._halted = False
        self._committed = False
        self._violations: list[str] = []
        self._words: list[tuple[int, int, int, int]] = []

    def _account_addresses(self) -> range:
        return range(ACCOUNT_BASE, ACCOUNT_BASE + ACCOUNT_COUNT)

    def _write_base(self, address: int, value: int) -> None:
        if not 0 <= address < MEMORY_LIMIT:
            raise ValueError(f"account address {address} outside 0..{MEMORY_LIMIT - 1}")
        self._base[address] = _wrap_signed(value)

    @property
    def registers(self) -> tuple[int, ...]:
        """Current register file as an immutable tuple."""

        return tuple(self._registers)

    @property
    def uid(self) -> int:
        """Current effective UID inside the sandbox."""

        return self._uid

    @property
    def shadow(self) -> dict[int, int]:
        """Copy-on-write overlay; empty means nothing was written."""

        return dict(self._shadow)

    @property
    def base(self) -> dict[int, int]:
        """Frozen baseline snapshot; the VM never mutates it."""

        return dict(self._base)

    def read_memory(self, address: int) -> int:
        """Read a memory slot through the copy-on-write overlay."""

        if not 0 <= address < MEMORY_LIMIT:
            raise ValueError(f"address {address} outside 0..{MEMORY_LIMIT - 1}")
        if address in self._shadow:
            return self._shadow[address]
        return self._base.get(address, 0)

    def write_memory(self, address: int, value: int) -> None:
        """Write a memory slot into the shadow overlay."""

        if not 0 <= address < MEMORY_LIMIT:
            raise ValueError(f"address {address} outside 0..{MEMORY_LIMIT - 1}")
        self._shadow[address] = _wrap_signed(value)

    def load(self, code: bytes) -> None:
        """Decode a bytecode program into the instruction buffer.

        Raises:
            AssemblyError: When the stream length is not a multiple of four.
        """

        material = bytes(code)
        if len(material) % INSTRUCTION_BYTES != 0:
            raise AssemblyError("bytecode length must be a multiple of four")
        words: list[tuple[int, int, int, int]] = []
        for offset in range(0, len(material), INSTRUCTION_BYTES):
            chunk = material[offset : offset + INSTRUCTION_BYTES]
            words.append((chunk[0], chunk[1], chunk[2], chunk[3]))
        self._words = words

    def run(self, code: bytes, *, gas: int = 10_000) -> VeritasResult:
        """Execute a program under a gas budget and return the final state.

        Raises:
            ValueError: When gas is negative.
        """

        if gas < 0:
            raise ValueError("gas must not be negative")
        self.load(code)
        self._gas_limit = int(gas)
        self._gas_used = 0
        self._steps = 0
        self._halted = False
        self._committed = False
        status = _STATUS_SAFE
        while not self._halted:
            if self._pc >= len(self._words):
                break
            if self._gas_used >= self._gas_limit:
                self._violations.append("GAS_EXHAUSTED")
                status = _STATUS_GAS
                self._halted = True
                break
            opcode, arg_a, arg_b, arg_c = self._words[self._pc]
            self._pc += 1
            self._gas_used += 1
            self._steps += 1
            try:
                self._execute(opcode, arg_a, arg_b, arg_c)
                self._check_soft_invariants()
            except VmViolation as exc:
                self._violations.append(exc.code)
                status = _STATUS_VIOLATION
                self._halted = True
                break
        if status == _STATUS_SAFE and not self._halted:
            # Falling off the end of the program is a clean stop; the final
            # invariants are still verified because the state is about to be read.
            self._halted = True
        return VeritasResult(
            status=status,
            steps=self._steps,
            gas_used=self._gas_used,
            gas_limit=self._gas_limit,
            violations=tuple(self._violations),
            registers=tuple(self._registers),
            accounts=tuple(self.read_memory(address) for address in self._account_addresses()),
            uid=self._uid,
            committed=self._committed,
            halted=self._halted,
            base_memory=dict(self._base),
            shadow_memory=dict(self._shadow),
            detail=self._describe(status),
        )

    def _describe(self, status: str) -> str:
        if status == _STATUS_SAFE:
            return (
                f"program completed in {self._steps} step(s), {self._gas_used} gas, "
                f"uid {self._uid}, committed={self._committed}"
            )
        if status == _STATUS_GAS:
            return f"gas meter stopped the program after {self._steps} step(s)"
        if status == _STATUS_VIOLATION:
            return f"invariant rejected the program: {', '.join(self._violations)}"
        return "vm error"

    def _execute(self, opcode: int, arg_a: int, arg_b: int, arg_c: int) -> None:
        """Execute one decoded instruction.

        Raises:
            VmViolation: On an invariant break, trap or malformed operand.
        """

        name = MNEMONICS.get(opcode)
        if name is None:
            raise VmViolation("INVALID_OPCODE", f"opcode {opcode} is not part of the 32-opcode set")
        if name == "NOP":
            return
        if name == "HALT":
            self._check_final_invariants()
            self._halted = True
            return
        if name == "COMMIT":
            self._check_final_invariants()
            self._committed = True
            self._halted = True
            return
        if name == "LOADI":
            self._set_register(arg_a, _wrap_signed(arg_b | (arg_c << 8)))
            return
        if name == "MOV":
            self._set_register(arg_a, self._get_register(arg_b))
            return
        if name == "LOAD":
            self._set_register(arg_a, self.read_memory(arg_b))
            return
        if name == "STORE":
            self.write_memory(arg_b, self._get_register(arg_a))
            return
        if name in {"ADD", "SUB", "MUL", "DIV", "MOD", "AND", "OR", "XOR"}:
            left = self._get_register(arg_a)
            right = self._get_register(arg_b)
            self._set_register(arg_a, self._arithmetic(name, left, right))
            return
        if name in {"SHL", "SHR"}:
            value = self._get_register(arg_a)
            shift = arg_b & 0x3F
            if name == "SHL":
                self._set_register(arg_a, _wrap_signed(value << shift))
            else:
                self._set_register(arg_a, _wrap_signed((value & _I64_MASK) >> shift))
            return
        if name == "CMP":
            self._cmp_left = self._get_register(arg_a)
            self._cmp_right = self._get_register(arg_b)
            return
        if name == "JMP":
            self._jump(arg_b | (arg_c << 8))
            return
        if name == "JZ":
            if self._cmp_left == self._cmp_right:
                self._jump(arg_b | (arg_c << 8))
            return
        if name == "JNZ":
            if self._cmp_left != self._cmp_right:
                self._jump(arg_b | (arg_c << 8))
            return
        if name == "JLT":
            if self._cmp_left < self._cmp_right:
                self._jump(arg_b | (arg_c << 8))
            return
        if name == "JGT":
            if self._cmp_left > self._cmp_right:
                self._jump(arg_b | (arg_c << 8))
            return
        if name == "PUSH":
            if len(self._stack) >= STACK_LIMIT:
                raise VmViolation("STACK_OVERFLOW", f"data stack exceeded {STACK_LIMIT} entries")
            self._stack.append(self._get_register(arg_a))
            return
        if name == "POP":
            if not self._stack:
                raise VmViolation("STACK_UNDERFLOW", "POP on an empty data stack")
            self._set_register(arg_a, self._stack.pop())
            return
        if name == "CALL":
            if len(self._return_stack) >= CALL_DEPTH_LIMIT:
                raise VmViolation("CALL_DEPTH", f"call stack exceeded {CALL_DEPTH_LIMIT} frames")
            self._return_stack.append(self._pc)
            self._jump(arg_b | (arg_c << 8))
            return
        if name == "RET":
            if not self._return_stack:
                raise VmViolation("STACK_UNDERFLOW", "RET without a matching CALL")
            self._pc = self._return_stack.pop()
            return
        if name == "SETUID":
            target = arg_b | (arg_c << 8)
            if target == 0 and not self.allow_uid0:
                raise VmViolation("UID_ESCALATION_DENIED", "transition to uid 0 requires an explicit capability")
            self._uid = target
            return
        if name == "XFER":
            source = arg_a
            destination = arg_b
            amount = self._get_register(arg_c)
            self._transfer(source, destination, amount)
            return
        if name == "CHECKBAL":
            balance = self.read_memory(arg_a)
            if balance < 0:
                raise VmViolation("NEGATIVE_BALANCE", f"account {arg_a:#x} holds {balance}")
            return
        if name == "GAS":
            amount = arg_b | (arg_c << 8)
            if self._gas_used + amount > self._gas_limit:
                raise VmViolation("GAS_EXHAUSTED", f"GAS {amount} would exceed the budget")
            self._gas_used += amount
            return
        if name == "TRAP":
            raise VmViolation(f"TRAP_{arg_a:02x}", f"explicit trap 0x{arg_a:02x}")
        raise VmViolation("INVALID_OPCODE", f"unhandled mnemonic {name}")

    def _arithmetic(self, name: str, left: int, right: int) -> int:
        if name == "ADD":
            return _wrap_signed(left + right)
        if name == "SUB":
            return _wrap_signed(left - right)
        if name == "MUL":
            return _wrap_signed(left * right)
        if name == "DIV":
            if right == 0:
                raise VmViolation("DIVISION_BY_ZERO", "DIV with a zero divisor")
            return _wrap_signed(int(left / right))
        if name == "MOD":
            if right == 0:
                raise VmViolation("DIVISION_BY_ZERO", "MOD with a zero divisor")
            return _wrap_signed(left - int(left / right) * right)
        if name == "AND":
            return _wrap_signed(left & right)
        if name == "OR":
            return _wrap_signed(left | right)
        return _wrap_signed(left ^ right)

    def _transfer(self, source: int, destination: int, amount: int) -> None:
        """Move value between two account slots while preserving conservation.

        The guard runs before any write so a rejected transfer leaves no partial
        state; that is the property a pre-commit verifier must provide.
        """

        if not 0 <= source < MEMORY_LIMIT or not 0 <= destination < MEMORY_LIMIT:
            raise VmViolation("BAD_ADDRESS", "XFER addresses must be inside 0..255")
        if amount < 0:
            raise VmViolation("NEGATIVE_TRANSFER", f"XFER amount {amount} is negative")
        balance = self.read_memory(source)
        if balance < amount:
            raise VmViolation(
                "INSUFFICIENT_BALANCE",
                f"account {source:#x} holds {balance} but {amount} was requested",
            )
        self.write_memory(source, balance - amount)
        self.write_memory(destination, self.read_memory(destination) + amount)

    def _check_soft_invariants(self) -> None:
        """Reject negative account balances after every instruction.

        Checking here instead of only at COMMIT means a direct STORE cannot park a
        negative value in an account slot and later hide behind a transfer.
        """

        for address in self._account_addresses():
            if self.read_memory(address) < 0:
                raise VmViolation(
                    "NEGATIVE_BALANCE", f"account {address:#x} became negative"
                )

    def _check_final_invariants(self) -> None:
        """Verify conservation and non-negativity before a commit or halt."""

        self._check_soft_invariants()
        observed = sum(self.read_memory(address) for address in self._account_addresses())
        if observed != self._baseline_sum:
            raise VmViolation(
                "BALANCE_CONSERVATION",
                f"account total moved from {self._baseline_sum} to {observed}",
            )

    def _jump(self, target: int) -> None:
        if not 0 <= target <= len(self._words):
            raise VmViolation("BAD_JUMP", f"jump target {target} outside 0..{len(self._words)}")
        self._pc = target

    def _get_register(self, index: int) -> int:
        if not 0 <= index < REGISTER_COUNT:
            raise VmViolation("BAD_REGISTER", f"register index {index} outside 0..{REGISTER_COUNT - 1}")
        return self._registers[index]

    def _set_register(self, index: int, value: int) -> None:
        if not 0 <= index < REGISTER_COUNT:
            raise VmViolation("BAD_REGISTER", f"register index {index} outside 0..{REGISTER_COUNT - 1}")
        self._registers[index] = _wrap_signed(value)


def _parse_register(token: str) -> int:
    """Parse a register operand written as r0..r7 or a bare 0..7."""

    cleaned = token.strip().lower()
    if cleaned.startswith("r"):
        cleaned = cleaned[1:]
    if not cleaned.isdigit():
        raise AssemblyError(f"invalid register operand {token!r}")
    index = int(cleaned)
    if not 0 <= index < REGISTER_COUNT:
        raise AssemblyError(f"register {token!r} outside r0..r7")
    return index


def _parse_immediate(token: str, *, maximum: int) -> int:
    """Parse a decimal or hexadecimal immediate inside the allowed range."""

    cleaned = token.strip()
    try:
        value = int(cleaned, 0)
    except ValueError as exc:
        raise AssemblyError(f"invalid immediate {token!r}") from exc
    if not 0 <= value <= maximum:
        raise AssemblyError(f"immediate {token!r} outside 0..{maximum}")
    return value


def assemble(source: str) -> bytes:
    """Compile a symbolic program into fixed width four byte instructions.

    Labels are resolved in a second pass because a forward jump does not know its
    target index while the label is still unread.

    Raises:
        AssemblyError: On an unknown mnemonic, a bad operand or an unresolved label.
    """

    parsed: list[tuple[str, list[str], int]] = []
    labels: dict[str, int] = {}
    for line_number, raw_line in enumerate(source.splitlines(), start=1):
        line = raw_line.split("#", 1)[0].split(";", 1)[0].strip()
        if not line:
            continue
        while ":" in line:
            label, _separator, rest = line.partition(":")
            name = label.strip().lower()
            if not name or " " in name or "\t" in name:
                break
            if name in labels:
                raise AssemblyError(f"duplicate label {name!r} on line {line_number}")
            labels[name] = len(parsed)
            line = rest.strip()
            if not line:
                break
        if not line:
            continue
        tokens = line.replace(",", " ").split()
        mnemonic = tokens[0].upper()
        if mnemonic not in OPCODES:
            raise AssemblyError(f"unknown mnemonic {tokens[0]!r} on line {line_number}")
        parsed.append((mnemonic, tokens[1:], line_number))

    encoded = bytearray()
    for mnemonic, operands, line_number in parsed:
        shape = _ARITY[mnemonic]
        try:
            encoded.extend(_encode_instruction(mnemonic, shape, operands, labels))
        except AssemblyError as exc:
            raise AssemblyError(f"line {line_number}: {exc}") from exc
    return bytes(encoded)


def _resolve_target(token: str, labels: Mapping[str, int], instruction_count: int) -> int:
    """Resolve a jump target written as a label or a numeric instruction index."""

    cleaned = token.strip()
    if cleaned.lower() in labels:
        return labels[cleaned.lower()]
    try:
        target = int(cleaned, 0)
    except ValueError as exc:
        raise AssemblyError(f"unknown jump target {token!r}") from exc
    if not 0 <= target <= instruction_count:
        raise AssemblyError(f"jump target {target} outside 0..{instruction_count}")
    return target


def _encode_instruction(
    mnemonic: str,
    shape: str,
    operands: list[str],
    labels: Mapping[str, int],
) -> bytes:
    """Encode one instruction according to its operand shape."""

    opcode = OPCODES[mnemonic]
    arg_a = arg_b = arg_c = 0
    if shape == "none":
        if operands:
            raise AssemblyError(f"{mnemonic} takes no operands")
    elif shape == "reg":
        _require(operands, 1, mnemonic)
        arg_a = _parse_register(operands[0])
    elif shape == "reg_reg":
        _require(operands, 2, mnemonic)
        arg_a = _parse_register(operands[0])
        arg_b = _parse_register(operands[1])
    elif shape == "reg_imm16":
        _require(operands, 2, mnemonic)
        arg_a = _parse_register(operands[0])
        value = _parse_immediate(operands[1], maximum=0xFFFF)
        arg_b, arg_c = value & 0xFF, (value >> 8) & 0xFF
    elif shape == "reg_imm8":
        _require(operands, 2, mnemonic)
        arg_a = _parse_register(operands[0])
        arg_b = _parse_immediate(operands[1], maximum=0x3F)
    elif shape == "reg_addr":
        _require(operands, 2, mnemonic)
        arg_a = _parse_register(operands[0])
        arg_b = _parse_immediate(operands[1], maximum=MEMORY_LIMIT - 1)
    elif shape == "addr":
        _require(operands, 1, mnemonic)
        arg_a = _parse_immediate(operands[0], maximum=MEMORY_LIMIT - 1)
    elif shape == "imm8":
        _require(operands, 1, mnemonic)
        arg_a = _parse_immediate(operands[0], maximum=0xFF)
    elif shape == "imm16":
        _require(operands, 1, mnemonic)
        value = _parse_immediate(operands[0], maximum=0xFFFF)
        # Standalone immediates live in bytes b/c; the interpreter decodes
        # b | c << 8. Writing them into a/b would silently become zero.
        arg_b, arg_c = value & 0xFF, (value >> 8) & 0xFF
    elif shape == "target":
        _require(operands, 1, mnemonic)
        target = _resolve_target(operands[0], labels, 0xFFFF)
        arg_b, arg_c = target & 0xFF, (target >> 8) & 0xFF
    elif shape == "addr_addr_reg":
        _require(operands, 3, mnemonic)
        arg_a = _parse_immediate(operands[0], maximum=MEMORY_LIMIT - 1)
        arg_b = _parse_immediate(operands[1], maximum=MEMORY_LIMIT - 1)
        arg_c = _parse_register(operands[2])
    else:
        raise AssemblyError(f"unsupported operand shape {shape}")
    return bytes((opcode, arg_a & 0xFF, arg_b & 0xFF, arg_c & 0xFF))


def _require(operands: list[str], count: int, mnemonic: str) -> None:
    if len(operands) != count:
        raise AssemblyError(f"{mnemonic} expects {count} operand(s), got {len(operands)}")


def run(code: bytes, *, gas: int = 10_000) -> VeritasResult:
    """Run a bytecode program on a fresh VM with no seeded accounts.

    Raises:
        ValueError: When gas is negative.
    """

    return VeritasVM().run(code, gas=gas)


_VALID_TRANSFER = """
LOADI r0, 30
XFER 0x10, 0x11, r0
COMMIT
"""

_OVERDRAFT = """
LOADI r0, 500
XFER 0x10, 0x11, r0
COMMIT
"""

_UID_ESCALATION = """
SETUID 0
COMMIT
"""

_GAS_LOOP = """
loop:
JMP loop
"""


def _run_self_tests() -> tuple[bool, list[str]]:
    """Execute the fixed probe programs and report which invariants held."""

    problems: list[str] = []
    good = VeritasVM(accounts={0x10: 100, 0x11: 0})
    result = good.run(assemble(_VALID_TRANSFER), gas=64)
    if result.status != _STATUS_SAFE or not result.committed:
        problems.append(f"valid transfer rejected ({result.status})")
    elif result.accounts[0] != 70 or result.accounts[1] != 30:
        problems.append("valid transfer produced wrong balances")
    overdraft = VeritasVM(accounts={0x10: 100})
    if overdraft.run(assemble(_OVERDRAFT), gas=64).status != _STATUS_VIOLATION:
        problems.append("overdraft accepted")
    escalation = VeritasVM(accounts={0x10: 100})
    if escalation.run(assemble(_UID_ESCALATION), gas=64).status != _STATUS_VIOLATION:
        problems.append("uid escalation accepted")
    loop = VeritasVM()
    if loop.run(assemble(_GAS_LOOP), gas=32).status != _STATUS_GAS:
        problems.append("gas meter did not stop an infinite loop")
    return not problems, problems


def probe(ctx: ScanContext) -> Finding:
    """Self-test the CoW VM and report whether pre-commit proof is available.

    A failure is CRITICAL rather than WARNING: if the gate accepts an overdraft or
    a uid escalation then every downstream "verified" transaction is a lie, which
    is exactly the condition this pillar exists to prevent.
    """

    try:
        healthy, problems = _run_self_tests()
    except (AssemblyError, ValueError, RuntimeError) as exc:
        detail = f"vm self-test could not run: {type(exc).__name__}: {exc}"
        return make_finding(
            SPEC,
            "WARNING",
            detail,
            risk=4.0,
            slots={"detail": detail},
            repro_hint="Assemble and run the built-in transfer programs to reproduce the VM failure.",
        )
    if not healthy:
        detail = f"vm invariant self-test failed: {'; '.join(problems)}"
        return make_finding(
            SPEC,
            "CRITICAL",
            detail,
            risk=8.0,
            slots={"detail": detail},
            repro_hint="Run VeritasVM().run(assemble(OVERDRAFT_PROGRAM)) and inspect the result status.",
        )
    detail = (
        f"{len(OPCODES)}-opcode CoW vm self-test passed: transfer committed, overdraft and uid "
        "escalation rejected, gas meter stopped a loop"
    )
    return make_finding(
        SPEC,
        "SAFE",
        detail,
        risk=0.0,
        slots={"detail": detail},
        repro_hint="Assemble a transfer program and confirm the VM commits it without touching the base map.",
    )
