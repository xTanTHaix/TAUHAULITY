"""Bounded file level supply chain artifact scanner for pillar six.

Pillar six used to verify only its own deserialization firewall. This module
turns the pillar into a scanner of the project that is being scanned:

* serialized payload files (.pkl, .pickle, .joblib, .dill) are streamed through
  pickletools.genops and never loaded. Opcodes that can import a callable, call
  it, mutate an instance or reach outside the stream are reported with their
  mnemonic and byte offset, which is enough evidence to act on while the payload
  stays inert.
* Python source is parsed with ast.parse and only real AST shapes are reported,
  so a string literal or a comment can never trigger a finding. The classic call
  rules cover ungated deserialization, dynamic evaluation of a non-literal
  expression, shell execution, archive extraction and disabled TLS verification.
  The 2026 malware shapes are covered as well: install-time execution from
  setup.py, setup.cfg and an in-tree pyproject build backend; environment
  credential harvesting (enumeration plus a network or process call in one code
  path); raw socket egress to a literal or environment supplied host; the
  reverse-shell shape (socket channel plus a shell spawn); and obfuscated payloads
  (a decoder feeding exec/eval/compile, or a large high-entropy literal executed).
* declared dependencies are audited before they are installed
  (tauhaulity.tools.dep_audit): typosquat names, digit-mixing suspicious names,
  direct URLs, unpinned declarations and foreign indexes become findings without
  any network access.
* every finding carries quarantine_eligible. It is True only when the evidence is
  the file itself (unsafe or malformed pickle payloads, a mismatched or invalid
  pyc cache, and an install-time execution manifest), because moving that file
  out of the load path neutralises it. Call sites, dependency declarations and
  behavioural shapes stay in place for review; see the constant comment.
* every .pyc is verified against its source: caches inside __pycache__ resolve
  the source from the parent directory with the ".cpython-3XX" suffix stripped,
  and legacy caches sitting next to their .py source use that sibling. The PEP
  552 header is checked (magic, flags, recorded source timestamp and size, or the
  blake2b source hash). A source binding mismatch is high, an orphan cache and a
  truncated or foreign-magic header are medium.
* the walk is bounded by ScanBudget (files, bytes, per-file bytes, depth), skips
  the usual build and cache directories plus the policy ignore list, and never
  follows a symlink, so a link loop cannot trap it. When the walk stops early or
  a candidate is larger than the per-file cap, ArtifactReport.truncated is True
  and the detail line states exactly how many files and bytes were inspected.

Nothing here executes a scanned artifact. The stdlib is the only dependency and
an unreadable, undecodable or malformed file is skipped instead of raising, so a
scan of a hostile tree always produces a report.
"""

from __future__ import annotations

import ast
import fnmatch
import importlib.util
import math
import os
import pickletools
import struct
import sys
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import TYPE_CHECKING, Final, Iterable, Iterator, Mapping

if TYPE_CHECKING:
    from tauhaulity.tools.suppress import SuppressionStore

PICKLE_SUFFIXES: Final[frozenset[str]] = frozenset({".pkl", ".pickle", ".joblib", ".dill"})
SOURCE_SUFFIX: Final[str] = ".py"
PYC_SUFFIX: Final[str] = ".pyc"

PYC_HEADER_SIZE: Final[int] = 16
PYC_HASH_FLAG: Final[int] = 0b01
PYC_CHECK_SOURCE_FLAG: Final[int] = 0b10
PYC_KNOWN_FLAGS: Final[int] = PYC_HASH_FLAG | PYC_CHECK_SOURCE_FLAG

# Directory names that are never entered. __pycache__ is deliberately absent:
# CPython 3.7 and newer always place bytecode caches there, so skipping it would
# make every pyc check dead code. Only regular files with a known suffix are
# inspected inside it, which for a cache directory means the .pyc files.
# .tooling is a provisioning directory that holds installed interpreters and
# their site-packages: it is the same kind of environment as .venv and scanning
# it would spend the whole budget on third-party code that the project does not
# ship. A project specific exclusion stays available through the policy list.
SKIPPED_DIR_NAMES: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        ".tooling",
        "venv",
        "node_modules",
        "build",
        "dist",
        "target",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".eggs",
        # Runtime state of the tool itself: dossier reports, the credential
        # allowlist, the suppression store and the quarantine store. The stored
        # quarantine payload is deliberately inert material that must not be
        # re-reported as an unsafe artifact, and scanning the state directory
        # would make every scan flag the previous scan's output.
        ".tauhaulity",
    }
)

# Opcode family -> why a scanner refuses to trust a stream that uses it.
BLOCKED_PICKLE_OPCODES: Final[dict[str, str]] = {
    "GLOBAL": "imports a callable by module and name",
    "STACK_GLOBAL": "imports a callable whose names come from the stream",
    "REDUCE": "calls the previously resolved callable with stream supplied arguments",
    "INST": "imports a class by module and name and constructs it",
    "OBJ": "constructs an object and runs its class constructor",
    "NEWOBJ": "allocates an instance of an attacker chosen class",
    "NEWOBJ_EX": "allocates an instance with attacker supplied __new__ arguments",
    "BUILD": "invokes __setstate__ or mutates __dict__ on an attacker chosen object",
    "PERSID": "resolves a persistent id through the loader callback",
    "BINPERSID": "resolves a binary persistent id through the loader callback",
    "EXT1": "resolves an extension registry object",
    "EXT2": "resolves an extension registry object",
    "EXT4": "resolves an extension registry object",
}

_IMPORT_OPCODES: Final[frozenset[str]] = frozenset(
    {"GLOBAL", "STACK_GLOBAL", "INST", "PERSID", "BINPERSID", "EXT1", "EXT2", "EXT4"}
)
_CALL_OPCODES: Final[frozenset[str]] = frozenset({"REDUCE", "OBJ", "NEWOBJ", "NEWOBJ_EX"})
_MUTATE_OPCODES: Final[frozenset[str]] = frozenset({"BUILD"})
_QUOTED_OPCODES: Final[frozenset[str]] = frozenset({"GLOBAL", "INST", "STACK_GLOBAL"})

_MAX_OPCODE_OCCURRENCES: Final[int] = 8
_MAX_DETAIL_QUOTE: Final[int] = 48
_MAX_DETAIL_EXCEPTION: Final[int] = 120
_MAX_FINDINGS_PER_FILE: Final[int] = 64
_MAX_FINDINGS: Final[int] = 512

_DESERIALIZER_CALLS: Final[frozenset[str]] = frozenset(
    {
        "pickle.load",
        "pickle.loads",
        "_pickle.load",
        "_pickle.loads",
        "dill.load",
        "dill.loads",
        "joblib.load",
        "marshal.load",
        "marshal.loads",
    }
)
_SHELL_CALLS: Final[frozenset[str]] = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
    }
)
_IMPLICIT_SHELL_CALLS: Final[frozenset[str]] = frozenset(
    {"subprocess.getoutput", "subprocess.getstatusoutput"}
)
_EVAL_CALLS: Final[frozenset[str]] = frozenset({"eval", "exec", "builtins.eval", "builtins.exec"})
_COMPILE_CALLS: Final[frozenset[str]] = frozenset({"compile", "builtins.compile"})
_OS_SHELL_CALLS: Final[frozenset[str]] = frozenset({"os.system", "os.popen"})

# Install-time execution: pip runs setup.py and the build backend, so code there
# executes with the installing user's privileges. The 2026 PyPI record "123bla"
# overrode the install command for exactly that.
_SETUP_FILENAME: Final[str] = "setup.py"
_MANIFEST_FILENAMES: Final[frozenset[str]] = frozenset({"pyproject.toml", "setup.cfg"})
_INSTALL_COMMAND_TOKENS: Final[frozenset[str]] = frozenset(
    {"install", "develop", "pre_install", "build_ext"}
)
_INSTALL_TIME_CALL_ROOTS: Final[frozenset[str]] = frozenset(
    {"subprocess", "socket", "urllib", "http", "ftplib", "requests", "httpx", "telnetlib", "smtplib"}
)
_INSTALL_TIME_CALL_NAMES: Final[frozenset[str]] = frozenset(
    {"os.system", "os.popen", "os.execv", "os.execve", "os.spawnl", "os.spawnv", "os.spawnve"}
)
_TRUSTED_BUILD_BACKENDS: Final[frozenset[str]] = frozenset(
    {
        "setuptools.build_meta",
        "setuptools.build_meta:__legacy__",
        "flit_core.buildapi",
        "poetry.core.masonry.api",
        "hatchling.build",
        "pdm.backend",
        "pdm.pep517.api",
        "mesonpy",
        "scikit_build_core.build",
        "maturin",
        "uv_build",
        "enscons.api",
    }
)

# Credential harvesting: the real "2026-09-0requests" campaign enumerated every
# environment variable named SECRET/API/TOKEN/KEY and shipped them over a raw
# socket. Both halves must co-occur in one module before this is reported.
_ENV_GET_CALLS: Final[frozenset[str]] = frozenset({"os.getenv", "os.environ.get"})
_ENV_CONTAINER_CALLS: Final[frozenset[str]] = frozenset(
    {"os.environ.items", "os.environ.keys", "os.environ.values"}
)
_NETWORK_ROOTS: Final[frozenset[str]] = frozenset(
    {"socket", "urllib", "requests", "httpx", "http", "ftplib", "smtplib", "telnetlib"}
)
_SPAWN_CALLS: Final[frozenset[str]] = frozenset(
    {"os.system", "os.popen", "os.execv", "os.execve", "os.spawnl", "os.spawnv"}
)
_SOCKET_PRIMITIVES: Final[frozenset[str]] = frozenset(
    {"socket.socket", "socket.create_connection", "socket.socketpair"}
)
_LOOPBACK_HOSTS: Final[frozenset[str]] = frozenset(
    {"localhost", "127.0.0.1", "::1", "0.0.0.0", "ip6-localhost"}
)
_SHELL_LITERALS: Final[tuple[str, ...]] = (
    "/bin/sh",
    "/bin/bash",
    "cmd.exe",
    "powershell",
    "cmd /c",
    "sh -c",
    "python -c",
)
_SUBPROCESS_SHELL_CALLS: Final[frozenset[str]] = frozenset(
    {
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
    }
)

# Obfuscated payload: a decoder whose output reaches exec/eval/compile, or a large
# high-entropy literal handed to exec. The 2026 PyPI package "123bla" carried an
# encoded blob in setup.py for exactly this.
_DECODER_CALLS: Final[frozenset[str]] = frozenset(
    {
        "base64.b64decode",
        "base64.b85decode",
        "base64.b32decode",
        "base64.b16decode",
        "base64.a85decode",
        "base64.urlsafe_b64decode",
        "codecs.decode",
        "marshal.loads",
        "zlib.decompress",
        "binascii.unhexlify",
        "bytes.fromhex",
    }
)
_OBFUSCATION_ENTROPY: Final[float] = 4.5
_LARGE_LITERAL: Final[int] = 200
_MAX_DETECTOR_FINDINGS_PER_MODULE: Final[int] = 24

# Cheap pre-parse filter. Every detection below needs one of these spellings to
# exist in the file: the call name is either written literally or imported from
# a module whose name is written literally. A file without a single trigger can
# never produce a call finding, so the AST parser is only invoked on candidates.
_TRIGGER_TOKENS: Final[tuple[bytes, ...]] = (
    b"pickle",
    b"dill",
    b"joblib",
    b"marshal",
    b"yaml",
    b"torch",
    b"eval",
    b"exec",
    b"compile",
    b"system",
    b"popen",
    b"subprocess",
    b"extract",
    b"unpack_archive",
    b"verify",
    b"environ",
    b"getenv",
    b"socket",
    b"urllib",
    b"ftplib",
    b"base64",
    b"b64decode",
    b"rot13",
    b"zlib",
    b"codecs",
)

_SEVERITY_RANK: Final[Mapping[str, int]] = {"high": 0, "medium": 1, "low": 2}

#: Findings whose evidence is the file itself, so quarantining (moving the file
#: out of the load path) is a real neutralisation:
#:   pickle_unsafe / pickle_malformed: the .pkl payload is inert once moved;
#:   pyc_mismatch / pyc_invalid: a cache the interpreter would otherwise load;
#:   install_time_execution: the setup.py / setup.cfg / pyproject that runs code
#:     while pip installs the distribution.
#: Everything else stays in place: dangerous_api call sites, dependency
#: declarations and the env/socket/reverse-shell/obfuscation shapes are code or
#: manifest lines to review and fix, and deleting the file would either break the
#: project or hide the decision instead of preventing the load. pyc_orphan is a
#: removable cache but removing it is housekeeping, not neutralisation, so it is
#: reported without being suggested automatically.
_QUARANTINE_ELIGIBLE_KINDS: Final[frozenset[str]] = frozenset(
    {
        "pickle_unsafe",
        "pickle_malformed",
        "pyc_mismatch",
        "pyc_invalid",
        "install_time_execution",
    }
)


@dataclass(frozen=True, slots=True)
class ScanBudget:
    """Hard limits applied to one artifact scan.

    Attributes:
        max_files: Maximum number of files the walk may inspect.
        max_bytes: Maximum number of artifact bytes the scan may read.
        max_file_bytes: Files larger than this are skipped, not read.
        max_depth: Maximum directory depth below the project root.

    Raises:
        ValueError: When a limit is negative or not an integer.
    """

    max_files: int = 4000
    max_bytes: int = 8 * 1024 * 1024
    max_file_bytes: int = 256 * 1024
    max_depth: int = 8

    def __post_init__(self) -> None:
        for name in ("max_files", "max_bytes", "max_file_bytes", "max_depth"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"{name} must be an integer")
            if value < 0:
                raise ValueError(f"{name} must not be negative")


@dataclass(frozen=True, slots=True)
class ArtifactFinding:
    """One supply chain problem found inside a scanned project.

    Attributes:
        rel_path: Project relative forward slash path of the evidence.
        kind: Finding family (pickle_unsafe, pickle_malformed, dangerous_api,
            pyc_mismatch, pyc_orphan, pyc_invalid).
        severity: high, medium or low.
        detail: One line explanation naming the exact construct, never a payload.
        line_no: One based source line for AST findings, None otherwise.
        symbol: Enclosing function or class name from the AST, empty for findings
            that are not tied to a call site (pickle and pyc evidence).
        quarantine_eligible: True when the evidence IS the artifact file, so
            moving that file out of the load path neutralises it without editing
            source. False for code call sites and dependency declarations, which
            must be reviewed and fixed instead of deleted.
    """

    rel_path: str
    kind: str
    severity: str
    detail: str
    line_no: int | None = None
    symbol: str = ""
    quarantine_eligible: bool = False


@dataclass(frozen=True, slots=True)
class ArtifactReport:
    """Outcome of one bounded artifact scan.

    Attributes:
        findings: Findings ordered by severity, path and line.
        files_inspected: Regular files walked, including files whose suffix was
            not inspectable. This is the number the dossier reports.
        bytes_inspected: Bytes actually read from inspected file bodies.
        truncated: True when a budget, a depth cap, a per-file size cap or a
            detection cap stopped the scan before the whole tree was covered.
        detail: One line summary that always states the file and byte counts.
        suppressed: Findings dropped by the reviewed suppression store, never
            hidden: the detail line states the count and the store path.
    """

    findings: tuple[ArtifactFinding, ...]
    files_inspected: int
    bytes_inspected: int
    truncated: bool
    detail: str
    suppressed: int = 0


@dataclass(slots=True)
class _ScanState:
    """Mutable accumulator used while walking one project tree."""

    findings: list[ArtifactFinding] = field(default_factory=list)
    files_inspected: int = 0
    bytes_inspected: int = 0
    truncated: bool = False
    hard_stop: bool = False
    oversize_skipped: int = 0
    depth_pruned: int = 0
    caps_hit: int = 0
    root: Path | None = None
    dependency_note: str = ""


def _directory_readable(root: Path) -> bool:
    """Return True when root is a readable directory."""

    try:
        return root.is_dir()
    except OSError:
        return False


def scan_source_tree(
    root: Path,
    *,
    budget: ScanBudget = ScanBudget(),
    ignored: tuple[str, ...] = (),
    suppress: "SuppressionStore | None" = None,
) -> ArtifactReport:
    """Scan a project tree for supply chain artifacts without executing them.

    Parameters:
        root: Project directory to scan.
        budget: Hard file, byte, per-file and depth limits.
        ignored: Policy ignore patterns, matched against project relative forward
            slash paths exactly like tauhaulity.core.policy.Policy.is_ignored.
        suppress: Optional reviewed suppression store. Matching findings are
            dropped from the report, counted in ArtifactReport.suppressed and
            named in the detail line; nothing is ever hidden silently.

    Returns:
        An ArtifactReport. A missing or unreadable root is reported as an empty
        non-truncated report whose detail says so, so the pillar can distinguish
        "nothing to scan" from "scanner was blocked".
    """

    root_path = Path(root)
    if not _directory_readable(root_path):
        return ArtifactReport(
            findings=(),
            files_inspected=0,
            bytes_inspected=0,
            truncated=False,
            detail="project root is not a readable directory, nothing was scanned",
        )
    patterns = _normalize_patterns(ignored)
    state = _ScanState()
    state.root = root_path
    try:
        _walk(root_path, budget, patterns, state)
    except OSError as exc:
        # The walker handles per-entry errors itself; this is the last resort so
        # that a hostile tree degrades into a report instead of an exception.
        state.truncated = True
        state.hard_stop = True
        state.findings.append(
            ArtifactFinding(
                rel_path="",
                kind="scan_incomplete",
                severity="low",
                detail=f"walk aborted by {type(exc).__name__}: {_printable(str(exc), _MAX_DETAIL_EXCEPTION)}",
            )
        )
    _merge_dependency_findings(root_path, state)
    ordered = tuple(
        replace(
            finding,
            quarantine_eligible=finding.kind in _QUARANTINE_ELIGIBLE_KINDS,
        )
        for finding in sorted(state.findings, key=_finding_sort_key)
    )
    suppressed = 0
    store_path = ""
    if suppress is not None:
        store_path = str(getattr(suppress, "path", "") or "")
        try:
            from tauhaulity.tools.suppress import filter_findings
        except ImportError:
            # A partial checkout keeps the scanner usable without the review
            # layer; the fail-safe direction is to report every finding.
            filter_findings = None  # type: ignore[assignment]
        if filter_findings is not None:
            kept, suppressed = filter_findings(ordered, suppress)
            ordered = tuple(kept)
    return ArtifactReport(
        findings=ordered,
        files_inspected=state.files_inspected,
        bytes_inspected=state.bytes_inspected,
        truncated=state.truncated,
        detail=_render_detail(state, budget, ordered, suppressed, store_path),
        suppressed=suppressed,
    )


def _normalize_patterns(ignored: Iterable[str]) -> tuple[str, ...]:
    """Normalize ignore patterns to forward slash form without edge slashes."""

    patterns: list[str] = []
    for pattern in ignored:
        if not isinstance(pattern, str):
            continue
        stripped = pattern.replace(chr(92), "/").strip().strip("/")
        if stripped and stripped != ".":
            patterns.append(stripped)
    return tuple(dict.fromkeys(patterns))


def _is_ignored(rel_path: str, patterns: tuple[str, ...]) -> bool:
    """Return True when a project relative path matches one ignore pattern."""

    if not patterns:
        return False
    candidate = rel_path.replace(chr(92), "/")
    for pattern in patterns:
        if fnmatch.fnmatch(candidate, pattern):
            return True
        if candidate == pattern or candidate.startswith(pattern + "/"):
            return True
    return False


def _walk(root: Path, budget: ScanBudget, patterns: tuple[str, ...], state: _ScanState) -> None:
    """Walk the tree depth first, applying every budget before reading a file.

    os.scandir is used instead of listdir plus stat calls because a directory
    entry already caches the file type, and, where the platform provides it, the
    size. On a slow mount (a WSL drvfs path or a network share) that removes most
    of the per-file syscalls without changing the detection logic.
    """

    stack: list[tuple[Path, int]] = [(root, 0)]
    while stack:
        if state.hard_stop:
            return
        directory, depth = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
                for entry in entries:
                    if state.hard_stop:
                        return
                    try:
                        if entry.is_symlink():
                            continue
                        is_directory = entry.is_dir(follow_symlinks=False)
                        is_file = entry.is_file(follow_symlinks=False)
                    except OSError:
                        continue
                    name = entry.name
                    try:
                        rel = Path(entry.path).relative_to(root).as_posix()
                    except ValueError:
                        continue
                    if _is_ignored(rel, patterns):
                        continue
                    if is_directory:
                        if name in SKIPPED_DIR_NAMES:
                            continue
                        if depth + 1 > budget.max_depth:
                            state.truncated = True
                            state.depth_pruned += 1
                            continue
                        stack.append((Path(entry.path), depth + 1))
                        continue
                    if not is_file:
                        continue
                    if state.files_inspected >= budget.max_files:
                        state.truncated = True
                        state.hard_stop = True
                        return
                    state.files_inspected += 1
                    try:
                        _inspect_entry(entry, rel, budget, state)
                    except OSError:
                        continue
        except OSError:
            continue


def _inspect_entry(entry: os.DirEntry[str], rel: str, budget: ScanBudget, state: _ScanState) -> None:
    """Dispatch one regular file to the detector that matches its suffix."""

    path = Path(entry.path)
    suffix = path.suffix.lower()
    if suffix == PYC_SUFFIX:
        _inspect_pyc(path, rel, budget, state)
        return
    manifest = path.name in _MANIFEST_FILENAMES
    if not manifest and suffix not in PICKLE_SUFFIXES and suffix != SOURCE_SUFFIX:
        return
    try:
        size = entry.stat(follow_symlinks=False).st_size
    except OSError:
        return
    data = _read_candidate(path, size, budget, state)
    if data is None:
        return
    if manifest:
        _inspect_manifest(data, path.name, rel, state)
    elif suffix == SOURCE_SUFFIX:
        _inspect_source(data, rel, state)
    else:
        _inspect_pickle(data, rel, state)


def _read_candidate(path: Path, size: int, budget: ScanBudget, state: _ScanState) -> bytes | None:
    """Read one candidate file inside the per-file and total byte budgets."""

    if size > budget.max_file_bytes:
        state.truncated = True
        state.oversize_skipped += 1
        return None
    if state.bytes_inspected + size > budget.max_bytes:
        state.truncated = True
        state.hard_stop = True
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    state.bytes_inspected += len(data)
    return data


def _inspect_pickle(data: bytes, rel: str, state: _ScanState) -> None:
    """Stream a pickle with genops and report blocked opcodes or a bad stream."""

    blocked: list[tuple[str, int, object]] = []
    total_blocked = 0
    malformed: str | None = None
    try:
        for opcode, argument, position in pickletools.genops(data):
            name = opcode.name
            if name not in BLOCKED_PICKLE_OPCODES:
                continue
            total_blocked += 1
            if len(blocked) < _MAX_OPCODE_OCCURRENCES:
                blocked.append((name, int(position), argument))
    except Exception as exc:  # genops raises several types on hostile input
        malformed = f"{type(exc).__name__}: {_printable(str(exc), _MAX_DETAIL_EXCEPTION)}"
    if blocked:
        state.findings.append(
            ArtifactFinding(
                rel_path=rel,
                kind="pickle_unsafe",
                severity="high",
                detail=_unsafe_pickle_detail(blocked, total_blocked),
            )
        )
    if malformed is not None:
        state.findings.append(
            ArtifactFinding(
                rel_path=rel,
                kind="pickle_malformed",
                severity="medium",
                detail=f"genops rejected the stream ({malformed})",
            )
        )


def _unsafe_pickle_detail(blocked: list[tuple[str, int, object]], total_blocked: int) -> str:
    """Build the evidence line for blocked pickle opcodes."""

    occurrences: list[str] = []
    names: list[str] = []
    for name, position, argument in blocked:
        names.append(name)
        label = name
        if name in _QUOTED_OPCODES and isinstance(argument, str) and argument.strip():
            label += f"('{_printable(argument, _MAX_DETAIL_QUOTE)}')"
        occurrences.append(f"{label} at offset {position}")
    if total_blocked > len(blocked):
        occurrences.append(f"+{total_blocked - len(blocked)} more blocked opcode(s)")
    reasons: list[str] = []
    if any(name in _IMPORT_OPCODES for name in names):
        reasons.append("can import a callable from any module")
    if any(name in _CALL_OPCODES for name in names):
        reasons.append("can call the resolved callable")
    if any(name in _MUTATE_OPCODES for name in names):
        reasons.append("can mutate an instance through __setstate__")
    if not reasons:
        reasons.append("reaches outside the stream")
    return "unsafe opcode(s): " + ", ".join(occurrences) + "; " + " and ".join(reasons)


def _dotted(node: ast.AST) -> str:
    """Return the dotted spelling of a Name or Attribute chain, else an empty string."""

    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else ""
    return ""


def _resolve(name: str, aliases: Mapping[str, str]) -> str:
    """Resolve a dotted call name through the module level import aliases."""

    if not name:
        return ""
    if name in aliases:
        return aliases[name]
    root, dot, rest = name.partition(".")
    if root in aliases:
        base = aliases[root]
        return f"{base}.{rest}" if rest else base
    return name


def _first_argument_is_literal(call: ast.Call) -> bool:
    """True when the first positional argument is a string or bytes literal."""

    if not call.args:
        return False
    first = call.args[0]
    return isinstance(first, ast.Constant) and isinstance(first.value, (str, bytes))


def _keyword_flag(call: ast.Call, keyword: str, expected: bool) -> bool:
    """True when the call passes keyword=<expected boolean literal>."""

    for item in call.keywords:
        if item.arg != keyword:
            continue
        value = item.value
        return isinstance(value, ast.Constant) and value.value is expected
    return False


def _yaml_uses_safe_loader(call: ast.Call) -> bool:
    """True when yaml.load is given a safe loader by keyword or position."""

    loader: ast.AST | None = None
    for item in call.keywords:
        if item.arg == "Loader":
            loader = item.value
            break
    if loader is None and len(call.args) >= 2:
        loader = call.args[1]
    if loader is None:
        return False
    name = _dotted(loader)
    if not name:
        return False
    return name.rsplit(".", 1)[-1] in {"SafeLoader", "CSafeLoader"}


def _safe_archive_filter(call: ast.Call) -> bool:
    """True when extractall is bounded by an explicit safe tar filter.

    The PEP 706 filter="data" and filter="tar" modes reject absolute paths,
    parent traversal and special files, which is exactly the control a safe
    review asks for. A missing filter, filter=None or a non-literal filter
    cannot be proven safe from the call site, so it is reported.
    """

    for item in call.keywords:
        if item.arg != "filter":
            continue
        value = item.value
        return isinstance(value, ast.Constant) and value.value in ("data", "tar")
    return False


def _classify_call(call: ast.Call, aliases: Mapping[str, str]) -> tuple[str, str] | None:
    """Classify one call site as a high or medium dangerous API finding."""

    name = _resolve(_dotted(call.func), aliases)
    # Archive extraction is matched on the attribute only, because the common
    # shape is chained: tarfile.open("a.tar").extractall("."). The receiver is a
    # Call, so a dotted name would be empty and the rule would never fire.
    attribute = call.func.attr if isinstance(call.func, ast.Attribute) else ""
    if attribute == "extractall" and not _safe_archive_filter(call):
        return (
            "medium",
            "extractall() unpacks an archive without a safe filter (path traversal can write outside the target)",
        )
    if attribute == "unpack_archive":
        return (
            "medium",
            "unpack_archive() unpacks an archive without path traversal validation",
        )
    if attribute == "extract" and not call.args:
        return "medium", "extract() without an explicit member unpacks archive content blindly"
    if not name:
        return None
    if name in _DESERIALIZER_CALLS:
        return "high", f"{name}() deserializes a byte stream and can execute arbitrary code"
    if name == "yaml.load" and not _yaml_uses_safe_loader(call):
        return "high", "yaml.load() without SafeLoader can instantiate arbitrary Python objects"
    if name == "torch.load" and not _keyword_flag(call, "weights_only", True):
        return "high", "torch.load() without weights_only=True can execute arbitrary code"
    if name in _EVAL_CALLS and not _first_argument_is_literal(call):
        return "high", f"{name}() evaluates a non-literal expression"
    if name in _COMPILE_CALLS and not _first_argument_is_literal(call):
        return "high", "compile() compiles a non-literal string at runtime"
    if name in _OS_SHELL_CALLS:
        return "high", f"{name}() runs a command through the system shell"
    if name in _SHELL_CALLS and _keyword_flag(call, "shell", True):
        return "high", f"{name}(shell=True) runs a command through the system shell"
    if name in _IMPLICIT_SHELL_CALLS:
        return "high", f"{name}() always runs a command through the system shell"
    if _keyword_flag(call, "verify", False):
        return "medium", "verify=False disables TLS certificate validation"
    return None


def _has_trigger_token(data: bytes) -> bool:
    """True when the source contains a spelling that a detection can resolve to."""

    return any(token in data for token in _TRIGGER_TOKENS)


def _iter_ast(tree: ast.AST) -> Iterator[tuple[ast.AST, tuple[str, ...], bool]]:
    """Yield every node with its enclosing name tuple and loop ancestry.

    The traversal is iterative because a Python level recursive generator spent
    more time in call frames than in the detectors. The name tuple is shared by
    every node in one scope and extended only when a function or class is
    entered, so the cost per node is a yield and one isinstance. A module level
    node yields an empty tuple; a method yields (Class, method); a closure yields
    (outer, inner).
    """

    stack: list[tuple[ast.AST, tuple[str, ...], bool]] = [(tree, (), False)]
    while stack:
        node, names, in_loop = stack.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            yield node, names, in_loop
            child_names = names + (node.name,)
            for child in ast.iter_child_nodes(node):
                stack.append((child, child_names, False))
            continue
        loop = in_loop or isinstance(
            node,
            (ast.For, ast.AsyncFor, ast.While, ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp),
        )
        yield node, names, loop
        for child in ast.iter_child_nodes(node):
            stack.append((child, names, loop))


def _add_finding(state: _ScanState, finding: ArtifactFinding, per_file: list[int]) -> None:
    """Append a finding while honouring the per-file and total detection caps."""

    if per_file[0] >= _MAX_FINDINGS_PER_FILE or len(state.findings) >= _MAX_FINDINGS:
        state.truncated = True
        state.caps_hit += 1
        return
    per_file[0] += 1
    state.findings.append(finding)


def _shannon_entropy(text: str) -> float:
    """Return the Shannon entropy of a string, in bits per character."""

    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    length = float(len(text))
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


@dataclass(slots=True)
class _SourceIndex:
    """One pass over the AST, retaining only what the detectors need.

    Collecting calls, loop scoped calls, assignments, os.environ iterations and
    class definitions in a single traversal keeps the added rules close to the
    cost of the previous single generic walk: a 2000-line module is visited once,
    not once per rule.
    """

    calls: list[tuple[ast.Call, str]] = field(default_factory=list)
    loop_calls: list[tuple[ast.Call, str]] = field(default_factory=list)
    assignments: dict[tuple[str, str], list[ast.AST]] = field(default_factory=dict)
    env_iterations: list[tuple[int, str]] = field(default_factory=list)
    class_defs: list[tuple[ast.ClassDef, str]] = field(default_factory=list)


def _collect_import_aliases(node: ast.AST, aliases: dict[str, str]) -> None:
    """Record the aliases introduced by one Import or ImportFrom statement."""

    if isinstance(node, ast.Import):
        for alias in node.names:
            if alias.asname:
                aliases[alias.asname] = alias.name
            else:
                root = alias.name.split(".", 1)[0]
                aliases[root] = root
    elif isinstance(node, ast.ImportFrom):
        if node.module is None or node.level:
            return
        for alias in node.names:
            if alias.name == "*":
                continue
            aliases[alias.asname or alias.name] = node.module + "." + alias.name


def _build_index(tree: ast.AST) -> tuple[_SourceIndex, dict[str, str]]:
    """Build the detector index and the import alias map in one traversal."""

    index = _SourceIndex()
    aliases: dict[str, str] = {}
    for node, names, in_loop in _iter_ast(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            _collect_import_aliases(node, aliases)
        elif isinstance(node, ast.Call):
            symbol = ".".join(names)
            index.calls.append((node, symbol))
            if in_loop:
                index.loop_calls.append((node, symbol))
        elif isinstance(node, ast.Assign):
            symbol = ".".join(names)
            for target in node.targets:
                if isinstance(target, ast.Name):
                    index.assignments.setdefault((symbol, target.id), []).append(node.value)
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            index.assignments.setdefault((".".join(names), node.target.id), []).append(node.value)
        elif isinstance(node, (ast.For, ast.AsyncFor)) and _dotted(node.iter).endswith("os.environ"):
            index.env_iterations.append((int(node.lineno), ".".join(names)))
        elif isinstance(node, ast.ClassDef):
            index.class_defs.append((node, ".".join(names)))
    return index, aliases


def _find_decoder(node: ast.AST, aliases: Mapping[str, str]) -> tuple[str, int] | None:
    """Return the first decoder call inside a subtree, or None."""

    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        name = _resolve(_dotted(child.func), aliases)
        if name in _DECODER_CALLS:
            return name, int(child.lineno)
    return None


def _is_env_derived(node: ast.AST, aliases: Mapping[str, str]) -> bool:
    """True when a value comes from os.environ or os.getenv anywhere in its subtree."""

    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            name = _resolve(_dotted(child.func), aliases)
            if name in _ENV_GET_CALLS or name in _ENV_CONTAINER_CALLS:
                return True
        elif isinstance(child, ast.Subscript):
            base = _dotted(child.value)
            if base == "os.environ" or base.endswith(".environ"):
                return True
    return False


def _connect_host(
    call: ast.Call,
    symbol: str,
    assignments: Mapping[tuple[str, str], list[ast.AST]],
    aliases: Mapping[str, str],
) -> tuple[str, str]:
    """Classify a connect target as loopback, literal, environment or unknown."""

    if not call.args:
        return "", "unknown"
    argument = call.args[0]
    if isinstance(argument, (ast.Tuple, ast.List)) and argument.elts:
        argument = argument.elts[0]
    if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
        host = argument.value.strip()
        if not host or host in _LOOPBACK_HOSTS:
            return "", "loopback"
        return host, "literal"
    if isinstance(argument, ast.Name):
        values = assignments.get((symbol, argument.id), [])
        for value in values:
            if _is_env_derived(value, aliases):
                return "<os.environ>", "environment"
        for value in values:
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                host = value.value.strip()
                if not host or host in _LOOPBACK_HOSTS:
                    return "", "loopback"
                return host, "literal"
        return "", "unknown"
    if _is_env_derived(argument, aliases):
        return "<os.environ>", "environment"
    return "", "unknown"


def _env_harvesting_findings(
    rel: str,
    index: _SourceIndex,
    aliases: Mapping[str, str],
) -> list[ArtifactFinding]:
    """Report a module that both enumerates the environment and reaches the network.

    The boundary is deliberate: a named lookup such as os.environ.get("TOKEN") is
    ordinary configuration and is not harvesting. Only enumeration (iteration,
    items/keys/values or a lookup inside a loop) counts, and it only counts when
    the same module also opens a network channel or spawns a process.
    """

    environment: list[tuple[int, str, str]] = [
        (line_no, "iterates over os.environ", symbol)
        for line_no, symbol in index.env_iterations
    ]
    for node, symbol in index.calls:
        name = _resolve(_dotted(node.func), aliases)
        if name in _ENV_CONTAINER_CALLS:
            environment.append((int(node.lineno), f"calls {name}()", symbol))
        elif name == "dict" and node.args and _dotted(node.args[0]) == "os.environ":
            environment.append((int(node.lineno), "copies os.environ into a dict", symbol))
    for node, symbol in index.loop_calls:
        name = _resolve(_dotted(node.func), aliases)
        if name in _ENV_GET_CALLS:
            environment.append((int(node.lineno), f"calls {name}() inside a loop", symbol))
    if not environment:
        return []
    network: list[tuple[int, str, str]] = []
    for node, symbol in index.calls:
        name = _resolve(_dotted(node.func), aliases)
        if name.partition(".")[0] in _NETWORK_ROOTS or name in _SPAWN_CALLS:
            network.append((int(node.lineno), name, symbol))
    if not network:
        return []
    # Genuine co-occurrence means the same code path: both halves inside one
    # function, or environment enumeration at module level of a script whose
    # network call is elsewhere. An unrelated helper that copies os.environ next
    # to an unrelated socket client is not harvesting.
    match: tuple[tuple[int, str, str], tuple[int, str, str]] | None = None
    for entry in environment:
        for candidate in network:
            if entry[2] and entry[2] == candidate[2]:
                match = (entry, candidate)
                break
            if not entry[2]:
                match = (entry, candidate)
                break
        if match is not None:
            break
    if match is None:
        return []
    (environment_line, environment_evidence, symbol), (network_line, network_name, _) = match
    detail = (
        f"module {environment_evidence} (line {environment_line}) and reaches the network "
        f"via {network_name}() (line {network_line}), the environment credential harvesting shape"
    )
    return [
        ArtifactFinding(
            rel_path=rel,
            kind="env_secret_harvesting",
            severity="high",
            detail=detail,
            line_no=environment_line,
            symbol=symbol,
        )
    ]


def _socket_findings(
    rel: str,
    index: _SourceIndex,
    aliases: Mapping[str, str],
) -> list[ArtifactFinding]:
    """Report raw socket egress and the reverse-shell shape.

    A loopback literal keeps a reviewed internal-service client quiet: only a
    non-loopback literal or a host taken from the environment counts as egress.
    The reverse-shell rule needs a socket channel and a shell spawn in the same
    module, so a lone subprocess(shell=True) stays a plain dangerous_api finding.
    """

    findings: list[ArtifactFinding] = []
    socket_present = any(
        _resolve(_dotted(node.func), aliases) in _SOCKET_PRIMITIVES for node, _ in index.calls
    )
    if not socket_present:
        return findings
    assignments = index.assignments
    socket_variables: set[tuple[str, str]] = set()
    for (symbol, variable), values in assignments.items():
        for value in values:
            if isinstance(value, ast.Call) and _resolve(_dotted(value.func), aliases) in _SOCKET_PRIMITIVES:
                socket_variables.add((symbol, variable))
                break
    for node, symbol in index.calls:
        name = _resolve(_dotted(node.func), aliases)
        if name == "socket.socket":
            continue
        receiver: str | None = None
        if name == "socket.create_connection":
            receiver = "socket"
        elif name.endswith(".connect"):
            function = node.func
            if isinstance(function, ast.Attribute) and isinstance(function.value, ast.Name):
                if (symbol, function.value.id) in socket_variables:
                    receiver = function.value.id
            if receiver is None and name.startswith("socket."):
                receiver = "socket"
        if receiver is None:
            continue
        host, kind = _connect_host(node, symbol, assignments, aliases)
        if kind in {"unknown", "loopback"}:
            continue
        if kind == "environment":
            detail = (
                f"connect() at line {node.lineno} takes its host from os.environ, so the "
                "exfiltration destination is supplied at runtime"
            )
        else:
            detail = (
                f"socket connects to '{host}' at line {node.lineno}, the exfiltration or "
                "reverse-shell primitive"
            )
        findings.append(
            ArtifactFinding(
                rel_path=rel,
                kind="raw_socket_egress",
                severity="high",
                detail=detail,
                line_no=int(node.lineno),
                symbol=symbol,
            )
        )
        break
    shell_hits: list[tuple[int, str, str]] = []
    for node, symbol in index.calls:
        name = _resolve(_dotted(node.func), aliases)
        if name in _SUBPROCESS_SHELL_CALLS and _keyword_flag(node, "shell", True):
            shell_hits.append((int(node.lineno), f"{name}(shell=True)", symbol))
            continue
        arguments = list(node.args) + [keyword.value for keyword in node.keywords]
        matched = ""
        for argument in arguments:
            for literal in ast.walk(argument):
                if not isinstance(literal, ast.Constant) or not isinstance(literal.value, str):
                    continue
                lowered = literal.value.lower()
                matched = next((token for token in _SHELL_LITERALS if token in lowered), "")
                if matched:
                    break
            if matched:
                break
        if matched:
            shell_hits.append((int(node.lineno), f"literal '{matched}'", symbol))
    if shell_hits:
        line_no, evidence, symbol = shell_hits[0]
        findings.append(
            ArtifactFinding(
                rel_path=rel,
                kind="reverse_shell_shape",
                severity="high",
                detail=(
                    f"a socket channel and a shell spawn ({evidence}) at line {line_no} in the "
                    "same module match a reverse shell"
                ),
                line_no=line_no,
                symbol=symbol,
            )
        )
    return findings


def _obfuscation_hits(
    index: _SourceIndex,
    aliases: Mapping[str, str],
) -> list[tuple[int, str, str]]:
    """Return (line, evidence, symbol) for decoded or high-entropy payload execution."""

    decoded: list[tuple[str, str, str, int]] = []
    for (symbol, variable), values in index.assignments.items():
        for value in values:
            decoder = _find_decoder(value, aliases)
            if decoder is not None:
                decoded.append((symbol, variable, decoder[0], decoder[1]))
                break
    hits: list[tuple[int, str, str]] = []
    for node, symbol in index.calls:
        name = _resolve(_dotted(node.func), aliases)
        if name not in _EVAL_CALLS and name not in _COMPILE_CALLS:
            continue
        if not node.args:
            continue
        first = node.args[0]
        decoder = _find_decoder(first, aliases)
        if decoder is not None:
            hits.append(
                (
                    int(node.lineno),
                    f"{name}() executes the result of {decoder[0]}() (line {decoder[1]})",
                    symbol,
                )
            )
            continue
        if isinstance(first, ast.Name):
            for dec_symbol, variable, decoder_name, decoder_line in decoded:
                if dec_symbol == symbol and variable == first.id:
                    hits.append(
                        (
                            int(node.lineno),
                            f"{name}() executes {variable}, decoded from {decoder_name}() at line {decoder_line}",
                            symbol,
                        )
                    )
                    break
        literal = first
        if (
            isinstance(literal, ast.Constant)
            and isinstance(literal.value, str)
            and len(literal.value) >= _LARGE_LITERAL
            and _shannon_entropy(literal.value) >= _OBFUSCATION_ENTROPY
        ):
            hits.append(
                (
                    int(node.lineno),
                    f"{name}() executes a {len(literal.value)} character high-entropy literal",
                    symbol,
                )
            )
    seen: set[tuple[int, str]] = set()
    unique: list[tuple[int, str, str]] = []
    for hit in hits:
        key = (hit[0], hit[1])
        if key in seen:
            continue
        seen.add(key)
        unique.append(hit)
    return unique[:_MAX_DETECTOR_FINDINGS_PER_MODULE]


def _install_time_findings(
    rel: str,
    index: _SourceIndex,
    aliases: Mapping[str, str],
    obfuscation: list[tuple[int, str, str]],
) -> list[ArtifactFinding]:
    """Report code that runs while pip installs the distribution.

    The 2026 PyPI record "123bla" shipped a setup.py that replaced the install
    command; the same primitive is a cmdclass override, an install-command
    subclass, a network or process call in setup.py, or an encoded blob executed
    there.
    """

    findings: list[ArtifactFinding] = []

    def add(line_no: int, detail: str, symbol: str = "") -> None:
        if len(findings) >= _MAX_DETECTOR_FINDINGS_PER_MODULE:
            return
        findings.append(
            ArtifactFinding(
                rel_path=rel,
                kind="install_time_execution",
                severity="high",
                detail=detail,
                line_no=line_no,
                symbol=symbol,
            )
        )

    for node, symbol in index.calls:
        resolved = _resolve(_dotted(node.func), aliases)
        last = resolved.rsplit(".", 1)[-1]
        root = resolved.partition(".")[0]
        is_setup_call = resolved == "setup" or (last == "setup" and root in {"setuptools", "distutils"})
        if not is_setup_call:
            continue
        for keyword in node.keywords:
            if keyword.arg == "cmdclass":
                add(
                    int(node.lineno),
                    "setup() overrides cmdclass, so a custom command runs arbitrary code during pip install",
                    symbol,
                )
            elif keyword.arg == "scripts":
                entries = (
                    keyword.value.elts
                    if isinstance(keyword.value, (ast.List, ast.Tuple))
                    else [keyword.value]
                )
                for entry in entries:
                    if (
                        isinstance(entry, ast.Constant)
                        and isinstance(entry.value, str)
                        and entry.value.lower().endswith(".py")
                    ):
                        add(
                            int(node.lineno),
                            f"setup(scripts=...) installs the Python module {entry.value} as an executable script",
                            symbol,
                        )
                        break
    for node, _symbol in index.class_defs:
        for base in node.bases:
            resolved = _resolve(_dotted(base), aliases)
            last = resolved.rsplit(".", 1)[-1]
            if ".command." in resolved and last in _INSTALL_COMMAND_TOKENS:
                add(
                    int(node.lineno),
                    f"class {node.name} overrides the {last} command, which pip executes at install time",
                )
                break
    for node, symbol in index.calls:
        resolved = _resolve(_dotted(node.func), aliases)
        if resolved in _INSTALL_TIME_CALL_NAMES or resolved.partition(".")[0] in _INSTALL_TIME_CALL_ROOTS:
            add(
                int(node.lineno),
                f"setup.py calls {resolved}() while pip runs the install step",
                symbol,
            )
    for line_no, detail, symbol in obfuscation:
        add(line_no, f"{detail} inside setup.py, so the payload runs at install time", symbol)
    seen: set[tuple[int, str]] = set()
    unique: list[ArtifactFinding] = []
    for finding in findings:
        key = (finding.line_no or 0, finding.detail)
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique


def _text_line(text: str, needle: str, default: int = 1) -> int:
    """Return the one based line of the first occurrence of needle."""

    if not needle:
        return default
    for number, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return number
    return default


def _inspect_manifest(data: bytes, filename: str, rel: str, state: _ScanState) -> None:
    """Inspect pyproject.toml and setup.cfg for install-time code execution."""

    text = data.decode("utf-8", errors="replace")
    per_file = [0]
    if filename == "pyproject.toml":
        try:
            payload = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError):
            return
        build = payload.get("build-system")
        backend = build.get("build-backend") if isinstance(build, dict) else None
        if not isinstance(backend, str) or not backend or backend in _TRUSTED_BUILD_BACKENDS:
            return
        module = backend.split(":", 1)[0]
        first = module.split(".", 1)[0]
        in_tree = False
        root = state.root
        if root is not None:
            candidates = (
                root / (first + SOURCE_SUFFIX),
                root / first / "__init__.py",
                root / (module.replace(".", "/") + SOURCE_SUFFIX),
            )
            for candidate in candidates:
                try:
                    if candidate.is_file():
                        in_tree = True
                        break
                except OSError:
                    continue
        if in_tree:
            _add_finding(
                state,
                ArtifactFinding(
                    rel_path=rel,
                    kind="install_time_execution",
                    severity="high",
                    detail=(
                        f"pyproject.toml ships its own build backend {backend}, so that module "
                        "runs during pip install"
                    ),
                    line_no=_text_line(text, backend),
                ),
                per_file,
            )
        return
    section = ""
    for number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            continue
        if section != "options" or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key == "cmdclass" and value:
            _add_finding(
                state,
                ArtifactFinding(
                    rel_path=rel,
                    kind="install_time_execution",
                    severity="high",
                    detail=(
                        f"setup.cfg sets cmdclass = {value}, a command class that pip runs at install time"
                    ),
                    line_no=number,
                ),
                per_file,
            )
        elif key == "scripts" and ".py" in value.lower():
            _add_finding(
                state,
                ArtifactFinding(
                    rel_path=rel,
                    kind="install_time_execution",
                    severity="high",
                    detail="setup.cfg installs a Python module as an executable script (scripts = ...)",
                    line_no=number,
                ),
                per_file,
            )


def _merge_dependency_findings(root: Path, state: _ScanState) -> None:
    """Fold the declared-dependency audit into the artifact findings.

    The dependency audit runs lazily and its failure degrades to no dependency
    findings: a broken manifest must never stop the file level scan. Findings are
    converted to artifact findings so the suppression store, the severity ladder
    and the reviewable candidate list all work without a second code path.
    """

    try:
        from tauhaulity.tools import dep_audit
    except ImportError:
        return
    try:
        report = dep_audit.audit_dependencies(root)
    except Exception:  # a broken manifest set must never crash the scanner
        return
    if report.findings:
        state.dependency_note = (
            f"declared dependency audit produced {len(report.findings)} finding(s) "
            f"across {report.declared} declaration(s)"
        )
    for finding in report.findings:
        if len(state.findings) >= _MAX_FINDINGS:
            state.truncated = True
            state.caps_hit += 1
            return
        line_no = finding.line_no if finding.line_no > 0 else None
        state.findings.append(
            ArtifactFinding(
                rel_path=finding.rel_path,
                kind="dep_" + finding.kind,
                severity=finding.severity,
                detail=finding.detail,
                line_no=line_no,
                symbol=finding.name,
            )
        )


def _emit_call_findings(
    rel: str,
    calls: Iterable[tuple[ast.Call, str]],
    aliases: Mapping[str, str],
    state: _ScanState,
    per_file: list[int],
) -> None:
    """Classify and record the generic dangerous_api call rules."""

    for node, symbol in calls:
        classified = _classify_call(node, aliases)
        if classified is None:
            continue
        severity, detail = classified
        _add_finding(
            state,
            ArtifactFinding(
                rel_path=rel,
                kind="dangerous_api",
                severity=severity,
                detail=detail,
                line_no=int(node.lineno),
                symbol=symbol,
            ),
            per_file,
        )


def _inspect_source(data: bytes, rel: str, state: _ScanState) -> None:
    """Parse Python source and report every dangerous shape the rules cover."""

    is_setup = rel.rsplit("/", 1)[-1] == _SETUP_FILENAME
    if not is_setup and not _has_trigger_token(data):
        return
    try:
        tree = ast.parse(data, filename=rel)
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        # Unparseable source has no call graph to review; py_compile reports it
        # and the artifact scanner must not invent a finding for it.
        return
    per_file = [0]
    want_env = b"environ" in data or b"getenv" in data
    want_socket = b"socket" in data
    want_obfuscation = any(
        token in data
        for token in (
            b"base64",
            b"b64decode",
            b"rot13",
            b"zlib",
            b"marshal",
            b"codecs",
            b"binascii",
            b"exec",
            b"eval",
            b"compile",
        )
    )
    if not (want_env or want_socket or want_obfuscation or is_setup):
        # Only the generic call rules can fire. Classify calls while traversing
        # instead of materialising the full index, which keeps the common case as
        # cheap as the original single pass.
        calls: list[tuple[ast.Call, str]] = []
        aliases: dict[str, str] = {}
        for node, names, _ in _iter_ast(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                _collect_import_aliases(node, aliases)
            elif isinstance(node, ast.Call):
                calls.append((node, ".".join(names)))
        _emit_call_findings(rel, calls, aliases, state, per_file)
        return
    index, aliases = _build_index(tree)
    _emit_call_findings(rel, index.calls, aliases, state, per_file)
    if want_env:
        for finding in _env_harvesting_findings(rel, index, aliases):
            _add_finding(state, finding, per_file)
    if want_socket:
        for finding in _socket_findings(rel, index, aliases):
            _add_finding(state, finding, per_file)
    obfuscation: list[tuple[int, str, str]] = []
    if want_obfuscation:
        obfuscation = _obfuscation_hits(index, aliases)
        if not is_setup:
            for line_no, detail, symbol in obfuscation:
                _add_finding(
                    state,
                    ArtifactFinding(
                        rel_path=rel,
                        kind="obfuscated_payload",
                        severity="medium",
                        detail=detail,
                        line_no=line_no,
                        symbol=symbol,
                    ),
                    per_file,
                )
    if is_setup:
        for finding in _install_time_findings(rel, index, aliases, obfuscation):
            _add_finding(state, finding, per_file)


def _pyc_cache_tag(path: Path) -> str:
    """Return the cpython-3XX tag carried by a cache file name, or an empty string."""

    name = path.name
    if not name.endswith(PYC_SUFFIX):
        return ""
    stem = name[: -len(PYC_SUFFIX)]
    index = stem.rfind(".cpython-")
    if index <= 0:
        return ""
    return stem[index + 1 :]


def _pyc_source_path(path: Path) -> Path:
    """Resolve the source file a compiled cache claims to be built from.

    PEP 3147 caches live in __pycache__ and carry a ".cpython-3XX" (optionally
    preceded by ".opt-N") tag, so the source is one directory up with the tag
    stripped. A legacy cache next to its source maps by suffix substitution.
    """

    if path.parent.name != "__pycache__":
        return path.with_suffix(SOURCE_SUFFIX)
    stem = path.name[:-len(PYC_SUFFIX)] if path.name.endswith(PYC_SUFFIX) else path.stem
    tag = stem.rfind(".cpython-")
    if tag > 0:
        stem = stem[:tag]
    opt = stem.rfind(".opt-")
    if opt > 0:
        stem = stem[:opt]
    return path.parent.parent / (stem + SOURCE_SUFFIX)


def _inspect_pyc(path: Path, rel: str, budget: ScanBudget, state: _ScanState) -> None:
    """Verify one compiled cache against its PEP 552 header and its source."""

    source_path = _pyc_source_path(path)
    try:
        with path.open("rb") as handle:
            header = handle.read(PYC_HEADER_SIZE)
    except OSError:
        return
    state.bytes_inspected += len(header)
    if len(header) < PYC_HEADER_SIZE:
        state.findings.append(
            ArtifactFinding(
                rel_path=rel,
                kind="pyc_invalid",
                severity="medium",
                detail=f"header is {len(header)} byte(s) but a PEP 552 header needs {PYC_HEADER_SIZE}",
            )
        )
        return
    magic = header[:4]
    expected_magic = importlib.util.MAGIC_NUMBER
    cache_tag = _pyc_cache_tag(path)
    if (
        cache_tag
        and cache_tag != sys.implementation.cache_tag
        and magic != expected_magic
        and magic != b"\x00\x00\x00\x00"
    ):
        # The cache is tagged for another interpreter version and carries that
        # interpreter's magic, so this interpreter would never load it (it writes
        # its own tagged cache): a foreign version is coexistence, not tampering.
        # A cache tagged for this interpreter, a legacy sibling cache and an
        # all-zero magic (valid for no interpreter) are still reported.
        return
    if magic != expected_magic:
        state.findings.append(
            ArtifactFinding(
                rel_path=rel,
                kind="pyc_invalid",
                severity="medium",
                detail=(
                    f"magic {magic.hex()} does not match this interpreter {expected_magic.hex()}, "
                    "the cache cannot be trusted against the source"
                ),
            )
        )
        return
    flags = struct.unpack("<I", header[4:8])[0]
    unknown = flags & ~PYC_KNOWN_FLAGS
    if unknown:
        state.findings.append(
            ArtifactFinding(
                rel_path=rel,
                kind="pyc_invalid",
                severity="medium",
                detail=f"unknown PEP 552 flag bits set: {unknown:#x}",
            )
        )
        return
    try:
        source_stat = source_path.stat()
    except OSError:
        source_stat = None
    if source_stat is None:
        state.findings.append(
            ArtifactFinding(
                rel_path=rel,
                kind="pyc_orphan",
                severity="medium",
                detail=f"no source at {source_path.name} to validate the cached bytecode against",
            )
        )
        return
    if flags & PYC_HASH_FLAG:
        if not flags & PYC_CHECK_SOURCE_FLAG:
            # Unchecked hash caches carry no verifiable source binding; the
            # interpreter accepts them without looking at the source, so there is
            # no mismatch to report here.
            return
        source_size = source_stat.st_size
        if source_size > budget.max_file_bytes:
            state.truncated = True
            return
        if state.bytes_inspected + source_size > budget.max_bytes:
            state.truncated = True
            state.hard_stop = True
            return
        try:
            source_bytes = source_path.read_bytes()
        except OSError:
            return
        state.bytes_inspected += len(source_bytes)
        expected_hash = importlib.util.source_hash(source_bytes)
        if header[8:16] != expected_hash:
            state.findings.append(
                ArtifactFinding(
                    rel_path=rel,
                    kind="pyc_mismatch",
                    severity="high",
                    detail="stored blake2b source hash does not match the source file",
                )
            )
        return
    recorded_mtime, recorded_size = struct.unpack("<II", header[8:16])
    if recorded_size != source_stat.st_size:
        state.findings.append(
            ArtifactFinding(
                rel_path=rel,
                kind="pyc_mismatch",
                severity="high",
                detail=(
                    f"recorded source size {recorded_size} does not match "
                    f"{source_stat.st_size} byte(s) in {source_path.name}"
                ),
            )
        )
        return
    expected_mtime = int(source_stat.st_mtime)
    if recorded_mtime != expected_mtime:
        state.findings.append(
            ArtifactFinding(
                rel_path=rel,
                kind="pyc_mismatch",
                severity="high",
                detail=(
                    f"recorded source timestamp {recorded_mtime} does not match "
                    f"source mtime {expected_mtime}"
                ),
            )
        )


def _printable(text: str, limit: int) -> str:
    """Reduce arbitrary text to printable ASCII so a detail line cannot smuggle controls."""

    cleaned = "".join(char if 32 <= ord(char) < 127 else "?" for char in str(text))
    return cleaned.replace("'", " ")[:limit]


def _finding_sort_key(finding: ArtifactFinding) -> tuple[int, str, int, str, str, str]:
    """Order findings so the most severe evidence is first and stable."""

    return (
        _SEVERITY_RANK.get(finding.severity, 3),
        finding.rel_path,
        finding.line_no if finding.line_no is not None else 0,
        finding.kind,
        finding.symbol,
        finding.detail,
    )


def _finding_head(finding: ArtifactFinding) -> str:
    """Format one finding as path:line: kind (detail)."""

    location = finding.rel_path or "<scan>"
    if finding.line_no is not None:
        location = f"{location}:{finding.line_no}"
    return f"{location}: {finding.kind} ({finding.detail})"


def _render_detail(
    state: _ScanState,
    budget: ScanBudget,
    findings: tuple[ArtifactFinding, ...],
    suppressed: int = 0,
    store_path: str = "",
) -> str:
    """Compose the single line summary that the pillar puts in the dossier."""

    parts: list[str] = []
    if findings:
        parts.append(_finding_head(findings[0]))
        if len(findings) > 1:
            counts: dict[str, int] = {}
            for finding in findings[1:]:
                counts[finding.kind] = counts.get(finding.kind, 0) + 1
            parts.append(", ".join(f"{count} {kind} finding(s)" for kind, count in counts.items()))
        parts.append(f"{state.files_inspected} file(s) inspected")
    elif suppressed:
        parts.append(
            "no active unsafe serialized payload, dangerous API call site or pyc mismatch "
            f"after review in {state.files_inspected} file(s)"
        )
    else:
        parts.append(
            "no unsafe serialized payload, dangerous API call site or pyc mismatch found in "
            f"{state.files_inspected} file(s)"
        )
    if suppressed:
        location = store_path or "the suppression store"
        parts.append(f"{suppressed} finding(s) suppressed by review (see {location})")
    if state.dependency_note:
        parts.append(state.dependency_note)
    if state.truncated:
        parts.append(
            f"scan incomplete: {state.files_inspected} file(s) and {state.bytes_inspected} byte(s) inspected"
        )
        if state.oversize_skipped:
            parts.append(
                f"{state.oversize_skipped} file(s) skipped above the {budget.max_file_bytes} byte per-file cap"
            )
        if state.depth_pruned:
            parts.append(f"{state.depth_pruned} director(ies) left unvisited beyond depth {budget.max_depth}")
        if state.caps_hit:
            parts.append(f"{state.caps_hit} file(s) hit the {_MAX_FINDINGS_PER_FILE} finding per-file cap")
    else:
        parts.append(f"{state.bytes_inspected} byte(s) read")
    return "; ".join(parts)
