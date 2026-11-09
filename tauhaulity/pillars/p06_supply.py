"""Pillar 6 - SUPPLY-GUARD: deserialization firewall, pyc verifier, audit guardian.

The supply chain attack surface that matters for a developer machine is not the
network, it is the moment an untrusted byte string is deserialized inside a
trusted interpreter. This module implements three independent gates:

1. PickleGate walks a stream with pickletools.genops before anything is loaded.
   genops never executes the stream, so the gate can report the exact opcode,
   offset and reason while the payload is still inert. Opcodes that can import a
   callable (GLOBAL, STACK_GLOBAL), call it (REDUCE, INSTANTIATE, OBJ, NEWOBJ,
   NEWOBJ_EX), mutate an instance (BUILD) or reach outside the stream (PERSID,
   EXT1/2/4) are blocked. A malformed stream is rejected as well: refusing to
   parse it is cheaper than guessing.

2. PycVerifier checks a compiled cache against PEP 552 structure: magic number,
   flags, header size, timestamp/source-size or blake2b source hash, and
   truncation. A stale or tampered pyc is exactly how a bytecode level backdoor
   survives a source review, so the header is verified rather than trusted.

3. AuditGuardian delegates to tauhaulity.runtime.audit_hook. The guard is opt-in:
   installing a PEP-578 hook cannot be undone, so this class exposes capability
   discovery (PEP-578 and PEP-669 availability) and install/deactivate instead of
   arming itself on import.

The three gates above only prove that this pillar can protect its own process. The
probe therefore also runs tauhaulity.tools.artifact_scan over the project being
scanned: unsafe pickle opcodes (streamed, never loaded), dangerous call sites in
the project source (AST verified, so a string literal never triggers) and pyc
caches whose PEP 552 header disagrees with their source. The scan is bounded and
reports its own truncation, so a large tree degrades into a WARNING with the
exact file and byte counts instead of a silent claim of safety.

The scan also folds in the declared-dependency audit
(tauhaulity.tools.dep_audit): a typosquatted or suspicious package name, a direct
URL dependency, an unpinned declaration or a foreign index becomes a finding
before the package is ever installed. That mapping keeps the ladder honest: a
typosquat, a suspicious name, install-time execution and environment harvesting
are CRITICAL, an obfuscated payload alone is a WARNING, and a direct URL,
unpinned or unknown-index declaration alone is a WARNING.

Reviewed suppressions from <target>/.tauhaulity/suppressions.json are applied to
that scan. A suppression never hides evidence: the finding leaves the active list,
but the report, the scanner detail line, and the pillar detail all state how many
findings were suppressed and why the first suppression exists.

The frozen feed data behind these rules is not trusted to age silently: the
probe reads <target>/.tauhaulity/feeds through tauhaulity.tools.threat_feed and
appends a review note (and the feed_status slot) when a snapshot is missing or
older than the stale limit, naming the command that refreshes it. The staleness
note never changes the status ladder; it only makes the age visible.

Nothing here imports a sibling module at module import time: the runtime guard,
the monitoring tracer and the artifact scanner are loaded lazily so a partial
checkout still imports this pillar and the probe still produces a finding.
"""

from __future__ import annotations

import importlib.util
import marshal
import os
import pickle
import pickletools
import struct
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final, Iterable

from tauhaulity.core.contracts import Finding, PillarSpec, ScanContext, SPEC_BY_KEY, make_finding

SPEC: PillarSpec = SPEC_BY_KEY["supply_guard"]

# Opcodes that can reach code outside the pickle stream. Blocking BUILD is
# deliberate: it invokes __setstate__ on an attacker chosen class, which is code
# execution with extra steps.
BLOCKED_PICKLE_OPCODES: Final[frozenset[str]] = frozenset(
    {
        "GLOBAL",
        "STACK_GLOBAL",
        "REDUCE",
        "INSTANTIATE",
        "OBJ",
        "NEWOBJ",
        "NEWOBJ_EX",
        "BUILD",
        "INST",
        "PERSID",
        "BINPERSID",
        "EXT1",
        "EXT2",
        "EXT4",
    }
)

_OPCODE_REASONS: Final[dict[str, str]] = {
    "GLOBAL": "imports an arbitrary callable by module and name",
    "STACK_GLOBAL": "imports an arbitrary callable whose names come from the stream",
    "REDUCE": "calls the previously resolved callable with stream supplied arguments",
    "INSTANTIATE": "constructs a class instance from stream supplied arguments",
    "OBJ": "constructs an object and runs its class constructor",
    "NEWOBJ": "allocates an instance of an attacker chosen class",
    "NEWOBJ_EX": "allocates an instance with attacker supplied __new__ arguments",
    "BUILD": "invokes __setstate__ or mutates __dict__ on an attacker chosen object",
    "INST": "imports a class by module and name to build an instance",
    "PERSID": "resolves a persistent id through the loader callback",
    "BINPERSID": "resolves a binary persistent id through the loader callback",
    "EXT1": "resolves an extension registry object imported by the interpreter",
    "EXT2": "resolves an extension registry object imported by the interpreter",
    "EXT4": "resolves an extension registry object imported by the interpreter",
}

PYC_HEADER_SIZE: Final[int] = 16
PYC_HASH_FLAG: Final[int] = 0b01
PYC_CHECK_SOURCE_FLAG: Final[int] = 0b10


class UnsafePickleError(ValueError):
    """Raised when a pickle stream contains a blocked opcode.

    Attributes:
        verdict: The PickleVerdict that rejected the stream.
    """

    def __init__(self, verdict: "PickleVerdict") -> None:
        super().__init__(f"unsafe pickle stream: {verdict.reason}")
        self.verdict = verdict


@dataclass(frozen=True, slots=True)
class PickleFinding:
    """One blocked opcode occurrence inside a pickle stream.

    Attributes:
        opcode: Pickle opcode mnemonic, for example REDUCE.
        position: Byte offset of the opcode in the stream.
        argument: Truncated repr of the opcode argument.
        reason: Why the opcode is unsafe.
    """

    opcode: str
    position: int
    argument: str
    reason: str


@dataclass(frozen=True, slots=True)
class PickleVerdict:
    """Result of scanning one pickle stream.

    Attributes:
        allowed: True when the stream contains no blocked opcode.
        findings: Blocked opcode occurrences in stream order.
        opcodes_seen: Distinct opcode mnemonics observed, in order of appearance.
        reason: One line summary, safe to render in the dossier.
        size: Stream length in bytes.
    """

    allowed: bool
    findings: tuple[PickleFinding, ...]
    opcodes_seen: tuple[str, ...]
    reason: str
    size: int

    @property
    def blocked_opcodes(self) -> tuple[str, ...]:
        """Distinct blocked opcode mnemonics found in the stream."""

        return tuple(dict.fromkeys(finding.opcode for finding in self.findings))


class PickleGate:
    """Static pickle opcode firewall built on pickletools.genops.

    Attributes:
        blocked: Opcode mnemonics this gate rejects.
    """

    def __init__(self, blocked: Iterable[str] | None = None) -> None:
        self.blocked = frozenset(blocked) if blocked is not None else BLOCKED_PICKLE_OPCODES

    def scan(self, data: bytes | bytearray | memoryview) -> PickleVerdict:
        """Inspect a pickle stream without executing it.

        genops is a pure reader; the returned verdict is complete even when the
        stream is hostile. A ValueError from genops means the stream is truncated or
        malformed, which is reported as a rejection rather than an exception so a
        scanner never dies on adversarial input.
        """

        try:
            material = bytes(data)
        except (TypeError, ValueError) as exc:
            return PickleVerdict(False, (), (), f"stream is not bytes-like: {exc}", 0)
        findings: list[PickleFinding] = []
        seen: list[str] = []
        try:
            for opcode, argument, position in pickletools.genops(material):
                name = opcode.name
                if name not in seen:
                    seen.append(name)
                if name in self.blocked:
                    findings.append(
                        PickleFinding(
                            opcode=name,
                            position=int(position),
                            argument=repr(argument)[:120],
                            reason=_OPCODE_REASONS.get(name, "blocked opcode"),
                        )
                    )
        except ValueError as exc:
            reasoning = f"malformed pickle stream: {exc}"
            return PickleVerdict(
                False,
                tuple(findings) + (PickleFinding("<malformed>", 0, "", str(exc)[:120]),),
                tuple(seen),
                reasoning,
                len(material),
            )
        except (pickletools.OpcodeError, UnicodeDecodeError) as exc:
            reasoning = f"pickle opcode error: {exc}"
            return PickleVerdict(
                False,
                tuple(findings) + (PickleFinding("<malformed>", 0, "", str(exc)[:120]),),
                tuple(seen),
                reasoning,
                len(material),
            )
        if findings:
            return PickleVerdict(
                False,
                tuple(findings),
                tuple(seen),
                f"blocked opcode(s): {', '.join(dict.fromkeys(finding.opcode for finding in findings))}",
                len(material),
            )
        return PickleVerdict(True, (), tuple(seen), "no unsafe opcode observed", len(material))

    def loads(self, data: bytes | bytearray | memoryview) -> Any:
        """Deserialize a stream only after it passes the opcode gate.

        Raises:
            UnsafePickleError: When the stream contains a blocked opcode.
        """

        verdict = self.scan(data)
        if not verdict.allowed:
            raise UnsafePickleError(verdict)
        return pickle.loads(bytes(data))

    def is_allowed(self, data: bytes | bytearray | memoryview) -> bool:
        """True when the stream passes the opcode gate."""

        return self.scan(data).allowed


@dataclass(frozen=True, slots=True)
class PycFinding:
    """One problem found while verifying a compiled Python cache.

    Attributes:
        check: Short check identifier (magic, flags, header, hash, source-size).
        detail: Human readable explanation.
        severity: error for a rejection, warning for a suspicious but loadable file.
    """

    check: str
    detail: str
    severity: str = "error"


@dataclass(frozen=True, slots=True)
class PycVerdict:
    """Result of verifying one pyc file.

    Attributes:
        ok: True when no error severity finding was reported.
        findings: Problems in check order.
        magic: The four magic bytes read from the file.
        flags: PEP 552 flags word.
        hash_based: True when bit 0 of the flags is set.
        check_source: True when bit 1 of the flags is set.
        header_size: Header length this verifier used.
        size: Total file length.
        reason: One line summary.
    """

    ok: bool
    findings: tuple[PycFinding, ...]
    magic: bytes
    flags: int
    hash_based: bool
    check_source: bool
    header_size: int
    size: int
    reason: str

    @property
    def errors(self) -> tuple[PycFinding, ...]:
        """Only the findings that caused a rejection."""

        return tuple(finding for finding in self.findings if finding.severity == "error")


class PycVerifier:
    """Verify PEP 552 compiled cache structure against source bytes.

    The verifier is read-only and never executes the marshalled body. Structural
    verification is enough to detect a stale or tampered timestamp/hash header,
    which is where a cache poisoning attack has to lie to survive.
    """

    def verify(self, data: bytes | bytearray | memoryview, *, source: bytes | str | None = None) -> PycVerdict:
        """Verify a pyc blob, optionally against the source it claims to cache."""

        try:
            material = bytes(data)
        except (TypeError, ValueError) as exc:
            return PycVerdict(False, (PycFinding("bytes", str(exc)),), b"", 0, False, False, 0, 0, "not bytes")
        findings: list[PycFinding] = []
        size = len(material)
        if size < PYC_HEADER_SIZE:
            findings.append(
                PycFinding(
                    "header",
                    f"file is {size} bytes but a PEP 552 header needs {PYC_HEADER_SIZE}",
                )
            )
            return self._verdict(material, findings, 0, False, False)
        magic = material[:4]
        expected_magic = importlib.util.MAGIC_NUMBER
        if magic != expected_magic:
            findings.append(
                PycFinding(
                    "magic",
                    f"magic {magic.hex()} does not match this interpreter ({expected_magic.hex()})",
                )
            )
        flags = struct.unpack("<I", material[4:8])[0]
        hash_based = bool(flags & PYC_HASH_FLAG)
        check_source = bool(flags & PYC_CHECK_SOURCE_FLAG)
        unknown = flags & ~(PYC_HASH_FLAG | PYC_CHECK_SOURCE_FLAG)
        if unknown:
            findings.append(
                PycFinding(
                    "flags",
                    f"unknown PEP 552 flag bits set: {unknown:#x}",
                    severity="warning",
                )
            )
        if size == PYC_HEADER_SIZE:
            findings.append(PycFinding("body", "header only: the marshalled body is missing"))
        source_bytes = self._source_bytes(source)
        if hash_based:
            stored_hash = material[8:16]
            if check_source and source_bytes is not None:
                expected_hash = importlib.util.source_hash(source_bytes)
                if stored_hash != expected_hash:
                    findings.append(
                        PycFinding(
                            "hash",
                            "source hash mismatch: the cache does not match the checked source",
                        )
                    )
        else:
            source_size_field = struct.unpack("<I", material[12:16])[0]
            mtime_field = struct.unpack("<I", material[8:12])[0]
            if mtime_field == 0 and source_bytes is not None:
                findings.append(
                    PycFinding(
                        "timestamp",
                        "timestamp field is zero for a timestamp based cache",
                        severity="warning",
                    )
                )
            if source_bytes is not None and source_size_field != len(source_bytes):
                findings.append(
                    PycFinding(
                        "source-size",
                        f"recorded source size {source_size_field} does not match {len(source_bytes)} bytes",
                    )
                )
        return self._verdict(material, findings, flags, hash_based, check_source)

    def verify_file(self, path: Path, *, source_path: Path | None = None) -> PycVerdict:
        """Read a pyc from disk and verify it, optionally against its source file."""

        path = Path(path)
        try:
            data = path.read_bytes()
        except OSError as exc:
            return PycVerdict(False, (PycFinding("io", f"{path}: {exc}"),), b"", 0, False, False, PYC_HEADER_SIZE, 0, "unreadable")
        source: bytes | None = None
        if source_path is not None:
            try:
                source = Path(source_path).read_bytes()
            except OSError as exc:
                return PycVerdict(
                    False,
                    (PycFinding("io", f"{source_path}: {exc}"),),
                    b"",
                    0,
                    False,
                    False,
                    PYC_HEADER_SIZE,
                    0,
                    "unreadable source",
                )
        return self.verify(data, source=source)

    @staticmethod
    def _source_bytes(source: bytes | str | None) -> bytes | None:
        if source is None:
            return None
        if isinstance(source, str):
            return source.encode("utf-8")
        return bytes(source)

    @staticmethod
    def _verdict(
        material: bytes,
        findings: list[PycFinding],
        flags: int,
        hash_based: bool,
        check_source: bool,
    ) -> PycVerdict:
        errors = [finding for finding in findings if finding.severity == "error"]
        reason = "cache header verified" if not errors else errors[0].detail
        return PycVerdict(
            ok=not errors,
            findings=tuple(findings),
            magic=material[:4],
            flags=flags,
            hash_based=hash_based,
            check_source=check_source,
            header_size=PYC_HEADER_SIZE,
            size=len(material),
            reason=reason,
        )


class AuditGuardian:
    """Opt-in PEP-578 guard wrapper used by the pillar.

    Attributes:
        root: Project root handed to the guard for caller classification.
    """

    def __init__(self, root: Path | None = None) -> None:
        self.root = Path(root) if root is not None else None
        self._mode = "inactive"

    def capabilities(self) -> dict[str, Any]:
        """Report PEP-578 and PEP-669 availability plus the monitoring self-test."""

        try:
            from tauhaulity.runtime import monitoring as monitoring_module

            monitoring_test = monitoring_module.tracer.self_test()
        except (ImportError, OSError, RuntimeError) as exc:
            monitoring_test = {"available": False, "started": False, "reason": str(exc)}
        capabilities: dict[str, Any] = {
            "pep578": hasattr(sys, "addaudithook"),
            "pep669": bool(monitoring_test.get("available")),
            "monitoring": monitoring_test,
        }
        try:
            from tauhaulity.runtime import audit_hook as audit_module

            capabilities["guard_active"] = bool(audit_module.active())
        except (ImportError, OSError, RuntimeError):
            capabilities["guard_active"] = False
        return capabilities

    def install(self, enforce: bool = False) -> bool:
        """Install the runtime guard in watch or enforce mode.

        Returns:
            True when the guard reports itself active after the call. A missing
            runtime layer is reported as False instead of raising, so the pillar
            can degrade honestly.
        """

        try:
            from tauhaulity.runtime import audit_hook as audit_module
        except (ImportError, OSError, RuntimeError):
            self._mode = "unavailable"
            return False
        try:
            audit_module.install(enforce=enforce, root=self.root)
        except (RuntimeError, OSError, ValueError):
            self._mode = "failed"
            return False
        self._mode = "enforce" if enforce else "watch"
        return bool(audit_module.active())

    def deactivate(self) -> None:
        """Put the runtime guard to sleep."""

        try:
            from tauhaulity.runtime import audit_hook as audit_module

            audit_module.deactivate()
        except (ImportError, OSError, RuntimeError):
            pass
        self._mode = "inactive"

    def active(self) -> bool:
        """True while the runtime guard records events."""

        try:
            from tauhaulity.runtime import audit_hook as audit_module

            return bool(audit_module.active())
        except (ImportError, OSError, RuntimeError):
            return False

    def mode(self) -> str:
        """Return the locally remembered mode: watch, enforce, inactive."""

        return self._mode

    def stats(self) -> dict[str, Any]:
        """Return the runtime guard statistics, or a degraded placeholder."""

        try:
            from tauhaulity.runtime import audit_hook as audit_module

            return dict(audit_module.stats())
        except (ImportError, OSError, RuntimeError) as exc:
            return {"installed": False, "active": False, "reason": str(exc), "mode": self._mode}


class _ProbePayload:
    """Payload used only to build malicious pickle bytes, never to execute them."""

    def __reduce__(self):
        return (os.system, ("echo tauhaulity-probe",))


def _build_timestamp_pyc(source: str) -> tuple[bytes, bytes]:
    """Build a structurally valid timestamp based pyc for the probe self-test."""

    source_bytes = source.encode("utf-8")
    code = compile(source, "<tauhaulity-probe>", "exec")
    header = (
        importlib.util.MAGIC_NUMBER
        + struct.pack("<I", 0)
        + struct.pack("<I", int(time.time())) 
        + struct.pack("<I", len(source_bytes))
    )
    return header + marshal.dumps(code), source_bytes


def _probe_self_tests() -> tuple[bool, bool, bool, bool, str]:
    """Run the gate self-tests and return (benign, malicious, pyc, audit, detail)."""

    gate = PickleGate()
    verifier = PycVerifier()
    benign_stream = pickle.dumps({"user": "dev", "count": 3, "items": [1, 2, 3]}, protocol=2)
    benign_ok = gate.scan(benign_stream).allowed
    malicious_stream = pickle.dumps(_ProbePayload(), protocol=2)
    malicious_verdict = gate.scan(malicious_stream)
    malicious_blocked = (not malicious_verdict.allowed) and (
        "REDUCE" in malicious_verdict.blocked_opcodes
    )
    pyc_bytes, source_bytes = _build_timestamp_pyc("value = 1\n")
    valid_pyc = verifier.verify(pyc_bytes, source=source_bytes)
    corrupt_pyc = verifier.verify(pyc_bytes[:12], source=source_bytes)
    pyc_ok = valid_pyc.ok and not corrupt_pyc.ok
    guardian = AuditGuardian()
    capabilities = guardian.capabilities()
    audit_ok = bool(capabilities.get("pep578"))
    detail = (
        f"benign pickle accepted={benign_ok}, malicious pickle blocked={malicious_blocked} "
        f"({', '.join(malicious_verdict.blocked_opcodes) or 'none'}), pyc header verified={pyc_ok}, "
        f"pep578={capabilities.get('pep578')}, pep669={capabilities.get('pep669')}"
    )
    return benign_ok, malicious_blocked, pyc_ok, audit_ok, detail


_GATE_REPRO_HINT: Final[str] = (
    "Call PickleGate().scan on a pickled __reduce__ payload and check the opcode findings."
)
_ARTIFACT_REPRO_HINT: Final[str] = (
    "Open the reported file without executing it: stream pickle artifacts through "
    "pickletools.genops and read the reported source call site."
)
_DETAIL_LIMIT: Final[int] = 600
_FEED_REFRESH_COMMAND: Final[str] = "python scripts/threat_feed_check.py --refresh"
_FEED_STALE_AFTER_DAYS: Final[int] = 30


def _one_line(text: str) -> str:
    """Collapse a detail string to one line and bound its length for the dossier."""

    return " ".join(str(text).split())[:_DETAIL_LIMIT]


def _load_suppression_store(target: Any) -> tuple[Any, str]:
    """Load the reviewed suppression store for the scanned project.

    Returns:
        A pair of (store, first_reason). The store is None when the suppression
        layer is missing or unusable, in which case every finding is reported; the
        reason is the reviewer justification of the first stored entry. A broken
        review layer must never crash the pillar, so every failure degrades to the
        stricter behaviour of reporting everything.
    """

    try:
        from tauhaulity.tools import suppress as suppress_module
    except ImportError:
        return None, ""
    try:
        store = suppress_module.SuppressionStore(target)
        entries = store.load()
    except Exception:  # a broken review layer must not crash the pillar cascade
        return None, ""
    reason = ""
    if entries:
        reason = _one_line(str(getattr(entries[0], "reason", "") or ""))[:160]
    return store, reason


def _scan_project_artifacts(ctx: ScanContext) -> tuple[Any, str | None, str]:
    """Run the bounded artifact scanner over the scanned project.

    Returns:
        A triple of (report, error, first_suppression_reason). Exactly one of the
        first two members is None: the report when the scan completed, the error
        line when the scanner is missing or raised. A failed scan must never be
        rendered as SAFE, so the caller turns the error into a WARNING that names
        the exception class.
    """

    store, suppression_reason = _load_suppression_store(ctx.target)
    try:
        from tauhaulity.tools import artifact_scan
    except ImportError as exc:
        return None, f"artifact scanner unavailable ({type(exc).__name__})", suppression_reason
    ignored = tuple(getattr(ctx.policy, "ignored_paths", ()) or ())
    try:
        report = artifact_scan.scan_source_tree(ctx.target, ignored=ignored, suppress=store)
    except Exception as exc:  # a hostile tree must never crash the pillar cascade
        return None, f"artifact scan raised {type(exc).__name__}", suppression_reason
    return report, None, suppression_reason


def _load_feed_status(target: Any) -> tuple[Any, str]:
    """Read the cached threat-feed age for the scanned project.

    Returns:
        A pair of (FeedStatus, error). The status is None when the layer is
        missing or raised; the error names the exception class so the pillar can
        report an unavailable review note instead of pretending the data is fresh.
    """

    try:
        from tauhaulity.tools import threat_feed
    except ImportError:
        return None, "threat feed layer unavailable (ImportError)"
    try:
        return threat_feed.status(root=target, stale_after_days=_FEED_STALE_AFTER_DAYS), ""
    except Exception:  # a broken cache must never crash the pillar cascade
        return None, "threat feed status unavailable (unexpected error)"


def probe(ctx: ScanContext) -> Finding:
    """Self-test the deserialization gates and scan the project artifacts.

    CRITICAL is reserved for a gate that accepted a payload it must reject and for
    a high severity artifact finding: a declared but ineffective firewall is worse
    than an absent one because the dossier would otherwise claim protection, and
    an unsafe pickle or a shell call site inside the project is actionable now.
    """

    try:
        benign_ok, malicious_blocked, pyc_ok, audit_ok, gate_detail = _probe_self_tests()
        guardian = AuditGuardian(root=ctx.target)
        capabilities = guardian.capabilities()
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        detail = f"supply guard self-test raised {type(exc).__name__}: {exc}"
        return make_finding(
            SPEC,
            "WARNING",
            detail,
            risk=4.0,
            slots={"detail": detail},
            repro_hint=_GATE_REPRO_HINT,
        )
    gate_ok = benign_ok and malicious_blocked and pyc_ok
    report, scan_error, suppression_reason = _scan_project_artifacts(ctx)
    artifact_detail = report.detail if report is not None else "artifact scan unavailable"
    suppression_note = ""
    if report is not None and report.suppressed:
        suppression_note = f"{report.suppressed} finding(s) suppressed by review"
        if suppression_reason:
            suppression_note += f" (first reason: {suppression_reason})"
    repro_hint: str | None = None
    if not gate_ok:
        status = "CRITICAL"
        risk = 8.0
        detail = f"deserialization gate failure: {gate_detail}"
        repro_hint = _GATE_REPRO_HINT
    elif scan_error is not None:
        status = "WARNING"
        risk = 4.0
        detail = f"{scan_error}; {gate_detail}"
    elif any(finding.severity == "high" for finding in report.findings):
        status = "CRITICAL"
        risk = 8.0
        detail = f"{artifact_detail}; pickle gate self-test passed"
        repro_hint = _ARTIFACT_REPRO_HINT
    elif report.findings:
        status = "WARNING"
        risk = 4.0
        detail = f"{artifact_detail}; pickle gate self-test passed"
        repro_hint = "Open the reported file at the reported line and remove or gate the construct."
    elif report.truncated:
        status = "WARNING"
        risk = 2.5
        detail = (
            f"artifact scan stopped at the scan budget after {report.files_inspected} file(s) and "
            f"{report.bytes_inspected} byte(s) inspected, no finding so far; {gate_detail}"
        )
    elif not audit_ok:
        status = "WARNING"
        risk = 3.5
        detail = f"gates verified but no PEP-578 audit hook on this interpreter: {gate_detail}"
    else:
        status = "SAFE"
        risk = 0.0
        detail = (
            f"{artifact_detail}; {gate_detail}; "
            f"hook install available in watch/enforce mode; "
            f"pep669 monitoring={'available' if capabilities.get('pep669') else 'unavailable'}"
        )
    suppression_tail = ""
    if suppression_note and report is not None:
        # Never hide the review decision: whichever branch won, the dossier says
        # that something was suppressed and why the first grant exists. The
        # scanner detail already carries the count and the store path, so only the
        # reason is appended in that case instead of repeating the whole clause.
        marker = f"{report.suppressed} finding(s) suppressed by review"
        if marker in detail:
            if suppression_reason:
                suppression_tail = f"first suppression reason: {suppression_reason}"
        else:
            suppression_tail = suppression_note
    feed_status, feed_error = _load_feed_status(ctx.target)
    feed_tail = ""
    if feed_error:
        feed_tail = feed_error
        feed_slot = "unavailable"
    elif feed_status is not None and feed_status.stale:
        ages = ", ".join(
            snapshot.kind
            + (" missing" if snapshot.age_days < 0 else f" {snapshot.age_days:.0f} day(s) old")
            for snapshot in feed_status.snapshots
        )
        feed_tail = f"threat feed data is stale ({ages}); refresh with {_FEED_REFRESH_COMMAND}"
        feed_slot = "stale: " + ages
    elif feed_status is not None:
        newest = max(snapshot.age_days for snapshot in feed_status.snapshots)
        feed_slot = f"fresh ({newest:.1f} day(s) old)"
    else:
        feed_slot = "unavailable"
    detail = _one_line(detail)
    tails = [tail for tail in (suppression_tail, feed_tail) if tail]
    if tails:
        # Reserve room for the review notes so a long evidence line can never
        # truncate the reason or the staleness warning the operator must read.
        joined = "; ".join(tails)
        room = _DETAIL_LIMIT - len(joined) - 2
        head = detail[: max(0, room)].rstrip()
        detail = _one_line(f"{head}; {joined}" if head else joined)
    return make_finding(
        SPEC,
        status,
        detail,
        risk=risk,
        slots={"detail": detail, "feed_status": _one_line(feed_slot)[:160]},
        repro_hint=repro_hint,
    )
