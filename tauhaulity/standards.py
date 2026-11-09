"""Framework mapping: pillar evidence placed in the vocabulary teams report in.

What this module is: a translation layer. Each pillar observes specific evidence,
and that evidence corresponds to published adversary techniques and risk
categories, so the dossier can be read by somebody who reports against MITRE
ATT&CK or the OWASP Top 10 without translating by hand.

What this module is NOT: an attestation. Mapping an observation to T1552.001 does
not mean the control is implemented, tested or certified; it means the evidence a
scan produced is about the same subject. Every pillar therefore ships an explicit
limit sentence through explain(), and a pillar with no honest mapping returns an
empty tuple instead of padding the table with a plausible looking identifier.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from tauhaulity.core.contracts import PILLAR_SPECS

ATTACK = "MITRE ATT&CK"
OWASP = "OWASP Top 10 2021"
CIS = "CIS Controls v8"


@dataclass(frozen=True, slots=True)
class FrameworkRef:
    """One published reference.

    Attributes:
        framework: Framework name.
        identifier: Published identifier such as T1552.001 or A02:2021.
        title: Human readable title of the reference.
        url: Canonical documentation URL.
    """

    framework: str
    identifier: str
    title: str
    url: str


@dataclass(frozen=True, slots=True)
class CoverageRow:
    """One row of the coverage table shown in documentation.

    Attributes:
        pillar: Pillar number.
        name: Pillar title.
        techniques: Space separated ATT&CK identifiers.
        owasp: Comma separated OWASP identifiers.
        note: The honest limit of what this pillar observes.
    """

    pillar: int
    name: str
    techniques: str
    owasp: str
    note: str


def _attack(identifier: str, title: str) -> FrameworkRef:
    slug = identifier.replace(".", "/")
    return FrameworkRef(ATTACK, identifier, title, f"https://attack.mitre.org/techniques/{slug}/")


def _owasp(identifier: str, title: str) -> FrameworkRef:
    year, number = identifier.split(":")
    return FrameworkRef(OWASP, identifier, title, f"https://owasp.org/Top10/{year}/{number}/")


def _cis(identifier: str, title: str) -> FrameworkRef:
    return FrameworkRef(CIS, identifier, title, "https://www.cisecurity.org/controls/v8")


#: Pillar evidence mapped to the techniques and categories it is actually about.
PILLAR_STANDARDS: dict[int, tuple[FrameworkRef, ...]] = {
    1: (
        _attack("T1055", "Process Injection"),
        _attack("T1574.002", "Hijack Execution Flow: DLL Side-Loading"),
        _owasp("A08:2021", "Software and Data Integrity Failures"),
    ),
    2: (
        _attack("T1055", "Process Injection"),
        _attack("T1059", "Command and Scripting Interpreter"),
        _owasp("A03:2021", "Injection"),
    ),
    3: (
        _owasp("A04:2021", "Insecure Design"),
        _cis("16", "Application Software Security"),
    ),
    4: (
        _attack("T1562.001", "Impair Defenses: Disable or Modify Tools"),
        _cis("13", "Network Monitoring and Defense"),
    ),
    5: (
        _attack("T1552", "Unsecured Credentials"),
        _attack("T1005", "Data from Local System"),
        _owasp("A02:2021", "Cryptographic Failures"),
    ),
    6: (
        _attack("T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain"),
        _attack("T1203", "Exploitation for Client Execution"),
        _attack("T1027", "Obfuscated Files or Information"),
        _owasp("A08:2021", "Software and Data Integrity Failures"),
        _owasp("A03:2021", "Injection"),
    ),
    7: (
        _attack("T1048", "Exfiltration Over Alternative Protocol"),
        _attack("T1071.004", "Application Layer Protocol: DNS"),
        _attack("T1041", "Exfiltration Over C2 Channel"),
        _owasp("A09:2021", "Security Logging and Monitoring Failures"),
    ),
    8: (
        _attack("T1486", "Data Encrypted for Impact"),
        _attack("T1485", "Data Destruction"),
        _attack("T1490", "Inhibit System Recovery"),
        _cis("11", "Data Recovery"),
    ),
    9: (
        _attack("T1046", "Network Service Discovery"),
        _attack("T1571", "Non-Standard Port"),
        _attack("T1205", "Traffic Signaling"),
        _cis("12", "Network Infrastructure Management"),
    ),
    10: (
        _attack("T1195.002", "Supply Chain Compromise: Compromise Software Supply Chain"),
        _attack("T1546", "Event Triggered Execution"),
        _attack("T1554", "Compromise Host Software Binary"),
        _owasp("A06:2021", "Vulnerable and Outdated Components"),
    ),
    11: (
        _attack("T1552.001", "Unsecured Credentials: Credentials In Files"),
        _attack("T1552.004", "Unsecured Credentials: Private Keys"),
        _attack("T1078", "Valid Accounts"),
        _owasp("A07:2021", "Identification and Authentication Failures"),
    ),
    12: (
        _attack("T1204", "User Execution"),
        _cis("17", "Incident Response Management"),
    ),
}

#: Additional references that only apply once a specific status is reported.
STATUS_STANDARDS: dict[str, tuple[FrameworkRef, ...]] = {
    "LEAK_DETECTED": (_cis("16.11", "Leverage the secure software development lifecycle"),),
    "MALICIOUS_PTH": (_attack("T1546.016", "Event Triggered Execution: Installer Packages"),),
    "TAMPERED": (_attack("T1554", "Compromise Host Software Binary"),),
    "CRITICAL": (_cis("17.4", "Establish and maintain an incident response process"),),
    "CONFLICT_DETECTED": (_attack("T1046", "Network Service Discovery"),),
    "ZOMBIE_FOUND": (_attack("T1036", "Masquerading"),),
    "EXPOSED": (_attack("T1552", "Unsecured Credentials"),),
}

#: One honest limit sentence per pillar. A mapping that does not say what it
#: cannot see invites a reader to over-trust the scan.
_LIMITS: dict[int, str] = {
    1: "reports pointer table permissions, executable mappings and page digests; it does not intercept a hook or prove one is absent",
    2: "reports atomic swap capability, debug register readability and syscall policy state; it does not apply a policy",
    3: "runs invariant programs in a sandbox VM; it is not wired to the transaction engine of the host application",
    4: "verifies an in-memory filesystem and reports bifurcation availability; it does not redirect another process",
    5: "reports page pinning, mask rotation and constant time comparison; it is not a key management system",
    6: "scans files and bytecode for unsafe constructs; it does not execute or sandbox the payload it finds",
    7: "observes cleartext handed to TLS and evaluates DNS/ICMP entropy; it does not inspect encrypted traffic",
    8: "measures rollback readiness, canary coverage and ciphertext radar; it does not intercept every filesystem deletion, only those that go through tauhaulity",
    9: "enumerates local listening sockets and their owners; it does not probe remote hosts",
    10: "verifies installed file digests, startup hooks and name similarity; typosquat is a heuristic, not proof of malice",
    11: "matches credential patterns in the working tree and history; an unknown issuer with low entropy is not detected",
    12: "synthesizes reproduction scripts from recorded findings; it does not exploit the target or prove exploitability",
}

_IDENTIFIER_SHAPE = (
    ("T", 4),
    ("A", 2),
)


def refs_for(pillar: int, status: str = "") -> tuple[FrameworkRef, ...]:
    """Return the references for a pillar plus any status specific ones.

    Parameters:
        pillar: Pillar number, one through twelve.
        status: Optional status token such as LEAK_DETECTED.

    Returns:
        Deduplicated references in a stable order: pillar references first, then
        status references, each in declaration order.
    """

    ordered: list[FrameworkRef] = list(PILLAR_STANDARDS.get(pillar, ()))
    ordered.extend(STATUS_STANDARDS.get(status.upper(), ()))
    seen: set[tuple[str, str]] = set()
    unique: list[FrameworkRef] = []
    for ref in ordered:
        key = (ref.framework, ref.identifier)
        if key in seen:
            continue
        seen.add(key)
        unique.append(ref)
    return tuple(unique)


def format_refs(refs: tuple[FrameworkRef, ...]) -> str:
    """Render references as one report cell, keeping ATT&CK first.

    Parameters:
        refs: References to render.

    Returns:
        A short comma separated identifier list, or an empty string.
    """

    return ", ".join(ref.identifier for ref in refs)


def explain(pillar: int) -> str:
    """Return one sentence describing what the pillar observes and its limit."""

    spec = next((item for item in PILLAR_SPECS if item.number == pillar), None)
    if spec is None:
        return "unknown pillar"
    limit = _LIMITS.get(pillar, "no documented limit")
    return f"{spec.name}: {limit}."


def coverage(gaps_only: bool = False) -> tuple[CoverageRow, ...]:
    """Return the coverage table used in documentation.

    Parameters:
        gaps_only: When True only pillars with at least one reference are
            returned, which is the table a reader wants to see.
    """

    rows: list[CoverageRow] = []
    for spec in PILLAR_SPECS:
        refs = PILLAR_STANDARDS.get(spec.number, ())
        if gaps_only and not refs:
            continue
        rows.append(
            CoverageRow(
                pillar=spec.number,
                name=spec.name,
                techniques=" ".join(ref.identifier for ref in refs if ref.framework == ATTACK),
                owasp=", ".join(ref.identifier for ref in refs if ref.framework == OWASP),
                note=_LIMITS.get(spec.number, "no documented limit"),
            )
        )
    return tuple(rows)
