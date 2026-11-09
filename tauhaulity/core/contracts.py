"""Data contracts shared by the engine, pillars, dossier and CLI.

A single vocabulary module keeps the twelve pillar probes, the dossier
renderers and the command dispatcher from drifting apart: every status token,
slot key and finding shape is declared here, so renaming a status is a one line
change with an immediate, mechanical blast radius.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Callable, Mapping, Protocol, runtime_checkable

if TYPE_CHECKING:
    from tauhaulity.core.platform_probe import PlatformInfo
    from tauhaulity.core.policy import Policy

BENIGN_STATUSES: frozenset[str] = frozenset(
    {"SAFE", "READY", "PROTECTED", "CLEAN", "SECURE", "GENERATED", "DISABLED", "IDLE"}
)
WARNING_STATUSES: frozenset[str] = frozenset(
    {
        "WARNING",
        "TAMPERED",
        "UNPROTECTED",
        "CONFLICT_DETECTED",
        "NOT_INSTALLED",
        "EXPOSED",
    }
)
CRITICAL_STATUSES: frozenset[str] = frozenset(
    {"CRITICAL", "LEAK_DETECTED", "MALICIOUS_PTH", "ZOMBIE_FOUND"}
)

STATUS_SEVERITY: Mapping[str, int] = {
    **{status: 0 for status in BENIGN_STATUSES},
    **{status: 1 for status in WARNING_STATUSES},
    **{status: 2 for status in CRITICAL_STATUSES},
}

CANONICAL_SLOTS: tuple[str, ...] = (
    "detail",
    "hotpatch",
    "mirage",
    "ring_size",
    "trash_status",
    "ports",
    "zombies",
    "engine_tier",
    "venv_status",
    "hook_status",
    "token_status",
    "redacted_count",
    "suppressed",
    "hmac",
    "repro_files",
)


class ContractError(ValueError):
    """Raised when a pillar produces a finding that violates the shared schema."""


@dataclass(frozen=True, slots=True)
class PillarSpec:
    """Static identity and legal status tokens of one diagnostic pillar.

    Attributes:
        number: One based pillar number used by the dossier layout.
        key: Machine readable identifier (module suffix, artifact prefix).
        name: Human readable pillar title.
        mechanism: Short description of the detection mechanism for the dossier.
        statuses: Legal status tokens, most benign first.
        risk_scale: Upper bound of the risk score this pillar may report.
    """

    number: int
    key: str
    name: str
    mechanism: str
    statuses: tuple[str, ...]
    risk_scale: float = 10.0

    @property
    def default_status(self) -> str:
        """Status used when a probe raises instead of returning a finding."""

        return "WARNING" if "WARNING" in self.statuses else self.statuses[0]


@dataclass(frozen=True, slots=True)
class Finding:
    """One pillar verdict plus the dossier slot values it implies.

    Attributes:
        pillar: Pillar number this finding belongs to.
        status: One of the pillar spec's legal status tokens.
        detail: Single line evidence shown in the dossier.
        risk: Risk score in the closed range zero to the pillar risk scale.
        slots: Extra dossier placeholder values keyed by canonical slot names.
        repro_hint: Optional description used by the auto repro synthesizer.
    """

    pillar: int
    status: str
    detail: str
    risk: float = 0.0
    slots: Mapping[str, str] = field(default_factory=dict)
    repro_hint: str | None = None

    def slot(self, key: str, default: str = "") -> str:
        """Return a dossier slot value or a default when absent."""

        return self.slots.get(key, default)


@dataclass(frozen=True, slots=True)
class ScanOptions:
    """Runtime knobs that alter scan cost or output shape.

    Attributes:
        export_formats: Dossier formats to write; unknown values are rejected.
        deep: Enables expensive checks (full tree hashing, recursive probes).
        timeout_s: Soft per scan budget used by long running pillars.
        generate_repro: Allow the flight recorder to synthesize repro scripts.
        include_ignored: Also inspect paths excluded by the policy.
        record_telemetry: Append the verdict frame to the project telemetry log.
    """

    export_formats: tuple[str, ...] = ("md", "txt", "json")
    deep: bool = False
    timeout_s: float = 30.0
    generate_repro: bool = True
    include_ignored: bool = False
    record_telemetry: bool = True


@dataclass(slots=True)
class ScanContext:
    """Mutable per scan state handed to every pillar probe.

    Pillars receive this object instead of a bare path so that expensive shared
    work (platform fingerprint, policy, native engine handle) is computed once
    and can be reused through the artifact cache.
    """

    target: Path
    platform: "PlatformInfo"
    policy: "Policy"
    options: ScanOptions
    findings: dict[int, Finding] = field(default_factory=dict)
    artifacts: dict[str, Any] = field(default_factory=dict)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def record(self, finding: Finding) -> None:
        """Validate and store a pillar finding.

        Raises:
            ContractError: When the pillar number is unknown, the status token is
                not legal for that pillar, or the risk score is out of range.
        """

        spec = SPEC_BY_NUMBER.get(finding.pillar)
        if spec is None:
            raise ContractError(f"unknown pillar number: {finding.pillar}")
        if finding.status not in spec.statuses:
            raise ContractError(
                f"pillar {spec.number} status {finding.status!r} not in {spec.statuses}"
            )
        if not 0.0 <= finding.risk <= spec.risk_scale:
            raise ContractError(
                f"pillar {spec.number} risk {finding.risk} outside 0..{spec.risk_scale}"
            )
        self.findings[finding.pillar] = finding

    def finding(self, number: int) -> Finding | None:
        """Return the finding recorded for a pillar, if the probe ran."""

        return self.findings.get(number)

    def artifact(self, name: str, factory: Callable[[], Any]) -> Any:
        """Return a lazily created shared artifact, creating it once.

        Multiple pillars need the same native engine or undo store; caching here
        prevents duplicate handle allocation and keeps teardown centralized.
        """

        if name not in self.artifacts:
            self.artifacts[name] = factory()
        return self.artifacts[name]


@runtime_checkable
class PillarProbe(Protocol):
    """Structural type implemented by every tauhaulity.pillars module."""

    spec: PillarSpec

    def probe(self, ctx: ScanContext) -> Finding:
        """Run the pillar against a scan context and return its finding."""
        ...


def make_finding(
    spec: PillarSpec,
    status: str,
    detail: str,
    *,
    risk: float = 0.0,
    slots: Mapping[str, str] | None = None,
    repro_hint: str | None = None,
) -> Finding:
    """Build a finding with the pillar identity filled in.

    Raises:
        ContractError: When the status is not legal for the pillar or the risk
            score exceeds the pillar scale.
    """

    if status not in spec.statuses:
        raise ContractError(f"status {status!r} not legal for pillar {spec.number}")
    if not 0.0 <= risk <= spec.risk_scale:
        raise ContractError(f"risk {risk} outside 0..{spec.risk_scale} for pillar {spec.number}")
    return Finding(
        pillar=spec.number,
        status=status,
        detail=detail,
        risk=float(risk),
        slots=dict(slots or {}),
        repro_hint=repro_hint,
    )


PILLAR_SPECS: tuple[PillarSpec, ...] = (
    PillarSpec(
        number=1,
        key="aegis_vmi",
        name="Memory and GOT/IAT Integrity (AEGIS-VMI)",
        mechanism="Read-only pointer tables, MMU dirty-page tracking, native symbol resolution",
        statuses=("SAFE", "WARNING", "CRITICAL"),
    ),
    PillarSpec(
        number=2,
        key="hyper_immune",
        name="Zero-Day and Syscall Boundary (HYPER-IMMUNE)",
        mechanism="Atomic pointer swap, DR0-DR3 breakpoints, seccomp-bpf / Win32 mitigation",
        statuses=("SAFE", "WARNING", "CRITICAL"),
    ),
    PillarSpec(
        number=3,
        key="veritas_gate",
        name="Privilege and Transaction Gate (VERITAS-GATE)",
        mechanism="32-opcode copy-on-write register VM with deterministic gas metering",
        statuses=("SAFE", "WARNING", "CRITICAL"),
    ),
    PillarSpec(
        number=4,
        key="chrono_deception",
        name="Deception and Mirage Readiness (CHRONO-DECEPTION)",
        mechanism="Namespace bifurcation on Linux, thread-local PhantomFS on Windows",
        statuses=("READY", "DISABLED", "WARNING"),
    ),
    PillarSpec(
        number=5,
        key="crypto_shield",
        name="In-Memory Key Protection (CRYPTO-SHIELD)",
        mechanism="Page pinning, rotating XOR masks, branchless constant-time comparison",
        statuses=("SAFE", "EXPOSED", "WARNING"),
    ),
    PillarSpec(
        number=6,
        key="supply_guard",
        name="Third-Party Package and Deserialization (SUPPLY-GUARD)",
        mechanism="PEP-578 audit hooks, PEP-669 monitoring, pickletools opcode firewall",
        statuses=("SAFE", "WARNING", "CRITICAL"),
    ),
    PillarSpec(
        number=7,
        key="egress_dlp",
        name="Data Leak and Covert Channel (EGRESS-DLP)",
        mechanism="Pre-TLS cleartext inspection and 256-LUT Shannon entropy gate",
        statuses=("SAFE", "LEAK_DETECTED", "WARNING"),
    ),
    PillarSpec(
        number=8,
        key="ransom_dev_undo",
        name="Ransomware and Dev-Snap-Undo (RANSOM-ROLLBACK)",
        mechanism="Bounded circular undo store, canary traps and I/O entropy radar",
        statuses=("PROTECTED", "UNPROTECTED", "WARNING"),
    ),
    PillarSpec(
        number=9,
        key="port_sentinel",
        name="Process Lineage and Port Sweeper (PORT-SENTINEL)",
        mechanism="Native kernel socket tables with graceful then forceful reaping",
        statuses=("CLEAN", "CONFLICT_DETECTED", "ZOMBIE_FOUND", "WARNING"),
    ),
    PillarSpec(
        number=10,
        key="autonomic_venv",
        name="Autonomic Core and Venv Radar (AUTONOMIC-VENV-RADAR)",
        mechanism="Engine tier selection, virtual environment and shard integrity checks",
        statuses=("CLEAN", "TAMPERED", "MALICIOUS_PTH", "WARNING"),
    ),
    PillarSpec(
        number=11,
        key="git_dossier",
        name="Git Sentinel and Dossier Form (GIT-DOSSIER-SENTINEL)",
        mechanism="Staged secret scanning, pre-commit gate installation, HMAC stamped dossiers",
        statuses=("SECURE", "LEAK_DETECTED", "WARNING"),
    ),
    PillarSpec(
        number=12,
        key="auto_repro",
        name="Attack Flight-Recorder and Repro (AUTO-REPRO-GEN)",
        mechanism="Delta-minimized reproduction scripts synthesized from recorded findings",
        statuses=("GENERATED", "IDLE", "WARNING"),
    ),
)

SPEC_BY_NUMBER: Mapping[int, PillarSpec] = {spec.number: spec for spec in PILLAR_SPECS}
SPEC_BY_KEY: Mapping[str, PillarSpec] = {spec.key: spec for spec in PILLAR_SPECS}


def status_severity(status: str) -> int:
    """Map a status token to 0 (benign), 1 (warning) or 2 (critical).

    Unknown tokens resolve to 1 so that a future status cannot silently hide an
    anomaly by scoring as benign.
    """

    return STATUS_SEVERITY.get(status, 1)
