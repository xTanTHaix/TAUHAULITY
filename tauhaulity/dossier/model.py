"""Dossier data model shared by the renderers, the form parser and the engine.

The report is a frozen value object so that a dossier cannot drift from the
findings it claims to describe: every renderer receives the same validated
snapshot, and the HMAC is computed over that snapshot instead of over whatever a
renderer happened to print. Keeping the twelve findings in pillar order here (not
in each renderer) means the Markdown, text and JSON dossiers cannot disagree
about which pillars ran.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from tauhaulity.core.contracts import PILLAR_SPECS, Finding
from tauhaulity.core.policy import Policy
from tauhaulity.core.scorecard import Scorecard
from tauhaulity.core.verdict import Verdict

if TYPE_CHECKING:
    from tauhaulity.core.contracts import PillarSpec

# Bumped whenever a key is renamed or added so that automation can detect a
# schema change instead of silently reading a field that moved.
DOSSIER_SCHEMA = "tauhaulity.dossier/1"

# Legal origins of the signing key, mirroring redactor.resolve_signing_key.
KEY_SOURCES: tuple[str, ...] = ("machine", "env", "explicit", "none")

# Fixed artifact names required by the CLI contract; the extension is the format.
REPORT_FILENAMES: dict[str, str] = {
    "md": "tauhaulity_report.md",
    "txt": "tauhaulity_report.txt",
    "json": "tauhaulity_report.json",
}

# Section headings are shared by both human renderers so a test or a reviewer
# can locate a section without hard coding renderer specific punctuation.
SECTION_HEADINGS: tuple[str, ...] = (
    "SEC 0: SECURITY SCORECARD (SCORE, GRADE AND WHERE THE POINTS WENT)",
    "SEC 1: TARGET IDENTITY & ENVIRONMENT PROFILE",
    "SEC 2: 12-PILLAR DIAGNOSTIC & DEV-HEALTH MATRIX (AUTOMATED ANALYSIS)",
    "SEC 3: ACTIONABLE VULNERABILITY & DEV SLOTS",
    "SEC 4: USER SIGN-OFF & POLICY OVERRIDE FORM",
    "SEC 5: HMAC INTEGRITY STAMP",
    "SEC 6: HARDENING ACTIONS (ORDERED, COMMAND FIRST)",
)

# Identity rows as (attribute, display label) pairs. Renderers print the label,
# the JSON renderer derives its snake_case key from the same tuple, which is why
# the two documents stay aligned when a field is added.
IDENTITY_FIELDS: tuple[tuple[str, str], ...] = (
    ("target", "Target Name / Path"),
    ("os_label", "Host Operating System"),
    ("python_label", "Python Runtime Engine"),
    ("hardware_label", "Active Hardware Primitives"),
    ("timestamp_utc", "Scan Timestamp (UTC)"),
)


@dataclass(frozen=True, slots=True)
class DossierReport:
    """One immutable dossier snapshot ready to be rendered or persisted.

    Attributes:
        target: Absolute path of the scanned project root.
        os_label: Host operating system label from PlatformInfo.
        python_label: Interpreter label from PlatformInfo.
        hardware_label: Comma separated resolved primitive list.
        timestamp_utc: Generation time in ISO-8601 UTC form ending with Z.
        verdict: Aggregated verdict computed from the recorded findings.
        findings: Exactly twelve findings in ascending pillar order. Pillars
            that did not run are represented by an explicit placeholder finding
            whose detail says so, because silently hiding a missing probe would
            make the matrix look complete when it is not.
        scorecard: Bounded score with the grade, the deduction ledger and the
            recovery hint per pillar. The report can therefore state the ceiling
            and the reason for every lost point, which a bare risk number cannot.
        policy: Effective policy the dossier form is seeded from.
        repro_files: Names of synthesized repro scripts, relative to the target.
        hmac: HMAC-SHA256 hex digest over the report payload; empty only on the
            intermediate value built just before signing.
        generated_by: Producer signature embedded in every format.
        key_source: Origin of the signing key: machine, env or explicit. It is
            rendered in SEC 5 so a reader never mistakes a machine tie for a
            secret signature.
        signing_key: Key bytes used to sign this snapshot, kept only so the file
            trailer is stamped with the same key. It is excluded from repr and
            comparison and is never serialized into a dossier.
    """

    target: str
    os_label: str
    python_label: str
    hardware_label: str
    timestamp_utc: str
    verdict: Verdict
    findings: tuple[Finding, ...]
    scorecard: Scorecard
    policy: Policy
    repro_files: tuple[str, ...]
    hmac: str
    generated_by: str
    key_source: str = "machine"
    signing_key: bytes | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        """Reject snapshots that would render a misleading matrix.

        Raises:
            ValueError: When the findings are not exactly the twelve pillars in
                ascending order, or a scalar field has the wrong type.
        """

        if len(self.findings) != len(PILLAR_SPECS):
            raise ValueError(
                f"dossier needs {len(PILLAR_SPECS)} findings, got {len(self.findings)}"
            )
        expected = tuple(spec.number for spec in PILLAR_SPECS)
        observed = tuple(finding.pillar for finding in self.findings)
        if observed != expected:
            raise ValueError(f"findings must be ordered by pillar {expected}, got {observed}")
        for finding in self.findings:
            if not isinstance(finding, Finding):
                raise ValueError(f"finding for pillar {finding!r} is not a Finding")
        if not isinstance(self.verdict, Verdict):
            raise ValueError("verdict must be a Verdict instance")
        if not isinstance(self.scorecard, Scorecard):
            raise ValueError("scorecard must be a Scorecard instance")
        if not isinstance(self.policy, Policy):
            raise ValueError("policy must be a Policy instance")
        if not isinstance(self.repro_files, tuple):
            raise ValueError("repro_files must be a tuple of strings")
        if self.key_source not in KEY_SOURCES:
            raise ValueError(f"key_source must be one of {KEY_SOURCES}, got {self.key_source!r}")
        if self.signing_key is not None and not isinstance(self.signing_key, (bytes, bytearray)):
            raise ValueError("signing_key must be bytes or None")

    def finding(self, number: int) -> Finding:
        """Return the finding of one pillar.

        Raises:
            KeyError: When the pillar number is outside one through twelve.
        """

        if not 1 <= number <= len(self.findings):
            raise KeyError(f"unknown pillar {number}")
        return self.findings[number - 1]

    def pillar_rows(self) -> tuple[tuple[PillarSpec, Finding], ...]:
        """Return (spec, finding) pairs in pillar order for the renderers."""

        return tuple(zip(PILLAR_SPECS, self.findings))

    @property
    def hardening_actions(self) -> tuple[object, ...]:
        """Return the ordered hardening actions implied by this snapshot.

        The actions are derived from the frozen findings rather than stored, so a
        renderer can never show a stale plan and the snapshot stays small. The
        remediation module is optional: a checkout without it returns an empty
        tuple instead of failing the render.
        """

        try:
            from tauhaulity.remediation import actions_for
        except ImportError:
            return ()
        from types import SimpleNamespace

        holder = SimpleNamespace(findings={finding.pillar: finding for finding in self.findings})
        return tuple(actions_for(holder, self.scorecard))

    def repro_file_for(self, pillar: int) -> str:
        """Return the repro script name for a pillar, or an empty string.

        The synthesizer names scripts after the pillar number, so a prefix match
        keeps the lookup dependency free even when the caller passed extra files.
        """

        prefix = f"repro_slot_{pillar:02d}"
        for name in self.repro_files:
            if name.startswith(prefix):
                return name
        return ""

    def json_identity(self) -> dict[str, str]:
        """Return identity fields keyed by the snake_case JSON names.

        The keys are derived from IDENTITY_FIELDS so the Markdown labels and the
        JSON keys cannot drift apart unnoticed.
        """

        return {
            _json_key(label): str(getattr(self, attribute))
            for attribute, label in IDENTITY_FIELDS
        }


def _json_key(label: str) -> str:
    """Convert a display label into the stable snake_case JSON key."""

    cleaned = label.lower().replace("/", " ").replace("&", " ")
    tokens = [token for token in cleaned.replace("(", " ").replace(")", " ").split() if token]
    aliases = {
        "target name path": "target",
        "host operating system": "host_operating_system",
        "python runtime engine": "python_runtime_engine",
        "active hardware primitives": "active_hardware_primitives",
        "scan timestamp utc": "scan_timestamp_utc",
    }
    joined = " ".join(tokens)
    if joined in aliases:
        return aliases[joined]
    return joined.replace(" ", "_")
