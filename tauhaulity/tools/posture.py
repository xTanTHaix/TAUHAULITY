"""Per-machine security posture: what protects this project right now.

The README states the threat classes this tool does not defend against. A
paragraph cannot be acted on, so this module turns that boundary into a
checklist for one machine and one project:

* protection: the controls that are live (git gate, interpreter guard, honeytoken
  decoys, executable memory baseline, undo journal, quarantine store, fresh
  threat-intelligence snapshots);
* exposure: the conditions that need attention (development ports bound to a
  wildcard address, .env files, credential candidates in the working tree, stale
  bytecode caches);
* outside: the five threat classes this tool cannot cover, each marked na with
  the companion control that can. These are informational and never count as a
  failure.

Every probe is cheap, offline and wrapped: a missing capability becomes a single
"missing" item with the reason, and the rest of the report survives. The bytecode
check is a bounded header comparison, not the full artifact scan, so the whole
report stays inside a small CPU budget. No probe reads a secret into the report:
credential candidates are counted, never printed.
"""

from __future__ import annotations

import importlib.util
import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

POSTURE_STATES: Final[frozenset[str]] = frozenset({"on", "off", "stale", "missing", "na", "risk"})
PROBLEM_STATES: Final[frozenset[str]] = frozenset({"off", "stale", "missing", "risk"})
SECTIONS: Final[tuple[str, ...]] = ("protection", "exposure", "outside")

_PYC_SKIP_DIRS: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        ".tooling",
        "node_modules",
        "build",
        "dist",
        "target",
        ".tox",
        ".nox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tauhaulity",
    }
)
_PYC_MAX_FILES: Final[int] = 2000
_PYC_MAX_DEPTH: Final[int] = 8
_PYC_MAX_SOURCE_BYTES: Final[int] = 256 * 1024
_PYC_HEADER_SIZE: Final[int] = 16
_PYC_HASH_FLAG: Final[int] = 0b01
_PYC_CHECK_SOURCE_FLAG: Final[int] = 0b10

_ENV_MAX_FILES: Final[int] = 2000
_ENV_MAX_DEPTH: Final[int] = 6
_ENV_MAX_LISTED: Final[int] = 5


@dataclass(frozen=True, slots=True)
class PostureItem:
    """One checklist line of the posture report.

    Attributes:
        section: protection, exposure or outside.
        name: Stable machine readable item name.
        state: on, off, stale, missing, na or risk.
        detail: One line evidence safe to render; never a secret value.
        action: Copy-pasteable next step, or the companion control for outside.
    """

    section: str
    name: str
    state: str
    detail: str
    action: str = ""

    def __post_init__(self) -> None:
        if self.state not in POSTURE_STATES:
            raise ValueError("unknown posture state: " + str(self.state))


@dataclass(frozen=True, slots=True)
class PostureReport:
    """Outcome of one posture check.

    Attributes:
        items: Checklist items in section order.
        score_hint: Short hint about how many applicable signals are active.
        detail: One line summary of the report.
    """

    items: tuple[PostureItem, ...]
    score_hint: str
    detail: str

    def by_section(self) -> dict[str, list[PostureItem]]:
        """Group items by section, preserving the documented section order."""

        grouped: dict[str, list[PostureItem]] = {section: [] for section in SECTIONS}
        for item in self.items:
            grouped.setdefault(item.section, []).append(item)
        return grouped

    def problems(self) -> list[PostureItem]:
        """Items that need attention; informational 'na' items never appear."""

        return [item for item in self.items if item.state in PROBLEM_STATES]


def _line(text: object, limit: int = 300) -> str:
    """Collapse arbitrary text to one printable ASCII line."""

    cleaned = "".join(char if 32 <= ord(char) < 127 else " " for char in str(text))
    return " ".join(cleaned.split())[:limit]


def _safe_item(
    section: str,
    name: str,
    action: str,
    probe_name: str,
    root: Path,
) -> PostureItem:
    """Run one probe, degrading a raised exception to a single missing item."""

    probe = globals().get(probe_name)
    if not callable(probe):
        return PostureItem(section, name, "missing", "probe is not available", action)
    try:
        return probe(root)  # type: ignore[operator]
    except Exception as exc:  # a broken capability must never break the report
        return PostureItem(
            section,
            name,
            "missing",
            "probe unavailable (" + type(exc).__name__ + ")",
            action,
        )


# --------------------------------------------------------------- protection


def _probe_hook(root: Path) -> PostureItem:
    """Report whether the git pre-commit gate is installed."""

    from tauhaulity.tools.hook_installer import hook_status

    installed, path = hook_status(root)
    if installed:
        return PostureItem(
            "protection",
            "pre_commit_hook",
            "on",
            "git pre-commit gate installed at " + _line(path, 160),
        )
    return PostureItem(
        "protection",
        "pre_commit_hook",
        "off",
        "no git pre-commit gate in this project",
        "tauhaulity hook install " + str(root),
    )


def _probe_guard(root: Path) -> PostureItem:
    """Report whether the interpreter guard is available and armed here."""

    supported = hasattr(sys, "addaudithook")
    if not supported:
        return PostureItem(
            "protection",
            "interpreter_guard",
            "missing",
            "this interpreter has no PEP-578 audit hooks",
            "run on CPython 3.8+ or rely on an EDR for kernel and memory threats",
        )
    try:
        from tauhaulity.runtime import audit_hook

        active = bool(audit_hook.active())
    except ImportError:
        return PostureItem(
            "protection",
            "interpreter_guard",
            "missing",
            "interpreter guard module is unavailable",
            "reinstall tauhaulity to restore tauhaulity.runtime.audit_hook",
        )
    if active:
        return PostureItem(
            "protection",
            "interpreter_guard",
            "on",
            "PEP-578 guard is armed in this process",
        )
    return PostureItem(
        "protection",
        "interpreter_guard",
        "off",
        "PEP-578 hook is available but not armed in this process",
        "tauhaulity shield -- <command> (or import tauhaulity in the guarded process)",
    )


def _probe_honeytokens(root: Path) -> PostureItem:
    """Report whether decoy credentials are deployed."""

    from tauhaulity.tools.honeytoken import list_tokens

    tokens = list_tokens(root)
    if tokens:
        kinds = ", ".join(sorted({token.kind for token in tokens}))
        return PostureItem(
            "protection",
            "honeytoken_decoys",
            "on",
            str(len(tokens)) + " decoy credential(s) deployed (" + kinds + ")",
        )
    return PostureItem(
        "protection",
        "honeytoken_decoys",
        "off",
        "no decoy credentials deployed",
        "tauhaulity honeytoken deploy " + str(root),
    )


def _probe_memory_baseline(root: Path) -> PostureItem:
    """Report whether an executable memory baseline was captured."""

    from tauhaulity.pillars.p01_memory import load_baseline_ex

    result = load_baseline_ex(root)
    if result.record is not None:
        record = result.record
        return PostureItem(
            "protection",
            "memory_baseline",
            "on",
            str(len(record.modules))
            + " executable module baseline(s) captured at "
            + _line(record.captured_at, 60),
        )
    if result.present:
        return PostureItem(
            "protection",
            "memory_baseline",
            "stale",
            "baseline file present but rejected: " + _line(result.reason, 120),
            "tauhaulity baseline --memory " + str(root),
        )
    return PostureItem(
        "protection",
        "memory_baseline",
        "off",
        "no executable memory baseline captured",
        "tauhaulity baseline --memory " + str(root),
    )


def _probe_undo_journal(root: Path) -> PostureItem:
    """Report whether the undo net has recorded anything."""

    from tauhaulity.daemon.undo_store import UndoStore

    entries = UndoStore(root).list_entries(limit=1)
    if entries:
        return PostureItem(
            "protection",
            "undo_journal",
            "on",
            "undo journal contains captured file(s)",
        )
    return PostureItem(
        "protection",
        "undo_journal",
        "off",
        "undo journal is empty",
        "delete through tauhaulity rm <path> to capture an undo entry first",
    )


def _probe_quarantine(root: Path) -> PostureItem:
    """Report whether any detected artifact was neutralised."""

    from tauhaulity.tools.quarantine import QuarantineStore

    store = QuarantineStore(root)
    items = store.list_items()
    if items:
        return PostureItem(
            "protection",
            "quarantine_store",
            "on",
            str(len(items)) + " artifact(s) quarantined, " + str(store.usage_bytes()) + " byte(s) stored",
        )
    return PostureItem(
        "protection",
        "quarantine_store",
        "off",
        "no artifact is quarantined",
        "tauhaulity quarantine list " + str(root),
    )


def _probe_feed(root: Path) -> PostureItem:
    """Report the age of the cached threat-intelligence snapshots."""

    from tauhaulity.tools import threat_feed

    status = threat_feed.status(root=root)
    ages = ", ".join(
        snapshot.kind + (" missing" if snapshot.age_days < 0 else f" {snapshot.age_days:.1f} day(s) old")
        for snapshot in status.snapshots
    )
    if not status.stale:
        return PostureItem("protection", "threat_feed", "on", "snapshots fresh: " + ages)
    state = "missing" if all(snapshot.age_days < 0 for snapshot in status.snapshots) else "stale"
    return PostureItem(
        "protection",
        "threat_feed",
        state,
        "snapshots: " + ages,
        "tauhaulity feed refresh",
    )


# ----------------------------------------------------------------- exposure


def _list_listening() -> list:
    """Return the kernel listening table through the shared port sweeper.

    Kept as a module level seam so a test can substitute a table without opening
    real sockets; the probe itself never re-implements socket enumeration.
    """

    from tauhaulity.tools.port_sweeper import list_listening

    return list_listening()


def _exposed_entries(entries: list) -> list:
    """Apply pillar nine's EXPOSURE_PORTS rule to a listening table.

    The rule lives in tauhaulity.pillars.p09_ports and is imported here instead of
    copied, so the posture report and the pillar can never drift apart.
    """

    from tauhaulity.pillars.p09_ports import _exposed

    return _exposed(entries)


def _probe_wildcard_ports(root: Path) -> PostureItem:
    """Report development ports bound to a wildcard address."""

    entries = _list_listening()
    exposed = _exposed_entries(entries)
    if not exposed:
        return PostureItem(
            "exposure",
            "wildcard_dev_ports",
            "on",
            "no development port is bound to a wildcard address",
        )
    labels = []
    for entry in exposed[:5]:
        port = getattr(entry, "local_port", getattr(entry, "port", "?"))
        address = getattr(entry, "local_address", "?")
        labels.append(str(port) + " on " + str(address))
    return PostureItem(
        "exposure",
        "wildcard_dev_ports",
        "risk",
        str(len(exposed)) + " development port(s) reachable from the network: " + ", ".join(labels),
        "bind the service to 127.0.0.1, or run: tauhaulity free <port>",
    )


def _probe_env_files(root: Path) -> PostureItem:
    """Report .env files present in the working tree (names only, never values)."""

    found: list[str] = []
    inspected = 0
    for current, dirs, names in os.walk(root):
        depth = len(Path(current).relative_to(root).parts)
        dirs[:] = sorted(name for name in dirs if name not in _PYC_SKIP_DIRS)
        if depth >= _ENV_MAX_DEPTH:
            dirs[:] = []
        for name in sorted(names):
            if inspected >= _ENV_MAX_FILES:
                break
            inspected += 1
            if name == ".env" or name.startswith(".env."):
                found.append(str(Path(current, name).relative_to(root).as_posix()))
    if found:
        listed = ", ".join(found[:_ENV_MAX_LISTED])
        return PostureItem(
            "exposure",
            "dotenv_files",
            "risk",
            str(len(found)) + " .env file(s) in the tree: " + listed,
            "move the values into the OS keychain, gitignore the file, and add it to the policy ignored paths",
        )
    return PostureItem(
        "exposure",
        "dotenv_files",
        "on",
        "no .env file in the working tree",
    )


def _inspect_working_tree(root: Path):
    """Scan the working tree for credential candidates through the shared sentinel."""

    from tauhaulity.tools.git_sentinel import inspect_repository

    return inspect_repository(root, check_hook=False, use_baseline=False, history=False)


def _probe_credentials(root: Path) -> PostureItem:
    """Count credential candidates in the working tree, masked and never printed."""

    report = _inspect_working_tree(root)
    count = len(report.secrets) + len(report.remote_credentials)
    if count:
        return PostureItem(
            "exposure",
            "working_tree_credentials",
            "risk",
            str(count)
            + " credential candidate(s) in "
            + str(report.scanned_files)
            + " scanned file(s) (masked; values are never printed)",
            "rotate the credential and remove it from the working tree; run tauhaulity baseline only for known fixtures",
        )
    return PostureItem(
        "exposure",
        "working_tree_credentials",
        "on",
        "no credential candidate in the working tree",
    )


def _inspect_pyc_source(path: Path) -> Path:
    """Resolve the source a compiled cache claims to be built from."""

    if path.parent.name != "__pycache__":
        return path.with_suffix(".py")
    stem = path.name[:-len(".pyc")] if path.name.endswith(".pyc") else path.stem
    tag = stem.rfind(".cpython-")
    if tag > 0:
        stem = stem[:tag]
    opt = stem.rfind(".opt-")
    if opt > 0:
        stem = stem[:opt]
    return path.parent.parent / (stem + ".py")


def _stale_bytecode(root: Path) -> tuple[int, int, bool]:
    """Return (stale_count, checked_count, truncated) with a bounded light walk."""

    stale = 0
    checked = 0
    truncated = False
    for current, dirs, names in os.walk(root):
        depth = len(Path(current).relative_to(root).parts)
        dirs[:] = sorted(name for name in dirs if name not in _PYC_SKIP_DIRS)
        if depth >= _PYC_MAX_DEPTH:
            dirs[:] = []
            truncated = True
        for name in sorted(names):
            if not name.endswith(".pyc"):
                continue
            if checked >= _PYC_MAX_FILES:
                truncated = True
                break
            checked += 1
            path = Path(current, name)
            try:
                with path.open("rb") as handle:
                    header = handle.read(_PYC_HEADER_SIZE)
            except OSError:
                continue
            if len(header) < _PYC_HEADER_SIZE:
                stale += 1
                continue
            magic = header[:4]
            expected = importlib.util.MAGIC_NUMBER
            cache_tag = ""
            stem = path.name[:-4] if path.name.endswith(".pyc") else path.name
            tag_index = stem.rfind(".cpython-")
            if tag_index > 0:
                cache_tag = stem[tag_index + 1 :]
            if (
                cache_tag
                and cache_tag != sys.implementation.cache_tag
                and magic != expected
                and magic != b"\x00\x00\x00\x00"
            ):
                continue
            if magic != expected:
                stale += 1
                continue
            flags = struct.unpack("<I", header[4:8])[0]
            source = _inspect_pyc_source(path)
            try:
                source_stat = source.stat()
            except OSError:
                stale += 1
                continue
            if flags & _PYC_HASH_FLAG:
                if not flags & _PYC_CHECK_SOURCE_FLAG:
                    continue
                if source_stat.st_size > _PYC_MAX_SOURCE_BYTES:
                    truncated = True
                    continue
                try:
                    source_bytes = source.read_bytes()
                except OSError:
                    stale += 1
                    continue
                if header[8:16] != importlib.util.source_hash(source_bytes):
                    stale += 1
                continue
            recorded_mtime, recorded_size = struct.unpack("<II", header[8:16])
            if recorded_size != source_stat.st_size:
                stale += 1
            elif recorded_mtime != int(source_stat.st_mtime):
                stale += 1
    return stale, checked, truncated


def _probe_stale_bytecode(root: Path) -> PostureItem:
    """Report stale compiled caches that the interpreter could still load."""

    stale, checked, truncated = _stale_bytecode(root)
    note = " (walk truncated at the posture budget)" if truncated else ""
    if stale:
        return PostureItem(
            "exposure",
            "stale_bytecode",
            "risk",
            str(stale) + " stale bytecode cache(s) in " + str(checked) + " inspected" + note,
            "delete the __pycache__ directories or recompile: python -m compileall -q " + str(root),
        )
    return PostureItem(
        "exposure",
        "stale_bytecode",
        "on",
        "no stale bytecode cache in " + str(checked) + " inspected" + note,
    )


# ------------------------------------------------------------------- outside


def _outside_item(name: str, detail: str, action: str) -> PostureItem:
    """Build one informational item for a threat class this tool cannot cover."""

    return PostureItem("outside", name, "na", detail, action)


def _outside_items() -> tuple[PostureItem, ...]:
    """Return the five threat classes outside this tool's coverage."""

    return (
        _outside_item(
            "edge_appliance_patching",
            "a compromised VPN, firewall or web appliance sits before the host",
            "track CISA KEV and vendor advisories, and patch edge appliances on a schedule",
        ),
        _outside_item(
            "kernel_and_memory_attacks",
            "kernel implants and direct memory attacks live below the interpreter",
            "deploy EDR with kernel telemetry and memory scanning",
        ),
        _outside_item(
            "cloud_misconfiguration",
            "cloud IAM and storage posture is outside a developer project",
            "run a cloud posture scanner (CSPM) against the account",
        ),
        _outside_item(
            "phishing_and_credential_theft",
            "a phished session token bypasses every local control",
            "enforce MFA and use a password manager with origin binding",
        ),
        _outside_item(
            "network_segmentation",
            "a flat network lets an exposed service reach everything else",
            "segment networks and apply zero-trust egress rules",
        ),
    )


def _probe_specs(root: Path) -> tuple[tuple[str, str, str, str], ...]:
    """Return (section, name, fallback action, probe function name) rows."""

    return (
        ("protection", "pre_commit_hook", "tauhaulity hook install " + str(root), "_probe_hook"),
        ("protection", "interpreter_guard", "tauhaulity shield -- <command>", "_probe_guard"),
        ("protection", "honeytoken_decoys", "tauhaulity honeytoken deploy " + str(root), "_probe_honeytokens"),
        ("protection", "memory_baseline", "tauhaulity baseline --memory " + str(root), "_probe_memory_baseline"),
        ("protection", "undo_journal", "delete through tauhaulity rm <path>", "_probe_undo_journal"),
        ("protection", "quarantine_store", "tauhaulity quarantine list " + str(root), "_probe_quarantine"),
        ("protection", "threat_feed", "tauhaulity feed refresh", "_probe_feed"),
        ("exposure", "wildcard_dev_ports", "bind services to 127.0.0.1", "_probe_wildcard_ports"),
        ("exposure", "dotenv_files", "move secrets out of the tree", "_probe_env_files"),
        (
            "exposure",
            "working_tree_credentials",
            "rotate and remove the credential candidate",
            "_probe_credentials",
        ),
        ("exposure", "stale_bytecode", "delete stale __pycache__ directories", "_probe_stale_bytecode"),
    )


def posture(root: Path) -> PostureReport:
    """Build the offline posture checklist for one machine and one project.

    Parameters:
        root: Project root to inspect.

    Returns:
        A PostureReport whose items are ordered protection, exposure, outside.
        Every probe is wrapped: a broken or missing capability becomes one
        missing item and never raises.
    """

    root_path = Path(root)
    items: list[PostureItem] = []
    for section, name, action, probe_name in _probe_specs(root_path):
        items.append(_safe_item(section, name, action, probe_name, root_path))
    items.extend(_outside_items())
    report_items = tuple(items)
    on_count = sum(1 for item in report_items if item.state == "on")
    problem_count = sum(1 for item in report_items if item.state in PROBLEM_STATES)
    applicable = on_count + problem_count
    outside_count = sum(1 for item in report_items if item.state == "na")
    percent = int(round(100.0 * on_count / applicable)) if applicable else 0
    score_hint = (
        f"{on_count}/{applicable} applicable signal(s) active ({percent}%); "
        f"{problem_count} need attention; {outside_count} outside scope"
    )
    states = {state: 0 for state in POSTURE_STATES}
    for item in report_items:
        states[item.state] += 1
    detail = (
        f"posture for {root_path}: {states['on']} on, {states['off']} off, "
        f"{states['stale']} stale, {states['missing']} missing, {states['risk']} risk, "
        f"{states['na']} outside scope"
    )
    return PostureReport(items=report_items, score_hint=score_hint, detail=detail)


def render_text(report: PostureReport) -> str:
    """Render the report as readable text for the CLI."""

    lines = ["POSTURE", report.detail, "hint: " + report.score_hint]
    grouped = report.by_section()
    for section in SECTIONS:
        items = grouped.get(section, [])
        if not items:
            continue
        lines.append("")
        lines.append("[" + section + "]")
        for item in items:
            lines.append("  [" + item.state.upper() + "] " + item.name + ": " + item.detail)
            if item.action:
                lines.append("         action: " + item.action)
    return chr(10).join(lines)


def as_dict(report: PostureReport) -> dict[str, object]:
    """Render the report as a JSON friendly mapping for the CLI."""

    sections: dict[str, list[dict[str, str]]] = {}
    for section, items in report.by_section().items():
        sections[section] = [
            {
                "name": item.name,
                "state": item.state,
                "detail": item.detail,
                "action": item.action,
            }
            for item in items
        ]
    return {
        "detail": report.detail,
        "score_hint": report.score_hint,
        "sections": sections,
    }
