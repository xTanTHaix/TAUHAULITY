"""Self diagnostic used by the doctor command.

The doctor answers one question: would a scan work on this machine right now,
and if not which capability is missing. It therefore checks imports, the native
engine backend, the pillar registry and write access instead of re-running the
twelve pillar probes.
"""

from __future__ import annotations

import importlib
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from tauhaulity.core.contracts import PILLAR_SPECS
from tauhaulity.core.platform_probe import detect_platform


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    """One self check row.

    Attributes:
        name: Short capability name.
        ok: True when the capability works.
        detail: Evidence or the exact failure reason.
    """

    name: str
    ok: bool
    detail: str


@dataclass(slots=True)
class DoctorReport:
    """Aggregate doctor output."""

    checks: list[DoctorCheck] = field(default_factory=list)
    platform_label: str = ""

    @property
    def ok(self) -> bool:
        """True when every check passed."""

        return all(check.ok for check in self.checks)

    def render(self) -> str:
        """Render the checks as fixed width text."""

        lines = [f"TAUHAULITY DOCTOR - {self.platform_label}", "-" * 72]
        for check in self.checks:
            marker = "PASS" if check.ok else "FAIL"
            lines.append(f"[{marker}] {check.name:<24} {check.detail}")
        lines.append("-" * 72)
        lines.append("result: " + ("healthy" if self.ok else "attention required"))
        return chr(10).join(lines)


def _check_import(module: str) -> DoctorCheck:
    try:
        importlib.import_module(module)
    except Exception as exc:
        return DoctorCheck(module, False, f"{type(exc).__name__}: {exc}")
    return DoctorCheck(module, True, "imports cleanly")


def run_doctor(root: str | Path = ".") -> DoctorReport:
    """Inspect the runtime and report every capability that a scan needs.

    Parameters:
        root: Project directory used for the write access check.

    Returns:
        DoctorReport with one row per capability.
    """

    info = detect_platform()
    report = DoctorReport(platform_label=f"{info.os_label} / {info.python_label}")
    report.checks.append(DoctorCheck("python", sys.version_info >= (3, 12), info.python_version))
    report.checks.append(DoctorCheck("platform_probe", True, info.os_label))
    try:
        from tauhaulity.primitives.loader import get_engine

        engine = get_engine()
        report.checks.append(DoctorCheck("native_engine", True, f"{engine.backend} {engine.version}"))
    except Exception as exc:
        report.checks.append(DoctorCheck("native_engine", False, f"{type(exc).__name__}: {exc}"))
    try:
        from tauhaulity.pillars import load_pillars

        probes = load_pillars(strict=False)
        report.checks.append(
            DoctorCheck("pillar_registry", len(probes) == len(PILLAR_SPECS), f"{len(probes)}/{len(PILLAR_SPECS)} pillars")
        )
    except Exception as exc:
        report.checks.append(DoctorCheck("pillar_registry", False, f"{type(exc).__name__}: {exc}"))
    for module in (
        "tauhaulity.dossier.report",
        "tauhaulity.tools.git_sentinel",
        "tauhaulity.tools.port_sweeper",
        "tauhaulity.tools.venv_radar",
        "tauhaulity.daemon.undo_store",
    ):
        report.checks.append(_check_import(module))
    try:
        from tauhaulity.daemon.undo_store import UndoStore

        store = UndoStore(Path(root))
        report.checks.append(DoctorCheck("undo_store", store.usage_bytes() >= 0, "readable journal"))
    except Exception as exc:
        report.checks.append(DoctorCheck("undo_store", False, f"{type(exc).__name__}: {exc}"))
    target = Path(root)
    writable = os.access(target, os.W_OK) if target.exists() else False
    report.checks.append(DoctorCheck("write_access", writable, str(target)))
    return report
