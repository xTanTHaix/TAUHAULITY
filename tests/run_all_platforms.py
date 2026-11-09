"""Run the Tauhaulity test suite across every interpreter and platform available.

CI for a dual-engine, dual-OS project cannot be a single pytest invocation: the
matrix required by the blueprint covers CPython 3.12 through 3.15 on Windows
Native plus WSL Ubuntu and WSL Debian. This runner discovers what actually
exists on the host, reports what is missing instead of pretending it ran, and
exits non-zero when any reachable platform fails.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

KNOWN_INTERPRETERS: tuple[tuple[str, str], ...] = (
    ("windows-3.12", sys.executable),
    ("windows-3.13", r".tooling\py313\Scripts\python.exe"),
    ("windows-3.14", r".tooling\py314\Scripts\python.exe"),
    ("windows-3.15", r"L:\.Python315\python.exe"),
    ("windows-3.13t", r".tooling\py313t\Scripts\python.exe"),
    ("windows-3.14t", r".tooling\py314t\Scripts\python.exe"),
    ("windows-3.15t", r".tooling\py315t\Scripts\python.exe"),
)


@dataclass(frozen=True, slots=True)
class PlatformTarget:
    """One entry of the test matrix.

    Attributes:
        name: Human readable matrix label.
        command: Command prefix used to run Python on that platform.
        available: True when the interpreter answered and has pytest.
        reason: Why the target is unavailable, when it is.
    """

    name: str
    command: tuple[str, ...]
    available: bool
    reason: str = ""


@dataclass(slots=True)
class RunOutcome:
    """Result of one platform test run."""

    target: PlatformTarget
    returncode: int
    output: str

    @property
    def passed(self) -> bool:
        """True when pytest exited cleanly."""

        return self.returncode == 0


# Interpreter identity is part of the result: two builds of the same minor
# version can classify the process memory map differently, so a row that only
# says "3.15" is not reproducible. The probe records the exact version string,
# the GIL state, and whether a JIT is present and enabled.
GIL_PROBE = (
    "import pytest, sys, sysconfig; "
    "jit = getattr(sys, '_jit', None); "
    "enabled = getattr(jit, 'is_enabled', None); "
    "print('py=' + sys.version.split()[0], "
    "'gil=' + str(getattr(sys, '_is_gil_enabled', lambda: True)()), "
    "'build=' + str(sysconfig.get_config_var('Py_GIL_DISABLED')), "
    "'jit=' + ('present' if jit is not None else 'absent') + '/' + (str(bool(enabled())) if callable(enabled) else 'n/a'), "
    "'exe=' + sys.executable)"
)


def _probe(command: tuple[str, ...]) -> tuple[bool, str]:
    """Return whether the interpreter exists, can import pytest, and its identity.

    The identity string carries the version and the GIL state because a matrix
    label such as "windows-3.14" must never hide whether the leg actually ran a
    free-threaded build.
    """

    try:
        completed = subprocess.run(
            [*command, "-c", GIL_PROBE],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"{type(exc).__name__}: {exc}"
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout).strip().splitlines()
        return False, message[-1] if message else f"exit {completed.returncode}"
    return True, completed.stdout.strip()


def discover_windows_targets() -> list[PlatformTarget]:
    """Probe the known Windows interpreters plus any path in TAUHAULITY_PYTHONS.

    Returns:
        One PlatformTarget per candidate, including the unavailable ones so the
        report shows the missing legs instead of silently shrinking the matrix.
    """

    candidates: list[tuple[str, str]] = [("windows-current", sys.executable)]
    candidates.extend(KNOWN_INTERPRETERS)
    extra = os.environ.get("TAUHAULITY_PYTHONS", "")
    for index, raw in enumerate(part for part in extra.split(os.pathsep) if part.strip()):
        candidates.append((f"env-{index}", raw))
    targets: list[PlatformTarget] = []
    removed_duplicates: set[str] = set()
    for name, raw_path in candidates:
        path = Path(raw_path)
        if not path.is_absolute():
            path = ROOT / path
        key = str(path).lower()
        if key in removed_duplicates:
            continue
        removed_duplicates.add(key)
        if not path.is_file():
            targets.append(PlatformTarget(name, (str(path),), False, "interpreter not found"))
            continue
        command = (str(path),)
        available, identity = _probe(command)
        targets.append(
            PlatformTarget(name, command, available, f"skipped: {identity}" if not available else identity)
        )
    return targets


def discover_wsl_targets() -> list[PlatformTarget]:
    """Probe WSL distributions for a Linux pytest interpreter.

    The WSL path is derived from the repository location so the runner works
    regardless of where the checkout lives on the Windows drive.
    """

    wsl = shutil.which("wsl")
    if wsl is None:
        return [PlatformTarget("wsl", ("wsl.exe",), False, "wsl.exe not found")]
    targets: list[PlatformTarget] = []
    for distro in ("Ubuntu", "Debian"):
        command = ("wsl.exe", "-d", distro, "--", "bash", "-lc", f"cd {wsl_path(ROOT)} && python3 -m pytest -q")
        probe = ("wsl.exe", "-d", distro, "--", "bash", "-lc", "python3 -m pytest --version")
        try:
            completed = subprocess.run(list(probe), capture_output=True, text=True, timeout=120)
        except (OSError, subprocess.TimeoutExpired) as exc:
            targets.append(PlatformTarget(f"wsl-{distro.lower()}", command, False, f"{type(exc).__name__}: {exc}"))
            continue
        available = completed.returncode == 0
        reason = "" if available else (completed.stderr or completed.stdout).strip().splitlines()[-1:]
        targets.append(
            PlatformTarget(
                f"wsl-{distro.lower()}",
                command,
                available,
                "" if available else str(reason),
            )
        )
    return targets


def wsl_path(path: Path) -> str:
    """Translate a Windows path into its WSL mount form."""

    raw = str(path)
    drive, _, rest = raw.partition(":")
    if len(drive) == 1 and rest:
        return f"/mnt/{drive.lower()}{rest.replace(chr(92), '/')}"
    return raw.replace(chr(92), "/")


def run_target(target: PlatformTarget, extra_args: list[str]) -> RunOutcome:
    """Execute pytest for one matrix entry and capture its output."""

    command = [*target.command, "-m", "pytest", *extra_args] if target.name.startswith("windows") or target.name.startswith("env") else [*target.command]
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=1800, cwd=str(ROOT))
    except (OSError, subprocess.TimeoutExpired) as exc:
        return RunOutcome(target, 127, f"{type(exc).__name__}: {exc}")
    output = (completed.stdout or "") + (completed.stderr or "")
    return RunOutcome(target, completed.returncode, output.strip())


def main(argv: list[str] | None = None) -> int:
    """Run the matrix and print a compact report.

    Returns:
        Zero when every available target passed, one when a leg failed.
    """

    parser = argparse.ArgumentParser(description="Run the Tauhaulity suite across the platform matrix.")
    parser.add_argument("--json", action="store_true", help="emit a machine readable report")
    parser.add_argument("--include-wsl", action="store_true", help="also run the suite inside WSL Ubuntu and Debian")
    parser.add_argument("--tests", default="tests", help="pytest path to run")
    parser.add_argument("extra", nargs="*", help="extra arguments forwarded to pytest")
    args = parser.parse_args(argv)

    targets = discover_windows_targets()
    if args.include_wsl:
        targets.extend(discover_wsl_targets())

    extra_args = [args.tests, *args.extra]
    outcomes: list[RunOutcome] = []
    for target in targets:
        if not target.available:
            outcomes.append(RunOutcome(target, 0, target.reason))
            continue
        outcome = run_target(target, extra_args)
        outcomes.append(outcome)

    if args.json:
        print(
            json.dumps(
                [
                    {
                        "platform": outcome.target.name,
                        "interpreter": outcome.target.reason,
                        "available": outcome.target.available,
                        "returncode": outcome.returncode,
                        "tail": outcome.output.splitlines()[-1] if outcome.output else "",
                    }
                    for outcome in outcomes
                ],
                indent=2,
            )
        )
    else:
        for outcome in outcomes:
            if not outcome.target.available:
                print(f"[SKIP] {outcome.target.name:<16} {outcome.output}")
                continue
            marker = "PASS" if outcome.passed else "FAIL"
            tail = outcome.output.splitlines()[-1] if outcome.output else ""
            print(f"[{marker}] {outcome.target.name:<16} {tail}")

    available = [outcome for outcome in outcomes if outcome.target.available]
    if not available:
        print("no available platform target ran the suite", file=sys.stderr)
        return 1
    return 0 if all(outcome.passed for outcome in available) else 1


if __name__ == "__main__":
    sys.exit(main())
