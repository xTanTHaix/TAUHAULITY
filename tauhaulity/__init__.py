"""Tauhaulity - daily developer security utility with a 12-pillar diagnostic core.

Importing this package installs the interpreter level guard in watch mode unless
the environment variable TAUHAULITY_NO_AUTO is set. Watch mode only records
audited events into a bounded ring, so importing the package never changes the
behaviour of the host application. Enforcement requires an explicit policy opt
in (TAUHAULITY_ENFORCE=1 or the policy file written by the apply command),
because a silently blocking audit hook inside an unrelated application is a
defect, not a feature.
"""

from __future__ import annotations

import os
from pathlib import Path

__version__ = "0.4.0"
__all__ = ["__version__", "activate", "deactivate", "is_active", "GUARD"]

GUARD: object | None = None
_active: bool = False
_enforced: bool = False


def activate(*, enforce: bool | None = None, root: Path | None = None) -> bool:
    """Install the Tauhaulity runtime guard for the current interpreter.

    Parameters
    ----------
    enforce:
        True blocks policy violations, False only records them. When omitted the
        environment variables TAUHAULITY_ENFORCE decide, and the default is
        watch mode.
    root:
        Project root used to resolve the policy file. Defaults to the process
        working directory.

    Returns
    -------
    bool
        True when the guard is active after the call.

    Raises
    ------
    None
        Import failures of the runtime layer are reported as False so that a
        partially installed package never breaks the host program.
    """

    global GUARD, _active, _enforced

    if enforce is None:
        raw = os.environ.get("TAUHAULITY_ENFORCE", "").strip().lower()
        enforce = raw in {"1", "true", "yes", "on"}

    try:
        from tauhaulity.runtime.audit_hook import guard
    except ImportError:
        return False

    try:
        guard.install(enforce=bool(enforce), root=root)
    except (RuntimeError, OSError):
        return False

    GUARD = guard
    _active = True
    _enforced = bool(enforce)
    return True


def deactivate() -> bool:
    """Detach the guard from the interpreter.

    A CPython audit hook cannot be removed once added, so deactivation flips the
    guard into a dormant state where every event is ignored. This keeps repeated
    test runs from accumulating state instead of pretending the hook is gone.

    Returns
    -------
    bool
        True when a guard was present and has been put to sleep.
    """

    global _active, _enforced

    if not _active or GUARD is None:
        return False

    stop = getattr(GUARD, "deactivate", None)
    if callable(stop):
        stop()
    _active = False
    _enforced = False
    return True


def is_active() -> bool:
    """Report whether the guard is currently installed and awake."""

    return _active


def _auto_activate() -> None:
    """Arm watch mode on import unless the host opted out or asked for enforce."""

    if os.environ.get("TAUHAULITY_NO_AUTO", "").strip().lower() in {"1", "true", "yes"}:
        return
    activate()


_auto_activate()
