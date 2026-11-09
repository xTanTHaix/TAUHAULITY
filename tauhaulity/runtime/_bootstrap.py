"""Propagation shim that arms the guard inside Python children.

A PEP-578 hook only exists inside the process that installs it, so a worker or a
build step spawned with subprocess escapes containment completely. This module
materialises a tiny directory containing a sitecustomize.py shim; putting that
directory first on PYTHONPATH makes every Python child arm the same guard without
touching application code.

Design constraints that shape the shim:
- It must never break an interpreter. sitecustomize runs before application code,
  so every failure (missing tauhaulity install, broken policy value, import error)
  is swallowed: a broken guard must not turn into a broken build.
- It must be idempotent. The shim checks whether the guard is already active and
  returns without arming a second time, and the marker TAUHAULITY_GUARD_PROPAGATED
  prevents the parent from prefixing PYTHONPATH again.
- It must only arm when the environment asks for it: TAUHAULITY_ENFORCE or
  TAUHAULITY_GUARD_PROPAGATED must be truthy, and the flags are then read through
  the normal GuardPolicy.from_env() path so the child mirrors the parent policy.
- It writes nothing outside its own directory. The directory is created with a
  unique name (tempfile.mkdtemp) so two concurrent shields cannot collide.

Known escape hatches, documented rather than hidden: a child started with python -S
does not import site (no sitecustomize), a non-Python child (native binary, shell
script, Node process) never runs it, and a sitecustomize.py earlier on sys.path
(the script directory or cwd) takes precedence over the shim.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Final

__all__ = [
    "PROPAGATION_MARKER",
    "PropagationError",
    "SHIM_DIR_PREFIX",
    "SITECUSTOMIZE_SOURCE",
    "apply_env",
    "cleanup",
    "is_propagated",
    "materialise",
]

#: Environment marker that says "this environment already carries the shim".
#: guard_propagation() refuses to prepend PYTHONPATH a second time when it is set.
PROPAGATION_MARKER: Final[str] = "TAUHAULITY_GUARD_PROPAGATED"

#: Prefix of the unique shim directory created by tempfile.mkdtemp.
SHIM_DIR_PREFIX: Final[str] = "tauhaulity-guard-"

_TRUTHY: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})

#: The entire shim. Kept deliberately tiny and dependency free: it must import in
#: a bare interpreter even when tauhaulity itself is missing or broken.
SITECUSTOMIZE_SOURCE: Final[str] = '''"""Tauhaulity guard propagation shim (generated, safe to delete).

Arms tauhaulity.runtime.audit_hook inside this interpreter when the parent
process asked for propagation. Every failure is swallowed: a broken guard must
never stop a build step or a worker from running.
"""

import os


def _tauhaulity_arm_guard():
    try:
        enforce = os.environ.get("TAUHAULITY_ENFORCE", "").strip().lower()
        propagated = os.environ.get("TAUHAULITY_GUARD_PROPAGATED", "").strip().lower()
        wanted = {"1", "true", "yes", "on"}
        if enforce not in wanted and propagated not in wanted:
            return
        from tauhaulity.runtime import audit_hook

        guard = getattr(audit_hook, "guard", None)
        if guard is not None and getattr(guard, "active", False):
            return
        audit_hook.arm_shield(audit_hook.GuardPolicy.from_env())
    except Exception:
        return


_tauhaulity_arm_guard()
'''


class PropagationError(RuntimeError):
    """Raised when the propagation shim directory cannot be materialised."""


def materialise(directory: Path | None = None) -> Path:
    """Create the shim directory with a sitecustomize.py and return its path.

    Parameters:
        directory: Directory to use as the shim. When omitted a unique temporary
            directory is created with tempfile.mkdtemp, which is the concurrent
            safe default. A supplied directory is used as-is (the caller owns its
            uniqueness) and created when missing.

    Returns:
        The shim directory that must be put first on PYTHONPATH.

    Raises:
        PropagationError: When the directory or the shim file cannot be written.
    """

    try:
        if directory is None:
            target = Path(tempfile.mkdtemp(prefix=SHIM_DIR_PREFIX))
        else:
            target = Path(directory)
            target.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise PropagationError(f"cannot create shim directory: {type(exc).__name__}: {exc}") from exc
    shim = target / "sitecustomize.py"
    try:
        shim.write_text(SITECUSTOMIZE_SOURCE, encoding="utf-8", newline="\n")
    except OSError as exc:
        raise PropagationError(f"cannot write {shim}: {type(exc).__name__}: {exc}") from exc
    return target


def is_propagated(env: dict[str, str]) -> bool:
    """True when an environment already carries the propagation marker."""

    try:
        raw = env.get(PROPAGATION_MARKER, "")
    except (AttributeError, TypeError):
        return False
    return str(raw).strip().lower() in _TRUTHY


def apply_env(env: dict[str, str], shim: Path) -> dict[str, str]:
    """Return a copy of env with the shim first on PYTHONPATH and the marker set."""

    result = dict(env)
    result[PROPAGATION_MARKER] = "1"
    existing = result.get("PYTHONPATH", "")
    prefix = str(shim)
    result["PYTHONPATH"] = prefix + (os.pathsep + existing if existing else "")
    return result


def cleanup(directory: Path) -> bool:
    """Remove a shim directory created by materialise().

    Leaving the directory in place is harmless: it contains one small file and is
    only on the PYTHONPATH of children the caller spawned. Cleanup is offered so a
    long running embedding host can keep the temporary directory tidy.

    Returns:
        True when the directory existed and was removed, False otherwise.
    """

    target = Path(directory)
    try:
        if not target.exists():
            return False
        shutil.rmtree(target)
        return True
    except OSError:
        return False
