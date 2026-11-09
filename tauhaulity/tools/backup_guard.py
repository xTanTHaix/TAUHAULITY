"""Early warning for backup destruction, the step before ransomware encrypts.

Modern ransomware deletes shadow copies and disables recovery before it touches
user data, because a victim who can restore does not pay. Those commands are
specific, they run before the damage, and a user space tool can recognise their
shape from a process command line. That makes them the highest value early
warning available without an OS driver.

Two design rules keep this signal usable:

  * classification is token based and case insensitive. Joining the command line
    into one string and searching for substrings would let quoting, multiple
    spaces or a wrapper shell hide the shape, and would also fire on a README.
  * the module never raises and never acts. inspect_command() returns None for
    anything it does not recognise, restore_points_present() only runs documented
    read-only commands, and nothing here writes, elevates or blocks.

The optional attach_to_guard() observer installs its own audit hook callback for
"subprocess.Popen", records a bounded ring of recognised signals and hands them
to the caller's recorder. It is dependency free and stays off until called.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import sys
from collections import deque
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Final

SHADOW_DELETE: Final[str] = "shadow_delete"
BACKUP_DELETE: Final[str] = "backup_delete"
RECOVERY_DISABLE: Final[str] = "recovery_disable"
RESTORE_POINT_QUERY: Final[str] = "restore_point_query"
UNKNOWN: Final[str] = "unknown"

SIGNAL_KINDS: Final[tuple[str, ...]] = (
    SHADOW_DELETE,
    BACKUP_DELETE,
    RECOVERY_DISABLE,
    RESTORE_POINT_QUERY,
    UNKNOWN,
)

#: Signals retained by the observer; older ones are dropped, never written.
SIGNAL_RING_SIZE: Final[int] = 64

#: How long a read-only restore point probe may take before it reports unknown.
RESTORE_PROBE_TIMEOUT_S: Final[float] = 5.0

_SHELLS: Final[frozenset[str]] = frozenset(
    {"sh", "bash", "dash", "zsh", "ksh", "cmd", "powershell", "pwsh"}
)

#: Unit name fragments of common backup services on Linux.
_BACKUP_UNIT_MARKERS: Final[tuple[str, ...]] = (
    "backup",
    "restic",
    "borg",
    "duplicati",
    "urbackup",
    "veeam",
    "veem",
    "acronis",
    "bacula",
    "amanda",
    "rclone",
    "duplicity",
    "timeshift",
    "snapper",
    "shadowprotect",
)

#: Directory components that identify a snapshot store on POSIX hosts.
_SNAPSHOT_COMPONENTS: Final[frozenset[str]] = frozenset(
    {"snapshot", "snapshots", ".snapshot", "@snapshot", "@snapshots", ".snapshots"}
)

_WRITE_VERBS: Final[frozenset[str]] = frozenset({"stop", "disable", "mask", "kill"})

_MAX_TOKENS: Final[int] = 64
_MAX_TOKEN_CHARS: Final[int] = 512
_MAX_COMMAND_CHARS: Final[int] = 200
_MAX_SHELL_DEPTH: Final[int] = 2


class BackupGuardError(RuntimeError):
    """Raised for a programming error, never for an unrecognised command."""


@dataclass(frozen=True, slots=True)
class BackupSignal:
    """One command line shaped like backup or recovery destruction.

    Attributes:
        kind: shadow_delete, backup_delete, recovery_disable,
            restore_point_query or unknown.
        command: Normalized command line, bounded, suitable for a report.
        severity: high for deletion, medium for disabling, low for reconnaissance.
        detail: One sentence naming the shape that matched.
    """

    kind: str
    command: str
    severity: str
    detail: str


#: Signals observed by attach_to_guard(), oldest first, bounded.
_SIGNALS: deque[BackupSignal] = deque(maxlen=SIGNAL_RING_SIZE)
_HOOK_INSTALLED = False
#: True while this module runs its own read-only probe, so the observer does not
#: classify its own diagnostic commands as attacker activity.
_PROBING = False


def _decode(value: object) -> str | None:
    """Return text for bytes or a string like object, None for anything else."""

    if isinstance(value, bytes):
        try:
            return value.decode(sys.getfilesystemencoding(), "replace")
        except (UnicodeDecodeError, LookupError):
            return None
    if isinstance(value, str):
        return value
    try:
        raw = os.fspath(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if isinstance(raw, bytes):
        try:
            return raw.decode(sys.getfilesystemencoding(), "replace")
        except (UnicodeDecodeError, LookupError):
            return None
    return str(raw)


def _basename(token: str) -> str:
    """Return the lowercased executable name without a directory or suffix."""

    normalized = token.replace(chr(92), "/").rsplit("/", 1)[-1].strip().lower()
    if normalized.endswith(".exe"):
        normalized = normalized[:-4]
    return normalized


def _tokenize(text: str) -> list[str]:
    """Split a shell command string without ever raising."""

    if not text:
        return []
    try:
        parts = shlex.split(text, posix=(os.name != "nt"))
    except ValueError:
        parts = text.split()
    result: list[str] = []
    for part in parts[:_MAX_TOKENS]:
        clipped = part[:_MAX_TOKEN_CHARS]
        if clipped:
            result.append(clipped)
    return result


def _coerce_argv(argv: object) -> list[str]:
    """Normalize any argv-like value into a bounded list of tokens.

    A plain string is tokenized as a command line; a sequence is taken token by
    token. Unusable input (None, integers, nested lists) yields an empty list so
    the caller simply reports no signal instead of raising.
    """

    if argv is None:
        return []
    if isinstance(argv, (str, bytes)):
        text = _decode(argv)
        return _tokenize(text) if text is not None else []
    try:
        items = list(argv)  # type: ignore[arg-type]
    except TypeError:
        return []
    tokens: list[str] = []
    for item in items[:_MAX_TOKENS]:
        text = _decode(item)
        if text is None:
            return []
        clipped = text[:_MAX_TOKEN_CHARS]
        if clipped:
            tokens.append(clipped)
    return tokens


def _signal(kind: str, tokens: Sequence[str], severity: str, detail: str) -> BackupSignal:
    """Build a bounded signal; the command is the normalized token list."""

    return BackupSignal(
        kind=kind,
        command=" ".join(tokens)[:_MAX_COMMAND_CHARS],
        severity=severity,
        detail=detail,
    )


def _is_snapshot_path(token: str) -> bool:
    """True when a path names a snapshot directory entry."""

    normalized = token.replace(chr(92), "/").lower()
    parts = [part for part in normalized.split("/") if part and part not in {".", ".."}]
    if not parts:
        return False
    return any(part in _SNAPSHOT_COMPONENTS for part in parts)


def _tokens_lower(tokens: Sequence[str]) -> list[str]:
    """Return the argument tokens in lowercase, keeping their order."""

    return [token.lower() for token in tokens[1:]]


def _classify(tokens: Sequence[str]) -> BackupSignal | None:
    """Classify a normalized argv against the destructive command shapes."""

    executable = _basename(tokens[0])
    args = _tokens_lower(tokens)
    joined = " ".join(args)

    if executable == "vssadmin":
        if "delete" in args and ("shadows" in args or "shadow" in args):
            return _signal(
                SHADOW_DELETE, tokens, "high", "volume shadow copy deletion (vssadmin delete shadows)"
            )
        if "list" in args and ("shadows" in args or "shadowstorage" in args):
            return _signal(
                RESTORE_POINT_QUERY,
                tokens,
                "low",
                "shadow copy enumeration before an attack (vssadmin list shadows)",
            )
        return None

    if executable == "wmic":
        if "shadowcopy" in joined and "delete" in args:
            return _signal(
                SHADOW_DELETE,
                tokens,
                "high",
                "volume shadow copy deletion (wmic shadowcopy delete)",
            )
        if "shadowcopy" in joined and "list" in args:
            return _signal(
                RESTORE_POINT_QUERY, tokens, "low", "shadow copy enumeration (wmic shadowcopy list)"
            )
        return None

    if executable == "wbadmin":
        if "delete" in args and "catalog" in args:
            return _signal(
                BACKUP_DELETE, tokens, "high", "Windows backup catalog deletion (wbadmin delete catalog)"
            )
        if "delete" in args and "systemstatebackup" in joined:
            return _signal(
                BACKUP_DELETE,
                tokens,
                "high",
                "Windows system state backup deletion (wbadmin delete systemstatebackup)",
            )
        return None

    if executable == "bcdedit":
        if "recoveryenabled" in joined and "no" in args:
            return _signal(
                RECOVERY_DISABLE,
                tokens,
                "high",
                "Windows recovery disabled (bcdedit recoveryenabled no)",
            )
        if "bootstatuspolicy" in joined and "ignoreallfailures" in joined:
            return _signal(
                RECOVERY_DISABLE,
                tokens,
                "high",
                "boot failure recovery suppressed (bcdedit bootstatuspolicy ignoreallfailures)",
            )
        return None

    if executable == "wevtutil":
        if "cl" in args or "clearlog" in args:
            return _signal(
                RECOVERY_DISABLE,
                tokens,
                "medium",
                "event log clearing, a common precondition for destroying backups (wevtutil cl)",
            )
        return None

    if executable in {"rm", "unlink", "del", "erase"}:
        for token in args:
            if token.startswith("-"):
                continue
            if _is_snapshot_path(token):
                return _signal(
                    BACKUP_DELETE,
                    tokens,
                    "high",
                    "deletion of a snapshot directory (" + executable + " of a snapshot path)",
                )
        return None

    if executable == "lvremove":
        return _signal(
            BACKUP_DELETE,
            tokens,
            "high",
            "LVM logical volume removal, which destroys its snapshot (lvremove)",
        )

    if executable == "zfs":
        if "destroy" in args:
            return _signal(
                BACKUP_DELETE, tokens, "high", "ZFS dataset or snapshot destruction (zfs destroy)"
            )
        if "list" in args and ("-t" in args or "snapshot" in args):
            return _signal(
                RESTORE_POINT_QUERY, tokens, "low", "ZFS snapshot enumeration (zfs list -t snapshot)"
            )
        return None

    if executable == "btrfs":
        if "subvolume" in joined and "delete" in args:
            return _signal(
                BACKUP_DELETE,
                tokens,
                "high",
                "Btrfs subvolume deletion, which removes snapshots (btrfs subvolume delete)",
            )
        return None

    if executable == "systemctl":
        if args and args[0] in _WRITE_VERBS:
            if any(marker in joined for marker in _BACKUP_UNIT_MARKERS):
                return _signal(
                    RECOVERY_DISABLE,
                    tokens,
                    "high",
                    "backup service disabled (systemctl " + args[0] + " of a backup unit)",
                )
        return None

    return None


def _inner_shell_command(tokens: Sequence[str]) -> list[str]:
    """Return the command a wrapper shell would run, or an empty list.

    Only literal -c, /c and -Command forms are unwrapped. An encoded PowerShell
    command is deliberately ignored: decoding and executing it here would be an
    evasion surface of its own, and the guard already records the spawn event.
    """

    if _basename(tokens[0]) not in _SHELLS:
        return []
    for index, token in enumerate(tokens[1:], start=1):
        lowered = token.lower()
        if lowered in {"-c", "/c", "-command"}:
            remainder = tokens[index + 1 :]
            if not remainder:
                return []
            return _tokenize(" ".join(remainder))
        if lowered in {"-encodedcommand", "/encodedcommand"}:
            return []
    return []


def inspect_command(argv: object, _depth: int = 0) -> BackupSignal | None:
    """Classify one process command line against the known destructive shapes.

    Parameters:
        argv: Executable and arguments, as a sequence of strings or one command
            line string. Bytes, empty input, a single token or a malformed value
            all yield None instead of raising.

    Returns:
        A BackupSignal when the shape matches, otherwise None.
    """

    if _depth > _MAX_SHELL_DEPTH:
        return None
    tokens = _coerce_argv(argv)
    if len(tokens) < 2:
        # Every known destructive shape needs at least one argument, so a single
        # token cannot confirm it.
        return None
    signal = _classify(tokens)
    if signal is not None:
        return signal
    inner = _inner_shell_command(tokens)
    if inner:
        return inspect_command(inner, _depth + 1)
    return None


def _run_readonly(args: Sequence[str]) -> tuple[int, str] | None:
    """Run a documented read-only command, returning (code, output) or None."""

    global _PROBING
    _PROBING = True
    try:
        completed = subprocess.run(
            list(args),
            capture_output=True,
            timeout=RESTORE_PROBE_TIMEOUT_S,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    finally:
        _PROBING = False
    stdout = completed.stdout or b""
    stderr = completed.stderr or b""
    text = (stdout + b"\n" + stderr).decode(sys.getfilesystemencoding(), "replace")
    return int(completed.returncode), text


def _first_line(text: str, limit: int = 120) -> str:
    """Return the most informative line of command output, bounded.

    Error and denial lines come first because a tool banner is not an answer; the
    first non-empty line is the fallback for any other output shape.
    """

    lines = [line.strip() for line in text.splitlines() if line.strip()]
    for line in lines:
        lowered = line.lower()
        if "error" in lowered or "denied" in lowered or "access" in lowered:
            return line[:limit]
    return lines[0][:limit] if lines else ""


def _windows_restore_points() -> tuple[bool | None, str]:
    """Read shadow copy state through vssadmin, which is read-only."""

    executable = shutil.which("vssadmin")
    if executable is None:
        return None, "vssadmin is not available on this host"
    result = _run_readonly([executable, "list", "shadows"])
    if result is None:
        return None, "vssadmin did not answer within the probe timeout"
    code, text = result
    lowered = text.lower()
    if "no items found" in lowered or "no shadow copies" in lowered:
        return False, "vssadmin reports no shadow copies"
    if "shadow copy id" in lowered or "shadow copy creation time" in lowered:
        return True, "vssadmin reports at least one shadow copy"
    if code != 0:
        return None, "vssadmin could not answer: " + _first_line(text)
    return None, "vssadmin output was not recognised"


def _posix_restore_points() -> tuple[bool | None, str]:
    """Probe LVM, ZFS and Btrfs snapshots through their read-only list commands."""

    lvs = shutil.which("lvs")
    if lvs is not None:
        result = _run_readonly([lvs, "--noheadings", "-o", "lv_name,lv_attr"])
        if result is None:
            return None, "lvs did not answer within the probe timeout"
        code, text = result
        if code != 0:
            return None, "lvs could not answer: " + _first_line(text)
        snapshots = 0
        for line in text.splitlines():
            fields = line.split()
            if len(fields) >= 2 and fields[1][:1].lower() == "s":
                snapshots += 1
        if snapshots:
            return True, "lvs reports " + str(snapshots) + " LVM snapshot(s)"
        return False, "lvs reports no LVM snapshot"

    zfs = shutil.which("zfs")
    if zfs is not None:
        result = _run_readonly([zfs, "list", "-H", "-t", "snapshot"])
        if result is None:
            return None, "zfs did not answer within the probe timeout"
        code, text = result
        if code != 0:
            return None, "zfs could not answer: " + _first_line(text)
        lines = [line for line in text.splitlines() if line.strip()]
        if lines:
            return True, "zfs reports " + str(len(lines)) + " snapshot(s)"
        return False, "zfs reports no snapshot"

    btrfs = shutil.which("btrfs")
    if btrfs is not None:
        result = _run_readonly([btrfs, "subvolume", "list", "/"])
        if result is None:
            return None, "btrfs did not answer within the probe timeout"
        code, text = result
        if code != 0:
            return None, "btrfs could not answer: " + _first_line(text)
        named = [
            line
            for line in text.splitlines()
            if "snapshot" in line.lower() or "snap" in line.lower()
        ]
        if named:
            return True, "btrfs reports " + str(len(named)) + " snapshot-like subvolume(s)"
        return None, "btrfs subvolumes exist but a snapshot cannot be distinguished"

    return None, "no snapshot tool (lvs, zfs, btrfs) is available on this host"


@lru_cache(maxsize=1)
def _restore_points_cached() -> tuple[bool | None, str]:
    """Cached platform probe behind restore_points_present()."""

    if os.name == "nt":
        return _windows_restore_points()
    return _posix_restore_points()


def restore_points_present() -> tuple[bool | None, str]:
    """Report whether the host still has restore points or snapshots.

    The answer is a best-effort, read-only observation: True when at least one
    restore point or snapshot is visible, False when the platform tool answered
    that none exist, and None with a reason when this host cannot answer (no
    tool, no permission, timeout). Nothing is written, elevated or blocked.

    The result is cached for the process because the underlying commands are
    comparatively expensive and the answer does not change between probes.
    """

    return _restore_points_cached()


def reset_restore_cache() -> None:
    """Forget the cached restore point observation (used by tests and callers)."""

    _restore_points_cached.cache_clear()


def attach_to_guard(
    recorder: Callable[[BackupSignal], None] | None = None,
) -> bool:
    """Observe subprocess.Popen events and record recognised backup signals.

    This installs one additional audit hook callback in the current interpreter.
    It is optional, dependency free, and it never blocks the spawn: the signal is
    recorded and, when a recorder is supplied, also handed to it.

    Parameters:
        recorder: Optional callback invoked with each recognised signal. It must
            not raise; failures are ignored so an observer cannot break a spawn.

    Returns:
        True when the observer is armed (or was already), False when the
        interpreter cannot install audit hooks.
    """

    global _HOOK_INSTALLED
    if _HOOK_INSTALLED:
        return True
    add_hook = getattr(sys, "addaudithook", None)
    if not callable(add_hook):
        return False

    def _on_audit(event: str, args: tuple[object, ...]) -> None:
        if event != "subprocess.Popen" or _PROBING:
            return
        argv: object = ()
        try:
            if len(args) > 1:
                argv = args[1]
            elif args:
                argv = args[0]
        except (IndexError, TypeError):
            return
        signal = inspect_command(argv)
        if signal is None:
            return
        _SIGNALS.append(signal)
        if recorder is not None:
            try:
                recorder(signal)
            except (OSError, RuntimeError, ValueError, TypeError):
                pass

    try:
        add_hook(_on_audit)
    except (RuntimeError, TypeError, ValueError):
        return False
    _HOOK_INSTALLED = True
    return True


def detected_signals(limit: int = 16) -> list[BackupSignal]:
    """Return the most recent signals observed by attach_to_guard().

    Raises:
        ValueError: When limit is negative.
    """

    if limit < 0:
        raise ValueError("limit must not be negative")
    if limit == 0:
        return []
    return list(_SIGNALS)[-limit:]


def reset_signals() -> None:
    """Clear the observer ring (used by tests)."""

    _SIGNALS.clear()
