"""Undo-aware delete shim for bash and PowerShell.

A developer who types rm out of habit bypasses the undo ring, so the shim offers
a wrapper named trm that routes the same arguments through "tauhaulity rm": every
path is copied into the project journal before it is deleted and can be restored
with "tauhaulity undo". Overriding the real rm is available but never implicit,
because silently replacing a shell primitive is the kind of surprise that gets a
safety tool uninstalled; the generated block carries an explicit OVERRIDE note
when it is requested.

Installation is deliberately conservative:

  * the wrapper is appended to a shell startup file inside the home directory the
    caller passes, so tests and callers fully control the write location;
  * the previous file content is saved next to it with a .tauhaulity-backup
    suffix before the first modification, and a second install never overwrites
    that backup, so uninstall can restore the original bytes exactly;
  * uninstall removes the marked block only, and deletes a startup file that was
    created solely for the block, leaving every other line untouched;
  * the generated bash is plain POSIX compatible bash and the generated
    PowerShell avoids version specific syntax so it parses on Windows PowerShell
    5.1 and on pwsh 7 alike.

PowerShell installs the same block into both profile locations that exist inside
home (Documents/PowerShell for pwsh 7 and Documents/WindowsPowerShell for 5.1),
so "trm" is defined whichever PowerShell starts. shim_status and uninstall_shim
honour every location they manage.
"""

from __future__ import annotations

import os
import shlex
import shutil
import sys
from pathlib import Path

SUPPORTED_SHELLS: tuple[str, ...] = ("bash", "powershell")

#: Marker carried by the generated snippet itself, so a human reading a profile
#: can tell where the function came from even after the block markers are gone.
SHIM_MARKER = "# tauhaulity:delete-shim"

#: Block delimiters used for idempotent install and exact uninstall.
BLOCK_BEGIN = "# >>> tauhaulity:delete-shim >>>"
BLOCK_END = "# <<< tauhaulity:delete-shim <<<"

#: Same suffix as the git gate installer: one recognisable backup convention.
BACKUP_SUFFIX = ".tauhaulity-backup"

_POSIX_TARGET = ".bashrc"
_POWERSHELL_TARGETS: tuple[tuple[str, ...], ...] = (
    ("Documents", "PowerShell", "profile.ps1"),
    ("Documents", "WindowsPowerShell", "profile.ps1"),
)

_SHELL_ALIASES: dict[str, str] = {
    "bash": "bash",
    "sh": "bash",
    "zsh": "bash",
    "posix": "bash",
    "powershell": "powershell",
    "pwsh": "powershell",
    "ps": "powershell",
    "ps1": "powershell",
}


class ShimError(RuntimeError):
    """Raised when a shim file cannot be written or removed."""


def normalise_shell(shell: str) -> str:
    """Map a shell name or alias onto the two supported families.

    Parameters:
        shell: Shell name such as bash, sh, zsh, powershell or pwsh.

    Returns:
        Either "bash" or "powershell".

    Raises:
        ValueError: When the value is not a string or names an unknown shell.
    """

    if not isinstance(shell, str):
        raise ValueError("shell must be a string")
    key = shell.strip().lower()
    try:
        return _SHELL_ALIASES[key]
    except KeyError as exc:
        raise ValueError(
            "unsupported shell: " + shell + " (expected bash or powershell)"
        ) from exc


def _quote(shell: str, value: str) -> str:
    """Quote one word for the target shell.

    bash gets shlex quoting, which handles spaces and apostrophes. PowerShell
    single quotes are literal apart from a doubled quote, so that is the only
    escape needed and it works identically on 5.1 and 7.
    """

    if shell == "bash":
        return shlex.quote(value)
    return "'" + value.replace("'", "''") + "'"


def _invocation(shell: str, python: str, root: Path | None) -> str:
    """Render the command body shared by the trm and rm wrappers.

    Both wrappers call the CLI with "--" before the caller arguments so a path
    that begins with a dash is treated as a path and not as a flag. The root is
    embedded only when the caller supplied one; otherwise the CLI default of the
    current directory applies, which is what a project local wrapper wants.
    """

    # A wrapper generated on Windows embeds a drive letter, and Git Bash only
    # executes such an interpreter in its forward slash form. A POSIX host never
    # has a backslash in a real path, so the translation is unconditional.
    if shell == "bash":
        interpreter = python.replace(chr(92), "/")
    else:
        interpreter = python
    words = [_quote(shell, interpreter), "-m", "tauhaulity", "rm"]
    if root is not None:
        try:
            resolved = str(Path(root).resolve())
        except (OSError, RuntimeError):
            resolved = str(root)
        if shell == "bash":
            resolved = resolved.replace(chr(92), "/")
        words.extend(("--root", _quote(shell, resolved)))
    words.append("--")
    if shell == "bash":
        return " ".join(words) + ' "$@"'
    return "& " + " ".join(words) + " @args"


def shim_script(
    shell: str,
    *,
    root: Path | None = None,
    python: str | None = None,
) -> str:
    """Render the trm wrapper snippet for one shell.

    Parameters:
        shell: bash or a recognised alias, or powershell and its aliases.
        root: Project root baked into the wrapper, or None to use the CLI default.
        python: Interpreter used by the wrapper; None records the interpreter
            that is running this call, because a wrapper that finds the wrong
            Python cannot import tauhaulity at all.

    Returns:
        The complete snippet, one function definition plus its explanation. The
        text is not wrapped in install markers; install_shim adds those.

    Raises:
        ValueError: When the shell is not supported.
    """

    family = normalise_shell(shell)
    interpreter = str(python) if python else str(sys.executable)
    body = _invocation(family, interpreter, root)
    if family == "bash":
        lines = [
            SHIM_MARKER + " (bash)",
            "# Undo-aware delete wrapper: paths are journaled by 'tauhaulity rm'",
            "# before they are deleted and can be restored with 'tauhaulity undo'.",
            "# Remove with: python -m tauhaulity shim uninstall --shell bash",
            "trm() {",
            "    " + body,
            "}",
        ]
    else:
        lines = [
            SHIM_MARKER + " (powershell)",
            "# Undo-aware delete wrapper: paths are journaled by 'tauhaulity rm'",
            "# before they are deleted and can be restored with 'tauhaulity undo'.",
            "# Remove with: python -m tauhaulity shim uninstall --shell powershell",
            "function global:trm {",
            "    " + body,
            "}",
        ]
    return chr(10).join(lines) + chr(10)


def _override_script(shell: str, *, root: Path | None = None, python: str | None = None) -> str:
    """Render the explicit rm override section appended after the wrapper."""

    family = normalise_shell(shell)
    interpreter = str(python) if python else str(sys.executable)
    body = _invocation(family, interpreter, root)
    if family == "bash":
        lines = [
            "# OVERRIDE: the shell command 'rm' is replaced by the undo-aware wrapper",
            "# below. This is a deliberate opt-in (install --override-rm); uninstall",
            "# restores the shell's own rm.",
            "rm() {",
            "    " + body,
            "}",
        ]
    else:
        lines = [
            "# OVERRIDE: the 'rm' alias of Remove-Item is replaced by the undo-aware",
            "# wrapper below. This is a deliberate opt-in (install --override-rm);",
            "# uninstall restores the shell's own rm alias.",
            "if (Test-Path -Path Alias:rm) {",
            "    Remove-Item -Path Alias:rm -Force",
            "}",
            "function global:rm {",
            "    " + body,
            "}",
        ]
    return chr(10).join(lines) + chr(10)


def _block(shell: str, *, root: Path | None, override_rm: bool) -> str:
    """Render the complete marked block written into a startup file."""

    parts = [BLOCK_BEGIN + chr(10), shim_script(shell, root=root)]
    if override_rm:
        parts.append(chr(10) + _override_script(shell, root=root))
    parts.append(BLOCK_END + chr(10))
    return "".join(parts)


def _home_dir(home: Path | None) -> Path:
    """Resolve the home directory the install is confined to."""

    base = Path(home).expanduser() if home is not None else Path.home()
    try:
        base.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ShimError("cannot use home directory " + str(base) + ": " + str(exc)) from exc
    return base


def _targets(shell: str, home: Path | None) -> list[Path]:
    """Return every startup file this shell family owns inside home."""

    base = _home_dir(home)
    if shell == "bash":
        return [base / _POSIX_TARGET]
    return [base.joinpath(*parts) for parts in _POWERSHELL_TARGETS]


def _backup_path(target: Path) -> Path:
    """Return the backup file that preserves the pre-install content."""

    return target.with_name(target.name + BACKUP_SUFFIX)


def _read_text(path: Path) -> str:
    """Read a startup file, treating missing or undecodable content as empty."""

    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeError):
        return ""


def _write_text(path: Path, text: str) -> None:
    """Write a startup file atomically with POSIX newlines."""

    tmp = path.with_name(path.name + ".tauhaulity-tmp")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with tmp.open("w", encoding="utf-8", newline=chr(10)) as handle:
            handle.write(text)
        os.replace(tmp, path)
    except OSError as exc:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise ShimError("cannot write shim file " + str(path) + ": " + str(exc)) from exc


def _has_block(text: str) -> bool:
    """True when the text carries a complete install block."""

    return BLOCK_BEGIN in text and BLOCK_END in text


def _strip_block(text: str) -> tuple[str, bool]:
    """Remove every install block, returning the remaining text.

    Lines outside the markers are preserved verbatim. Blank lines at the end are
    dropped because they are the separator the installer added; uninstall then
    restores the backup when that is the only difference, so the file returns to
    its exact pre-install bytes.
    """

    kept: list[str] = []
    inside = False
    found = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == BLOCK_BEGIN:
            inside = True
            found = True
            continue
        if stripped == BLOCK_END:
            inside = False
            continue
        if inside:
            continue
        kept.append(line)
    while kept and not kept[-1].strip():
        kept.pop()
    remaining = chr(10).join(kept)
    if kept:
        remaining += chr(10)
    return remaining, found


def _compose(existing: str, block: str) -> str:
    """Append a block to existing text with exactly one separating blank line."""

    base = existing
    if base and not base.endswith(chr(10)):
        base += chr(10)
    if base and not base.endswith(chr(10) * 2):
        base += chr(10)
    return base + block


def install_shim(
    shell: str,
    *,
    home: Path | None = None,
    override_rm: bool = False,
) -> Path:
    """Install the undo-aware delete wrapper into a shell startup file.

    Installation is idempotent: the marked block is rewritten in place, never
    duplicated, and the pre-install content is backed up only on the first
    install so uninstall can restore it byte for byte.

    Parameters:
        shell: bash or powershell (aliases accepted).
        home: Directory the install is confined to; defaults to the real home.
        override_rm: Also replace the shell's own rm with the wrapper. The
            generated block states the override explicitly.

    Returns:
        The primary startup file that received the block.

    Raises:
        ValueError: When the shell is not supported.
        ShimError: When a startup file or its backup cannot be written.
    """

    family = normalise_shell(shell)
    targets = _targets(family, home)
    block = _block(family, root=None, override_rm=bool(override_rm))
    for target in targets:
        original = _read_text(target)
        backup = _backup_path(target)
        if not backup.is_file():
            # Keep the first pre-install state: a reinstall must not replace the
            # original content with a copy that already contains our block.
            _write_text(backup, original)
        stripped, _found = _strip_block(original)
        _write_text(target, _compose(stripped, block))
    return targets[0]


def uninstall_shim(shell: str, *, home: Path | None = None) -> bool:
    """Remove the installed wrapper block from every managed startup file.

    Parameters:
        shell: bash or powershell (aliases accepted).
        home: Directory the uninstall is confined to; defaults to the real home.

    Returns:
        True when at least one block was removed, False when none was installed.

    Raises:
        ValueError: When the shell is not supported.
        ShimError: When a startup file cannot be rewritten.
    """

    family = normalise_shell(shell)
    removed = False
    for target in _targets(family, home):
        original = _read_text(target)
        stripped, found = _strip_block(original)
        if not found:
            continue
        backup = _backup_path(target)
        backup_exists = backup.is_file()
        saved = _read_text(backup) if backup_exists else ""
        if saved and saved.rstrip(chr(10)) == stripped.rstrip(chr(10)):
            # Nothing except our block changed since install: restore exactly.
            _write_text(target, saved)
        elif backup_exists and not saved.strip() and not stripped.strip():
            # The backup proves the file exists only for our block, so removing it
            # restores the pre-install state of "file absent". Without a backup the
            # file is left in place, because it may have been created by the user.
            try:
                target.unlink()
            except OSError as exc:
                raise ShimError(
                    "cannot remove shim file " + str(target) + ": " + str(exc)
                ) from exc
        else:
            _write_text(target, stripped)
        try:
            if backup.is_file():
                backup.unlink()
        except OSError:
            # A backup that cannot be removed must not fail the uninstall; the
            # wrapper block is already gone, which is the guarantee that matters.
            pass
        removed = True
    return removed


def shim_status(shell: str, *, home: Path | None = None) -> tuple[bool, Path]:
    """Report whether the wrapper is installed and where it was found.

    Parameters:
        shell: bash or powershell (aliases accepted).
        home: Directory to inspect; defaults to the real home.

    Returns:
        A (installed, path) pair. When nothing is installed the path is the
        primary startup file that install_shim would write, so a caller can print
        an actionable location instead of an empty string.

    Raises:
        ValueError: When the shell is not supported.
    """

    family = normalise_shell(shell)
    targets = _targets(family, home)
    for target in targets:
        if _has_block(_read_text(target)):
            return True, target
    return False, targets[0]


def shell_from_environment() -> str:
    """Guess the shell family the current process is running under.

    The heuristic is intentionally small and honest: an explicit
    SHELL/ComSpec/POSH detection can be wrong inside a subprocess, so the CLI
    documents the guessed value and always allows --shell to override it.
    """

    try:
        if os.name == "nt":
            return "powershell"
        shell = os.environ.get("SHELL", "")
    except (OSError, TypeError):
        return "bash"
    name = Path(shell).name.lower() if shell else ""
    if name in {"pwsh", "pwsh-preview", "powershell"}:
        return "powershell"
    return "bash"


def shutil_bash_available() -> bool:
    """True when a bash executable is on PATH, used by callers that validate."""

    return shutil.which("bash") is not None
