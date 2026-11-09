"""Tests for the undo-aware delete shim.

The shim edits shell startup files, so the tests pin the safety properties rather
than the wording: installation is confined to the home directory that is passed
in, a reinstall never duplicates the block, uninstall restores the exact previous
bytes, and the generated snippets are accepted by the shell that will source
them. Snippet syntax is only checked when the corresponding shell exists on the
host, so the suite runs unchanged on Windows and inside WSL.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from tauhaulity.tools import shim

OVERRIDE_NOTE = "# OVERRIDE:"


def _bash_candidates() -> list[str]:
    """Return plausible bash executables, most portable first.

    On Windows plain "bash" is the WSL launcher and it fails when the default
    distribution has no bash, so the Git for Windows installation is probed too.
    """

    candidates: list[str] = []
    on_path = shutil.which("bash")
    if on_path:
        candidates.append(on_path)
    program_files = os.environ.get("ProgramFiles")
    if program_files:
        candidates.append(os.path.join(program_files, "Git", "bin", "bash.exe"))
        candidates.append(os.path.join(program_files, "Git", "usr", "bin", "bash.exe"))
    return candidates


def _bash() -> str | None:
    """Return a bash that actually runs, or None.

    Existence on PATH is not enough: each candidate is probed once and skipped
    otherwise, so the suite reports an honest skip instead of a false failure.
    """

    for candidate in _bash_candidates():
        if not os.path.isfile(candidate):
            continue
        try:
            probe = subprocess.run(
                [candidate, "-c", "exit 0"], capture_output=True, timeout=120
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if probe.returncode == 0:
            return candidate
    return None


def _powershell() -> str | None:
    return shutil.which("pwsh") or shutil.which("powershell")


def _bash_syntax(path: Path) -> subprocess.CompletedProcess[str]:
    binary = _bash()
    assert binary is not None
    return subprocess.run(
        [binary, "-n", path.as_posix()], capture_output=True, text=True, timeout=120
    )


def _powershell_syntax(path: Path) -> subprocess.CompletedProcess[str]:
    binary = _powershell()
    assert binary is not None
    command = (
        "$e=$null; $t=$null; "
        "[void][System.Management.Automation.Language.Parser]::ParseFile('"
        + path.as_posix()
        + "', [ref]$t, [ref]$e); "
        "if ($e.Count -gt 0) { $e | ForEach-Object { Write-Output $_.Message }; exit 1 }; "
        "exit 0"
    )
    return subprocess.run(
        [binary, "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        timeout=120,
    )


def test_shell_aliases_resolve_to_the_two_families() -> None:
    assert shim.normalise_shell("bash") == "bash"
    assert shim.normalise_shell("sh") == "bash"
    assert shim.normalise_shell("zsh") == "bash"
    assert shim.normalise_shell("PowerShell") == "powershell"
    assert shim.normalise_shell("pwsh") == "powershell"
    assert set(shim.SUPPORTED_SHELLS) == {"bash", "powershell"}


def test_unknown_shell_is_rejected() -> None:
    for value in ("fish", "", "auto", "cmd"):
        with pytest.raises(ValueError):
            shim.normalise_shell(value)
    with pytest.raises(ValueError):
        shim.normalise_shell(42)  # type: ignore[arg-type]


def test_bash_snippet_wraps_tauhaulity_rm(tmp_path: Path) -> None:
    text = shim.shim_script("bash", root=tmp_path / "project", python="/usr/bin/python3")
    assert shim.SHIM_MARKER in text
    assert "trm() {" in text
    assert "tauhaulity rm" in text
    assert "--root" in text
    assert str((tmp_path / "project").resolve()).replace(os.sep, "/") in text
    assert "/usr/bin/python3" in text
    assert "uninstall --shell bash" in text


def test_powershell_snippet_wraps_tauhaulity_rm(tmp_path: Path) -> None:
    text = shim.shim_script(
        "powershell", root=tmp_path / "project", python="C:/Python/python.exe"
    )
    assert shim.SHIM_MARKER in text
    assert "function global:trm {" in text
    assert "tauhaulity rm" in text
    assert "@args" in text
    assert "C:/Python/python.exe" in text
    assert "uninstall --shell powershell" in text


def test_bash_snippet_is_valid_bash(tmp_path: Path) -> None:
    if _bash() is None:
        pytest.skip("bash is not installed on this host")
    path = tmp_path / "shim.bash"
    path.write_text(shim.shim_script("bash", root=tmp_path, python="python3"), encoding="utf-8")
    completed = _bash_syntax(path)
    assert completed.returncode == 0, completed.stderr


def test_powershell_snippet_parses(tmp_path: Path) -> None:
    if _powershell() is None:
        pytest.skip("PowerShell is not installed on this host")
    path = tmp_path / "shim.ps1"
    path.write_text(
        shim.shim_script("powershell", root=tmp_path, python="python"), encoding="utf-8"
    )
    completed = _powershell_syntax(path)
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_install_creates_the_block_inside_home(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    path = shim.install_shim("bash", home=home)
    assert path == home / ".bashrc"
    text = path.read_text(encoding="utf-8")
    assert shim.BLOCK_BEGIN in text
    assert shim.BLOCK_END in text
    assert "trm() {" in text
    assert path.resolve().is_relative_to(home.resolve())


def test_install_is_idempotent(tmp_path: Path) -> None:
    home = tmp_path / "home"
    shim.install_shim("bash", home=home)
    shim.install_shim("bash", home=home)
    text = (home / ".bashrc").read_text(encoding="utf-8")
    assert text.count(shim.BLOCK_BEGIN) == 1
    assert text.count(shim.BLOCK_END) == 1


def test_install_preserves_existing_content_and_backup(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    original = "export EDITOR=vim" + chr(10)
    (home / ".bashrc").write_text(original, encoding="utf-8")
    shim.install_shim("bash", home=home)
    text = (home / ".bashrc").read_text(encoding="utf-8")
    assert text.startswith("export EDITOR=vim")
    backup = home / (".bashrc" + shim.BACKUP_SUFFIX)
    assert backup.read_text(encoding="utf-8") == original


def test_reinstall_does_not_rewrite_the_backup(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    (home / ".bashrc").write_text("first line" + chr(10), encoding="utf-8")
    shim.install_shim("bash", home=home)
    shim.install_shim("bash", home=home)
    backup = home / (".bashrc" + shim.BACKUP_SUFFIX)
    assert backup.read_text(encoding="utf-8") == "first line" + chr(10)


def test_uninstall_restores_the_original_bytes(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    original = "alias ll='ls -l'" + chr(10) + "export PAGER=less" + chr(10)
    (home / ".bashrc").write_text(original, encoding="utf-8")
    shim.install_shim("bash", home=home)
    assert shim.uninstall_shim("bash", home=home) is True
    assert (home / ".bashrc").read_text(encoding="utf-8") == original
    assert not (home / (".bashrc" + shim.BACKUP_SUFFIX)).exists()


def test_uninstall_removes_a_file_it_created(tmp_path: Path) -> None:
    home = tmp_path / "home"
    shim.install_shim("bash", home=home)
    assert (home / ".bashrc").is_file()
    assert shim.uninstall_shim("bash", home=home) is True
    assert not (home / ".bashrc").exists()


def test_uninstall_without_install_is_false(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    assert shim.uninstall_shim("bash", home=home) is False
    assert shim.uninstall_shim("powershell", home=home) is False


def test_override_rm_is_opt_in_and_visibly_marked(tmp_path: Path) -> None:
    home = tmp_path / "home"
    path = shim.install_shim("bash", home=home)
    assert OVERRIDE_NOTE not in path.read_text(encoding="utf-8")

    home_override = tmp_path / "home-override"
    marked = shim.install_shim("bash", home=home_override, override_rm=True)
    text = marked.read_text(encoding="utf-8")
    assert OVERRIDE_NOTE in text
    assert "rm() {" in text


def test_override_powershell_removes_the_alias_first(tmp_path: Path) -> None:
    home = tmp_path / "home"
    path = shim.install_shim("powershell", home=home, override_rm=True)
    text = path.read_text(encoding="utf-8")
    assert OVERRIDE_NOTE in text
    assert "Alias:rm" in text
    assert text.index("Alias:rm") < text.index("function global:rm")


def test_installed_bash_profile_is_valid_bash(tmp_path: Path) -> None:
    if _bash() is None:
        pytest.skip("bash is not installed on this host")
    home = tmp_path / "home"
    path = shim.install_shim("bash", home=home, override_rm=True)
    completed = _bash_syntax(path)
    assert completed.returncode == 0, completed.stderr


def test_installed_powershell_profiles_parse(tmp_path: Path) -> None:
    if _powershell() is None:
        pytest.skip("PowerShell is not installed on this host")
    home = tmp_path / "home"
    shim.install_shim("powershell", home=home, override_rm=True)
    for path in (
        home / "Documents" / "PowerShell" / "profile.ps1",
        home / "Documents" / "WindowsPowerShell" / "profile.ps1",
    ):
        completed = _powershell_syntax(path)
        assert completed.returncode == 0, str(path) + completed.stdout + completed.stderr


def test_powershell_install_covers_both_profiles(tmp_path: Path) -> None:
    home = tmp_path / "home"
    primary = shim.install_shim("powershell", home=home)
    assert primary.name == "profile.ps1"
    for path in (
        home / "Documents" / "PowerShell" / "profile.ps1",
        home / "Documents" / "WindowsPowerShell" / "profile.ps1",
    ):
        assert path.is_file()
        assert shim.BLOCK_BEGIN in path.read_text(encoding="utf-8")


def test_status_round_trip(tmp_path: Path) -> None:
    home = tmp_path / "home"
    installed, path = shim.shim_status("bash", home=home)
    assert installed is False
    assert path == home / ".bashrc"
    shim.install_shim("bash", home=home)
    installed, path = shim.shim_status("bash", home=home)
    assert installed is True
    assert path == home / ".bashrc"


def test_install_never_writes_outside_home(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    shim.install_shim("bash", home=home, override_rm=True)
    shim.install_shim("powershell", home=home, override_rm=True)
    created = [path for path in tmp_path.rglob("*") if path.is_file()]
    assert created
    assert all(path.resolve().is_relative_to(home.resolve()) for path in created)


def test_shell_from_environment_returns_a_supported_shell() -> None:
    assert shim.shell_from_environment() in shim.SUPPORTED_SHELLS
