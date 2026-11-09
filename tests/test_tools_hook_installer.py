"""Tests for the pre-commit gate installer.

The hook must be a real POSIX sh script that works without the package being
installed, so the tests inspect the rendered script, compile its embedded Python
payload, and exercise install/uninstall against a plain .git directory without
ever running git.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tauhaulity.tools.hook_installer import (
    GATE_MARKER,
    HookError,
    hook_status,
    install_hook,
    package_root,
    render_hook_script,
    uninstall_hook,
)

_PAYLOAD_RE = re.compile(r"-c '([^']*)'", re.DOTALL)


def _hook(sample_project: Path) -> Path:
    return sample_project / ".git" / "hooks" / "pre-commit"


def test_install_hook_writes_a_posix_script(sample_project: Path) -> None:
    path = install_hook(sample_project)
    assert path == _hook(sample_project)
    assert path.is_file()
    text = path.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh")
    assert GATE_MARKER in text
    assert "tauhaulity.tools.git_sentinel" in text
    assert "-c '" in text
    assert "TAUHAULITY_ROOT=" in text
    assert "TAUHAULITY_BLOCK=1" in text
    assert "cygpath" in text


def test_hook_status_round_trip(sample_project: Path) -> None:
    installed, path = hook_status(sample_project)
    assert installed is False
    assert path == _hook(sample_project)
    install_hook(sample_project)
    installed, path = hook_status(sample_project)
    assert installed is True
    assert path == _hook(sample_project)


def test_block_flag_is_embedded(sample_project: Path) -> None:
    path = install_hook(sample_project, block=False)
    text = path.read_text(encoding="utf-8")
    assert "TAUHAULITY_BLOCK=0" in text
    assert "TAUHAULITY_BLOCK=1" not in text


def test_rendered_script_quotes_a_root_with_spaces(tmp_path: Path) -> None:
    root = tmp_path / "my project"
    (root / ".git" / "hooks").mkdir(parents=True)
    script = render_hook_script(root)
    quoted = "'" + str(root.resolve()) + "'"
    assert quoted in script


def test_embedded_payload_is_valid_python(tmp_path: Path) -> None:
    root = tmp_path / "gate"
    (root / ".git").mkdir(parents=True)
    script = render_hook_script(root)
    match = _PAYLOAD_RE.search(script)
    assert match is not None
    payload = match.group(1)
    assert "'" not in payload
    compile(payload, "<tauhaulity-hook>", "exec")


def test_gate_payload_passes_a_clean_tree(project_root: Path, tmp_path: Path) -> None:
    # Run the exact payload the hook executes. The working directory is the
    # repository so the package is importable, and the scanned root has no git
    # metadata at all, so the gate must allow the commit without spawning git.
    root = tmp_path / "clean"
    root.mkdir()
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("print('ok')\n", encoding="utf-8")
    script = render_hook_script(root)
    payload = _PAYLOAD_RE.search(script).group(1)
    completed = subprocess.run(
        [sys.executable, "-c", payload, str(root), "1"],
        cwd=str(project_root),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    assert "commit blocked" not in completed.stderr


def test_reinstall_over_own_hook_is_idempotent(sample_project: Path) -> None:
    install_hook(sample_project)
    backup = sample_project / ".git" / "hooks" / "pre-commit.tauhaulity-backup"
    install_hook(sample_project, block=False)
    assert not backup.exists()
    assert "TAUHAULITY_BLOCK=0" in _hook(sample_project).read_text(encoding="utf-8")
    assert uninstall_hook(sample_project) is True


def test_foreign_hook_is_backed_up_and_restored(sample_project: Path) -> None:
    foreign = _hook(sample_project)
    foreign.parent.mkdir(parents=True, exist_ok=True)
    foreign.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    install_hook(sample_project)
    backup = foreign.with_name("pre-commit.tauhaulity-backup")
    assert backup.is_file()
    assert "tauhaulity:pre-commit-gate" in foreign.read_text(encoding="utf-8")
    assert uninstall_hook(sample_project) is True
    assert "exit 0" in foreign.read_text(encoding="utf-8")
    assert not backup.exists()


def test_uninstall_without_gate_is_false(sample_project: Path) -> None:
    assert uninstall_hook(sample_project) is False


def test_uninstall_ignores_a_foreign_hook(sample_project: Path) -> None:
    foreign = _hook(sample_project)
    foreign.parent.mkdir(parents=True, exist_ok=True)
    foreign.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    assert uninstall_hook(sample_project) is False
    assert foreign.read_text(encoding="utf-8") == "#!/bin/sh\nexit 0\n"


def test_install_requires_git_metadata(tmp_path: Path) -> None:
    with pytest.raises(HookError):
        install_hook(tmp_path)
    installed, path = hook_status(tmp_path)
    assert installed is False
    assert path.name == "pre-commit"


def test_install_accepts_a_gitdir_pointer(tmp_path: Path) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    metadata = tmp_path / "metadata"
    (metadata / "hooks").mkdir(parents=True)
    (worktree / ".git").write_text("gitdir: " + str(metadata) + "\n", encoding="utf-8")
    path = install_hook(worktree)
    assert path == metadata / "hooks" / "pre-commit"
    assert path.is_file()
    assert uninstall_hook(worktree) is True


@pytest.mark.skipif(os.name == "nt", reason="Win32 does not store POSIX execute bits")
def test_installed_hook_is_executable(sample_project: Path) -> None:
    path = install_hook(sample_project)
    assert os.access(path, os.X_OK)


def test_hook_status_reports_conventional_path_without_git(tmp_path: Path) -> None:
    installed, path = hook_status(tmp_path)
    assert installed is False
    assert path == tmp_path / ".git" / "hooks" / "pre-commit"

def _payload(script: str) -> str:
    match = _PAYLOAD_RE.search(script)
    assert match is not None
    return match.group(1)


def _run_payload(
    root: Path,
    cwd: Path,
    *,
    block: bool = True,
    package: str | None = None,
    isolated: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run the exact payload the hook executes, with an explicit package root.

    Isolated mode (-S -E) removes site-packages and PYTHONPATH, so the only way
    the payload can import the scanner is the package root embedded in the hook.
    """

    args = [sys.executable]
    if isolated:
        args.extend(["-S", "-E"])
    args.extend(["-c", _payload(render_hook_script(root)), str(root), "1" if block else "0"])
    if package is not None:
        args.append(package)
    return subprocess.run(
        args, cwd=str(cwd), capture_output=True, text=True, timeout=120
    )


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.setdefault("GIT_AUTHOR_NAME", "Tauhaulity Test")
    env.setdefault("GIT_AUTHOR_EMAIL", "test@example.test")
    env.setdefault("GIT_COMMITTER_NAME", "Tauhaulity Test")
    env.setdefault("GIT_COMMITTER_EMAIL", "test@example.test")
    return subprocess.run(
        ["git", *args], cwd=str(repo), capture_output=True, text=True, env=env, timeout=180
    )


def _real_repo(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "src").mkdir()
    (root / "src" / "app.py").write_text("print('ok')" + chr(10), encoding="utf-8")
    assert _git(root, "init", "-q").returncode == 0
    for key, value in (
        ("user.email", "test@example.test"),
        ("user.name", "Tauhaulity Test"),
        ("commit.gpgsign", "false"),
    ):
        assert _git(root, "config", key, value).returncode == 0
    return root


def test_rendered_script_embeds_the_package_root(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    script = render_hook_script(root)
    assert "TAUHAULITY_PACKAGE_ROOT=" in script
    assert str(package_root()) in script
    assert (package_root() / "tauhaulity" / "tools" / "git_sentinel.py").is_file()


def test_payload_fails_closed_when_the_scanner_is_unavailable(tmp_path: Path) -> None:
    root = tmp_path / "clean"
    (root / ".git").mkdir(parents=True)
    completed = _run_payload(root, tmp_path, package=str(tmp_path / "missing-package-root"))
    assert completed.returncode == 1
    assert "gate unavailable" in completed.stderr
    assert "commit blocked" in completed.stderr


def test_payload_warn_only_allows_the_commit_when_the_scanner_is_unavailable(
    tmp_path: Path,
) -> None:
    root = tmp_path / "clean"
    (root / ".git").mkdir(parents=True)
    completed = _run_payload(
        root, tmp_path, block=False, package=str(tmp_path / "missing-package-root")
    )
    assert completed.returncode == 0
    assert "gate unavailable" in completed.stderr
    assert "--warn-only" in completed.stderr
    assert "commit blocked" not in completed.stderr


def test_payload_imports_the_checkout_from_an_unrelated_project(tmp_path: Path) -> None:
    root = tmp_path / "unrelated"
    (root / ".git").mkdir(parents=True)
    (root / "app.py").write_text("print('clean')" + chr(10), encoding="utf-8")
    completed = _run_payload(root, tmp_path, package=str(package_root()))
    assert completed.returncode == 0, completed.stderr
    assert "gate unavailable" not in completed.stderr


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed on this host")
def test_real_commit_blocks_a_staged_token_and_never_echoes_it(tmp_path: Path) -> None:
    repo = _real_repo(tmp_path / "repo")
    token = "ghp_" + "Z" * 30
    install_hook(repo)
    (repo / ".env").write_text("GITHUB_TOKEN=" + token + chr(10), encoding="utf-8")
    assert _git(repo, "add", "-A").returncode == 0
    blocked = _git(repo, "commit", "-m", "leak attempt")
    combined = blocked.stdout + blocked.stderr
    assert blocked.returncode != 0, combined
    assert "commit blocked" in combined
    assert token not in combined, "the gate must never echo the raw secret"
    assert "secret in .env" in combined

    (repo / ".env").unlink()
    (repo / "safe.txt").write_text("clean" + chr(10), encoding="utf-8")
    assert _git(repo, "add", "-A").returncode == 0
    allowed = _git(repo, "commit", "-m", "clean change")
    assert allowed.returncode == 0, allowed.stdout + allowed.stderr


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed on this host")
def test_real_warn_only_gate_allows_the_leak_with_a_warning(tmp_path: Path) -> None:
    repo = _real_repo(tmp_path / "repo")
    token = "ghp_" + "Y" * 30
    install_hook(repo, block=False)
    (repo / ".env").write_text("GITHUB_TOKEN=" + token + chr(10), encoding="utf-8")
    assert _git(repo, "add", "-A").returncode == 0
    completed = _git(repo, "commit", "-m", "warn only")
    combined = completed.stdout + completed.stderr
    assert completed.returncode == 0, combined
    assert "tauhaulity" in combined.lower()
    assert token not in combined

@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed on this host")
def test_real_commit_allows_a_baselined_secret_but_blocks_a_new_one(
    tmp_path: Path,
) -> None:
    from tauhaulity.tools.allowlist import write_baseline

    repo = _real_repo(tmp_path / "repo")
    known = "ghp_" + "O" * 30
    (repo / ".env").write_text("GITHUB_TOKEN=" + known + chr(10), encoding="utf-8")
    install_hook(repo)
    written = write_baseline(repo)
    assert written.total >= 1

    assert _git(repo, "add", "-A").returncode == 0
    allowed = _git(repo, "commit", "-m", "accept the known token")
    combined_allowed = allowed.stdout + allowed.stderr
    assert allowed.returncode == 0, combined_allowed
    assert known not in combined_allowed

    fresh = "ghp_" + "N" * 30
    (repo / "src" / "fresh.py").write_text(
        "TOKEN = '" + fresh + "'" + chr(10), encoding="utf-8"
    )
    assert _git(repo, "add", "-A").returncode == 0
    blocked = _git(repo, "commit", "-m", "new token")
    combined = blocked.stdout + blocked.stderr
    assert blocked.returncode != 0, combined
    assert "commit blocked" in combined
    assert fresh not in combined

def _sh_candidates() -> list[str]:
    """Return plausible POSIX sh executables, most portable first."""

    candidates: list[str] = []
    on_path = shutil.which("sh")
    if on_path:
        candidates.append(on_path)
    program_files = os.environ.get("ProgramFiles")
    if program_files:
        candidates.append(os.path.join(program_files, "Git", "usr", "bin", "sh.exe"))
        candidates.append(os.path.join(program_files, "Git", "bin", "sh.exe"))
    return candidates


def _posix_sh() -> str | None:
    """Return a POSIX sh that actually runs, or None.

    A bare "sh" on Windows is not reliable: the Git Bash sh is often absent from
    PATH and the system32 bash.exe is a WSL launcher. Each candidate is probed.
    """

    for candidate in _sh_candidates():
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


def _run_rendered_hook(script: str, cwd: Path) -> subprocess.CompletedProcess[str]:
    sh = _posix_sh()
    assert sh is not None
    path = cwd / "rendered-pre-commit"
    path.write_text(script, encoding="utf-8")
    return subprocess.run(
        [sh, str(path)],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=120,
        env={"PATH": "/nonexistent", "HOME": str(cwd)},
    )


def test_rendered_hook_fails_closed_without_an_interpreter(tmp_path: Path) -> None:
    if _posix_sh() is None:
        pytest.skip("a POSIX sh is not available on this host")
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    script = render_hook_script(root).replace(
        str(Path(sys.executable).resolve()), str(tmp_path / "missing-python")
    )
    completed = _run_rendered_hook(script, tmp_path)
    assert completed.returncode == 1
    assert "not operational" in completed.stderr


def test_rendered_warn_only_hook_allows_a_missing_interpreter(tmp_path: Path) -> None:
    if _posix_sh() is None:
        pytest.skip("a POSIX sh is not available on this host")
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    script = render_hook_script(root, block=False).replace(
        str(Path(sys.executable).resolve()), str(tmp_path / "missing-python")
    )
    completed = _run_rendered_hook(script, tmp_path)
    assert completed.returncode == 0
    assert "warn-only" in completed.stderr
    assert "commit blocked" not in completed.stderr



