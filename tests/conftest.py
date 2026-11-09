"""Shared pytest fixtures for the Tauhaulity suite.

The suite must stay deterministic and fast, so automatic guard activation is
disabled for the test session (TAUHAULITY_NO_AUTO). Tests that verify hook
behaviour spawn a fresh interpreter instead of mutating the pytest process,
because an audit hook cannot be removed once installed.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

os.environ.setdefault("TAUHAULITY_NO_AUTO", "1")

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import pytest

from tauhaulity.core.platform_probe import detect_platform
from tauhaulity.core.policy import Policy


@pytest.fixture(scope="session")
def project_root() -> Path:
    """Absolute path of the repository root."""

    return ROOT


@pytest.fixture(scope="session")
def platform_info():
    """Cached platform fingerprint for the current host."""

    return detect_platform()


@pytest.fixture()
def default_policy() -> Policy:
    """Default policy used by pillar and engine tests."""

    return Policy()


@pytest.fixture()
def sample_project(tmp_path: Path) -> Path:
    """Build a small project tree that exercises every pillar.

    The tree is created with plain file writes (never git commands) so it stays
    portable across Windows, WSL Ubuntu and WSL Debian.
    """

    root = tmp_path / "sample_project"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text(
        "import os\n"
        "TOKEN = 'ghp_ExampleTokenValueThatLooksReal1234567890'\n"
        "\n"
        "def main() -> None:\n"
        "    print(os.getcwd())\n",
        encoding="utf-8",
    )
    (root / ".env").write_text("GITHUB_TOKEN=ghp_LeakedSecretValue9876543210abcdef\n", encoding="utf-8")
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text(
        "[core]\n"
        "\trepositoryformatversion = 0\n"
        "[remote \"origin\"]\n"
        "\turl = https://user:ghp_RemoteUrlSecret1234567890@example.test/repo.git\n",
        encoding="utf-8",
    )
    (root / ".git" / "hooks").mkdir()
    site = root / ".venv" / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    (site / "helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    (site / "totally_legit.pth").write_text("import os; os.system('echo pwned')\n", encoding="utf-8")
    (root / "canary.txt").write_text("do not modify\n", encoding="utf-8")
    (root / "notes.txt").write_text("plain notes\n", encoding="utf-8")
    return root


@pytest.fixture()
def repo_with_hook(sample_project: Path) -> Path:
    """Return the sample project with an installed pre-commit hook path."""

    hook = sample_project / ".git" / "hooks" / "pre-commit"
    hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    return sample_project
