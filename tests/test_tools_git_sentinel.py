"""Tests for the credential scanner, repository inspection and history scan.

Every git interaction is injected or short circuited except the two explicitly
marked real-repository tests, which build a throwaway repository in tmp_path: the
rest of the suite must never spawn a git process, so the scanner is proven on
synthetic blobs and fails closed when the binary is unavailable.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

import tauhaulity.tools.git_sentinel as sentinel
from tauhaulity.tools.allowlist import Baseline, BaselineEntry, fingerprint_hit
from tauhaulity.tools.git_sentinel import (
    REVOCATION_HINTS,
    GitSentinelReport,
    SecretHit,
    git_dir,
    inspect_repository,
    mask_secret,
    redact_text,
    scan_history,
    scan_staged,
    scan_text,
)

GITHUB_PAT = "github_pat_" + "A" * 82
CLASSIC_PAT = "ghp_" + "B" * 30
AWS_KEY = "AKIA" + "Q" * 16
GENERIC_VALUE = "q8Zr3Tn0Wl5Xv2Bk9Jm4Hc7Pd1Sg6Fa8"


def test_mask_secret_keeps_only_the_family_prefix() -> None:
    assert mask_secret(CLASSIC_PAT) == "ghp_****REDACTED****"
    assert mask_secret(GITHUB_PAT) == "github_pat_****REDACTED****"
    assert mask_secret(AWS_KEY) == "AKIA****REDACTED****"
    assert mask_secret("sk-" + "z" * 24) == "sk-****REDACTED****"
    assert mask_secret("") == "****REDACTED****"
    assert mask_secret("short") == "****REDACTED****"


def test_mask_secret_never_returns_the_secret_body() -> None:
    secret = "Zx9" + "vQ7" * 10
    masked = mask_secret(secret)
    assert secret not in masked
    assert secret[4:] not in masked


def test_scan_text_detects_github_token_with_line_number() -> None:
    hits = scan_text("first line\nTOKEN = '" + CLASSIC_PAT + "'\n", "src/config.py")
    assert len(hits) == 1
    hit = hits[0]
    assert isinstance(hit, SecretHit)
    assert (hit.rel_path, hit.line_no, hit.kind) == ("src/config.py", 2, "github_token")
    assert hit.masked == "ghp_****REDACTED****"
    assert CLASSIC_PAT not in hit.masked


def test_scan_text_detects_fine_grained_pat() -> None:
    hits = scan_text("export GITHUB_TOKEN=" + GITHUB_PAT, "ci/env.sh")
    assert [hit.kind for hit in hits] == ["github_pat"]
    assert hits[0].rel_path == "ci/env.sh"


def test_scan_text_detects_private_key_header_and_aws_key() -> None:
    text = "-----BEGIN OPENSSH PRIVATE KEY-----\nid " + AWS_KEY + "\n"
    kinds = {hit.kind for hit in scan_text(text, "secrets.txt")}
    assert kinds == {"private_key", "aws_access_key"}


def test_scan_text_detects_generic_high_entropy_assignment() -> None:
    hits = scan_text('api_key: "' + GENERIC_VALUE + '"', "conf/app.yaml")
    assert len(hits) == 1
    assert hits[0].kind == "generic_secret"
    assert GENERIC_VALUE not in hits[0].masked


def test_scan_text_ignores_placeholders_and_plain_code() -> None:
    text = (
        "def main() -> None:\n"
        "    print('hello world')\n"
        "TOKEN=changeme\n"
        "SECRET=None\n"
        "notes = 'this is ordinary prose with words in it'\n"
    )
    assert scan_text(text, "src/app.py") == []


def test_scan_text_deduplicates_overlapping_detectors() -> None:
    # The GitHub pattern and the generic assignment rule both match the token;
    # only the specific hit may survive.
    hits = scan_text("API_TOKEN=" + CLASSIC_PAT, "one.txt")
    assert [hit.kind for hit in hits] == ["github_token"]


def test_scan_text_empty_input() -> None:
    assert scan_text("", "x.py") == []


def test_redact_text_masks_and_counts_every_match() -> None:
    text = "token " + CLASSIC_PAT + " plus " + AWS_KEY + " done"
    redacted, count = redact_text(text)
    assert count == 2
    assert CLASSIC_PAT not in redacted
    assert AWS_KEY not in redacted
    assert "****REDACTED****" in redacted
    assert redact_text("") == ("", 0)


def test_git_dir_returns_none_outside_a_repository(tmp_path: Path) -> None:
    assert git_dir(tmp_path) is None


def test_git_dir_reads_a_gitdir_pointer(tmp_path: Path) -> None:
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    metadata = tmp_path / "metadata"
    metadata.mkdir()
    (worktree / ".git").write_text("gitdir: " + str(metadata) + "\n", encoding="utf-8")
    assert git_dir(worktree) == metadata


class _Completed:
    """Minimal stand-in for subprocess.CompletedProcess in runner tests."""

    def __init__(self, returncode: int, stdout: bytes) -> None:
        self.returncode = returncode
        self.stdout = stdout


def test_scan_staged_uses_injected_runner(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    calls: list[list[str]] = []

    def runner(args, cwd):
        calls.append(list(args))
        if args[:3] == ["git", "diff", "--cached"]:
            return (0, b"src/app.py\nnotes.txt\nimage.bin\n")
        if args == ["git", "show", ":src/app.py"]:
            return (0, ("KEY = '" + CLASSIC_PAT + "'\n").encode())
        if args == ["git", "show", ":notes.txt"]:
            return (0, b"plain notes\n")
        return (0, b"\x00\x01binary\x00")

    hits = scan_staged(root, runner=runner)
    assert [hit.rel_path for hit in hits] == ["src/app.py"]
    assert hits[0].line_no == 1
    assert calls[0][:3] == ["git", "diff", "--cached"]


def test_scan_staged_accepts_completed_process_shape(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)

    def runner(args, cwd):
        if args[:3] == ["git", "diff", "--cached"]:
            return _Completed(0, b"deploy.sh\n")
        return _Completed(0, ("export KEY=" + CLASSIC_PAT + "\n").encode())

    hits = scan_staged(root, runner=runner)
    assert [(hit.rel_path, hit.kind) for hit in hits] == [("deploy.sh", "github_token")]


def test_scan_staged_without_repository_never_calls_the_runner(tmp_path: Path) -> None:
    def runner(args, cwd):
        raise AssertionError("runner must not be invoked outside a repository")

    assert scan_staged(tmp_path, runner=runner) == []


def test_scan_staged_degrades_when_git_fails(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    assert scan_staged(root, runner=lambda args, cwd: (128, b"")) == []


def test_scan_staged_runner_exception_degrades(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)

    def runner(args, cwd):
        raise OSError("git exploded")

    assert scan_staged(root, runner=runner) == []


def test_inspect_repository_reports_masked_secrets_and_remote_credentials(
    monkeypatch: pytest.MonkeyPatch, sample_project: Path
) -> None:
    # Simulate a host without a usable git binary: no process is spawned.
    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    report = inspect_repository(sample_project)
    assert isinstance(report, GitSentinelReport)
    rels = {hit.rel_path for hit in report.secrets}
    assert ".env" in rels
    assert "src/app.py" in rels
    raw_env_secret = "ghp_LeakedSecretValue9876543210abcdef"
    assert all(raw_env_secret not in hit.masked for hit in report.secrets)
    assert report.remote_credentials
    assert all("ghp_RemoteUrlSecret" not in credential for credential in report.remote_credentials)
    assert "****REDACTED****" in report.remote_credentials[0]
    assert report.scanned_files > 0
    assert report.hook_installed is False
    assert "credential candidate" in report.findings_text
    assert report.leak_count == len(report.secrets) + len(report.remote_credentials)


def test_inspect_repository_reports_installed_hook(
    monkeypatch: pytest.MonkeyPatch, sample_project: Path
) -> None:
    from tauhaulity.tools.hook_installer import install_hook

    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    install_hook(sample_project)
    report = inspect_repository(sample_project)
    assert report.hook_installed is True
    assert report.hook_path is not None
    assert report.hook_path.name == "pre-commit"
    assert "installed" in report.findings_text


def test_inspect_repository_without_hook_check_skips_hook_state(
    monkeypatch: pytest.MonkeyPatch, sample_project: Path
) -> None:
    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    report = inspect_repository(sample_project, check_hook=False)
    assert report.hook_installed is False
    assert "pre-commit" not in report.findings_text


def test_inspect_repository_on_a_plain_directory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    root = tmp_path / "plain"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("print('clean')\n", encoding="utf-8")
    report = inspect_repository(root)
    assert report.secrets == []
    assert report.remote_credentials == []
    assert report.scanned_files == 1
    assert report.hook_path is None
    assert "no credential candidates" in report.findings_text

# ---------------------------------------------------------------------------
# S2 credential rule matrix
#
# One sample per family, each shaped like the real token so the exact pattern is
# exercised, and a matching documentation line that only names the credential and
# must stay quiet. Every masked rendering is asserted to hide the sample.
# ---------------------------------------------------------------------------

SECRET_SAMPLES: dict[str, str] = {
    "github_pat": "github_pat_" + "A" * 82,
    "github_token": "ghp_" + "B" * 30,
    "gitlab_token": "glpat-" + "C" * 20,
    "google_api_key": "AIza" + "D" * 35,
    "slack_token": "xoxb-123456789012-123456789012-" + "a" * 12,
    "discord_webhook": "https://discord.com/api/webhooks/123456789012345678/" + "E" * 40,
    "stripe_key": "sk_live_" + "F" * 24,
    "sendgrid_key": "SG." + "G" * 22 + "." + "H" * 43,
    "twilio_key": "SK" + "0123456789abcdef" * 2,
    "npm_token": "npm_" + "I" * 36,
    "pypi_token": "pypi-" + "J" * 50,
    "aws_access_key": "AKIA" + "K" * 16,
    "aws_secret_key": "AWS_SECRET_ACCESS_KEY=" + "L" * 40,
    "azure_devops_pat": "AZURE_DEVOPS_PAT=" + "M" * 52,
    "jwt": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
    + "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
    "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----",
    "database_uri": "postgres://app:s3cr3tPassw0rd@db.example.test:5432/app",
    "generic_secret": 'api_key = "' + GENERIC_VALUE + '"',
}

DOCUMENTATION_LINES: tuple[str, ...] = (
    "Set GITHUB_TOKEN in the environment before running the scanner.",
    "The gitlab_token setting is read from the shell profile.",
    "Use sk_live_ keys only in the deployed environment.",
    "AIza is the prefix of a Google API key, not a full key.",
    "Run npm_ scripts through npm run.",
    "A JWT has the form header.payload.signature.",
    "Connect to mongodb://localhost:27017/app for local work.",
    "AWS_SECRET_ACCESS_KEY=changeme",
    "AZURE_DEVOPS_PAT=<your token here>",
    "Documentation mentions pypi- and SG. prefixes only.",
)


@pytest.mark.parametrize("kind,sample", sorted(SECRET_SAMPLES.items()))
def test_rule_matrix_flags_each_family_and_masks_it(kind: str, sample: str) -> None:
    hits = scan_text(sample, "config/sample.txt")
    assert [hit.kind for hit in hits] == [kind]
    hit = hits[0]
    assert sample not in hit.masked
    assert hit.revocation_hint == REVOCATION_HINTS[kind]
    assert any(
        verb in hit.revocation_hint
        for verb in ("revoke", "rotate", "delete", "roll", "invalidate", "regenerate", "deactivate")
    )


@pytest.mark.parametrize("line", DOCUMENTATION_LINES)
def test_rule_matrix_ignores_documentation_mentions(line: str) -> None:
    assert scan_text(line, "docs/SECURITY.md") == []


def test_fenced_markdown_example_is_reported_but_masked() -> None:
    token = "ghp_" + "N" * 30
    text = (
        "Set the token first:" + chr(10)
        + "\u0060\u0060\u0060bash" + chr(10)
        + "export GITHUB_TOKEN=" + token + chr(10)
        + "\u0060\u0060\u0060" + chr(10)
    )
    hits = scan_text(text, "docs/setup.md")
    assert [hit.kind for hit in hits] == ["github_token"]
    assert hits[0].masked == "ghp_****REDACTED****"
    assert token not in hits[0].masked
    redacted, count = redact_text(text)
    assert count == 1
    assert token not in redacted
    assert "ghp_" + "****REDACTED****" in redacted


def test_mask_secret_keeps_the_new_family_prefixes() -> None:
    assert mask_secret("glpat-" + "x" * 20) == "glpat-****REDACTED****"
    assert mask_secret("sk_live_" + "x" * 24) == "sk_live_****REDACTED****"
    assert mask_secret("npm_" + "x" * 36) == "npm_****REDACTED****"
    assert mask_secret("pypi-" + "x" * 50) == "pypi-****REDACTED****"
    assert mask_secret("SG." + "x" * 22 + "." + "y" * 43) == "SG.****REDACTED****"
    assert mask_secret("SK" + "0" * 32) == "SK****REDACTED****"


def test_structured_rules_mask_only_the_secret_material() -> None:
    uri = "postgres://app:s3cr3tPassw0rd@db.example.test:5432/app"
    masked = scan_text(uri, "conf/db.yml")[0].masked
    assert masked == "postgres://app:****REDACTED****@db.example.test:5432/app"
    assert "s3cr3tPassw0rd" not in masked

    webhook = "https://discord.com/api/webhooks/123456789012345678/" + "P" * 40
    webhook_masked = scan_text(webhook, "conf/hooks.yml")[0].masked
    assert webhook_masked.startswith(
        "https://discord.com/api/webhooks/123456789012345678/"
    )
    assert "P" * 40 not in webhook_masked

    aws = "AWS_SECRET_ACCESS_KEY=" + "Q" * 40
    assert scan_text(aws, "ci/env.sh")[0].masked == "QQQQ****REDACTED****"


# ---------------------------------------------------------------------------
# S2 bounded history scan
# ---------------------------------------------------------------------------


_HISTORY_MARK = chr(1)


class _HistoryRunner:
    """Deterministic stand-in for the git plumbing used by the history scan.

    The production scan issues one merged "git log --raw" call; this fake renders
    the same stream from its commit list and per-commit diff rows, so the parser
    under test is the real one.
    """

    def __init__(self, commits, diffs, sizes, blobs) -> None:
        self.commits = list(commits)
        self.diffs = dict(diffs)
        self.sizes = dict(sizes)
        self.blobs = dict(blobs)
        self.calls: list[list[str]] = []

    def __call__(self, args, cwd):
        self.calls.append(list(args))
        if args[:2] == ["git", "log"]:
            payload = ""
            for commit in self.commits:
                payload += _HISTORY_MARK + commit + chr(10)
                diff = self.diffs.get(commit, b"")
                if diff:
                    text = diff.decode("utf-8", errors="replace")
                    payload += text
                    if not text.endswith(chr(10)):
                        payload += chr(10)
            return (0, payload.encode())
        if args[:3] == ["git", "cat-file", "-s"]:
            return (0, str(self.sizes.get(args[3], 0)).encode())
        if args[:3] == ["git", "cat-file", "blob"]:
            return (0, self.blobs.get(args[3], b""))
        return (1, b"")

    def blob_reads(self) -> list[list[str]]:
        """Return the blob content reads requested by the scan."""

        return [call for call in self.calls if call[:3] == ["git", "cat-file", "blob"]]


def _raw_row(old_sha: str, new_sha: str, status: str, path: str) -> str:
    """Render one git --raw diff row."""

    return ":" + "100644 100644 " + old_sha + " " + new_sha + " " + status + chr(9) + path


def _history_repo(tmp_path: Path) -> Path:
    """Create a throwaway directory with git metadata but no real repository."""

    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    return root


def _token_history(token: str, path: str = "legacy/env.py") -> tuple[_HistoryRunner, str, str]:
    """Build a one commit history whose added blob contains a token."""

    blob_sha = "b" * 40
    payload = ("before" + chr(10) + "GITHUB_TOKEN=" + token + chr(10)).encode()
    commit = "c" * 40
    runner = _HistoryRunner(
        [commit],
        {commit: _raw_row("0" * 40, blob_sha, "A", path).encode()},
        {blob_sha: len(payload)},
        {blob_sha: payload},
    )
    return runner, commit, blob_sha


HISTORY_TOKEN = "ghp_" + "H" * 30


def test_scan_history_reports_a_token_from_an_old_commit(tmp_path: Path) -> None:
    root = _history_repo(tmp_path)
    runner, commit, _blob = _token_history(HISTORY_TOKEN)
    hits = scan_history(root, runner=runner)
    assert len(hits) == 1
    assert hits[0].rel_path == commit[:8] + ":legacy/env.py"
    assert hits[0].kind == "github_token"
    assert HISTORY_TOKEN not in hits[0].masked
    assert hits[0].revocation_hint == REVOCATION_HINTS["github_token"]


def test_scan_history_attributes_the_introducing_commit(tmp_path: Path) -> None:
    root = _history_repo(tmp_path)
    blob_sha = "b" * 40
    payload = ("GITHUB_TOKEN=" + HISTORY_TOKEN + chr(10)).encode()
    added = "c" * 40
    removed = "d" * 40
    runner = _HistoryRunner(
        [removed, added],
        {
            removed: _raw_row(blob_sha, "0" * 40, "D", "src/old.py").encode(),
            added: _raw_row("0" * 40, blob_sha, "A", "src/old.py").encode(),
        },
        {blob_sha: len(payload)},
        {blob_sha: payload},
    )
    hits = scan_history(root, runner=runner)
    assert [hit.rel_path for hit in hits] == [added[:8] + ":src/old.py"]


def test_scan_history_returns_empty_for_a_clean_history(tmp_path: Path) -> None:
    root = _history_repo(tmp_path)
    commit = "c" * 40
    blob_sha = "b" * 40
    payload = ("plain notes" + chr(10)).encode()
    runner = _HistoryRunner(
        [commit],
        {commit: _raw_row("0" * 40, blob_sha, "A", "notes.txt").encode()},
        {blob_sha: len(payload)},
        {blob_sha: payload},
    )
    assert scan_history(root, runner=runner) == []


def test_scan_history_without_git_metadata_never_calls_git(tmp_path: Path) -> None:
    calls: list[object] = []

    def runner(args, cwd):
        calls.append(args)
        raise AssertionError("git must not run without repository metadata")

    assert scan_history(tmp_path, runner=runner) == []
    assert calls == []


def test_scan_history_skips_binary_blobs(tmp_path: Path) -> None:
    root = _history_repo(tmp_path)
    commit = "c" * 40
    blob_sha = "b" * 40
    payload = b"\x00\x01\x02binary payload"
    runner = _HistoryRunner(
        [commit],
        {commit: _raw_row("0" * 40, blob_sha, "A", "asset.bin").encode()},
        {blob_sha: len(payload)},
        {blob_sha: payload},
    )
    assert scan_history(root, runner=runner) == []
    assert len(runner.blob_reads()) == 1


def test_scan_history_skips_a_huge_blob_without_reading_it(tmp_path: Path) -> None:
    root = _history_repo(tmp_path)
    commit = "c" * 40
    blob_sha = "b" * 40
    runner = _HistoryRunner(
        [commit],
        {commit: _raw_row("0" * 40, blob_sha, "A", "huge.dump").encode()},
        {blob_sha: 10_000_000},
        {blob_sha: b""},
    )
    assert scan_history(root, runner=runner, max_blob_bytes=1024) == []
    assert runner.blob_reads() == []


def test_scan_history_bounds_the_commit_walk(tmp_path: Path) -> None:
    root = _history_repo(tmp_path)
    runner, _commit, _blob = _token_history(HISTORY_TOKEN)
    scan_history(root, runner=runner, max_commits=2)
    log_calls = [call for call in runner.calls if call[:2] == ["git", "log"]]
    assert log_calls
    assert "--max-count=2" in log_calls[0]


def test_scan_history_bounds_the_blob_walk(tmp_path: Path) -> None:
    root = _history_repo(tmp_path)
    commit = "c" * 40
    sha_a = "a" * 40
    sha_b = "b" * 40
    payload_a = ("A=" + "ghp_" + "J" * 30 + chr(10)).encode()
    payload_b = ("B=" + "ghp_" + "K" * 30 + chr(10)).encode()
    rows = _raw_row("0" * 40, sha_a, "A", "one.py") + chr(10) + _raw_row(
        "0" * 40, sha_b, "A", "two.py"
    )
    runner = _HistoryRunner(
        [commit],
        {commit: rows.encode()},
        {sha_a: len(payload_a), sha_b: len(payload_b)},
        {sha_a: payload_a, sha_b: payload_b},
    )
    hits = scan_history(root, runner=runner, max_blobs=1)
    assert len(hits) == 1


def test_scan_history_keeps_a_baselined_hit_suppressed(tmp_path: Path) -> None:
    root = _history_repo(tmp_path)
    runner, _commit, blob_sha = _token_history(HISTORY_TOKEN)
    hits = scan_history(root, runner=runner)
    assert hits
    baseline = Baseline(
        (
            BaselineEntry(
                fingerprint=fingerprint_hit(hits[0]),
                kind=hits[0].kind,
                rel_path=hits[0].rel_path,
                masked=hits[0].masked,
                created_at="2026-01-01T00:00:00+00:00",
            ),
        ),
        None,
        "",
    )
    assert scan_history(root, runner=runner, baseline=baseline) == []

    # An unrelated newer commit enters the window but does not change the commit
    # nor the path of the accepted finding, so it stays suppressed.
    newer = "e" * 40
    other_blob = "f" * 40
    payload = ("GITHUB_TOKEN=" + HISTORY_TOKEN + chr(10)).encode()
    clean = ("notes" + chr(10)).encode()
    expanded = _HistoryRunner(
        [newer, "c" * 40],
        {
            newer: _raw_row("0" * 40, other_blob, "A", "notes.txt").encode(),
            "c" * 40: _raw_row("0" * 40, blob_sha, "A", "legacy/env.py").encode(),
        },
        {blob_sha: len(payload), other_blob: len(clean)},
        {blob_sha: payload, other_blob: clean},
    )
    assert scan_history(root, runner=expanded, baseline=baseline) == []


def test_a_minified_line_does_not_stall_the_scanner() -> None:
    # A 200 KiB single line is what a bundled frontend file looks like; the
    # scanner must stay linear instead of backtracking over the whole line.
    started = time.perf_counter()
    assert scan_text("x" * 200_000, "dist/bundle.min.js") == []
    elapsed = time.perf_counter() - started
    assert elapsed < 5.0


def test_long_line_is_scanned_in_windows_without_duplicates() -> None:
    token = "ghp_" + "W" * 30
    line = ("x" * 10_000) + " GITHUB_TOKEN=" + token + " " + ("y" * 9_000)
    hits = scan_text(line, "dist/bundle.js")
    assert [hit.kind for hit in hits] == ["github_token"]
    assert hits[0].line_no == 1
    assert token not in hits[0].masked
    redacted, count = redact_text(line)
    assert count == 1
    assert token not in redacted
    assert "ghp_****REDACTED****" in redacted


def test_token_across_a_window_boundary_is_found() -> None:
    token = "ghp_" + "X" * 30
    line = ("x" * 4_090) + " " + token + ("y" * 2_000)
    hits = scan_text(line, "dist/bundle.js")
    assert [hit.kind for hit in hits] == ["github_token"]
    assert token not in hits[0].masked


def test_scan_history_loads_the_project_baseline(tmp_path: Path) -> None:
    import json

    from tauhaulity.tools.allowlist import baseline_path

    root = _history_repo(tmp_path)
    runner, _commit, _blob = _token_history(HISTORY_TOKEN)
    hits = scan_history(root, runner=runner)
    assert hits
    path = baseline_path(root)
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "fingerprint": fingerprint_hit(hits[0]),
                        "kind": hits[0].kind,
                        "rel_path": hits[0].rel_path,
                        "masked": hits[0].masked,
                        "created_at": "2026-01-01T00:00:00+00:00",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert scan_history(root, runner=runner) == []


def test_history_fingerprint_ignores_line_numbers() -> None:
    first = SecretHit("abc12345:src/app.py", 3, "github_token", "ghp_****REDACTED****")
    second = SecretHit("abc12345:src/app.py", 90, "github_token", "ghp_****REDACTED****")
    assert fingerprint_hit(first) == fingerprint_hit(second)


def test_scan_history_tolerates_malformed_output(tmp_path: Path) -> None:
    root = _history_repo(tmp_path)
    garbage = _HistoryRunner(["not-a-commit-id"], {"not-a-commit-id": b":broken"}, {}, {})
    assert scan_history(root, runner=garbage) == []

    commit = "c" * 40
    malformed = _HistoryRunner([commit], {commit: b":100644 broken row"}, {}, {})
    assert scan_history(root, runner=malformed) == []


def test_scan_history_validates_every_bound(tmp_path: Path) -> None:
    root = _history_repo(tmp_path)
    for kwargs in (
        {"max_commits": 0},
        {"max_commits": -3},
        {"max_commits": True},
        {"max_commits": "10"},
        {"max_blobs": 0},
        {"max_blob_bytes": 0},
    ):
        with pytest.raises(ValueError):
            scan_history(root, runner=lambda args, cwd: (1, b""), **kwargs)


def test_inspect_repository_reports_history_fields(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _history_repo(tmp_path)
    runner, _commit, _blob = _token_history(HISTORY_TOKEN)

    def default_runner(args, cwd):
        if args[:3] == ["git", "diff", "--cached"]:
            return (1, b"")
        return runner(args, cwd)

    monkeypatch.setattr(sentinel, "_default_runner", default_runner)
    report = inspect_repository(root, check_hook=False, history=True)
    assert report.history_hits == 1
    assert report.history_scanned == 1
    assert report.history_truncated is False
    assert report.history_secrets
    assert report.revoked_hints == [REVOCATION_HINTS["github_token"]]
    assert "git history" in report.findings_text
    assert HISTORY_TOKEN not in report.findings_text
    for hit in report.history_secrets:
        assert HISTORY_TOKEN not in hit.masked


def test_inspect_repository_marks_a_truncated_history(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _history_repo(tmp_path)
    commit = "c" * 40
    runner = _HistoryRunner([commit], {commit: b""}, {}, {})

    def default_runner(args, cwd):
        if args[:3] == ["git", "diff", "--cached"]:
            return (1, b"")
        return runner(args, cwd)

    monkeypatch.setattr(sentinel, "_default_runner", default_runner)
    report = inspect_repository(root, check_hook=False, history=True, history_max_commits=1)
    assert report.history_truncated is True
    assert report.history_hits == 0
    assert "truncated" in report.findings_text


def test_inspect_repository_skips_history_by_default(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _history_repo(tmp_path)
    calls: list[list[str]] = []

    def default_runner(args, cwd):
        calls.append(list(args))
        return (1, b"")

    monkeypatch.setattr(sentinel, "_default_runner", default_runner)
    report = inspect_repository(root, check_hook=False)
    assert report.history_hits == 0
    assert report.history_scanned == 0
    assert report.revoked_hints == []
    assert "git history" not in report.findings_text
    assert not any(call[:2] == ["git", "rev-list"] for call in calls)


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.setdefault("GIT_AUTHOR_NAME", "Tauhaulity Test")
    env.setdefault("GIT_AUTHOR_EMAIL", "test@example.test")
    env.setdefault("GIT_COMMITTER_NAME", "Tauhaulity Test")
    env.setdefault("GIT_COMMITTER_EMAIL", "test@example.test")
    return subprocess.run(
        ["git", *args], cwd=str(repo), capture_output=True, text=True, env=env, timeout=180
    )


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed on this host")
def test_real_history_scan_reports_a_deleted_token(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    token = "ghp_" + "M" * 30
    assert _git(repo, "init", "-q").returncode == 0
    (repo / ".env").write_text("GITHUB_TOKEN=" + token + chr(10), encoding="utf-8")
    assert _git(repo, "add", "-A").returncode == 0
    assert _git(repo, "commit", "-qm", "add token").returncode == 0
    (repo / ".env").write_text("clean" + chr(10), encoding="utf-8")
    assert _git(repo, "add", "-A").returncode == 0
    assert _git(repo, "commit", "-qm", "remove token").returncode == 0

    hits = scan_history(repo)
    assert hits
    assert all(":" in hit.rel_path for hit in hits)
    assert any(hit.kind == "github_token" for hit in hits)
    assert all(token not in hit.masked for hit in hits)

    report = inspect_repository(repo, check_hook=False, history=True)
    assert report.secrets == []
    assert report.history_hits >= 1
    assert token not in report.findings_text
    for hit in report.history_secrets:
        assert token not in hit.masked

    # The allowlist fingerprint of a history hit is stable when a later scan sees
    # the same commit from a different window position.
    baseline = Baseline(
        (
            BaselineEntry(
                fingerprint=fingerprint_hit(hits[0]),
                kind=hits[0].kind,
                rel_path=hits[0].rel_path,
                masked=hits[0].masked,
                created_at="2026-01-01T00:00:00+00:00",
            ),
        ),
        None,
        "",
    )
    suppressed = inspect_repository(repo, check_hook=False, history=True, baseline=baseline)
    assert suppressed.history_hits <= report.history_hits - 1

@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed on this host")
def test_real_history_batch_reads_every_small_blob(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    tokens = ["ghp_" + letter * 30 for letter in ("A", "B", "C")]
    assert _git(repo, "init", "-q").returncode == 0
    for index, token in enumerate(tokens):
        (repo / ("leak" + str(index) + ".env")).write_text(
            "GITHUB_TOKEN=" + token + chr(10), encoding="utf-8"
        )
    assert _git(repo, "add", "-A").returncode == 0
    assert _git(repo, "commit", "-qm", "three leaks").returncode == 0
    for index in range(len(tokens)):
        (repo / ("leak" + str(index) + ".env")).unlink()
    assert _git(repo, "add", "-A").returncode == 0
    assert _git(repo, "commit", "-qm", "remove leaks").returncode == 0

    hits = scan_history(repo)
    assert len(hits) == 3
    assert {hit.kind for hit in hits} == {"github_token"}
    assert all(token not in hit.masked for hit in hits for token in tokens)


@pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed on this host")
def test_real_history_scan_skips_binary_and_oversized_blobs(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir(parents=True)
    token = "ghp_" + "D" * 30
    assert _git(repo, "init", "-q").returncode == 0
    (repo / "blob.bin").write_bytes(b"\x00\x01binary" + token.encode() + b"\x00")
    (repo / "big.txt").write_text(
        token + chr(10) + "x" * 300_000, encoding="utf-8"
    )
    assert _git(repo, "add", "-A").returncode == 0
    assert _git(repo, "commit", "-qm", "assets").returncode == 0
    (repo / "blob.bin").unlink()
    (repo / "big.txt").unlink()
    assert _git(repo, "add", "-A").returncode == 0
    assert _git(repo, "commit", "-qm", "remove assets").returncode == 0

    # The binary blob is skipped by content and the oversized blob by its size.
    assert scan_history(repo, max_blob_bytes=262_144) == []
    # Raising the per blob bound lets the text blob through but still not the binary.
    widened = scan_history(repo, max_blob_bytes=1_000_000)
    assert len(widened) == 1
    assert widened[0].kind == "github_token"
    assert token not in widened[0].masked

# ---------------------------------------------------------------------------
# S2 follow-up: the candidate walk must not spend its bounded file budget on
# provisioning trees. A .tooling directory with an installed interpreter holds
# tens of thousands of files and sorts before src/, which used to fill the 200
# file cap with vendored code and leave the project's own files unscanned.
# ---------------------------------------------------------------------------


def _project_with_token(root: Path, token: str = "ghp_" + "Z" * 30) -> Path:
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text(
        "TOKEN = '" + token + "'" + chr(10), encoding="utf-8"
    )
    return root


def _relative_candidates(root: Path) -> set[str]:
    return {
        path.relative_to(root).as_posix() for path in sentinel._candidate_files(root)
    }


def test_candidate_walk_skips_a_provisioning_tree(tmp_path: Path) -> None:
    root = _project_with_token(tmp_path / "project")
    for index in range(250):
        package = (
            root
            / ".tooling"
            / "pythons"
            / "Lib"
            / "site-packages"
            / ("pkg%03d" % index)
        )
        package.mkdir(parents=True, exist_ok=True)
        (package / "module.py").write_text("VALUE = " + str(index) + chr(10), encoding="utf-8")

    relatives = _relative_candidates(root)
    assert relatives == {"src/app.py"}
    assert len(relatives) <= 200

    report = inspect_repository(root)
    assert [hit.rel_path for hit in report.secrets] == ["src/app.py"]
    assert report.scanned_files == 1


def test_generic_interpreter_installation_is_skipped(tmp_path: Path) -> None:
    root = _project_with_token(tmp_path / "project", "ghp_" + "Y" * 30)
    runtime = root / "vendor" / "runtime"
    (runtime / "Lib").mkdir(parents=True)
    (runtime / "python.exe").write_text("", encoding="utf-8")
    (runtime / "Lib" / "leaked.py").write_text(
        "TOKEN = 'ghp_" + "X" * 30 + "'" + chr(10), encoding="utf-8"
    )

    relatives = _relative_candidates(root)
    assert "src/app.py" in relatives
    assert "vendor/runtime/Lib/leaked.py" not in relatives
    report = inspect_repository(root)
    assert [hit.rel_path for hit in report.secrets] == ["src/app.py"]


def test_posix_interpreter_layout_is_skipped(tmp_path: Path) -> None:
    root = _project_with_token(tmp_path / "project", "ghp_" + "T" * 30)
    runtime = root / "vendor" / "posix-python"
    (runtime / "bin").mkdir(parents=True)
    (runtime / "lib" / "python3.12").mkdir(parents=True)
    (runtime / "bin" / "python3").write_text("", encoding="utf-8")
    (runtime / "lib" / "python3.12" / "leaked.py").write_text(
        "TOKEN = 'ghp_" + "S" * 30 + "'" + chr(10), encoding="utf-8"
    )

    report = inspect_repository(root)
    assert [hit.rel_path for hit in report.secrets] == ["src/app.py"]


def test_arbitrary_virtualenv_directory_is_skipped(tmp_path: Path) -> None:
    root = _project_with_token(tmp_path / "project", "ghp_" + "W" * 30)
    environment = root / "envs" / "custom"
    (environment / "Lib").mkdir(parents=True)
    (environment / "pyvenv.cfg").write_text("home = python" + chr(10), encoding="utf-8")
    (environment / "Lib" / "leaked.py").write_text(
        "TOKEN = 'ghp_" + "V" * 30 + "'" + chr(10), encoding="utf-8"
    )

    report = inspect_repository(root)
    assert [hit.rel_path for hit in report.secrets] == ["src/app.py"]


def test_hidden_project_directories_are_still_scanned(tmp_path: Path) -> None:
    # Skipping provisioning trees must not become "skip every dot directory":
    # workflow files are project source and can carry credentials.
    root = tmp_path / "project"
    (root / ".github" / "workflows").mkdir(parents=True)
    token = "ghp_" + "U" * 30
    (root / ".github" / "workflows" / "ci.yml").write_text(
        "token: " + token + chr(10), encoding="utf-8"
    )

    report = inspect_repository(root)
    assert [hit.rel_path for hit in report.secrets] == [".github/workflows/ci.yml"]
    assert token not in report.secrets[0].masked



