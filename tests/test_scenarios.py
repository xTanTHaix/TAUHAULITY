"""Scenario tests for the onboarding surface and the safety rails.

These tests drive the real CLI as a subprocess where the interaction matters
(stdin being a pipe, exit codes for CI) and through the engine directly where a
subprocess would only blur the measurement.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from tauhaulity.core.contracts import ScanOptions
from tauhaulity.core.policy import Policy
from tauhaulity.engine import run_scan

PYTHON = sys.executable
TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def _cli(args: list[str], *, cwd: Path, stdin: int | None = subprocess.DEVNULL) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["TAUHAULITY_NO_AUTO"] = "1"
    # Simulate an installed console script: the checkout root is importable even
    # when the command runs from an unrelated project directory. The hook gate is
    # deliberately NOT given this help, so it must embed its own package root.
    checkout = str(Path(__file__).resolve().parents[1])
    env["PYTHONPATH"] = checkout + os.pathsep + env.get("PYTHONPATH", "")
    return subprocess.run(
        [PYTHON, "-m", "tauhaulity", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        stdin=stdin,
        env=env,
        timeout=300,
    )


def _toy_project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("VALUE = 1" + chr(10), encoding="utf-8")
    return root


def test_free_refuses_without_confirmation_when_not_interactive(tmp_path: Path) -> None:
    completed = _cli(["free", "64999"], cwd=tmp_path)
    assert completed.returncode == 1
    combined = completed.stdout + completed.stderr
    assert "--yes" in combined
    assert "terminated" not in combined


def test_free_dry_run_never_signals(tmp_path: Path) -> None:
    completed = _cli(["free", "64999", "--dry-run"], cwd=tmp_path)
    assert completed.returncode == 0
    assert "nothing was signalled" in completed.stdout


def test_rm_dry_run_keeps_the_file(tmp_path: Path) -> None:
    root = _toy_project(tmp_path)
    target = root / "src" / "app.py"
    completed = _cli(["rm", str(target), "--root", str(root), "--dry-run"], cwd=root)
    assert completed.returncode == 0
    assert target.is_file()
    assert "would capture" in completed.stdout


def test_rm_then_undo_through_the_cli(tmp_path: Path) -> None:
    root = _toy_project(tmp_path)
    target = root / "src" / "app.py"
    removed = _cli(["rm", str(target), "--root", str(root)], cwd=root)
    assert removed.returncode == 0
    assert not target.exists()
    restored = _cli(["undo", "--root", str(root)], cwd=root)
    assert restored.returncode == 0
    assert target.is_file()


def _git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.setdefault("GIT_AUTHOR_NAME", "Tauhaulity Test")
    env.setdefault("GIT_AUTHOR_EMAIL", "test@example.test")
    env.setdefault("GIT_COMMITTER_NAME", "Tauhaulity Test")
    env.setdefault("GIT_COMMITTER_EMAIL", "test@example.test")
    return subprocess.run(
        ["git", *args],
        cwd=str(root),
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
    )


def test_pre_commit_gate_blocks_a_real_commit(tmp_path: Path) -> None:
    import shutil

    if shutil.which("git") is None:
        pytest.skip("git is not installed on this host")
    root = _toy_project(tmp_path)
    assert _git(root, "init", "-q").returncode == 0
    installed = _cli(["hook", "install", str(root)], cwd=root)
    assert installed.returncode == 0, installed.stdout + installed.stderr
    (root / ".env").write_text("GITHUB_TOKEN=" + TOKEN + chr(10), encoding="utf-8")
    assert _git(root, "add", ".env").returncode == 0
    blocked = _git(root, "commit", "-m", "leak attempt")
    assert blocked.returncode != 0, "the gate must abort a commit containing a PAT"
    combined = blocked.stdout + blocked.stderr
    assert "tauhaulity" in combined.lower()
    assert TOKEN not in combined, "the gate must never echo the raw secret"
    (root / ".env").unlink()
    (root / "safe.txt").write_text("clean" + chr(10), encoding="utf-8")
    # Stage the deletion too: the gate inspects the index, so an unstaged removal
    # still leaves the credential blob staged and must keep blocking.
    assert _git(root, "add", "-A").returncode == 0
    allowed = _git(root, "commit", "-m", "clean change")
    assert allowed.returncode == 0, allowed.stdout + allowed.stderr


def test_baseline_writes_allowlist(tmp_path: Path) -> None:
    root = _toy_project(tmp_path)
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text(
        "[remote " + chr(34) + "origin" + chr(34) + "]" + chr(10)
        + "	url = https://user:" + TOKEN + "@example.test/repo.git" + chr(10),
        encoding="utf-8",
    )
    completed = _cli(["baseline", str(root)], cwd=root)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    allowlist = root / ".tauhaulity" / "allowlist.json"
    assert allowlist.is_file()
    payload = json.loads(allowlist.read_text(encoding="utf-8"))
    assert payload["entries"]


def test_setup_skips_hook_without_git(tmp_path: Path) -> None:
    root = _toy_project(tmp_path)
    completed = _cli(["setup", str(root)], cwd=root)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "no .git directory" in completed.stdout
    assert not (root / ".tauhaulity" / "allowlist.json").exists(), "setup must not baseline by default"


def test_setup_installs_gate_in_a_repository(tmp_path: Path) -> None:
    root = _toy_project(tmp_path)
    (root / ".git" / "hooks").mkdir(parents=True)
    completed = _cli(["setup", str(root)], cwd=root)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert (root / ".git" / "hooks" / "pre-commit").is_file()


def test_setup_then_gate_blocks_a_staged_secret(tmp_path: Path) -> None:
    import shutil

    if shutil.which("git") is None:
        pytest.skip("git is not installed on this host")
    root = _toy_project(tmp_path)
    assert _git(root, "init", "-q").returncode == 0
    completed = _cli(["setup", str(root)], cwd=root)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    (root / ".env").write_text("GITHUB_TOKEN=" + TOKEN + chr(10), encoding="utf-8")
    assert _git(root, "add", ".env").returncode == 0
    blocked = _git(root, "commit", "-m", "onboarding leak")
    assert blocked.returncode != 0, "setup must leave the gate blocking real secrets"
    assert TOKEN not in (blocked.stdout + blocked.stderr)


def test_setup_baseline_flag_accepts_fixtures(tmp_path: Path) -> None:
    root = _toy_project(tmp_path)
    (root / ".git").mkdir()
    (root / ".git" / "config").write_text(
        "[remote " + chr(34) + "origin" + chr(34) + "]" + chr(10)
        + "	url = https://user:" + TOKEN + "@example.test/repo.git" + chr(10),
        encoding="utf-8",
    )
    completed = _cli(["setup", str(root), "--baseline"], cwd=root)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert (root / ".tauhaulity" / "allowlist.json").is_file()


def test_watch_stops_after_duration(tmp_path: Path) -> None:
    root = _toy_project(tmp_path)
    completed = _cli(["watch", str(root), "--duration", "0.4", "--interval", "0.1"], cwd=root)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "watch stopped" in completed.stdout


def test_verify_json_roundtrip_and_tamper(tmp_path: Path) -> None:
    root = _toy_project(tmp_path)
    audit = _cli(["audit", str(root), "--export", "md,txt,json", "--no-repro", "--json"], cwd=root)
    assert audit.returncode in {0, 1, 2}, audit.stderr
    report = root / "tauhaulity_report.json"
    assert report.is_file()
    good = _cli(["verify", str(report)], cwd=root)
    assert good.returncode == 0, good.stdout + good.stderr
    assert "VALID" in good.stdout
    damaged = root / "damaged.json"
    payload = json.loads(report.read_text(encoding="utf-8"))
    # Mutate a value that is guaranteed to differ regardless of the host: a pillar
    # status can legitimately already be CRITICAL on another interpreter version,
    # which would make a status flip a no-op and hide a broken verifier.
    payload["scan_timestamp_utc"] = "1999-01-01T00:00:00Z"
    damaged.write_text(json.dumps(payload, indent=2) + chr(10), encoding="utf-8")
    bad = _cli(["verify", str(damaged)], cwd=root)
    assert bad.returncode == 1
    assert "INVALID" in bad.stdout


def test_zipapp_builds_and_runs(tmp_path: Path) -> None:
    output = tmp_path / "tauhaulity.pyz"
    build = subprocess.run(
        [PYTHON, "scripts/build_zipapp.py", "--output", str(output)],
        cwd=str(Path(__file__).resolve().parents[1]),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert build.returncode == 0, build.stdout + build.stderr
    assert output.is_file() and output.stat().st_size > 10_000
    project = _toy_project(tmp_path)
    run = subprocess.run(
        [PYTHON, str(output), "doctor", "--root", str(project)],
        cwd=str(project),
        capture_output=True,
        text=True,
        timeout=300,
        env={**os.environ, "TAUHAULITY_NO_AUTO": "1"},
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert "TAUHAULITY DOCTOR" in run.stdout
    assert "result: healthy" in run.stdout
    assert "0/12" not in run.stdout


def test_bench_command_reports_rows(tmp_path: Path) -> None:
    root = _toy_project(tmp_path)
    completed = _cli(["bench", "--root", str(root), "--runs", "1", "--json"], cwd=root)
    assert completed.returncode == 0, completed.stdout + completed.stderr
    rows = json.loads(completed.stdout)
    names = {row["name"] for row in rows}
    assert "scan (12 pillars, no reports)" in names
    assert "doctor self-check" in names
    assert all(row["runs"] == 1 for row in rows)


def test_scan_scales_to_many_files(tmp_path: Path) -> None:
    root = tmp_path / "many"
    root.mkdir()
    for index in range(2000):
        (root / f"file_{index:04d}.txt").write_text("line " + str(index) + chr(10), encoding="utf-8")
    started = time.perf_counter()
    result = run_scan(root, policy=Policy(), options=ScanOptions(generate_repro=False, record_telemetry=False), write_reports=False)
    elapsed = time.perf_counter() - started
    assert len(result.ctx.findings) == 12
    assert elapsed < 60.0, f"scan of 2000 files took {elapsed:.1f}s"


def test_concurrent_scans_do_not_corrupt_each_other(tmp_path: Path) -> None:
    root = _toy_project(tmp_path)
    outcomes: list[str] = []
    errors: list[BaseException] = []

    def work() -> None:
        try:
            result = run_scan(root, options=ScanOptions(generate_repro=False, record_telemetry=False), write_reports=False)
            outcomes.append(result.verdict.name)
        except BaseException as exc:  # surface any race instead of hiding it
            errors.append(exc)

    threads = [threading.Thread(target=work) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=120)
    assert not errors
    assert len(outcomes) == 4
    assert len(set(outcomes)) == 1


def test_sources_and_docs_are_latin_script_only() -> None:
    root = Path(__file__).resolve().parents[1]
    ranges = ((0x0E00, 0x0E80), (0xAC00, 0xD7A4), (0x4E00, 0x9FFF))
    offenders: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in {".py", ".md", ".txt", ".toml"}:
            continue
        if ".tooling" in path.parts or "__pycache__" in path.parts:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        if any(any(low <= ord(char) < high for low, high in ranges) for char in text):
            offenders.append(str(path.relative_to(root)))
    assert offenders == []
