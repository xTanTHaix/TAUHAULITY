"""Pillar adapter tests for pillars eight to eleven.

The probes are the only place where the tools and daemons meet the dossier
contract, so these tests assert both the contract (legal status token, risk
range, recorded finding) and the two invariants that matter operationally:
a scan never mutates the project and a scan never terminates a process.
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
from pathlib import Path

import pytest

import tauhaulity.tools.git_sentinel as sentinel
import tauhaulity.tools.port_sweeper as port_sweeper
import tauhaulity.tools.venv_radar as venv_radar
from tauhaulity.core.contracts import SPEC_BY_NUMBER, Finding, ScanContext, ScanOptions
from tauhaulity.core.platform_probe import detect_platform
from tauhaulity.core.policy import Policy
from tauhaulity.pillars import p08_ransom, p09_ports, p10_venv, p11_git

SAMPLE_RAW_SECRETS = (
    "ghp_LeakedSecretValue9876543210abcdef",
    "ghp_RemoteUrlSecret1234567890",
    "ghp_ExampleTokenValueThatLooksReal1234567890",
)


def _context(root: Path, policy: Policy | None = None) -> ScanContext:
    return ScanContext(
        target=Path(root),
        platform=detect_platform(),
        policy=policy or Policy(),
        options=ScanOptions(),
    )


def test_pillar_specs_are_wired_to_the_shared_contract() -> None:
    assert p08_ransom.SPEC is SPEC_BY_NUMBER[8]
    assert p09_ports.SPEC is SPEC_BY_NUMBER[9]
    assert p10_venv.SPEC is SPEC_BY_NUMBER[10]
    assert p11_git.SPEC is SPEC_BY_NUMBER[11]
    assert p08_ransom.SPEC.statuses == ("PROTECTED", "UNPROTECTED", "WARNING")
    assert p09_ports.SPEC.statuses == ("CLEAN", "CONFLICT_DETECTED", "ZOMBIE_FOUND", "WARNING")
    assert p10_venv.SPEC.statuses == ("CLEAN", "TAMPERED", "MALICIOUS_PTH", "WARNING")
    assert p11_git.SPEC.statuses == ("SECURE", "LEAK_DETECTED", "WARNING")


def test_p08_protected_on_sample_project(sample_project: Path) -> None:
    ctx = _context(sample_project)
    finding = p08_ransom.probe(ctx)
    assert isinstance(finding, Finding)
    assert finding.pillar == 8
    assert finding.status == "PROTECTED"
    assert 0.0 <= finding.risk <= 10.0
    assert finding.slot("ring_size").endswith("MB")
    assert finding.slot("trash_status") == "EMPTY"
    assert "canary" in finding.detail
    ctx.record(finding)
    assert ctx.finding(8) is finding
    # A probe must be read only: it may not create the undo journal.
    assert not (sample_project / ".tauhaulity").exists()


def test_p08_uses_the_policy_ring_budget(sample_project: Path) -> None:
    finding = p08_ransom.probe(_context(sample_project, Policy(undo_ring_mb=32)))
    assert finding.slot("ring_size") == "32 MB"


def test_p08_reports_existing_restore_points(sample_project: Path) -> None:
    from tauhaulity.daemon.undo_store import UndoStore

    store = UndoStore(sample_project, ring_mb=16)
    store.capture([sample_project / "notes.txt"])
    finding = p08_ransom.probe(_context(sample_project))
    assert finding.status == "PROTECTED"
    assert finding.slot("trash_status").endswith("RESTORE POINTS")


def test_p08_unprotected_when_the_store_cannot_initialize(tmp_path: Path) -> None:
    target = tmp_path / "not-a-project.txt"
    target.write_text("x", encoding="utf-8")
    finding = p08_ransom.probe(_context(target))
    assert finding.status == "UNPROTECTED"
    assert finding.slot("trash_status") == "UNAVAILABLE"
    assert finding.repro_hint is not None
    assert "cannot initialize" in finding.detail


def test_p08_warns_on_ciphertext(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / "src").mkdir(parents=True)
    (root / "src" / "locked").write_bytes(os.urandom(8192))
    (root / "canary.txt").write_text("watch me", encoding="utf-8")
    finding = p08_ransom.probe(_context(root))
    assert finding.status == "WARNING"
    assert "ciphertext" in finding.detail
    assert finding.risk > 0.0


def test_p09_clean_without_listeners(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(port_sweeper, "list_listening", lambda: [])
    monkeypatch.setattr(port_sweeper, "backend_name", lambda: "procfs")
    finding = p09_ports.probe(_context(tmp_path))
    assert finding.status == "CLEAN"
    assert finding.slot("ports") == "none"
    assert finding.slot("zombies") == "0"
    assert finding.risk == 0.0


def test_p09_detects_a_development_port_conflict(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    entries = [
        port_sweeper.PortEntry(3000, "tcp", 111, "alpha"),
        port_sweeper.PortEntry(3000, "tcp", 222, "beta"),
    ]
    monkeypatch.setattr(port_sweeper, "list_listening", lambda: entries)
    monkeypatch.setattr(port_sweeper, "backend_name", lambda: "procfs")
    monkeypatch.setattr(port_sweeper, "zombie_entries", lambda rows: [])
    finding = p09_ports.probe(_context(tmp_path))
    assert finding.status == "CONFLICT_DETECTED"
    assert "3000" in finding.detail
    assert finding.slot("ports") == "2 listening"


def test_p09_detects_zombie_listeners(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    entries = [port_sweeper.PortEntry(8080, "tcp", 4242, "stale")]
    monkeypatch.setattr(port_sweeper, "list_listening", lambda: entries)
    monkeypatch.setattr(port_sweeper, "backend_name", lambda: "procfs")
    monkeypatch.setattr(port_sweeper, "zombie_entries", lambda rows: list(rows))
    finding = p09_ports.probe(_context(tmp_path))
    assert finding.status == "ZOMBIE_FOUND"
    assert finding.slot("zombies") == "1"
    assert "zombie" in finding.detail


def test_p09_warns_when_no_backend_is_available(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(port_sweeper, "list_listening", lambda: [])
    monkeypatch.setattr(port_sweeper, "backend_name", lambda: "unsupported")
    finding = p09_ports.probe(_context(tmp_path))
    assert finding.status == "WARNING"
    assert "no kernel socket table" in finding.detail


def test_p09_warns_when_enumeration_raises(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def explode():
        raise OSError("kernel denied the table")

    monkeypatch.setattr(port_sweeper, "list_listening", explode)
    finding = p09_ports.probe(_context(tmp_path))
    assert finding.status == "WARNING"
    assert finding.slot("ports") == "unknown"


def test_p09_never_terminates_a_process(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    entries = [
        port_sweeper.PortEntry(3000, "tcp", 111, "alpha"),
        port_sweeper.PortEntry(3000, "tcp", 222, "beta"),
    ]
    monkeypatch.setattr(port_sweeper, "list_listening", lambda: entries)
    monkeypatch.setattr(port_sweeper, "backend_name", lambda: "procfs")
    monkeypatch.setattr(port_sweeper, "zombie_entries", lambda rows: [])

    def forbidden(*args, **kwargs):
        raise AssertionError("a diagnostic scan must never terminate a process")

    monkeypatch.setattr(port_sweeper, "free_port", forbidden)
    monkeypatch.setattr(port_sweeper, "_terminate_force", forbidden)
    monkeypatch.setattr(port_sweeper, "_terminate_graceful", forbidden)
    finding = p09_ports.probe(_context(tmp_path))
    assert finding.status in p09_ports.SPEC.statuses


def test_p10_flags_a_malicious_pth(sample_project: Path, platform_info) -> None:
    ctx = _context(sample_project)
    finding = p10_venv.probe(ctx)
    assert finding.status == "MALICIOUS_PTH"
    assert finding.slot("engine_tier") == platform_info.engine_tier
    assert ".venv" in finding.slot("venv_status")
    assert finding.repro_hint is not None
    ctx.record(finding)
    assert ctx.finding(10) is finding


def test_p10_clean_without_a_virtual_environment(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("print(1)\n", encoding="utf-8")
    finding = p10_venv.probe(_context(tmp_path))
    assert finding.status == "CLEAN"
    assert finding.slot("venv_status") == "CLEAN"
    assert "engine tier" in finding.detail


def test_p10_warns_when_the_radar_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def explode(root):
        raise OSError("site-packages unreadable")

    monkeypatch.setattr(venv_radar, "inspect_venv", explode)
    finding = p10_venv.probe(_context(tmp_path))
    assert finding.status == "WARNING"
    assert finding.slot("venv_status") == "UNKNOWN"


def test_p10_reports_tampering(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    report = venv_radar.VenvReport(
        venv_path=tmp_path / ".venv",
        pth_files=1,
        pth_findings=[],
        suspicious_binaries=["evil.dll"],
        permission_anomalies=[],
        status="TAMPERED",
        detail="1 unindexed binary",
    )
    monkeypatch.setattr(venv_radar, "inspect_venv", lambda root: report)
    finding = p10_venv.probe(_context(tmp_path))
    assert finding.status == "TAMPERED"
    assert finding.repro_hint is not None


def _clean_project(root: Path) -> Path:
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (root / "README.md").write_text("# clean project\n", encoding="utf-8")
    (root / ".git").mkdir()
    return root


def test_p11_detects_leaks_and_never_echoes_them(
    monkeypatch: pytest.MonkeyPatch, sample_project: Path
) -> None:
    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    ctx = _context(sample_project)
    finding = p11_git.probe(ctx)
    assert finding.status == "LEAK_DETECTED"
    assert finding.slot("token_status").endswith("SECRETS")
    assert int(finding.slot("redacted_count")) >= 2
    assert finding.slot("hook_status") == "MISSING"
    assert "****REDACTED****" in finding.detail
    for secret in SAMPLE_RAW_SECRETS:
        assert secret not in finding.detail
        for value in finding.slots.values():
            assert secret not in value
    ctx.record(finding)
    assert ctx.finding(11) is finding


def test_p11_secure_when_the_gate_is_installed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from tauhaulity.tools.hook_installer import install_hook

    root = _clean_project(tmp_path / "clean")
    install_hook(root)
    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    finding = p11_git.probe(_context(root))
    assert finding.status == "SECURE"
    assert finding.slot("hook_status") == "INSTALLED"
    assert finding.slot("token_status") == "CLEAN"
    assert finding.slot("redacted_count") == "0"
    assert len(finding.slot("hmac")) == 32


def test_p11_clean_project_without_the_gate_is_still_secure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # A repository cannot be expected to carry the pre-commit gate before
    # anything is wrong, so a missing hook must not drive the overall verdict.
    root = _clean_project(tmp_path / "clean")
    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    finding = p11_git.probe(_context(root))
    assert finding.status == "SECURE"
    assert finding.risk == 0.0
    assert finding.slot("hook_status") == "MISSING"
    assert "run tauhaulity hook install" in finding.detail
    assert finding.repro_hint is None


def test_p11_hmac_matches_the_dossier_helper(
    monkeypatch: pytest.MonkeyPatch, sample_project: Path
) -> None:
    redactor = pytest.importorskip("tauhaulity.dossier.redactor")
    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    finding = p11_git.probe(_context(sample_project))
    expected = redactor.hmac_sha256_hex(
        finding.detail + "|" + finding.slot("redacted_count")
    )[:32]
    assert finding.slot("hmac") == expected


def test_p11_warns_when_inspection_fails(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    def explode(root, **kwargs):
        raise OSError("repository unreadable")

    monkeypatch.setattr(sentinel, "inspect_repository", explode)
    finding = p11_git.probe(_context(tmp_path))
    assert finding.status == "WARNING"
    assert finding.slot("token_status") == "UNKNOWN"
    assert len(finding.slot("hmac")) == 32


@pytest.mark.parametrize(
    "module",
    [p08_ransom, p09_ports, p10_venv, p11_git],
    ids=["p08", "p09", "p10", "p11"],
)
def test_every_probe_is_fast_and_contract_clean(
    module, monkeypatch: pytest.MonkeyPatch, sample_project: Path
) -> None:
    if module is p11_git:
        monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    ctx = _context(sample_project)
    started = time.perf_counter()
    finding = module.probe(ctx)
    elapsed = time.perf_counter() - started
    ctx.record(finding)
    assert finding.status in module.SPEC.statuses
    assert 0.0 <= finding.risk <= module.SPEC.risk_scale
    assert finding.detail
    assert elapsed < 2.5

def _secret_project(root: Path) -> Path:
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text(
        "TOKEN = 'ghp_" + "A" * 30 + "'" + chr(10), encoding="utf-8"
    )
    return root


def test_p11_reports_baseline_suppression(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from tauhaulity.tools.allowlist import write_baseline

    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    root = _secret_project(tmp_path / "baselined")
    written = write_baseline(root)
    assert written.total >= 1
    finding = p11_git.probe(_context(root))
    assert finding.slot("token_status") == "CLEAN"
    assert finding.slot("suppressed") == str(written.total)
    assert (
        str(written.total) + " candidate(s) suppressed by the baseline"
        in finding.detail
    )
    # Nothing is active, so the clean verdict holds; the baseline work is visible
    # in the detail and carries a small honest risk instead of a warning status.
    assert finding.status == "SECURE"
    assert finding.risk == 0.5
    raw = "ghp_" + "A" * 30
    assert raw not in finding.detail
    for value in finding.slots.values():
        assert raw not in value


def test_p11_new_secret_after_baseline_is_still_reported(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from tauhaulity.tools.allowlist import write_baseline

    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    root = _secret_project(tmp_path / "baselined")
    write_baseline(root)
    (root / "src" / "fresh.py").write_text(
        "TOKEN = 'ghp_" + "B" * 30 + "'" + chr(10), encoding="utf-8"
    )
    finding = p11_git.probe(_context(root))
    assert finding.status == "LEAK_DETECTED"
    assert finding.slot("token_status").endswith("SECRETS")
    assert int(finding.slot("redacted_count")) >= 1
    assert "suppressed by the baseline" in finding.detail


def test_p11_detail_always_states_the_suppressed_count(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    root = _clean_project(tmp_path / "clean")
    finding = p11_git.probe(_context(root))
    assert "0 candidate(s) suppressed by the baseline" in finding.detail

# ---------------------------------------------------------------------------
# S4: verifiable virtual environment integrity (RECORD hashes, startup hooks,
# typosquat). These tests drive pillar ten through synthetic environments so the
# status ladder is proven with real evidence instead of a stubbed report.


def _p10_digest(payload: bytes) -> str:
    """Return the RECORD style urlsafe base64 sha256 digest."""

    return base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()


def _p10_environment(root: Path) -> tuple[Path, Path]:
    """Create an empty environment and return (venv, site-packages)."""

    venv = root / ".venv"
    site = venv / "lib" / "python3.12" / "site-packages"
    site.mkdir(parents=True)
    return venv, site


def _p10_record(
    site: Path,
    entries: list[tuple[str, str]],
    dist: str = "demo",
    version: str = "1.0",
) -> Path:
    """Write a dist-info RECORD file; digests must already be hash specs."""

    info = site / (dist + "-" + version + ".dist-info")
    info.mkdir(parents=True, exist_ok=True)
    lines = [rel + "," + spec for rel, spec in entries]
    lines.append(info.name + "/RECORD,,")
    (info / "RECORD").write_text(chr(10).join(lines) + chr(10), encoding="utf-8")
    return info


def test_p10_malicious_detail_keeps_engine_tier_and_evidence(
    sample_project: Path, platform_info
) -> None:
    finding = p10_venv.probe(_context(sample_project))
    assert finding.status == "MALICIOUS_PTH"
    assert "engine tier " + platform_info.engine_tier in finding.detail
    assert "1 high" in finding.detail
    assert "top: " in finding.detail
    assert ".pth" in finding.detail
    assert finding.repro_hint is not None
    assert ".pth" in finding.repro_hint


def test_p10_record_mismatch_is_tampered(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venvdir, site = _p10_environment(root)
    (site / "pkg.py").write_bytes(b"print('modified')" + b"\n")
    _p10_record(site, [("pkg.py", "sha256=" + _p10_digest(b"print('original')\n"))])
    finding = p10_venv.probe(_context(root))
    assert finding.status == "TAMPERED"
    assert "RECORD 1 checked / 1 mismatch" in finding.detail
    assert "sha256" in (finding.repro_hint or "")


def test_p10_correct_record_is_clean(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venvdir, site = _p10_environment(root)
    payload = b"VALUE = 1\n"
    (site / "pkg.py").write_bytes(payload)
    _p10_record(site, [("pkg.py", "sha256=" + _p10_digest(payload))])
    finding = p10_venv.probe(_context(root))
    assert finding.status == "CLEAN"
    assert "RECORD 1 checked / 0 mismatch" in finding.detail
    assert finding.risk == 0.0


def test_p10_startup_hook_is_tampered_not_malicious(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venvdir, site = _p10_environment(root)
    (site / "sitecustomize.py").write_text("import os\n", encoding="utf-8")
    finding = p10_venv.probe(_context(root))
    assert finding.status == "TAMPERED"
    assert "startup 1" in finding.detail


def test_p10_typosquat_is_tampered(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venvdir, site = _p10_environment(root)
    _p10_record(site, [], dist="reqeusts", version="2.31.0")
    finding = p10_venv.probe(_context(root))
    assert finding.status == "TAMPERED"
    assert "typosquat 1" in finding.detail
    assert "requests" in (finding.repro_hint or "")


def test_p10_reports_record_truncation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(venv_radar, "MAX_RECORD_FILES", 1)
    root = tmp_path / "project"
    _venvdir, site = _p10_environment(root)
    payload = b"VALUE = 1\n"
    for name in ("one.py", "two.py"):
        (site / name).write_bytes(payload)
    _p10_record(
        site,
        [(name, "sha256=" + _p10_digest(payload)) for name in ("one.py", "two.py")],
    )
    finding = p10_venv.probe(_context(root))
    assert "truncated" in finding.detail
    assert finding.status in p10_venv.SPEC.statuses


def test_p10_probe_stays_under_two_seconds(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venvdir, site = _p10_environment(root)
    entries: list[tuple[str, str]] = []
    for index in range(300):
        name = "mod%03d.py" % index
        payload = ("VALUE = %d" % index).encode("ascii")
        (site / name).write_bytes(payload)
        entries.append((name, "sha256=" + _p10_digest(payload)))
    _p10_record(site, entries, dist="bulk", version="1.0")
    started = time.perf_counter()
    finding = p10_venv.probe(_context(root))
    elapsed = time.perf_counter() - started
    assert finding.status == "CLEAN"
    assert elapsed < 2.0

# ---------------------------------------------------------------------------
# S2: git history leaks and revocation hints through pillar eleven
# ---------------------------------------------------------------------------


def _p11_fake_git(*, token: str | None, commits: list[str] | None = None):
    """Return a git runner whose history holds one token blob."""

    history = ["c" * 40] if commits is None else list(commits)
    blob_sha = "b" * 40
    payload = (
        ("GITHUB_TOKEN=" + token + chr(10)).encode()
        if token
        else ("clean" + chr(10)).encode()
    )
    row = (
        ":"
        + "100644 100644 "
        + "0" * 40
        + " "
        + blob_sha
        + " A"
        + chr(9)
        + "legacy/env.py"
    )

    def runner(args, cwd):
        if args[:3] == ["git", "diff", "--cached"]:
            return (1, b"")
        if args[:2] == ["git", "log"]:
            payload_log = ""
            for commit in history:
                payload_log += chr(1) + commit + chr(10)
                if token:
                    payload_log += row + chr(10)
            return (0, payload_log.encode())
        if args[:3] == ["git", "cat-file", "-s"]:
            return (0, str(len(payload)).encode())
        if args[:3] == ["git", "cat-file", "blob"]:
            return (0, payload)
        return (1, b"")

    return runner


def test_p11_detects_a_history_only_leak(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    token = "ghp_" + "R" * 30
    root = _clean_project(tmp_path / "clean")
    monkeypatch.setattr(sentinel, "_default_runner", _p11_fake_git(token=token))
    finding = p11_git.probe(_context(root))
    assert finding.status == "LEAK_DETECTED"
    assert finding.risk == 9.0
    assert finding.slot("history_count") == "1"
    assert finding.slot("token_status") == "1 SECRETS"
    assert finding.slot("hook_status") == "MISSING"
    assert "1 in git history" in finding.detail
    assert "revoke" in finding.detail
    assert "****REDACTED****" in finding.detail
    assert token not in finding.detail
    for value in finding.slots.values():
        assert token not in value
    assert finding.repro_hint is not None


def test_p11_clean_project_with_clean_history_is_secure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _clean_project(tmp_path / "clean")
    monkeypatch.setattr(
        sentinel, "_default_runner", _p11_fake_git(token=None, commits=[])
    )
    finding = p11_git.probe(_context(root))
    assert finding.status == "SECURE"
    assert finding.risk == 0.0
    assert finding.slot("history_count") == "0"
    assert finding.slot("token_status") == "CLEAN"
    assert "run tauhaulity hook install" in finding.detail


def test_p11_detail_states_current_and_history_counts(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _clean_project(tmp_path / "clean")
    (root / ".env").write_text(
        "GITHUB_TOKEN=ghp_" + "T" * 30 + chr(10), encoding="utf-8"
    )
    monkeypatch.setattr(
        sentinel, "_default_runner", _p11_fake_git(token="ghp_" + "U" * 30)
    )
    finding = p11_git.probe(_context(root))
    assert finding.status == "LEAK_DETECTED"
    assert "1 credential candidate(s) redacted" in finding.detail
    assert "1 in git history" in finding.detail
    assert finding.slot("history_count") == "1"
    assert finding.slot("token_status") == "2 SECRETS"


def test_p11_baseline_suppresses_a_history_finding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import json

    from tauhaulity.tools.allowlist import baseline_path, fingerprint_hit
    from tauhaulity.tools.git_sentinel import SecretHit

    token = "ghp_" + "V" * 30
    root = _clean_project(tmp_path / "clean")
    monkeypatch.setattr(sentinel, "_default_runner", _p11_fake_git(token=token))

    accepted = SecretHit("cccccccc:legacy/env.py", 1, "github_token", "ghp_****REDACTED****")
    entry = {
        "fingerprint": fingerprint_hit(accepted),
        "kind": accepted.kind,
        "rel_path": accepted.rel_path,
        "masked": accepted.masked,
        "created_at": "2026-01-01T00:00:00+00:00",
    }
    path = baseline_path(root)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"version": 1, "entries": [entry]}), encoding="utf-8")

    finding = p11_git.probe(_context(root))
    assert finding.status == "SECURE"
    assert finding.risk == 0.5
    assert finding.slot("history_count") == "0"
    assert finding.slot("suppressed") == "1"
    assert finding.slot("token_status") == "CLEAN"
    assert "suppressed by the baseline" in finding.detail
    assert token not in finding.detail


def test_p11_bounds_the_history_walk(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _clean_project(tmp_path / "clean")
    calls: list[list[str]] = []
    fake = _p11_fake_git(token=None, commits=[])

    def recording(args, cwd):
        calls.append(list(args))
        return fake(args, cwd)

    monkeypatch.setattr(sentinel, "_default_runner", recording)
    p11_git.probe(_context(root))
    log_calls = [call for call in calls if call[:2] == ["git", "log"]]
    assert log_calls
    assert "--max-count=" + str(p11_git._HISTORY_MAX_COMMITS) in log_calls[0]


def test_p11_history_truncation_is_visible(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _clean_project(tmp_path / "clean")
    commits = ["%040x" % index for index in range(p11_git._HISTORY_MAX_COMMITS)]
    monkeypatch.setattr(
        sentinel, "_default_runner", _p11_fake_git(token=None, commits=commits)
    )
    finding = p11_git.probe(_context(root))
    assert finding.status == "SECURE"
    assert finding.slot("history_count") == "0"
    assert "truncated at bound" in finding.detail


def test_p11_detail_lists_a_hint_for_each_active_family(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = _clean_project(tmp_path / "clean")
    (root / ".env").write_text(
        "DATABASE_URL=postgres://app:hunter2pass@db.example.test/app" + chr(10),
        encoding="utf-8",
    )
    monkeypatch.setattr(
        sentinel, "_default_runner", _p11_fake_git(token="ghp_" + "W" * 30)
    )
    finding = p11_git.probe(_context(root))
    assert finding.status == "LEAK_DETECTED"
    assert "rotate the database password" in finding.detail
    assert "revoke the GitHub token" in finding.detail
    assert "hunter2pass" not in finding.detail
    assert finding.slot("history_count") == "1"


def test_p11_probe_on_this_repository_stays_under_two_seconds(
    project_root: Path,
) -> None:
    # This checkout has no git metadata, so the history walk is skipped and the
    # probe cost stays the bounded file walk.
    started = time.perf_counter()
    finding = p11_git.probe(_context(project_root))
    elapsed = time.perf_counter() - started
    assert finding.status in p11_git.SPEC.statuses
    assert finding.slot("history_count") == "0"
    assert elapsed < 2.0




def test_p09_flags_wildcard_development_listener(tmp_path: Path) -> None:
    """A development service bound to every interface must be reported.

    The same service on the loopback address must stay CLEAN, otherwise the rule
    would fire on every laptop and teach the reader to ignore the pillar.
    """

    import socket

    from tauhaulity.pillars import p09_ports as pillar

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    bound = 0
    for candidate in pillar.EXPOSURE_PORTS:
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("0.0.0.0", candidate))
            probe.listen(1)
        except OSError:
            probe.close()
            continue
        server.close()
        server = probe
        bound = candidate
        break
    if not bound:
        pytest.skip("every development port is already in use on this host")
    try:
        finding = pillar.probe(_context(tmp_path))
        assert finding.status == "WARNING", finding.detail
        assert "reachable" in finding.detail
        assert str(bound) in finding.detail
    finally:
        server.close()
