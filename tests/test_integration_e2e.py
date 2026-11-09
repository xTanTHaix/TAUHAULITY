"""End to end integration tests across the twelve pillars and the CLI.

These tests exercise the real service APIs that the CLI calls, on a synthetic
project tree created without git commands so the suite runs identically on
Windows, WSL Ubuntu and WSL Debian.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from tauhaulity.core.contracts import PILLAR_SPECS, Finding, ScanContext, ScanOptions, SPEC_BY_KEY, make_finding
from tauhaulity.core.platform_probe import detect_platform
from tauhaulity.core.policy import Policy
from tauhaulity.core.verdict import compute_verdict
from tauhaulity.engine import run_scan

pytestmark = pytest.mark.integration


def test_pillar_registry_is_complete() -> None:
    from tauhaulity.pillars import load_pillars

    probes = load_pillars(strict=True)
    assert len(probes) == len(PILLAR_SPECS) == 12
    assert [probe.spec.number for probe in probes] == list(range(1, 13))


def test_full_scan_writes_signed_dossiers(sample_project: Path) -> None:
    pytest.importorskip("tauhaulity.dossier.report")
    result = run_scan(sample_project, policy=Policy(), options=ScanOptions())
    assert set(result.report_paths) == {"md", "txt", "json"}
    for path in result.report_paths.values():
        assert Path(path).is_file() and Path(path).stat().st_size > 0
    assert result.report is not None
    from tauhaulity.dossier.report import verify_report

    assert verify_report(result.report)
    markdown = Path(result.report_paths["md"]).read_text(encoding="utf-8")
    for token in (
        "AEGIS-VMI",
        "HYPER-IMMUNE",
        "VERITAS-GATE",
        "CHRONO-DECEPTION",
        "CRYPTO-SHIELD",
        "SUPPLY-GUARD",
        "EGRESS-DLP",
        "RANSOM-ROLLBACK",
        "PORT-SENTINEL",
        "AUTONOMIC-VENV-RADAR",
        "GIT-DOSSIER-SENTINEL",
        "AUTO-REPRO-GEN",
    ):
        assert token in markdown, token
    payload = json.loads(Path(result.report_paths["json"]).read_text(encoding="utf-8"))
    assert payload["verdict"] == result.verdict.name
    assert len(payload["pillars"]) == 12
    assert payload["hmac_sha256"]


def test_scan_records_every_pillar_finding(sample_project: Path) -> None:
    result = run_scan(sample_project, write_reports=False)
    assert len(result.ctx.findings) == 12
    assert result.verdict.bitmask >= 0


def test_form_roundtrip_updates_policy(sample_project: Path) -> None:
    pytest.importorskip("tauhaulity.dossier.report")
    from tauhaulity.core.policy import policy_path
    from tauhaulity.dossier.form_parser import parse_form
    from tauhaulity.dossier.report import build_report, render_markdown

    result = run_scan(sample_project, write_reports=False)
    report = build_report(result.ctx)
    overrides = parse_form(render_markdown(report))
    merged = Policy().with_overrides(overrides)
    merged = merged.validate()
    assert isinstance(merged, Policy)
    merged.save(policy_path(sample_project))
    reloaded = Policy.load(policy_path(sample_project))
    assert reloaded.to_dict() == merged.to_dict()


def test_git_sentinel_detects_pat(sample_project: Path) -> None:
    from tauhaulity.tools.git_sentinel import inspect_repository, scan_text

    token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
    hits = scan_text("TOKEN=" + token + chr(10), "config.py")
    assert hits, "classic GitHub PAT must be detected"
    assert any(hit.masked != token for hit in hits)
    report = inspect_repository(sample_project)
    assert report.scanned_files >= 1
    assert report.hook_installed is False


def test_hook_install_and_remove(sample_project: Path) -> None:
    from tauhaulity.tools.hook_installer import hook_status, install_hook, uninstall_hook

    path = install_hook(sample_project, block=True)
    assert path.is_file()
    script = path.read_text(encoding="utf-8")
    assert "tauhaulity" in script
    installed, reported = hook_status(sample_project)
    assert installed and reported == path
    assert uninstall_hook(sample_project) is True
    assert hook_status(sample_project)[0] is False


def test_port_sweeper_sees_bound_socket() -> None:
    from tauhaulity.tools.port_sweeper import list_listening

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        entries = list_listening()
        observed = {getattr(entry, "local_port", getattr(entry, "port", 0)) for entry in entries}
        assert port in observed, f"port {port} not observed in {sorted(observed)[:20]}"
    finally:
        server.close()


def test_venv_radar_flags_injected_pth(sample_project: Path) -> None:
    from tauhaulity.tools.venv_radar import inspect_venv

    report = inspect_venv(sample_project)
    assert report.pth_files >= 1
    assert report.pth_findings, "code execution inside a .pth file must be flagged"
    assert report.status in {"MALICIOUS_PTH", "TAMPERED", "WARNING"}


def test_undo_restores_deleted_tree(sample_project: Path) -> None:
    from tauhaulity.daemon.undo_store import UndoStore

    tree = sample_project / "work" / "nested"
    tree.mkdir(parents=True)
    (tree / "keep.txt").write_text("precious" * 10, encoding="utf-8")
    store = UndoStore(sample_project, ring_mb=64)
    entries = store.capture([sample_project / "work"])
    assert entries and entries[0].bytes > 0
    shutil.rmtree(sample_project / "work")
    assert not (sample_project / "work").exists()
    restored = store.restore(entries[0].entry_id)
    assert restored.restored >= 2
    assert (tree / "keep.txt").read_text(encoding="utf-8") == "precious" * 10


def test_synthesized_repro_is_executable(tmp_path: Path) -> None:
    from tauhaulity.repro.synthesizer import AutoReproSynthesizer

    ctx = ScanContext(
        target=tmp_path,
        platform=detect_platform(),
        policy=Policy(),
        options=ScanOptions(),
    )
    spec = SPEC_BY_KEY["git_dossier"]
    finding = make_finding(
        spec,
        "LEAK_DETECTED",
        "GitHub PAT detected in config.py",
        risk=8.0,
        slots={"detail": "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"},
        repro_hint="github_pat",
    )
    synthesizer = AutoReproSynthesizer(tmp_path / "repro")
    script = synthesizer.synthesize(finding, ctx)
    assert script is not None and script.is_file()
    completed = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, timeout=120)
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_cli_audit_end_to_end(sample_project: Path, capsys) -> None:
    pytest.importorskip("tauhaulity.dossier.report")
    from tauhaulity.cli import main

    code = main(["audit", str(sample_project), "--export", "md,txt,json", "--json", "--no-repro"])
    assert code in {0, 1, 2}
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] in {"SAFE", "AT_RISK", "CRITICAL"}
    for path in payload["reports"].values():
        assert Path(path).is_file()


def test_verdict_aggregation_matches_findings(sample_project: Path) -> None:
    result = run_scan(sample_project, write_reports=False)
    verdict = compute_verdict(result.ctx)
    assert verdict.name == result.verdict.name
    assert verdict.risk == result.verdict.risk
