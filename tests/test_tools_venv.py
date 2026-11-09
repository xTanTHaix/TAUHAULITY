"""Tests for the virtual environment integrity radar.

The suite builds synthetic site-packages trees because every interesting case is
destructive to prove on a real machine: a corrupted RECORD digest, a startup
hook, a typosquat and a .pth that adds a directory outside the environment.

RECORD digests are computed the same way pip writes them (urlsafe base64 sha256
without padding), so the tests exercise the real verification path.
"""

from __future__ import annotations

import base64
import hashlib
import os
import sys
import time
from pathlib import Path

import pytest

import tauhaulity.tools.venv_radar as venv_radar
from tauhaulity.tools.venv_radar import (
    PthFinding,
    VenvReport,
    find_venvs,
    inspect_venv,
)


def _environment(root: Path, version: str = "python3.12") -> tuple[Path, Path]:
    """Create an empty environment and return (venv, site-packages)."""

    venv = root / ".venv"
    site = venv / "lib" / version / "site-packages"
    site.mkdir(parents=True)
    return venv, site


def _digest(payload: bytes) -> str:
    """Return the RECORD style urlsafe base64 sha256 digest."""

    return base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()


def _record(
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
    (info / "RECORD").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return info


def test_inspect_venv_flags_executable_pth(sample_project: Path) -> None:
    report = inspect_venv(sample_project)
    assert isinstance(report, VenvReport)
    assert report.status == "MALICIOUS_PTH"
    assert report.venv_path is not None
    assert report.venv_path.name == ".venv"
    assert report.pth_files == 1
    assert report.pth_findings
    finding = report.pth_findings[0]
    assert isinstance(finding, PthFinding)
    assert finding.code in {"EXEC_IMPORT", "EXEC_CALL"}
    assert finding.severity == "high"
    assert finding.rel_path.endswith("totally_legit.pth")
    assert "1 high" in report.detail


def test_inspect_venv_without_environment_is_clean(tmp_path: Path) -> None:
    report = inspect_venv(tmp_path)
    assert report.status == "CLEAN"
    assert report.venv_path is None
    assert report.pth_files == 0
    assert report.pth_findings == []
    assert report.record_checked == 0
    assert report.truncated is False
    assert "no virtual environment" in report.detail


def test_inspect_venv_accepts_a_resolvable_relative_pth(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venv, site = _environment(root)
    (site / "mylib").mkdir()
    (site / "mylib.pth").write_text("mylib\n", encoding="utf-8")
    report = inspect_venv(root)
    assert report.pth_files == 1
    assert report.pth_findings == []
    assert report.status == "CLEAN"


def test_inspect_venv_reports_dangling_pth_target_as_advisory(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venv, site = _environment(root)
    (site / "ghost.pth").write_text("not_installed_package\n", encoding="utf-8")
    report = inspect_venv(root)
    assert [finding.code for finding in report.pth_findings] == ["dangling_path"]
    assert report.pth_findings[0].severity == "low"
    assert report.status == "CLEAN"


def test_inspect_venv_flags_path_injection_outside_the_environment(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venv, site = _environment(root)
    outside = tmp_path / "outside"
    outside.mkdir()
    (site / "outside.pth").write_text(str(outside) + "\n", encoding="utf-8")
    report = inspect_venv(root)
    assert [finding.code for finding in report.pth_findings] == ["path_injection"]
    assert report.pth_findings[0].severity == "medium"
    assert report.status == "TAMPERED"


def test_inspect_venv_flags_exec_call_payload(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venv, site = _environment(root)
    (site / "hook.pth").write_text('exec("import os")\n', encoding="utf-8")
    report = inspect_venv(root)
    assert report.status == "MALICIOUS_PTH"
    assert report.pth_findings[0].code == "EXEC_CALL"


def test_inspect_venv_flags_unindexed_binary(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venv, site = _environment(root)
    (site / "evil.dll").write_bytes(b"MZ fake payload")
    report = inspect_venv(root)
    assert report.status == "TAMPERED"
    assert any(path.endswith("evil.dll") for path in report.suspicious_binaries)
    assert "unindexed binar" in report.detail


def test_recorded_binary_is_not_suspicious(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venv, site = _environment(root)
    payload = b"MZ fake payload"
    (site / "demo.pyd").write_bytes(payload)
    _record(site, [("demo.pyd", "sha256=" + _digest(payload))])
    report = inspect_venv(root)
    assert report.suspicious_binaries == []
    assert report.record_checked == 1
    assert report.status == "CLEAN"


@pytest.mark.skipif(os.name == "nt", reason="Win32 ACLs are not visible through st_mode")
def test_inspect_venv_flags_world_writable_artifact(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venv, site = _environment(root)
    target = site / "helper.py"
    target.write_text("VALUE = 1\n", encoding="utf-8")
    os.chmod(target, 0o666)
    report = inspect_venv(root)
    assert any(path.endswith("helper.py") for path in report.permission_anomalies)
    assert report.status == "TAMPERED"


def test_find_venvs_detects_a_named_environment(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    environment = root / "myenv"
    (environment / "Lib" / "site-packages").mkdir(parents=True)
    (environment / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    assert find_venvs(root) == [environment]


def test_find_venvs_ignores_plain_directories(tmp_path: Path) -> None:
    root = tmp_path / "project"
    (root / "venv").mkdir(parents=True)
    (root / "src").mkdir()
    assert find_venvs(root) == []


def test_inspect_venv_survives_a_file_root(tmp_path: Path) -> None:
    target = tmp_path / "not-a-directory.txt"
    target.write_text("x", encoding="utf-8")
    report = inspect_venv(target)
    assert report.status == "WARNING"
    assert "not a directory" in report.detail


def test_plain_directory_has_no_findings(tmp_path: Path) -> None:
    root = tmp_path / "plain"
    (root / "src").mkdir(parents=True)
    (root / "src" / "app.py").write_text("print(1)\n", encoding="utf-8")
    report = inspect_venv(root)
    assert report.status == "CLEAN"
    assert report.pth_findings == []
    assert report.startup_injections == []
    assert report.typosquat_suspects == []
    assert report.record_checked == 0
    assert report.truncated is False


def test_report_defaults_keep_old_callers_working() -> None:
    report = VenvReport(venv_path=None, pth_files=0)
    assert report.status == "CLEAN"
    assert report.record_checked == 0
    assert report.record_mismatches == 0
    assert report.startup_injections == []
    assert report.typosquat_suspects == []
    assert report.truncated is False
    assert PthFinding("x", 1, "EXEC_CALL", "high").detail == ""


# ---------------------------------------------------------------- RECORD hashes


def test_record_verification_accepts_a_correct_digest(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venv, site = _environment(root)
    payload = b"print('hello')\n"
    (site / "pkg.py").write_bytes(payload)
    _record(site, [("pkg.py", "sha256=" + _digest(payload))])
    report = inspect_venv(root)
    assert report.record_checked == 1
    assert report.record_mismatches == 0
    assert [finding for finding in report.pth_findings if finding.code.startswith("record_")] == []
    assert report.status == "CLEAN"
    assert "RECORD 1 verified" in report.detail


def test_record_mismatch_is_high_and_tampered(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venv, site = _environment(root)
    (site / "pkg.py").write_bytes(b"print('modified')\n")
    _record(site, [("pkg.py", "sha256=" + _digest(b"print('original')\n"))])
    report = inspect_venv(root)
    assert report.record_mismatches == 1
    assert report.status == "TAMPERED"
    finding = next(item for item in report.pth_findings if item.code == "record_mismatch")
    assert finding.severity == "high"
    assert finding.rel_path.endswith("pkg.py")
    assert "sha256 differs" in finding.detail


def test_record_missing_file_is_medium(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venv, site = _environment(root)
    _record(site, [("ghost.py", "sha256=" + _digest(b"absent"))])
    report = inspect_venv(root)
    finding = next(item for item in report.pth_findings if item.code == "record_missing")
    assert finding.severity == "medium"
    assert finding.rel_path.endswith("ghost.py")
    assert report.status == "TAMPERED"


def test_record_unreadable_is_medium(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "project"
    _venv, site = _environment(root)
    (site / "pkg.py").write_text("VALUE = 1\n", encoding="utf-8")
    _record(site, [("pkg.py", "sha256=" + _digest(b"VALUE = 1\n"))])
    monkeypatch.setattr(venv_radar, "_hash_file", lambda path, state: ("", "unreadable"))
    report = inspect_venv(root)
    finding = next(item for item in report.pth_findings if item.code == "record_unreadable")
    assert finding.severity == "medium"
    assert report.status == "TAMPERED"


def test_blank_record_hash_is_counted_and_not_flagged(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venv, site = _environment(root)
    (site / "pkg.py").write_text("VALUE = 1\n", encoding="utf-8")
    _record(site, [("pkg.py", ""), ("pkg.py", "sha256=")])
    report = inspect_venv(root)
    assert [item for item in report.pth_findings if item.code.startswith("record_")] == []
    assert report.record_checked == 0
    assert report.status == "CLEAN"


def test_record_verification_reports_truncation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(venv_radar, "MAX_RECORD_FILES", 1)
    root = tmp_path / "project"
    _venv, site = _environment(root)
    payload = b"VALUE = 1\n"
    for name in ("one.py", "two.py"):
        (site / name).write_bytes(payload)
    _record(
        site,
        [
            ("one.py", "sha256=" + _digest(payload)),
            ("two.py", "sha256=" + _digest(payload)),
        ],
    )
    report = inspect_venv(root)
    assert report.truncated is True
    assert report.record_checked == 1
    assert "truncated" in report.detail


def test_record_verification_stops_at_the_byte_budget(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(venv_radar, "MAX_RECORD_BYTES", 4)
    root = tmp_path / "project"
    _venv, site = _environment(root)
    payload = b"0123456789"
    (site / "big.py").write_bytes(payload)
    _record(site, [("big.py", "sha256=" + _digest(payload))])
    report = inspect_venv(root)
    assert report.truncated is True
    assert report.record_checked == 0
    assert report.record_mismatches == 0


def test_findings_never_contain_file_contents(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venv, site = _environment(root)
    marker = "SECRET_MARKER_CONTENT_9f3a"
    (site / "pkg.py").write_text(marker + "\n", encoding="utf-8")
    _record(site, [("pkg.py", "sha256=" + _digest(b"something else"))])
    report = inspect_venv(root)
    assert report.status == "TAMPERED"
    rendered = report.detail
    for finding in report.pth_findings:
        rendered += " " + finding.code + " " + finding.detail + " " + finding.rel_path
    assert marker not in rendered


# ------------------------------------------------------- startup and interpreter


def test_sitecustomize_is_a_startup_injection(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venv, site = _environment(root)
    (site / "sitecustomize.py").write_text("import os\n", encoding="utf-8")
    report = inspect_venv(root)
    assert [path.endswith("sitecustomize.py") for path in report.startup_injections] == [True]
    finding = next(item for item in report.pth_findings if item.code == "startup_injection")
    assert finding.severity == "high"
    assert report.status == "TAMPERED"
    assert "1 startup injection(s)" in report.detail


def test_usercustomize_is_a_startup_injection(tmp_path: Path) -> None:
    root = tmp_path / "project"
    venv, site = _environment(root)
    (venv / "usercustomize.py").write_text("import sys\n", encoding="utf-8")
    report = inspect_venv(root)
    assert report.startup_injections
    assert report.status == "TAMPERED"


def test_missing_base_interpreter_is_medium(tmp_path: Path) -> None:
    root = tmp_path / "project"
    venv, _site = _environment(root)
    (venv / "pyvenv.cfg").write_text(
        "home = /nonexistent/base/bin\ninclude-system-site-packages = false\n",
        encoding="utf-8",
    )
    report = inspect_venv(root)
    finding = next(item for item in report.pth_findings if item.code == "interpreter_missing")
    assert finding.severity == "medium"
    assert finding.line_no == 1
    assert report.status == "TAMPERED"


def test_existing_base_interpreter_is_informational(tmp_path: Path) -> None:
    root = tmp_path / "project"
    venv, _site = _environment(root)
    (venv / "pyvenv.cfg").write_text(
        "home = " + str(Path(sys.executable).parent) + chr(10)
        + "executable = " + sys.executable + chr(10),
        encoding="utf-8",
    )
    report = inspect_venv(root)
    assert report.status == "CLEAN"
    informational = [item for item in report.pth_findings if item.code == "base_path_escape"]
    assert informational
    assert informational[0].severity == "low"


# ---------------------------------------------------------------- typosquatting


def test_typosquat_resembles_a_popular_package(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venv, site = _environment(root)
    _record(site, [], dist="reqeusts", version="2.31.0")
    report = inspect_venv(root)
    assert report.typosquat_suspects
    assert "requests" in report.typosquat_suspects[0]
    assert "distance" in report.typosquat_suspects[0]
    finding = next(item for item in report.pth_findings if item.code == "typosquat_suspect")
    assert finding.severity == "medium"
    assert "requests" in finding.detail
    assert finding.rel_path.endswith(".dist-info")
    assert report.status == "TAMPERED"


def test_popular_package_name_is_not_a_typosquat(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venv, site = _environment(root)
    _record(site, [], dist="requests", version="2.31.0")
    report = inspect_venv(root)
    assert report.typosquat_suspects == []
    assert report.status == "CLEAN"


def test_popular_name_list_is_substantial() -> None:
    assert len(venv_radar.POPULAR_PYPI_NAMES) >= 120
    assert len(set(venv_radar.POPULAR_PYPI_NAMES)) == len(venv_radar.POPULAR_PYPI_NAMES)


# ------------------------------------------------------------------- symlinks


@pytest.mark.skipif(os.name == "nt", reason="creating symlinks needs developer mode on Win32")
def test_symlink_with_matching_digest_is_clean(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venv, site = _environment(root)
    payload = b"print('linked')\n"
    real = site / "real_module.py"
    real.write_bytes(payload)
    os.symlink(real, site / "linked_module.py")
    _record(site, [("linked_module.py", "sha256=" + _digest(payload))])
    report = inspect_venv(root)
    assert report.record_mismatches == 0
    assert report.status == "CLEAN"


# ---------------------------------------------------------------- performance


def test_inspect_venv_on_this_repository_is_fast(project_root: Path) -> None:
    started = time.perf_counter()
    report = inspect_venv(project_root)
    elapsed = time.perf_counter() - started
    assert report.status in {"CLEAN", "TAMPERED", "MALICIOUS_PTH", "WARNING"}
    assert elapsed < 1.0


def test_inspect_venv_handles_five_thousand_files(tmp_path: Path) -> None:
    root = tmp_path / "project"
    _venv, site = _environment(root)
    entries: list[tuple[str, str]] = []
    for index in range(5000):
        name = "mod%04d.py" % index
        payload = ("VALUE = %d" % index).encode("ascii")
        (site / name).write_bytes(payload)
        entries.append((name, "sha256=" + _digest(payload)))
    _record(site, entries, dist="big", version="1.0")
    started = time.perf_counter()
    report = inspect_venv(root)
    elapsed = time.perf_counter() - started
    assert report.truncated is True
    assert report.record_checked == venv_radar.MAX_RECORD_FILES
    assert report.record_mismatches == 0
    assert elapsed < 3.0
