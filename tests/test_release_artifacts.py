"""Release artifact tests: the wheel and zipapp must be installable and intact.

A release that cannot be verified is a release nobody should install, so this
module builds both artifacts into a temporary directory and checks the PEP 427
RECORD digests byte for byte, the console entry point declaration, and that the
zipapp actually runs a scan end to end.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build_release.py"


def _build(tmp_path: Path) -> dict:
    completed = subprocess.run(
        [sys.executable, str(BUILDER), "--output", str(tmp_path)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(completed.stdout)


def test_wheel_record_digests_match(tmp_path: Path) -> None:
    summary = _build(tmp_path)
    wheel = Path(summary["wheel"])
    assert wheel.is_file()
    with zipfile.ZipFile(wheel) as archive:
        assert archive.testzip() is None
        record_name = next(name for name in archive.namelist() if name.endswith("/RECORD"))
        rows = list(csv.reader(io.StringIO(archive.read(record_name).decode("utf-8"))))
        assert rows, "RECORD is empty"
        declared = {row[0]: row for row in rows if row}
        for name in archive.namelist():
            if name == record_name:
                continue
            assert name in declared, f"{name} is not listed in RECORD"
            entry = declared[name]
            digest_field = entry[1]
            if not digest_field.startswith("sha256="):
                continue
            encoded = digest_field.split("=", 1)[1]
            expected = base64.urlsafe_b64encode(hashlib.sha256(archive.read(name)).digest()).rstrip(b"=").decode("ascii")
            assert encoded == expected, f"digest mismatch for {name}"
            assert int(entry[2]) == len(archive.read(name))


def test_wheel_declares_the_console_script(tmp_path: Path) -> None:
    summary = _build(tmp_path)
    with zipfile.ZipFile(summary["wheel"]) as archive:
        entry_name = next(name for name in archive.namelist() if name.endswith("entry_points.txt"))
        text = archive.read(entry_name).decode("utf-8")
        metadata_name = next(name for name in archive.namelist() if name.endswith("METADATA"))
        metadata = archive.read(metadata_name).decode("utf-8")
    assert "tauhaulity = tauhaulity.cli:main" in text
    assert "Name: tauhaulity" in metadata
    assert "Requires-Python: >=3.12" in metadata


def test_zipapp_runs_a_scan_and_a_doctor(tmp_path: Path) -> None:
    summary = _build(tmp_path)
    zipapp_path = Path(summary["zipapp"])
    assert zipapp_path.is_file() and zipapp_path.stat().st_size > 100_000

    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("VALUE = 1" + chr(10), encoding="utf-8")

    doctor = subprocess.run(
        [sys.executable, str(zipapp_path), "doctor", "--root", str(project)],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert doctor.returncode == 0, doctor.stdout + doctor.stderr
    assert "result: healthy" in doctor.stdout

    audit = subprocess.run(
        [sys.executable, str(zipapp_path), "audit", str(project), "--no-repro", "--json"],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert audit.returncode in {0, 1, 2}, audit.stdout + audit.stderr
    payload = json.loads(audit.stdout)
    assert len(payload["findings"]) == 12


def test_checksums_cover_both_artifacts(tmp_path: Path) -> None:
    summary = _build(tmp_path)
    manifest = Path(summary["checksums"])
    lines = [line for line in manifest.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 2
    names = {line.split("  ", 1)[1] for line in lines}
    assert names == {Path(summary["wheel"]).name, Path(summary["zipapp"]).name}
    for line in lines:
        digest, name = line.split("  ", 1)
        actual = hashlib.sha256((tmp_path / name).read_bytes()).hexdigest()
        assert digest == actual
