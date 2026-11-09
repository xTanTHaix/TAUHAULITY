"""Tests for the declared-dependency audit.

Every fixture is a real manifest set on disk. The tests pin the detector rules
(typosquat distance, digit-mixing names, direct URLs, unpinned declarations and
foreign indexes), the parser coverage for all five manifest formats, and the
degradation behaviour: a malformed or oversized manifest must never stop the
audit.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tauhaulity.tools import dep_audit


def _write(root: Path, name: str, text: str) -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _kinds(report: dep_audit.DepReport) -> set[str]:
    return {finding.kind for finding in report.findings}


def _names(report: dep_audit.DepReport, kind: str) -> set[str]:
    return {finding.name for finding in report.findings if finding.kind == kind}


def test_embedded_popular_lists_have_the_documented_size() -> None:
    assert len(dep_audit.POPULAR_PYPI) == 200
    assert len(dep_audit.POPULAR_NPM) == 100
    assert len(dep_audit.POPULAR_NAMES) >= 250
    assert "requests" in dep_audit.POPULAR_PYPI
    assert "react" in dep_audit.POPULAR_NPM
    assert all(name == name.strip().lower() for name in dep_audit.POPULAR_NAMES)


def test_levenshtein_is_the_classic_edit_distance() -> None:
    assert dep_audit.levenshtein("", "") == 0
    assert dep_audit.levenshtein("abc", "abc") == 0
    assert dep_audit.levenshtein("kitten", "sitting") == 3
    assert dep_audit.levenshtein("reqeusts", "requests") == 2
    assert dep_audit.levenshtein("requests", "reqeusts") == 2
    assert dep_audit.levenshtein("flask", "") == 5


def test_normalize_name_folds_case_and_separators() -> None:
    assert dep_audit.normalize_name("Flask") == "flask"
    assert dep_audit.normalize_name("typing_extensions") == "typing-extensions"
    assert dep_audit.normalize_name("zope.interface") == "zope-interface"
    assert dep_audit.normalize_name("  Flask  ") == "flask"


def test_typosquat_is_detected_by_edit_distance(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "reqeusts==2.0.0" + chr(10))
    report = dep_audit.audit_dependencies(tmp_path)
    assert "typosquat" in _kinds(report)
    finding = next(item for item in report.findings if item.kind == "typosquat")
    assert finding.name == "reqeusts"
    assert finding.severity == "high"
    assert finding.rel_path == "requirements.txt"
    assert finding.line_no == 1
    assert "2" in finding.detail and "requests" in finding.detail


def test_short_names_need_distance_one(tmp_path: Path) -> None:
    # "qqq" is distance 3 from every popular name, so a three character name
    # only fires at distance 1; the distance 2 rule needs more than seven
    # characters ("reqeusts" is distance 2 from requests and is reported).
    _write(tmp_path, "requirements.txt", "qqq==1.0.0" + chr(10))
    report = dep_audit.audit_dependencies(tmp_path)
    assert _names(report, "typosquat") == set()


def test_digit_mixing_name_is_suspicious(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "0requests==1.0" + chr(10) + "requests2" + chr(10))
    report = dep_audit.audit_dependencies(tmp_path)
    assert _names(report, "suspicious_name") == {"0requests", "requests2"}
    for finding in report.findings:
        if finding.kind == "suspicious_name":
            assert finding.severity == "high"
            assert finding.name in {"0requests", "requests2"}


def test_pinned_declaration_has_no_finding(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "flask>=3.0.0" + chr(10) + "requests==2.32.0" + chr(10))
    report = dep_audit.audit_dependencies(tmp_path)
    assert report.findings == ()
    assert report.declared == 2
    assert "no typosquat" in report.detail


def test_unpinned_declaration_is_low(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "flask" + chr(10))
    report = dep_audit.audit_dependencies(tmp_path)
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.kind == "unpinned"
    assert finding.severity == "low"
    assert finding.name == "flask"


def test_direct_url_is_medium(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "requirements.txt",
        "git+https://github.com/example/payload.git#egg=payload" + chr(10),
    )
    report = dep_audit.audit_dependencies(tmp_path)
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.kind == "direct_url"
    assert finding.severity == "medium"
    assert finding.name == "payload"


def test_unknown_index_is_medium_and_pypi_is_trusted(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "requirements.txt",
        "--index-url https://pypi.org/simple" + chr(10)
        + "flask==3.0.0" + chr(10)
        + "--extra-index-url https://evil.example/simple" + chr(10),
    )
    report = dep_audit.audit_dependencies(tmp_path)
    assert _names(report, "unknown_index") == {"evil.example"}
    finding = next(item for item in report.findings if item.kind == "unknown_index")
    assert finding.severity == "medium"
    assert finding.line_no == 3


def test_pyproject_dependencies_and_optional_dependencies(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "pyproject.toml",
        "[project]" + chr(10)
        + 'name = "demo"' + chr(10)
        + "dependencies = [" + chr(10)
        + '  "requests==2.32.0",' + chr(10)
        + '  "reqeusts==1.0",' + chr(10)
        + '  "git+https://evil.example/pkg.git",' + chr(10)
        + "]" + chr(10)
        + "[project.optional-dependencies]" + chr(10)
        + 'dev = ["pytest>=7", "black"]' + chr(10),
    )
    report = dep_audit.audit_dependencies(tmp_path)
    assert report.declared == 5
    assert "typosquat" in _kinds(report)
    assert _names(report, "typosquat") == {"reqeusts"}
    assert "direct_url" in _kinds(report)
    assert _names(report, "unpinned") == {"black"}


def test_setup_cfg_install_requires_and_extras(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "setup.cfg",
        "[metadata]" + chr(10)
        + "name = demo" + chr(10)
        + "[options]" + chr(10)
        + "install_requires =" + chr(10)
        + "    flask>=3" + chr(10)
        + "    pandas" + chr(10)
        + "[options.extras_require]" + chr(10)
        + "dev =" + chr(10)
        + "    pytest>=7" + chr(10)
        + "    reqeusts" + chr(10),
    )
    report = dep_audit.audit_dependencies(tmp_path)
    assert report.declared == 4
    assert _names(report, "unpinned") == {"pandas", "reqeusts"}
    assert _names(report, "typosquat") == {"reqeusts"}


def test_pipfile_and_package_json(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "Pipfile",
        "[packages]" + chr(10)
        + 'requests = "*"' + chr(10)
        + 'flask = "==3.0.0"' + chr(10)
        + "[dev-packages]" + chr(10)
        + 'pytest = ">=7"' + chr(10),
    )
    _write(
        tmp_path,
        "package.json",
        json.dumps(
            {
                "dependencies": {
                    "lodash": "^4.17.21",
                    "reqeusts": "1.0.0",
                    "left-pad": "latest",
                },
                "devDependencies": {"typescript": "^5.0.0"},
            }
        ),
    )
    report = dep_audit.audit_dependencies(tmp_path)
    assert report.files_scanned == 2
    assert report.declared == 7
    assert _names(report, "typosquat") == {"reqeusts"}
    assert _names(report, "unpinned") == {"left-pad", "requests"}


def test_clean_project_has_no_findings(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "requests==2.32.0" + chr(10) + "flask>=3.0.0" + chr(10))
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"lodash": "^4.17.21"}}))
    report = dep_audit.audit_dependencies(tmp_path)
    assert report.findings == ()
    assert report.declared == 3
    assert report.files_scanned == 2
    assert "3 dependency declaration(s) in 2 manifest file(s)" in report.detail


def test_malformed_manifests_are_skipped_without_raising(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "requirements.txt",
        "this is not a requirement" + chr(10)
        + "-r other.txt" + chr(10)
        + "# comment" + chr(10)
        + "" + chr(10)
        + "flask==3.0.0" + chr(10),
    )
    _write(tmp_path, "pyproject.toml", "this is not = toml")
    _write(tmp_path, "package.json", "{not json")
    _write(tmp_path, "Pipfile", "not = valid = toml")
    _write(tmp_path, "setup.cfg", "[options" + chr(10) + "broken")
    report = dep_audit.audit_dependencies(tmp_path)
    assert report.declared == 1
    assert report.findings == ()
    assert isinstance(report.findings, tuple)


def test_oversized_manifest_is_truncated_not_read(tmp_path: Path) -> None:
    line = "flask==3.0.0" + chr(10)
    payload = line * (dep_audit.MAX_MANIFEST_BYTES // len(line) + 8)
    assert len(payload) > dep_audit.MAX_MANIFEST_BYTES
    _write(tmp_path, "requirements.txt", payload)
    report = dep_audit.audit_dependencies(tmp_path)
    assert report.files_scanned == 0
    assert report.declared == 0
    assert "truncated at the manifest budget" in report.detail


def test_missing_root_is_reported_not_raised(tmp_path: Path) -> None:
    report = dep_audit.audit_dependencies(tmp_path / "absent")
    assert report.findings == ()
    assert report.declared == 0
    assert "not a readable directory" in report.detail


def test_popular_override_limits_the_pool(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "reqeusts==1.0" + chr(10) + "flask==3.0.0" + chr(10))
    report = dep_audit.audit_dependencies(tmp_path, popular=("requests",))
    assert _names(report, "typosquat") == {"reqeusts"}
    narrow = dep_audit.audit_dependencies(tmp_path, popular=("django",))
    assert narrow.findings == ()


def test_findings_are_ordered_by_severity_then_path(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", "flask" + chr(10) + "reqeusts==1.0" + chr(10))
    report = dep_audit.audit_dependencies(tmp_path)
    assert report.findings[0].severity == "high"
    assert report.findings[-1].severity == "low"
    assert "reqeusts is edit distance 2" in report.detail


def test_audit_does_not_touch_the_project(tmp_path: Path) -> None:
    path = _write(tmp_path, "requirements.txt", "flask==3.0.0" + chr(10))
    before = path.stat().st_mtime_ns
    dep_audit.audit_dependencies(tmp_path)
    assert path.stat().st_mtime_ns == before
    assert [entry.name for entry in tmp_path.iterdir()] == ["requirements.txt"]
