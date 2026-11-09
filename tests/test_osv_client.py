"""Tests for the OSV advisory client.

The network is never required: the HTTP call is stubbed for the behaviour tests,
and the one live test is marked slow and skips when OSV cannot be reached.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tauhaulity.tools import osv_client
from tauhaulity.tools.osv_client import (
    OsvReport,
    OsvUnavailable,
    PackageRef,
    Vulnerability,
    declared_dependencies,
    load_cache,
    query,
    save_cache,
)

BATCH_RESPONSE = {
    "results": [
        {"vulns": [{"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["CVE-2020-0001"], "affected": [
            {"package": {"name": "requests", "ecosystem": "PyPI"},
             "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.20.0"}]}]}
        ]}]},
        {"vulns": []},
    ]
}


def test_query_maps_ids_aliases_and_fix(monkeypatch) -> None:
    monkeypatch.setattr(osv_client, "_post_json", lambda url, payload: BATCH_RESPONSE)
    report = query([PackageRef("requests", "2.19.0"), PackageRef("flask", "3.0.0")])
    assert report.count == 1
    item = report.vulnerabilities[0]
    assert item.vuln_id == "GHSA-aaaa-bbbb-cccc"
    assert item.aliases == ("CVE-2020-0001",)
    assert item.fixed == "2.20.0"
    assert item.url.startswith("https://osv.dev/vulnerability/")
    assert report.queried == 2


def test_unpinned_dependencies_are_skipped_not_guessed(monkeypatch) -> None:
    monkeypatch.setattr(osv_client, "_post_json", lambda url, payload: {"results": []})
    report = query([PackageRef("flask", ""), PackageRef("requests", "2.19.0")])
    assert report.queried == 1
    assert any("flask" in note for note in report.skipped)


def test_network_failure_is_reported_not_raised(monkeypatch) -> None:
    def explode(url, payload):
        raise OsvUnavailable("URLError: offline")

    monkeypatch.setattr(osv_client, "_post_json", explode)
    report = query([PackageRef("requests", "2.19.0")])
    assert report.count == 0
    assert "offline" in report.detail


def test_query_rejects_an_unbounded_batch() -> None:
    with pytest.raises(ValueError):
        query([PackageRef("p" + str(index), "1.0") for index in range(osv_client.MAX_PACKAGES * osv_client.MAX_BATCHES + 1)])


def test_cache_round_trip(tmp_path: Path) -> None:
    report = OsvReport(
        vulnerabilities=[Vulnerability("requests", "2.19.0", "GHSA-x", ("CVE-1",), "summary", "2.20.0", "u")],
        queried=2,
        skipped=("flask (no pinned version)",),
        detail="1 advisory",
    )
    path = save_cache(report, tmp_path / "osv.json")
    loaded = load_cache(path)
    assert loaded is not None
    assert loaded.source == "cache"
    assert loaded.count == 1
    assert loaded.vulnerabilities[0].vuln_id == "GHSA-x"
    assert loaded.skipped == report.skipped


def test_cache_degrades_when_missing_or_corrupt(tmp_path: Path) -> None:
    assert load_cache(tmp_path / "absent.json") is None
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    assert load_cache(broken) is None


def test_declared_dependencies_reads_both_formats(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("requests==2.19.0" + chr(10) + "flask" + chr(10), encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[project]" + chr(10)
        + 'name = "demo"' + chr(10)
        + 'dependencies = ["jinja2==2.11.2", "urllib3"]' + chr(10)
        + '[project.optional-dependencies]' + chr(10)
        + 'dev = ["pytest==9.2.0"]' + chr(10),
        encoding="utf-8",
    )
    references, notes = declared_dependencies(tmp_path)
    pinned = {item.name: item.version for item in references}
    assert pinned["requests"] == "2.19.0"
    assert pinned["jinja2"] == "2.11.2"
    assert pinned["flask"] == ""
    assert pinned["pytest"] == "9.2.0"
    assert notes == ()


def test_declared_dependencies_survives_malformed_files(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("this is not a requirement" + chr(10) + "requests==2.19.0" + chr(10), encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text("not = toml =", encoding="utf-8")
    references, notes = declared_dependencies(tmp_path)
    assert any(item.name == "requests" for item in references)
    assert notes and "pyproject.toml" in notes[0]


@pytest.mark.slow
def test_live_osv_lookup_finds_real_advisories() -> None:
    """Prove the client against the real service; skip when offline."""

    try:
        report = query([PackageRef("requests", "2.19.0")])
    except OsvUnavailable as exc:
        pytest.skip("OSV unavailable: " + str(exc))
    if report.detail.startswith("OSV lookup failed"):
        pytest.skip(report.detail)
    assert report.count > 0, report.detail
    assert report.vulnerabilities[0].url.startswith("https://osv.dev/vulnerability/")
