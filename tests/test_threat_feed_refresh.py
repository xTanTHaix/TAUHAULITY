"""Tests for the cached threat-feed freshness layer.

No test in the default suite touches the network: the two fetchers are replaced
with local stubs, and the one live refresh test is slow-marked and skips when the
endpoints are unreachable. The cache format, the atomic write, the failure
handling and the staleness decision are all exercised against real files.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tauhaulity.tools import threat_feed

ROOT = Path(__file__).resolve().parents[1]


def _stub_fetchers(monkeypatch, osv_entries=("endpoint=osv status=200 advisory=GHSA-test",)) -> None:
    monkeypatch.setattr(
        threat_feed,
        "_fetch_osv",
        lambda timeout: (
            threat_feed.OSV_ENDPOINT,
            osv_entries,
            "OSV querybatch answered HTTP 200 with 1 advisory reference(s)",
        ),
    )
    monkeypatch.setattr(
        threat_feed,
        "_fetch_malicious",
        lambda timeout: (
            threat_feed.MALICIOUS_TREE_URL,
            (
                "package=0requests record=MAL-2026-0001 reasons=exfiltration-env-variables summary=test record",
                "package=blag record=MAL-2026-0002 reasons=- summary=untagged record",
            ),
            "OpenSSF malicious-packages answered HTTP 200; sampled 2 record(s)",
        ),
    )


def _rewrite_captured_at(root: Path, kind: str, when: datetime) -> None:
    path = threat_feed.feed_cache_path(kind, root)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["captured_at"] = when.isoformat(timespec="seconds")
    path.write_text(json.dumps(payload), encoding="utf-8")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def test_status_on_empty_cache_is_missing_stale_and_offline(
    tmp_path: Path, monkeypatch
) -> None:
    def forbidden(*args, **kwargs):
        raise AssertionError("status() must never touch the network")

    monkeypatch.setattr(threat_feed, "_http_request", forbidden)
    result = threat_feed.status(root=tmp_path)
    assert result.stale is True
    assert result.stale_after_days == 30
    assert [snapshot.kind for snapshot in result.snapshots] == ["osv", "malicious"]
    assert all(snapshot.age_days < 0 for snapshot in result.snapshots)
    assert "missing" in result.detail
    assert "stale" in result.detail
    assert "scripts/threat_feed_check.py --refresh" in result.detail
    assert not threat_feed.feed_cache_dir(tmp_path).exists()


def test_refresh_writes_snapshots_and_status_then_reports_fresh(
    tmp_path: Path, monkeypatch
) -> None:
    _stub_fetchers(monkeypatch)
    result = threat_feed.refresh(root=tmp_path)
    assert result.stale is False
    assert "refreshed" in result.detail
    cache_dir = threat_feed.feed_cache_dir(tmp_path)
    assert cache_dir.is_dir()
    osv_cache = threat_feed.feed_cache_path("osv", tmp_path)
    malicious_cache = threat_feed.feed_cache_path("malicious", tmp_path)
    assert osv_cache.is_file() and malicious_cache.is_file()
    payload = json.loads(osv_cache.read_text(encoding="utf-8"))
    assert payload["version"] == threat_feed.CACHE_VERSION == 1
    assert payload["generator"] == "tauhaulity.tools.threat_feed"
    assert payload["kind"] == "osv"
    assert payload["source"] == threat_feed.OSV_ENDPOINT
    assert payload["captured_at"]
    assert payload["entries"] == ["endpoint=osv status=200 advisory=GHSA-test"]
    assert [path.name for path in cache_dir.glob("*.tmp")] == []
    fresh = threat_feed.status(root=tmp_path)
    assert fresh.stale is False
    for snapshot in fresh.snapshots:
        assert 0.0 <= snapshot.age_days < 1.0
        assert snapshot.captured_at
        assert snapshot.entries
    malicious = next(item for item in fresh.snapshots if item.kind == "malicious")
    assert len(malicious.entries) == 2
    assert malicious.entries[0].startswith("package=0requests record=MAL-2026-0001")


def test_failed_refresh_keeps_the_previous_snapshot(tmp_path: Path, monkeypatch) -> None:
    _stub_fetchers(monkeypatch)
    threat_feed.refresh(root=tmp_path)
    osv_cache = threat_feed.feed_cache_path("osv", tmp_path)
    before = osv_cache.read_text(encoding="utf-8")

    def broken(timeout):
        raise RuntimeError("simulated network failure")

    monkeypatch.setattr(threat_feed, "_fetch_osv", broken)
    result = threat_feed.refresh(("osv",), root=tmp_path)
    assert "refresh failed" in result.detail
    assert "previous snapshot kept" in result.detail
    assert "RuntimeError" in result.detail
    assert osv_cache.read_text(encoding="utf-8") == before
    assert result.stale is False
    previous = next(item for item in result.snapshots if item.kind == "osv")
    assert previous.age_days >= 0.0


def test_failed_refresh_without_previous_snapshot_is_reported(
    tmp_path: Path, monkeypatch
) -> None:
    def broken_osv(timeout):
        raise TimeoutError("simulated timeout")

    def broken_malicious(timeout):
        raise OSError("simulated socket failure")

    monkeypatch.setattr(threat_feed, "_fetch_osv", broken_osv)
    monkeypatch.setattr(threat_feed, "_fetch_malicious", broken_malicious)
    result = threat_feed.refresh(root=tmp_path)
    assert result.stale is True
    assert "no previous snapshot" in result.detail
    assert "TimeoutError" in result.detail
    assert "OSError" in result.detail
    assert not threat_feed.feed_cache_dir(tmp_path).exists()


def test_cache_write_failure_is_reported_and_network_errors_never_raise(
    tmp_path: Path, monkeypatch
) -> None:
    _stub_fetchers(monkeypatch)

    def broken_write(*args, **kwargs):
        raise OSError("simulated read-only cache")

    monkeypatch.setattr(threat_feed, "_write_cache", broken_write)
    result = threat_feed.refresh(root=tmp_path)
    assert "cache write failed" in result.detail
    assert "OSError" in result.detail
    assert result.stale is True


def test_corrupt_cache_degrades_to_missing(tmp_path: Path) -> None:
    cache_dir = threat_feed.feed_cache_dir(tmp_path)
    cache_dir.mkdir(parents=True)
    (cache_dir / "osv.json").write_text("{ not json", encoding="utf-8")
    payload = {
        "version": 999,
        "kind": "malicious",
        "captured_at": _now().isoformat(),
        "entries": ["package=x record=y reasons=- summary=z"],
    }
    (cache_dir / "malicious.json").write_text(json.dumps(payload), encoding="utf-8")
    result = threat_feed.status(root=tmp_path)
    assert result.stale is True
    assert all(snapshot.age_days < 0 for snapshot in result.snapshots)
    assert "missing" in result.detail


def test_staleness_uses_the_configured_limit(tmp_path: Path) -> None:
    snapshot = threat_feed.record_snapshot(
        "osv",
        root=tmp_path,
        source=threat_feed.OSV_ENDPOINT,
        entries=("endpoint=osv status=200 advisory=GHSA-test",),
        detail="old snapshot fixture",
    )
    threat_feed.record_snapshot(
        "malicious",
        root=tmp_path,
        source=threat_feed.MALICIOUS_TREE_URL,
        entries=("package=0requests record=MAL-2026-0001 reasons=typosquatting summary=test",),
        detail="old snapshot fixture",
    )
    assert snapshot.age_days < 1.0
    _rewrite_captured_at(tmp_path, "osv", _now() - timedelta(days=40))
    _rewrite_captured_at(tmp_path, "malicious", _now() - timedelta(days=40))
    stale = threat_feed.status(root=tmp_path, stale_after_days=30)
    assert stale.stale is True
    osv = next(item for item in stale.snapshots if item.kind == "osv")
    assert 39.0 <= osv.age_days <= 41.0
    assert "40." in stale.detail
    relaxed = threat_feed.status(root=tmp_path, stale_after_days=60)
    assert relaxed.stale is False


def test_record_snapshot_roundtrip_and_unknown_kind(tmp_path: Path) -> None:
    snapshot = threat_feed.record_snapshot(
        "malicious",
        root=tmp_path,
        source="unit test feed",
        entries=("package=0requests record=MAL-2026-0001 reasons=typosquatting summary=test",),
        detail="recorded by a test",
    )
    assert snapshot.kind == "malicious"
    assert snapshot.entries == (
        "package=0requests record=MAL-2026-0001 reasons=typosquatting summary=test",
    )
    reloaded = threat_feed.status(root=tmp_path)
    malicious = next(item for item in reloaded.snapshots if item.kind == "malicious")
    assert malicious.source == "unit test feed"
    assert malicious.entries == snapshot.entries
    with pytest.raises(ValueError):
        threat_feed.record_snapshot("unknown", root=tmp_path, source="x", entries=())


def test_unknown_kind_in_refresh_is_reported(tmp_path: Path, monkeypatch) -> None:
    _stub_fetchers(monkeypatch)
    result = threat_feed.refresh(("bogus", "osv"), root=tmp_path)
    assert "ignored unknown feed kind" in result.detail
    assert any(snapshot.kind == "osv" and snapshot.age_days >= 0 for snapshot in result.snapshots)


def test_default_root_is_the_current_directory(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    _stub_fetchers(monkeypatch)
    result = threat_feed.refresh()
    assert result.stale is False
    assert threat_feed.feed_cache_path("osv").is_file()
    assert threat_feed.feed_cache_path("osv").parent == tmp_path / ".tauhaulity" / "feeds"


def test_script_reads_the_shared_feed_cache_offline(tmp_path: Path) -> None:
    threat_feed.record_snapshot(
        "malicious",
        root=tmp_path,
        source="shared feed probe",
        entries=(
            "package=0requests record=MAL-2026-7777 reasons=exfiltration-env-variables summary=probe record campaign=2026-09-0requests",
            "package=blag record=MAL-2026-7778 reasons=- summary=untagged probe",
        ),
        detail="script replay probe",
    )
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "threat_feed_check.py"),
            "--json",
            "--feed-root",
            str(tmp_path),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    payload = json.loads(completed.stdout)
    assert "cached feed snapshot" in payload["source"]
    records = payload["records"]
    assert any(record["package"] == "0requests" for record in records), records
    assert payload["summary"]["sampled"] >= 2
    assert payload["summary"]["coverage_of_tagged"] == 1.0


@pytest.mark.slow
def test_live_refresh_when_the_network_is_available(tmp_path: Path) -> None:
    try:
        result = threat_feed.refresh(("osv", "malicious"), root=tmp_path, timeout=10.0)
    except Exception as exc:  # a truly broken environment must not fail the suite
        pytest.skip("live refresh raised " + type(exc).__name__ + ": " + str(exc))
    if all(snapshot.age_days < 0 for snapshot in result.snapshots):
        pytest.skip("network unavailable: " + result.detail)
    assert result.stale is False
    refreshed = [snapshot for snapshot in result.snapshots if snapshot.age_days >= 0]
    assert refreshed
    assert any(snapshot.source for snapshot in refreshed)
    assert any(snapshot.entries for snapshot in refreshed)
