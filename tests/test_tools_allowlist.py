"""Tests for the accepted finding baseline (allowlist).

The baseline is the only thing that can silence a credential finding, so these
tests pin the two properties that make that safe: a fingerprint survives a line
shift in the same file, and only candidates that were actually recorded are
suppressed. A missing or corrupt allowlist must degrade to "suppress nothing"
instead of raising, because the scanner runs inside a commit gate.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import tauhaulity.tools.git_sentinel as sentinel
from tauhaulity.tools.allowlist import (
    ALLOWLIST_DIRNAME,
    ALLOWLIST_FILENAME,
    Baseline,
    BaselineEntry,
    BaselineReport,
    baseline_path,
    filter_hits,
    fingerprint_hit,
    load_baseline,
    remove_baseline,
    write_baseline,
)
from tauhaulity.tools.git_sentinel import SecretHit, inspect_repository, scan_staged

PAT = "ghp_" + "A" * 30
NEW_PAT = "ghp_" + "B" * 30
REMOTE_PAT = "ghp_" + "C" * 30


def _hit(
    rel_path: str = "src/app.py",
    line_no: int = 1,
    kind: str = "github_token",
    masked: str = "ghp_****REDACTED****",
) -> SecretHit:
    return SecretHit(rel_path, line_no, kind, masked)


def _project(root: Path, *, token: str = PAT) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "src").mkdir(exist_ok=True)
    (root / "src" / "app.py").write_text(
        "TOKEN = '" + token + "'" + chr(10), encoding="utf-8"
    )
    return root


def _entry(hit: SecretHit) -> BaselineEntry:
    return BaselineEntry(
        fingerprint=fingerprint_hit(hit), kind=hit.kind, rel_path=hit.rel_path,
        masked=hit.masked, created_at="2026-01-01T00:00:00+00:00",
    )


def test_fingerprint_is_stable_when_lines_shift() -> None:
    before = _hit(line_no=1)
    after = _hit(line_no=42)
    assert fingerprint_hit(before) == fingerprint_hit(after)


def test_fingerprint_depends_on_kind_path_and_mask() -> None:
    base = _hit()
    assert fingerprint_hit(base) != fingerprint_hit(_hit(kind="aws_access_key"))
    assert fingerprint_hit(base) != fingerprint_hit(_hit(rel_path="src/other.py"))
    assert fingerprint_hit(base) != fingerprint_hit(_hit(masked="AKIA****REDACTED****"))


def test_fingerprint_is_a_short_hex_digest() -> None:
    value = fingerprint_hit(_hit())
    assert len(value) == 32
    assert value == value.lower()
    int(value, 16)


def test_fingerprint_normalizes_windows_separators() -> None:
    assert fingerprint_hit(_hit(rel_path="src" + chr(92) + "app.py")) == fingerprint_hit(
        _hit(rel_path="src/app.py")
    )


def test_baseline_path_lives_in_the_state_directory(tmp_path: Path) -> None:
    path = baseline_path(tmp_path)
    assert path == tmp_path / ALLOWLIST_DIRNAME / ALLOWLIST_FILENAME


def test_load_without_a_file_returns_an_empty_baseline(tmp_path: Path) -> None:
    baseline = load_baseline(tmp_path)
    assert isinstance(baseline, Baseline)
    assert baseline.entries == ()
    assert baseline.is_empty is True
    assert len(baseline) == 0
    assert baseline.path == baseline_path(tmp_path)


def test_load_of_corrupt_json_degrades_to_empty(tmp_path: Path) -> None:
    target = baseline_path(tmp_path)
    target.parent.mkdir(parents=True)
    target.write_text("{not json at all", encoding="utf-8")
    assert load_baseline(tmp_path).entries == ()


def test_load_of_invalid_utf8_degrades_to_empty(tmp_path: Path) -> None:
    target = baseline_path(tmp_path)
    target.parent.mkdir(parents=True)
    target.write_bytes(b"\xff\xfe\x00broken")
    assert load_baseline(tmp_path).entries == ()


def test_load_of_an_unexpected_shape_degrades_to_empty(tmp_path: Path) -> None:
    target = baseline_path(tmp_path)
    target.parent.mkdir(parents=True)
    target.write_text(json.dumps({"entries": "nope"}), encoding="utf-8")
    assert load_baseline(tmp_path).entries == ()


def test_load_accepts_a_plain_list(tmp_path: Path) -> None:
    target = baseline_path(tmp_path)
    target.parent.mkdir(parents=True)
    hit = _hit()
    target.write_text(
        json.dumps(
            [
                {
                    "fingerprint": fingerprint_hit(hit),
                    "kind": hit.kind,
                    "rel_path": hit.rel_path,
                    "masked": hit.masked,
                }
            ]
        ),
        encoding="utf-8",
    )
    baseline = load_baseline(tmp_path)
    assert len(baseline) == 1
    assert baseline.entries[0].rel_path == "src/app.py"
    assert baseline.entries[0].masked == hit.masked


def test_write_baseline_records_current_findings(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    root = _project(tmp_path / "project")
    report = write_baseline(root)
    assert isinstance(report, BaselineReport)
    assert report.path == baseline_path(root)
    assert report.path.is_file()
    assert report.added >= 1
    assert report.total >= 1
    assert report.active_preview
    assert all(PAT not in line for line in report.active_preview)
    text = report.path.read_text(encoding="utf-8")
    assert PAT not in text
    assert "github_token" in text
    payload = json.loads(text)
    assert payload["version"] == 1
    assert payload["entries"]
    entry = payload["entries"][0]
    assert set(entry) == {"fingerprint", "kind", "rel_path", "masked", "created_at"}


def test_write_baseline_is_idempotent_and_keeps_stamps(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    root = _project(tmp_path / "project")
    first = write_baseline(root)
    stamp = json.loads(first.path.read_text(encoding="utf-8"))["entries"][0]["created_at"]
    second = write_baseline(root)
    assert second.added == 0
    assert second.total == first.total
    assert second.active_preview == []
    payload = json.loads(second.path.read_text(encoding="utf-8"))
    assert payload["entries"][0]["created_at"] == stamp


def test_write_baseline_records_remote_url_credentials(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    root = tmp_path / "project"
    (root / ".git").mkdir(parents=True)
    (root / ".git" / "config").write_text(
        "[remote \"origin\"]" + chr(10)
        + chr(9) + "url = https://user:" + REMOTE_PAT + "@example.test/repo.git" + chr(10),
        encoding="utf-8",
    )
    report = write_baseline(root)
    baseline = load_baseline(root)
    kinds = {entry.kind for entry in baseline.entries}
    assert "remote_url" in kinds
    remote = next(entry for entry in baseline.entries if entry.kind == "remote_url")
    assert remote.rel_path == ".git/config"
    assert REMOTE_PAT not in remote.masked
    assert report.total >= 1


def test_write_baseline_reports_added_candidates(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    root = _project(tmp_path / "project")
    write_baseline(root)
    (root / "src" / "new.py").write_text("TOKEN = '" + NEW_PAT + "'" + chr(10), encoding="utf-8")
    report = write_baseline(root)
    assert report.added == 1
    assert report.total == 2
    assert len(report.active_preview) == 1
    assert NEW_PAT not in report.active_preview[0]


def test_filter_hits_suppresses_only_accepted_fingerprints() -> None:
    known = _hit()
    other = _hit(masked="AKIA****REDACTED****")
    baseline = Baseline((_entry(known),), None, "")
    active, suppressed = filter_hits([known, other], baseline)
    assert active == [other]
    assert suppressed == 1


def test_filter_hits_with_an_empty_baseline_keeps_everything() -> None:
    hits = [_hit(), _hit(rel_path="b.py")]
    active, suppressed = filter_hits(hits, Baseline((), None, ""))
    assert active == hits
    assert suppressed == 0


def test_inspect_repository_applies_the_stored_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    root = _project(tmp_path / "project")
    written = write_baseline(root)
    report = inspect_repository(root)
    assert report.secrets == []
    assert report.suppressed == written.total
    assert report.baseline_entries == written.total
    assert report.baseline_path == baseline_path(root)
    assert "suppressed by the baseline" in report.findings_text


def test_inspect_repository_can_ignore_the_stored_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    root = _project(tmp_path / "project")
    write_baseline(root)
    report = inspect_repository(root, use_baseline=False)
    assert report.secrets
    assert report.suppressed == 0
    assert "suppressed by the baseline" not in report.findings_text


def test_inspect_repository_accepts_an_explicit_empty_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    root = _project(tmp_path / "project")
    write_baseline(root)
    report = inspect_repository(root, baseline=Baseline((), None, ""))
    assert report.secrets
    assert report.suppressed == 0


def test_inspect_repository_does_not_suppress_a_new_secret(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    root = _project(tmp_path / "project")
    write_baseline(root)
    (root / "src" / "fresh.py").write_text(
        "API = '" + NEW_PAT + "'" + chr(10), encoding="utf-8"
    )
    report = inspect_repository(root)
    assert [hit.rel_path for hit in report.secrets] == ["src/fresh.py"]
    assert report.suppressed >= 1


def test_scan_staged_accepts_an_explicit_baseline(tmp_path: Path) -> None:
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)

    def runner(args, cwd):
        if args[:3] == ["git", "diff", "--cached"]:
            return (0, b"deploy.sh" + chr(10).encode())
        return (0, ("export KEY=" + PAT + chr(10)).encode())

    hits = scan_staged(root, runner=runner)
    assert len(hits) == 1
    baseline = Baseline((_entry(hits[0]),), None, "")
    assert scan_staged(root, runner=runner, baseline=baseline) == []


def test_corrupt_allowlist_does_not_hide_anything(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    root = _project(tmp_path / "project")
    target = baseline_path(root)
    target.parent.mkdir(parents=True)
    target.write_text("<<< not a baseline >>>", encoding="utf-8")
    report = inspect_repository(root)
    assert report.secrets
    assert report.suppressed == 0


def test_write_baseline_rejects_a_missing_root(tmp_path: Path) -> None:
    from tauhaulity.tools.allowlist import AllowlistError

    missing = tmp_path / "missing"
    with pytest.raises(AllowlistError):
        write_baseline(missing)
    assert not missing.exists()


def test_remove_baseline_deletes_the_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sentinel, "_default_runner", lambda args, cwd: (1, b""))
    root = _project(tmp_path / "project")
    write_baseline(root)
    assert remove_baseline(root) is True
    assert not baseline_path(root).exists()
    assert remove_baseline(root) is False
