"""Tests for the honeytoken decoy traps.

The decoys exist to be read by the wrong program, so the tests pin the two
properties that make that safe: every deployed file is obviously fake and carries
its traceability marker, and deploy never destroys a real file. The runtime half
is proven in tests/test_runtime_audit_hook.py, where a fresh interpreter can
install the audit hook without leaking it into the rest of the suite.
"""

from __future__ import annotations

import base64
import json
import os
import stat
from pathlib import Path

import pytest

from tauhaulity.tools import honeytoken
from tauhaulity.tools.git_sentinel import inspect_repository, scan_text

NEWLINE = chr(10)


def _project(tmp_path: Path) -> Path:
    root = tmp_path / "project"
    root.mkdir(parents=True)
    return root


def test_deploy_creates_every_default_decoy(tmp_path: Path) -> None:
    root = _project(tmp_path)
    armed = honeytoken.deploy(root)
    assert armed.manifest_path == root / ".tauhaulity" / "honeytokens.json"
    assert armed.manifest_path.is_file()
    assert [token.kind for token in armed.tokens] == list(honeytoken.HONEYTOKEN_KINDS)
    for token in armed.tokens:
        assert token.absolute_path.is_file()
        text = token.absolute_path.read_text(encoding="utf-8")
        assert token.marker in text
        assert token.marker.startswith(honeytoken.MARKER_PREFIX)
        assert token.rel_path.endswith(".honeytoken")
    assert honeytoken.load(root) is not None


def test_deploy_only_requested_kinds(tmp_path: Path) -> None:
    root = _project(tmp_path)
    armed = honeytoken.deploy(root, kinds=("dotenv", "npmrc"))
    assert [token.kind for token in armed.tokens] == ["dotenv", "npmrc"]
    assert not (root / ".ssh").exists()
    assert not (root / ".aws").exists()


def test_unknown_kind_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(honeytoken.HoneytokenError):
        honeytoken.deploy(_project(tmp_path), kinds=("dotenv", "nope"))


def test_deploy_rejects_a_missing_root(tmp_path: Path) -> None:
    missing = tmp_path / "missing"
    with pytest.raises(honeytoken.HoneytokenError):
        honeytoken.deploy(missing)
    assert not missing.exists()


@pytest.mark.skipif(os.name == "nt", reason="Win32 does not store POSIX mode bits")
def test_decoys_and_manifest_are_owner_only(tmp_path: Path) -> None:
    root = _project(tmp_path)
    armed = honeytoken.deploy(root)
    assert stat.S_IMODE(armed.manifest_path.stat().st_mode) == 0o600
    for token in armed.tokens:
        assert stat.S_IMODE(token.absolute_path.stat().st_mode) == 0o600


def test_deploy_never_touches_a_real_env_file(tmp_path: Path) -> None:
    root = _project(tmp_path)
    real = root / ".env"
    original = "REAL_TOKEN=super-secret-value" + NEWLINE
    real.write_text(original, encoding="utf-8")
    armed = honeytoken.deploy(root)
    assert real.read_text(encoding="utf-8") == original
    assert (root / ".env.honeytoken").is_file()
    assert all(token.rel_path != ".env" for token in armed.tokens)


def test_deploy_refuses_an_occupied_path_without_force(tmp_path: Path) -> None:
    root = _project(tmp_path)
    target = root / ".pypirc.honeytoken"
    original = "[pypi]" + NEWLINE + "password = real" + NEWLINE
    target.write_text(original, encoding="utf-8")
    with pytest.raises(honeytoken.HoneytokenError):
        honeytoken.deploy(root)
    assert target.read_text(encoding="utf-8") == original
    # The whole deployment is planned before anything is written.
    assert not (root / ".tauhaulity" / "honeytokens.json").exists()
    assert not (root / ".env.honeytoken").exists()


def test_force_replaces_the_occupied_path(tmp_path: Path) -> None:
    root = _project(tmp_path)
    target = root / ".pypirc.honeytoken"
    target.write_text("REAL=1" + NEWLINE, encoding="utf-8")
    armed = honeytoken.deploy(root, force=True)
    pypirc = next(token for token in armed.tokens if token.kind == "pypirc")
    assert pypirc.marker in target.read_text(encoding="utf-8")
    assert "REAL=1" not in target.read_text(encoding="utf-8")


def test_redeploy_is_idempotent_and_keeps_markers(tmp_path: Path) -> None:
    root = _project(tmp_path)
    first = honeytoken.deploy(root)
    first_markers = {token.kind: token.marker for token in first.tokens}
    first_stamps = {token.kind: token.created_at for token in first.tokens}
    second = honeytoken.deploy(root)
    assert {token.kind: token.marker for token in second.tokens} == first_markers
    assert {token.kind: token.created_at for token in second.tokens} == first_stamps
    assert second.created_at == first.created_at
    payload = json.loads(first.manifest_path.read_text(encoding="utf-8"))
    assert len(payload["tokens"]) == len(honeytoken.HONEYTOKEN_KINDS)
    assert list(root.rglob("*.honeytoken-tmp")) == []


def test_manifest_round_trips_with_relative_paths(tmp_path: Path) -> None:
    root = _project(tmp_path)
    armed = honeytoken.deploy(root)
    payload = json.loads(armed.manifest_path.read_text(encoding="utf-8"))
    assert payload["version"] == honeytoken.MANIFEST_VERSION
    assert payload["generator"] == honeytoken.GENERATOR
    assert payload["created_at"] == armed.created_at
    for row in payload["tokens"]:
        assert set(row) == {"kind", "rel_path", "created_at", "marker"}
        assert not Path(row["rel_path"]).is_absolute()
        assert row["marker"].startswith(honeytoken.MARKER_PREFIX)

    loaded = honeytoken.load(root)
    assert loaded is not None
    assert loaded.root == Path(os.path.abspath(root))
    assert loaded.manifest_path == armed.manifest_path
    assert loaded.created_at == armed.created_at
    assert [
        (token.kind, token.rel_path, token.marker, token.created_at)
        for token in loaded.tokens
    ] == [
        (token.kind, token.rel_path, token.marker, token.created_at)
        for token in armed.tokens
    ]
    assert [token.absolute_path for token in loaded.tokens] == [
        token.absolute_path for token in armed.tokens
    ]


def test_corrupt_manifest_degrades_to_none(tmp_path: Path) -> None:
    root = _project(tmp_path)
    armed = honeytoken.deploy(root)
    armed.manifest_path.write_text("{not json", encoding="utf-8")
    assert honeytoken.load(root) is None
    assert honeytoken.list_tokens(root) == []
    assert honeytoken.token_paths(root) == ()
    assert "none armed" in honeytoken.honeytoken_status(root)
    assert honeytoken.remove(root) is False
    assert armed.tokens[0].absolute_path.is_file()
    repaired = honeytoken.deploy(root)
    assert repaired.manifest_path.is_file()
    assert len(honeytoken.list_tokens(root)) == len(honeytoken.HONEYTOKEN_KINDS)


def test_manifest_ignores_entries_that_escape_the_root(tmp_path: Path) -> None:
    root = _project(tmp_path)
    armed = honeytoken.deploy(root, kinds=("dotenv",))
    payload = json.loads(armed.manifest_path.read_text(encoding="utf-8"))
    payload["tokens"].append(
        {"kind": "dotenv", "rel_path": "../outside", "created_at": "", "marker": "th-honeytoken-deadbeef"}
    )
    armed.manifest_path.write_text(json.dumps(payload), encoding="utf-8")
    loaded = honeytoken.load(root)
    assert loaded is not None
    assert [token.rel_path for token in loaded.tokens] == [".env.honeytoken"]


def test_remove_is_clean_and_idempotent(tmp_path: Path) -> None:
    root = _project(tmp_path)
    real = root / ".env"
    real.write_text("KEEP=1" + NEWLINE, encoding="utf-8")
    armed = honeytoken.deploy(root)
    assert honeytoken.remove(root) is True
    assert not armed.manifest_path.exists()
    assert all(not token.absolute_path.exists() for token in armed.tokens)
    assert real.read_text(encoding="utf-8") == "KEEP=1" + NEWLINE
    assert honeytoken.remove(root) is False


def test_remove_never_deletes_a_file_that_lost_its_marker(tmp_path: Path) -> None:
    root = _project(tmp_path)
    armed = honeytoken.deploy(root, kinds=("dotenv",))
    target = armed.tokens[0].absolute_path
    target.write_text("user replaced the decoy" + NEWLINE, encoding="utf-8")
    assert honeytoken.remove(root) is True
    assert target.is_file()
    assert target.read_text(encoding="utf-8") == "user replaced the decoy" + NEWLINE


def test_decoy_content_is_never_a_usable_credential(tmp_path: Path) -> None:
    root = _project(tmp_path)
    armed = honeytoken.deploy(root)
    for token in armed.tokens:
        text = token.absolute_path.read_text(encoding="utf-8")
        assert token.marker in text
        assert scan_text(text, token.rel_path) == []
        assert "super-secret" not in text
        assert "AKIA" not in text
        assert "ghp_" not in text

    ssh = next(token for token in armed.tokens if token.kind == "ssh_key")
    ssh_text = ssh.absolute_path.read_text(encoding="utf-8")
    assert "-----BEGIN FAKE SSH PRIVATE KEY-----" in ssh_text
    body = "".join(
        line
        for line in ssh_text.splitlines()
        if line and not line.startswith("#") and not line.startswith("-----")
    )
    decoded = base64.b64decode(body).decode("ascii")
    assert ssh.marker in decoded
    assert not decoded.startswith("openssh-key-v1")


def test_decoys_do_not_trip_the_credential_scanner(tmp_path: Path) -> None:
    root = _project(tmp_path)
    honeytoken.deploy(root)
    report = inspect_repository(root)
    assert report.secrets == []
    assert report.scanned_files == 0


def test_token_paths_are_absolute(tmp_path: Path) -> None:
    root = _project(tmp_path)
    armed = honeytoken.deploy(root)
    paths = honeytoken.token_paths(root)
    assert len(paths) == len(honeytoken.HONEYTOKEN_KINDS)
    assert all(path.is_absolute() for path in paths)
    assert set(paths) == {token.absolute_path for token in armed.tokens}


def test_status_reports_armed_count_per_kind_and_alerts(tmp_path: Path) -> None:
    root = _project(tmp_path)
    empty = honeytoken.honeytoken_status(root)
    assert "none armed" in empty
    assert "0 alert(s) since guard start" in empty
    assert NEWLINE not in empty

    honeytoken.deploy(root, kinds=("dotenv", "ssh_key"))
    status = honeytoken.honeytoken_status(root)
    assert "2 armed" in status
    assert "dotenv" in status and "ssh_key" in status
    assert "0 alert(s) since guard start" in status
    assert NEWLINE not in status


def test_deploy_report_names_the_manifest(tmp_path: Path) -> None:
    root = _project(tmp_path)
    report = honeytoken.deploy_report(root)
    assert "deployed 5 honeytoken(s)" in report
    assert str(honeytoken.manifest_path(root)) in report
    assert NEWLINE not in report


def test_pillar_eight_reports_armed_honeytokens(tmp_path: Path) -> None:
    from tauhaulity.core.contracts import ScanContext, ScanOptions
    from tauhaulity.core.platform_probe import detect_platform
    from tauhaulity.core.policy import Policy
    from tauhaulity.pillars import p08_ransom

    root = _project(tmp_path)
    honeytoken.deploy(root, kinds=("dotenv", "ssh_key"))
    ctx = ScanContext(
        target=root,
        platform=detect_platform(),
        policy=Policy(),
        options=ScanOptions(),
    )
    finding = p08_ransom.probe(ctx)
    assert finding.status in p08_ransom.SPEC.statuses
    assert "2 honeytoken(s) armed" in finding.detail
    assert "honeytoken read(s)" not in finding.detail
    assert finding.slot("ring_size").endswith("MB")
