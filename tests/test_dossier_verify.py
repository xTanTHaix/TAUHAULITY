"""Integrity verification tests for the three dossier formats.

The suite drives the real writer and then attacks the produced files: a flipped
byte, a wrong key, a stripped trailer, a converted line ending and an edited JSON
pillar status. It also covers environment key resolution end to end so the CI
affordance is tested through the same path a release engineer would use.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from tauhaulity.core.contracts import PILLAR_SPECS, ScanContext, ScanOptions, make_finding
from tauhaulity.core.platform_probe import detect_platform
from tauhaulity.core.policy import Policy
from tauhaulity.dossier.form_parser import parse_form, render_form_lines
from tauhaulity.dossier.integrity import split_file_stamp
from tauhaulity.dossier.redactor import (
    SIGNING_KEY_ENV,
    hmac_sha256_hex,
    machine_key,
)
from tauhaulity.dossier.render_md import render_markdown_redacted
from tauhaulity.dossier.report import (
    build_report,
    render_markdown,
    render_text,
    report_hmac_payload,
    write_reports,
)
from tauhaulity.dossier.verify import VerificationResult, verify_dossier_file

# Deterministic test key: 32 bytes, not the machine key, so a wrong key test can
# never accidentally pass on a host whose machine key collides with it.
KEY = bytes(range(32))
OTHER_KEY = bytes(range(32, 64))
CREDENTIAL = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

ALL_FORMATS = ("md", "txt", "json")
TEXT_FORMATS = ("md", "txt")


def _context(root: Path, *, policy: Policy | None = None, credential: bool = False) -> ScanContext:
    root.mkdir(parents=True, exist_ok=True)
    ctx = ScanContext(
        target=root,
        platform=detect_platform(),
        policy=policy or Policy(),
        options=ScanOptions(),
    )
    for spec in PILLAR_SPECS:
        detail = f"evidence for pillar {spec.number}"
        if credential and spec.number == 11:
            detail = "staged credential " + CREDENTIAL
        ctx.record(
            make_finding(
                spec,
                spec.statuses[0],
                detail,
                risk=float(spec.number) / 2.0,
                slots={"detail": str(root)},
                repro_hint="repro hint" if spec.number == 7 else None,
            )
        )
    return ctx


def _written(
    tmp_path: Path,
    *,
    policy: Policy | None = None,
    signing_key: bytes | None = KEY,
    formats: tuple[str, ...] = ALL_FORMATS,
) -> tuple[object, dict[str, Path]]:
    """Build and persist a report, returning it alongside the written paths."""

    ctx = _context(tmp_path / "project", policy=policy)
    report = build_report(ctx, signing_key=signing_key)
    paths = write_reports(report, tmp_path / "reports", formats=formats)
    return report, paths


def test_all_three_formats_verify_with_an_explicit_key(tmp_path: Path) -> None:
    report, paths = _written(tmp_path)
    for token in ALL_FORMATS:
        result = verify_dossier_file(paths[token], key=KEY)
        assert isinstance(result, VerificationResult)
        assert result.valid is True, (token, result.reason)
        assert result.key_source == "explicit"
        assert len(result.digest) == 64
    assert verify_dossier_file(paths["md"], key=KEY).scheme == "file-stamp"
    assert verify_dossier_file(paths["txt"], key=KEY).scheme == "file-stamp"
    assert verify_dossier_file(paths["json"], key=KEY).scheme == "canonical-json"
    # The JSON canonical digest is the report HMAC itself.
    assert verify_dossier_file(paths["json"], key=KEY).digest == report.hmac


def test_verification_without_a_key_uses_the_machine_key(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(SIGNING_KEY_ENV, raising=False)
    report, paths = _written(tmp_path, signing_key=None)
    assert report.key_source == "machine"
    for token in ALL_FORMATS:
        result = verify_dossier_file(paths[token])
        assert result.valid is True, (token, result.reason)
        assert result.key_source == "machine"


def test_markdown_and_text_end_with_one_integrity_trailer(tmp_path: Path) -> None:
    _report, paths = _written(tmp_path, formats=TEXT_FORMATS)
    for token in TEXT_FORMATS:
        raw = paths[token].read_bytes()
        assert not raw.startswith(b"\xef\xbb\xbf"), "no BOM is allowed"
        assert raw.endswith(b"\n")
        assert not raw.endswith(b"\n\n"), "exactly one trailing newline is allowed"
        text = raw.decode("utf-8")
        lines = text.splitlines()
        assert lines[-1].startswith("INTEGRITY: sha256=")
        assert sum(line.startswith("INTEGRITY:") for line in lines) == 1
        stamp = split_file_stamp(raw)
        assert stamp.sha256_hex == hashlib.sha256(stamp.payload).hexdigest()


def test_file_stamp_hmac_uses_the_resolved_key(tmp_path: Path) -> None:
    _report, paths = _written(tmp_path, formats=TEXT_FORMATS)
    for token in TEXT_FORMATS:
        raw = paths[token].read_bytes()
        stamp = split_file_stamp(raw)
        expected = hmac_sha256_hex(
            stamp.payload.decode("utf-8"),
            KEY,
        )
        assert stamp.hmac_hex == expected
        # A different key must not reproduce the recorded HMAC.
        assert hmac_sha256_hex(stamp.payload.decode("utf-8"), OTHER_KEY) != stamp.hmac_hex
        assert verify_dossier_file(paths[token], key=KEY).digest == stamp.sha256_hex


@pytest.mark.parametrize("token", TEXT_FORMATS)
def test_single_byte_flip_is_detected(tmp_path: Path, token: str) -> None:
    _report, paths = _written(tmp_path, formats=TEXT_FORMATS)
    path = paths[token]
    raw = bytearray(path.read_bytes())
    raw[0] = raw[0] ^ 0x01
    path.write_bytes(bytes(raw))
    result = verify_dossier_file(path, key=KEY)
    assert result.valid is False
    assert "sha256 mismatch" in result.reason
    # The sha256 half is keyless, so the same tamper is visible without a key.
    keyless = verify_dossier_file(path, key=None, use_machine_key=False)
    assert keyless.valid is False
    assert "sha256 mismatch" in keyless.reason


def test_json_single_byte_flip_is_detected(tmp_path: Path) -> None:
    _report, paths = _written(tmp_path, formats=("json",))
    path = paths["json"]
    raw = path.read_bytes()
    # Flip one byte of the signed target path. The pillar display name is not part
    # of the canonical payload, so the flip must land in a signed field.
    marker = b"project"
    index = raw.index(marker)
    mutated = raw[:index] + b"projecT" + raw[index + len(marker) :]
    path.write_bytes(mutated)
    result = verify_dossier_file(path, key=KEY)
    assert result.valid is False
    assert "hmac mismatch" in result.reason


@pytest.mark.parametrize("token", ALL_FORMATS)
def test_wrong_key_is_detected(tmp_path: Path, token: str) -> None:
    _report, paths = _written(tmp_path, formats=ALL_FORMATS)
    result = verify_dossier_file(paths[token], key=OTHER_KEY)
    assert result.valid is False
    assert "hmac mismatch" in result.reason
    assert result.key_source == "explicit"


def test_missing_trailer_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "no_trailer.md"
    path.write_bytes(b"# dossier body without a stamp\n")
    result = verify_dossier_file(path, key=KEY)
    assert result.valid is False
    assert result.scheme == "file-stamp"
    assert "missing INTEGRITY trailer" in result.reason


def test_malformed_trailer_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "bad_trailer.txt"
    path.write_bytes(b"body line\nINTEGRITY: sha256=deadbeef hmac=deadbeef\n")
    result = verify_dossier_file(path, key=KEY)
    assert result.valid is False
    assert "malformed INTEGRITY trailer" in result.reason


def test_text_byte_order_mark_is_reported(tmp_path: Path) -> None:
    _report, paths = _written(tmp_path, formats=("md",))
    path = paths["md"]
    path.write_bytes(b"\xef\xbb\xbf" + path.read_bytes())
    result = verify_dossier_file(path, key=KEY)
    assert result.valid is False
    assert "byte order mark" in result.reason


def test_empty_file_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "empty.txt"
    path.write_bytes(b"")
    result = verify_dossier_file(path, key=KEY)
    assert result.valid is False
    assert "empty" in result.reason


def test_crlf_converted_file_is_reported(tmp_path: Path) -> None:
    _report, paths = _written(tmp_path, formats=("md",))
    path = paths["md"]
    converted = path.read_bytes().replace(b"\n", b"\r\n")
    path.write_bytes(converted)
    result = verify_dossier_file(path, key=KEY)
    assert result.valid is False
    assert "CRLF" in result.reason


def test_missing_file_is_reported(tmp_path: Path) -> None:
    result = verify_dossier_file(tmp_path / "absent.md", key=KEY)
    assert result.valid is False
    assert "does not exist" in result.reason
    assert result.key_source == "none"


def test_directory_is_reported(tmp_path: Path) -> None:
    target = tmp_path / "folder.md"
    target.mkdir()
    result = verify_dossier_file(target, key=KEY)
    assert result.valid is False
    assert "not a regular file" in result.reason


def test_unknown_extension_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "dossier.pdf"
    path.write_text("not a dossier\n", encoding="utf-8")
    result = verify_dossier_file(path, key=KEY)
    assert result.valid is False
    assert result.scheme == "none"
    assert "unsupported dossier extension" in result.reason


def test_no_machine_key_requires_an_explicit_key(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv(SIGNING_KEY_ENV, raising=False)
    _report, paths = _written(tmp_path, signing_key=None)
    for token in ALL_FORMATS:
        result = verify_dossier_file(paths[token], use_machine_key=False)
        assert result.valid is False
        assert result.key_source == "none"
        assert "no signing key available" in result.reason
        assert verify_dossier_file(paths[token], key=machine_key()).valid is True


def test_env_hex_key_signs_and_verifies(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(SIGNING_KEY_ENV, KEY.hex())
    ctx = _context(tmp_path / "project")
    report = build_report(ctx)
    assert report.key_source == "env"
    assert report.hmac == hmac_sha256_hex(report_hmac_payload(report), KEY)
    paths = write_reports(report, tmp_path / "reports")
    for token in ALL_FORMATS:
        result = verify_dossier_file(paths[token])
        assert result.valid is True, (token, result.reason)
        assert result.key_source == "env"


def test_env_file_key_with_raw_bytes_signs_and_verifies(tmp_path: Path, monkeypatch) -> None:
    raw_key = bytes([0x80 + offset for offset in range(32)])
    key_file = tmp_path / "signing.key"
    key_file.write_bytes(raw_key)
    monkeypatch.setenv(SIGNING_KEY_ENV, str(key_file))
    ctx = _context(tmp_path / "project")
    report = build_report(ctx)
    assert report.key_source == "env"
    assert report.hmac == hmac_sha256_hex(report_hmac_payload(report), raw_key)
    paths = write_reports(report, tmp_path / "reports", formats=TEXT_FORMATS)
    for token in TEXT_FORMATS:
        raw = paths[token].read_bytes()
        stamp = split_file_stamp(raw)
        assert stamp.hmac_hex == hmac_sha256_hex(stamp.payload.decode("utf-8"), raw_key)
        assert verify_dossier_file(paths[token]).valid is True


def test_invalid_env_key_makes_build_report_fail(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv(SIGNING_KEY_ENV, "obviously-not-a-key")
    with pytest.raises(ValueError) as caught:
        build_report(_context(tmp_path / "project"))
    message = str(caught.value)
    assert SIGNING_KEY_ENV in message
    assert "obviously-not-a-key" not in message, "the secret value must not be echoed"


def test_invalid_env_key_is_reported_by_verification(tmp_path: Path, monkeypatch) -> None:
    _report, paths = _written(tmp_path, formats=("md",))
    monkeypatch.setenv(SIGNING_KEY_ENV, str(tmp_path / "missing.key"))
    result = verify_dossier_file(paths["md"])
    assert result.valid is False
    assert result.key_source == "none"
    assert "cannot resolve signing key" in result.reason


def test_json_modified_pillar_status_is_detected(tmp_path: Path) -> None:
    _report, paths = _written(tmp_path, formats=("json",))
    path = paths["json"]
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["pillars"][4]["status"] = "CRITICAL"
    path.write_bytes((json.dumps(payload, indent=2) + "\n").encode("utf-8"))
    result = verify_dossier_file(path, key=KEY)
    assert result.valid is False
    assert result.scheme == "canonical-json"
    assert "hmac mismatch" in result.reason


def test_json_missing_signature_is_reported(tmp_path: Path) -> None:
    _report, paths = _written(tmp_path, formats=("json",))
    path = paths["json"]
    payload = json.loads(path.read_text(encoding="utf-8"))
    del payload["hmac_sha256"]
    path.write_bytes((json.dumps(payload, indent=2) + "\n").encode("utf-8"))
    result = verify_dossier_file(path, key=KEY)
    assert result.valid is False
    assert "hmac_sha256" in result.reason


def test_json_unknown_schema_is_reported(tmp_path: Path) -> None:
    _report, paths = _written(tmp_path, formats=("json",))
    path = paths["json"]
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["schema"] = "tauhaulity.dossier/999"
    path.write_bytes((json.dumps(payload, indent=2) + "\n").encode("utf-8"))
    result = verify_dossier_file(path, key=KEY)
    assert result.valid is False
    assert "unsupported dossier schema" in result.reason


def test_json_invalid_syntax_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "broken.json"
    path.write_bytes(b"{not json")
    result = verify_dossier_file(path, key=KEY)
    assert result.valid is False
    assert "not valid JSON" in result.reason


def test_json_byte_order_mark_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "bom.json"
    path.write_bytes(b"\xef\xbb\xbf{}")
    result = verify_dossier_file(path, key=KEY)
    assert result.valid is False
    assert "byte order mark" in result.reason


def test_form_round_trip_survives_the_trailer(tmp_path: Path) -> None:
    policy = Policy(
        enforce_active=True,
        auto_hotpatch=True,
        block_git_secrets=False,
        undo_ring_mb=256,
        auto_zombie_free=True,
        ignored_paths=("build", "node_modules"),
        auditor="Zoe\u0308 A\u030angstro\u0308m",
    )
    ctx = _context(tmp_path / "project", policy=policy)
    report = build_report(ctx, signing_key=KEY)
    for token in TEXT_FORMATS:
        path = write_reports(report, tmp_path / "reports", formats=(token,))[token]
        text = path.read_text(encoding="utf-8")
        assert text.splitlines()[-1].startswith("INTEGRITY: ")
        merged = policy.with_overrides(parse_form(text))
        assert merged == policy


def test_sec4_form_block_stays_byte_identical(tmp_path: Path) -> None:
    policy = Policy(undo_ring_mb=1024, auditor="Ada Lovelace")
    ctx = _context(tmp_path / "project", policy=policy)
    report = build_report(ctx, signing_key=KEY)
    expected = render_form_lines(policy)
    assert len(expected) == 7
    for token in TEXT_FORMATS:
        text = write_reports(report, tmp_path / "reports", formats=(token,))[token].read_text(
            encoding="utf-8"
        )
        lines = text.splitlines()
        for form_line in expected:
            assert lines.count(form_line) == 1, form_line


def test_redacted_markdown_is_stamped_after_redaction(tmp_path: Path) -> None:
    ctx = _context(tmp_path / "project", credential=True)
    report = build_report(ctx, signing_key=KEY)
    text = render_markdown_redacted(report)
    assert CREDENTIAL not in text
    path = tmp_path / "redacted.md"
    path.write_bytes(text.encode("utf-8"))
    result = verify_dossier_file(path, key=KEY)
    assert result.valid is True, result.reason


def test_rendered_text_and_markdown_carry_the_report_digest(tmp_path: Path) -> None:
    report = build_report(_context(tmp_path / "project"), signing_key=KEY)
    for text in (render_markdown(report), render_text(report)):
        assert report.hmac in text
        assert "INTEGRITY: sha256=" in text


def test_verification_never_raises_for_a_readable_file(tmp_path: Path) -> None:
    path = tmp_path / "garbage.txt"
    path.write_bytes(bytes(range(64)))
    result = verify_dossier_file(path, key=KEY)
    assert result.valid is False
    assert result.reason


def test_build_report_keeps_positional_repro_files_compatibility(tmp_path: Path) -> None:
    ctx = _context(tmp_path / "project")
    report = build_report(ctx, ("repro_slot_01.py",), signing_key=KEY)
    assert report.repro_files == ("repro_slot_01.py",)
    assert report.key_source == "explicit"
    assert report.hmac == hmac_sha256_hex(report_hmac_payload(report), KEY)


def test_report_repr_never_prints_the_signing_key(tmp_path: Path) -> None:
    report = build_report(_context(tmp_path / "project"), signing_key=KEY)
    rendered = repr(report)
    assert "signing_key" not in rendered
    assert report.signing_key == KEY


def test_verification_rejects_non_bytes_key(tmp_path: Path) -> None:
    path = tmp_path / "dossier.md"
    path.write_text("body\n", encoding="utf-8")
    with pytest.raises(TypeError):
        verify_dossier_file(path, key="not-bytes")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        verify_dossier_file(path, key=b"")
