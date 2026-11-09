"""Tests for credential redaction, masking and dossier HMAC integrity."""

from __future__ import annotations

import pytest

from tauhaulity.dossier import redactor
from tauhaulity.dossier.redactor import (
    MASK,
    SIGNING_KEY_ENV,
    hmac_sha256_hex,
    machine_key,
    mask_secret,
    redact_text,
    resolve_signing_key,
    verify_hmac,
)

CLASSIC_TOKEN = "ghp_ExampleTokenValueThatLooksReal1234567890"
FINE_GRAINED = "github_pat_" + "A" * 60
OPENAI_KEY = "sk-" + "b" * 40
AWS_KEY = "AKIA" + "Q" * 16


def test_redacts_every_family_and_counts_matches() -> None:
    text = (
        "GITHUB_TOKEN=" + CLASSIC_TOKEN + "\n"
        "FINE=" + FINE_GRAINED + "\n"
        "OPENAI=" + OPENAI_KEY + "\n"
        "AWS=" + AWS_KEY + "\n"
    )
    redacted, count = redact_text(text)
    assert count == 4
    for secret in (CLASSIC_TOKEN, FINE_GRAINED, OPENAI_KEY, AWS_KEY):
        assert secret not in redacted
    assert redacted.count(MASK) == 4
    assert "ghp_" + MASK in redacted
    assert "github_pat_" + MASK in redacted
    assert "sk-" + MASK in redacted
    assert "AKIA" + MASK in redacted


def test_redaction_is_idempotent_and_counts_zero_second_time() -> None:
    first, first_count = redact_text("token " + CLASSIC_TOKEN)
    second, second_count = redact_text(first)
    assert first_count == 1
    assert second_count == 0
    assert second == first


def test_masks_url_userinfo_and_private_key_blocks() -> None:
    url_text = "remote = https://user:" + CLASSIC_TOKEN + "@example.test/repo.git"
    redacted_url, url_count = redact_text(url_text)
    assert url_count == 1
    assert CLASSIC_TOKEN not in redacted_url
    assert "https://user:" + MASK + "@example.test/repo.git" in redacted_url

    pem = (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQ\n"
        "-----END OPENSSH PRIVATE KEY-----"
    )
    redacted_pem, pem_count = redact_text(pem)
    assert pem_count == 1
    assert "b3BlbnNzaC1rZXk" not in redacted_pem
    assert MASK in redacted_pem


def test_bearer_header_is_masked() -> None:
    redacted, count = redact_text("Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345")
    assert count == 1
    assert "abcdefghijklmnopqrstuvwxyz012345" not in redacted
    assert "Bearer " + MASK in redacted


def test_clean_text_reports_zero() -> None:
    assert redact_text("nothing to see here") == ("nothing to see here", 0)
    assert redact_text("") == ("", 0)


def test_mask_secret_keeps_only_family_prefix() -> None:
    assert mask_secret(CLASSIC_TOKEN) == "ghp_" + MASK
    assert mask_secret(FINE_GRAINED) == "github_pat_" + MASK
    assert mask_secret(OPENAI_KEY) == "sk-" + MASK
    assert mask_secret(AWS_KEY) == "AKIA" + MASK
    assert mask_secret("plain-secret-value") == MASK
    assert mask_secret("") == ""
    # Masking an already masked value stays stable so repeated passes agree.
    assert mask_secret("ghp_" + MASK) == "ghp_" + MASK


def test_mask_secret_rejects_non_string() -> None:
    with pytest.raises(TypeError):
        mask_secret(123)  # type: ignore[arg-type]


def test_redact_text_rejects_non_string() -> None:
    with pytest.raises(TypeError):
        redact_text(None)  # type: ignore[arg-type]


def test_machine_key_is_stable_and_32_bytes() -> None:
    first = machine_key()
    second = machine_key()
    assert isinstance(first, bytes)
    assert len(first) == 32
    assert first == second
    assert first != b"\x00" * 32


def test_hmac_verify_true_false_and_malformed() -> None:
    payload = "tauhaulity dossier payload"
    key = b"unit-test-key"
    signature = hmac_sha256_hex(payload, key)
    assert len(signature) == 64
    assert verify_hmac(payload, signature, key) is True
    assert verify_hmac(payload, signature.upper(), key) is True
    assert verify_hmac(payload + " ", signature, key) is False
    assert verify_hmac(payload, signature, b"other-key") is False
    assert verify_hmac(payload, "", key) is False
    assert verify_hmac(payload, "not-a-digest", key) is False
    assert verify_hmac(None, signature, key) is False  # type: ignore[arg-type]
    assert verify_hmac(payload, None, key) is False  # type: ignore[arg-type]


def test_hmac_uses_machine_key_when_omitted() -> None:
    payload = "dossier body"
    assert hmac_sha256_hex(payload) == hmac_sha256_hex(payload, machine_key())
    assert verify_hmac(payload, hmac_sha256_hex(payload)) is True


def test_hmac_rejects_non_bytes_key() -> None:
    with pytest.raises(TypeError):
        hmac_sha256_hex("text", "string-key")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        hmac_sha256_hex(b"bytes", b"key")  # type: ignore[arg-type]


def test_report_masks_credentials_found_in_pillar_evidence(tmp_path) -> None:
    from tauhaulity.core.contracts import PILLAR_SPECS, ScanContext, ScanOptions, make_finding
    from tauhaulity.core.platform_probe import detect_platform
    from tauhaulity.core.policy import Policy
    from tauhaulity.dossier.report import (
        build_report,
        render_json,
        render_markdown,
        report_hmac_payload,
    )

    root = tmp_path / "project"
    root.mkdir()
    ctx = ScanContext(target=root, platform=detect_platform(), policy=Policy(), options=ScanOptions())
    for spec in PILLAR_SPECS:
        detail = (
            "staged credential " + CLASSIC_TOKEN
            if spec.number == 11
            else f"clean evidence {spec.number}"
        )
        ctx.record(make_finding(spec, spec.statuses[0], detail, slots={"detail": detail}))
    report = build_report(ctx)
    assert CLASSIC_TOKEN not in report.finding(11).detail
    assert MASK in report.finding(11).detail
    assert CLASSIC_TOKEN not in render_markdown(report)
    assert CLASSIC_TOKEN not in render_json(report)
    assert CLASSIC_TOKEN not in report_hmac_payload(report)


def test_resolve_signing_key_prefers_explicit_then_env_then_machine(monkeypatch) -> None:
    monkeypatch.delenv(SIGNING_KEY_ENV, raising=False)
    assert resolve_signing_key(b"unit-explicit-key") == (b"unit-explicit-key", "explicit")
    assert resolve_signing_key() == (machine_key(), "machine")
    monkeypatch.setenv(SIGNING_KEY_ENV, "0123456789abcdef" * 4)
    # An explicit key must win even when the environment is configured.
    assert resolve_signing_key(b"unit-explicit-key") == (b"unit-explicit-key", "explicit")
    key, source = resolve_signing_key()
    assert source == "env"
    assert len(key) == 32


def test_resolve_signing_key_reads_a_hex_env_value(monkeypatch) -> None:
    hex_key = "0123456789abcdef" * 4
    monkeypatch.setenv(SIGNING_KEY_ENV, hex_key)
    key, source = resolve_signing_key()
    assert source == "env"
    assert key == bytes.fromhex(hex_key)


def test_resolve_signing_key_reads_a_hex_key_file(tmp_path, monkeypatch) -> None:
    key = bytes(range(32))
    key_file = tmp_path / "signing.key"
    key_file.write_text(key.hex() + chr(10), encoding="ascii")
    monkeypatch.setenv(SIGNING_KEY_ENV, str(key_file))
    assert resolve_signing_key() == (key, "env")


def test_resolve_signing_key_reads_a_base64_key_file(tmp_path, monkeypatch) -> None:
    import base64

    key = bytes(range(32))
    key_file = tmp_path / "signing.b64"
    key_file.write_text(base64.b64encode(key).decode("ascii") + chr(10), encoding="ascii")
    monkeypatch.setenv(SIGNING_KEY_ENV, str(key_file))
    assert resolve_signing_key() == (key, "env")


def test_resolve_signing_key_reads_a_raw_binary_key_file(tmp_path, monkeypatch) -> None:
    key = bytes([0x80 + offset for offset in range(32)])
    key_file = tmp_path / "signing.bin"
    key_file.write_bytes(key)
    monkeypatch.setenv(SIGNING_KEY_ENV, str(key_file))
    assert resolve_signing_key() == (key, "env")


def test_resolve_signing_key_ignores_a_blank_env_value(monkeypatch) -> None:
    monkeypatch.setenv(SIGNING_KEY_ENV, "   ")
    assert resolve_signing_key() == (machine_key(), "machine")


def test_resolve_signing_key_rejects_an_invalid_env_value(monkeypatch) -> None:
    monkeypatch.setenv(SIGNING_KEY_ENV, "obviously-not-a-key")
    with pytest.raises(ValueError) as caught:
        resolve_signing_key()
    message = str(caught.value)
    assert SIGNING_KEY_ENV in message
    assert "obviously-not-a-key" not in message


def test_resolve_signing_key_rejects_a_missing_env_key_file(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv(SIGNING_KEY_ENV, str(tmp_path / "absent.key"))
    with pytest.raises(ValueError) as caught:
        resolve_signing_key()
    assert SIGNING_KEY_ENV in str(caught.value)


def test_resolve_signing_key_rejects_an_empty_env_key_file(tmp_path, monkeypatch) -> None:
    key_file = tmp_path / "empty.key"
    key_file.write_bytes(b"")
    monkeypatch.setenv(SIGNING_KEY_ENV, str(key_file))
    with pytest.raises(ValueError) as caught:
        resolve_signing_key()
    assert "empty" in str(caught.value)


def test_resolve_signing_key_rejects_bad_explicit_values() -> None:
    with pytest.raises(TypeError):
        resolve_signing_key("string-key")  # type: ignore[arg-type]
    with pytest.raises(ValueError):
        resolve_signing_key(b"")


def test_module_exposes_documented_machine_key_caveat() -> None:
    # The docstring must state that the machine key is tamper-evident, not secret,
    # so a reader cannot mistake the stamp for a trusted signature.
    assert "not a" in redactor.machine_key.__doc__.lower()
    assert "tamper" in redactor.machine_key.__doc__.lower()
