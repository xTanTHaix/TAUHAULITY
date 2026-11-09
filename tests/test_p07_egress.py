"""Tests for pillar seven: pre-TLS capture, DNS/ICMP entropy gates, secret detector.

The pre-TLS path is exercised through watch_callable so no socket is opened, and
once through a real install/uninstall cycle on ssl.SSLSocket.send to prove the
monkeypatch is reversible.
"""

from __future__ import annotations

import os
import ssl
from pathlib import Path

import pytest

from tauhaulity.core.contracts import ScanContext, ScanOptions
from tauhaulity.pillars import p07_egress as pillar

_GITHUB_TOKEN = b"ghp_AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"


def _make_ctx(target: Path, platform_info, policy) -> ScanContext:
    return ScanContext(target=Path(target), platform=platform_info, policy=policy, options=ScanOptions())


def test_pre_tls_hook_captures_and_detects() -> None:
    hook = pillar.PreTlsHook(capacity=8, slot_bytes=64)
    try:
        calls: list[bytes] = []
        instrumented = hook.watch_callable(lambda data, flags=0: calls.append(data) or len(data))
        payload = b"POST /upload HTTP/1.1\r\n" + _GITHUB_TOKEN + b"\r\n\r\n"
        assert instrumented(payload, 0) == len(payload)
        assert calls == [payload]
        captured = hook.drain()
        assert len(captured) == 1
        assert len(captured[0]) <= hook.slot_bytes
        assert captured[0] == payload[: hook.slot_bytes]
        stats = hook.stats()
        assert stats["observed"] == 1
        assert stats["secret_hits"] >= 1
        assert hook.recent_hits(1)
        assert hook.drain() == []
    finally:
        hook.close()


def test_pre_tls_hook_install_and_uninstall() -> None:
    original = ssl.SSLSocket.send
    hook = pillar.PreTlsHook(capacity=4, slot_bytes=32)
    try:
        assert hook.install() is True
        assert hook.active is True
        assert ssl.SSLSocket.send is not original
        assert hook.install() is True
        assert hook.uninstall() is True
        assert hook.active is False
        assert ssl.SSLSocket.send is original
        assert hook.uninstall() is False
    finally:
        hook.close()
    assert ssl.SSLSocket.send is original


def test_pre_tls_ring_is_bounded() -> None:
    hook = pillar.PreTlsHook(capacity=2, slot_bytes=16)
    try:
        instrumented = hook.watch_callable(lambda data, flags=0: len(data))
        for index in range(10):
            instrumented(bytes([index]) * 16, 0)
        captured = hook.drain()
        assert len(captured) <= 2
        stats = hook.stats()
        assert stats["observed"] == 10
        assert stats["ring_produced"] <= 2
        assert stats["dropped"] >= 1
    finally:
        hook.close()


def test_dns_gate_allows_normal_names() -> None:
    gate = pillar.DnsGate()
    for name in ("api.github.com", "www.example.test", "localhost", "a.b.c.d.example.org."):
        verdict = gate.evaluate(name)
        assert verdict.allowed, f"{name}: {verdict.reasons}"
    assert gate.allows(b"example.com")


def test_dns_gate_rejects_tunnel_names() -> None:
    gate = pillar.DnsGate()
    tunnel = gate.evaluate("dGhpcyBpcyBhIHR1bm5lbCBwYXlsb2FkLndpdGguYmluYXJ5.example.com")
    assert tunnel.allowed is False
    assert tunnel.reasons
    assert tunnel.max_entropy >= 4.2
    long_label = gate.evaluate("a" * 64 + ".example.com")
    assert long_label.allowed is False
    overlong_name = gate.evaluate(".".join(["abc"] * 100) + ".example.com")
    assert overlong_name.allowed is False
    assert gate.evaluate("").allowed is False
    assert gate.evaluate("double..dot.example.com").allowed is False


def test_icmp_gate_payload_policy() -> None:
    gate = pillar.IcmpGate()
    assert gate.allows(b"tauhaulity ping", icmp_type=8) is True
    assert gate.evaluate(b"", icmp_type=8).allowed is True
    dense = bytes(range(256))
    tunnel = gate.evaluate(dense, icmp_type=8)
    assert tunnel.allowed is False
    assert tunnel.entropy > 7.0
    oversized = gate.evaluate(b"A" * 600, icmp_type=8)
    assert oversized.allowed is False
    assert gate.evaluate(b"payload", icmp_type=13).allowed is False
    assert gate.evaluate(b"", icmp_type=13).allowed is True
    assert gate.evaluate(bytes(range(256)), icmp_type=0).allowed is False


def test_secret_detector_patterns() -> None:
    detector = pillar.SecretPatternDetector()
    payload = (
        b"token=" + _GITHUB_TOKEN + b" aws=AKIAABCDEFGHIJKLMNOP "
        b"-----BEGIN OPENSSH PRIVATE KEY----- password=hunter2hunter2"
    )
    hits = detector.detect(payload)
    kinds = {hit.kind for hit in hits}
    assert "github-classic-pat" in kinds
    assert "aws-access-key" in kinds
    assert "pem-private-key" in kinds
    assert "password-assignment" in kinds
    for hit in hits:
        assert "****REDACTED****" in hit.masked
        assert _GITHUB_TOKEN.decode() not in hit.masked
        assert hit.start >= 0
    assert detector.has_secrets(b"sk-" + b"a" * 24) is True
    assert detector.has_secrets(b"GET /health HTTP/1.1\r\nHost: api.example.test\r\n\r\n") is False
    redacted, count = detector.redact(payload)
    assert count >= 1
    assert _GITHUB_TOKEN not in redacted
    assert b"****REDACTED****" in redacted


def test_secret_detector_flags_base64_blob() -> None:
    detector = pillar.SecretPatternDetector()
    blob = b"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk="
    hits = detector.detect(b"data=" + blob)
    assert any(hit.kind == "base64-blob" for hit in hits)


def test_probe_returns_legal_finding(sample_project: Path, platform_info, default_policy) -> None:
    ctx = _make_ctx(sample_project, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.pillar == 7
    assert finding.status in pillar.SPEC.statuses
    assert 0.0 <= finding.risk <= pillar.SPEC.risk_scale
    assert "dns tunnel blocked" in finding.slot("detail")
    ctx.record(finding)
