"""Tests for the reviewable finding suppression store.

The fixtures are real project trees: a gated deserialization wrapper shaped like
the tool's own PickleGate, a module level shell call, and TLS verification
disabled in two separate files. The tests prove three properties the mechanism
must never lose: a suppression is tied to the reviewed code and not to a line
number, an empty reason cannot be stored, and a broken store degrades to "no
suppressions" instead of crashing the scanner.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from tauhaulity.core.contracts import ScanContext, ScanOptions
from tauhaulity.pillars import p06_supply as pillar
from tauhaulity.tools import artifact_scan, suppress

GATE_SOURCE = (
    "import pickle\n"
    "class PickleGate:\n"
    "    def scan(self, data):\n"
    "        return bool(data)\n"
    "    def loads(self, data):\n"
    "        if not self.scan(data):\n"
    "            raise ValueError('unsafe stream')\n"
    "        return pickle.loads(data)\n"
)
TWO_CALL_SOURCE = (
    "import pickle\n"
    "def first(data):\n"
    "    return pickle.loads(data)\n"
    "def second(data):\n"
    "    return pickle.loads(data)\n"
)
TLS_SOURCE = (
    "import requests\n"
    "def fetch(url):\n"
    "    return requests.get(url, verify=False)\n"
)
SHELL_SOURCE = "import os\nos.system('ls')\n"


def _write(root: Path, name: str, text: str) -> Path:
    """Write one project relative source file and return its path."""

    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _context(root: Path, platform_info, policy) -> ScanContext:
    """Build a scan context for a temporary project."""

    return ScanContext(target=root, platform=platform_info, policy=policy, options=ScanOptions())


def _scan(root: Path, store: suppress.SuppressionStore | None = None) -> artifact_scan.ArtifactReport:
    """Scan a project, optionally applying a suppression store."""

    return artifact_scan.scan_source_tree(root, suppress=store)


def test_fingerprint_ignores_the_line_number(tmp_path: Path) -> None:
    _write(tmp_path, "gate.py", GATE_SOURCE)
    first = [finding for finding in _scan(tmp_path).findings if finding.rel_path == "gate.py"]
    assert len(first) == 1
    assert first[0].symbol == "PickleGate.loads"
    fingerprint_before = suppress.fingerprint_finding(first[0].rel_path, first[0].kind, first[0].symbol)
    _write(tmp_path, "gate.py", chr(10) * 3 + GATE_SOURCE)
    shifted = [finding for finding in _scan(tmp_path).findings if finding.rel_path == "gate.py"]
    assert shifted[0].line_no == first[0].line_no + 3
    fingerprint_after = suppress.fingerprint_finding(shifted[0].rel_path, shifted[0].kind, shifted[0].symbol)
    assert fingerprint_after == fingerprint_before


def test_fingerprint_changes_when_the_enclosing_symbol_is_renamed(tmp_path: Path) -> None:
    _write(tmp_path, "gate.py", GATE_SOURCE)
    original = _scan(tmp_path).findings[0]
    _write(tmp_path, "gate.py", GATE_SOURCE.replace("PickleGate", "SafeGate"))
    renamed = _scan(tmp_path).findings[0]
    assert original.symbol == "PickleGate.loads"
    assert renamed.symbol == "SafeGate.loads"
    assert suppress.fingerprint_finding(
        original.rel_path, original.kind, original.symbol
    ) != suppress.fingerprint_finding(renamed.rel_path, renamed.kind, renamed.symbol)


def test_fingerprint_is_sha256_hex_and_path_normalized() -> None:
    fingerprint = suppress.fingerprint_finding("pkg/app.py", "dangerous_api", "PickleGate.loads")
    assert len(fingerprint) == 64
    assert int(fingerprint, 16) >= 0
    assert fingerprint == suppress.fingerprint_finding("pkg/app.py", "dangerous_api", "PickleGate.loads")
    assert fingerprint == suppress.fingerprint_finding(
        "pkg" + chr(92) + "app.py", "dangerous_api", "PickleGate.loads"
    )
    assert fingerprint != suppress.fingerprint_finding("pkg/app.py", "dangerous_api", "Other.loads")


def test_add_refuses_an_empty_reason(tmp_path: Path) -> None:
    _write(tmp_path, "gate.py", GATE_SOURCE)
    keys = suppress.list_suppression_candidates(tmp_path)
    store = suppress.SuppressionStore(tmp_path)
    with pytest.raises(suppress.SuppressionError):
        store.add(keys, "")
    with pytest.raises(ValueError):
        store.add(keys, "   " + chr(10))
    assert not store.path.exists(), "an empty reason must not create the store"


def test_store_roundtrip_writes_a_versioned_atomic_file(tmp_path: Path) -> None:
    _write(tmp_path, "gate.py", GATE_SOURCE)
    _write(tmp_path, "api.py", SHELL_SOURCE)
    keys = suppress.list_suppression_candidates(tmp_path)
    store = suppress.SuppressionStore(tmp_path)
    added = store.add(keys, "reviewed wrappers and probe code for the test fixture")
    assert added == len(keys) >= 2
    assert store.path.is_file()
    payload = json.loads(store.path.read_text(encoding="utf-8"))
    assert payload["version"] == suppress.SUPPRESS_VERSION == 1
    assert payload["generator"] == "tauhaulity.tools.suppress"
    assert payload["created_at"]
    assert len(payload["entries"]) == added
    for entry in payload["entries"]:
        assert entry["fingerprint"] == suppress.fingerprint_finding(
            entry["rel_path"], entry["kind"], entry["symbol"]
        )
        assert entry["reason"] == "reviewed wrappers and probe code for the test fixture"
        assert entry["created_at"]
    leftovers = [path.name for path in store.path.parent.iterdir() if path.name.endswith(".tmp")]
    assert leftovers == []
    assert store.add(keys, "second review pass") == 0
    assert suppress.SuppressionStore(tmp_path).load()[0].reason == (
        "reviewed wrappers and probe code for the test fixture"
    )


@pytest.mark.skipif(os.name == "nt", reason="NTFS exposes only the read-only bit, not POSIX mode 0600")
def test_store_file_is_owner_only_on_posix(tmp_path: Path) -> None:
    _write(tmp_path, "gate.py", GATE_SOURCE)
    store = suppress.SuppressionStore(tmp_path)
    store.add(suppress.list_suppression_candidates(tmp_path), "owner only permission check")
    assert (store.path.stat().st_mode & 0o777) == 0o600


def test_corrupt_or_missing_store_degrades_to_no_suppressions(tmp_path: Path) -> None:
    _write(tmp_path, "gate.py", GATE_SOURCE)
    store = suppress.SuppressionStore(tmp_path)
    assert store.load() == []
    assert _scan(tmp_path, store=store).suppressed == 0
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text("not json at all", encoding="utf-8")
    assert store.load() == []
    assert len(_scan(tmp_path, store=store).findings) == 1
    store.path.write_text(json.dumps({"version": 1, "entries": "not a list"}), encoding="utf-8")
    assert store.load() == []
    store.path.write_text(json.dumps([42, {"kind": "dangerous_api"}]), encoding="utf-8")
    assert store.load() == []


def test_load_recomputes_fingerprints_and_drops_anonymous_entries(tmp_path: Path) -> None:
    _write(tmp_path, "gate.py", GATE_SOURCE)
    finding = _scan(tmp_path).findings[0]
    store = suppress.SuppressionStore(tmp_path)
    store.path.parent.mkdir(parents=True, exist_ok=True)
    store.path.write_text(
        json.dumps(
            {
                "version": 1,
                "entries": [
                    {
                        "fingerprint": "not-the-right-digest",
                        "kind": finding.kind,
                        "rel_path": finding.rel_path,
                        "symbol": finding.symbol,
                        "reason": "hand written entry with a stale digest",
                        "created_at": "2026-01-01T00:00:00+00:00",
                    },
                    {
                        "kind": finding.kind,
                        "rel_path": finding.rel_path,
                        "symbol": finding.symbol,
                        "reason": "no digest at all",
                    },
                    {
                        "kind": finding.kind,
                        "rel_path": finding.rel_path,
                        "symbol": finding.symbol,
                        "reason": "",
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    entries = store.load()
    # All three records describe the same reviewed call site, so the recomputed
    # fingerprint collapses them into one entry; the anonymous record is dropped.
    assert len(entries) == 1
    assert entries[0].fingerprint == finding_symbol_fingerprint(finding)
    assert entries[0].reason == "hand written entry with a stale digest"
    assert _scan(tmp_path, store=store).suppressed == 1


def finding_symbol_fingerprint(finding: artifact_scan.ArtifactFinding) -> str:
    """Recompute the suppression fingerprint of one scanner finding."""

    return suppress.fingerprint_finding(finding.rel_path, finding.kind, finding.symbol)


def test_filter_findings_drops_only_the_reviewed_site(tmp_path: Path) -> None:
    _write(tmp_path, "gate.py", GATE_SOURCE)
    _write(tmp_path, "api.py", SHELL_SOURCE)
    keys = suppress.list_suppression_candidates(tmp_path)
    gate_key = next(key for key in keys if key.rel_path == "gate.py")
    store = suppress.SuppressionStore(tmp_path)
    assert store.add([gate_key], "the gate validates before it deserializes") == 1
    report = _scan(tmp_path, store=store)
    assert [finding.rel_path for finding in report.findings] == ["api.py"]
    assert report.suppressed == 1
    assert "1 finding(s) suppressed by review" in report.detail
    assert "suppressions.json" in report.detail


def test_two_call_sites_in_one_file_one_suppression(tmp_path: Path) -> None:
    _write(tmp_path, "calls.py", TWO_CALL_SOURCE)
    keys = suppress.list_suppression_candidates(tmp_path)
    first_key = next(key for key in keys if key.symbol == "first")
    store = suppress.SuppressionStore(tmp_path)
    store.add([first_key], "first() only receives a constant produced in process")
    report = _scan(tmp_path, store=store)
    assert [finding.symbol for finding in report.findings] == ["second"]
    assert report.suppressed == 1


def test_every_finding_suppressed_is_stated_not_silent(tmp_path: Path) -> None:
    _write(tmp_path, "api.py", SHELL_SOURCE)
    keys = suppress.list_suppression_candidates(tmp_path)
    store = suppress.SuppressionStore(tmp_path)
    store.add(keys, "probe fixture, never executed")
    report = _scan(tmp_path, store=store)
    assert report.findings == ()
    assert report.suppressed == 1
    assert "no active unsafe serialized payload" in report.detail
    assert "1 finding(s) suppressed by review" in report.detail
    assert "suppressions.json" in report.detail


def test_remove_all_clears_the_review_decisions(tmp_path: Path) -> None:
    _write(tmp_path, "gate.py", GATE_SOURCE)
    store = suppress.SuppressionStore(tmp_path)
    store.add(suppress.list_suppression_candidates(tmp_path), "temporary review")
    assert store.remove_all() is True
    assert store.remove_all() is False
    assert store.load() == []
    assert len(_scan(tmp_path, store=store).findings) == 1


def test_list_suppression_candidates_reports_current_keys(tmp_path: Path) -> None:
    _write(tmp_path, "gate.py", GATE_SOURCE)
    _write(tmp_path, "api.py", SHELL_SOURCE)
    keys = suppress.list_suppression_candidates(tmp_path)
    assert [(key.rel_path, key.kind, key.symbol) for key in keys] == [
        ("api.py", "dangerous_api", ""),
        ("gate.py", "dangerous_api", "PickleGate.loads"),
    ]
    assert all(key.line_no is not None and key.line_no > 0 for key in keys)
    assert all(len(key.fingerprint) == 64 for key in keys)
    deduplicated = suppress.list_suppression_candidates(_write_dedup_project(tmp_path / "dedup"))
    assert len(deduplicated) == 1


def _write_dedup_project(root: Path) -> Path:
    """Build a project with two calls in one function, which share one fingerprint."""

    _write(
        root,
        "twice.py",
        "import pickle\n"
        "def load_pair(a, b):\n"
        "    first = pickle.loads(a)\n"
        "    second = pickle.loads(b)\n"
        "    return first, second\n",
    )
    return root


def test_suppression_store_is_per_project(tmp_path: Path) -> None:
    left = tmp_path / "left"
    right = tmp_path / "right"
    for root in (left, right):
        _write(root, "gate.py", GATE_SOURCE)
    store = suppress.SuppressionStore(left)
    store.add(suppress.list_suppression_candidates(left), "left project review only")
    assert suppress.SuppressionStore(right).load() == []
    assert len(_scan(right).findings) == 1


def test_real_gated_wrapper_is_flagged_then_reviewed(
    tmp_path: Path, platform_info, default_policy
) -> None:
    _write(tmp_path, "gate.py", GATE_SOURCE)
    flagged = _scan(tmp_path)
    assert len(flagged.findings) == 1
    finding = flagged.findings[0]
    assert finding.kind == "dangerous_api"
    assert finding.severity == "high"
    assert finding.symbol == "PickleGate.loads"
    reason = (
        "PickleGate.loads runs PickleGate.scan over the opcode stream before it "
        "deserializes, so this call is the gated entry point"
    )
    store = suppress.SuppressionStore(tmp_path)
    assert store.add([suppress.FindingKey(finding.rel_path, finding.kind, finding.line_no, finding.symbol)], reason) == 1
    reviewed = _scan(tmp_path, store=store)
    assert reviewed.findings == ()
    assert reviewed.suppressed == 1
    probe = pillar.probe(_context(tmp_path, platform_info, default_policy))
    assert probe.status == "SAFE", probe.detail
    detail = probe.slot("detail")
    assert "1 finding(s) suppressed by review" in detail
    assert "first suppression reason:" in detail
    assert "gated entry point" in detail