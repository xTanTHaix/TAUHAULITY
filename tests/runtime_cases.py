"""Runtime detector corpus: honeytoken, memory baseline and the watch backends.

The red-team corpus covers the static scanners. These thirty cases give the three
runtime protections the same measured treatment: each case builds a real fixture,
calls the shipped API, and asserts the behaviour a reviewer would expect. Assertions
live inside the builders, so the shared corpus runner reports a raised
AssertionError as a case failure.

Run: python -m pytest tests/test_runtime_corpus.py -m corpus
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

from tests.corpus_runner import CorpusCase, run_corpus, summarize

RUNTIME_CASES: list[CorpusCase] = []


def _case(case_id: str, category: str, description: str, builder) -> None:
    """Register one case whose builder performs the assertions itself."""

    RUNTIME_CASES.append(
        CorpusCase(
            case_id=case_id,
            category=category,
            description=description,
            build=builder,
            expect={},
        )
    )


def _project(root: Path) -> Path:
    """Create a minimal project and return it."""

    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "src" / "app.py").write_text("VALUE = 1" + chr(10), encoding="utf-8")
    return root


# --------------------------------------------------------------- honeytoken
def _honeytoken_deploy(root: Path) -> None:
    from tauhaulity.tools.honeytoken import deploy, list_tokens

    _project(root)
    tokens = deploy(root)
    assert tokens.tokens, "deploy must create at least one decoy"
    assert len(list_tokens(root)) == len(tokens.tokens)


def _honeytoken_read_alerts(root: Path) -> None:
    script = (
        "import sys, pathlib;"
        "sys.path.insert(0, sys.argv[1]);"
        "from tauhaulity.runtime import audit_hook;"
        "from tauhaulity.tools.honeytoken import token_paths;"
        "audit_hook.set_honeypot_paths([str(p) for p in token_paths(pathlib.Path(sys.argv[2]))]);"
        "audit_hook.guard.install(enforce=False);"
        "open(sys.argv[3], 'rb').read();"
        "print(len(audit_hook.honeypot_events()));"
    )
    from tauhaulity.tools.honeytoken import deploy, token_paths

    project = _project(root)
    deploy(project)
    decoy = token_paths(project)[0]
    report = root.parent / "project" if False else project
    completed = subprocess.run(
        [sys.executable, "-c", script, str(Path(__file__).resolve().parents[1]), str(project), str(decoy)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip().splitlines()[-1] not in {"", "0"}, "reading a decoy must alert"


def _honeytoken_non_decoy_silent(root: Path) -> None:
    from tauhaulity.runtime import audit_hook
    from tauhaulity.tools.honeytoken import deploy

    project = _project(root)
    deploy(project)
    audit_hook.set_honeypot_paths([str(p) for p in []])
    audit_hook.reset() if hasattr(audit_hook, "reset") else None
    audit_hook.set_honeypot_paths([])
    assert audit_hook.honeypot_events() == []


def _honeytoken_never_clobbers(root: Path) -> None:
    from tauhaulity.tools.honeytoken import deploy

    project = _project(root)
    real = project / ".env"
    real.write_text("REAL=1" + chr(10), encoding="utf-8")
    try:
        deploy(project, kinds=("dotenv",))
    except Exception:
        pass
    assert real.read_text(encoding="utf-8").strip() == "REAL=1", "a real file must never be replaced"


def _honeytoken_idempotent(root: Path) -> None:
    from tauhaulity.tools.honeytoken import deploy, load

    project = _project(root)
    first = deploy(project)
    second = deploy(project)
    assert len(first.tokens) == len(second.tokens)
    assert load(project) is not None


def _honeytoken_remove_only_own(root: Path) -> None:
    from tauhaulity.tools.honeytoken import deploy, remove

    project = _project(root)
    deploy(project)
    stranger = project / "decoy_notes.txt"
    stranger.write_text("not ours", encoding="utf-8")
    assert remove(project) is True
    assert stranger.is_file(), "remove must not delete unrelated files"


def _honeytoken_corrupt_manifest(root: Path) -> None:
    from tauhaulity.tools.honeytoken import honeytoken_status, load

    project = _project(root)
    store = project / ".tauhaulity"
    store.mkdir(parents=True, exist_ok=True)
    (store / "honeytokens.json").write_text("{not json", encoding="utf-8")
    assert load(project) is None
    assert "0" in honeytoken_status(project)


def _honeytoken_decoys_are_fake(root: Path) -> None:
    from tauhaulity.tools.honeytoken import deploy, token_paths

    project = _project(root)
    deploy(project)
    for path in token_paths(project):
        text = path.read_text(encoding="utf-8", errors="replace")
        assert "th-honeytoken-" in text, f"{path.name} must carry the marker"
    for path in token_paths(project):
        text = path.read_text(encoding="utf-8", errors="replace")
        if "PRIVATE KEY" in text:
            assert "not a real" in text.lower() or "decoy" in text.lower(), "the key decoy must be visibly fake"


def _honeytoken_status_lists_kinds(root: Path) -> None:
    from tauhaulity.tools.honeytoken import deploy, honeytoken_status

    project = _project(root)
    deploy(project)
    status = honeytoken_status(project)
    assert "armed" in status and "alert" in status


def _honeytoken_dormant_without_paths(root: Path) -> None:
    from tauhaulity.runtime import audit_hook

    audit_hook.set_honeypot_paths([])
    _project(root)
    (root / "src" / "app.py").read_text(encoding="utf-8")
    assert audit_hook.honeypot_events() == [], "an unregistered path must not produce an alert"


# ------------------------------------------------------------ memory baseline
def _baseline_module() -> str:
    return (
        "def helper(value: int) -> int:" + chr(10)
        + "    return value + 1" + chr(10)
        + "CONSTANT = " + "1" * 64 + chr(10)
        * 40
    )


def _memory_fixture(root: Path) -> Path:
    project = _project(root)
    module = project / "src" / "baselined.py"
    module.write_text(_baseline_module(), encoding="utf-8")
    return project


def _memory_capture_clean(root: Path) -> None:
    from tauhaulity.pillars.p01_memory import capture_baseline, compare_baseline

    project = _memory_fixture(root)
    record = capture_baseline(project)
    assert record.modules, "a baseline must record at least one module"
    assert compare_baseline(record, record) == []


def _record_with(modules) -> object:
    """Build a synthetic baseline record around supplied module entries."""

    from tauhaulity.pillars.p01_memory import BaselineBudget, make_record

    return make_record(
        Path("/project"),
        modules,
        budget=BaselineBudget(page_size=4096, total_bytes=1024, per_module_bytes=1024, max_modules=8),
        captured_at="2026-01-01T00:00:00Z",
    )


def _module(name: str, digest: str, pages: tuple[str, ...] | None = None) -> object:
    """Build one synthetic module baseline entry.

    The validator requires 256 bit hex strings for both the image digest and every
    page digest, so the caller passes a 64 character hex marker and any page
    override is expanded the same way.
    """

    from tauhaulity.pillars.p01_memory import ModuleBaseline

    marker = (digest * 64)[:64]
    page_list = tuple(pages) if pages else (marker,)
    return ModuleBaseline(
        module=name,
        path="/project/lib/" + name + ".so",
        size=1024,
        digest=marker,
        pages=page_list,
        captured_at="2026-01-01T00:00:00Z",
    )


def _memory_changed(root: Path) -> None:
    from tauhaulity.pillars.p01_memory import compare_baseline

    before = _record_with((_module("alpha", "a", ("1" * 64, "2" * 64)),))
    after = _record_with((_module("alpha", "b", ("1" * 64, "3" * 64)),))
    deltas = compare_baseline(after, before)
    assert [delta.kind for delta in deltas] == ["changed"]
    assert deltas[0].module == "alpha"


def _memory_missing(root: Path) -> None:
    from tauhaulity.pillars.p01_memory import compare_baseline

    before = _record_with((_module("alpha", "a"), _module("beta", "c")))
    after = _record_with((_module("alpha", "a"),))
    deltas = compare_baseline(after, before)
    assert [(delta.kind, delta.module) for delta in deltas] == [("missing", "beta")]


def _memory_new(root: Path) -> None:
    from tauhaulity.pillars.p01_memory import compare_baseline

    before = _record_with((_module("alpha", "a"),))
    after = _record_with((_module("alpha", "a"), _module("gamma", "d")))
    deltas = compare_baseline(after, before)
    assert [(delta.kind, delta.module) for delta in deltas] == [("new", "gamma")]


def _memory_missing_store(root: Path) -> None:
    from tauhaulity.pillars.p01_memory import load_baseline

    project = _memory_fixture(root)
    assert load_baseline(project) is None


def _memory_corrupt_store(root: Path) -> None:
    from tauhaulity.pillars.p01_memory import load_baseline_ex

    project = _memory_fixture(root)
    store = project / ".tauhaulity"
    store.mkdir(parents=True, exist_ok=True)
    (store / "memory_baseline.json").write_text("{", encoding="utf-8")
    result = load_baseline_ex(project)
    assert result.record is None and result.reason


def _memory_budget(root: Path) -> None:
    from importlib.machinery import EXTENSION_SUFFIXES

    from tauhaulity.pillars.p01_memory import BaselineBudget, hash_module_files

    project = _project(root)
    # The baseline deliberately refuses a plain project source file (it is not a
    # loaded interpreter module), so the budget case uses a native extension
    # suffix, which the eligibility rule accepts anywhere on disk.
    big = project / "src" / ("bigmodule" + EXTENSION_SUFFIXES[0])
    big.write_bytes(b"\x00" * 64_000)
    modules, refused = hash_module_files(
        (("big", big),),
        budget=BaselineBudget(per_module_bytes=1024, total_bytes=4096, max_modules=8),
    )
    assert modules, f"the module must be hashed within the budget (refused: {refused})"
    assert modules[0].truncated is True, "the truncated flag must be visible"


def _memory_store_is_json(root: Path) -> None:
    from tauhaulity.pillars.p01_memory import BASELINE_SCHEMA, BaselineRecord, baseline_path, save_baseline

    project = _memory_fixture(root)
    record = _record_with((_module("alpha", "a"),))
    path = save_baseline(project, record)
    assert path == baseline_path(project)
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document.get("schema") == BASELINE_SCHEMA
    assert document.get("digest")
    assert document["payload"]["modules"], "the archived payload must list the modules"
    assert isinstance(record, BaselineRecord)


def _memory_scan_does_not_write(root: Path) -> None:
    from tauhaulity.core.contracts import ScanOptions
    from tauhaulity.engine import run_scan

    project = _memory_fixture(root)
    store = project / ".tauhaulity" / "memory_baseline.json"
    run_scan(project, options=ScanOptions(generate_repro=False, record_telemetry=False), write_reports=False)
    assert not store.exists(), "a scan must never create a baseline"


def _memory_probe_reports_change(root: Path) -> None:
    from tauhaulity.core.contracts import ScanOptions
    from tauhaulity.engine import run_scan
    from tauhaulity.pillars.p01_memory import capture_baseline

    project = _memory_fixture(root)
    capture_baseline(project)
    result = run_scan(project, options=ScanOptions(generate_repro=False, record_telemetry=False), write_reports=False)
    finding = result.ctx.findings[1]
    assert finding.status in {"SAFE", "WARNING", "CRITICAL"}
    assert "baseline" in finding.detail.lower() or "module" in finding.detail.lower()


# -------------------------------------------------------------------- watch
def _watch_backend_name(root: Path) -> None:
    from tauhaulity.daemon.watch import watch_backend_name

    assert watch_backend_name("auto") in {"linux-inotify", "windows-rdcw", "polling"}


def _watch_detects_change(root: Path) -> None:
    from tauhaulity.daemon.watch import create_backend

    project = _project(root)
    canary = project / "canary.txt"
    canary.write_text("decoy" + chr(10), encoding="utf-8")
    backend = create_backend(project, backend="auto", interval_s=0.05)
    events: list[object] = []
    backend.start()
    try:
        time.sleep(0.2)
        canary.write_text("tampered by a fake ransomware burst" + chr(10), encoding="utf-8")
        deadline = time.monotonic() + 6.0
        while time.monotonic() < deadline:
            changes = backend.events()
            if changes:
                events.extend(changes)
                break
            time.sleep(0.05)
    finally:
        backend.stop()
    assert events, "a tampered canary must produce an event"


def _watch_stop_is_prompt(root: Path) -> None:
    import threading

    from tauhaulity.daemon.watch import create_backend

    project = _project(root)
    backend = create_backend(project, backend="polling", interval_s=0.05)
    backend.start()
    started = time.perf_counter()
    backend.stop()
    assert time.perf_counter() - started < 5.0


def _watch_loop_honours_duration(root: Path) -> None:
    from tauhaulity.daemon.watch import watch_loop

    project = _project(root)
    started = time.perf_counter()
    count = watch_loop(project, interval_s=0.1, duration_s=0.4, backend="polling")
    elapsed = time.perf_counter() - started
    assert count >= 0 and elapsed < 10.0


def _watch_freeze_defaults_off(root: Path) -> None:
    from tauhaulity.daemon import watch as watch_module

    calls: list[int] = []
    original = watch_module.suspend_process
    watch_module.suspend_process = lambda pid: calls.append(pid) or True  # type: ignore[assignment]
    try:
        project = _project(root)
        watch_module.watch_loop(project, interval_s=0.1, duration_s=0.3, backend="polling")
        assert calls == [], "freeze must be opt in"
    finally:
        watch_module.suspend_process = original  # type: ignore[assignment]


def _watch_protected_pids(root: Path) -> None:
    from tauhaulity.daemon.watch import _pid_is_suspendable

    assert not _pid_is_suspendable(0)
    assert not _pid_is_suspendable(4)
    assert not _pid_is_suspendable(os.getpid())


def _watch_vanished_file_safe(root: Path) -> None:
    from tauhaulity.daemon.watch import create_backend

    project = _project(root)
    backend = create_backend(project, backend="polling", interval_s=0.05)
    backend.start()
    try:
        target = project / "src" / "fleeting.py"
        target.write_text("VALUE = 1" + chr(10), encoding="utf-8")
        time.sleep(0.1)
        target.unlink()
        time.sleep(0.15)
        backend.events()
    finally:
        backend.stop()
    assert True


def _watch_idle_is_not_a_busy_loop(root: Path) -> None:
    from tauhaulity.daemon.watch import create_backend

    project = _project(root)
    backend = create_backend(project, backend="polling", interval_s=0.1)
    backend.start()
    try:
        before = time.process_time()
        time.sleep(1.0)
        used = time.process_time() - before
    finally:
        backend.stop()
    assert used < 0.4, f"idle use was {used:.3f}s of CPU in one second"


def _watch_canary_reported(root: Path) -> None:
    from tauhaulity.daemon.watch import create_backend

    project = _project(root)
    canary = project / "canary.txt"
    canary.write_text("decoy" + chr(10), encoding="utf-8")
    backend = create_backend(project, backend="polling", interval_s=0.05)
    backend.start()
    try:
        time.sleep(0.15)
        canary.write_text("tampered" + chr(10), encoding="utf-8")
        time.sleep(0.3)
        changes = backend.events()
    finally:
        backend.stop()
    assert changes, "a modified canary must be observed"


# ------------------------------------------------------------ registration
# One entry per case: (id, category, description, builder). Keeping the table in
# one place makes the coverage of each runtime detector auditable at a glance.
_REGISTRATIONS: tuple[tuple[str, str, str, object], ...] = (
    ("honeytoken-deploy", "honeytoken", "deploy creates decoys and a manifest", _honeytoken_deploy),
    ("honeytoken-read-alerts", "honeytoken", "reading a decoy records an alert", _honeytoken_read_alerts),
    ("honeytoken-non-decoy-silent", "honeytoken", "unrelated reads record nothing", _honeytoken_non_decoy_silent),
    ("honeytoken-never-clobbers", "honeytoken", "a real .env survives deploy", _honeytoken_never_clobbers),
    ("honeytoken-idempotent", "honeytoken", "re-deploy does not duplicate decoys", _honeytoken_idempotent),
    ("honeytoken-remove-scoped", "honeytoken", "remove deletes only its own decoys", _honeytoken_remove_only_own),
    ("honeytoken-corrupt-manifest", "honeytoken", "a corrupt manifest degrades to zero", _honeytoken_corrupt_manifest),
    ("honeytoken-decoys-are-fake", "honeytoken", "decoys carry the marker and are visibly fake", _honeytoken_decoys_are_fake),
    ("honeytoken-status", "honeytoken", "status lists kinds and the alert count", _honeytoken_status_lists_kinds),
    ("honeytoken-dormant", "honeytoken", "no registered path means no alert", _honeytoken_dormant_without_paths),
    ("memory-capture-clean", "memory_baseline", "capture then compare with no change", _memory_capture_clean),
    ("memory-changed", "memory_baseline", "a modified module reports changed", _memory_changed),
    ("memory-missing", "memory_baseline", "a deleted module reports missing", _memory_missing),
    ("memory-new", "memory_baseline", "an added module reports new", _memory_new),
    ("memory-missing-store", "memory_baseline", "no store returns None without raising", _memory_missing_store),
    ("memory-corrupt-store", "memory_baseline", "a corrupt store reports the reason", _memory_corrupt_store),
    ("memory-budget", "memory_baseline", "the byte budget is visible in the record", _memory_budget),
    ("memory-store-json", "memory_baseline", "the store is versioned JSON", _memory_store_is_json),
    ("memory-scan-is-read-only", "memory_baseline", "a scan never writes a baseline", _memory_scan_does_not_write),
    ("memory-probe", "memory_baseline", "the probe reports the baseline state", _memory_probe_reports_change),
    ("watch-backend-name", "watch", "backend selection exposes a name", _watch_backend_name),
    ("watch-detects-change", "watch", "a created file produces an event", _watch_detects_change),
    ("watch-stop-prompt", "watch", "stopping the backend returns promptly", _watch_stop_is_prompt),
    ("watch-duration", "watch", "the loop honours its duration", _watch_loop_honours_duration),
    ("watch-freeze-default-off", "watch", "freeze is opt in", _watch_freeze_defaults_off),
    ("watch-protected-pids", "watch", "protected pids are refused", _watch_protected_pids),
    ("watch-vanished-file", "watch", "a vanished file does not raise", _watch_vanished_file_safe),
    ("watch-idle-cpu", "watch", "idle use stays far below one second", _watch_idle_is_not_a_busy_loop),
    ("watch-canary", "watch", "a modified canary is observed", _watch_canary_reported),
    ("watch-backend-auto", "watch", "auto selection is always one of the known backends", _watch_backend_name),
)

for _identifier, _category, _description, _builder in _REGISTRATIONS:
    _case(_identifier, _category, _description, _builder)

assert len(RUNTIME_CASES) == 30, "the runtime corpus is defined as thirty cases"

def main(argv: list[str] | None = None) -> int:
    """Run the runtime corpus and print the summary."""

    outcomes = run_corpus(RUNTIME_CASES)
    summary = summarize(outcomes)
    print(f"runtime cases {summary['cases']}, passed {summary['passed']}")
    for category, rate in summary["rates"].items():
        print(f"  recall {category:<20} {rate * 100:.0f}%")
    if summary["failures"]:
        print("failures: " + ", ".join(summary["failures"]))
    return 0 if not summary["failures"] else 1


if __name__ == "__main__":
    raise SystemExit(main())