"""Tests for the ransomware-style write burst detector (0.4.0-A).

Two signals are required before a verdict: destructive volume inside a sliding
window AND a uniform rename wave to a suffix the process has not learned. The most
important test in this file is the build shape: 5,000 renames that reuse existing
suffixes must produce zero verdicts.

Every scenario that arms the guard runs in a fresh interpreter because an audit
hook cannot be removed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path

import pytest

from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import BurstTracker, GuardPolicy


def _env(project_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["TAUHAULITY_NO_AUTO"] = "1"
    for name in (
        "TAUHAULITY_ENFORCE",
        "TAUHAULITY_DENY_RANSOM_BURST",
        "TAUHAULITY_DENY_CONNECT",
        "TAUHAULITY_DENY_SUBPROCESS",
        "TAUHAULITY_DENY_DESERIALIZE",
        "TAUHAULITY_DENY_SECRET_EGRESS",
    ):
        env.pop(name, None)
    env["PYTHONPATH"] = str(project_root) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _run(project_root: Path, code: str, *args: str) -> dict[str, object]:
    completed = subprocess.run(
        [sys.executable, "-c", code, *args],
        cwd=str(project_root),
        env=_env(project_root),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, f"stdout={completed.stdout}\nstderr={completed.stderr}"
    lines = [line for line in completed.stdout.strip().splitlines() if line.strip()]
    assert lines, completed.stderr
    return json.loads(lines[-1])


_RANSOM_SCRIPT = """
import json, os, sys, time
from pathlib import Path
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

project = Path(sys.argv[1])
mode = sys.argv[2]
window = float(sys.argv[3])
threshold = int(sys.argv[4])
project.mkdir(parents=True, exist_ok=True)
enforced = mode == "enforce"
flag_on = mode in {"enforce", "watchflag"}
arm_shield(GuardPolicy(
    enforce=enforced,
    burst_window_s=window,
    burst_threshold=threshold,
    deny_ransom_burst=flag_on,
))
outcome = {
    "before": 0, "after_ten": 0, "blocked": False, "message": "", "errors": 0,
    "events": [], "denials": [], "stats": {}, "summary": {},
}

for index in range(5):
    (project / ("warm_%d.py" % index)).write_text("x", encoding="utf-8")
for index in range(5):
    os.rename(project / ("warm_%d.py" % index), project / ("warm_%d_b.py" % index))
time.sleep(window + 0.1)
outcome["before"] = audit_hook.stats()["burst_verdicts"]
files = []
for index in range(40):
    source = project / ("doc_%d.txt" % index)
    source.write_text("payload", encoding="utf-8")
    files.append(source)

for index in range(10):
    try:
        os.rename(files[index], project / ("doc_%d.txt.locked" % index))
    except PermissionError as exc:
        outcome["errors"] += 1
        outcome["blocked"] = True
        outcome["message"] = str(exc)
        break
outcome["after_ten"] = audit_hook.stats()["burst_verdicts"]
for index in range(10, 40):
    if outcome["blocked"]:
        break
    try:
        os.rename(files[index], project / ("doc_%d.txt.locked" % index))
    except PermissionError as exc:
        outcome["errors"] += 1
        outcome["blocked"] = True
        outcome["message"] = str(exc)
        break
outcome["events"] = [
    event for event in audit_hook.events(128) if event.get("event") == "ransom_burst"
]
outcome["denials"] = [
    denial for denial in audit_hook.denials(32) if denial.get("kind") == "ransom_burst"
]
stats = audit_hook.stats()
outcome["stats"] = {
    key: stats[key] for key in (
        "burst_events", "burst_verdicts", "burst_tracker_size", "recorded",
    )
}
outcome["summary"] = audit_hook.burst_summary()
print(json.dumps(outcome, default=str))
"""


def test_ransomware_shape_records_exactly_one_verdict(project_root: Path, tmp_path: Path) -> None:
    payload = _run(project_root, _RANSOM_SCRIPT, str(tmp_path / "victim"), "watch", "0.2", "30")
    assert payload["before"] == 0
    assert payload["after_ten"] == 0, "the threshold must not be crossed by ten renames"
    assert payload["blocked"] is False
    assert payload["errors"] == 0
    events = payload["events"]
    assert len(events) == 1, events
    event = events[0]
    assert event["event"] == "ransom_burst"
    assert event["blocked"] is False
    assert event["volume"] == 30
    assert event["rename_count"] == 30
    assert event["suffix"] == ".locked"
    assert float(event["dominance"]) >= 0.8
    assert len(event["examples"]) == 5
    assert all(str(example).endswith(".locked") for example in event["examples"])
    denials = payload["denials"]
    assert len(denials) == 1
    denial = denials[0]
    assert denial["kind"] == "ransom_burst"
    assert denial["blocked"] is False
    assert denial["flag"] == "deny_ransom_burst"
    assert denial["suffix"] == ".locked"
    assert payload["stats"]["burst_events"] == 1
    assert payload["stats"]["burst_verdicts"] == 1
    assert payload["stats"]["burst_tracker_size"] <= 512
    summary = payload["summary"]
    assert summary["verdicts"] == 1
    assert summary["last_verdict"]["suffix"] == ".locked"
    assert summary["threshold"] == 30
    assert ".locked" in summary["known_suffixes"]


def test_enforcement_raises_only_on_the_crossing_operation(
    project_root: Path, tmp_path: Path
) -> None:
    payload = _run(project_root, _RANSOM_SCRIPT, str(tmp_path / "victim"), "enforce", "0.2", "12")
    assert payload["before"] == 0
    assert payload["after_ten"] == 0
    assert payload["blocked"] is True
    message = str(payload["message"])
    assert "12 destructive operations" in message
    assert ".locked" in message
    assert "deny_ransom_burst" in message
    assert payload["errors"] == 1
    assert len(payload["events"]) == 1
    assert len(payload["denials"]) == 1
    assert payload["stats"]["burst_events"] == 1
    assert payload["stats"]["burst_verdicts"] == 1


def test_enforcement_flag_off_never_raises(project_root: Path, tmp_path: Path) -> None:
    payload = _run(project_root, _RANSOM_SCRIPT, str(tmp_path / "victim"), "watchflag", "0.2", "30")
    assert payload["blocked"] is False
    assert payload["errors"] == 0
    assert len(payload["events"]) == 1
    assert payload["stats"]["burst_verdicts"] == 1


_BUILD_SCRIPT = """
import json, os, sys, time
from pathlib import Path
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

project = Path(sys.argv[1])
window = float(sys.argv[2])
threshold = int(sys.argv[3])
operations = int(sys.argv[4])
project.mkdir(parents=True, exist_ok=True)
arm_shield(GuardPolicy(
    enforce=False,
    burst_window_s=window,
    burst_threshold=threshold,
))
for index in range(20):
    source = project / ("seed_%d.tmp" % index)
    source.write_text("x", encoding="utf-8")
    suffix = ".py" if index % 2 == 0 else ".js"
    os.rename(source, project / ("seed_%d%s" % (index, suffix)))
time.sleep(window + 0.1)
started = time.perf_counter()
for index in range(operations):
    source = project / ("bulk_%d.tmp" % index)
    source.write_text("x", encoding="utf-8")
    suffix = ".py" if index % 2 == 0 else ".js"
    os.rename(source, project / ("bulk_%d%s" % (index, suffix)))
elapsed = time.perf_counter() - started
bursts = [
    event for event in audit_hook.events(256) if event.get("event") == "ransom_burst"
]
stats = audit_hook.stats()
print(json.dumps({
    "operations": operations,
    "elapsed": elapsed,
    "bursts": bursts,
    "verdicts": stats["burst_verdicts"],
    "burst_events": stats["burst_events"],
    "tracker_size": stats["burst_tracker_size"],
    "known_suffixes": list(audit_hook.burst_summary()["known_suffixes"]),
}, default=str))
"""


def test_build_shape_reusing_existing_suffixes_has_zero_verdicts(
    project_root: Path, tmp_path: Path
) -> None:
    payload = _run(project_root, _BUILD_SCRIPT, str(tmp_path / "buildtree"), "0.2", "30", "5000")
    assert payload["operations"] == 5000
    assert payload["bursts"] == [], "a bulk build reusing existing suffixes must never fire"
    assert payload["verdicts"] == 0
    assert payload["burst_events"] == 0
    assert payload["tracker_size"] <= 512
    assert ".py" in payload["known_suffixes"]
    assert ".js" in payload["known_suffixes"]


_MIXED_SCRIPT = """
import json, os, sys, time
from pathlib import Path
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

project = Path(sys.argv[1])
window = float(sys.argv[2])
threshold = int(sys.argv[3])
project.mkdir(parents=True, exist_ok=True)
arm_shield(GuardPolicy(
    enforce=False,
    burst_window_s=window,
    burst_threshold=threshold,
))
for index in range(5):
    (project / ("warm_%d.py" % index)).write_text("x", encoding="utf-8")
for index in range(5):
    os.rename(project / ("warm_%d.py" % index), project / ("warm_%d_b.py" % index))
time.sleep(window + 0.1)
for index in range(20):
    (project / ("delete_%d.txt" % index)).write_text("x", encoding="utf-8")
for index in range(10):
    (project / ("rename_%d.txt" % index)).write_text("x", encoding="utf-8")
for index in range(20):
    os.remove(project / ("delete_%d.txt" % index))
for index in range(10):
    os.rename(project / ("rename_%d.txt" % index), project / ("rename_%d.txt.enc" % index))
events = [
    event for event in audit_hook.events(128) if event.get("event") == "ransom_burst"
]
print(json.dumps({
    "events": events,
    "verdicts": audit_hook.stats()["burst_verdicts"],
}, default=str))
"""


def test_deletes_plus_renames_confirm_with_volume_from_deletes(
    project_root: Path, tmp_path: Path
) -> None:
    payload = _run(project_root, _MIXED_SCRIPT, str(tmp_path / "mixedtree"), "0.2", "30")
    assert len(payload["events"]) == 1
    event = payload["events"][0]
    assert event["volume"] == 30
    assert event["rename_count"] == 10
    assert event["suffix"] == ".enc"
    assert payload["verdicts"] == 1


_DORMANT_SCRIPT = """
import json, os, sys
from pathlib import Path
from tauhaulity.runtime import audit_hook

project = Path(sys.argv[1])
project.mkdir(parents=True, exist_ok=True)
for index in range(40):
    source = project / ("quiet_%d.txt" % index)
    source.write_text("x", encoding="utf-8")
    os.rename(source, project / ("quiet_%d.txt.locked" % index))
stats = audit_hook.stats()
print(json.dumps({
    "active": audit_hook.active(),
    "events": audit_hook.events(16),
    "denials": audit_hook.denials(16),
    "recorded": stats["recorded"],
    "burst_events": stats["burst_events"],
    "burst_verdicts": stats["burst_verdicts"],
    "tracker_size": stats["burst_tracker_size"],
}, default=str))
"""


def test_dormant_guard_records_nothing(project_root: Path, tmp_path: Path) -> None:
    payload = _run(project_root, _DORMANT_SCRIPT, str(tmp_path / "dormanttree"))
    assert payload["active"] is False
    assert payload["events"] == []
    assert payload["denials"] == []
    assert payload["recorded"] == 0
    assert payload["burst_events"] == 0
    assert payload["burst_verdicts"] == 0
    assert payload["tracker_size"] == 0


_OVERHEAD_SCRIPT = """
import json, os, sys, time, tracemalloc
from pathlib import Path
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

project = Path(sys.argv[1])
window = float(sys.argv[2])
threshold = int(sys.argv[3])
operations = int(sys.argv[4])
project.mkdir(parents=True, exist_ok=True)
first = project / "toggle_a.py"
second = project / "toggle_b.py"
first.write_text("x", encoding="utf-8")

def toggle_loop(count):
    if first.exists():
        source, target = first, second
    else:
        source, target = second, first
    started = time.perf_counter()
    for _ in range(count):
        os.rename(source, target)
        source, target = target, source
    return time.perf_counter() - started

inactive_loops = 2000
inactive_elapsed = toggle_loop(inactive_loops)
arm_shield(GuardPolicy(enforce=False, burst_window_s=window, burst_threshold=threshold))
# Warm-up: learn the ".py" suffix inside the first window.
for _ in range(5):
    pass
warm = toggle_loop(5)
time.sleep(window + 0.1)
armed_elapsed = toggle_loop(operations)
tracemalloc.start()
toggle_loop(500)
_current, peak = tracemalloc.get_traced_memory()
tracemalloc.stop()
stats = audit_hook.stats()
print(json.dumps({
    "operations": operations,
    "inactive_loops": inactive_loops,
    "inactive_elapsed": inactive_elapsed,
    "inactive_us_per_op": inactive_elapsed / inactive_loops * 1e6,
    "armed_elapsed": armed_elapsed,
    "armed_us_per_op": armed_elapsed / operations * 1e6,
    "added_us_per_op": (armed_elapsed / operations - inactive_elapsed / inactive_loops) * 1e6,
    "peak_bytes": peak,
    "verdicts": stats["burst_verdicts"],
    "tracker_size": stats["burst_tracker_size"],
}))
"""



def test_audited_operation_overhead_and_memory_are_bounded(
    project_root: Path, tmp_path: Path
) -> None:
    payload = _run(project_root, _OVERHEAD_SCRIPT, str(tmp_path / "overheadtree"), "0.2", "30", "5000")
    assert payload["operations"] == 5000
    assert payload["inactive_loops"] == 2000
    assert payload["verdicts"] == 0
    assert payload["tracker_size"] <= 512
    assert payload["armed_elapsed"] < 60.0, (
        f"5,000 audited renames took {payload['armed_elapsed']:.3f}s, bound is 60.0s"
    )
    assert payload["added_us_per_op"] < 3000.0, (
        f"the guard added {payload['added_us_per_op']:.1f} us per rename, bound is 3000 us"
    )
    assert payload["peak_bytes"] < 8 * 1024 * 1024, payload["peak_bytes"]


# ---------------------------------------------------------------------------
# Unit level tracker mathematics (no hook is installed)
# ---------------------------------------------------------------------------


def test_tracker_cap_and_bounded_memory_for_100k_operations() -> None:
    tracker = BurstTracker()
    tracemalloc.start()
    started = time.perf_counter()
    for index in range(100_000):
        tracker.observe(
            "rename",
            "/tmp/source_%d.tmp" % index,
            "/tmp/target_%d.wave" % index,
            now=index * 0.0001,
            window_s=5.0,
            threshold=10**9,
        )
    elapsed = time.perf_counter() - started
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert tracker.size <= tracker.capacity == 512
    assert len(tracker.known_suffixes) <= 64
    assert elapsed < 15.0, f"100,000 tracker operations took {elapsed:.3f}s"
    assert peak < 8 * 1024 * 1024, peak


def test_tracker_requires_both_signals_and_learns_suffixes() -> None:
    tracker = BurstTracker()
    # Warm-up: one second of renames to an existing suffix. Nothing may fire.
    for index in range(10):
        assert tracker.observe(
            "rename",
            "/p/seed_%d.tmp" % index,
            "/p/seed_%d.py" % index,
            now=0.1 * index,
            window_s=1.0,
            threshold=30,
        ) is None
    assert ".py" in tracker.known_suffixes
    # After the warm-up, only 20 uniform renames: below the volume threshold.
    for index in range(20):
        assert tracker.observe(
            "rename",
            "/p/a_%d.txt" % index,
            "/p/a_%d.locked" % index,
            now=2.0 + 0.001 * index,
            window_s=1.0,
            threshold=30,
        ) is None
    assert tracker.verdicts == 0
    # The 30th uniform rename inside the window confirms the burst.
    verdict = None
    for index in range(20, 30):
        verdict = tracker.observe(
            "rename",
            "/p/a_%d.txt" % index,
            "/p/a_%d.locked" % index,
            now=2.0 + 0.001 * index,
            window_s=1.0,
            threshold=30,
        )
    assert verdict is not None
    assert verdict.suffix == ".locked"
    assert verdict.volume == 30
    assert verdict.rename_count == 30
    assert verdict.dominance == 1.0
    assert len(verdict.examples) == 5
    assert tracker.verdicts == 1
    # The dominant suffix is learned and the window cleared: no second verdict
    # from the same wave.
    assert ".locked" in tracker.known_suffixes
    for index in range(30, 60):
        assert tracker.observe(
            "rename",
            "/p/a_%d.txt" % index,
            "/p/a_%d.locked" % index,
            now=2.0 + 0.001 * index,
            window_s=1.0,
            threshold=30,
        ) is None
    assert tracker.verdicts == 1


def test_tracker_dominance_below_eighty_percent_does_not_fire() -> None:
    tracker = BurstTracker()
    for index in range(10):
        tracker.observe(
            "rename", "/p/s%d.tmp" % index, "/p/s%d.py" % index,
            now=0.1 * index, window_s=1.0, threshold=30,
        )
    verdict = None
    for index in range(30):
        suffix = ".locked" if index % 2 == 0 else ".enc"
        verdict = tracker.observe(
            "rename", "/p/b%d.txt" % index, "/p/b%d%s" % (index, suffix),
            now=2.0 + 0.001 * index, window_s=1.0, threshold=30,
        )
        if verdict is not None:
            break
    assert verdict is None, "a 50/50 suffix split is not a uniform wave"
    assert tracker.verdicts == 0


def test_policy_burst_fields_and_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TAUHAULITY_DENY_RANSOM_BURST", raising=False)
    default = GuardPolicy()
    assert default.burst_window_s == 5.0
    assert default.burst_threshold == 30
    assert default.deny_ransom_burst is False
    assert default.as_dict()["burst_threshold"] == 30
    monkeypatch.setenv("TAUHAULITY_DENY_RANSOM_BURST", "1")
    assert GuardPolicy.from_env().deny_ransom_burst is True
    with pytest.raises(ValueError):
        GuardPolicy(burst_window_s=0)
    with pytest.raises(ValueError):
        GuardPolicy(burst_threshold=0)
    custom = GuardPolicy(burst_window_s=2.5, burst_threshold=12)
    assert custom.as_dict()["burst_window_s"] == 2.5
    assert custom.as_dict()["burst_threshold"] == 12


def test_runtime_package_reexports_burst_api() -> None:
    from tauhaulity import runtime

    assert runtime.BurstTracker is audit_hook.BurstTracker
    assert runtime.BurstVerdict is audit_hook.BurstVerdict
    summary = runtime.burst_summary()
    for key in ("capacity", "size", "verdicts", "window_s", "threshold", "deny_ransom_burst"):
        assert key in summary