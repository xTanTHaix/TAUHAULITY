"""False-positive guard for the 0.4.0 detectors (marked slow).

One case per legitimate heavy operation: a build wave, a dependency install, an
archive extraction, a checkout-like rewrite and a canary-named file the user
created on purpose. The runtime guard is armed inside a subprocess and every
detector counter is read after the operation. A non-zero burst verdict or entropy
alert on any of these is a release blocker, because a detector that fires on a
normal build is a detector the user turns off.

The cases run in a subprocess because a PEP-578 audit hook cannot be removed once
installed: arming it inside pytest would leak into the rest of the suite.

Run with:  python -m pytest tests/test_bulk_write_fp.py -m slow -q -s
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.bulk_write_cases import CASES

pytestmark = pytest.mark.slow

_CASE_SCRIPT = """
import json, sys
from pathlib import Path
from tauhaulity.runtime import audit_hook
from tests.bulk_write_cases import CASE_BY_ID, run_case

case_id, project = sys.argv[1], Path(sys.argv[2])
project.mkdir(parents=True, exist_ok=True)
audit_hook.install(enforce=False, root=project)
payload = run_case(CASE_BY_ID[case_id], project)
print(json.dumps(payload))
"""

#: Collected measurements, printed once by the summary test for the report.
RESULTS: list[dict] = []


def _subprocess_env(project_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    env["TAUHAULITY_NO_AUTO"] = "1"
    env.pop("TAUHAULITY_ENFORCE", None)
    env.pop("TAUHAULITY_HONEYPOT_ENFORCE", None)
    env["PYTHONPATH"] = str(project_root) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def _run_case(project_root: Path, case_id: str, project: Path) -> dict:
    completed = subprocess.run(
        [sys.executable, "-c", _CASE_SCRIPT, case_id, str(project)],
        cwd=str(project_root),
        env=_subprocess_env(project_root),
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    lines = [line for line in completed.stdout.strip().splitlines() if line.strip()]
    assert lines, completed.stderr
    return json.loads(lines[-1])


def _numbers(payload: dict) -> str:
    measured = payload.get("measured", {})
    return (
        "files_created=" + str(measured.get("files_created", 0))
        + " files_renamed=" + str(measured.get("files_renamed", 0))
        + " files_deleted=" + str(measured.get("files_deleted", 0))
        + " operation_s=" + str(measured.get("operation_s", payload.get("total_s", 0.0)))
        + " destructive_events=" + str(payload.get("destructive_events", 0))
        + " threshold=" + str(payload.get("burst_threshold", 0))
        + " window_s=" + str(payload.get("burst_window_s", 0.0))
        + " burst_events=" + str(payload.get("burst_events", 0))
        + " burst_verdicts=" + str(payload.get("burst_verdicts", 0))
        + " entropy_alerts=" + str(payload.get("entropy_alerts", 0))
        + " entropy_files=" + str(payload.get("entropy_files", 0))
        + " canary_events=" + str(payload.get("canary_events", 0))
        + " canary_watched=" + str(payload.get("canary_watched", 0))
        + " canary_farm_deployed=" + str(payload.get("canary_farm_deployed", 0))
        + " canary_farm_events=" + str(payload.get("canary_farm_events", 0))
    )


@pytest.mark.parametrize("case", CASES, ids=[case.case_id for case in CASES])
def test_benign_bulk_write_does_not_fire(
    case, project_root: Path, tmp_path: Path
) -> None:
    payload = _run_case(project_root, case.case_id, tmp_path / "project")
    print("BULK-WRITE-FP " + case.case_id + ": " + _numbers(payload), flush=True)
    RESULTS.append(payload)

    features = payload.get("features", {})
    missing = [phase for phase in case.requires if not features.get(phase)]
    if missing:
        pytest.xfail(
            "benign corpus case needs phase "
            + ", ".join(missing)
            + " which is not on this tree yet; measured counters: "
            + _numbers(payload)
        )

    if case.exercise_burst:
        # A zero verdict only means something when the case really did cross the
        # detector's volume threshold with destructive events.
        assert payload["destructive_events"] >= payload["burst_threshold"] > 0, (
            case.case_id
            + ": the case did not exercise the burst detector ("
            + str(payload["destructive_events"])
            + " destructive events vs threshold "
            + str(payload["burst_threshold"])
            + ")"
        )
    if case.exercise_radar:
        assert payload["entropy_files"] >= 1, (
            case.case_id + ": the entropy radar did not inspect any file"
        )
    if case.case_id == "legitimate-canary-name":
        # The farm must really be armed and must not claim the user's own file.
        assert payload["canary_farm_deployed"] >= 1, (
            "the canary farm did not plant a decoy in the test tree"
        )
        assert payload["canary_farm_includes_user_file"] is False, (
            "the canary farm adopted a canary-named file the user created"
        )
    assert payload["burst_verdicts"] == 0, (
        case.case_id + " produced a ransomware burst verdict on a legitimate write: "
        + str(payload.get("last_burst"))
    )
    assert payload["burst_events"] == 0, case.case_id + ": burst events recorded"
    assert payload["entropy_alerts"] == 0, (
        case.case_id + ": entropy radar alarms on legitimate files"
    )
    assert payload["canary_events"] == 0, (
        case.case_id + ": canary watcher raised a false alarm"
    )
    assert payload["canary_farm_events"] == 0, (
        case.case_id + ": canary farm raised a false alarm"
    )
    assert payload["measured"].get("files_created", 0) > 0


def test_bulk_write_summary() -> None:
    """Print the consolidated false-positive ledger for the report."""

    assert RESULTS, "the corpus cases did not run"
    for payload in RESULTS:
        print(
            "BULK-WRITE-FP-SUMMARY "
            + payload["case_id"]
            + " requires="
            + ",".join(payload.get("requires", []))
            + " features="
            + json.dumps(payload.get("features", {}), sort_keys=True)
            + " "
            + _numbers(payload),
            flush=True,
        )
    assert len(RESULTS) == len(CASES)
