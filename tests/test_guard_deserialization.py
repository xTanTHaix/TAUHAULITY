"""Tests for the in-process deserialization gate (0.3.1-B).

The gate wraps loader callables, so every enforcement scenario runs in a fresh
interpreter: a wrapped module-level function cannot be safely un-imported from the
pytest process, and an audit hook cannot be removed at all.

Decision model under test: the gate refuses a stream that contains an execution
opcode unless its *source path* is trusted or project owned. It deliberately does
not exempt a caller because the caller is project code: a project module loading an
attacker supplied pickle is the exact attack this phase closes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import pickle
import subprocess
import sys
from pathlib import Path

import pytest

from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy


class _HarmlessPayload:
    """Pickle payload with GLOBAL+REDUCE that executes abs(-5) when loaded."""

    def __reduce__(self):
        return (abs, (-5,))


def _malicious_pickle() -> bytes:
    return base64.b64encode(pickle.dumps(_HarmlessPayload(), protocol=2)).decode("ascii")


def _benign_pickle() -> bytes:
    payload = pickle.dumps({"alpha": 1, "items": [1, 2, 3], "name": "benign"}, protocol=2)
    return base64.b64encode(payload).decode("ascii")


_PACKAGE_SOURCE = (
    "import pickle\n"
    "\n"
    "def load_pickle(data):\n"
    "    return pickle.loads(data)\n"
    "\n"
    "def load_from(path):\n"
    "    with open(path, 'rb') as handle:\n"
    "        return pickle.load(handle)\n"
)


def _build_tree(tmp_path: Path) -> tuple[Path, Path]:
    site = tmp_path / "fake-venv" / "Lib" / "site-packages"
    package = site / "evil_pkg"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(_PACKAGE_SOURCE, encoding="utf-8")
    project = tmp_path / "project"
    project_package = project / "proj_pkg"
    project_package.mkdir(parents=True)
    (project_package / "__init__.py").write_text(_PACKAGE_SOURCE, encoding="utf-8")
    return site, project


def _env(project_root: Path, project_dir: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env["TAUHAULITY_NO_AUTO"] = "1"
    for name in (
        "TAUHAULITY_ENFORCE",
        "TAUHAULITY_DENY_DESERIALIZE",
        "TAUHAULITY_TRUSTED_PICKLES",
        "TAUHAULITY_PROJECT_ROOTS",
        "TAUHAULITY_GUARD_ALLOW",
    ):
        env.pop(name, None)
    env["TAUHAULITY_PROJECT_ROOTS"] = str(project_dir)
    env["PYTHONPATH"] = str(project_root) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if extra:
        env.update(extra)
    return env


def _run(
    project_root: Path,
    project_dir: Path,
    code: str,
    *args: str,
    extra_env: dict[str, str] | None = None,
) -> dict[str, object]:
    completed = subprocess.run(
        [sys.executable, "-c", code, *args],
        cwd=str(project_root),
        env=_env(project_root, project_dir, extra_env),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, f"stdout={completed.stdout}\nstderr={completed.stderr}"
    lines = [line for line in completed.stdout.strip().splitlines() if line.strip()]
    assert lines, completed.stderr
    return json.loads(lines[-1])


_LOAD_SCRIPT = """
import base64, json, pickle, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

mode, payload_b64, site_dir, project_dir = sys.argv[1:5]
sys.path.insert(0, site_dir)
sys.path.insert(0, project_dir)
payload = base64.b64decode(payload_b64)
arm_shield(GuardPolicy(enforce=(mode != "watch")))
import evil_pkg
import proj_pkg

outcome = {"blocked": False, "value": None, "message": "", "denials": []}
try:
    if mode == "project":
        outcome["value"] = proj_pkg.load_pickle(payload)["alpha"]
    elif mode == "watch":
        outcome["value"] = evil_pkg.load_pickle(payload)
    else:
        outcome["value"] = evil_pkg.load_pickle(payload)["alpha"]
except PermissionError as exc:
    outcome["blocked"] = True
    outcome["message"] = str(exc)
except Exception as exc:
    outcome["error"] = type(exc).__name__ + ": " + str(exc)[:120]
outcome["denials"] = audit_hook.denials(8)
stats = audit_hook.stats()
outcome["stats"] = {key: stats[key] for key in (
    "denials", "blocked_events", "deserialization_watch_events", "deserialization_gate_active"
)}
outcome["events"] = [event for event in audit_hook.events(64) if event.get("blocked")]
print(json.dumps(outcome, default=str))
"""


def test_malicious_stream_is_refused_when_enforced(project_root: Path, tmp_path: Path) -> None:
    site, project = _build_tree(tmp_path)
    payload = _run(
        project_root, project, _LOAD_SCRIPT, "enforce", _malicious_pickle(), str(site), str(project)
    )
    assert payload["blocked"] is True
    message = str(payload["message"])
    assert "unsafe deserialization" in message
    assert "pickle.loads" in message
    assert "GLOBAL" in message
    assert "offset" in message
    assert "evil_pkg" in message
    assert "deny_unsafe_deserialization" in message
    denial = payload["denials"][0]
    assert denial["kind"] == "deserialization"
    assert denial["flag"] == "deny_unsafe_deserialization"
    assert denial["event"] == "pickle.loads"
    assert denial["opcode"] in {"GLOBAL", "REDUCE"}
    assert isinstance(denial["offset"], int)
    assert denial["provenance"]["kind"] == "site-packages"
    assert denial["provenance"]["package"] == "evil_pkg"
    assert isinstance(denial["time"], float)
    assert payload["stats"]["denials"] == 1
    assert payload["stats"]["blocked_events"] >= 1
    assert payload["stats"]["deserialization_gate_active"] is True
    assert payload["events"]


def test_benign_stream_loads_under_enforcement(project_root: Path, tmp_path: Path) -> None:
    site, project = _build_tree(tmp_path)
    payload = _run(
        project_root, project, _LOAD_SCRIPT, "enforce", _benign_pickle(), str(site), str(project)
    )
    assert payload["blocked"] is False
    assert payload["value"] == 1
    assert payload["denials"] == []
    assert payload["stats"]["denials"] == 0


def test_watch_mode_records_without_raising(project_root: Path, tmp_path: Path) -> None:
    site, project = _build_tree(tmp_path)
    payload = _run(
        project_root, project, _LOAD_SCRIPT, "watch", _malicious_pickle(), str(site), str(project)
    )
    assert payload["blocked"] is False
    assert payload["value"] == 5, "watch mode must call the real loader unchanged"
    denials = payload["denials"]
    assert len(denials) == 1
    assert denials[0]["blocked"] is False
    assert denials[0]["watch"] is True
    assert denials[0]["kind"] == "deserialization"
    assert payload["stats"]["denials"] == 0
    assert payload["stats"]["blocked_events"] == 0
    assert payload["stats"]["deserialization_watch_events"] >= 1


def test_project_caller_is_still_refused_for_malicious_stream(
    project_root: Path, tmp_path: Path
) -> None:
    site, project = _build_tree(tmp_path)
    payload = _run(
        project_root, project, _LOAD_SCRIPT, "project", _malicious_pickle(), str(site), str(project)
    )
    assert payload["blocked"] is True
    assert "opcode" in str(payload["message"])
    assert payload["denials"][0]["provenance"]["kind"] == "project"


def test_project_caller_may_load_benign_stream(project_root: Path, tmp_path: Path) -> None:
    site, project = _build_tree(tmp_path)
    payload = _run(
        project_root, project, _LOAD_SCRIPT, "project", _benign_pickle(), str(site), str(project)
    )
    assert payload["blocked"] is False
    assert payload["value"] == 1


_TRUSTED_FILE_SCRIPT = """
import json, pickle, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

site_dir, project_dir, source_path, trusted_dir = sys.argv[1:5]
sys.path.insert(0, site_dir)
sys.path.insert(0, project_dir)
arm_shield(GuardPolicy(enforce=True, trusted_paths=(trusted_dir,)))
import evil_pkg

outcome = {"loaded": None, "message": "", "denials": []}
try:
    outcome["loaded"] = evil_pkg.load_from(source_path)
except PermissionError as exc:
    outcome["message"] = str(exc)
outcome["denials"] = audit_hook.denials(8)
print(json.dumps(outcome, default=str))
"""

_PROJECT_FILE_SCRIPT = """
import json, pickle, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

project_dir, source_path = sys.argv[1:3]
arm_shield(GuardPolicy(enforce=True))
outcome = {"loaded": None, "message": "", "denials": []}
try:
    with open(source_path, "rb") as handle:
        outcome["loaded"] = pickle.load(handle)
except PermissionError as exc:
    outcome["message"] = str(exc)
outcome["denials"] = audit_hook.denials(8)
print(json.dumps(outcome, default=str))
"""


def test_trusted_paths_allow_an_otherwise_malicious_file(
    project_root: Path, tmp_path: Path
) -> None:
    site, project = _build_tree(tmp_path)
    trusted = tmp_path / "trusted-models"
    trusted.mkdir()
    source = trusted / "model.pkl"
    source.write_bytes(pickle.dumps(_HarmlessPayload(), protocol=2))
    payload = _run(
        project_root,
        project,
        _TRUSTED_FILE_SCRIPT,
        str(site),
        str(project),
        str(source),
        str(trusted),
    )
    assert payload["loaded"] == 5
    assert payload["message"] == ""
    assert payload["denials"] == []


def test_project_owned_file_is_trusted(project_root: Path, tmp_path: Path) -> None:
    _site, project = _build_tree(tmp_path)
    source = project / "cache.pkl"
    source.write_bytes(pickle.dumps(_HarmlessPayload(), protocol=2))
    payload = _run(project_root, project, _PROJECT_FILE_SCRIPT, str(project), str(source))
    assert payload["loaded"] == 5
    assert payload["message"] == ""


_WRAP_SCRIPT = """
import json, pickle, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield, shield, unpatch_deserialization

original_loads = pickle.loads
original_marshal = __import__("marshal").loads
outcome = {}
arm_shield(GuardPolicy(enforce=True))
outcome["wrapped"] = pickle.loads is not original_loads
first_id = id(pickle.loads)
arm_shield(GuardPolicy(enforce=True))
outcome["no_double_wrap"] = id(pickle.loads) == first_id
outcome["gate_active"] = audit_hook.deserialization_gate_active()
restored = unpatch_deserialization()
outcome["restored_count"] = restored
outcome["identity_restored"] = pickle.loads is original_loads
outcome["marshal_restored"] = __import__("marshal").loads is original_marshal
outcome["gate_inactive"] = not audit_hook.deserialization_gate_active()
with shield(GuardPolicy(enforce=True)):
    outcome["scoped_wrapped"] = pickle.loads is not original_loads
outcome["scoped_restored"] = pickle.loads is original_loads
print(json.dumps(outcome))
"""


def test_wrap_unwrap_identity_and_no_double_wrap(project_root: Path, tmp_path: Path) -> None:
    _site, project = _build_tree(tmp_path)
    payload = _run(project_root, project, _WRAP_SCRIPT)
    assert payload["wrapped"] is True
    assert payload["no_double_wrap"] is True
    assert payload["gate_active"] is True
    assert payload["restored_count"] >= 2
    assert payload["identity_restored"] is True
    assert payload["marshal_restored"] is True
    assert payload["gate_inactive"] is True
    assert payload["scoped_wrapped"] is True
    assert payload["scoped_restored"] is True


_IMPORT_SCRIPT = """
import json, marshal, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

arm_shield(GuardPolicy(enforce=True))
import json as imported_json
import tempfile
import pathlib
round_trip = marshal.loads(marshal.dumps({"a": [1, 2, 3]}))
folded = imported_json.dumps({"value": 1})
outcome = {
    "round_trip": round_trip,
    "json_length": len(folded),
    "denials": len(audit_hook.denials(8)),
    "gate_active": audit_hook.deserialization_gate_active(),
}
print(json.dumps(outcome))
"""


def test_imports_and_marshal_round_trip_survive_enforcement(
    project_root: Path, tmp_path: Path
) -> None:
    _site, project = _build_tree(tmp_path)
    payload = _run(project_root, project, _IMPORT_SCRIPT)
    assert payload["round_trip"] == {"a": [1, 2, 3]}
    assert payload["json_length"] == len('{"value": 1}')
    assert payload["denials"] == 0, "a marshal payload is not a pickle and must pass through"
    assert payload["gate_active"] is True


_OPTIONAL_MODULES_SCRIPT = """
import importlib.util, json, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

before = {name: name in sys.modules for name in ("yaml", "dill", "torch")}
arm_shield(GuardPolicy(enforce=True))
after = {name: name in sys.modules for name in ("yaml", "dill", "torch")}
installed = {name: importlib.util.find_spec(name) is not None for name in ("yaml", "dill", "torch")}
print(json.dumps({"before": before, "after": after, "installed": installed,
                  "gate_active": audit_hook.deserialization_gate_active()}))
"""


def test_optional_modules_are_not_imported_by_arming(
    project_root: Path, tmp_path: Path
) -> None:
    _site, project = _build_tree(tmp_path)
    payload = _run(project_root, project, _OPTIONAL_MODULES_SCRIPT)
    assert payload["before"] == payload["after"]
    assert payload["after"]["yaml"] is False
    assert payload["after"]["dill"] is False
    assert payload["after"]["torch"] is False
    assert payload["gate_active"] is True


_OVERHEAD_SCRIPT = """
import base64, json, pickle, sys, time
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

payload = base64.b64decode(sys.argv[1])
arm_shield(GuardPolicy(enforce=True))
for _ in range(100):
    pickle.loads(payload)
loops = 10000
started = time.perf_counter()
for _ in range(loops):
    pickle.loads(payload)
elapsed = time.perf_counter() - started
print(json.dumps({
    "loops": loops,
    "elapsed": elapsed,
    "us_per_load": elapsed / loops * 1e6,
    "denials": len(audit_hook.denials(4)),
}))
"""

#: Documented ceiling for 10,000 benign loads through the enforced gate. The
#: measured value on the development host is reported in the phase report; the
#: bound is generous enough for a loaded CI runner.
BENIGN_LOAD_COST_BOUND_S = 3.0


def test_benign_load_overhead_stays_bounded(project_root: Path, tmp_path: Path) -> None:
    _site, project = _build_tree(tmp_path)
    payload = _run(project_root, project, _OVERHEAD_SCRIPT, _benign_pickle())
    assert payload["loops"] == 10000
    assert payload["denials"] == 0
    assert payload["elapsed"] < BENIGN_LOAD_COST_BOUND_S, (
        f"10,000 enforced benign loads took {payload['elapsed']:.3f}s, bound is "
        f"{BENIGN_LOAD_COST_BOUND_S:.1f}s"
    )


# ---------------------------------------------------------------------------
# Policy model and trust resolution (in-process, no hook is installed)
# ---------------------------------------------------------------------------


def test_policy_exposes_deserialization_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("TAUHAULITY_DENY_DESERIALIZE", "TAUHAULITY_TRUSTED_PICKLES"):
        monkeypatch.delenv(name, raising=False)
    default = GuardPolicy()
    assert default.deny_unsafe_deserialization is True
    assert default.trusted_paths == ()
    assert default.as_dict()["deny_unsafe_deserialization"] is True
    assert default.as_dict()["trusted_paths"] == []

    monkeypatch.setenv("TAUHAULITY_DENY_DESERIALIZE", "0")
    monkeypatch.setenv(
        "TAUHAULITY_TRUSTED_PICKLES",
        os.pathsep.join(("trusted-a", "trusted-b")),
    )
    policy = GuardPolicy.from_env()
    assert policy.deny_unsafe_deserialization is False
    assert policy.trusted_paths == ("trusted-a", "trusted-b")


def test_relative_trusted_paths_resolve_against_the_project_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "project"
    root.mkdir()
    monkeypatch.setenv("TAUHAULITY_PROJECT_ROOTS", str(root))
    monkeypatch.setattr(audit_hook, "_PROJECT_ROOT_OVERRIDE", None)
    policy = GuardPolicy(trusted_paths=("trusted-models",))
    resolved = audit_hook._resolved_trusted_paths(policy)
    assert resolved == (
        audit_hook._normalized_path(str(root / "trusted-models")),
    )
    assert audit_hook._source_is_trusted(str(root / "data.pkl"), policy) is True
    assert audit_hook._source_is_trusted(str(tmp_path / "outside.pkl"), policy) is False
    assert audit_hook._source_is_trusted(None, policy) is False
    assert audit_hook._source_is_trusted("<memory stream>", policy) is False


def test_deserialization_message_is_exact() -> None:
    message = audit_hook._deserialization_message(
        "pickle.loads", "REDUCE", 46, "evil_pkg", "deny_unsafe_deserialization"
    )
    assert message == (
        "Tauhaulity policy: unsafe deserialization via pickle.loads blocked at opcode "
        "REDUCE (offset 46) from package 'evil_pkg' by deny_unsafe_deserialization"
    )


def test_runtime_package_reexports_deserialization_api() -> None:
    from tauhaulity import runtime

    assert runtime.unpatch_deserialization is audit_hook.unpatch_deserialization
    assert runtime.deserialization_gate_active is audit_hook.deserialization_gate_active
