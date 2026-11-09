"""Tests for the interpreter level runtime guard and PEP-669 monitoring.

A PEP-578 audit hook can never be removed from a process, so every test that
installs it runs inside a fresh interpreter. Nothing here arms the guard inside the
pytest process itself: that would leak an audit hook into the rest of the suite.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tauhaulity.runtime import audit_hook
from tauhaulity.runtime import monitoring


def _subprocess_env(
    project_root: Path,
    *,
    auto: bool = True,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    env = os.environ.copy()
    if auto:
        env.pop("TAUHAULITY_NO_AUTO", None)
    else:
        env["TAUHAULITY_NO_AUTO"] = "1"
    env.pop("TAUHAULITY_ENFORCE", None)
    env.pop("TAUHAULITY_HONEYPOT_ENFORCE", None)
    env["PYTHONPATH"] = str(project_root) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if extra:
        env.update(extra)
    return env


def _run(
    project_root: Path,
    code: str,
    *args: str,
    auto: bool = True,
    extra_env: dict[str, str] | None = None,
) -> dict[str, object]:
    completed = subprocess.run(
        [sys.executable, "-c", code, *args],
        cwd=str(project_root),
        env=_subprocess_env(project_root, auto=auto, extra=extra_env),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, f"stdout={completed.stdout}\nstderr={completed.stderr}"
    lines = [line for line in completed.stdout.strip().splitlines() if line.strip()]
    assert lines, completed.stderr
    return json.loads(lines[-1])


_INSTALL_AND_RECORD = """
import json, sys
from tauhaulity.runtime import audit_hook

audit_hook.reset()
audit_hook.install(enforce=False)
with open(sys.argv[1], "r", encoding="utf-8") as handle:
    handle.read(1)
stats = audit_hook.stats()
print(json.dumps({
    "active": audit_hook.active(),
    "enforce": audit_hook.enforce_enabled(),
    "installed": stats["installed"],
    "ring_size": stats["ring_size"],
    "open_count": stats["counts"]["open"],
    "events": audit_hook.events(8),
}))
"""

_DORMANT = """
import json, sys
from tauhaulity.runtime import audit_hook

audit_hook.install(enforce=False)
audit_hook.reset()
audit_hook.deactivate()
with open(sys.argv[1], "r", encoding="utf-8") as handle:
    handle.read(1)
print(json.dumps({
    "active": audit_hook.active(),
    "events": audit_hook.events(8),
    "recorded": audit_hook.stats()["recorded"],
}))
"""

_RING_BOUNDED = """
import json, sys
from tauhaulity.runtime import audit_hook

audit_hook.install(enforce=False)
audit_hook.reset()
path = sys.argv[1]
for _ in range(300):
    with open(path, "a", encoding="utf-8") as handle:
        handle.write("x")
stats = audit_hook.stats()
print(json.dumps({
    "ring_size": stats["ring_size"],
    "ring_capacity": stats["ring_capacity"],
    "recorded": stats["recorded"],
    "open_count": stats["counts"]["open"],
    "recent": len(audit_hook.events(5)),
    "latest_seq": audit_hook.events(1)[0]["seq"] if audit_hook.events(1) else 0,
}))
"""

_AUTO_ACTIVATE = """
import json
import tauhaulity

guard = tauhaulity.GUARD
print(json.dumps({
    "active": tauhaulity.is_active(),
    "guard": guard is not None,
    "enforce": bool(guard.enforce_enabled()) if guard is not None else None,
}))
"""

_ENFORCE_SCRIPT = """
import json, sys
from tauhaulity.runtime import audit_hook

project, site_dir, env_path, notes_path = sys.argv[1:5]
sys.path.insert(0, site_dir)
audit_hook.install(enforce=True, root=project)
import evil

outcome = {"blocked": False, "message": ""}
try:
    evil.steal(env_path)
except PermissionError as exc:
    outcome["blocked"] = True
    outcome["message"] = str(exc)[:120]
outcome["benign"] = evil.benign(notes_path)
with open(env_path, "r", encoding="utf-8") as handle:
    outcome["direct_read"] = handle.read()[:16]
outcome["violations"] = audit_hook.stats()["violations"]
outcome["blocked_events"] = [event for event in audit_hook.events(32) if event["blocked"]]
print(json.dumps(outcome))
"""


def test_guard_installs_and_records_open(project_root: Path, tmp_path: Path) -> None:
    target = tmp_path / "probe.txt"
    target.write_text("hello", encoding="utf-8")
    payload = _run(project_root, _INSTALL_AND_RECORD, str(target))
    assert payload["active"] is True
    assert payload["enforce"] is False
    assert payload["installed"] is True
    assert payload["open_count"] >= 1
    assert payload["ring_size"] >= 1
    events = payload["events"]
    assert any(event["event"] == "open" and "probe.txt" in event["detail"] for event in events)


def test_guard_is_dormant_after_deactivate(project_root: Path, tmp_path: Path) -> None:
    target = tmp_path / "dormant.txt"
    target.write_text("hello", encoding="utf-8")
    payload = _run(project_root, _DORMANT, str(target), auto=False)
    assert payload["active"] is False
    assert payload["events"] == []
    assert payload["recorded"] == 0


def test_event_ring_is_bounded(project_root: Path, tmp_path: Path) -> None:
    target = tmp_path / "ring.log"
    target.write_text("", encoding="utf-8")
    payload = _run(project_root, _RING_BOUNDED, str(target), auto=False)
    assert payload["ring_capacity"] == audit_hook.EVENT_RING_SIZE
    assert payload["ring_size"] == payload["ring_capacity"]
    assert payload["recorded"] >= 300
    assert payload["open_count"] >= 300
    assert payload["recent"] == 5
    assert payload["latest_seq"] >= 300


def test_package_import_auto_activates_watch_mode(project_root: Path) -> None:
    payload = _run(project_root, _AUTO_ACTIVATE)
    assert payload["active"] is True
    assert payload["guard"] is True
    assert payload["enforce"] is False


def _build_enforce_fixture(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    project = tmp_path / "project"
    project.mkdir()
    (project / ".env").write_text("API_TOKEN=super-secret-value\n", encoding="utf-8")
    notes = project / "notes.txt"
    notes.write_text("plain notes", encoding="utf-8")
    site = tmp_path / "site-packages"
    site.mkdir()
    (site / "evil.py").write_text(
        "def steal(path):\n"
        "    with open(path, 'r', encoding='utf-8') as handle:\n"
        "        return handle.read()\n"
        "\n"
        "def benign(path):\n"
        "    with open(path, 'r', encoding='utf-8') as handle:\n"
        "        return handle.read()\n",
        encoding="utf-8",
    )
    return project, site, project / ".env", notes


def test_enforce_blocks_third_party_secret_read(project_root: Path, tmp_path: Path) -> None:
    project, site, env_path, notes = _build_enforce_fixture(tmp_path)
    payload = _run(project_root, _ENFORCE_SCRIPT, str(project), str(site), str(env_path), str(notes))
    assert payload["blocked"] is True
    assert "credential" in payload["message"].lower()
    assert payload["benign"] == "plain notes"
    assert payload["direct_read"] == "API_TOKEN=super-"
    assert payload["violations"] >= 1
    assert payload["blocked_events"]
    assert "blocked sensitive read" in payload["blocked_events"][0]["detail"]
    assert payload["blocked_events"][0]["origin"] == "third-party"


_ENFORCE_OFF_BY_DEFAULT = """
import json, sys
from tauhaulity.runtime import audit_hook

project, site_dir, env_path, notes_path = sys.argv[1:5]
sys.path.insert(0, site_dir)
audit_hook.install(enforce=False, root=project)
import evil

try:
    content = evil.steal(env_path)
    blocked = False
except PermissionError:
    content = ""
    blocked = True
print(json.dumps({
    "blocked": blocked,
    "content": content[:16],
    "enforce": audit_hook.enforce_enabled(),
    "violations": audit_hook.stats()["violations"],
}))
"""


def test_enforce_is_off_by_default(project_root: Path, tmp_path: Path) -> None:
    project, site, env_path, notes = _build_enforce_fixture(tmp_path)
    payload = _run(project_root, _ENFORCE_OFF_BY_DEFAULT, str(project), str(site), str(env_path), str(notes))
    assert payload["blocked"] is False
    assert payload["enforce"] is False
    assert payload["violations"] == 0
    assert payload["content"] == "API_TOKEN=super-"


def test_sensitive_path_classifier() -> None:
    assert audit_hook.is_sensitive_path("/home/dev/project/.env") is True
    assert audit_hook.is_sensitive_path("/home/dev/.env.local") is True
    assert audit_hook.is_sensitive_path("/home/dev/.ssh/id_ed25519") is True
    assert audit_hook.is_sensitive_path("C:/Users/dev/.aws/credentials") is True
    assert audit_hook.is_sensitive_path("/home/dev/.npmrc") is True
    assert audit_hook.is_sensitive_path("/home/dev/.pypirc") is True
    assert audit_hook.is_sensitive_path("/home/dev/.ssh/id_rsa") is True
    assert audit_hook.is_sensitive_path("/etc/ssl/server.pem") is True
    assert audit_hook.is_sensitive_path("/home/dev/notes.txt") is False
    assert audit_hook.is_sensitive_path("/home/dev/project/src/main.py") is False
    assert audit_hook.is_sensitive_path(None) is False


def test_classify_origin_buckets(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    inside = str(root / "src" / "app.py")
    third_party = str(tmp_path / ".venv" / "Lib" / "site-packages" / "requests" / "__init__.py")
    assert audit_hook.classify_origin(inside, root) == "project"
    assert audit_hook.classify_origin(third_party, root) == "third-party"
    assert audit_hook.classify_origin("<frozen importlib._bootstrap>") == "builtin"
    assert audit_hook.classify_origin(os.__file__) == "stdlib"
    assert audit_hook.classify_origin(audit_hook.__file__) == "runtime"
    assert audit_hook.classify_origin(str(tmp_path / "loose" / "file.py")) in {"unknown", "project"}


# ---------------------------------------------------------------------------
# S7: honeytoken honeypot support in the audit hook.
#
# Every script below runs in a fresh interpreter because the hook cannot be
# removed; each one deploys decoys into a throwaway project and then arms the
# watched path set explicitly.
# ---------------------------------------------------------------------------

_HONEYTOKEN_WATCH = """
import json, os, sys
from tauhaulity.tools import honeytoken
from tauhaulity.runtime import audit_hook

root, notes = sys.argv[1], sys.argv[2]
armed = honeytoken.deploy(root)
audit_hook.install(enforce=False)
audit_hook.reset()
registered = audit_hook.set_honeypot_paths(
    [str(path) for path in honeytoken.token_paths(root)]
)
decoy = str(armed.tokens[0].absolute_path)
with open(decoy, "r", encoding="utf-8") as handle:
    handle.read()
with open(notes, "r", encoding="utf-8") as handle:
    handle.read()
stats = audit_hook.stats()
print(json.dumps({
    "registered": registered,
    "alerts": audit_hook.honeypot_events(8),
    "count": stats["honeypot_alerts"],
    "watched": stats["honeypot_paths"],
    "decoy": decoy,
    "pid": os.getpid(),
    "recorded": stats["recorded"],
}))
"""

_HONEYTOKEN_DORMANT = """
import json, sys
from tauhaulity.tools import honeytoken
from tauhaulity.runtime import audit_hook

root = sys.argv[1]
armed = honeytoken.deploy(root)
audit_hook.install(enforce=False)
audit_hook.reset()
registered = audit_hook.set_honeypot_paths([])
decoy = str(armed.tokens[0].absolute_path)
with open(decoy, "r", encoding="utf-8") as handle:
    handle.read()
stats = audit_hook.stats()
print(json.dumps({
    "registered": registered,
    "alerts": audit_hook.honeypot_events(8),
    "count": stats["honeypot_alerts"],
    "watched": stats["honeypot_paths"],
    "recorded": stats["recorded"],
}))
"""

_HONEYTOKEN_ENFORCE = """
import json, os, sys
from tauhaulity.tools import honeytoken
from tauhaulity.runtime import audit_hook

root, notes = sys.argv[1], sys.argv[2]
armed = honeytoken.deploy(root)
audit_hook.install(enforce=True)
audit_hook.reset()
audit_hook.set_honeypot_paths([str(path) for path in honeytoken.token_paths(root)])
decoy = str(armed.tokens[0].absolute_path)
outcome = {
    "blocked": False,
    "message": "",
    "flag": os.environ.get("TAUHAULITY_HONEYPOT_ENFORCE", ""),
}
try:
    with open(decoy, "r", encoding="utf-8") as handle:
        handle.read()
except PermissionError as exc:
    outcome["blocked"] = True
    outcome["message"] = str(exc)[:160]
with open(notes, "r", encoding="utf-8") as handle:
    outcome["benign"] = handle.read()[:16]
outcome["alerts"] = audit_hook.honeypot_events(8)
print(json.dumps(outcome))
"""

_HONEYTOKEN_COST = """
import json, sys, time
from tauhaulity.tools import honeytoken
from tauhaulity.runtime import audit_hook

root, notes = sys.argv[1], sys.argv[2]
honeytoken.deploy(root)
audit_hook.install(enforce=False)
paths = [str(path) for path in honeytoken.token_paths(root)]
armed_loops = 10000
armed_trials = 10
dormant_loops = 4000
dormant_trials = 5

def run(loops):
    started = time.perf_counter()
    for _ in range(loops):
        with open(notes, "r", encoding="utf-8") as handle:
            handle.read(1)
    return time.perf_counter() - started

dormant = []
for _ in range(dormant_trials):
    audit_hook.set_honeypot_paths([])
    audit_hook.reset()
    dormant.append(run(dormant_loops))
armed = []
for _ in range(armed_trials):
    audit_hook.set_honeypot_paths(paths)
    audit_hook.reset()
    armed.append(run(armed_loops))

dormant_per_call = min(dormant) / dormant_loops
armed_per_call = min(armed) / armed_loops
stats = audit_hook.stats()
print(json.dumps({
    "armed_calls": armed_loops * armed_trials,
    "dormant_calls": dormant_loops * dormant_trials,
    "armed_per_call_us": armed_per_call * 1e6,
    "dormant_per_call_us": dormant_per_call * 1e6,
    "added_per_call_us": (armed_per_call - dormant_per_call) * 1e6,
    "alerts": stats["honeypot_alerts"],
    "watched": stats["honeypot_paths"],
}))
"""

#: Documented ceiling for the honeypot branch on the open hot path. The measured
#: cost on the development host is about one microsecond per open, so the bound is
#: deliberately loose enough for a loaded CI runner and still meaningful.
HONEYPOT_ADDED_COST_BOUND_US = 25.0


def _honeytoken_project(tmp_path: Path) -> tuple[Path, Path]:
    project = tmp_path / "project"
    project.mkdir()
    notes = project / "notes.txt"
    notes.write_text("plain notes", encoding="utf-8")
    return project, notes


def test_honeytoken_open_records_one_alert(project_root: Path, tmp_path: Path) -> None:
    project, notes = _honeytoken_project(tmp_path)
    payload = _run(project_root, _HONEYTOKEN_WATCH, str(project), str(notes), auto=False)
    assert payload["registered"] == 5
    assert payload["watched"] == 5
    assert payload["count"] == 1
    alerts = payload["alerts"]
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert["event"] == "open"
    assert alert["path"] == payload["decoy"]
    assert alert["pid"] == payload["pid"]
    assert alert["caller"] == "__main__"
    # The non-honeypot read and the decoy read both stay in the ordinary ring.
    assert payload["recorded"] >= 2


def test_honeytoken_is_dormant_without_registered_paths(
    project_root: Path, tmp_path: Path
) -> None:
    project, _notes = _honeytoken_project(tmp_path)
    payload = _run(project_root, _HONEYTOKEN_DORMANT, str(project), auto=False)
    assert payload["registered"] == 0
    assert payload["alerts"] == []
    assert payload["count"] == 0
    assert payload["watched"] == 0
    # The ordinary event ring still records the open, so the guard is definitely
    # active and the honeypot branch is the part that allocated nothing.
    assert payload["recorded"] >= 1


def test_honeytoken_block_requires_enforce_and_the_env_flag(
    project_root: Path, tmp_path: Path
) -> None:
    project, notes = _honeytoken_project(tmp_path)
    blocked = _run(
        project_root,
        _HONEYTOKEN_ENFORCE,
        str(project),
        str(notes),
        auto=False,
        extra_env={"TAUHAULITY_HONEYPOT_ENFORCE": "1"},
    )
    assert blocked["flag"] == "1"
    assert blocked["blocked"] is True
    assert "honeytoken" in str(blocked["message"]).lower()
    assert blocked["benign"] == "plain notes"
    assert len(blocked["alerts"]) == 1

    quiet = _run(project_root, _HONEYTOKEN_ENFORCE, str(project), str(notes), auto=False)
    assert quiet["flag"] == ""
    assert quiet["blocked"] is False
    assert len(quiet["alerts"]) == 1


def test_honeytoken_check_keeps_the_guard_fast(
    project_root: Path, tmp_path: Path
) -> None:
    project, notes = _honeytoken_project(tmp_path)
    payload = _run(
        project_root, _HONEYTOKEN_COST, str(project), str(notes), auto=False
    )
    assert payload["armed_calls"] == 100000
    assert payload["watched"] == 5
    assert payload["alerts"] == 0
    assert payload["armed_per_call_us"] > 0
    assert payload["added_per_call_us"] < HONEYPOT_ADDED_COST_BOUND_US


def test_honeypot_paths_are_normalized_and_deduplicated(tmp_path: Path) -> None:
    first = tmp_path / "first.txt"
    second = tmp_path / "second.txt"
    try:
        registered = audit_hook.set_honeypot_paths(
            [str(first), str(first), str(second)]
        )
        assert registered == 2
        assert audit_hook.stats()["honeypot_paths"] == 2
    finally:
        audit_hook.set_honeypot_paths([])
    assert audit_hook.stats()["honeypot_paths"] == 0


def test_honeypot_event_limits_are_validated() -> None:
    assert audit_hook.honeypot_events(0) == []
    with pytest.raises(ValueError):
        audit_hook.honeypot_events(-1)


def test_monitoring_tracer_self_test() -> None:
    assert monitoring.available() is True, "CPython 3.12+ must expose sys.monitoring"
    result = monitoring.tracer.self_test()
    assert result["available"] is True
    assert result["started"] is True, result["reason"]
    assert result["callbacks"] >= 1
    assert result["tool_id"] in monitoring.PREFERRED_TOOL_IDS
    assert monitoring.tracer.active() is False
    stats = monitoring.tracer.stats()
    assert stats["python_calls"] >= 1
    assert stats["tool_id"] is None

# ---------------------------------------------------------------------------
# 0.3.0 containment layer: provenance resolver and policy model
# ---------------------------------------------------------------------------

import importlib


def _resolve_from_filename(filename: str, module_name: str = "") -> dict[str, object]:
    """Execute resolve_provenance inside a frame with a controlled filename.

    Executing compiled code with an explicit filename is the only way to obtain a
    frame that claims to live in a stdlib or project path without writing into the
    interpreter installation.
    """

    namespace: dict[str, object] = {}
    if module_name:
        namespace["__name__"] = module_name
    source = (
        "import tauhaulity.runtime.audit_hook as _guard\n"
        "result = _guard.resolve_provenance().as_dict()\n"
    )
    exec(compile(source, filename, "exec"), namespace)
    return namespace["result"]


def test_resolve_provenance_stdlib_frame() -> None:
    info = _resolve_from_filename(os.__file__, "stdlib_probe")
    assert info["kind"] == "stdlib"
    assert info["path"] == os.path.abspath(os.__file__)


def test_resolve_provenance_project_frame(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    root = tmp_path / "project-root"
    root.mkdir()
    monkeypatch.setenv("TAUHAULITY_PROJECT_ROOTS", str(root))
    info = _resolve_from_filename(str(root / "src" / "app.py"), "project_app")
    assert info["kind"] == "project"
    assert info["module"] == "project_app"


def test_resolve_provenance_site_packages_frame(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = tmp_path / "venv" / "Lib" / "site-packages"
    package = site / "bad_pkg"
    package.mkdir(parents=True)
    module_file = package / "__init__.py"
    module_file.write_text("", encoding="utf-8")
    monkeypatch.syspath_prepend(str(site))
    info = _resolve_from_filename(str(module_file), "bad_pkg")
    assert info["kind"] == "site-packages"
    assert info["package"] == "bad_pkg"


def test_resolve_provenance_from_imported_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    site = tmp_path / "venv" / "Lib" / "site-packages"
    package = site / "prov_pkg"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(
        "import tauhaulity.runtime.audit_hook as _guard\n"
        "\n"
        "def where():\n"
        "    return _guard.resolve_provenance().as_dict()\n",
        encoding="utf-8",
    )
    monkeypatch.syspath_prepend(str(site))
    module = importlib.import_module("prov_pkg")
    try:
        info = module.where()
    finally:
        sys.modules.pop("prov_pkg", None)
    assert info["kind"] == "site-packages"
    assert info["package"] == "prov_pkg"
    assert info["module"] == "prov_pkg"


def test_resolve_provenance_unknown_frame(tmp_path: Path) -> None:
    info = _resolve_from_filename(str(tmp_path / "loose" / "script.py"), "loose_script")
    assert info["kind"] == "unknown"


def test_resolve_provenance_depth_hint() -> None:
    def wrapper() -> dict[str, object]:
        return audit_hook.resolve_provenance(depth_hint=1).as_dict()

    info = wrapper()
    # depth_hint=1 skips the wrapper frame and reports this test frame, which
    # lives in a project file.
    assert info["kind"] == "project"


def test_guard_policy_defaults() -> None:
    policy = audit_hook.GuardPolicy()
    assert policy.enforce is False
    assert policy.deny_third_party_connect is True
    assert policy.deny_third_party_subprocess is True
    assert policy.deny_sensitive_reads is True
    assert policy.allowlist == ("tauhaulity",)
    assert policy.as_dict()["allowlist"] == ["tauhaulity"]


def test_guard_policy_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        "TAUHAULITY_ENFORCE",
        "TAUHAULITY_DENY_CONNECT",
        "TAUHAULITY_DENY_SUBPROCESS",
        "TAUHAULITY_GUARD_ALLOW",
    ):
        monkeypatch.delenv(name, raising=False)
    default = audit_hook.GuardPolicy.from_env()
    assert default.enforce is False
    assert default.deny_third_party_connect is True
    assert default.deny_third_party_subprocess is True
    assert default.allowlist == ("tauhaulity",)

    monkeypatch.setenv("TAUHAULITY_ENFORCE", "1")
    monkeypatch.setenv("TAUHAULITY_DENY_CONNECT", "0")
    monkeypatch.setenv("TAUHAULITY_DENY_SUBPROCESS", "off")
    monkeypatch.setenv("TAUHAULITY_GUARD_ALLOW", "alpha, beta.two")
    policy = audit_hook.GuardPolicy.from_env()
    assert policy.enforce is True
    assert policy.deny_third_party_connect is False
    assert policy.deny_third_party_subprocess is False
    assert policy.deny_sensitive_reads is True
    assert set(policy.allowlist) == {"tauhaulity", "alpha", "beta.two"}


def test_guard_policy_allowlist_always_contains_tauhaulity() -> None:
    policy = audit_hook.GuardPolicy(allowlist=("alpha",))
    assert policy.allowlist == ("tauhaulity", "alpha")
    ours = audit_hook.Provenance(
        "site-packages", "/venv/site-packages/tauhaulity/__init__.py", "tauhaulity", "tauhaulity"
    )
    third_party = audit_hook.Provenance(
        "site-packages", "/venv/site-packages/evil/__init__.py", "evil", "evil"
    )
    assert policy.allows(ours) is True
    assert policy.allows(third_party) is False


def test_runtime_package_reexports() -> None:
    from tauhaulity import runtime

    assert runtime.GuardPolicy is audit_hook.GuardPolicy
    assert runtime.Provenance is audit_hook.Provenance
    assert runtime.resolve_provenance is audit_hook.resolve_provenance
    assert callable(runtime.arm_shield)
    assert callable(runtime.shield)
    assert runtime.denials(0) == []


def test_denial_message_names_package_event_and_flag() -> None:
    connect = audit_hook._denial_message(
        "connect", "evil_pkg", "socket.connect", "1.2.3.4:443", "deny_third_party_connect"
    )
    assert "site-packages" in connect
    assert "evil_pkg" in connect
    assert "socket.connect" in connect
    assert "deny_third_party_connect" in connect
    read = audit_hook._denial_message(
        "sensitive_read", "pkg", "open", "/project/.env", "deny_sensitive_reads"
    )
    assert "credential" in read.lower()
    assert "/project/.env" in read
    assert "deny_sensitive_reads" in read
    spawn = audit_hook._denial_message(
        "subprocess", "pkg", "subprocess.Popen", "/bin/sh", "deny_third_party_subprocess"
    )
    assert "subprocess.Popen" in spawn
    assert "deny_third_party_subprocess" in spawn


def test_guard_stats_expose_policy_and_counters() -> None:
    stats = audit_hook.stats()
    for key in (
        "events_ring_size",
        "denials",
        "blocked_events",
        "provenance_cache_hits",
        "policy",
    ):
        assert key in stats
    assert stats["policy"]["allowlist"][0] == "tauhaulity"
    assert stats["denials"] == 0
    assert audit_hook.denials(0) == []
    with pytest.raises(ValueError):
        audit_hook.denials(-1)
