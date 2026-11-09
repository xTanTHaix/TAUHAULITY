"""Tests for the 0.3.0 containment layer: provenance aware enforcement.

A PEP-578 audit hook cannot be removed, so every scenario that arms enforcement
runs in a fresh interpreter. The scripts below build a fake virtual environment,
put its site-packages directory on sys.path, and verify that the same operation is
blocked from the planted package while it succeeds from a project module.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest

from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, Provenance, resolve_provenance

#: Documented ceiling for the watch mode envelope on 100,000 audited events. The
#: measured cost on the development host is reported in the phase report; the bound
#: is loose enough for a loaded CI runner and still meaningful (50 microseconds per
#: event would already be an order of magnitude above the measured value).
ARMED_EVENT_COST_BOUND_S = 5.0
COST_EVENTS = 100_000

_PACKAGE_SOURCE = (
    "import os, socket, subprocess, sys\n"
    "\n"
    "def raw_connect(host, port):\n"
    "    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
    "    sock.settimeout(2.0)\n"
    "    try:\n"
    "        sock.connect((host, port))\n"
    "    finally:\n"
    "        sock.close()\n"
    "    return 'connected'\n"
    "\n"
    "def resolve(host, port):\n"
    "    return socket.getaddrinfo(host, port)\n"
    "\n"
    "def spawn():\n"
    "    proc = subprocess.Popen([sys.executable, '-c', 'pass'])\n"
    "    proc.wait(timeout=20)\n"
    "    return proc.returncode\n"
    "\n"
    "def shell():\n"
    "    return os.system('echo tauhaulity-guard-probe')\n"
    "\n"
    "def read_path(path):\n"
    "    with open(path, 'r', encoding='utf-8') as handle:\n"
    "        return handle.read()\n"
)

_PROJECT_SOURCE = (
    "import socket, subprocess, sys\n"
    "\n"
    "def raw_connect(host, port):\n"
    "    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
    "    sock.settimeout(2.0)\n"
    "    try:\n"
    "        sock.connect((host, port))\n"
    "    finally:\n"
    "        sock.close()\n"
    "    return 'connected'\n"
    "\n"
    "def read_path(path):\n"
    "    with open(path, 'r', encoding='utf-8') as handle:\n"
    "        return handle.read()\n"
)


def _guard_env(project_root: Path, project_dir: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env["TAUHAULITY_NO_AUTO"] = "1"
    for name in (
        "TAUHAULITY_ENFORCE",
        "TAUHAULITY_DENY_CONNECT",
        "TAUHAULITY_DENY_SUBPROCESS",
        "TAUHAULITY_GUARD_ALLOW",
        "TAUHAULITY_HONEYPOT_ENFORCE",
    ):
        env.pop(name, None)
    env["TAUHAULITY_PROJECT_ROOTS"] = str(project_dir)
    env["PYTHONPATH"] = str(project_root) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if extra:
        env.update(extra)
    return env


def _run_guard(
    project_root: Path,
    project_dir: Path,
    code: str,
    *args: str,
    extra_env: dict[str, str] | None = None,
) -> dict[str, object]:
    completed = subprocess.run(
        [sys.executable, "-c", code, *args],
        cwd=str(project_root),
        env=_guard_env(project_root, project_dir, extra_env),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, f"stdout={completed.stdout}\nstderr={completed.stderr}"
    lines = [line for line in completed.stdout.strip().splitlines() if line.strip()]
    assert lines, completed.stderr
    return json.loads(lines[-1])


def _build_tree(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    site = tmp_path / "fake-venv" / "Lib" / "site-packages"
    package = site / "evil_pkg"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(_PACKAGE_SOURCE, encoding="utf-8")
    project = tmp_path / "project"
    project_package = project / "proj_pkg"
    project_package.mkdir(parents=True)
    (project_package / "__init__.py").write_text(_PROJECT_SOURCE, encoding="utf-8")
    env_path = project / ".env"
    env_path.write_text("API_TOKEN=guard-test-value\n", encoding="utf-8")
    notes = project / "notes.txt"
    notes.write_text("plain notes", encoding="utf-8")
    return site, project, env_path, notes


@pytest.fixture()
def listener():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    try:
        yield server.getsockname()
    finally:
        server.close()


_CONNECT_SCRIPT = """
import json, os, socket, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

site_dir, project_dir, host, port = sys.argv[1:5]
sys.path.insert(0, site_dir)
sys.path.insert(0, project_dir)
arm_shield(GuardPolicy(enforce=True))
import evil_pkg
import proj_pkg

outcome = {"evil": {}, "evil_resolve": {}, "project": {}, "denials": []}
try:
    evil_pkg.raw_connect(host, int(port))
    outcome["evil"]["blocked"] = False
except PermissionError as exc:
    outcome["evil"] = {"blocked": True, "message": str(exc)}
try:
    evil_pkg.resolve(host, int(port))
    outcome["evil_resolve"]["blocked"] = False
except PermissionError as exc:
    outcome["evil_resolve"] = {"blocked": True, "message": str(exc)}
try:
    outcome["project"]["value"] = proj_pkg.raw_connect(host, int(port))
except PermissionError as exc:
    outcome["project"] = {"blocked": True, "message": str(exc)}
outcome["denials"] = audit_hook.denials(8)
stats = audit_hook.stats()
outcome["stats"] = {key: stats[key] for key in (
    "denials", "blocked_events", "events_ring_size", "provenance_cache_hits"
)}
outcome["policy"] = stats["policy"]
outcome["blocked_events"] = [event for event in audit_hook.events(64) if event["blocked"]]
print(json.dumps(outcome))
"""


def test_connect_from_site_packages_is_blocked(
    project_root: Path, tmp_path: Path, listener: tuple[str, int]
) -> None:
    site, project, _env, _notes = _build_tree(tmp_path)
    host, port = listener
    payload = _run_guard(
        project_root, project, _CONNECT_SCRIPT, str(site), str(project), host, str(port)
    )
    evil = payload["evil"]
    assert evil["blocked"] is True
    message = str(evil["message"])
    assert "site-packages" in message
    assert "evil_pkg" in message
    assert "socket.connect" in message
    assert "deny_third_party_connect" in message
    assert f"{host}" in message

    resolve = payload["evil_resolve"]
    assert resolve["blocked"] is True
    assert "socket.getaddrinfo" in str(resolve["message"])
    assert "deny_third_party_connect" in str(resolve["message"])

    # The same operation from a project module is allowed: provenance decides.
    assert payload["project"] == {"value": "connected"}

    denials = payload["denials"]
    assert len(denials) == 2
    first = denials[0]
    assert first["kind"] == "connect"
    assert first["event"] == "socket.connect"
    assert first["flag"] == "deny_third_party_connect"
    assert isinstance(first["time"], float) and first["time"] > 0
    assert isinstance(first["target"], str) and first["target"]
    assert first["provenance"]["kind"] == "site-packages"
    assert first["provenance"]["package"] == "evil_pkg"
    stats = payload["stats"]
    assert stats["denials"] == 2
    assert stats["blocked_events"] >= 2
    assert isinstance(stats["events_ring_size"], int)
    assert stats["provenance_cache_hits"] >= 1
    assert payload["policy"]["enforce"] is True
    blocked_events = payload["blocked_events"]
    assert blocked_events
    assert blocked_events[0]["origin"] == "third-party"
    assert blocked_events[0]["flag"] == "deny_third_party_connect"


_SPAWN_SCRIPT = """
import json, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

site_dir, project_dir = sys.argv[1:3]
sys.path.insert(0, site_dir)
sys.path.insert(0, project_dir)
arm_shield(GuardPolicy(enforce=True))
import evil_pkg

outcome = {"popen": {}, "shell": {}, "denials": []}
for label, call in (("popen", evil_pkg.spawn), ("shell", evil_pkg.shell)):
    try:
        outcome[label]["blocked"] = False
        outcome[label]["value"] = str(call())[:80]
    except PermissionError as exc:
        outcome[label] = {"blocked": True, "message": str(exc)}
outcome["denials"] = audit_hook.denials(8)
print(json.dumps(outcome))
"""


def test_subprocess_and_shell_are_blocked(project_root: Path, tmp_path: Path) -> None:
    site, project, _env, _notes = _build_tree(tmp_path)
    payload = _run_guard(project_root, project, _SPAWN_SCRIPT, str(site), str(project))
    popen = payload["popen"]
    assert popen["blocked"] is True
    assert "subprocess.Popen" in str(popen["message"])
    assert "deny_third_party_subprocess" in str(popen["message"])
    assert "evil_pkg" in str(popen["message"])
    shell = payload["shell"]
    assert shell["blocked"] is True
    assert "os.system" in str(shell["message"])
    assert "deny_third_party_subprocess" in str(shell["message"])
    denials = payload["denials"]
    assert len(denials) == 2
    assert {denial["kind"] for denial in denials} == {"subprocess"}
    assert {denial["event"] for denial in denials} == {"subprocess.Popen", "os.system"}


_READ_SCRIPT = """
import json, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

site_dir, project_dir, env_path, notes_path = sys.argv[1:5]
sys.path.insert(0, site_dir)
sys.path.insert(0, project_dir)
arm_shield(GuardPolicy(enforce=True))
import evil_pkg
import proj_pkg

outcome = {"evil_env": {}, "evil_notes": {}, "project_env": {}, "denials": []}
try:
    evil_pkg.read_path(env_path)
    outcome["evil_env"]["blocked"] = False
except PermissionError as exc:
    outcome["evil_env"] = {"blocked": True, "message": str(exc)}
try:
    outcome["evil_notes"]["value"] = evil_pkg.read_path(notes_path).strip()
except PermissionError as exc:
    outcome["evil_notes"] = {"blocked": True, "message": str(exc)}
try:
    outcome["project_env"]["value"] = proj_pkg.read_path(env_path).strip()
except PermissionError as exc:
    outcome["project_env"] = {"blocked": True, "message": str(exc)}
outcome["denials"] = audit_hook.denials(8)
print(json.dumps(outcome))
"""


def test_sensitive_read_is_blocked(project_root: Path, tmp_path: Path) -> None:
    site, project, env_path, notes = _build_tree(tmp_path)
    payload = _run_guard(
        project_root, project, _READ_SCRIPT, str(site), str(project), str(env_path), str(notes)
    )
    evil_env = payload["evil_env"]
    assert evil_env["blocked"] is True
    message = str(evil_env["message"])
    assert "evil_pkg" in message
    assert "credential" in message.lower()
    assert "deny_sensitive_reads" in message
    # A non sensitive file is still readable by the package.
    assert payload["evil_notes"] == {"value": "plain notes"}
    # The project reading its own secret is allowed.
    assert payload["project_env"] == {"value": "API_TOKEN=guard-test-value"}
    denials = payload["denials"]
    assert len(denials) == 1
    assert denials[0]["kind"] == "sensitive_read"
    assert denials[0]["flag"] == "deny_sensitive_reads"
    assert denials[0]["event"] == "open"
    assert ".env" in denials[0]["target"]


_OFF_SCRIPT = """
import json, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

site_dir, project_dir, host, port = sys.argv[1:5]
sys.path.insert(0, site_dir)
sys.path.insert(0, project_dir)
arm_shield(GuardPolicy(enforce=False))
import evil_pkg

outcome = {"blocked": False, "denials": [], "recorded": 0}
try:
    outcome["value"] = evil_pkg.raw_connect(host, int(port))
except PermissionError as exc:
    outcome["blocked"] = True
    outcome["message"] = str(exc)
outcome["denials"] = audit_hook.denials(4)
outcome["recorded"] = audit_hook.stats()["recorded"]
outcome["enforce"] = audit_hook.enforce_enabled()
print(json.dumps(outcome))
"""


def test_enforce_off_only_records(project_root: Path, tmp_path: Path, listener: tuple[str, int]) -> None:
    site, project, _env, _notes = _build_tree(tmp_path)
    host, port = listener
    payload = _run_guard(
        project_root, project, _OFF_SCRIPT, str(site), str(project), host, str(port)
    )
    assert payload["blocked"] is False
    assert payload["value"] == "connected"
    assert payload["denials"] == []
    assert payload["enforce"] is False
    assert payload["recorded"] >= 1


_ALLOWLIST_SCRIPT = """
import json, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

site_dir, project_dir, host, port = sys.argv[1:5]
sys.path.insert(0, site_dir)
sys.path.insert(0, project_dir)
arm_shield(GuardPolicy.from_env())
import evil_pkg

outcome = {"blocked": False, "denials": [], "policy": audit_hook.stats()["policy"]}
try:
    outcome["value"] = evil_pkg.raw_connect(host, int(port))
except PermissionError as exc:
    outcome["blocked"] = True
    outcome["message"] = str(exc)
outcome["denials"] = audit_hook.denials(4)
print(json.dumps(outcome))
"""


def test_allowlisted_package_is_not_blocked(
    project_root: Path, tmp_path: Path, listener: tuple[str, int]
) -> None:
    site, project, _env, _notes = _build_tree(tmp_path)
    host, port = listener
    payload = _run_guard(
        project_root,
        project,
        _ALLOWLIST_SCRIPT,
        str(site),
        str(project),
        host,
        str(port),
        extra_env={
            "TAUHAULITY_ENFORCE": "1",
            "TAUHAULITY_GUARD_ALLOW": "tauhaulity,evil_pkg",
        },
    )
    assert payload["blocked"] is False
    assert payload["value"] == "connected"
    assert payload["denials"] == []
    assert "evil_pkg" in payload["policy"]["allowlist"]
    assert payload["policy"]["enforce"] is True


_FLAGS_SCRIPT = """
import json, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

site_dir, project_dir, env_path, host, port = sys.argv[1:6]
sys.path.insert(0, site_dir)
sys.path.insert(0, project_dir)
arm_shield(GuardPolicy(
    enforce=True,
    deny_third_party_connect=True,
    deny_third_party_subprocess=False,
    deny_sensitive_reads=False,
))
import evil_pkg

outcome = {"connect": {}, "spawn": {}, "read": {}, "denials": []}
try:
    evil_pkg.raw_connect(host, int(port))
    outcome["connect"]["blocked"] = False
except PermissionError as exc:
    outcome["connect"] = {"blocked": True, "message": str(exc)}
try:
    outcome["spawn"]["value"] = evil_pkg.spawn()
except PermissionError as exc:
    outcome["spawn"] = {"blocked": True, "message": str(exc)}
try:
    outcome["read"]["value"] = evil_pkg.read_path(env_path).strip()
except PermissionError as exc:
    outcome["read"] = {"blocked": True, "message": str(exc)}
outcome["denials"] = audit_hook.denials(8)
print(json.dumps(outcome))
"""


def test_each_policy_flag_is_independent(
    project_root: Path, tmp_path: Path, listener: tuple[str, int]
) -> None:
    site, project, env_path, _notes = _build_tree(tmp_path)
    host, port = listener
    payload = _run_guard(
        project_root,
        project,
        _FLAGS_SCRIPT,
        str(site),
        str(project),
        str(env_path),
        host,
        str(port),
    )
    assert payload["connect"]["blocked"] is True
    assert "deny_third_party_connect" in str(payload["connect"]["message"])
    # Subprocess and sensitive read flags are off, so those operations run.
    assert payload["spawn"] == {"value": 0}
    assert payload["read"] == {"value": "API_TOKEN=guard-test-value"}
    denials = payload["denials"]
    assert len(denials) == 1
    assert denials[0]["kind"] == "connect"


_SHIELD_SCRIPT = """
import json, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, shield

site_dir, project_dir, host, port = sys.argv[1:5]
sys.path.insert(0, site_dir)
sys.path.insert(0, project_dir)
import evil_pkg

outcome = {"inside": {}, "after": {}, "active_during": None, "active_after": None}
with shield(GuardPolicy(enforce=True)):
    outcome["active_during"] = audit_hook.active()
    try:
        evil_pkg.raw_connect(host, int(port))
        outcome["inside"]["blocked"] = False
    except PermissionError as exc:
        outcome["inside"] = {"blocked": True, "message": str(exc)}
outcome["active_after"] = audit_hook.active()
try:
    outcome["after"]["value"] = evil_pkg.raw_connect(host, int(port))
except PermissionError as exc:
    outcome["after"] = {"blocked": True, "message": str(exc)}
outcome["denials"] = audit_hook.denials(4)
print(json.dumps(outcome))
"""


def test_shield_context_manager_restores_dormant_state(
    project_root: Path, tmp_path: Path, listener: tuple[str, int]
) -> None:
    site, project, _env, _notes = _build_tree(tmp_path)
    host, port = listener
    payload = _run_guard(
        project_root, project, _SHIELD_SCRIPT, str(site), str(project), host, str(port)
    )
    assert payload["inside"]["blocked"] is True
    assert payload["active_during"] is True
    assert payload["active_after"] is False
    assert payload["after"] == {"value": "connected"}
    assert len(payload["denials"]) == 1


_COST_SCRIPT = """
import json, sys, time
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

arm_shield(GuardPolicy(enforce=False))
audit_hook.reset()
events = 100000
started = time.perf_counter()
for _ in range(events):
    sys._getframe(0)
elapsed = time.perf_counter() - started
stats = audit_hook.stats()
print(json.dumps({
    "elapsed": elapsed,
    "events": events,
    "recorded": stats["recorded"],
    "frame_count": stats["counts"]["sys._getframe"],
    "ring_size": stats["events_ring_size"],
    "denials": stats["denials"],
}))
"""


def test_watch_mode_envelope_stays_bounded(project_root: Path, tmp_path: Path) -> None:
    site, project, _env, _notes = _build_tree(tmp_path)
    payload = _run_guard(project_root, project, _COST_SCRIPT, str(site), str(project))
    assert payload["recorded"] >= COST_EVENTS
    assert payload["frame_count"] >= COST_EVENTS
    assert payload["ring_size"] == audit_hook.EVENT_RING_SIZE
    assert payload["denials"] == 0
    assert payload["elapsed"] < ARMED_EVENT_COST_BOUND_S, (
        f"{COST_EVENTS} audited events took {payload['elapsed']:.3f}s, bound is "
        f"{ARMED_EVENT_COST_BOUND_S:.1f}s"
    )
