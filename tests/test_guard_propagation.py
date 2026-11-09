"""Tests for child process guard propagation (0.3.3-A).

A PEP-578 hook dies with its process, so the only way to contain a Python child is
to make the child arm itself. The shim produced by propagation_sitecustomize() is
put first on PYTHONPATH, where the standard site module imports it before
application code. Every scenario that arms a guard runs in a fresh interpreter.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from tauhaulity.runtime import audit_hook
from tauhaulity.runtime import _bootstrap

_PACKAGE_SOURCE = (
    "import socket\n"
    "\n"
    "def raw_connect(host, port):\n"
    "    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
    "    sock.settimeout(5.0)\n"
    "    try:\n"
    "        sock.connect((host, port))\n"
    "    finally:\n"
    "        sock.close()\n"
    "    return 'connected'\n"
)


class _Receiver:
    """Loopback listener that records accepted connections for the plain child."""

    def __init__(self) -> None:
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(8)
        self.port = int(self.server.getsockname()[1])
        self.connections: list[bytes] = []
        self._stop = False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop:
            try:
                connection, _address = self.server.accept()
            except OSError:
                return
            try:
                while True:
                    data = connection.recv(65536)
                    if not data:
                        break
                    self.connections.append(data)
            except OSError:
                pass
            finally:
                try:
                    connection.close()
                except OSError:
                    pass

    def close(self) -> None:
        self._stop = True
        try:
            self.server.close()
        except OSError:
            pass
        self._thread.join(timeout=2.0)


@pytest.fixture()
def receiver():
    server = _Receiver()
    try:
        yield server
    finally:
        server.close()


def _site_dir(tmp_path: Path) -> Path:
    site = tmp_path / "fake-venv" / "Lib" / "site-packages"
    package = site / "evil_pkg"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text(_PACKAGE_SOURCE, encoding="utf-8")
    return site


def _env(project_root: Path, extra: dict[str, str] | None = None) -> dict[str, str]:
    env = os.environ.copy()
    env["TAUHAULITY_NO_AUTO"] = "1"
    for name in (
        "TAUHAULITY_ENFORCE",
        "TAUHAULITY_GUARD_PROPAGATED",
        "TAUHAULITY_GUARD_ALLOW",
        "TAUHAULITY_DENY_CONNECT",
        "TAUHAULITY_DENY_SUBPROCESS",
        "TAUHAULITY_DENY_DESERIALIZE",
        "TAUHAULITY_DENY_SECRET_EGRESS",
    ):
        env.pop(name, None)
    env["PYTHONPATH"] = str(project_root) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    if extra:
        env.update(extra)
    return env


def _run(
    project_root: Path,
    code: str,
    *args: str,
    cwd: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> dict[str, object]:
    completed = subprocess.run(
        [sys.executable, "-c", code, *args],
        cwd=str(cwd if cwd is not None else project_root),
        env=_env(project_root, extra_env),
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert completed.returncode == 0, f"stdout={completed.stdout}\nstderr={completed.stderr}"
    lines = [line for line in completed.stdout.strip().splitlines() if line.strip()]
    assert lines, completed.stderr
    return json.loads(lines[-1])


_CHILD_CONNECT = (
    "import json, sys\n"
    "site_dir, port_text = sys.argv[1:3]\n"
    "sys.path.insert(0, site_dir)\n"
    "import evil_pkg\n"
    "outcome = {'blocked': False, 'message': ''}\n"
    "try:\n"
    "    evil_pkg.raw_connect('127.0.0.1', int(port_text))\n"
    "except PermissionError as exc:\n"
    "    outcome['blocked'] = True\n"
    "    outcome['message'] = str(exc)[:220]\n"
    "print(json.dumps(outcome))\n"
)

_PARENT_SCRIPT = """
import json, os, subprocess, sys
from pathlib import Path
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield, cleanup_propagation, guard_propagation

site_dir, port_text, child_code = sys.argv[1:4]
arm_shield(GuardPolicy(enforce=True))
propagated_env = guard_propagation(dict(os.environ))
plain_env = dict(os.environ)
plain_env.pop("TAUHAULITY_GUARD_PROPAGATED", None)
plain_env.pop("TAUHAULITY_ENFORCE", None)
results = {}
for label, env in (("propagated", propagated_env), ("plain", plain_env)):
    completed = subprocess.run(
        [sys.executable, "-c", child_code, site_dir, port_text],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    lines = [line for line in completed.stdout.strip().splitlines() if line.strip()]
    results[label] = {
        "returncode": completed.returncode,
        "payload": json.loads(lines[-1]) if lines else None,
        "stderr_tail": completed.stderr[-200:],
    }
shim_prefix = propagated_env.get("PYTHONPATH", "").split(os.pathsep)[0]
results["marker"] = propagated_env.get("TAUHAULITY_GUARD_PROPAGATED")
results["enforce_env"] = propagated_env.get("TAUHAULITY_ENFORCE")
results["shim_exists"] = Path(shim_prefix, "sitecustomize.py").is_file()
results["cleaned"] = cleanup_propagation(Path(shim_prefix))
results["shim_after_cleanup"] = Path(shim_prefix).exists()
print(json.dumps(results))
"""


def test_enforcement_propagates_into_a_python_child(
    project_root: Path, tmp_path: Path, receiver: _Receiver
) -> None:
    site = _site_dir(tmp_path)
    payload = _run(
        project_root, _PARENT_SCRIPT, str(site), str(receiver.port), _CHILD_CONNECT
    )
    assert payload["marker"] == "1"
    assert payload["enforce_env"] == "1"
    assert payload["shim_exists"] is True
    propagated = payload["propagated"]
    assert propagated["returncode"] == 0, propagated["stderr_tail"]
    assert propagated["payload"]["blocked"] is True
    message = str(propagated["payload"]["message"])
    assert "socket.connect" in message
    assert "deny_third_party_connect" in message
    # The gap was real: the same child without the propagated environment escapes.
    plain = payload["plain"]
    assert plain["returncode"] == 0, plain["stderr_tail"]
    assert plain["payload"]["blocked"] is False
    assert payload["cleaned"] is True
    assert payload["shim_after_cleanup"] is False


_CHILD_WATCH = (
    "import json, sys\n"
    "site_dir, port_text = sys.argv[1:3]\n"
    "sys.path.insert(0, site_dir)\n"
    "from tauhaulity.runtime import audit_hook\n"
    "import evil_pkg\n"
    "outcome = {'active': audit_hook.active(), 'enforce': audit_hook.enforce_enabled(), 'blocked': False}\n"
    "try:\n"
    "    evil_pkg.raw_connect('127.0.0.1', int(port_text))\n"
    "except PermissionError:\n"
    "    outcome['blocked'] = True\n"
    "print(json.dumps(outcome))\n"
)

_WATCH_PARENT_SCRIPT = """
import json, os, subprocess, sys
from pathlib import Path
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield, cleanup_propagation, guard_propagation

site_dir, port_text, child_code = sys.argv[1:4]
arm_shield(GuardPolicy(enforce=False))
propagated_env = guard_propagation(dict(os.environ))
completed = subprocess.run(
    [sys.executable, "-c", child_code, site_dir, port_text],
    env=propagated_env,
    capture_output=True,
    text=True,
    timeout=120,
)
lines = [line for line in completed.stdout.strip().splitlines() if line.strip()]
shim_prefix = propagated_env.get("PYTHONPATH", "").split(os.pathsep)[0]
cleanup_propagation(Path(shim_prefix))
print(json.dumps({
    "returncode": completed.returncode,
    "stderr_tail": completed.stderr[-200:],
    "payload": json.loads(lines[-1]) if lines else None,
    "enforce_env": propagated_env.get("TAUHAULITY_ENFORCE"),
}))
"""


def test_watch_policy_propagates_as_watch(
    project_root: Path, tmp_path: Path, receiver: _Receiver
) -> None:
    site = _site_dir(tmp_path)
    payload = _run(
        project_root, _WATCH_PARENT_SCRIPT, str(site), str(receiver.port), _CHILD_WATCH
    )
    assert payload["enforce_env"] == "0"
    assert payload["returncode"] == 0, payload["stderr_tail"]
    child = payload["payload"]
    assert child["active"] is True, "the shim must arm watch mode from the marker"
    assert child["enforce"] is False
    assert child["blocked"] is False, "watch mode must not block"


def test_broken_shim_is_swallowed(project_root: Path, tmp_path: Path) -> None:
    shim = tmp_path / "broken-shim"
    shim.mkdir()
    (shim / "sitecustomize.py").write_text("raise ImportError('broken shim')\n", encoding="utf-8")
    env = _env(project_root)
    env["PYTHONPATH"] = str(shim) + os.pathsep + env.get("PYTHONPATH", "")
    completed = subprocess.run(
        [sys.executable, "-c", "print('alive')"],
        cwd=str(project_root),
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert completed.returncode == 0, completed.stderr
    assert "alive" in completed.stdout


def test_generated_shim_survives_a_missing_tauhaulity(tmp_path: Path) -> None:
    shim = audit_hook.propagation_sitecustomize(tmp_path / "shim")
    empty = tmp_path / "empty"
    empty.mkdir()
    try:
        env = os.environ.copy()
        env["TAUHAULITY_NO_AUTO"] = "1"
        env["TAUHAULITY_GUARD_PROPAGATED"] = "1"
        env["PYTHONPATH"] = str(shim)
        env.pop("PYTHONHOME", None)
        completed = subprocess.run(
            [sys.executable, "-c", "print('alive')"],
            cwd=str(empty),
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert completed.returncode == 0, completed.stderr
        assert "alive" in completed.stdout
    finally:
        audit_hook.cleanup_propagation(shim)


def test_marker_prevents_double_prepend_and_cleanup_removes_directory(tmp_path: Path) -> None:
    env = {"PATH": "unchanged"}
    propagated = audit_hook.guard_propagation(env, directory=tmp_path / "shim")
    assert propagated["TAUHAULITY_GUARD_PROPAGATED"] == "1"
    assert propagated["PATH"] == "unchanged"
    prefix = propagated["PYTHONPATH"].split(os.pathsep)[0]
    shim = Path(prefix)
    assert (shim / "sitecustomize.py").is_file()
    assert propagated["PYTHONPATH"] == str(shim)
    assert "TAUHAULITY_ENFORCE" in propagated
    assert "TAUHAULITY_GUARD_ALLOW" in propagated

    again = audit_hook.guard_propagation(propagated)
    assert again["PYTHONPATH"] == propagated["PYTHONPATH"]
    assert again["TAUHAULITY_GUARD_PROPAGATED"] == "1"
    assert again is not propagated

    assert audit_hook.cleanup_propagation(shim) is True
    assert not shim.exists()
    assert audit_hook.cleanup_propagation(shim) is False


def test_default_shim_directories_are_unique() -> None:
    first = audit_hook.propagation_sitecustomize()
    second = audit_hook.propagation_sitecustomize()
    try:
        assert first != second
        assert (first / "sitecustomize.py").is_file()
        assert (second / "sitecustomize.py").is_file()
        source = (first / "sitecustomize.py").read_text(encoding="utf-8")
        assert "TAUHAULITY_GUARD_PROPAGATED" in source
        assert "arm_shield" in source
        assert "except Exception" in source
        assert _bootstrap.SITECUSTOMIZE_SOURCE.strip() == source.strip()
    finally:
        audit_hook.cleanup_propagation(first)
        audit_hook.cleanup_propagation(second)
    assert not first.exists()
    assert not second.exists()


def test_shim_is_inert_without_marker_or_enforce(project_root: Path, tmp_path: Path) -> None:
    shim = audit_hook.propagation_sitecustomize(tmp_path / "inert")
    try:
        env = _env(project_root)
        env.pop("TAUHAULITY_ENFORCE", None)
        env.pop("TAUHAULITY_GUARD_PROPAGATED", None)
        env["PYTHONPATH"] = str(shim) + os.pathsep + env.get("PYTHONPATH", "")
        completed = subprocess.run(
            [
                sys.executable,
                "-c",
                "import json, sys; print(json.dumps({'imported': 'tauhaulity' in sys.modules}))",
            ],
            cwd=str(project_root),
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert completed.returncode == 0, completed.stderr
        payload = json.loads(completed.stdout.strip().splitlines()[-1])
        assert payload["imported"] is False
    finally:
        audit_hook.cleanup_propagation(shim)


def test_propagation_marker_is_exported() -> None:
    from tauhaulity import runtime

    assert runtime.PROPAGATION_MARKER == "TAUHAULITY_GUARD_PROPAGATED"
    assert runtime.propagation_sitecustomize is audit_hook.propagation_sitecustomize
    assert runtime.guard_propagation is audit_hook.guard_propagation
    assert runtime.cleanup_propagation is audit_hook.cleanup_propagation

def test_propagation_never_weakens_an_explicit_enforce_request() -> None:
    """An environment that asks for enforcement must keep asking for it.

    Reading audit_hook arms a watch mode guard on import, so a caller that builds
    the child environment before arming enforcement (the CLI does exactly that) used
    to get its own TAUHAULITY_ENFORCE=1 mirrored back as 0, and the child silently
    watched instead of enforcing. The mirror is one directional now.
    """

    child_env = audit_hook.guard_propagation({"TAUHAULITY_ENFORCE": "1"})
    try:
        assert child_env["TAUHAULITY_ENFORCE"] == "1"
        assert child_env[_bootstrap.PROPAGATION_MARKER] == "1"
        shim = Path(child_env["PYTHONPATH"].split(os.pathsep)[0])
        assert (shim / "sitecustomize.py").is_file()
    finally:
        audit_hook.cleanup_propagation(Path(child_env["PYTHONPATH"].split(os.pathsep)[0]))
