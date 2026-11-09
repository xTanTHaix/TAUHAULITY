"""Tests for the outbound secret egress gate (0.3.2-A).

The gate patches class methods on socket/ssl, so every enforcement scenario runs
in a fresh interpreter. A parent loopback receiver collects what actually left the
process, which is the only way to prove that a blocked buffer never reached the
wire.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy

_SECRET = "sk-live-9f8A7b6C5d4E3f2G1h0I"
_SECRET_LABEL = "prod-token"
_OTHER_SECRET = "Qq11Ww22Ee33Rr44Zz55"

_PACKAGE_SOURCE = (
    "import socket, time\n"
    "\n"
    "def send_bytes(host, port, payload):\n"
    "    sock = socket.create_connection((host, port), timeout=5)\n"
    "    try:\n"
    "        sock.sendall(payload)\n"
    "    finally:\n"
    "        sock.close()\n"
    "\n"
    "def send_secret(host, port, secret, prefix='Authorization: Bearer '):\n"
    "    send_bytes(host, port, prefix.encode() + secret.encode())\n"
    "\n"
    "def send_split(host, port, first, second):\n"
    "    sock = socket.create_connection((host, port), timeout=5)\n"
    "    try:\n"
    "        sock.sendall(first)\n"
    "        time.sleep(0.02)\n"
    "        sock.sendall(second)\n"
    "    finally:\n"
    "        sock.close()\n"
    "\n"
    "def sendmsg_buffers(host, port, buffers):\n"
    "    sock = socket.create_connection((host, port), timeout=5)\n"
    "    try:\n"
    "        sock.sendmsg(buffers)\n"
    "    finally:\n"
    "        sock.close()\n"
    "\n"
    "def sendfile_path(host, port, path):\n"
    "    sock = socket.create_connection((host, port), timeout=5)\n"
    "    try:\n"
    "        with open(path, 'rb') as handle:\n"
    "            sock.sendfile(handle)\n"
    "    finally:\n"
    "        sock.close()\n"
)

_PREFIX = b"Authorization: Bearer "


class _Receiver:
    """Loopback TCP receiver that records every byte the child actually sent."""

    def __init__(self) -> None:
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(8)
        self.port = int(self.server.getsockname()[1])
        self._chunks: list[bytes] = []
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
                    data = connection.recv(1 << 20)
                    if not data:
                        break
                    self._chunks.append(data)
            except OSError:
                pass
            finally:
                try:
                    connection.close()
                except OSError:
                    pass

    def data(self) -> bytes:
        return b"".join(self._chunks)

    def wait_for(self, expected_bytes: int, timeout: float = 10.0) -> bytes:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if len(self.data()) >= expected_bytes:
                break
            time.sleep(0.01)
        return self.data()

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
        "TAUHAULITY_DENY_SECRET_EGRESS",
        "TAUHAULITY_EGRESS_SECRETS",
        "TAUHAULITY_PROJECT_ROOTS",
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


_SEND_SCRIPT = """
import json, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield, register_secrets

mode, port_text, secret_text, site_dir = sys.argv[1:5]
sys.path.insert(0, site_dir)
register_secrets([secret_text], label="prod-token")
arm_shield(
    GuardPolicy(
        enforce=(mode in {"block", "split_full_second"}),
        deny_third_party_connect=False,
    ),
    secret_files=("/nonexistent",),
)
import evil_pkg

outcome = {"blocked": False, "message": "", "denials": [], "stats": {}, "events": []}
try:
    if mode == "benign":
        evil_pkg.send_bytes(
            "127.0.0.1", int(port_text),
            b"GET /health HTTP/1.1" + b"x" * len(secret_text),
        )
    elif mode == "split":
        halfway = len(secret_text) // 2
        evil_pkg.send_split(
            "127.0.0.1", int(port_text),
            secret_text[:halfway].encode(), secret_text[halfway:].encode(),
        )
    elif mode == "split_full_second":
        evil_pkg.send_split(
            "127.0.0.1", int(port_text),
            b"Authorization: Bearer ", secret_text.encode(),
        )
    else:
        evil_pkg.send_secret("127.0.0.1", int(port_text), secret_text)
except PermissionError as exc:
    outcome["blocked"] = True
    outcome["message"] = str(exc)
outcome["denials"] = audit_hook.denials(8)
stats = audit_hook.stats()
outcome["stats"] = {
    key: stats[key] for key in (
        "denials", "blocked_events", "secret_egress_watch_events",
        "egress_gate_active", "secret_registry_size",
    )
}
outcome["events"] = [event for event in audit_hook.events(64) if event.get("blocked")]
print(json.dumps(outcome))
"""


def test_secret_bearing_send_is_refused_when_enforced(
    project_root: Path, tmp_path: Path, receiver: _Receiver
) -> None:
    site = _site_dir(tmp_path)
    payload = _run(project_root, _SEND_SCRIPT, "block", str(receiver.port), _SECRET, str(site))
    assert payload["blocked"] is True
    message = str(payload["message"])
    assert "secret egress blocked" in message
    assert f"label '{_SECRET_LABEL}'" in message
    assert "byte offset 22" in message
    assert "127.0.0.1" in message
    assert "deny_egress_with_secrets" in message
    assert _SECRET not in message
    denial = payload["denials"][0]
    assert denial["kind"] == "secret_egress"
    assert denial["label"] == _SECRET_LABEL
    assert denial["offset"] == 22
    assert len(denial["sha256_prefix"]) == 16
    assert denial["flag"] == "deny_egress_with_secrets"
    assert _SECRET not in json.dumps(payload)
    assert payload["stats"]["denials"] == 1
    assert payload["stats"]["blocked_events"] >= 1
    assert payload["stats"]["egress_gate_active"] is True
    assert payload["events"]
    assert _SECRET not in json.dumps(payload["events"])
    assert receiver.wait_for(1, timeout=1.0) == b"", "a blocked buffer must not reach the wire"


def test_benign_buffer_of_the_same_size_is_sent(
    project_root: Path, tmp_path: Path, receiver: _Receiver
) -> None:
    site = _site_dir(tmp_path)
    expected = b"GET /health HTTP/1.1" + b"x" * len(_SECRET)
    payload = _run(project_root, _SEND_SCRIPT, "benign", str(receiver.port), _SECRET, str(site))
    assert payload["blocked"] is False
    assert payload["denials"] == []
    received = receiver.wait_for(len(expected))
    assert received == expected


def test_secret_split_across_two_sends_is_not_detected(
    project_root: Path, tmp_path: Path, receiver: _Receiver
) -> None:
    site = _site_dir(tmp_path)
    payload = _run(project_root, _SEND_SCRIPT, "split", str(receiver.port), _SECRET, str(site))
    assert payload["blocked"] is False
    assert payload["denials"] == []
    received = receiver.wait_for(len(_SECRET))
    # Documented boundary: each buffer is judged on its own, so a secret split
    # below the window between two sends is not reconstructed.
    assert received == _SECRET.encode()


def test_full_secret_in_the_second_buffer_is_refused(
    project_root: Path, tmp_path: Path, receiver: _Receiver
) -> None:
    site = _site_dir(tmp_path)
    payload = _run(
        project_root, _SEND_SCRIPT, "split_full_second", str(receiver.port), _SECRET, str(site)
    )
    assert payload["blocked"] is True
    assert payload["denials"][0]["offset"] == 0
    assert payload["denials"][0]["label"] == _SECRET_LABEL
    # The first, secret-free buffer was already sent before the refusal.
    assert receiver.wait_for(len(_PREFIX)) == _PREFIX


def test_watch_mode_records_and_sends_unchanged(
    project_root: Path, tmp_path: Path, receiver: _Receiver
) -> None:
    site = _site_dir(tmp_path)
    payload = _run(project_root, _SEND_SCRIPT, "watch", str(receiver.port), _SECRET, str(site))
    assert payload["blocked"] is False
    denials = payload["denials"]
    assert len(denials) == 1
    assert denials[0]["kind"] == "secret_egress"
    assert denials[0]["blocked"] is False
    assert denials[0]["watch"] is True
    assert payload["stats"]["denials"] == 0
    assert payload["stats"]["blocked_events"] == 0
    assert payload["stats"]["secret_egress_watch_events"] >= 1
    received = receiver.wait_for(len(_PREFIX) + len(_SECRET))
    assert received == _PREFIX + _SECRET.encode()


_WRAP_SCRIPT = """
import json, socket, ssl, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield, shield, unpatch_egress

targets = [
    ("socket.send", socket.socket, "send"),
    ("socket.sendall", socket.socket, "sendall"),
    ("socket.sendto", socket.socket, "sendto"),
    ("socket.sendmsg", socket.socket, "sendmsg"),
    ("socket.sendfile", socket.socket, "sendfile"),
    ("ssl.send", ssl.SSLSocket, "send"),
    ("ssl.sendall", ssl.SSLSocket, "sendall"),
    ("ssl.sendmsg", ssl.SSLSocket, "sendmsg"),
]
originals = {}
for name, owner, attribute in targets:
    originals[name] = getattr(owner, attribute, None)
arm_shield(GuardPolicy(enforce=True), secret_files=("/nonexistent",))
first_ids = {
    name: id(getattr(owner, attribute))
    for name, owner, attribute in targets
    if getattr(owner, attribute, None) is not None
}
wrapped = {
    name: bool(getattr(getattr(owner, attribute, None), "__tauhaulity_egress_gate__", False))
    for name, owner, attribute in targets
}
arm_shield(GuardPolicy(enforce=True), secret_files=("/nonexistent",))
second_ids = {
    name: id(getattr(owner, attribute))
    for name, owner, attribute in targets
    if getattr(owner, attribute, None) is not None
}
gate_active_before = audit_hook.egress_gate_active()
restored_count = unpatch_egress()
identity = {
    name: getattr(owner, attribute, None) is originals[name]
    for name, owner, attribute in targets
}
outcome = {
    "wrapped": wrapped,
    "wrapped_count": sum(wrapped.values()),
    "no_double_wrap": first_ids == second_ids,
    "gate_active": gate_active_before,
    "restored_count": restored_count,
    "identity": identity,
    "gate_inactive": not audit_hook.egress_gate_active(),
}
socket_send = originals["socket.send"]
with shield(GuardPolicy(enforce=True)):
    outcome["scoped_wrapped"] = socket.socket.send is not socket_send
outcome["scoped_restored"] = socket.socket.send is socket_send
print(json.dumps(outcome))
"""


def test_wrap_and_unwrap_restore_identities(project_root: Path, tmp_path: Path) -> None:
    _site_dir(tmp_path)
    payload = _run(project_root, _WRAP_SCRIPT)
    wrapped = payload["wrapped"]
    assert payload["gate_active"] is True
    # Seven callables are covered on Windows (socket.sendmsg does not exist there,
    # ssl.SSLSocket.sendmsg does) and eight on Linux where both sendmsg functions
    # exist as distinct objects.
    assert payload["wrapped_count"] >= 7
    for name in (
        "socket.send",
        "socket.sendall",
        "socket.sendto",
        "socket.sendfile",
        "ssl.send",
        "ssl.sendall",
        "ssl.sendmsg",
    ):
        assert wrapped[name] is True, name
    assert payload["restored_count"] == payload["wrapped_count"]
    assert all(payload["identity"].values())
    assert payload["gate_inactive"] is True
    assert payload["scoped_wrapped"] is True
    assert payload["scoped_restored"] is True


_LAZY_SSL_SCRIPT = """
import json, socket, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

assert "ssl" not in sys.modules
arm_shield(GuardPolicy(enforce=True), secret_files=("/nonexistent",))
outcome = {
    "ssl_absent_before": "ssl" not in sys.modules,
    "socket_wrapped": getattr(socket.socket.send, "__tauhaulity_egress_gate__", False),
    "gate_active": audit_hook.egress_gate_active(),
}
import ssl
outcome["ssl_after_import_wrapped"] = getattr(
    ssl.SSLSocket.send, "__tauhaulity_egress_gate__", False
)
print(json.dumps(outcome))
"""


def test_ssl_is_wrapped_only_when_already_imported(project_root: Path, tmp_path: Path) -> None:
    _site_dir(tmp_path)
    payload = _run(project_root, _LAZY_SSL_SCRIPT)
    assert payload["ssl_absent_before"] is True
    assert payload["socket_wrapped"] is True
    assert payload["gate_active"] is True
    assert payload["ssl_after_import_wrapped"] is False


_WINDOW_SCRIPT = """
import json, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield, register_secrets

port_text, secret_text, site_dir = sys.argv[1:4]
sys.path.insert(0, site_dir)
register_secrets([secret_text], label="window-token")
arm_shield(
    GuardPolicy(
        enforce=True,
        deny_third_party_connect=False,
        secret_redaction_bytes=32,
    ),
    secret_files=("/nonexistent",),
)
import evil_pkg

outcome = {"after_window_blocked": False, "inside_window_blocked": False}
try:
    evil_pkg.send_bytes("127.0.0.1", int(port_text), b"A" * 32 + secret_text.encode())
except PermissionError:
    outcome["after_window_blocked"] = True
try:
    evil_pkg.send_bytes("127.0.0.1", int(port_text), secret_text.encode() + b"B" * 32)
except PermissionError:
    outcome["inside_window_blocked"] = True
print(json.dumps(outcome))
"""


def test_redaction_window_bounds_the_inspection(
    project_root: Path, tmp_path: Path, receiver: _Receiver
) -> None:
    site = _site_dir(tmp_path)
    payload = _run(project_root, _WINDOW_SCRIPT, str(receiver.port), _SECRET, str(site))
    assert payload["after_window_blocked"] is False, "bytes past the window are not inspected"
    assert payload["inside_window_blocked"] is True


_SECRET_FILE_SCRIPT = """
import json, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

mode, port_text, secret_text, file_path, site_dir = sys.argv[1:6]
sys.path.insert(0, site_dir)
policy = GuardPolicy(enforce=True, deny_third_party_connect=False)
if mode == "explicit":
    arm_shield(policy, secret_files=(file_path,))
elif mode == "env":
    arm_shield(policy)
else:
    arm_shield(policy, secret_files=("/nonexistent",))
import evil_pkg

outcome = {"blocked": False, "message": "", "registry": audit_hook.stats()["secret_registry_size"]}
try:
    evil_pkg.send_secret("127.0.0.1", int(port_text), secret_text)
except PermissionError as exc:
    outcome["blocked"] = True
    outcome["message"] = str(exc)
print(json.dumps(outcome))
"""


def test_explicit_secret_file_is_honoured(
    project_root: Path, tmp_path: Path, receiver: _Receiver
) -> None:
    site = _site_dir(tmp_path)
    secret_file = tmp_path / "credentials.env"
    secret_file.write_text(f"API_TOKEN={_SECRET}\n", encoding="utf-8")
    payload = _run(
        project_root,
        _SECRET_FILE_SCRIPT,
        "explicit",
        str(receiver.port),
        _SECRET,
        str(secret_file),
        str(site),
    )
    assert payload["blocked"] is True
    assert payload["registry"] == 1


def test_env_secret_files_are_honoured(
    project_root: Path, tmp_path: Path, receiver: _Receiver
) -> None:
    site = _site_dir(tmp_path)
    secret_file = tmp_path / "env-secrets.txt"
    secret_file.write_text(f"TOKEN={_SECRET}\n", encoding="utf-8")
    payload = _run(
        project_root,
        _SECRET_FILE_SCRIPT,
        "env",
        str(receiver.port),
        _SECRET,
        str(secret_file),
        str(site),
        extra_env={"TAUHAULITY_EGRESS_SECRETS": str(secret_file)},
    )
    assert payload["blocked"] is True
    assert payload["registry"] == 1


def test_project_env_is_harvested_by_default(
    project_root: Path, tmp_path: Path, receiver: _Receiver
) -> None:
    site = _site_dir(tmp_path)
    project = tmp_path / "harvest-project"
    project.mkdir()
    (project / ".env").write_text(f"APP_SECRET={_SECRET}\nSHORT=abc\n", encoding="utf-8")
    script = """
import json, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield

port_text, secret_text, site_dir = sys.argv[1:4]
sys.path.insert(0, site_dir)
arm_shield(GuardPolicy(enforce=True, deny_third_party_connect=False))
import evil_pkg

outcome = {"blocked": False, "registry": audit_hook.stats()["secret_registry_size"]}
try:
    evil_pkg.send_secret("127.0.0.1", int(port_text), secret_text)
except PermissionError:
    outcome["blocked"] = True
print(json.dumps(outcome))
"""
    payload = _run(
        project_root,
        script,
        str(receiver.port),
        _SECRET,
        str(site),
        cwd=project,
    )
    assert payload["blocked"] is True
    assert payload["registry"] == 1


_OVERHEAD_SCRIPT = """
import json, socket, sys, threading, time
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield, register_secrets

register_secrets(
    ["sk-live-9f8A7b6C5d4E3f2G1h0I", "Qq11Ww22Ee33Rr44Zz55"], label="env"
)
arm_shield(
    GuardPolicy(enforce=True, deny_third_party_connect=False),
    secret_files=("/nonexistent",),
)
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(1)
port = listener.getsockname()[1]
received = []

def drain():
    connection, _address = listener.accept()
    try:
        while True:
            data = connection.recv(1 << 20)
            if not data:
                break
            received.append(len(data))
    finally:
        connection.close()

threading.Thread(target=drain, daemon=True).start()
client = socket.create_connection(("127.0.0.1", port))
small = b"GET /health HTTP/1.1\\r\\nHost: api.example.test\\r\\n\\r\\n"
for _ in range(100):
    client.sendall(small)
loops = 10000
started = time.perf_counter()
for _ in range(loops):
    client.sendall(small)
small_elapsed = time.perf_counter() - started
large = b"x" * (1024 * 1024)
started = time.perf_counter()
client.sendall(large)
large_elapsed = time.perf_counter() - started
client.shutdown(socket.SHUT_WR)
client.close()
deadline = time.monotonic() + 15.0
while sum(received) < loops * len(small) + len(large) and time.monotonic() < deadline:
    time.sleep(0.01)
print(json.dumps({
    "small_loops": loops,
    "small_elapsed": small_elapsed,
    "us_per_small_send": small_elapsed / loops * 1e6,
    "large_elapsed": large_elapsed,
    "large_bytes": len(large),
    "received": sum(received),
    "expected": (loops + 100) * len(small) + len(large),
    "denials": len(audit_hook.denials(4)),
}))
"""

#: Documented ceilings on the shared build host. The measured values in the phase
#: report are far below these; the bounds only guard against an accidental
#: full-buffer copy or a scan inside the send loop.
SMALL_SEND_COST_BOUND_S = 5.0
LARGE_SEND_COST_BOUND_S = 1.0


def test_send_overhead_stays_bounded(project_root: Path, tmp_path: Path) -> None:
    _site_dir(tmp_path)
    payload = _run(project_root, _OVERHEAD_SCRIPT)
    assert payload["small_loops"] == 10000
    assert payload["denials"] == 0
    assert payload["received"] == payload["expected"]
    assert payload["small_elapsed"] < SMALL_SEND_COST_BOUND_S, (
        f"10,000 small sends took {payload['small_elapsed']:.3f}s, bound is "
        f"{SMALL_SEND_COST_BOUND_S:.1f}s"
    )
    assert payload["large_elapsed"] < LARGE_SEND_COST_BOUND_S, (
        f"a 1 MiB send took {payload['large_elapsed']:.3f}s, bound is "
        f"{LARGE_SEND_COST_BOUND_S:.1f}s"
    )



_SENDMSG_SCRIPT = """
import json, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield, register_secrets

mode, port_text, secret_text, site_dir = sys.argv[1:5]
sys.path.insert(0, site_dir)
register_secrets([secret_text], label="prod-token")
arm_shield(
    GuardPolicy(enforce=True, deny_third_party_connect=False),
    secret_files=("/nonexistent",),
)
import evil_pkg

halfway = len(secret_text) // 2
buffers = {
    "second": [b"Authorization: Bearer ", secret_text.encode()],
    "benign": [b"GET /health HTTP/1.1\\r\\n", b"Host: api.example.test\\r\\n\\r\\n"],
    "split_entries": [secret_text[:halfway].encode(), secret_text[halfway:].encode()],
}[mode]
outcome = {"blocked": False, "message": "", "denials": []}
try:
    evil_pkg.sendmsg_buffers("127.0.0.1", int(port_text), buffers)
except PermissionError as exc:
    outcome["blocked"] = True
    outcome["message"] = str(exc)
outcome["denials"] = audit_hook.denials(8)
print(json.dumps(outcome))
"""

SENDMSG_UNAVAILABLE = not hasattr(socket.socket, "sendmsg")


@pytest.mark.skipif(SENDMSG_UNAVAILABLE, reason="socket.sendmsg is not available on this platform")
def test_sendmsg_secret_in_second_buffer_is_denied(
    project_root: Path, tmp_path: Path, receiver: _Receiver
) -> None:
    site = _site_dir(tmp_path)
    payload = _run(
        project_root, _SENDMSG_SCRIPT, "second", str(receiver.port), _SECRET, str(site)
    )
    assert payload["blocked"] is True
    message = str(payload["message"])
    assert "socket.sendmsg" in message
    assert f"label '{_SECRET_LABEL}'" in message
    assert "byte offset 22" in message
    assert "deny_egress_with_secrets" in message
    denial = payload["denials"][0]
    assert denial["kind"] == "secret_egress"
    assert denial["offset"] == 22
    assert denial["label"] == _SECRET_LABEL
    assert _SECRET not in json.dumps(payload)
    assert receiver.wait_for(1, timeout=1.0) == b""


@pytest.mark.skipif(SENDMSG_UNAVAILABLE, reason="socket.sendmsg is not available on this platform")
def test_sendmsg_benign_buffers_are_sent(
    project_root: Path, tmp_path: Path, receiver: _Receiver
) -> None:
    site = _site_dir(tmp_path)
    payload = _run(
        project_root, _SENDMSG_SCRIPT, "benign", str(receiver.port), _SECRET, str(site)
    )
    assert payload["blocked"] is False
    assert payload["denials"] == []
    expected = b"GET /health HTTP/1.1\r\nHost: api.example.test\r\n\r\n"
    assert receiver.wait_for(len(expected)) == expected


@pytest.mark.skipif(SENDMSG_UNAVAILABLE, reason="socket.sendmsg is not available on this platform")
def test_sendmsg_secret_split_across_entries_is_caught(
    project_root: Path, tmp_path: Path, receiver: _Receiver
) -> None:
    site = _site_dir(tmp_path)
    payload = _run(
        project_root, _SENDMSG_SCRIPT, "split_entries", str(receiver.port), _SECRET, str(site)
    )
    # The concatenation of the buffers inside one sendmsg call contains the full
    # secret, so the call is refused even though no single buffer does.
    assert payload["blocked"] is True
    denial = payload["denials"][0]
    assert denial["offset"] == 0
    assert denial["label"] == _SECRET_LABEL
    assert receiver.wait_for(1, timeout=1.0) == b""


_SENDFILE_SCRIPT = """
import json, sys
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield, register_secrets

mode, port_text, secret_text, site_dir, file_path = sys.argv[1:6]
sys.path.insert(0, site_dir)
register_secrets([secret_text], label="prod-token")
arm_shield(
    GuardPolicy(enforce=True, deny_third_party_connect=False),
    secret_files=("/nonexistent",),
)
import evil_pkg

outcome = {"blocked": False, "message": "", "denials": []}
try:
    evil_pkg.sendfile_path("127.0.0.1", int(port_text), file_path)
except PermissionError as exc:
    outcome["blocked"] = True
    outcome["message"] = str(exc)
outcome["denials"] = audit_hook.denials(8)
print(json.dumps(outcome))
"""

SENDFILE_UNAVAILABLE = not hasattr(socket.socket, "sendfile")


@pytest.mark.skipif(SENDFILE_UNAVAILABLE, reason="socket.sendfile is not available on this platform")
def test_sendfile_of_a_secret_bearing_file_is_denied(
    project_root: Path, tmp_path: Path, receiver: _Receiver
) -> None:
    site = _site_dir(tmp_path)
    source = tmp_path / "model.bin"
    source.write_bytes(b"PREFIX" + _SECRET.encode() + b"SUFFIX")
    payload = _run(
        project_root,
        _SENDFILE_SCRIPT,
        "secret",
        str(receiver.port),
        _SECRET,
        str(site),
        str(source),
    )
    assert payload["blocked"] is True
    message = str(payload["message"])
    assert "socket.sendfile" in message
    assert f"label '{_SECRET_LABEL}'" in message
    assert "byte offset 6" in message
    denial = payload["denials"][0]
    assert denial["kind"] == "secret_egress"
    assert denial["offset"] == 6
    assert denial["call"] == "socket.sendfile"
    assert denial["source"] == str(source)
    assert _SECRET not in json.dumps(payload)
    assert receiver.wait_for(1, timeout=1.0) == b""


@pytest.mark.skipif(SENDFILE_UNAVAILABLE, reason="socket.sendfile is not available on this platform")
def test_sendfile_of_a_benign_file_is_sent(
    project_root: Path, tmp_path: Path, receiver: _Receiver
) -> None:
    site = _site_dir(tmp_path)
    source = tmp_path / "image.bin"
    content = b"x" * 4096
    source.write_bytes(content)
    payload = _run(
        project_root,
        _SENDFILE_SCRIPT,
        "benign",
        str(receiver.port),
        _SECRET,
        str(site),
        str(source),
    )
    assert payload["blocked"] is False
    assert payload["denials"] == []
    received = receiver.wait_for(len(content))
    assert received == content


_SENDMSG_OVERHEAD_SCRIPT = """
import json, socket, sys, threading, time
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield, register_secrets

if not hasattr(socket.socket, "sendmsg"):
    print(json.dumps({"available": False}))
    raise SystemExit(0)
register_secrets(
    ["sk-live-9f8A7b6C5d4E3f2G1h0I", "Qq11Ww22Ee33Rr44Zz55"], label="env"
)
arm_shield(
    GuardPolicy(enforce=True, deny_third_party_connect=False),
    secret_files=("/nonexistent",),
)
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(1)
port = listener.getsockname()[1]
received = []

def drain():
    connection, _address = listener.accept()
    try:
        while True:
            data = connection.recv(1 << 20)
            if not data:
                break
            received.append(len(data))
    finally:
        connection.close()

threading.Thread(target=drain, daemon=True).start()
client = socket.create_connection(("127.0.0.1", port))
parts = [b"GET /health HTTP/1.1\\r\\n", b"Host: api.example.test\\r\\n\\r\\n"]
for _ in range(100):
    client.sendmsg(parts)
loops = 10000
started = time.perf_counter()
for _ in range(loops):
    client.sendmsg(parts)
elapsed = time.perf_counter() - started
client.shutdown(socket.SHUT_WR)
client.close()
expected = (loops + 100) * sum(len(part) for part in parts)
deadline = time.monotonic() + 15.0
while sum(received) < expected and time.monotonic() < deadline:
    time.sleep(0.01)
print(json.dumps({
    "available": True,
    "loops": loops,
    "elapsed": elapsed,
    "us_per_sendmsg": elapsed / loops * 1e6,
    "received": sum(received),
    "expected": expected,
    "denials": len(audit_hook.denials(4)),
}))
"""

SENDMSG_COST_BOUND_S = 5.0


@pytest.mark.skipif(SENDMSG_UNAVAILABLE, reason="socket.sendmsg is not available on this platform")
def test_sendmsg_overhead_stays_bounded(project_root: Path, tmp_path: Path) -> None:
    _site_dir(tmp_path)
    payload = _run(project_root, _SENDMSG_OVERHEAD_SCRIPT)
    assert payload["available"] is True
    assert payload["loops"] == 10000
    assert payload["denials"] == 0
    assert payload["received"] == payload["expected"]
    assert payload["elapsed"] < SENDMSG_COST_BOUND_S, (
        f"10,000 sendmsg calls took {payload['elapsed']:.3f}s, bound is "
        f"{SENDMSG_COST_BOUND_S:.1f}s"
    )


_SENDFILE_OVERHEAD_SCRIPT = """
import json, os, socket, sys, tempfile, threading, time
from tauhaulity.runtime import audit_hook
from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield, register_secrets

if not hasattr(socket.socket, "sendfile"):
    print(json.dumps({"available": False}))
    raise SystemExit(0)
register_secrets(
    ["sk-live-9f8A7b6C5d4E3f2G1h0I", "Qq11Ww22Ee33Rr44Zz55"], label="env"
)
arm_shield(
    GuardPolicy(enforce=True, deny_third_party_connect=False),
    secret_files=("/nonexistent",),
)
root = tempfile.mkdtemp(prefix="tauhaulity-sendfile-overhead-")
small_path = os.path.join(root, "small.bin")
large_path = os.path.join(root, "large.bin")
with open(small_path, "wb") as handle:
    handle.write(b"x" * 4096)
with open(large_path, "wb") as handle:
    handle.write(b"x" * (1024 * 1024))
listener = socket.socket()
listener.bind(("127.0.0.1", 0))
listener.listen(1)
port = listener.getsockname()[1]
received = []

def drain():
    connection, _address = listener.accept()
    try:
        while True:
            data = connection.recv(1 << 20)
            if not data:
                break
            received.append(len(data))
    finally:
        connection.close()

threading.Thread(target=drain, daemon=True).start()
client = socket.create_connection(("127.0.0.1", port))
procedure = 1000
with open(small_path, "rb") as handle:
    for _ in range(10):
        handle.seek(0)
        client.sendfile(handle)
started = time.perf_counter()
with open(small_path, "rb") as handle:
    for _ in range(procedure):
        handle.seek(0)
        client.sendfile(handle)
small_elapsed = time.perf_counter() - started
started = time.perf_counter()
with open(large_path, "rb") as handle:
    client.sendfile(handle)
large_elapsed = time.perf_counter() - started
client.shutdown(socket.SHUT_WR)
client.close()
expected = (procedure + 10) * 4096 + (1024 * 1024)
deadline = time.monotonic() + 20.0
while sum(received) < expected and time.monotonic() < deadline:
    time.sleep(0.01)
print(json.dumps({
    "available": True,
    "procedure": procedure,
    "small_elapsed": small_elapsed,
    "us_per_small_sendfile": small_elapsed / procedure * 1e6,
    "large_elapsed": large_elapsed,
    "received": sum(received),
    "expected": expected,
    "denials": len(audit_hook.denials(4)),
}))
"""

SENDFILE_SMALL_CALLS_BOUND_S = 3.0
SENDFILE_LARGE_CALL_BOUND_S = 1.0


@pytest.mark.skipif(SENDFILE_UNAVAILABLE, reason="socket.sendfile is not available on this platform")
def test_sendfile_overhead_stays_bounded(project_root: Path, tmp_path: Path) -> None:
    _site_dir(tmp_path)
    payload = _run(project_root, _SENDFILE_OVERHEAD_SCRIPT)
    assert payload["available"] is True
    assert payload["denials"] == 0
    assert payload["received"] == payload["expected"]
    assert payload["small_elapsed"] < SENDFILE_SMALL_CALLS_BOUND_S, (
        f"1,000 small sendfile calls took {payload['small_elapsed']:.3f}s, bound is "
        f"{SENDFILE_SMALL_CALLS_BOUND_S:.1f}s"
    )
    assert payload["large_elapsed"] < SENDFILE_LARGE_CALL_BOUND_S, (
        f"one 1 MiB sendfile took {payload['large_elapsed']:.3f}s, bound is "
        f"{SENDFILE_LARGE_CALL_BOUND_S:.1f}s"
    )


# ---------------------------------------------------------------------------
# Registry, harvest and policy model (in-process: no hook is installed)
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_registry():
    audit_hook.clear_secrets()
    yield
    audit_hook.clear_secrets()


def test_register_and_clear_secrets() -> None:
    assert audit_hook.register_secrets([_SECRET], label="env") == 1
    assert audit_hook.register_secrets([_SECRET], label="other") == 1
    assert audit_hook.register_secrets(["", _OTHER_SECRET], label="env") == 2
    assert audit_hook.stats()["secret_registry_size"] == 2
    assert audit_hook.clear_secrets() == 2
    assert audit_hook.stats()["secret_registry_size"] == 0
    with pytest.raises(TypeError):
        audit_hook.register_secrets([123])


def test_harvest_secrets_finds_credentials_and_skips_weak_values(tmp_path: Path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    strong_a = "Abc123!@#xyzLongToken"
    strong_b = "Zx9$Qw8!Er7@Ty6"
    (root / ".env").write_text(
        "PLAIN_WORD=onlylowercase\n"
        "SHORT=abc123\n"
        "SPACED=has space value123\n"
        "SYMBOLS=!@#$%^&*()_+=\n"
        "TOKEN=" + strong_a + "\n"
        "EMPTY=\n"
        "# comment line\n",
        encoding="utf-8",
    )
    (root / ".env.local").write_text(
        "API=" + strong_b + "\nexport OTHER=Qq11Ww22Ee33Rr44\n", encoding="utf-8"
    )
    assert audit_hook.harvest_secrets(root) == 3
    assert audit_hook.stats()["secret_registry_size"] == 3
    serialized = json.dumps(
        {
            "stats": audit_hook.stats(),
            "events": audit_hook.events(16),
            "denials": audit_hook.denials(16),
        }
    )
    for value in (strong_a, strong_b, "Qq11Ww22Ee33Rr44", "onlylowercase"):
        assert value not in serialized
    assert audit_hook.clear_secrets() == 3


def test_harvest_of_a_missing_directory_is_quiet(tmp_path: Path) -> None:
    assert audit_hook.harvest_secrets(tmp_path / "absent") == 0


def test_policy_egress_fields(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TAUHAULITY_DENY_SECRET_EGRESS", raising=False)
    default = GuardPolicy()
    assert default.deny_egress_with_secrets is True
    assert default.secret_redaction_bytes == 0
    assert default.as_dict()["deny_egress_with_secrets"] is True
    monkeypatch.setenv("TAUHAULITY_DENY_SECRET_EGRESS", "0")
    assert GuardPolicy.from_env().deny_egress_with_secrets is False
    with pytest.raises(ValueError):
        GuardPolicy(secret_redaction_bytes=-1)
    assert GuardPolicy(secret_redaction_bytes=1024).as_dict()["secret_redaction_bytes"] == 1024


def test_secret_egress_message_is_exact() -> None:
    message = audit_hook._secret_egress_message(
        "socket.sendall", "prod-token", 22, "('127.0.0.1', 5000)", "deny_egress_with_secrets"
    )
    assert message == (
        "Tauhaulity policy: secret egress blocked: label 'prod-token' matched at byte "
        "offset 22 for socket.sendall to ('127.0.0.1', 5000) by deny_egress_with_secrets"
    )


def test_runtime_package_reexports_egress_api() -> None:
    from tauhaulity import runtime

    assert runtime.register_secrets is audit_hook.register_secrets
    assert runtime.clear_secrets is audit_hook.clear_secrets
    assert runtime.harvest_secrets is audit_hook.harvest_secrets
    assert runtime.unpatch_egress is audit_hook.unpatch_egress
    assert runtime.egress_gate_active is audit_hook.egress_gate_active