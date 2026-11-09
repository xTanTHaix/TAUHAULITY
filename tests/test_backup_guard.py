"""Tests for the backup destruction guard and its pillar eight wiring.

The classifier is the security relevant part: a missed shape is a silent early
warning, and a false positive on a routine admin command makes the warning
useless. The table below therefore covers every recognised shape, a representative
benign command per family and malformed input, and the observer test runs in a
fresh interpreter because an audit hook cannot be removed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tauhaulity.tools import backup_guard
from tauhaulity.tools.backup_guard import (
    BACKUP_DELETE,
    RECOVERY_DISABLE,
    RESTORE_POINT_QUERY,
    SHADOW_DELETE,
    BackupSignal,
    attach_to_guard,
    detected_signals,
    inspect_command,
    reset_restore_cache,
    restore_points_present,
)

_DESTRUCTIVE_SHAPES: tuple[tuple[tuple[str, ...], str, str], ...] = (
    (("vssadmin", "delete", "shadows", "/all", "/quiet"), SHADOW_DELETE, "high"),
    (("vssadmin.exe", "Delete", "Shadows", "/for=C:"), SHADOW_DELETE, "high"),
    (("wmic", "shadowcopy", "delete"), SHADOW_DELETE, "high"),
    (("wbadmin", "delete", "catalog", "-quiet"), BACKUP_DELETE, "high"),
    (("wbadmin", "delete", "systemstatebackup", "-deleteOldest"), BACKUP_DELETE, "high"),
    (("bcdedit", "/set", "{default}", "recoveryenabled", "No"), RECOVERY_DISABLE, "high"),
    (
        ("bcdedit", "/set", "{default}", "bootstatuspolicy", "ignoreallfailures"),
        RECOVERY_DISABLE,
        "high",
    ),
    (("wevtutil", "cl", "System"), RECOVERY_DISABLE, "medium"),
    (("rm", "-rf", "/var/lib/lxc/snapshots"), BACKUP_DELETE, "high"),
    (("rm", "-rf", "data/.snapshot"), BACKUP_DELETE, "high"),
    (("lvremove", "-f", "/dev/vg0/snap_2024"), BACKUP_DELETE, "high"),
    (("zfs", "destroy", "tank/data@backup-1"), BACKUP_DELETE, "high"),
    (("btrfs", "subvolume", "delete", "/mnt/.snapshots/1"), BACKUP_DELETE, "high"),
    (("systemctl", "stop", "restic-backup.service"), RECOVERY_DISABLE, "high"),
)

_QUERY_SHAPES: tuple[tuple[str, ...], ...] = (
    ("vssadmin", "list", "shadows"),
    ("wmic", "shadowcopy", "list", "brief"),
    ("zfs", "list", "-t", "snapshot"),
)

_BENIGN_COMMANDS: tuple[tuple[str, ...], ...] = (
    ("vssadmin", "list", "writers"),
    ("vssadmin", "list", "volumes"),
    ("wbadmin", "start", "backup", "-backupTarget:D:"),
    ("bcdedit", "/enum"),
    ("bcdedit", "/set", "{default}", "recoveryenabled", "Yes"),
    ("wevtutil", "qe", "System"),
    ("git", "checkout", "--", "."),
    ("npm", "ci"),
    ("python", "-m", "pip", "install", "-r", "requirements.txt"),
    ("cargo", "build", "--release"),
    ("tar", "-xzf", "archive.tar.gz"),
    ("rm", "-rf", "build"),
    ("rm", "-rf", "dist"),
    ("systemctl", "stop", "nginx.service"),
    ("zfs", "list"),
    ("lvcreate", "-L", "1G", "-s", "/dev/vg0/base", "-n", "snap01"),
)


@pytest.mark.parametrize("argv,kind,severity", _DESTRUCTIVE_SHAPES)
def test_destructive_shapes_are_classified(
    argv: tuple[str, ...], kind: str, severity: str
) -> None:
    signal = inspect_command(list(argv))
    assert isinstance(signal, BackupSignal)
    assert signal.kind == kind
    assert signal.severity == severity
    assert signal.command and signal.detail
    assert len(signal.command) <= 200
    assert any(token in signal.command for token in argv)


@pytest.mark.parametrize("argv", _QUERY_SHAPES)
def test_restore_point_queries_are_low_severity(argv: tuple[str, ...]) -> None:
    signal = inspect_command(list(argv))
    assert isinstance(signal, BackupSignal)
    assert signal.kind == RESTORE_POINT_QUERY
    assert signal.severity == "low"


@pytest.mark.parametrize("argv", _BENIGN_COMMANDS)
def test_benign_commands_yield_no_signal(argv: tuple[str, ...]) -> None:
    assert inspect_command(list(argv)) is None


def test_shell_wrappers_are_unwrapped() -> None:
    assert inspect_command(["/bin/sh", "-c", "vssadmin delete shadows /all"]).kind == SHADOW_DELETE
    assert (
        inspect_command(["powershell", "-Command", "bcdedit /set {default} recoveryenabled no"]).kind
        == RECOVERY_DISABLE
    )
    assert inspect_command(["/bin/sh", "-c", "echo hello"]) is None
    assert inspect_command(["cmd", "/c", "wevtutil cl System"]).kind == RECOVERY_DISABLE


def test_encoded_powershell_is_not_decoded() -> None:
    # Decoding an encoded command here would create an evasion surface of its own;
    # the guard already records the spawn event for the analyst.
    assert inspect_command(["powershell", "-EncodedCommand", "dgBzAHMAYQBkAG0AaQBuAA=="]) is None


def test_command_string_input_is_tokenized() -> None:
    signal = inspect_command("vssadmin delete shadows /all")
    assert signal is not None and signal.kind == SHADOW_DELETE


def test_mismatched_shapes_are_not_guessed() -> None:
    assert inspect_command(["vssadmin", "delete", "writers"]) is None
    assert inspect_command(["wmic", "process", "delete"]) is None
    assert inspect_command(["bcdedit", "/set", "{default}", "safeboot", "minimal"]) is None
    assert inspect_command(["rm", "-rf", "backup-notes"]) is None
    assert inspect_command(["systemctl", "start", "restic-backup.service"]) is None


def test_odd_input_never_raises() -> None:
    odd_inputs = (
        None,
        [],
        ["vssadmin"],
        b"vssadmin delete shadows",
        "vssadmin delete shadows",
        42,
        {"cmd": "vssadmin delete shadows"},
        [["vssadmin", "delete", "shadows"]],
        [b"vssadmin", b"delete", b"shadows"],
        ["vssadmin", 42],
        "",
        (),
    )
    for value in odd_inputs:
        signal = inspect_command(value)
        assert signal is None or isinstance(signal, BackupSignal)


def test_signal_dataclass_is_frozen_and_stable() -> None:
    first = inspect_command(["vssadmin", "delete", "shadows"])
    second = inspect_command(["vssadmin", "delete", "shadows"])
    assert first == second
    assert first is not None
    with pytest.raises(Exception):
        first.kind = "tampered"  # type: ignore[misc]


def test_restore_points_present_returns_a_typed_answer() -> None:
    reset_restore_cache()
    try:
        value, reason = restore_points_present()
        assert value in (True, False, None)
        assert isinstance(reason, str) and reason
        assert restore_points_present() == (value, reason)
    finally:
        reset_restore_cache()


def test_restore_points_present_degrades_when_no_tool_is_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_restore_cache()
    monkeypatch.setattr(backup_guard.shutil, "which", lambda name: None)
    try:
        value, reason = restore_points_present()
        assert value is None
        assert "not available" in reason or "no snapshot tool" in reason
    finally:
        reset_restore_cache()


def test_restore_points_present_reports_a_timeout_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reset_restore_cache()
    monkeypatch.setattr(backup_guard.shutil, "which", lambda name: "tools/" + name)
    monkeypatch.setattr(backup_guard, "_run_readonly", lambda args: None)
    try:
        value, reason = restore_points_present()
        assert value is None
        assert "did not answer" in reason
    finally:
        reset_restore_cache()


_ATTACH_SCRIPT = """
import json, subprocess, sys
from tauhaulity.tools import backup_guard

seen = []
armed = backup_guard.attach_to_guard(seen.append)
armed_again = backup_guard.attach_to_guard()
benign = subprocess.run(
    [sys.executable, "-c", "pass"], capture_output=True, text=True, timeout=60
)
# Execute Python with an argv that looks like a destructive admin command: the
# audit event fires before the spawn, so the observer sees the shape while no
# backup command is ever executed.
spawned = subprocess.run(
    ["vssadmin", "delete", "shadows", "/all", "/quiet"],
    executable=sys.executable,
    capture_output=True,
    text=True,
    timeout=60,
)
payload = {
    "armed": armed,
    "armed_again": armed_again,
    "recorded": [
        [signal.kind, signal.severity] for signal in backup_guard.detected_signals(8)
    ],
    "callbacks": [signal.kind for signal in seen],
    "benign_code": benign.returncode,
    "spawned_code": spawned.returncode,
    "empty_ring": backup_guard.detected_signals(0),
}
print(json.dumps(payload))
"""


def _run_attach_script(project_root: Path) -> dict:
    env = os.environ.copy()
    env["TAUHAULITY_NO_AUTO"] = "1"
    env["PYTHONPATH"] = str(project_root) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    completed = subprocess.run(
        [sys.executable, "-c", _ATTACH_SCRIPT],
        cwd=str(project_root),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    lines = [line for line in completed.stdout.strip().splitlines() if line.strip()]
    assert lines, completed.stderr
    return json.loads(lines[-1])


def test_observer_records_a_destructive_spawn(project_root: Path) -> None:
    payload = _run_attach_script(project_root)
    assert payload["armed"] is True
    assert payload["armed_again"] is True
    assert payload["callbacks"] == [SHADOW_DELETE]
    assert payload["recorded"] == [[SHADOW_DELETE, "high"]]
    assert payload["benign_code"] == 0
    assert payload["spawned_code"] in (0, 1, 2)
    assert payload["empty_ring"] == []


def test_detected_signals_validates_the_limit() -> None:
    assert detected_signals(0) == []
    with pytest.raises(ValueError):
        detected_signals(-1)


def _context(root: Path):
    from tauhaulity.core.contracts import ScanContext, ScanOptions
    from tauhaulity.core.platform_probe import detect_platform
    from tauhaulity.core.policy import Policy

    return ScanContext(
        target=Path(root),
        platform=detect_platform(),
        policy=Policy(),
        options=ScanOptions(),
    )


def _p08_finding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    signals: list,
    restore: tuple[bool | None, str],
):
    from tauhaulity.pillars import p08_ransom

    monkeypatch.setattr(
        backup_guard, "detected_signals", lambda limit=16: list(signals)
    )
    monkeypatch.setattr(backup_guard, "restore_points_present", lambda: restore)
    root = tmp_path / "project"
    root.mkdir(parents=True, exist_ok=True)
    return p08_ransom.probe(_context(root))


def test_p08_warns_on_an_observed_backup_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from tauhaulity.pillars import p08_ransom

    signal = BackupSignal(
        SHADOW_DELETE,
        "vssadmin delete shadows /all /quiet",
        "high",
        "volume shadow copy deletion",
    )
    finding = _p08_finding(
        tmp_path, monkeypatch, signals=[signal], restore=(None, "not observable")
    )
    assert finding.status == "WARNING"
    assert "backup tampering shape observed" in finding.detail
    assert SHADOW_DELETE in finding.detail
    assert "vssadmin delete shadows" in finding.detail
    assert finding.slot("backup_signal") == SHADOW_DELETE
    assert 0.0 <= finding.risk <= p08_ransom.SPEC.risk_scale
    assert finding.repro_hint is not None


def test_p08_scales_the_risk_with_the_signal_severity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    low = BackupSignal(
        RESTORE_POINT_QUERY, "vssadmin list shadows", "low", "shadow copy enumeration"
    )
    finding = _p08_finding(
        tmp_path, monkeypatch, signals=[low], restore=(True, "vssadmin reports one shadow copy")
    )
    assert finding.status == "WARNING"
    assert finding.risk == 5.0


def test_p08_reports_an_unobservable_restore_point_state_as_such(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    finding = _p08_finding(
        tmp_path,
        monkeypatch,
        signals=[],
        restore=(None, "vssadmin requires administrator rights"),
    )
    assert finding.status == "PROTECTED"
    assert "could not observe" in finding.detail
    assert "vssadmin requires administrator rights" in finding.detail
    assert finding.slot("backup_signal") == "NONE"


def test_p08_states_present_and_absent_restore_points(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    present = _p08_finding(
        tmp_path / "present",
        monkeypatch,
        signals=[],
        restore=(True, "lvs reports 2 LVM snapshot(s)"),
    )
    assert present.status == "PROTECTED"
    assert "restore points: present" in present.detail

    absent = _p08_finding(
        tmp_path / "absent",
        monkeypatch,
        signals=[],
        restore=(False, "lvs reports no LVM snapshot"),
    )
    assert absent.status == "PROTECTED"
    assert "restore points: none visible" in absent.detail
