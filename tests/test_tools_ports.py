"""Tests for socket enumeration and bounded port reaping.

The real kernel table is read (read only) to prove the fallback works, but every
mutating path is exercised with injected data: a test suite must never terminate
a process, and free_port is the only function that can.
"""

from __future__ import annotations

import os
import socket

import pytest

import tauhaulity.tools.port_sweeper as sweeper
from tauhaulity.tools.port_sweeper import (
    PortEntry,
    PortFreeResult,
    PortOwner,
    backend_name,
    conflicting_ports,
    find_port_owners,
    free_port,
    list_listening,
    zombie_entries,
)


def test_list_listening_returns_sorted_port_entries() -> None:
    entries = list_listening()
    assert isinstance(entries, list)
    assert all(isinstance(entry, PortEntry) for entry in entries)
    assert entries == sorted(entries, key=lambda item: (item.port, item.protocol, item.pid))
    for entry in entries[:8]:
        assert 0 < entry.port < 65536
        assert entry.local_port == entry.port
        assert entry.is_listening is True
        assert entry.state == "LISTEN"
        assert ":" in entry.endpoint


def test_backend_name_is_a_known_backend() -> None:
    assert backend_name() in {"windows-iphlpapi", "procfs", "unsupported"}


def test_find_port_owners_validates_the_port() -> None:
    with pytest.raises(ValueError):
        find_port_owners(0)
    with pytest.raises(ValueError):
        find_port_owners(70000)


def test_find_port_owners_returns_owner_records() -> None:
    owners = find_port_owners(1)
    assert all(isinstance(owner, PortOwner) for owner in owners)
    assert all(owner.protocol in {"tcp", "tcp6"} for owner in owners)


def test_free_port_reports_an_unbound_port() -> None:
    result = free_port(1, dry_run=True)
    assert isinstance(result, PortFreeResult)
    assert result.killed == []
    assert isinstance(result.message, str)


def test_free_port_validates_the_port() -> None:
    with pytest.raises(ValueError):
        free_port(0)


def test_engine_rows_are_coerced_and_filtered(monkeypatch: pytest.MonkeyPatch) -> None:
    class EngineRow:
        protocol = "tcp"
        local_address = "0.0.0.0"
        local_port = 8123
        pid = 4242
        state = "LISTEN"

    class EstablishedRow:
        protocol = "tcp"
        local_address = "127.0.0.1"
        local_port = 8124
        pid = 4243
        state = "ESTABLISHED"

    monkeypatch.setattr(sweeper, "_engine_entries", lambda: [EngineRow(), EstablishedRow()])
    entries = list_listening()
    assert [entry.port for entry in entries] == [8123]
    assert entries[0].pid == 4242
    assert entries[0].protocol == "tcp"
    assert sweeper.uncoerced_rows() == 1


def test_simple_port_pid_rows_are_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    class SimpleRow:
        port = 7001
        pid = 42

    monkeypatch.setattr(sweeper, "_engine_entries", lambda: [SimpleRow()])
    entries = list_listening()
    assert [(entry.port, entry.pid) for entry in entries] == [(7001, 42)]
    assert entries[0].state == "LISTEN"
    assert entries[0].protocol == "tcp"
    assert sweeper.uncoerced_rows() == 0


def test_malformed_rows_are_counted_not_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    class Malformed:
        port = "not-a-number"
        pid = 1

    monkeypatch.setattr(sweeper, "_engine_entries", lambda: [Malformed()])
    assert list_listening() == []
    assert sweeper.uncoerced_rows() == 1


def test_engine_pid_none_becomes_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    class Row:
        protocol = "tcp6"
        local_address = "::"
        local_port = 9000
        pid = None
        state = "LISTEN"

    monkeypatch.setattr(sweeper, "_engine_entries", lambda: [Row()])
    entries = list_listening()
    assert entries[0].pid == 0
    assert entries[0].protocol == "tcp6"


def test_empty_engine_result_falls_back_to_the_kernel(monkeypatch: pytest.MonkeyPatch) -> None:
    fallback = [PortEntry(65001, "tcp", 1, "fallback")]
    monkeypatch.setattr(sweeper, "_engine_entries", lambda: [])
    if os.name == "nt":
        monkeypatch.setattr(sweeper, "_windows_entries", lambda: fallback)
    else:
        monkeypatch.setattr(sweeper, "_linux_entries", lambda: fallback)
    assert list_listening() == fallback


def test_conflicting_ports_only_report_multiple_owners() -> None:
    entries = [
        PortEntry(3000, "tcp", 111, "alpha"),
        PortEntry(3000, "tcp", 222, "beta"),
        PortEntry(8000, "tcp", 333, "gamma"),
        PortEntry(9999, "tcp", 444, "delta"),
    ]
    conflicts = conflicting_ports(entries)
    assert set(conflicts) == {3000}
    assert len(conflicts[3000]) == 2


def test_conflicting_ports_ignores_dual_stack_single_owner() -> None:
    entries = [
        PortEntry(3000, "tcp", 111, "alpha"),
        PortEntry(3000, "tcp6", 111, "alpha"),
    ]
    assert conflicting_ports(entries) == {}


def test_zombie_entries_flags_dead_owners(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sweeper, "_process_alive", lambda pid: False)
    monkeypatch.setattr(sweeper, "_is_defunct", lambda pid: False)
    entries = [
        PortEntry(3000, "tcp", 1234, "stale"),
        PortEntry(3001, "tcp", 0, "unknown"),
    ]
    zombies = zombie_entries(entries)
    assert [entry.pid for entry in zombies] == [1234]


def test_zombie_entries_ignores_live_and_unknown_owners(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sweeper, "_process_alive", lambda pid: True)
    monkeypatch.setattr(sweeper, "_is_defunct", lambda pid: False)
    entries = [PortEntry(3000, "tcp", 4321, "alive"), PortEntry(3001, "tcp", 0, "unknown")]
    assert zombie_entries(entries) == []


def test_free_port_refuses_to_kill_the_current_process(monkeypatch: pytest.MonkeyPatch) -> None:
    own = os.getpid()
    calls: list[tuple[str, int]] = []
    monkeypatch.setattr(
        sweeper, "find_port_owners", lambda port: [PortOwner(port, own, "pytest", "tcp")]
    )
    monkeypatch.setattr(
        sweeper, "_terminate_graceful", lambda pid: calls.append(("graceful", pid)) or True
    )
    monkeypatch.setattr(
        sweeper, "_terminate_force", lambda pid: calls.append(("forced", pid)) or True
    )
    result = free_port(4242)
    assert calls == []
    assert result.killed == []
    assert result.released is False
    assert str(own) in result.message


def test_free_port_respects_dry_run(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[int] = []
    monkeypatch.setattr(
        sweeper, "find_port_owners", lambda port: [PortOwner(port, 987654, "victim", "tcp")]
    )
    monkeypatch.setattr(
        sweeper, "_terminate_graceful", lambda pid: calls.append(pid) or True
    )
    result = free_port(4243, dry_run=True)
    assert calls == []
    assert result.killed == []
    assert "dry run" in result.message


def test_free_port_reports_successful_reaping(monkeypatch: pytest.MonkeyPatch) -> None:
    state = {"alive": True}

    def fake_owners(port: int) -> list[PortOwner]:
        return [PortOwner(port, 987654, "victim", "tcp")] if state["alive"] else []

    def fake_graceful(pid: int) -> bool:
        state["alive"] = False
        return True

    monkeypatch.setattr(sweeper, "find_port_owners", fake_owners)
    monkeypatch.setattr(sweeper, "_process_alive", lambda pid: state["alive"])
    monkeypatch.setattr(sweeper, "_terminate_graceful", fake_graceful)
    result = free_port(4244, force_after_ms=10)
    assert result.released is True
    assert result.killed == [987654]
    assert "released" in result.message


def test_bound_socket_is_enumerated_without_being_touched() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        entries = [entry for entry in list_listening() if entry.port == port]
        if not entries:
            pytest.skip("kernel socket table is unavailable on this host")
        assert any(entry.pid == os.getpid() for entry in entries) or all(
            entry.pid == 0 for entry in entries
        )
        result = free_port(port, dry_run=True)
        assert result.killed == []
        assert result.released is False
        assert server.fileno() != -1
    finally:
        server.close()
