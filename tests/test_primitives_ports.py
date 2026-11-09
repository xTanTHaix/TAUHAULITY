"""Port table tests: kernel visibility, parsing parity and structural safety.

The kernel table must see a socket bound on 127.0.0.1 in the test process, must
never spawn netstat/lsof/ss, and the procfs parser must decode the byte-shuffled
address formats correctly even on Windows where /proc does not exist.
"""

from __future__ import annotations

import ctypes
import os
import socket
import subprocess

import pytest

from tauhaulity.primitives import loader, port_table
from tauhaulity.primitives.loader import PortEntry

PROCFS_HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode\n"
)
PROCFS_IPV4_LISTEN = (
    "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 "
    "00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0\n"
)


@pytest.fixture()
def engine():
    """Return a freshly constructed engine and drop the cache afterwards."""

    loader._reset_engine()
    built = loader.get_engine()
    try:
        yield built
    finally:
        loader._reset_engine()


@pytest.fixture()
def bound_socket():
    """Bind and listen on an ephemeral loopback port for the duration of a test."""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        yield sock, int(sock.getsockname()[1])
    finally:
        sock.close()


def test_port_table_sees_a_loopback_listener(engine, bound_socket) -> None:
    if port_table.platform_module() is None:
        pytest.skip("no kernel port table backend on this host")
    _sock, port = bound_socket
    entries = engine.port_table()
    assert isinstance(entries, list)
    matching = [entry for entry in entries if entry.local_port == port]
    assert matching, f"kernel table did not report the bound port {port}"
    assert any(entry.protocol.startswith("tcp") for entry in matching)
    assert any(entry.state == "LISTEN" for entry in matching)
    assert any(entry.local_address in {"127.0.0.1", "::1", "0.0.0.0", "::"} for entry in matching)
    assert any(entry.pid in {None, os.getpid()} for entry in matching)


def test_port_table_never_spawns_a_process(engine, bound_socket, monkeypatch) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("the port table must not spawn a process")

    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(subprocess, "run", forbidden)
    monkeypatch.setattr(os, "system", forbidden)
    monkeypatch.setattr(os, "popen", forbidden)
    entries = engine.port_table()
    assert isinstance(entries, list)
    assert all(isinstance(entry, PortEntry) for entry in entries)
    _sock, port = bound_socket
    if port_table.platform_module() is not None:
        assert any(entry.local_port == port and entry.state == "LISTEN" for entry in entries)


def test_collect_ports_is_total_on_repeated_calls() -> None:
    first = port_table.collect_ports()
    second = port_table.collect_ports()
    assert isinstance(first, list) and isinstance(second, list)
    assert all(isinstance(entry, PortEntry) for entry in first + second)


def test_port_entries_are_sane() -> None:
    for entry in port_table.collect_ports():
        assert entry.protocol in {"tcp", "tcp6"}
        assert 0 < entry.local_port <= 65535
        assert isinstance(entry.local_address, str) and entry.local_address
        assert entry.pid is None or entry.pid >= 0
        assert isinstance(entry.state, str) and entry.state


def test_port_entry_record_semantics() -> None:
    entry = PortEntry("tcp", "127.0.0.1", 8080, 1234, "LISTEN")
    assert entry.is_listening is True
    assert entry.endpoint == "127.0.0.1:8080"
    assert entry == PortEntry("tcp", "127.0.0.1", 8080, 1234, "LISTEN")
    assert hash(entry) == hash(PortEntry("tcp", "127.0.0.1", 8080, 1234, "LISTEN"))
    assert entry.pid is not None
    assert PortEntry("tcp", "10.0.0.1", 53, None, "ESTABLISHED").pid is None
    with pytest.raises(AttributeError):
        entry.local_port = 9090  # type: ignore[misc]


def test_ipv6_endpoint_is_bracketed() -> None:
    entry = PortEntry("tcp6", "::1", 8443, None, "LISTEN")
    assert entry.endpoint == "[::1]:8443"


def test_listening_and_port_holders_helpers() -> None:
    entries = [
        PortEntry("tcp", "0.0.0.0", 8080, 10, "LISTEN"),
        PortEntry("tcp6", "::", 8080, 11, "LISTEN"),
        PortEntry("tcp", "127.0.0.1", 8080, 12, "ESTABLISHED"),
        PortEntry("tcp", "127.0.0.1", 9090, 13, "LISTEN"),
    ]
    listeners = port_table.listening(entries)
    assert [entry.local_port for entry in listeners] == [8080, 8080, 9090]
    holders = port_table.port_holders(entries, 8080)
    assert [entry.state for entry in holders] == ["LISTEN", "LISTEN", "ESTABLISHED"]
    assert port_table.port_holders(entries, "not a port") == []


def test_procfs_ipv4_rows_are_decoded() -> None:
    from tauhaulity.primitives import posix

    rows = posix.parse_tcp_rows(PROCFS_HEADER + PROCFS_IPV4_LISTEN, "tcp")
    assert rows == [("tcp", "127.0.0.1", 8080, "LISTEN", "12345")]


def test_procfs_ipv6_rows_reverse_each_word() -> None:
    from tauhaulity.primitives import posix

    line = (
        "   1: 00000000000000000000000001000000:1F90 "
        "00000000000000000000000000000000:0000 0A 00000000:00000000 "
        "00:00000000 00000000  1000        0 54321 1 0000000000000000 100 0 0 10 0\n"
    )
    rows = posix.parse_tcp_rows(PROCFS_HEADER + line, "tcp6", ipv6=True)
    assert rows == [("tcp6", "::1", 8080, "LISTEN", "54321")]


def test_procfs_ipv4_mapped_ipv6_address() -> None:
    from tauhaulity.primitives import posix

    line = (
        "   2: 0000000000000000FFFF00000100007F:0050 "
        "00000000000000000000000000000000:0000 0A 00000000:00000000 "
        "00:00000000 00000000  1000        0 777 1 0000000000000000 100 0 0 10 0\n"
    )
    rows = posix.parse_tcp_rows(PROCFS_HEADER + line, "tcp6", ipv6=True)
    assert rows[0][1] == "::ffff:127.0.0.1"
    assert rows[0][2] == 80


def test_procfs_parser_skips_malformed_rows() -> None:
    from tauhaulity.primitives import posix

    body = (
        "garbage without fields\n"
        "   0: not-a-hex-address:1F90 00000000:0000 0A 0:0 0:0 0 0 0 1\n"
        "   1: 0100007F:ZZZZ 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 1 1\n"
        "   2: 0100007F:0000 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 2 1\n"
        "   3: 0100007F:0050 00000000:0000 01 00000000:00000000 00:00000000 00000000 0 0 3 1\n"
    )
    rows = posix.parse_tcp_rows(PROCFS_HEADER + body, "tcp")
    assert rows == [("tcp", "127.0.0.1", 80, "ESTABLISHED", "3")]


def test_address_decoders_reject_wrong_widths() -> None:
    from tauhaulity.primitives import posix

    with pytest.raises(ValueError):
        posix._decode_ipv4_address("0100")
    with pytest.raises(ValueError):
        posix._decode_ipv6_address("0100")


def test_win32_structure_layout_matches_the_documented_abi() -> None:
    from tauhaulity.primitives import win32

    assert win32.layout_error() == ""
    assert ctypes.sizeof(win32.MIB_TCPROW_OWNER_PID) == 24
    assert ctypes.sizeof(win32.MIB_TCPTABLE_OWNER_PID) == 28
    assert ctypes.sizeof(win32.MIB_TCP6ROW_OWNER_PID) == 56
    assert ctypes.sizeof(win32.MIB_TCP6TABLE_OWNER_PID) == 60
    assert win32.MIB_TCPTABLE_OWNER_PID.table.offset == 4
    assert win32.MIB_TCP6TABLE_OWNER_PID.table.offset == 4


def test_platform_modules_expose_the_same_primitive_names() -> None:
    from tauhaulity.primitives import posix, win32

    for name in (
        "capability_report",
        "dirty_pages",
        "lock_pages",
        "protect_pages",
        "qpc",
        "tcp_table",
        "unlock_pages",
    ):
        assert callable(getattr(posix, name, None)), f"posix is missing {name}"
        assert callable(getattr(win32, name, None)), f"win32 is missing {name}"
    for name in ("PROT_READ", "PROT_READ_WRITE", "DIRTY_PAGES_STATUS"):
        assert hasattr(posix, name)
        assert hasattr(win32, name)


def test_platform_modules_degrade_off_their_own_platform() -> None:
    from tauhaulity.primitives import posix, win32

    if os.name == "nt":
        assert posix.tcp_table() == []
        assert posix.lock_pages(bytearray(4096)) is False
        assert posix.qpc() > 0
        assert isinstance(posix.capability_report(), dict)
    else:
        table = win32.tcp_table()
        assert table == []
        assert win32.lock_pages(bytearray(4096)) is False
        assert win32.dirty_pages(os.getpid()) == -1
        with pytest.raises(OSError):
            win32.qpc()
        assert isinstance(win32.capability_report(), dict)


def test_socket_table_is_identical_on_the_rust_and_ctypes_tiers(bound_socket, monkeypatch) -> None:
    """A digest tier switch must never change the kernel socket table.

    SHA-256, CRC-64 and Shannon entropy come from the cdylib, while the socket
    table is always served by the platform layer (iphlpapi on Windows, procfs on
    Linux). If the tier changed those rows, the port sweeper pillar would report
    different holders depending on which digest backend happened to be selected,
    so the three views below must agree exactly for the port this test owns.
    """

    if port_table.platform_module() is None:
        pytest.skip("no kernel port table backend on this host")
    if loader.find_native_library() is None:
        pytest.skip("tauhaulity_silicon_shield is not built for this platform")
    _sock, port = bound_socket

    monkeypatch.delenv(loader.DISABLE_NATIVE_ENV, raising=False)
    loader._reset_engine()
    try:
        native = loader.get_engine()
        if native.backend != "rust":
            pytest.skip("the native tier was rejected by load-time verification")
        native_rows = [entry for entry in native.port_table() if entry.local_port == port]
        assert native_rows, f"the rust tier did not report the bound port {port}"

        # The platform layer alone is what the default ctypes tier would use.
        platform_rows = [entry for entry in port_table.collect_ports() if entry.local_port == port]
        assert platform_rows == native_rows

        monkeypatch.setenv(loader.DISABLE_NATIVE_ENV, "1")
        loader._reset_engine()
        fallback = loader.get_engine()
        assert fallback.backend in {"ctypes", "python"}
        fallback_rows = [entry for entry in fallback.port_table() if entry.local_port == port]
        assert fallback_rows == native_rows
    finally:
        loader._reset_engine()
