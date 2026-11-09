"""Platform neutral kernel socket table shared by the engine and the sweeper.

The port sweeper pillar and the engine must agree on what the kernel reports,
so both go through this module instead of importing win32 or posix directly.
The dispatch is intentionally tiny and defensive: a machine without procfs or
without iphlpapi yields an empty table, never an exception, because a port scan
that crashes is worse than a port scan that reports nothing it can prove.

No function in this module spawns a subprocess. That is a hard requirement: a
security tool that shells out to netstat would trip its own process audit hook
and would not work at all inside a sandbox that blocks process creation.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from tauhaulity.primitives.loader import PortEntry

__all__ = ["backend_name", "collect_ports", "listening", "platform_module", "port_holders"]


def platform_module() -> Any:
    """Return the backend module for this host, or None when unsupported.

    The import is lazy so a Windows host never parses the procfs code and a
    Linux host never builds the iphlpapi structures.
    """

    try:
        if os.name == "nt":
            from tauhaulity.primitives import win32

            return win32
        if sys.platform.startswith("linux"):
            from tauhaulity.primitives import posix

            return posix
    except (ImportError, OSError):
        return None
    return None


def backend_name() -> str:
    """Return the short name of the backend that would serve the port table."""

    if platform_module() is None:
        return "unavailable"
    return "win32" if os.name == "nt" else "posix"


def collect_ports() -> list[PortEntry]:
    """Return the kernel TCP table, or an empty list when it is unreadable.

    Every failure mode (missing procfs, denied iphlpapi call, malformed row) is
    absorbed here: the pillar records the empty artifact and its dossier slot
    says so, which is truthful, instead of aborting the scan.
    """

    module = platform_module()
    if module is None:
        return []
    try:
        entries = module.tcp_table()
    except Exception:
        return []
    if not entries:
        return []
    normalised: list[PortEntry] = []
    for entry in entries:
        if isinstance(entry, PortEntry):
            normalised.append(entry)
    return normalised


def listening(entries: list[PortEntry]) -> list[PortEntry]:
    """Return the listening rows ordered by port, protocol and address.

    A wildcard IPv4 listener and a dual stack IPv6 listener can both appear on
    the same port, so the ordering includes the protocol and the address to stay
    deterministic across backends.
    """

    return sorted(
        (entry for entry in entries if entry.is_listening),
        key=lambda entry: (entry.local_port, entry.protocol, entry.local_address),
    )


def port_holders(entries: list[PortEntry], port: int) -> list[PortEntry]:
    """Return every row bound to one port, listening first.

    The CLI uses this for the 'free <port>' workflow: a port can be held by a
    listener and by established connections of the same or another process, and
    the operator needs to see all of them before anything is terminated.
    """

    try:
        wanted = int(port)
    except (TypeError, ValueError):
        return []
    matches = [entry for entry in entries if entry.local_port == wanted]
    matches.sort(key=lambda entry: (not entry.is_listening, entry.protocol, str(entry.pid)))
    return matches
