"""Pillar nine: port ownership and zombie process detection (PORT-SENTINEL).

The probe is strictly observational: it enumerates listening sockets, groups the
development ports developers actually collide on, and flags listeners whose owner
process is gone or defunct. Killing is never part of a scan; free_port exists for
an explicit user command, and a diagnostic that terminates a stranger's process
because a port looked odd would be worse than the conflict it reports.
"""

from __future__ import annotations

from pathlib import Path

from tauhaulity.core.contracts import SPEC_BY_KEY, Finding, ScanContext, make_finding

SPEC = SPEC_BY_KEY["port_sentinel"]

DEV_PORTS: tuple[int, ...] = (3000, 8000, 5432, 8080)

#: Development ports that are also risky on every interface. A database or a dev
#: server bound to 0.0.0.0 is reachable from the whole local network, while the
#: same service on 127.0.0.1 is not, so the binding address is the finding rather
#: than the port itself. System services that always bind wide (135, 445, ...) are
#: deliberately not included: flagging them would make every Windows scan noisy
#: without telling the developer anything they can act on.
EXPOSURE_PORTS: tuple[int, ...] = (3000, 3306, 4200, 5000, 5173, 5432, 6379, 8000, 8080, 8888, 9229, 27017)

_WILDCARD_ADDRESSES: tuple[str, ...] = ("0.0.0.0", "::", "[::]", "*")

_MAX_LISTED = 12


def _enumerate() -> tuple[list | None, str]:
    """Return the listening table and the backend that produced it."""

    try:
        from tauhaulity.tools.port_sweeper import backend_name, list_listening
    except ImportError:
        return None, "port sweeper module is unavailable"
    try:
        entries = list_listening()
    except (OSError, RuntimeError, ValueError) as exc:
        return None, "socket enumeration failed: " + str(exc)
    try:
        backend = backend_name()
    except (OSError, RuntimeError, ValueError):
        backend = "unknown"
    return entries, backend


def _exposed(entries: list) -> list:
    """Return development-port listeners bound to a wildcard address.

    Parameters:
        entries: Listening sockets from the native kernel table.

    Returns:
        Entries that are both on a development port and reachable from the
        network, which is the combination a developer can fix in one line.
    """

    exposed = []
    for entry in entries:
        address = (getattr(entry, "local_address", "") or "").strip()
        port = getattr(entry, "local_port", getattr(entry, "port", 0))
        if port in EXPOSURE_PORTS and address in _WILDCARD_ADDRESSES:
            exposed.append(entry)
    return exposed


def _classify(entries: list) -> tuple[list, dict, list]:
    """Return zombies, conflicting development ports and owner labels."""

    try:
        from tauhaulity.tools.port_sweeper import conflicting_ports, zombie_entries
    except ImportError:
        return [], {}, []
    try:
        zombies = zombie_entries(entries)
    except (OSError, RuntimeError, ValueError):
        zombies = []
    try:
        conflicts = conflicting_ports(entries, DEV_PORTS)
    except (OSError, RuntimeError, ValueError):
        conflicts = {}
    owners: list[str] = []
    for entry in entries[:_MAX_LISTED]:
        label = str(entry.port) + "/" + entry.protocol
        if entry.pid > 0:
            label += " " + str(entry.pid)
            if entry.process_name:
                label += " " + Path(entry.process_name).name
        owners.append(label)
    return zombies, conflicts, owners


def probe(ctx: ScanContext) -> Finding:
    """Report listening sockets, development port conflicts and zombies."""

    entries, backend = _enumerate()
    if entries is None:
        detail = backend
        return make_finding(
            SPEC,
            "WARNING",
            detail,
            risk=3.0,
            slots={"ports": "unknown", "zombies": "0", "detail": detail},
            repro_hint="call tauhaulity.tools.port_sweeper.backend_name() to see which table is reachable",
        )

    zombies, conflicts, owners = _classify(entries)
    ports_slot = "none" if not entries else str(len(entries)) + " listening"
    listed = ", ".join(owners)
    if len(entries) > _MAX_LISTED:
        listed += ", +" + str(len(entries) - _MAX_LISTED) + " more"

    detail = (
        str(len(entries))
        + " listening socket(s) via "
        + backend
        + ((": " + listed) if listed else "")
    )

    if zombies:
        dead = ", ".join(str(entry.port) + "/" + entry.protocol for entry in zombies[:8])
        detail += "; zombie listener(s) on " + dead
        return make_finding(
            SPEC,
            "ZOMBIE_FOUND",
            detail,
            risk=7.0,
            slots={"ports": ports_slot, "zombies": str(len(zombies)), "detail": detail},
            repro_hint=(
                "inspect owners with tauhaulity.tools.port_sweeper.find_port_owners(port) "
                "and reap explicitly with free_port(port)"
            ),
        )

    if conflicts:
        detail += "; development port conflict on " + ", ".join(
            str(port) for port in sorted(conflicts)
        )
        return make_finding(
            SPEC,
            "CONFLICT_DETECTED",
            detail,
            risk=5.0,
            slots={"ports": ports_slot, "zombies": "0", "detail": detail},
            repro_hint=(
                "run tauhaulity.tools.port_sweeper.find_port_owners(port) for each "
                "conflicting development port to see which processes share it"
            ),
        )

    exposed = _exposed(entries)
    if exposed:
        described = ", ".join(
            str(getattr(entry, "local_port", getattr(entry, "port", 0)))
            + "/"
            + entry.protocol
            + "@"
            + (getattr(entry, "local_address", "") or "*")
            for entry in exposed[:8]
        )
        detail += "; development service(s) reachable from the network: " + described
        return make_finding(
            SPEC,
            "WARNING",
            detail,
            risk=3.5,
            slots={"ports": ports_slot, "zombies": "0", "detail": detail},
            repro_hint=(
                "bind the service to 127.0.0.1 (or ::1) instead of every interface; "
                "check with tauhaulity.tools.port_sweeper.list_listening()"
            ),
        )

    if backend == "unsupported":
        detail += "; no kernel socket table is available on this platform"
        return make_finding(
            SPEC,
            "WARNING",
            detail,
            risk=2.0,
            slots={"ports": ports_slot, "zombies": "0", "detail": detail},
            repro_hint="install the native engine to enumerate sockets on this host",
        )

    return make_finding(
        SPEC,
        "CLEAN",
        detail,
        risk=0.0,
        slots={"ports": ports_slot, "zombies": "0", "detail": detail},
    )
