"""OS level primitives shared by the pillars, the CLI and the dossier.

The public surface is deliberately small: the three tier engine and the
PortEntry record. Platform backends (win32, posix) are imported on demand by
the loader so a Windows host never parses procfs structures and a Linux host
never builds the iphlpapi tables.
"""

from __future__ import annotations

from tauhaulity.primitives.loader import PortEntry, ShieldEngine, get_engine

__all__ = ["PortEntry", "ShieldEngine", "get_engine"]
