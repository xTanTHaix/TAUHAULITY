"""Pillar eight: ransomware rollback readiness (RANSOM-ROLLBACK).

The probe answers one question honestly: if a destructive writer started in this
project right now, could the damage be undone and would anyone notice in time?
That decomposes into three independent measurements, all read only:

  * the undo journal can be constructed with the policy ring budget;
  * canary decoys exist and can be fingerprinted;
  * the I/O entropy radar finds no fresh ciphertext.

UNPROTECTED is reserved for a store that cannot initialize at all. A project
with no canary is reported as PROTECTED with a lower risk score and an explicit
coverage note, because the journal alone still makes deletion reversible.

The probe also reports the two backup-destruction signals: a recognised
destructive backup command observed by tauhaulity.tools.backup_guard (recorded
only when the optional observer is armed) escalates the pillar to WARNING with
the command shape, and the read-only restore point observation is stated in the
detail. An observation that the host cannot answer is reported as "could not
observe", never as clean; the absence of restore points on a developer machine is
stated but does not by itself change the status, because a fresh checkout has no
backups and warning about that would train the reader to ignore the report.
"""

from __future__ import annotations

from pathlib import Path

from tauhaulity.core.contracts import SPEC_BY_KEY, Finding, ScanContext, make_finding

SPEC = SPEC_BY_KEY["ransom_dev_undo"]

_RADAR_MAX_FILES = 48

#: Risk a recognised backup tampering shape contributes, by its severity.
_BACKUP_RISK: dict[str, float] = {"high": 8.5, "medium": 7.5, "low": 5.0}


def _build_store(root: Path, ring_mb: int) -> tuple[object | None, str | None]:
    """Construct the undo store without writing anything to disk."""

    try:
        from tauhaulity.daemon.undo_store import UndoStore, UndoStoreError
    except ImportError:
        return None, "undo store module is unavailable"
    try:
        return UndoStore(root, ring_mb=ring_mb), None
    except (UndoStoreError, OSError, ValueError) as exc:
        return None, str(exc)


def _canary_count(root: Path) -> int:
    """Return how many canary decoys the watcher can baseline."""

    try:
        from tauhaulity.daemon.canary import CanaryWatcher
    except ImportError:
        return 0
    try:
        watcher = CanaryWatcher(root)
        watcher.snapshot()
        return watcher.watched_count
    except (OSError, ValueError, RuntimeError):
        return 0


def _radar_alerts(root: Path) -> list:
    """Sample the tree for ciphertext-like files with a small file budget."""

    try:
        from tauhaulity.daemon.entropy_radar import scan_for_ransomware
    except ImportError:
        return []
    try:
        return scan_for_ransomware(root, max_files=_RADAR_MAX_FILES)
    except (OSError, ValueError):
        return []


def _honeytoken_state(root: Path) -> tuple[int, int]:
    """Return (armed honeytokens, honeypot alerts) without requiring the guard.

    Both halves degrade to zero: a build without the honeytoken module reports no
    traps, and an uninstalled runtime guard reports no alerts. The probe must never
    crash because an optional subsystem is missing.
    """

    armed = 0
    try:
        from tauhaulity.tools.honeytoken import load as load_honeytokens
    except ImportError:
        load_honeytokens = None
    if load_honeytokens is not None:
        try:
            loaded = load_honeytokens(root)
        except (OSError, RuntimeError, ValueError):
            loaded = None
        if loaded is not None:
            armed = len(loaded.tokens)
    try:
        from tauhaulity.runtime import audit_hook
    except ImportError:
        return armed, 0
    try:
        snapshot = audit_hook.stats()
    except (OSError, RuntimeError, ValueError, TypeError):
        return armed, 0
    try:
        alerts = int(snapshot.get("honeypot_alerts", 0) or 0)
    except (TypeError, ValueError):
        alerts = 0
    return armed, alerts


def _backup_state() -> tuple[list, tuple[bool | None, str]]:
    """Return observed backup signals and the read-only restore point observation.

    Both halves degrade gracefully: a build without the backup guard module reports
    no signals and an unobservable host, and a failing platform probe becomes
    "could not observe" instead of an exception in the dossier.
    """

    signals: list = []
    try:
        from tauhaulity.tools.backup_guard import detected_signals
    except ImportError:
        detected_signals = None
    if detected_signals is not None:
        try:
            signals = list(detected_signals(4))
        except (OSError, RuntimeError, ValueError, TypeError):
            signals = []
    try:
        from tauhaulity.tools.backup_guard import restore_points_present
    except ImportError:
        return signals, (None, "backup guard module is unavailable")
    try:
        return signals, restore_points_present()
    except (OSError, RuntimeError, ValueError, TypeError) as exc:
        return signals, (None, "restore point probe failed: " + type(exc).__name__)


def _store_usage(store: object) -> tuple[int, int, str]:
    """Read journal usage and entry count, degrading to zeros on I/O failure."""

    try:
        usage = int(store.usage_bytes())  # type: ignore[attr-defined]
        entries = list(store.list_entries(limit=100))  # type: ignore[attr-defined]
    except (OSError, RuntimeError, ValueError):
        return 0, 0, "UNREADABLE"
    status = "EMPTY" if not entries else str(len(entries)) + " RESTORE POINTS"
    return usage, len(entries), status


def probe(ctx: ScanContext) -> Finding:
    """Measure rollback readiness for the scanned project."""

    root = Path(ctx.target)
    ring_mb = int(ctx.policy.undo_ring_mb)
    ring_label = str(ring_mb) + " MB"

    store, error = _build_store(root, ring_mb)
    if store is None:
        detail = "undo store cannot initialize: " + (error or "unknown error")
        return make_finding(
            SPEC,
            "UNPROTECTED",
            detail,
            risk=8.0,
            slots={
                "ring_size": ring_label,
                "trash_status": "UNAVAILABLE",
                "detail": detail,
            },
            repro_hint=(
                "construct tauhaulity.daemon.undo_store.UndoStore with the project "
                "root and the policy undo_ring_mb to see the initialization error"
            ),
        )

    usage, entry_count, trash_status = _store_usage(store)
    canaries = _canary_count(root)
    honeytokens, honeypot_alerts = _honeytoken_state(root)
    alerts = _radar_alerts(root)
    initialized = bool(getattr(store, "is_initialized", lambda: False)())

    detail = (
        "undo ring "
        + ring_label
        + " armed"
        + (" (journal on disk)" if initialized else " (journal not yet created)")
        + ", "
        + str(entry_count)
        + " restore point(s), "
        + str(usage)
        + " bytes journaled, "
        + str(canaries)
        + " canary trap(s), "
        + str(honeytokens)
        + " honeytoken(s) armed"
    )
    if honeypot_alerts:
        detail += (
            "; "
            + str(honeypot_alerts)
            + " honeytoken read(s) recorded by the runtime guard"
        )

    backup_signals, restore_state = _backup_state()
    slots = {
        "ring_size": ring_label,
        "trash_status": trash_status,
        "detail": detail,
        "backup_signal": "NONE",
    }
    if backup_signals:
        worst = backup_signals[-1]
        detail += (
            "; backup tampering shape observed: "
            + str(worst.kind)
            + " ("
            + str(worst.command)
            + ")"
        )
        slots["detail"] = detail
        slots["backup_signal"] = str(worst.kind)
        return make_finding(
            SPEC,
            "WARNING",
            detail,
            risk=_BACKUP_RISK.get(str(worst.severity), 8.0),
            slots=slots,
            repro_hint=(
                "identify the process that issued this command with tauhaulity watch ., "
                "verify restore points still exist, and treat the host as compromised "
                "before it encrypts anything else"
            ),
        )
    restore_value, restore_reason = restore_state
    if restore_value is None:
        detail += "; restore points: could not observe (" + str(restore_reason) + ")"
    elif restore_value:
        detail += "; restore points: present (" + str(restore_reason) + ")"
    else:
        detail += "; restore points: none visible (" + str(restore_reason) + ")"
    slots["detail"] = detail

    if alerts:
        worst = alerts[0]
        detail += (
            "; ciphertext-like file "
            + worst.rel_path
            + " at "
            + format(float(worst.entropy), ".2f")
            + " bits per byte"
        )
        slots["detail"] = detail
        return make_finding(
            SPEC,
            "WARNING",
            detail,
            risk=6.5,
            slots=slots,
            repro_hint=(
                "inspect "
                + worst.rel_path
                + " with tauhaulity.daemon.entropy_radar.scan_for_ransomware and "
                "restore the newest journal entry if the change was not intended"
            ),
        )

    risk = 0.5
    if not canaries:
        risk = 1.5
        detail += "; no canary decoy found, tamper detection coverage is empty"
    slots["detail"] = detail
    return make_finding(
        SPEC,
        "PROTECTED",
        detail,
        risk=risk,
        slots=slots,
        repro_hint=None,
    )
