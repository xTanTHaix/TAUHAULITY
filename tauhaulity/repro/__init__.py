"""Attack flight recorder, delta minimizer and repro script synthesizer.

The recorder stores events as shared 128 byte telemetry frames, the minimizer
reduces a replay case to the smallest event set that still reproduces a failure,
and the synthesizer writes a standalone standard library script that exits non-zero
once the vulnerability has been mitigated. Imports stay lazy so a missing sibling
module can never break importing the package.
"""

from __future__ import annotations

import importlib
from typing import Any

_LAZY: dict[str, tuple[str, str]] = {
    "ReplayEvent": ("tauhaulity.repro.recorder", "ReplayEvent"),
    "ReplayCase": ("tauhaulity.repro.recorder", "ReplayCase"),
    "ReplayRecorder": ("tauhaulity.repro.recorder", "ReplayRecorder"),
    "delta_minimize": ("tauhaulity.repro.minimizer", "delta_minimize"),
    "MinimizedCase": ("tauhaulity.repro.minimizer", "MinimizedCase"),
    "AutoReproSynthesizer": ("tauhaulity.repro.synthesizer", "AutoReproSynthesizer"),
}

__all__ = list(_LAZY)


def __getattr__(name: str) -> Any:
    """Resolve one public name from its defining module on first use."""

    target = _LAZY.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = target
    module = importlib.import_module(module_name)
    value = getattr(module, attribute)
    globals()[name] = value
    return value
