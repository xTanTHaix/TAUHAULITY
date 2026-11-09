"""Interpreter level guard and low impact monitoring used by the pillars.

Importing this package is deliberately side effect free. Adding a PEP-578 audit
hook is irreversible for the life of the process, so the hook is only installed
through an explicit activate() call (the package level tauhaulity.activate does
that, and it honours TAUHAULITY_NO_AUTO so a test session or an embedding host can
opt out). Submodules are imported lazily so importing tauhaulity.runtime does not
pull ctypes or allocate the guard state until a caller needs it.

The containment layer is re-exported here for ergonomic embedding:
arm_shield(policy, secret_files=()) arms the process wide guard and harvests the
credential files, shield(policy) scopes a policy to one block,
guard_propagation(env) returns an environment that arms the guard inside Python
children via a sitecustomize shim, unpatch_deserialization() and unpatch_egress()
remove the loader and send wrappers, register_secrets/clear_secrets/
harvest_secrets manage the outbound secret registry, and GuardPolicy /
resolve_provenance / denials expose the policy model, the provenance resolver and
the denial records.
"""

from __future__ import annotations

import importlib
from typing import Any

__all__ = [
    "BurstTracker",
    "BurstVerdict",
    "GuardPolicy",
    "PROPAGATION_MARKER",
    "Provenance",
    "arm_shield",
    "audit_hook",
    "burst_summary",
    "cleanup_propagation",
    "clear_secrets",
    "denials",
    "deserialization_gate_active",
    "egress_gate_active",
    "guard_propagation",
    "harvest_secrets",
    "monitoring",
    "propagation_sitecustomize",
    "register_secrets",
    "resolve_provenance",
    "shield",
    "unpatch_deserialization",
    "unpatch_egress",
]

_LAZY_MODULES = {"audit_hook", "monitoring"}
_LAZY_SYMBOLS = {
    "BurstTracker": "audit_hook",
    "BurstVerdict": "audit_hook",
    "GuardPolicy": "audit_hook",
    "PROPAGATION_MARKER": "audit_hook",
    "Provenance": "audit_hook",
    "arm_shield": "audit_hook",
    "burst_summary": "audit_hook",
    "cleanup_propagation": "audit_hook",
    "clear_secrets": "audit_hook",
    "denials": "audit_hook",
    "deserialization_gate_active": "audit_hook",
    "egress_gate_active": "audit_hook",
    "guard_propagation": "audit_hook",
    "harvest_secrets": "audit_hook",
    "propagation_sitecustomize": "audit_hook",
    "register_secrets": "audit_hook",
    "resolve_provenance": "audit_hook",
    "shield": "audit_hook",
    "unpatch_deserialization": "audit_hook",
    "unpatch_egress": "audit_hook",
}


def __getattr__(name: str) -> Any:
    """Resolve a lazy submodule or a re-exported guard symbol on first access.

    Raises:
        AttributeError: When the requested attribute is not part of the public
            runtime surface.
    """

    if name in _LAZY_MODULES:
        module = importlib.import_module(f"{__name__}.{name}")
        globals()[name] = module
        return module
    owner = _LAZY_SYMBOLS.get(name)
    if owner is not None:
        module = importlib.import_module(f"{__name__}.{owner}")
        value = getattr(module, name)
        globals()[name] = value
        return value
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
