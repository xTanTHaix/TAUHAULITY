"""Discovery and ordering of the twelve pillar probes.

Pillar modules are discovered by filename (pNN_*.py) instead of being imported
from a hard coded list, so adding or replacing a pillar is a file level change.
Each module exposes a SPEC PillarSpec and a callable probe(ctx); the registry
wraps them in a tiny adapter so the rest of the engine only depends on the
PillarProbe protocol rather than on module level naming.
"""

from __future__ import annotations

import importlib
import pkgutil
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from tauhaulity.core.contracts import PILLAR_SPECS, PillarProbe, PillarSpec, ScanContext

_MODULE_PATTERN = "p[0-9][0-9]_*.py"
_MODULE_NAME = re.compile(r"^p([0-9]{2})_")


class PillarRegistryError(RuntimeError):
    """Raised when a discovered pillar module violates the probe contract."""


@dataclass(frozen=True, slots=True)
class ModuleProbe:
    """Adapter that turns a pillar module into a PillarProbe.

    Attributes:
        spec: Static pillar identity declared by the module.
        module: Imported module object exposing probe(ctx).
    """

    spec: PillarSpec
    module: object

    def probe(self, ctx: ScanContext):
        """Delegate to the module level probe function."""

        return self.module.probe(ctx)


def discover_modules() -> list[str]:
    """Return importable pillar module names ordered by pillar number.

    Returns:
        Module names such as tauhaulity.pillars.p01_memory.
    """

    package_dir = Path(__file__).resolve().parent
    found: list[tuple[int, str]] = []
    for path in sorted(package_dir.glob(_MODULE_PATTERN)):
        if path.name.startswith("__"):
            continue
        prefix = path.stem.split("_", 1)[0]
        digits = prefix[1:]
        if not digits.isdigit():
            continue
        found.append((int(digits), f"{__name__}.{path.stem}"))
    if not found:
        # A zipapp (dist/tauhaulity.pyz) has no package directory on disk, so the
        # filesystem glob above is empty. pkgutil understands zipimport and is the
        # only discovery mechanism that works in both deployment shapes.
        for info in pkgutil.iter_modules(__path__):
            match = _MODULE_NAME.match(info.name)
            if match:
                found.append((int(match.group(1)), f"{__name__}.{info.name}"))
    found = sorted(dict(found).items())
    return [name for _, name in found]


def load_pillars(*, strict: bool = True) -> list[PillarProbe]:
    """Import every pillar module and validate its contract.

    Parameters:
        strict: When True, a missing or malformed pillar raises instead of being
            skipped, which keeps a released build from shipping with holes.

    Raises:
        PillarRegistryError: When strict is True and a module is missing its SPEC
            or probe, or when fewer than twelve pillars are available.
    """

    probes: list[PillarProbe] = []
    numbers: set[int] = set()
    for module_name in discover_modules():
        module = importlib.import_module(module_name)
        spec = getattr(module, "SPEC", None)
        probe = getattr(module, "probe", None)
        if not isinstance(spec, PillarSpec) or not callable(probe):
            if strict:
                raise PillarRegistryError(f"{module_name} must expose SPEC and probe()")
            continue
        if spec.number in numbers:
            raise PillarRegistryError(f"duplicate pillar number {spec.number} in {module_name}")
        numbers.add(spec.number)
        probes.append(ModuleProbe(spec=spec, module=module))
    probes.sort(key=lambda item: item.spec.number)
    if strict and len(probes) != len(PILLAR_SPECS):
        missing = sorted(set(spec.number for spec in PILLAR_SPECS) - numbers)
        raise PillarRegistryError(f"missing pillar modules for numbers {missing}")
    return probes


def specs(probes: Iterable[PillarProbe]) -> tuple[PillarSpec, ...]:
    """Return the specs of the loaded probes in pillar order."""

    return tuple(sorted((probe.spec for probe in probes), key=lambda spec: spec.number))
