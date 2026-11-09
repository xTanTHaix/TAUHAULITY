"""Query OSV for known vulnerabilities in the dependencies a project declares.

OSV is the aggregated vulnerability database from Google and the OpenSSF, and its
batch endpoint accepts a package name, ecosystem and version. This client turns a
declared dependency list into known vulnerabilities without adding a dependency of
its own: standard library only, a bounded number of packages per query, and an
explicit offline path so a scan never fails because a network is unavailable.

The result is deliberately conservative. A finding means "OSV records an advisory
for this name and version", which is a fact about the database, not a claim about
this project's exposure; the report says so rather than implying an exploit.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Final, Sequence

OSV_QUERY_URL: Final[str] = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL: Final[str] = "https://api.osv.dev/v1/vulns/"
USER_AGENT: Final[str] = "tauhaulity-osv-client"

MAX_PACKAGES: Final[int] = 100
MAX_BATCHES: Final[int] = 3
TIMEOUT_S: Final[float] = 20.0
RETRY_DELAY_S: Final[float] = 1.5


class OsvUnavailable(RuntimeError):
    """Raised when the OSV service cannot be reached or answered."""


@dataclass(frozen=True, slots=True)
class PackageRef:
    """One declared dependency.

    Attributes:
        name: Distribution name as declared.
        version: Resolved version, or an empty string when the project only pins
            a range, in which case the query is skipped and reported as such.
        ecosystem: OSV ecosystem name, PyPI or npm.
    """

    name: str
    version: str = ""
    ecosystem: str = "PyPI"


@dataclass(frozen=True, slots=True)
class Vulnerability:
    """One advisory that OSV associates with a package version.

    Attributes:
        package: Package the advisory applies to.
        version: Version queried.
        vuln_id: OSV or GHSA identifier.
        aliases: Other identifiers, typically CVE and GHSA.
        summary: One line description, when the batch response carries it.
        fixed: First version that fixes it, when the database states one.
        url: Canonical advisory URL.
    """

    package: str
    version: str
    vuln_id: str
    aliases: tuple[str, ...] = ()
    summary: str = ""
    fixed: str = ""
    url: str = ""


@dataclass(slots=True)
class OsvReport:
    """Outcome of one OSV lookup.

    Attributes:
        vulnerabilities: Advisories found, most recent first per package.
        queried: Packages actually sent to the service.
        skipped: Packages skipped with a reason.
        source: Where the answer came from: 'osv-api' or 'cache'.
        detail: One line summary suitable for a dossier or a console.
    """

    vulnerabilities: list[Vulnerability] = field(default_factory=list)
    queried: int = 0
    skipped: tuple[str, ...] = ()
    source: str = "osv-api"
    detail: str = ""

    @property
    def count(self) -> int:
        """Number of advisories found."""

        return len(self.vulnerabilities)

    def by_package(self) -> dict[str, list[Vulnerability]]:
        """Group advisories by package name."""

        grouped: dict[str, list[Vulnerability]] = {}
        for item in self.vulnerabilities:
            grouped.setdefault(item.package, []).append(item)
        return grouped


def _post_json(url: str, payload: object) -> dict:
    """POST JSON and decode the response, raising OsvUnavailable on failure."""

    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_S) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        raise OsvUnavailable(type(exc).__name__ + ": " + str(exc)) from exc


def _get_json(url: str) -> dict:
    """GET JSON and decode it, raising OsvUnavailable on failure."""

    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT_S) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
        raise OsvUnavailable(type(exc).__name__ + ": " + str(exc)) from exc


def _fixed_version(vuln: dict, package: str) -> str:
    """Return the first fixing version recorded for a package, if any."""

    for affected in vuln.get("affected", []):
        name = affected.get("package", {}).get("name", "")
        if name and name.lower() != package.lower():
            continue
        for entry in affected.get("ranges", []):
            for event in entry.get("events", []):
                if "fixed" in event:
                    return str(event["fixed"])
    return ""


def query(packages: Sequence[PackageRef], *, enrich: bool = False) -> OsvReport:
    """Look up advisories for the given dependencies.

    Parameters:
        packages: Declared dependencies. Entries without a version are skipped,
            because OSV answers per version and guessing one would be dishonest.
        enrich: When True, fetch each advisory detail page for its summary and
            fix version. The batch endpoint already returns ids, so this costs one
            request per advisory and is off by default.

    Returns:
        An OsvReport; never raises for a network problem, instead returning an
        empty report whose detail names the failure.

    Raises:
        ValueError: When more packages are supplied than the client will send in
            one call, so a caller cannot accidentally turn a scan into a flood.
    """

    if len(packages) > MAX_PACKAGES * MAX_BATCHES:
        raise ValueError(f"at most {MAX_PACKAGES * MAX_BATCHES} packages per lookup")

    ready: list[PackageRef] = []
    skipped: list[str] = []
    for item in packages:
        if not item.name:
            continue
        if not item.version:
            skipped.append(item.name + " (no pinned version)")
            continue
        ready.append(item)
    if not ready:
        return OsvReport(skipped=tuple(skipped), detail="no pinned dependency to check")

    vulnerabilities: list[Vulnerability] = []
    queried = 0
    batches = 0
    for start in range(0, len(ready), MAX_PACKAGES):
        if batches >= MAX_BATCHES:
            break
        chunk = ready[start : start + MAX_PACKAGES]
        batches += 1
        payload = {
            "queries": [
                {"package": {"name": item.name, "ecosystem": item.ecosystem}, "version": item.version}
                for item in chunk
            ]
        }
        try:
            response = _post_json(OSV_QUERY_URL, payload)
        except OsvUnavailable as exc:
            return OsvReport(
                vulnerabilities=vulnerabilities,
                queried=queried,
                skipped=tuple(skipped),
                detail="OSV lookup failed: " + str(exc),
            )
        results = response.get("results", []) or []
        for index, item in enumerate(chunk):
            queried += 1
            # A short response must not silently drop the remaining packages: the
            # count of what was asked for stays honest even when the service
            # answers fewer rows than requested.
            result = results[index] if index < len(results) and isinstance(results[index], dict) else {}
            for raw in result.get("vulns", []) or []:
                vuln_id = str(raw.get("id", ""))
                if not vuln_id:
                    continue
                summary = str(raw.get("summary", "")) if isinstance(raw, dict) else ""
                fixed = _fixed_version(raw, item.name)
                if enrich:
                    try:
                        detail = _get_json(OSV_VULN_URL + vuln_id)
                        summary = str(detail.get("summary", summary))
                        fixed = _fixed_version(detail, item.name) or fixed
                        time.sleep(0.05)
                    except OsvUnavailable:
                        pass
                aliases = tuple(str(alias) for alias in raw.get("aliases", []) or [])
                vulnerabilities.append(
                    Vulnerability(
                        package=item.name,
                        version=item.version,
                        vuln_id=vuln_id,
                        aliases=aliases,
                        summary=summary,
                        fixed=fixed,
                        url="https://osv.dev/vulnerability/" + vuln_id,
                    )
                )
    detail = (
        f"{len(vulnerabilities)} advisory(ies) for {queried} dependency(ies) via OSV"
        if vulnerabilities
        else f"no advisory for {queried} dependency(ies) via OSV"
    )
    if skipped:
        detail += f"; skipped {len(skipped)} without a pinned version"
    return OsvReport(vulnerabilities=vulnerabilities, queried=queried, skipped=tuple(skipped), detail=detail)


_REQUIREMENT_PATTERN: Final[str] = r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:==\s*([^\s;#]+))?"


def declared_dependencies(root: Path) -> tuple[list[PackageRef], tuple[str, ...]]:
    """Read the dependencies a project declares, with the versions it pins.

    Only pinned versions can be checked against OSV, because the database answers
    per version. A dependency declared as a range is returned anyway so the caller
    can report it as unchecked rather than silently ignoring it.

    Parameters:
        root: Project root.

    Returns:
        A tuple of (references, notes) where notes explain anything unreadable.
    """

    import re

    root = Path(root)
    references: list[PackageRef] = []
    notes: list[str] = []
    seen: set[tuple[str, str]] = set()

    def add(name: str, version: str) -> None:
        key = (name.lower(), version)
        if name and key not in seen:
            seen.add(key)
            references.append(PackageRef(name=name, version=version))

    for path in sorted(root.glob("requirements*.txt")):
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError as exc:
            notes.append(f"{path.name}: {type(exc).__name__}")
            continue
        for line in lines:
            stripped = line.split("#", 1)[0].strip()
            if not stripped or stripped.startswith("-"):
                continue
            match = re.match(_REQUIREMENT_PATTERN, stripped)
            if match:
                add(match.group(1), match.group(2) or "")
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            import tomllib

            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            project = data.get("project", {})
            for spec in list(project.get("dependencies", []) or []) + [
                dep
                for group in (project.get("optional-dependencies", {}) or {}).values()
                for dep in group
            ]:
                match = re.match(_REQUIREMENT_PATTERN, str(spec).strip())
                if match:
                    add(match.group(1), match.group(2) or "")
        except (OSError, ValueError) as exc:
            notes.append(f"pyproject.toml: {type(exc).__name__}")
    return references, tuple(notes)


def save_cache(report: OsvReport, path: Path) -> Path:
    """Persist a lookup so a later run can replay it without the network."""

    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "detail": report.detail,
        "queried": report.queried,
        "skipped": list(report.skipped),
        "vulnerabilities": [asdict(item) for item in report.vulnerabilities],
    }
    path.write_text(json.dumps(payload, indent=2) + chr(10), encoding="utf-8", newline=chr(10))
    return path


def load_cache(path: Path) -> OsvReport | None:
    """Load a cached lookup, or None when it is missing or unreadable."""

    path = Path(path)
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    items = payload.get("vulnerabilities", [])
    vulnerabilities = [
        Vulnerability(
            package=str(item.get("package", "")),
            version=str(item.get("version", "")),
            vuln_id=str(item.get("vuln_id", "")),
            aliases=tuple(item.get("aliases", ())),
            summary=str(item.get("summary", "")),
            fixed=str(item.get("fixed", "")),
            url=str(item.get("url", "")),
        )
        for item in items
    ]
    return OsvReport(
        vulnerabilities=vulnerabilities,
        queried=int(payload.get("queried", 0)),
        skipped=tuple(payload.get("skipped", ())),
        source="cache",
        detail=str(payload.get("detail", "cached OSV lookup")),
    )
