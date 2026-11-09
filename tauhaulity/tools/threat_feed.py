"""Threat and advisory data with an explicit age, refreshed on demand.

The scanner ships frozen rule lists and a frozen malicious-package sample. Frozen
data is honest only when the tool says how old it is, so this module keeps a
small on-disk cache under <root>/.tauhaulity/feeds with a captured_at timestamp
per kind and reports the age of every snapshot. Nothing here needs the network
unless refresh() is called explicitly:

* status() reads the cache only and reports fresh, stale or missing per kind;
* refresh() asks the OSV API and the OpenSSF malicious-packages repository, one
  bounded sample per kind, and never raises. A failed refresh keeps the previous
  snapshot and records the failure in the returned detail;
* every cache file is versioned JSON written atomically (temporary file plus
  os.replace) with owner only permissions, and a corrupt file degrades to
  "missing" instead of a crash.

What a refresh proves: the endpoints answered, the advisory and malicious-package
sample is current at that moment, and the local data is no longer older than the
snapshot timestamp. What it does not prove: that the local rule set covers every
new attack, that the sample is representative, or that an advisory affects this
project. Refresh also honours the unauthenticated GitHub rate limit: with a
GITHUB_TOKEN or GH_TOKEN in the environment it samples up to 50 records, without
one it samples at most 10 and says so in the detail.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Final

FEED_DIRNAME: Final[str] = ".tauhaulity"
FEED_SUBDIR: Final[str] = "feeds"
CACHE_VERSION: Final[int] = 1
GENERATOR: Final[str] = "tauhaulity.tools.threat_feed"

SUPPORTED_KINDS: Final[tuple[str, ...]] = ("osv", "malicious")
DEFAULT_STALE_AFTER_DAYS: Final[int] = 30
REFRESH_COMMAND: Final[str] = "python scripts/threat_feed_check.py --refresh"

OSV_ENDPOINT: Final[str] = "https://api.osv.dev/v1/querybatch"
OSV_PACKAGES: Final[tuple[str, ...]] = ("requests", "urllib3", "flask", "numpy")

MALICIOUS_TREE_URL: Final[str] = (
    "https://api.github.com/repos/ossf/malicious-packages/git/trees/main?recursive=1"
)
MALICIOUS_RAW_BASE: Final[str] = (
    "https://raw.githubusercontent.com/ossf/malicious-packages/main/"
)
MALICIOUS_PREFIX: Final[str] = "osv/malicious/pypi/"
MAX_MALICIOUS_RECORDS: Final[int] = 50
UNAUTHENTICATED_RECORD_BUDGET: Final[int] = 10

#: Reason tags the OpenSSF feed publishes in record details; the refresh stores the
#: tags it recognises so the sample stays reviewable without the prose payload.
MALICIOUS_REASON_TAGS: Final[tuple[str, ...]] = (
    "exfiltration-env-variables",
    "exfiltration-credentials",
    "typosquatting",
    "malicious-install-hooks",
    "install-time-code-execution",
    "reverse-shell",
    "network-communication",
    "remote-code-execution",
    "obfuscated-code",
    "data-exfiltration",
    "credential-theft",
    "backdoor",
    "crypto-mining",
    "dependency-confusion",
)

_USER_AGENT: Final[str] = "tauhaulity-threat-feed"


@dataclass(frozen=True, slots=True)
class FeedSnapshot:
    """One cached snapshot of one feed kind.

    Attributes:
        source: Endpoint or repository the snapshot was taken from.
        kind: Feed kind, osv or malicious.
        captured_at: UTC ISO timestamp of the snapshot, empty when missing.
        age_days: Age in days at read time, negative when no snapshot exists.
        entries: Bounded reviewable lines; one per advisory or sampled record.
        detail: One line describing the snapshot or why it is missing.
    """

    source: str
    kind: str
    captured_at: str
    age_days: float
    entries: tuple[str, ...]
    detail: str


@dataclass(frozen=True, slots=True)
class FeedStatus:
    """Freshness of every feed kind at one moment.

    Attributes:
        snapshots: One FeedSnapshot per requested kind, in kind order.
        stale: True when any snapshot is missing or older than the limit.
        stale_after_days: Age limit used for this status decision.
        detail: One line summary naming each kind, its age and the refresh command.
    """

    snapshots: tuple[FeedSnapshot, ...]
    stale: bool
    stale_after_days: int
    detail: str


def _utc_now() -> datetime:
    """Return the current UTC time."""

    return datetime.now(timezone.utc)


def _stamp(moment: datetime) -> str:
    """Render one UTC time as an ISO 8601 second precision string."""

    return moment.isoformat(timespec="seconds")


def _one_line(text: object, limit: int = 240) -> str:
    """Collapse arbitrary text to one printable ASCII line."""

    cleaned = "".join(char if 32 <= ord(char) < 127 else " " for char in str(text))
    return " ".join(cleaned.split())[:limit]


def _parse_stamp(value: object) -> datetime | None:
    """Parse a stored ISO timestamp, returning None when unusable."""

    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def feed_cache_dir(root: Path | None = None) -> Path:
    """Return the feed cache directory for a project root (default: cwd)."""

    base = Path(root) if root is not None else Path.cwd()
    return base / FEED_DIRNAME / FEED_SUBDIR


def feed_cache_path(kind: str, root: Path | None = None) -> Path:
    """Return the cache file for one feed kind."""

    return feed_cache_dir(root) / (kind + ".json")


def _load_snapshot(kind: str, root: Path | None, now: datetime) -> FeedSnapshot:
    """Read one cache file, degrading to a missing snapshot when unusable."""

    path = feed_cache_path(kind, root)
    missing_detail = (
        f"no cached {kind} snapshot; refresh with {REFRESH_COMMAND}"
    )
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return FeedSnapshot("", kind, "", -1.0, (), missing_detail)
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return FeedSnapshot("", kind, "", -1.0, (), missing_detail)
    if not isinstance(payload, dict) or payload.get("version") != CACHE_VERSION:
        return FeedSnapshot("", kind, "", -1.0, (), missing_detail)
    captured = _parse_stamp(payload.get("captured_at"))
    if captured is None:
        return FeedSnapshot("", kind, "", -1.0, (), missing_detail)
    raw_entries = payload.get("entries")
    entries: list[str] = []
    if isinstance(raw_entries, list):
        for item in raw_entries[:MAX_MALICIOUS_RECORDS]:
            if isinstance(item, str) and item:
                entries.append(item)
    age = max(0.0, (now - captured).total_seconds() / 86400.0)
    source = payload.get("source")
    detail = payload.get("detail")
    return FeedSnapshot(
        source=source if isinstance(source, str) else "",
        kind=kind,
        captured_at=_stamp(captured),
        age_days=age,
        entries=tuple(entries),
        detail=_one_line(detail) if isinstance(detail, str) and detail else f"cached {kind} snapshot",
    )


def _write_cache(
    kind: str,
    *,
    root: Path | None,
    source: str,
    entries: Sequence[str],
    detail: str,
) -> FeedSnapshot:
    """Write one snapshot atomically and return it as read back from disk.

    Raises:
        OSError: When the cache directory or file cannot be written. The caller
            reports the failure and keeps any previous snapshot untouched.
    """

    now = _utc_now()
    directory = feed_cache_dir(root)
    directory.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    payload = {
        "version": CACHE_VERSION,
        "generator": GENERATOR,
        "kind": kind,
        "source": _one_line(source),
        "captured_at": _stamp(now),
        "entries": [_one_line(entry, 400) for entry in entries],
        "detail": _one_line(detail),
    }
    text = json.dumps(payload, indent=2, sort_keys=False) + chr(10)
    temporary = directory / (kind + ".json.tmp")
    with temporary.open("w", encoding="utf-8", newline=chr(10)) as handle:
        handle.write(text)
    os.replace(temporary, directory / (kind + ".json"))
    try:
        os.chmod(directory / (kind + ".json"), 0o600)
    except OSError:
        pass
    return _load_snapshot(kind, root, now)


def record_snapshot(
    kind: str,
    *,
    root: Path | None = None,
    source: str,
    entries: Sequence[str],
    detail: str = "",
) -> FeedSnapshot:
    """Store an externally fetched snapshot, for tools that already have data.

    This is the hook scripts/threat_feed_check.py uses after it samples the feed
    itself, so the cache stays in one format no matter who fetched it.

    Raises:
        ValueError: When the kind is not supported.
        OSError: When the cache cannot be written.
    """

    if kind not in SUPPORTED_KINDS:
        raise ValueError("unknown feed kind: " + str(kind))
    return _write_cache(
        kind, root=root, source=source, entries=entries, detail=detail or "externally recorded snapshot"
    )


def _http_request(
    url: str,
    *,
    data: bytes | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 20.0,
) -> tuple[int, object]:
    """Perform one HTTP request and decode its JSON body.

    Raises whatever urllib raises so a caller can report the failure honestly.
    """

    merged = {"User-Agent": _USER_AGENT}
    if headers:
        merged.update(headers)
    request = urllib.request.Request(url, data=data, headers=merged)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        status = int(getattr(response, "status", 200) or 200)
        body = response.read()
    return status, json.loads(body.decode("utf-8"))


def _fetch_osv(timeout: float) -> tuple[str, tuple[str, ...], str]:
    """Query the OSV batch endpoint once and return (source, entries, detail)."""

    payload = {
        "queries": [
            {"package": {"name": name, "ecosystem": "PyPI"}} for name in OSV_PACKAGES
        ]
    }
    body = json.dumps(payload).encode("utf-8")
    status, decoded = _http_request(
        OSV_ENDPOINT,
        data=body,
        headers={"Content-Type": "application/json"},
        timeout=timeout,
    )
    advisories: list[str] = []
    if isinstance(decoded, dict):
        for result in decoded.get("results", []) or []:
            if not isinstance(result, dict):
                continue
            for vuln in result.get("vulns", []) or []:
                if isinstance(vuln, dict):
                    identifier = vuln.get("id")
                    if isinstance(identifier, str) and identifier:
                        advisories.append(identifier)
    advisory = advisories[0] if advisories else "none"
    entry = (
        f"endpoint={OSV_ENDPOINT} status={status} packages={len(OSV_PACKAGES)} advisory={advisory}"
    )
    detail = (
        f"OSV querybatch answered HTTP {status} with {len(advisories)} advisory reference(s) "
        f"for {len(OSV_PACKAGES)} popular packages"
    )
    return OSV_ENDPOINT, (entry,), detail


def _github_headers() -> tuple[dict[str, str], bool]:
    """Return GitHub request headers and whether a token was found."""

    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or ""
    if token:
        headers["Authorization"] = "Bearer " + token
    return headers, bool(token)


def _malicious_entry(record: dict, fallback_package: str) -> str:
    """Render one OSV malicious record as a reviewable single line."""

    package = fallback_package
    affected = record.get("affected")
    if isinstance(affected, list) and affected and isinstance(affected[0], dict):
        record_package = affected[0].get("package")
        if isinstance(record_package, dict) and isinstance(record_package.get("name"), str):
            package = record_package["name"]
    record_id = record.get("id") if isinstance(record.get("id"), str) else ""
    details = record.get("details") if isinstance(record.get("details"), str) else ""
    summary = record.get("summary") if isinstance(record.get("summary"), str) else ""
    lowered = details.lower()
    reasons = [tag for tag in MALICIOUS_REASON_TAGS if tag in lowered]
    reason_text = ",".join(reasons) if reasons else "-"
    campaign = ""
    for line in details.splitlines():
        if line.strip().lower().startswith("campaign:"):
            campaign = line.split(":", 1)[1].strip()
            break
    entry = (
        f"package={package or 'unknown'} record={record_id or 'unknown'} "
        f"reasons={reason_text} summary={_one_line(summary, 100)}"
    )
    if campaign:
        entry += " campaign=" + _one_line(campaign, 60)
    return entry


def _fetch_malicious(timeout: float) -> tuple[str, tuple[str, ...], str]:
    """Sample the OpenSSF malicious-packages repository for real records.

    One request lists the repository tree, then one request per sampled record
    file, bounded by the unauthenticated GitHub rate limit unless a token is
    present in the environment.
    """

    headers, authenticated = _github_headers()
    status, tree = _http_request(MALICIOUS_TREE_URL, headers=headers, timeout=timeout)
    paths: list[str] = []
    if isinstance(tree, dict):
        for item in tree.get("tree", []) or []:
            if not isinstance(item, dict):
                continue
            path = item.get("path")
            if (
                isinstance(path, str)
                and path.startswith(MALICIOUS_PREFIX)
                and path.endswith(".json")
            ):
                paths.append(path)
    paths.sort()
    budget = MAX_MALICIOUS_RECORDS if authenticated else UNAUTHENTICATED_RECORD_BUDGET
    entries: list[str] = []
    for path in paths[:budget]:
        parts = path.split("/")
        fallback_package = parts[-2] if len(parts) >= 2 else "unknown"
        raw_url = MALICIOUS_RAW_BASE + urllib.parse.quote(path)
        try:
            _record_status, record = _http_request(
                raw_url, headers={"Accept": "application/json"}, timeout=timeout
            )
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            continue
        if isinstance(record, dict):
            entries.append(_malicious_entry(record, fallback_package))
    token_note = "authenticated" if authenticated else "unauthenticated GitHub limit of 60 requests/hour"
    detail = (
        f"OpenSSF malicious-packages answered HTTP {status}; sampled {len(entries)} record(s) "
        f"from {len(paths)} pypi path(s) with {token_note}"
    )
    return MALICIOUS_TREE_URL, tuple(entries), detail


def _fetch_kind(kind: str, timeout: float) -> tuple[str, tuple[str, ...], str]:
    """Dispatch one kind to its fetcher."""

    if kind == "osv":
        return _fetch_osv(timeout)
    return _fetch_malicious(timeout)


def _render_status(
    snapshots: Sequence[FeedSnapshot], stale: bool, stale_after_days: int, note: str = ""
) -> str:
    """Compose the one line freshness summary."""

    parts: list[str] = []
    for snapshot in snapshots:
        if snapshot.age_days < 0:
            parts.append(snapshot.kind + ": missing")
        else:
            parts.append(f"{snapshot.kind}: {snapshot.age_days:.1f} day(s) old")
    state = "stale" if stale else "fresh"
    detail = (
        f"threat feed {state} (limit {stale_after_days} day(s)): "
        + "; ".join(parts)
        + f"; refresh with {REFRESH_COMMAND}"
    )
    if note:
        detail += "; " + note
    return _one_line(detail, 480)


def _compute_status(
    *, root: Path | None, stale_after_days: int, kinds: Sequence[str], note: str = ""
) -> FeedStatus:
    """Build a FeedStatus from the cache for the requested kinds."""

    now = _utc_now()
    snapshots = tuple(_load_snapshot(kind, root, now) for kind in kinds)
    stale = any(
        snapshot.age_days < 0 or snapshot.age_days > stale_after_days for snapshot in snapshots
    )
    return FeedStatus(
        snapshots=snapshots,
        stale=stale,
        stale_after_days=stale_after_days,
        detail=_render_status(snapshots, stale, stale_after_days, note),
    )


def status(*, root: Path | None = None, stale_after_days: int = 30) -> FeedStatus:
    """Report the age of every cached snapshot without touching the network.

    Parameters:
        root: Project root holding .tauhaulity/feeds (default: current directory).
        stale_after_days: Age above which a snapshot counts as stale.

    Returns:
        A FeedStatus naming fresh, stale and missing kinds. A corrupt cache file
        degrades to a missing snapshot instead of raising.
    """

    limit = max(0, int(stale_after_days))
    return _compute_status(root=root, stale_after_days=limit, kinds=SUPPORTED_KINDS)


def refresh(
    kinds: Sequence[str] = ("osv", "malicious"),
    *,
    root: Path | None = None,
    timeout: float = 20.0,
) -> FeedStatus:
    """Refresh the requested feed kinds, keeping previous snapshots on failure.

    Parameters:
        kinds: Feed kinds to refresh; unknown kinds are reported, not raised.
        root: Project root holding .tauhaulity/feeds (default: current directory).
        timeout: Per request timeout in seconds.

    Returns:
        A FeedStatus computed from the cache after the attempt. Network failures
        and write failures are reported in the detail and never raise; a failed
        refresh does not delete or modify the previous snapshot.
    """

    requested: list[str] = []
    notes: list[str] = []
    for kind in kinds:
        if kind in SUPPORTED_KINDS:
            if kind not in requested:
                requested.append(kind)
        else:
            notes.append(f"ignored unknown feed kind {kind!r}")
    for kind in requested:
        try:
            source, entries, fetch_detail = _fetch_kind(kind, float(timeout))
        except Exception as exc:  # network and payload failures are reported, never raised
            # TimeoutError and urllib failures are OSError subclasses, so the
            # fetch is handled before the cache write to keep the two failure
            # classes distinct in the detail line.
            previous = _load_snapshot(kind, root, _utc_now())
            if previous.age_days < 0:
                notes.append(f"{kind}: refresh failed ({type(exc).__name__}), no previous snapshot")
            else:
                notes.append(
                    f"{kind}: refresh failed ({type(exc).__name__}), previous snapshot kept "
                    f"({previous.age_days:.1f} day(s) old)"
                )
            continue
        try:
            snapshot = _write_cache(
                kind,
                root=root,
                source=source,
                entries=entries,
                detail=fetch_detail,
            )
        except OSError as exc:
            notes.append(
                f"{kind}: cache write failed ({type(exc).__name__}), previous snapshot kept"
            )
            continue
        notes.append(
            f"{kind}: refreshed {len(snapshot.entries)} entry(ies) "
            f"from {snapshot.source or 'unknown source'}"
        )
    return _compute_status(
        root=root,
        stale_after_days=DEFAULT_STALE_AFTER_DAYS,
        kinds=SUPPORTED_KINDS,
        note="refresh: " + "; ".join(notes) if notes else "refresh: nothing requested",
    )
