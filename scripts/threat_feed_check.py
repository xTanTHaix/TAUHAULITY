"""Check Tauhaulity rules against real malicious packages from the OpenSSF feed.

Reading a threat feed is not the same as being protected against it. This script
pulls real records from the OpenSSF malicious-packages repository (the community
record of packages removed from PyPI and npm for abuse), maps the reasons those
records cite onto the rule ids this project implements, and prints the coverage.
It is an indicator-level check: it proves which attack classes our rules name, not
that a specific payload would be caught at runtime.

The default replay prefers the shared feed cache written by
tauhaulity.tools.threat_feed (<feed-root>/.tauhaulity/feeds/malicious.json) when
it exists, and merges the curated docs sample so the coverage number keeps its
breadth. A run without --refresh therefore replays current data offline when a
refresh has happened, and the curated snapshot otherwise. --refresh keeps the
original behaviour (sample the feed, rewrite the curated sample) and also writes
the shared cache so the pillar stops warning about stale data.

Run:  python scripts/threat_feed_check.py --limit 40
      python scripts/threat_feed_check.py --limit 40 --json
      python scripts/threat_feed_check.py --refresh
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

API = "https://api.github.com/repos/ossf/malicious-packages/contents/osv/malicious/pypi"
HEADERS = {"User-Agent": "tauhaulity-threat-feed-check", "Accept": "application/vnd.github+json"}

#: Feed reason tags mapped to the rule this project implements for that class.
REASON_RULES: dict[str, str] = {
    "exfiltration-env-variables": "p06 env_secret_harvesting",
    "exfiltration-credentials": "p06 env_secret_harvesting",
    "typosquatting": "p06 dependency typosquat audit",
    "malicious-install-hooks": "p06 install_time_execution",
    "install-time-code-execution": "p06 install_time_execution",
    "reverse-shell": "p06 reverse_shell_shape",
    "network-communication": "p06 raw_socket_egress",
    "remote-code-execution": "runtime guard subprocess denial",
    "obfuscated-code": "p06 obfuscated_payload",
    "data-exfiltration": "p07 egress entropy gate and secret patterns",
    "credential-theft": "p11 credential sentinel",
    "backdoor": "p06 reverse_shell_shape",
    "crypto-mining": "p06 raw_socket_egress",
    "dependency-confusion": "p06 dependency direct_url audit",
}


@dataclass(slots=True)
class FeedRecord:
    """One feed entry reduced to what matters here."""

    package: str
    record_id: str
    modified: str
    summary: str
    reasons: tuple[str, ...] = field(default_factory=tuple)
    covered_by: tuple[str, ...] = field(default_factory=tuple)
    campaign: str = ""


def _get(url: str, timeout: float = 60.0):
    """Fetch JSON with the headers GitHub requires."""

    request = urllib.request.Request(url, headers=HEADERS)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def _reasons_from(details: str) -> tuple[tuple[str, ...], str]:
    """Extract reason tags and a campaign name from a record's prose.

    The feed stores free text, so the parser looks for the structured tokens the
    project actually publishes (dash separated tags in the Reasons section and a
    Campaign line) and ignores everything else rather than guessing.
    """

    lower = details.lower()
    found = [tag for tag in REASON_RULES if tag in lower]
    campaign = ""
    for line in details.splitlines():
        if line.strip().lower().startswith("campaign:"):
            campaign = line.split(":", 1)[1].strip()
            break
    return tuple(found), campaign


def collect(limit: int = 40) -> tuple[list[FeedRecord], str]:
    """Fetch up to the requested number of real records.

    Returns:
        The records and a note describing the source, or an explanatory note when
        the network is unavailable. The caller decides whether that is fatal,
        because a demonstration machine may legitimately be offline.
    """

    try:
        entries = _get(API)
    except (urllib.error.URLError, TimeoutError, ValueError) as exc:
        return [], "feed unavailable: " + type(exc).__name__ + ": " + str(exc)
    records: list[FeedRecord] = []
    for entry in entries[:limit]:
        package = entry.get("name", "")
        try:
            files = _get(API + "/" + package)
            record = _get(files[0]["download_url"])
        except (KeyError, IndexError, urllib.error.URLError, TimeoutError, ValueError) as exc:
            records.append(FeedRecord(package, "", "", "unreadable: " + type(exc).__name__))
            continue
        details = record.get("details", "")
        reasons, campaign = _reasons_from(details)
        records.append(
            FeedRecord(
                package=package,
                record_id=record.get("id", ""),
                modified=record.get("modified", ""),
                summary=record.get("summary", ""),
                reasons=reasons,
                covered_by=tuple(REASON_RULES[tag] for tag in reasons),
                campaign=campaign,
            )
        )
    return records, "OpenSSF malicious-packages feed"


def summarize(records: list[FeedRecord]) -> dict[str, object]:
    """Aggregate coverage across the sampled records."""

    total = len(records)
    tagged = [record for record in records if record.reasons]
    covered = [record for record in tagged if record.covered_by]
    per_rule: dict[str, int] = {}
    for record in tagged:
        for rule in record.covered_by:
            per_rule[rule] = per_rule.get(rule, 0) + 1
    campaigns = sorted({record.campaign for record in records if record.campaign})
    return {
        "sampled": total,
        "with_reason_tags": len(tagged),
        "covered_by_a_rule": len(covered),
        "coverage_of_tagged": round(len(covered) / len(tagged), 3) if tagged else 0.0,
        "per_rule": dict(sorted(per_rule.items(), key=lambda item: -item[1])),
        "campaigns": campaigns[:10],
    }


def render(records: list[FeedRecord], summary: dict[str, object], source: str) -> str:
    """Render a readable report."""

    lines = ["source: " + source, ""]
    header = f"{'PACKAGE':<24}{'RECORD':<18}{'REASONS':<46}COVERED BY"
    lines.extend([header, "-" * len(header)])
    for record in records:
        reasons = ", ".join(record.reasons) or "(no structured reason)"
        covered = ", ".join(record.covered_by) or "-"
        lines.append(f"{record.package[:23]:<24}{record.record_id:<18}{reasons[:45]:<46}{covered[:60]}")
    lines.append("")
    lines.append(json.dumps(summary, indent=2))
    return chr(10).join(lines)


DEFAULT_CACHE = ROOT / "docs" / "threat-feed-sample.json"


def load_cache(path: Path) -> tuple[list[FeedRecord], str]:
    """Load a previously sampled feed snapshot.

    The GitHub API allows sixty unauthenticated requests per hour, so the sample
    is cached in the repository. A run without --refresh uses the snapshot, which
    also makes the coverage number reproducible on a machine with no network.
    """

    if not path.is_file():
        return [], "no cached sample at " + str(path)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return [], "cached sample unreadable: " + type(exc).__name__
    records = [
        FeedRecord(
            package=item.get("package", ""),
            record_id=item.get("record_id", ""),
            modified=item.get("modified", ""),
            summary=item.get("summary", ""),
            reasons=tuple(item.get("reasons", ())),
            covered_by=tuple(item.get("covered_by", ())),
            campaign=item.get("campaign", ""),
        )
        for item in payload.get("records", [])
    ]
    return records, "cached sample from " + payload.get("captured_at", "an earlier run")


def save_cache(path: Path, records: list[FeedRecord], source: str) -> None:
    """Persist a fresh sample so later runs are offline and cheap."""

    import datetime

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "source": source,
        "captured_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "records": [asdict(record) for record in records],
    }
    path.write_text(json.dumps(payload, indent=2) + chr(10), encoding="utf-8", newline=chr(10))


_ENTRY_RE = re.compile(
    r"^package=(?P<package>.*?) record=(?P<record>.*?) reasons=(?P<reasons>.*?) "
    r"summary=(?P<summary>.*?)(?: campaign=(?P<campaign>.*))?$"
)


def entry_line(record: FeedRecord) -> str:
    """Render one record in the shared feed cache format."""

    reasons = ",".join(record.reasons) if record.reasons else "-"
    line = (
        "package=" + (record.package or "unknown")
        + " record=" + (record.record_id or "unknown")
        + " reasons=" + reasons
        + " summary=" + record.summary.replace(chr(10), " ")[:100]
    )
    if record.campaign:
        line += " campaign=" + record.campaign.replace(chr(10), " ")[:60]
    return line


def record_from_entry(line: str) -> FeedRecord | None:
    """Parse one shared feed cache entry back into a FeedRecord."""

    match = _ENTRY_RE.match(line.strip())
    if match is None:
        return None
    raw_reasons = match.group("reasons") or ""
    reasons = tuple(tag for tag in raw_reasons.split(",") if tag and tag != "-")
    return FeedRecord(
        package=match.group("package"),
        record_id=match.group("record"),
        modified="",
        summary=match.group("summary"),
        reasons=reasons,
        covered_by=tuple(REASON_RULES[tag] for tag in reasons if tag in REASON_RULES),
        campaign=match.group("campaign") or "",
    )


def load_feed_cache(feed_root: Path) -> tuple[list[FeedRecord], str]:
    """Read the shared threat-feed cache, or report that it is missing."""

    try:
        from tauhaulity.tools import threat_feed
    except ImportError:
        return [], "shared feed cache module unavailable"
    try:
        snapshot_status = threat_feed.status(root=feed_root)
    except (OSError, ValueError, RuntimeError):
        return [], "shared feed cache unreadable"
    snapshot = next(
        (item for item in snapshot_status.snapshots if item.kind == "malicious"), None
    )
    if snapshot is None or snapshot.age_days < 0:
        return [], "no cached feed snapshot at " + str(threat_feed.feed_cache_path("malicious", feed_root))
    records = [record for record in (record_from_entry(line) for line in snapshot.entries) if record]
    source = (
        "cached feed snapshot from " + snapshot.captured_at
        + f" ({snapshot.age_days:.1f} day(s) old)"
    )
    return records, source


def _merge_records(newer: list[FeedRecord], legacy: list[FeedRecord]) -> list[FeedRecord]:
    """Keep the fresh records first and append legacy records not already present."""

    seen = {(record.package, record.record_id) for record in newer}
    return list(newer) + [
        record for record in legacy if (record.package, record.record_id) not in seen
    ]


def main(argv: list[str] | None = None) -> int:
    """Sample the feed and print coverage."""

    parser = argparse.ArgumentParser(description="Check rule coverage against real malicious packages.")
    parser.add_argument("--limit", type=int, default=40, help="how many feed records to sample")
    parser.add_argument("--json", action="store_true", help="emit JSON only")
    parser.add_argument("--refresh", action="store_true", help="ignore the cache and fetch fresh records")
    parser.add_argument("--allow-offline", action="store_true", help="exit zero when nothing can be read")
    parser.add_argument("--cache", default=str(DEFAULT_CACHE), help="curated snapshot path")
    parser.add_argument(
        "--feed-root",
        default=str(ROOT),
        help="project root holding .tauhaulity/feeds (default: this repository)",
    )
    args = parser.parse_args(argv)
    feed_root = Path(args.feed_root)

    cache_path = Path(args.cache)
    if args.refresh:
        records, source = collect(max(1, min(args.limit, 200)))
        if records:
            save_cache(cache_path, records, source)
            try:
                from tauhaulity.tools import threat_feed

                snapshot = threat_feed.record_snapshot(
                    "malicious",
                    root=feed_root,
                    source=source,
                    entries=tuple(entry_line(record) for record in records),
                    detail="scripts/threat_feed_check.py sampled " + str(len(records)) + " record(s)",
                )
                print(
                    "feed cache refreshed: "
                    + str(threat_feed.feed_cache_path("malicious", feed_root))
                    + " (" + str(len(snapshot.entries)) + " record(s) at " + snapshot.captured_at + ")",
                    file=sys.stderr,
                )
            except (OSError, ValueError, ImportError) as exc:
                print(
                    "feed cache not refreshed: " + type(exc).__name__ + ": " + str(exc),
                    file=sys.stderr,
                )
    else:
        records, source = [], ""
        if cache_path == DEFAULT_CACHE:
            records, source = load_feed_cache(feed_root)
        legacy_records, legacy_source = load_cache(cache_path)
        if records:
            records = _merge_records(records, legacy_records)
            if legacy_records:
                source += " plus " + legacy_source
        else:
            records, source = legacy_records, legacy_source
    summary = summarize(records)
    if not records:
        payload = {"source": source, "records": [], "summary": summary}
        print(json.dumps(payload, indent=2) if args.json else source)
        return 0 if args.allow_offline else 1
    if args.json:
        print(json.dumps({"source": source, "summary": summary, "records": [asdict(r) for r in records]}, indent=2))
    else:
        print(render(records, summary, source))
    return 0


if __name__ == "__main__":
    sys.exit(main())
