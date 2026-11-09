"""Measure false-positive behaviour on a large body of real, trusted Python code.

The red-team corpus proves the detector fires on attacks. It cannot prove the
detector stays quiet on ordinary code, because the corpus was written by the same
author. The standard library of the interpreter is a large, real, well reviewed
corpus that nobody wrote for this test, so it is the fairest available control.
Findings there are not automatically false positives: the standard library really
does contain pickle, subprocess and dangerous call sites. What matters is the
volume and the severity mix.

Run: python scripts/false_positive_probe.py [root ...]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from tauhaulity.core.contracts import ScanOptions
from tauhaulity.core.platform_probe import detect_platform
from tauhaulity.core.policy import Policy
from tauhaulity.tools.artifact_scan import scan_source_tree


def probe(root: Path) -> dict[str, object]:
    """Scan one directory and summarise the findings."""

    started = time.process_time()
    result = scan_source_tree(root)
    elapsed = time.process_time() - started
    kinds: Counter[str] = Counter()
    severities: Counter[str] = Counter()
    for finding in result.findings:
        kinds[finding.kind] += 1
        severities[getattr(finding, "severity", "unknown")] += 1
    return {
        "root": str(root),
        "files_inspected": getattr(result, "files_inspected", 0),
        "truncated": bool(getattr(result, "truncated", False)),
        "findings": len(result.findings),
        "per_1000_files": round(1000 * len(result.findings) / max(1, getattr(result, "files_inspected", 0)), 2),
        "by_kind": dict(kinds.most_common()),
        "by_severity": dict(severities.most_common()),
        "cpu_seconds": round(elapsed, 3),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="False-positive probe on trusted code.")
    parser.add_argument("roots", nargs="*", help="directories to scan; defaults to the interpreter stdlib")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    import sysconfig

    roots = [Path(item) for item in args.roots] if args.roots else [Path(sysconfig.get_paths()["stdlib"])]
    reports = [probe(root) for root in roots if root.is_dir()]
    if args.json:
        print(json.dumps(reports, indent=2))
        return 0
    for report in reports:
        print("root            :", report["root"])
        print("files inspected :", report["files_inspected"], "| truncated:", report["truncated"])
        print("findings        :", report["findings"], f"({report['per_1000_files']} per 1000 files)")
        print("by severity     :", report["by_severity"])
        print("by kind         :", report["by_kind"])
        print("cpu seconds     :", report["cpu_seconds"])
        print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
