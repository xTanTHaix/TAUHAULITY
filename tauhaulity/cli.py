"""Command dispatcher for the tauhaulity command line interface.

The CLI is a thin adapter: every command validates its arguments, calls one
service function and renders the result. Keeping the logic out of argparse makes
the services testable without a subprocess and keeps the console output honest
about what actually happened (no optimistic messages on failure paths).
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import shutil
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Sequence

from tauhaulity import __version__
from tauhaulity.core.contracts import ScanOptions
from tauhaulity.core.policy import Policy, PolicyError, policy_path
from tauhaulity.engine import ScanError, run_scan, summarize

EXIT_OK = 0
EXIT_AT_RISK = 1
EXIT_CRITICAL = 2
EXIT_USAGE = 3
EXIT_UNAVAILABLE = 4

_VERDICT_EXIT = {"SAFE": EXIT_OK, "AT_RISK": EXIT_AT_RISK, "CRITICAL": EXIT_CRITICAL}


def invocation_prefix() -> str:
    """Return the shortest command that reproduces this invocation.

    A newcomer reaches the tool three ways: the single-file zipapp, the module
    entry point from a checkout, or the installed console script. Printed "next
    steps" that always say `tauhaulity` are wrong for the first two, so the hint
    text is derived from how the process was actually started.
    """

    entry = Path(sys.argv[0]).name if sys.argv and sys.argv[0] else ""
    full = sys.argv[0] if sys.argv and sys.argv[0] else ""
    if entry.endswith(".pyz"):
        return f'python "{full}"'
    if entry == "__main__.py" or (entry.endswith(".py") and "tauhaulity" in full.replace(chr(92), "/")):
        return "python -m tauhaulity"
    if getattr(sys, "frozen", False):
        return f'"{full}"'
    return "tauhaulity"


def _error(message: str) -> int:
    """Print a usage or runtime error to stderr and return the usage code."""

    print(f"tauhaulity: {message}", file=sys.stderr)
    return EXIT_USAGE


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser with every supported subcommand.

    Returns:
        A configured ArgumentParser; calling parse_args with no arguments is
        rewritten by main() into the default audit command.
    """

    parser = argparse.ArgumentParser(
        prog="tauhaulity",
        description="12-pillar project safety scan, undo net, git secret gate, port sweeper and dossier exporter.",
    )
    parser.add_argument("--version", action="version", version=f"tauhaulity {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    audit = subparsers.add_parser("audit", help="run the twelve pillar scan and export dossiers")
    audit.add_argument("target", nargs="?", default=".")
    audit.add_argument("--export", default="md,txt,json", help="comma separated dossier formats")
    audit.add_argument("--out", default=None, help="output directory for dossiers")
    audit.add_argument("--deep", action="store_true", help="enable expensive checks")
    audit.add_argument("--no-repro", action="store_true", help="skip reproduction script synthesis")
    audit.add_argument("--json", action="store_true", help="print a machine readable summary")

    undo = subparsers.add_parser("undo", help="list or restore files captured by the undo net")
    undo.add_argument("--root", default=".")
    undo.add_argument("--list", action="store_true", help="list captured entries")
    undo.add_argument("--id", default=None, help="entry id to restore; defaults to the newest")

    rm = subparsers.add_parser("rm", help="delete paths after capturing them in the undo ring")
    rm.add_argument("paths", nargs="+")
    rm.add_argument("--root", default=".")
    rm.add_argument("--dry-run", action="store_true", help="show what would be captured and deleted")

    free = subparsers.add_parser("free", help="release a port held by a hung or zombie process")
    free.add_argument("port", type=int)
    free.add_argument("--dry-run", action="store_true")
    free.add_argument("--force", action="store_true", help="skip the graceful signal phase")
    free.add_argument("--yes", action="store_true", help="confirm termination without an interactive prompt")

    ports = subparsers.add_parser("ports", help="list listening sockets and their owning processes")
    ports.add_argument("--json", action="store_true")

    hook = subparsers.add_parser("hook", help="install, remove or inspect the git pre-commit gate")
    hook.add_argument("action", choices=("install", "uninstall", "status"))
    hook.add_argument("path", nargs="?", default=".")
    hook.add_argument("--warn-only", action="store_true", help="hook reports instead of blocking")

    venv = subparsers.add_parser("venv-check", help="inspect a virtual environment for tampering")
    venv.add_argument("path", nargs="?", default=".")
    venv.add_argument("--json", action="store_true")

    apply_cmd = subparsers.add_parser("apply", help="apply a filled dossier form as the active policy")
    apply_cmd.add_argument("form")
    apply_cmd.add_argument("--root", default=".")

    doctor = subparsers.add_parser("doctor", help="self diagnostic of the local engine")
    doctor.add_argument("--root", default=".")
    doctor.add_argument("--json", action="store_true")

    diff = subparsers.add_parser("diff", help="compare two JSON dossiers")
    diff.add_argument("old")
    diff.add_argument("new")

    ci = subparsers.add_parser("ci", help="one gate for a pipeline: scan, dependencies, advisories, exit code")
    ci.add_argument("path", nargs="?", default=".")
    ci.add_argument("--online", action="store_true", help="refresh the OSV advisories before checking")
    ci.add_argument("--fail-on", choices=("critical", "warning", "none"), default="critical")
    ci.add_argument("--json", action="store_true")
    ci.add_argument("--no-deps", action="store_true", help="skip the dependency declaration audit")
    ci.add_argument("--no-vulns", action="store_true", help="skip the advisory check")

    posture = subparsers.add_parser("posture", help="what protects this machine now, what is stale, and what it cannot cover")
    posture.add_argument("path", nargs="?", default=".")
    posture.add_argument("--json", action="store_true")
    posture.add_argument("--strict", action="store_true", help="exit non-zero when a protection item is off or stale")

    feed = subparsers.add_parser("feed", help="show or refresh the cached threat-intelligence snapshots")
    feed.add_argument("action", nargs="?", choices=("status", "refresh"), default="status")
    feed.add_argument("--stale-after-days", type=int, default=30)
    feed.add_argument("--json", action="store_true")

    quarantine = subparsers.add_parser("quarantine", help="move a dangerous artefact out of the load path")
    quarantine.add_argument("action", choices=("list", "apply", "restore", "purge"))
    quarantine.add_argument("path", nargs="?", default=".")
    quarantine.add_argument("--reason", default="", help="why the file is being quarantined (required for apply)")
    quarantine.add_argument("--index", default="", help="comma separated candidate numbers from the list output")
    quarantine.add_argument("--all", action="store_true", help="apply to every current candidate")
    quarantine.add_argument("--id", default="", help="stored item id for restore or purge")
    quarantine.add_argument("--latest", action="store_true", help="restore the most recently quarantined item")
    quarantine.add_argument("--dry-run", action="store_true")
    quarantine.add_argument("--json", action="store_true")

    guard = subparsers.add_parser("guard", help="inspect the interpreter guard and what it blocked")
    guard.add_argument("action", nargs="?", choices=("status", "denials", "policy"), default="status")
    guard.add_argument("--json", action="store_true")

    shield = subparsers.add_parser(
        "shield",
        help="run a command with the interpreter guard armed (blocks third-party egress, spawns and secret reads)",
    )
    # The positional is named argv, not command: the top level subparsers use
    # dest="command" to route the dispatch, and a second destination with that
    # name would overwrite the route with a list.
    shield.add_argument("argv", nargs=argparse.REMAINDER, help="command to run, after --")
    shield.add_argument("--allow", default="", help="comma separated module prefixes to allow")
    shield.add_argument("--watch", action="store_true", help="record instead of blocking")
    shield.add_argument(
        "--children",
        action="store_true",
        help="propagate the guard into Python child processes the command spawns",
    )

    deps = subparsers.add_parser("deps", help="audit the declared dependencies before installing them")
    deps.add_argument("path", nargs="?", default=".")
    deps.add_argument("--json", action="store_true")

    vulns = subparsers.add_parser("vulns", help="check declared dependencies against the OSV database")
    vulns.add_argument("path", nargs="?", default=".")
    vulns.add_argument("--online", action="store_true", help="query OSV now instead of replaying the cache")
    vulns.add_argument("--enrich", action="store_true", help="fetch each advisory for its summary and fix version")
    vulns.add_argument("--json", action="store_true", help="emit the advisories as JSON")

    suppress = subparsers.add_parser("suppress", help="review and record accepted scanner findings")
    suppress.add_argument("action", choices=("list", "add", "reset"))
    suppress.add_argument("path", nargs="?", default=".")
    suppress.add_argument("--reason", default="", help="why these findings are accepted (required for add)")
    suppress.add_argument("--index", default="", help="comma separated candidate numbers from the list output")
    suppress.add_argument("--all", action="store_true", help="accept every current candidate")

    setup = subparsers.add_parser("setup", help="one-command onboarding: doctor, git gate, credential baseline")
    setup.add_argument("path", nargs="?", default=".")
    setup.add_argument("--no-hook", action="store_true", help="do not install the git pre-commit gate")
    setup.add_argument(
        "--baseline",
        action="store_true",
        help="also record current credential candidates as accepted (off by default)",
    )

    baseline = subparsers.add_parser("baseline", help="record current credential findings as accepted")
    baseline.add_argument("path", nargs="?", default=".")
    baseline.add_argument("--reset", action="store_true", help="delete the stored baseline")
    baseline.add_argument(
        "--memory",
        action="store_true",
        help="capture the executable memory baseline instead of the credential one",
    )

    honey = subparsers.add_parser("honeytoken", help="deploy or inspect decoy credential traps")
    honey.add_argument("action", choices=("deploy", "status", "remove"))
    honey.add_argument("path", nargs="?", default=".")
    honey.add_argument("--force", action="store_true", help="replace an occupied path when deploying")

    canary = subparsers.add_parser("canary", help="deploy or inspect the ransomware canary farm")
    canary.add_argument("action", choices=("deploy", "status", "remove"))
    canary.add_argument("path", nargs="?", default=".")
    canary.add_argument(
        "--max-files",
        type=int,
        default=40,
        help="hard cap on decoys across the whole tree",
    )
    canary.add_argument(
        "--per-directory",
        type=int,
        default=1,
        help="decoys planted in each eligible directory",
    )
    canary.add_argument(
        "--kinds",
        default="",
        help="comma separated decoy families (sheet, document, pdf, notes); empty uses all",
    )

    shim = subparsers.add_parser("shim", help="install or inspect the undo-aware delete wrapper")
    shim.add_argument("action", choices=("install", "uninstall", "status", "print"))
    shim.add_argument("--shell", choices=("auto", "bash", "powershell"), default="auto")
    shim.add_argument("--override-rm", action="store_true", help="also wrap the real rm command")

    watch = subparsers.add_parser("watch", help="watch a project for canary and entropy events")
    watch.add_argument("path", nargs="?", default=".")
    watch.add_argument("--interval", type=float, default=1.0, help="poll interval in seconds")
    watch.add_argument("--duration", type=float, default=None, help="stop after this many seconds")
    watch.add_argument("--freeze", action="store_true", help="freeze a process caught writing a canary")
    watch.add_argument(
        "--backend",
        choices=("auto", "linux", "windows", "polling"),
        default="auto",
        help="kernel notification backend; auto selects the best available one",
    )

    verify = subparsers.add_parser("verify", help="verify the integrity stamp of a dossier")
    verify.add_argument("report")
    verify.add_argument("--key", default=None, help="64 hex characters or a path to a key file")
    verify.add_argument("--no-machine-key", action="store_true", help="ignore the host derived key")

    bench = subparsers.add_parser("bench", help="measure the primary command paths")
    bench.add_argument("--root", default=".")
    bench.add_argument("--runs", type=int, default=3)
    bench.add_argument("--json", action="store_true")

    return parser


def command_audit(args: argparse.Namespace) -> int:
    """Run a scan, print the pillar matrix and return a CI friendly code."""

    formats = tuple(part.strip() for part in str(args.export).split(",") if part.strip())
    if not formats:
        return _error("no export formats requested")
    options = ScanOptions(
        export_formats=formats,
        deep=bool(args.deep),
        generate_repro=not bool(args.no_repro),
    )
    try:
        result = run_scan(args.target, options=options, out_dir=args.out)
    except ScanError as exc:
        return _error(str(exc))
    if args.json:
        payload = {
            "target": str(result.target),
            "verdict": result.verdict.name,
            "risk": result.verdict.risk,
            "duration_ms": round(result.duration_ms, 1),
            "findings": [
                {
                    "pillar": finding.pillar,
                    "status": finding.status,
                    "detail": finding.detail,
                    "risk": finding.risk,
                }
                for finding in (result.finding(number) for number in range(1, 13))
            ],
            "reports": {key: str(value) for key, value in result.report_paths.items()},
            "warnings": list(result.warnings),
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
    else:
        print(f"TAUHAULITY SCAN - {result.target}")
        print("-" * 78)
        for number in range(1, 13):
            finding = result.finding(number)
            print(f"P{number:02d} [{finding.status:<17}] risk {finding.risk:4.1f}  {finding.detail[:60]}")
        print("-" * 78)
        print("verdict: " + summarize(result))
        for name, path in result.report_paths.items():
            print(f"report[{name}]: {path}")
        for warning in result.warnings:
            print("warning: " + warning)
    return _VERDICT_EXIT.get(result.verdict.name, EXIT_AT_RISK)


def command_undo(args: argparse.Namespace) -> int:
    """List or restore captured undo entries."""

    from tauhaulity.daemon.undo_store import UndoStore

    root = Path(args.root).resolve()
    store = UndoStore(root, ring_mb=Policy.load(policy_path(root)).undo_ring_mb)
    if args.list or args.id is None:
        entries = store.list_entries(limit=20)
        if not entries:
            print(f"undo net empty for {root}")
            return EXIT_OK
        print(f"undo entries under {root} (usage {store.usage_bytes()} bytes)")
        for entry in entries:
            print(f"  {entry.entry_id}  {entry.created_at}  {entry.bytes:>8} bytes  {len(entry.paths)} path(s)")
            for path in entry.paths[:5]:
                print(f"      {path}")
        if args.list:
            return EXIT_OK
    result = store.restore(args.id)
    print(result.message)
    return EXIT_OK if result.restored else EXIT_AT_RISK


def command_rm(args: argparse.Namespace) -> int:
    """Capture then delete the requested paths through the undo ring."""

    from tauhaulity.daemon.undo_store import UndoStore

    root = Path(args.root).resolve()
    policy = Policy.load(policy_path(root))
    store = UndoStore(root, ring_mb=policy.undo_ring_mb)
    targets: list[Path] = []
    for raw in args.paths:
        candidate = Path(raw)
        if not candidate.exists():
            return _error(f"path does not exist: {candidate}")
        targets.append(candidate)
    if args.dry_run:
        preview_fn = getattr(store, "preview", None)
        preview = preview_fn(targets) if callable(preview_fn) else [str(target) for target in targets]
        print(f"dry run: would capture and delete {len(preview)} item(s)")  # preview only
        for line in preview:
            print(f"  {line}")
        return EXIT_OK
    entries = store.capture(targets)
    for entry in entries:
        print(f"captured {entry.entry_id} ({entry.bytes} bytes, {len(entry.paths)} path(s))")
    for target in targets:
        if target.is_dir():
            shutil.rmtree(target)
        else:
            target.unlink()
        print(f"removed {target}")
    print(f"run '{invocation_prefix()} undo --root {root}' to restore")
    return EXIT_OK


def _confirm(question: str) -> bool:
    """Ask a yes/no question only when a human is actually present.

    A destructive command must never read a script's stdin by accident, so a
    non interactive session is treated as "no" and the caller is told to pass
    --yes explicitly.
    """

    if not sys.stdin.isatty():
        return False
    try:
        answer = input(question + " [y/N] ")
    except (EOFError, KeyboardInterrupt, OSError):
        return False
    return answer.strip().lower() in {"y", "yes"}


def command_free(args: argparse.Namespace) -> int:
    """Release a port, previewing first unless the caller confirmed.

    The preview always names the owning processes before anything is signalled,
    because a diagnostic tool that silently kills the wrong process is worse than
    the port conflict it was asked to solve.
    """

    from tauhaulity.tools import port_sweeper

    if not 1 <= args.port <= 65535:
        return _error("port must be within 1..65535")
    preview_fn = getattr(port_sweeper, "describe_port_action", None)
    try:
        preview = preview_fn(args.port) if callable(preview_fn) else f"port {args.port}: owner preview unavailable"
    except (OSError, RuntimeError, ValueError) as exc:
        preview = f"port {args.port}: preview failed: {exc}"
    if args.dry_run:
        print(preview)
        print("dry run: nothing was signalled")
        return EXIT_OK
    confirmed = bool(args.yes)
    if not confirmed:
        print(preview)
        confirmed = _confirm(f"terminate the process holding port {args.port}?")
    if not confirmed:
        # The prompt may be answered "n", or stdin may be a pipe or a null device
        # that reports itself as a character device on Windows. Both cases exit
        # without signalling anything, and both point at the explicit --yes flag.
        print("confirmation declined or unavailable; re-run with --yes to terminate the owner", file=sys.stderr)
        return EXIT_AT_RISK
    result = port_sweeper.free_port(args.port, force_after_ms=0 if args.force else 500, dry_run=False)
    print(result.message)
    for pid in result.killed:
        print(f"  terminated pid {pid}")
    return EXIT_OK if result.released else EXIT_AT_RISK


def command_ports(args: argparse.Namespace) -> int:
    """List listening sockets from the native kernel table."""

    from tauhaulity.tools.port_sweeper import list_listening

    entries = list_listening()
    if args.json:
        print(
            json.dumps(
                [
                    {
                        "protocol": entry.protocol,
                        "address": entry.local_address,
                        "port": entry.local_port,
                        "pid": entry.pid,
                        "state": entry.state,
                    }
                    for entry in entries
                ],
                indent=2,
            )
        )
        return EXIT_OK
    print(f"{'PROTO':<6}{'ADDRESS':<28}{'PORT':>6}  {'PID':>8}  STATE")
    for entry in entries:
        pid_value = getattr(entry, "pid", None)
        pid = "-" if not pid_value else str(pid_value)
        port = getattr(entry, "local_port", None)
        if port is None:
            port = getattr(entry, "port", 0)
        address = getattr(entry, "local_address", "") or "*"
        print(f"{entry.protocol:<6}{address:<28}{port:>6}  {pid:>8}  {entry.state}")
    print(f"{len(entries)} listening socket(s)")
    return EXIT_OK


def command_hook(args: argparse.Namespace) -> int:
    """Install, remove or report the git pre-commit secret gate."""

    from tauhaulity.tools.hook_installer import hook_status, install_hook, uninstall_hook

    root = Path(args.path).resolve()
    if args.action == "install":
        path = install_hook(root, block=not args.warn_only)
        print(f"installed pre-commit gate at {path}")
        return EXIT_OK
    if args.action == "uninstall":
        removed = uninstall_hook(root)
        print("pre-commit gate removed" if removed else "no tauhaulity gate was installed")
        return EXIT_OK if removed else EXIT_AT_RISK
    installed, path = hook_status(root)
    print(("installed at " if installed else "not installed; checked ") + str(path))
    return EXIT_OK if installed else EXIT_AT_RISK


def command_venv(args: argparse.Namespace) -> int:
    """Inspect a virtual environment for .pth injection and rogue binaries."""

    from tauhaulity.tools.venv_radar import inspect_venv

    target = Path(args.path).resolve()
    if not target.exists():
        # Every other command treats a missing target as a usage error; agreeing
        # here keeps a scripted caller from having to special case this one.
        return _error(f"venv-check target does not exist: {target}")
    report = inspect_venv(target)
    if args.json:
        print(
            json.dumps(
                {
                    "venv": str(report.venv_path),
                    "status": report.status,
                    "detail": report.detail,
                    "pth_files": report.pth_files,
                    "pth_findings": [
                        {
                            "rel_path": finding.rel_path,
                            "line_no": finding.line_no,
                            "code": finding.code,
                            "severity": finding.severity,
                        }
                        for finding in report.pth_findings
                    ],
                    "suspicious_binaries": list(report.suspicious_binaries),
                    "permission_anomalies": list(report.permission_anomalies),
                },
                indent=2,
            )
        )
    else:
        print(f"venv: {report.venv_path}")
        print(f"status: {report.status} - {report.detail}")
        for finding in report.pth_findings:
            print(f"  {finding.rel_path}:{finding.line_no} [{finding.severity}] {finding.code}")
        for binary in report.suspicious_binaries:
            print(f"  rogue binary: {binary}")
    return EXIT_OK if report.status == "CLEAN" else EXIT_AT_RISK


def command_apply(args: argparse.Namespace) -> int:
    """Merge the checked boxes of a dossier form into the project policy."""

    from tauhaulity.dossier.form_parser import FormError, parse_form

    form_path = Path(args.form)
    if not form_path.is_file():
        return _error(f"form not found: {form_path}")
    root = Path(args.root).resolve()
    try:
        overrides = parse_form(form_path.read_text(encoding="utf-8"))
    except FormError as exc:
        return _error(f"invalid form: {exc}")
    current = Policy.load(policy_path(root))
    try:
        merged = current.with_overrides(overrides)
    except PolicyError as exc:
        return _error(f"invalid policy: {exc}")
    written = merged.save(policy_path(root))
    print(f"policy updated at {written}")
    for key, value in merged.to_dict().items():
        print(f"  {key} = {value}")
    return EXIT_OK


def command_doctor(args: argparse.Namespace) -> int:
    """Run the self diagnostic and print the capability table."""

    from tauhaulity.doctor import run_doctor

    report = run_doctor(args.root)
    if args.json:
        print(
            json.dumps(
                {
                    "platform": report.platform_label,
                    "ok": report.ok,
                    "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in report.checks],
                },
                indent=2,
            )
        )
    else:
        print(report.render())
    return EXIT_OK if report.ok else EXIT_AT_RISK


def command_diff(args: argparse.Namespace) -> int:
    """Compare two JSON dossiers and print the status deltas."""

    try:
        old = json.loads(Path(args.old).read_text(encoding="utf-8"))
        new = json.loads(Path(args.new).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return _error(f"cannot read dossier: {exc}")
    old_rows = {int(row["pillar"]): row for row in old.get("pillars", [])}
    new_rows = {int(row["pillar"]): row for row in new.get("pillars", [])}
    changes = 0
    for number in sorted(set(old_rows) | set(new_rows)):
        before = old_rows.get(number, {}).get("status", "MISSING")
        after = new_rows.get(number, {}).get("status", "MISSING")
        if before != after:
            changes += 1
            print(f"P{number:02d} {before:<17} -> {after}")
    print(f"{changes} changed pillar(s); verdict {old.get('verdict')} -> {new.get('verdict')}")
    return EXIT_OK if changes == 0 else EXIT_AT_RISK


def _resolve_shell(requested: str) -> str:
    """Map the auto shell choice onto the shell the user is actually running.

    A Windows user inside Git Bash needs the bash wrapper, so the shim module is
    asked first and the platform name is only the last resort.
    """

    if requested != "auto":
        return requested
    try:
        from tauhaulity.tools.shim import shell_from_environment

        detected = shell_from_environment()
        if detected:
            return detected
    except (ImportError, AttributeError, OSError):
        pass
    return "powershell" if os.name == "nt" else "bash"


def _parse_signing_key(raw: str) -> bytes:
    """Accept a hex key or a path to a key file.

    Raises:
        ValueError: When the value is neither 64 hex characters nor a readable
            file containing a hex key or raw bytes.
    """

    candidate = Path(raw)
    if candidate.is_file():
        material = candidate.read_bytes()
        text = material.decode("ascii", errors="ignore").strip()
        if len(text) == 64 and all(char in "0123456789abcdefABCDEF" for char in text):
            return bytes.fromhex(text)
        if material:
            return material
        raise ValueError(f"key file is empty: {candidate}")
    compact = raw.strip()
    if len(compact) == 64 and all(char in "0123456789abcdefABCDEF" for char in compact):
        return bytes.fromhex(compact)
    raise ValueError("--key must be 64 hex characters or a path to a key file")


def command_setup(args: argparse.Namespace) -> int:
    """Run the one-command onboarding sequence.

    The sequence is ordered so the tool is useful even when a later step is
    skipped: capability check, git gate (only inside a repository), credential
    baseline, then the exact next commands to type.
    """

    root = Path(args.path).resolve()
    if not root.is_dir():
        return _error(f"setup target is not a directory: {root}")
    from tauhaulity.doctor import run_doctor

    report = run_doctor(root)
    print(f"tauhaulity setup - {root}")
    for check in report.checks:
        marker = "PASS" if check.ok else "FAIL"
        print(f"  [{marker}] {check.name:<22} {check.detail}")
    if not report.ok:
        print("setup stopped: fix the failing capabilities above first", file=sys.stderr)
        return EXIT_AT_RISK
    if not args.no_hook:
        if (root / ".git").exists():
            from tauhaulity.tools.hook_installer import hook_status, install_hook

            installed, path = hook_status(root)
            if installed:
                print(f"  [SKIP] git gate already installed at {path}")
            else:
                print(f"  [DONE] git gate installed at {install_hook(root)}")
        else:
            print("  [SKIP] git gate: no .git directory in this target")
    if args.baseline:
        from tauhaulity.tools.allowlist import write_baseline

        baseline = write_baseline(root)
        print(f"  [DONE] credential baseline: {baseline.added} accepted finding(s) in {baseline.path}")
        print("  [WARN] accepted findings will no longer block commits; review the baseline before pushing")
    else:
        from tauhaulity.tools.git_sentinel import inspect_repository

        # Deliberately do not baseline automatically: onboarding often happens
        # while a real .env is staged, and silently accepting it would whitelist
        # the exact leak the gate exists to stop.
        inspection = inspect_repository(root)
        print(f"  [INFO] {inspection.leak_count} credential candidate(s) visible; "
              "run 'tauhaulity baseline' only for known fixtures")
    prefix = invocation_prefix()
    print("next steps:")
    print(f"  {prefix}                    # 12-pillar scan and dossier export")
    print(f"  {prefix} shim install       # optional: undo-aware delete wrapper")
    return EXIT_OK


def command_baseline(args: argparse.Namespace) -> int:
    """Record or reset the accepted credential findings of a project."""

    from tauhaulity.tools.allowlist import remove_baseline, write_baseline

    root = Path(args.path).resolve()
    if not root.is_dir():
        return _error(f"baseline target is not a directory: {root}")
    if args.memory:
        from tauhaulity.pillars.p01_memory import memory_baseline_capture

        print(memory_baseline_capture(root))
        print(f"run '{invocation_prefix()} audit' to compare the live process against this baseline")
        return EXIT_OK
    if args.reset:
        removed = remove_baseline(root)
        print("baseline removed" if removed else "no baseline to remove")
        return EXIT_OK
    report = write_baseline(root)
    print(f"baseline written to {report.path}")
    print(f"  accepted findings: {report.added}")
    for preview in list(getattr(report, "active_preview", ()))[:5]:
        print(f"  {preview}")
    return EXIT_OK


def command_canary(args: argparse.Namespace) -> int:
    """Deploy, inspect or remove the canary farm decoys.

    The farm is explicit because planting decoy files inside a project changes the
    tree the user owns. Deployment is idempotent and refuses to overwrite a file
    it did not create, so a repeated run is safe; the watch loop only monitors a
    farm that was armed deliberately.
    """

    from tauhaulity.daemon.canary import (
        CanaryFarmError,
        canary_farm_status,
        deploy_canary_farm,
        remove_canary_farm,
    )

    root = Path(args.path).resolve()
    if not root.is_dir():
        return _error(f"canary target is not a directory: {root}")
    try:
        if args.action == "deploy":
            raw_kinds = tuple(
                part.strip() for part in str(args.kinds).split(",") if part.strip()
            )
            report = deploy_canary_farm(
                root,
                per_directory=int(args.per_directory),
                max_files=int(args.max_files),
                kinds=raw_kinds or None,
            )
            print(canary_farm_status(root))
            print(f"manifest: {report.manifest_path}")
            print(
                "monitor the farm with '"
                + invocation_prefix()
                + " watch .' so a decoy tamper is reported with its kind"
            )
            return EXIT_OK
        if args.action == "remove":
            removed = remove_canary_farm(root)
            if removed:
                print(f"canary farm removed: {removed} decoy(s)")
            else:
                print("canary farm: none armed")
            return EXIT_OK
        print(canary_farm_status(root))
        return EXIT_OK
    except CanaryFarmError as exc:
        return _error(str(exc))


def command_shim(args: argparse.Namespace) -> int:
    """Install, remove or inspect the undo-aware delete wrapper."""

    from tauhaulity.tools.shim import install_shim, shim_script, shim_status, uninstall_shim

    shell = _resolve_shell(args.shell)
    if args.action == "print":
        # The snippet must match what install writes: no baked root, so the
        # wrapper journals into whatever project directory the user is in.
        print(shim_script(shell, python=sys.executable))
        return EXIT_OK
    if args.action == "install":
        path = install_shim(shell, override_rm=args.override_rm)
        print(f"shim installed for {shell} in {path}")
        if args.override_rm:
            print("warning: the real rm command now routes through tauhaulity rm")
        return EXIT_OK
    if args.action == "uninstall":
        removed = uninstall_shim(shell)
        print("shim removed" if removed else "shim was not installed")
        return EXIT_OK if removed else EXIT_AT_RISK
    installed, path = shim_status(shell)
    print(("installed at " if installed else "not installed; checked ") + str(path))
    return EXIT_OK if installed else EXIT_AT_RISK


def command_watch(args: argparse.Namespace) -> int:
    """Watch a project for canary and entropy events until stopped."""

    from tauhaulity.daemon.canary import canary_farm_status
    from tauhaulity.daemon.watch import watch_loop
    from tauhaulity.tools.backup_guard import attach_to_guard, detected_signals

    root = Path(args.path).resolve()
    if not root.is_dir():
        return _error(f"watch target is not a directory: {root}")

    # Backup destruction happens before encryption starts, so the watch loop arms
    # the command observer: a live process that tries to delete shadow copies is
    # reported while the decoys are still intact.
    observer_armed = attach_to_guard()
    if observer_armed:
        print("backup observer: armed (shadow copy and backup deletion shapes)")
    print(canary_farm_status(root))

    def emit(event: object) -> None:
        kind = getattr(event, "kind", "event")
        path = getattr(event, "path", "")
        detail = getattr(event, "detail", "")
        print(f"[{kind}] {path}: {detail}")

    def announce(backend_name: str) -> None:
        print(f"watch backend: {backend_name}")

    try:
        count = watch_loop(
            root,
            interval_s=args.interval,
            duration_s=args.duration,
            freeze=bool(args.freeze),
            on_event=emit,
            backend=args.backend,
            on_backend=announce,
        )
    except KeyboardInterrupt:
        print("watch interrupted")
        return EXIT_OK
    print(f"watch stopped after {count} event(s)")
    if observer_armed:
        signals = detected_signals(limit=8)
        if signals:
            print(f"backup tampering signals: {len(signals)}")
            for signal in signals:
                print(f"  {signal.get('kind', '')}: {signal.get('command', '')[:110]}")
        else:
            print("backup tampering signals: none observed")
    return EXIT_OK


def command_verify(args: argparse.Namespace) -> int:
    """Verify the integrity stamp of a generated dossier."""

    from tauhaulity.dossier.verify import verify_dossier_file

    try:
        key = _parse_signing_key(args.key) if args.key else None
    except ValueError as exc:
        return _error(str(exc))
    result = verify_dossier_file(
        Path(args.report),
        key=key,
        use_machine_key=not args.no_machine_key,
    )
    print("VALID" if result.valid else "INVALID")
    print(f"  scheme    : {result.scheme}")
    print(f"  digest    : {getattr(result, 'digest', '')}")
    print(f"  key source: {getattr(result, 'key_source', '')}")
    print(f"  reason    : {result.reason}")
    return EXIT_OK if result.valid else EXIT_AT_RISK


def _print_suppression_candidates(keys: list) -> None:
    """Render the reviewable candidate list with stable numbering."""

    print("review the findings below, then accept the ones you have verified:")
    for index, key in enumerate(keys, start=1):
        symbol = key.symbol or "<module>"
        print(f"  [{index}] {key.rel_path}:{key.line_no}  {key.kind}  {symbol}  {key.fingerprint[:12]}")


def command_deps(args: argparse.Namespace) -> int:
    """Audit the dependency declarations of a project.

    This runs before anything is installed, which is the only moment a typosquat
    or a direct URL dependency can still be refused cheaply.
    """

    from tauhaulity.tools.dep_audit import audit_dependencies

    root = Path(args.path).resolve()
    if not root.is_dir():
        return _error(f"deps target is not a directory: {root}")
    report = audit_dependencies(root)
    if args.json:
        print(
            json.dumps(
                {
                    "declared": report.declared,
                    "files_scanned": report.files_scanned,
                    "detail": report.detail,
                    "findings": [asdict(finding) for finding in report.findings],
                },
                indent=2,
            )
        )
        return EXIT_AT_RISK if report.findings else EXIT_OK
    print(f"declared dependencies : {report.declared} in {report.files_scanned} file(s)")
    print(f"result                : {report.detail}")
    for finding in report.findings:
        location = f"{finding.rel_path}:{finding.line_no}" if finding.line_no else finding.rel_path
        print(f"  [{finding.severity}] {finding.kind}: {finding.name} ({location}) - {finding.detail}")
    return EXIT_AT_RISK if report.findings else EXIT_OK


def command_posture(args: argparse.Namespace) -> int:
    """Report what is protecting this project right now, and what it cannot cover.

    The README lists the threat classes this tool does not defend against. A reader
    cannot act on a paragraph, so this command turns the same list into a per-machine
    checklist: the controls that are live, the ones that are stale or missing, and
    the companion each uncovered class needs.
    """

    from tauhaulity.tools.posture import as_dict, posture, render_text

    root = Path(args.path).resolve()
    if not root.is_dir():
        return _error(f"posture target is not a directory: {root}")
    report = posture(root)
    if args.json:
        print(json.dumps(as_dict(report), indent=2))
    else:
        print(render_text(report))
    problems = report.problems()
    if args.strict and problems:
        return EXIT_AT_RISK
    return EXIT_OK


def command_feed(args: argparse.Namespace) -> int:
    """Report the age of the cached threat data, or refresh it.

    A security tool that silently runs on year-old data is a liability, so the age
    is printed on demand and pillar six repeats it in every scan. The status action
    never touches the network; refresh is the only action that does.
    """

    from tauhaulity.tools import threat_feed

    root = Path.cwd()
    if args.action == "refresh":
        status = threat_feed.refresh(root=root)
    else:
        status = threat_feed.status(root=root, stale_after_days=int(args.stale_after_days))
    if args.json:
        print(
            json.dumps(
                {
                    "stale": status.stale,
                    "stale_after_days": status.stale_after_days,
                    "detail": status.detail,
                    "snapshots": [
                        {
                            "kind": snapshot.kind,
                            "source": snapshot.source,
                            "captured_at": snapshot.captured_at,
                            "age_days": snapshot.age_days,
                            "entries": len(snapshot.entries),
                        }
                        for snapshot in status.snapshots
                    ],
                },
                indent=2,
            )
        )
        return EXIT_AT_RISK if status.stale else EXIT_OK
    print(f"threat data : {status.detail}")
    print(f"stale       : {status.stale} (limit {status.stale_after_days} day(s))")
    for snapshot in status.snapshots:
        age = f"{snapshot.age_days:.2f}" if snapshot.age_days >= 0 else "unknown"
        print(f"  {snapshot.kind:<10} {age:>8} day(s)  {len(snapshot.entries):>3} entrie(s)  {snapshot.source}")
    if not status.snapshots:
        print("  no snapshot cached; run 'tauhaulity feed refresh'")
    return EXIT_AT_RISK if status.stale else EXIT_OK


def command_ci(args: argparse.Namespace) -> int:
    """Run every gate a pipeline needs and return one exit code.

    A CI job needs one number, not five commands to remember. This runs the scan,
    the dependency declaration audit and the advisory check, prints one line per
    gate with the reason it failed, and maps the result to an exit code the shell
    can act on. Network use is opt in so a pipeline without egress still works.
    """

    root = Path(args.path).resolve()
    if not root.is_dir():
        return _error(f"ci target is not a directory: {root}")

    gates: list[dict[str, object]] = []
    worst = 0

    from tauhaulity.core.contracts import ScanOptions
    from tauhaulity.core.policy import Policy
    from tauhaulity.engine import run_scan

    try:
        result = run_scan(
            root,
            policy=Policy(),
            options=ScanOptions(generate_repro=False, record_telemetry=False),
        )
        verdict = result.verdict.name
        score = result.scorecard.score if getattr(result, "scorecard", None) else 0
        blocking = {"CRITICAL", "LEAK_DETECTED", "TAMPERED", "MALICIOUS_PTH", "UNPROTECTED", "CACHE_POISONED", "MISMATCH"}
        advisory = {"WARNING", "CONFLICT_DETECTED", "ZOMBIE_FOUND", "UNPINNED", "STALE"}
        wanted = blocking | (advisory if args.fail_on == "warning" else set())
        # The context keeps findings keyed by pillar number, not in a list.
        findings = list(result.ctx.findings.values()) if isinstance(result.ctx.findings, dict) else list(result.ctx.findings)
        failing = [finding for finding in findings if getattr(finding, "status", "") in wanted]
        status = "fail" if failing and args.fail_on != "none" else "pass"
        if failing and args.fail_on != "none":
            worst = max(worst, EXIT_AT_RISK)
        # A CI job should not leave dossier files behind in the working tree.
        for suffix in ("md", "txt", "json"):
            stale_report = root / f"tauhaulity_report.{suffix}"
            if stale_report.is_file():
                try:
                    stale_report.unlink()
                except OSError:
                    pass
        if (root / ".tauhaulity").is_dir():
            shutil.rmtree(root / ".tauhaulity", ignore_errors=True)
        gates.append(
            {
                "gate": "scan",
                "status": status,
                "detail": f"{verdict} | score {score}/100 | {len(failing)} blocking finding(s)",
                "pillars": [finding.pillar for finding in failing][:6],
            }
        )
    except Exception as exc:
        gates.append({"gate": "scan", "status": "error", "detail": f"{type(exc).__name__}: {exc}"})
        worst = max(worst, EXIT_ERROR)

    if not args.no_deps:
        try:
            from tauhaulity.tools.dep_audit import audit_dependencies

            deps = audit_dependencies(root)
            bad = [finding for finding in deps.findings if finding.severity in {"high", "medium"}]
            if bad and args.fail_on != "none":
                worst = max(worst, EXIT_AT_RISK)
            gates.append(
                {
                    "gate": "dependencies",
                    "status": "fail" if bad and args.fail_on != "none" else "pass",
                    "detail": deps.detail[:180],
                    "findings": [f"{finding.kind}:{finding.name}" for finding in bad][:8],
                }
            )
        except Exception as exc:
            gates.append({"gate": "dependencies", "status": "error", "detail": f"{type(exc).__name__}: {exc}"})

    if not args.no_vulns:
        try:
            from tauhaulity.tools.osv_client import declared_dependencies, load_cache, query, save_cache

            references, _notes = declared_dependencies(root)
            cache_path = root / ".tauhaulity" / "osv-last.json"
            report = None
            if args.online:
                report = query(references)
                if report.source == "osv-api" and not report.detail.startswith("OSV lookup failed"):
                    save_cache(report, cache_path)
            if report is None:
                report = load_cache(cache_path)
            if report is None:
                gates.append({"gate": "advisories", "status": "unknown", "detail": "no cached result; run with --online once"})
            else:
                if report.count and args.fail_on != "none":
                    worst = max(worst, EXIT_AT_RISK)
                gates.append(
                    {
                        "gate": "advisories",
                        "status": "fail" if report.count and args.fail_on != "none" else "pass",
                        "detail": f"{report.detail} (source: {report.source})",
                        "advisories": [f"{item.package}:{item.vuln_id}" for item in report.vulnerabilities][:8],
                    }
                )
        except Exception as exc:
            gates.append({"gate": "advisories", "status": "error", "detail": f"{type(exc).__name__}: {exc}"})

    if args.json:
        print(json.dumps({"gates": gates, "exit_code": worst}, indent=2))
        return worst
    for gate in gates:
        print(f"[{str(gate['status']).upper():<7}] {gate['gate']:<13} {gate['detail']}")
        for extra in ("pillars", "findings", "advisories"):
            values = gate.get(extra)
            if values:
                print(f"          {extra}: " + ", ".join(str(value) for value in values))
    print()
    print("exit code: " + str(worst) + (" (fail)" if worst else " (pass)"))
    return worst


def command_quarantine(args: argparse.Namespace) -> int:
    """List, apply, restore or purge quarantined artefacts.

    Quarantine is the one prevention step that works without kernel access, so the
    command shows the file name before it moves anything and always records the
    reviewer's reason. The stored copy is byte exact and restorable.
    """

    from tauhaulity.tools.quarantine import QuarantineError, QuarantineStore, suggest_quarantine

    root = Path(args.path).resolve()
    if not root.is_dir():
        return _error(f"quarantine target is not a directory: {root}")
    store = QuarantineStore(root)

    if args.action == "list":
        candidates = suggest_quarantine(root)
        items = store.list_items()
        if args.json:
            print(
                json.dumps(
                    {
                        "candidates": [str(path.relative_to(root)) for path in candidates],
                        "stored": [asdict(item) for item in items],
                        "usage_bytes": store.usage_bytes(),
                    },
                    indent=2,
                    default=str,
                )
            )
            return EXIT_OK
        if candidates:
            print("eligible artefacts (the evidence is the file itself):")
            for index, path in enumerate(candidates, start=1):
                try:
                    size = path.stat().st_size
                except OSError:
                    size = 0
                print(f"  [{index}] {path.relative_to(root)}  ({size} bytes)")
        else:
            print("no eligible artefact found")
        if items:
            print(f"already quarantined ({len(items)} item(s), {store.usage_bytes()} bytes):")
            for item in items:
                print(f"  {item.item_id}  {item.kind}  {item.original_path}  {item.quarantined_at}")
        return EXIT_OK

    if args.action == "restore":
        item_id = args.id
        if not item_id and args.latest:
            items = store.list_items()
            if not items:
                return _error("the quarantine store is empty")
            item_id = items[-1].item_id
        if not item_id:
            return _error("restore needs --id or --latest")
        restored = store.restore(item_id)
        print(f"restored {item_id}" if restored else f"restore refused for {item_id}")
        return EXIT_OK if restored else EXIT_AT_RISK

    if args.action == "purge":
        if not args.id and not args.all:
            return _error("purge needs --id or --all; quarantined files are never deleted automatically")
        removed = store.purge(args.id or None)
        print(f"purged {removed} item(s)")
        return EXIT_OK

    # apply
    if not args.reason.strip():
        return _error("apply requires --reason: a quarantine always records why")
    candidates = suggest_quarantine(root)
    if not candidates:
        print("no eligible artefact found")
        return EXIT_OK
    if args.all:
        selected = list(candidates)
    else:
        raw = [part.strip() for part in args.index.split(",") if part.strip()]
        if not raw:
            return _error("apply requires --index 1,3 or --all")
        selected = []
        for part in raw:
            if not part.isdigit():
                return _error(f"--index expects numbers, got {part!r}")
            position = int(part)
            if not 1 <= position <= len(candidates):
                return _error(f"--index {position} is outside 1..{len(candidates)}")
            selected.append(candidates[position - 1])
    # Record the real finding kind, not just the file: the manifest is what a
    # reviewer reads later, and "unknown" would lose the reason it was taken.
    kinds: dict[str, str] = {}
    try:
        from tauhaulity.tools.artifact_scan import scan_source_tree

        scanned = scan_source_tree(root)
        for finding in scanned.findings:
            if finding.quarantine_eligible:
                kinds[str((root / finding.rel_path).resolve())] = finding.kind
    except Exception:
        kinds = {}
    print("about to quarantine: " + ", ".join(path.relative_to(root).as_posix() for path in selected))
    try:
        report = store.quarantine(selected, reason=args.reason, kinds=kinds or None, dry_run=args.dry_run)
    except QuarantineError as exc:
        return _error(str(exc))
    print(report.detail)
    for item in report.items:
        print(f"  {item.item_id}  {item.kind}  {item.original_path} -> {item.stored_path}")
    for entry in report.skipped:
        print(f"  skipped: {entry}")
    if args.dry_run:
        print("dry run: nothing was moved")
    return EXIT_OK


def command_guard(args: argparse.Namespace) -> int:
    """Report the guard policy and what it has blocked in this process."""

    from tauhaulity.runtime import audit_hook

    if args.action == "policy":
        policy = audit_hook.GuardPolicy.from_env()
        payload = asdict(policy)
        print(json.dumps(payload, indent=2) if args.json else chr(10).join(f"{k}: {v}" for k, v in payload.items()))
        return EXIT_OK
    if args.action == "denials":
        entries = audit_hook.guard.denials(limit=32)
        if args.json:
            print(json.dumps(entries, indent=2))
            return EXIT_AT_RISK if entries else EXIT_OK
        if not entries:
            print("no denial recorded in this process")
            return EXIT_OK
        for entry in entries:
            print(f"{entry.get('time', '')} {entry.get('kind', '')} -> {entry.get('target', '')} ({entry.get('flag', '')})")
        return EXIT_AT_RISK
    stats = audit_hook.guard.stats()
    if args.json:
        print(json.dumps(stats, indent=2))
        return EXIT_OK
    # active is a property on the guard object, not a method.
    active_value = getattr(audit_hook.guard, "active", False)
    if callable(active_value):
        active_value = active_value()
    print(f"guard active   : {active_value}")
    print(f"enforced       : {stats.get('enforce', False)}")
    print(f"events kept    : {stats.get('events', 0)}")
    print(f"denials        : {stats.get('denials', 0)}")
    print("policy         : " + str(stats.get("policy", {})))

    # A ransomware-shaped write burst is a summary, not a per-event stream: one
    # verdict means one wave, and the last verdict carries the suffix and examples.
    from tauhaulity.runtime import burst_summary

    summary = burst_summary()
    print(f"burst verdicts : {summary.get('verdicts', 0)} (threshold {summary.get('threshold')} ops in {summary.get('window_s')}s)")
    last = summary.get("last_verdict") or {}
    if last:
        print("last burst     : " + f"{last.get('volume')} ops, {last.get('dominance')} of {last.get('rename_count')} renames share {last.get('suffix')}")
        for example in last.get("examples", [])[:3]:
            print(f"                 {example}")
    return EXIT_OK


def command_shield(args: argparse.Namespace) -> int:
    """Run a child command with the guard armed.

    The guard is an audit hook, so it can only protect a process that installs it.
    Wrapping the interpreter is the practical way to put an untrusted script or a
    freshly installed dependency under containment without editing its code.
    """

    argv = [part for part in args.argv if part != "--"]
    if not argv:
        return _error("shield needs a command, for example: tauhaulity shield -- python app.py")
    from tauhaulity.runtime import audit_hook

    policy = audit_hook.GuardPolicy.from_env()
    allow = tuple(part.strip() for part in args.allow.split(",") if part.strip())
    policy = audit_hook.GuardPolicy(
        enforce=not args.watch,
        deny_third_party_connect=policy.deny_third_party_connect,
        deny_third_party_subprocess=policy.deny_third_party_subprocess,
        deny_sensitive_reads=policy.deny_sensitive_reads,
        allowlist=policy.allowlist + allow,
    )
    from tauhaulity.runtime import audit_hook as _hook
    from tauhaulity.runtime import _bootstrap

    env = dict(os.environ)
    env["TAUHAULITY_ENFORCE"] = "1" if not args.watch else "0"
    env["TAUHAULITY_GUARD_ALLOW"] = ",".join(policy.allowlist)
    env["TAUHAULITY_DENY_CONNECT"] = "1" if policy.deny_third_party_connect else "0"
    env["TAUHAULITY_DENY_SUBPROCESS"] = "1" if policy.deny_third_party_subprocess else "0"
    env["TAUHAULITY_DENY_DESERIALIZE"] = "1" if policy.deny_unsafe_deserialization else "0"
    env["TAUHAULITY_DENY_SECRET_EGRESS"] = "1" if policy.deny_egress_with_secrets else "0"
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1]) + os.pathsep + env.get("PYTHONPATH", "")

    shim_dir: Path | None = None
    if args.children:
        # A child interpreter that spawns its own Python workers escapes the hook,
        # so the shim puts arming into sitecustomize and marks the environment.
        child_env = _hook.guard_propagation(env)
        shim_root = child_env.get("PYTHONPATH", "").split(os.pathsep)[0]
        if shim_root:
            shim_dir = Path(shim_root)
        env = child_env
    wrapper = (
        "import runpy, sys;"
        "from tauhaulity.runtime import audit_hook;"
        "audit_hook.arm_shield();"
        "runpy.run_path(sys.argv[1], run_name='__main__')"
    )
    scope = "this process and its Python children" if args.children else "this process"
    print(f"shield: {'enforcing' if policy.enforce else 'watching'} {argv[0]}, scope {scope}, allowlist {policy.allowlist}")
    try:
        completed = subprocess.run([sys.executable, "-c", wrapper, argv[0], *argv[1:]], env=env, check=False)
    finally:
        if shim_dir is not None:
            _bootstrap.cleanup(shim_dir)
    return completed.returncode


def command_vulns(args: argparse.Namespace) -> int:
    """Check the declared dependencies against OSV.

    A scan must stay useful offline, so the cached answer is the default and the
    network is only contacted on request; when neither is available the command
    says so and exits with the "unavailable" code instead of pretending the
    project is clean.
    """

    from tauhaulity.tools.osv_client import OsvUnavailable, declared_dependencies, load_cache, query, save_cache
    from tauhaulity.tools.osv_client import OsvReport

    root = Path(args.path).resolve()
    if not root.is_dir():
        return _error(f"vulns target is not a directory: {root}")
    cache_path = root / ".tauhaulity" / "osv-last.json"
    references, notes = declared_dependencies(root)
    if not references:
        print("no declared dependency found (requirements*.txt or pyproject.toml)")
        for note in notes:
            print("  note: " + note)
        return EXIT_OK
    report: OsvReport | None = None
    if args.online:
        report = query(references, enrich=bool(args.enrich))
        if report.source == "osv-api" and not report.detail.startswith("OSV lookup failed"):
            save_cache(report, cache_path)
    if report is None or report.source != "osv-api":
        cached = load_cache(cache_path)
        if cached is not None and not args.online:
            report = cached
        elif report is None:
            report = OsvReport(skipped=tuple(item.name for item in references), detail="no OSV data available offline")

    if args.json:
        print(
            json.dumps(
                {
                    "declared": len(references),
                    "queried": report.queried,
                    "source": report.source,
                    "detail": report.detail,
                    "vulnerabilities": [asdict(item) for item in report.vulnerabilities],
                },
                indent=2,
            )
        )
        return EXIT_AT_RISK if report.count else EXIT_OK
    print(f"dependencies declared : {len(references)}")
    print(f"source                : {report.source}")
    print(f"result                : {report.detail}")
    for item in report.vulnerabilities:
        fix = item.fixed or "no fix recorded"
        print(f"  {item.package} {item.version}: {item.vuln_id} ({fix}) {item.url}")
    if report.skipped:
        print("unchecked (no pinned version): " + ", ".join(report.skipped[:10]))
    return EXIT_AT_RISK if report.count else EXIT_OK


def command_suppress(args: argparse.Namespace) -> int:
    """List, accept or clear reviewed scanner findings.

    Suppression exists so a project can be scanned by its own maintainers: a
    finding that has been reviewed and justified should stop failing the gate,
    but only with a recorded reason and only for the reviewed code symbol.
    """

    from tauhaulity.tools.suppress import (
        SuppressionError,
        SuppressionStore,
        list_suppression_candidates,
    )

    root = Path(args.path).resolve()
    if not root.is_dir():
        return _error(f"suppress target is not a directory: {root}")
    store = SuppressionStore(root)
    if args.action == "reset":
        removed = store.remove_all()
        print("suppression store cleared" if removed else f"no suppression store at {store.path}")
        return EXIT_OK
    try:
        keys = list_suppression_candidates(root)
    except SuppressionError as exc:
        return _error(f"cannot scan {root}: {exc}")
    if args.action == "list":
        entries = store.load()
        if not keys:
            print(f"no findings to review; {len(entries)} suppression(s) recorded in {store.path}")
            return EXIT_OK
        _print_suppression_candidates(keys)
        print(f"{len(keys)} candidate(s); {len(entries)} already recorded in {store.path}")
        return EXIT_OK
    if not args.reason.strip():
        return _error("add requires --reason with the review decision")
    if args.all:
        selected = list(keys)
    else:
        raw = [part.strip() for part in args.index.split(",") if part.strip()]
        if not raw:
            return _error("add requires --index 1,3 or --all")
        selected = []
        for part in raw:
            if not part.isdigit():
                return _error(f"--index expects numbers, got {part!r}")
            position = int(part)
            if not 1 <= position <= len(keys):
                return _error(f"--index {position} is outside 1..{len(keys)}")
            selected.append(keys[position - 1])
        selected = list(dict.fromkeys(selected))
    try:
        added = store.add(selected, args.reason)
    except SuppressionError as exc:
        return _error(str(exc))
    print(f"recorded {added} suppression(s) in {store.path}")
    for key in selected:
        print(f"  {key.rel_path}:{key.line_no}  {key.kind}  {key.symbol or '<module>'}")
    print(f"run '{invocation_prefix()} audit' to confirm the finding is now accepted, not hidden")
    return EXIT_OK


def command_honeytoken(args: argparse.Namespace) -> int:
    """Deploy, inspect or remove decoy credential traps.

    The traps are only useful together with the runtime guard, so the deploy
    output states the exact next step instead of implying that files alone
    protect anything.
    """

    from tauhaulity.tools.honeytoken import (
        HoneytokenError,
        deploy_report,
        honeytoken_status,
        remove,
    )

    root = Path(args.path).resolve()
    if not root.is_dir():
        return _error(f"honeytoken target is not a directory: {root}")
    try:
        if args.action == "deploy":
            print(deploy_report(root, force=bool(args.force)))
            print("arm the guard in the process you want to observe with:")
            print("  python -c 'import tauhaulity; tauhaulity.activate()'  (or set TAUHAULITY_ENFORCE=1)")
            return EXIT_OK
        if args.action == "remove":
            removed = remove(root)
            print("honeytokens removed" if removed else "no honeytokens deployed")
            return EXIT_OK
        print(honeytoken_status(root))
        return EXIT_OK
    except HoneytokenError as exc:
        return _error(str(exc))


def command_bench(args: argparse.Namespace) -> int:
    """Measure the primary command paths and print the table."""

    from tauhaulity.bench import render_json, render_table, run_benchmarks

    root = Path(args.root).resolve()
    if not root.is_dir():
        return _error(f"bench target is not a directory: {root}")
    results = run_benchmarks(root, runs=args.runs)
    print(render_json(results) if args.json else render_table(results))
    return EXIT_OK


_HANDLERS = {
    "audit": command_audit,
    "setup": command_setup,
    "baseline": command_baseline,
    "shim": command_shim,
    "watch": command_watch,
    "verify": command_verify,
    "suppress": command_suppress,
    "vulns": command_vulns,
    "deps": command_deps,
    "guard": command_guard,
    "shield": command_shield,
    "ci": command_ci,
    "feed": command_feed,
    "posture": command_posture,
    "quarantine": command_quarantine,
    "honeytoken": command_honeytoken,
    "canary": command_canary,
    "bench": command_bench,
    "undo": command_undo,
    "rm": command_rm,
    "free": command_free,
    "ports": command_ports,
    "hook": command_hook,
    "venv-check": command_venv,
    "apply": command_apply,
    "doctor": command_doctor,
    "diff": command_diff,
}


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point used by the console script and by python -m tauhaulity.

    Parameters:
        argv: Argument list without the program name; defaults to sys.argv.

    Returns:
        Process exit code: zero safe, one at risk, two critical, three usage
        error, four unavailable dependency.
    """

    raw = list(sys.argv[1:] if argv is None else argv)
    if not raw:
        raw = ["audit", "."]
    parser = build_parser()
    args = parser.parse_args(raw)
    handler = _HANDLERS.get(args.command)
    if handler is None:
        parser.print_help()
        return EXIT_USAGE
    try:
        return handler(args)
    except ImportError as exc:
        print(f"tauhaulity: {args.command} is unavailable in this build: {exc}", file=sys.stderr)
        return EXIT_UNAVAILABLE
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"tauhaulity: {args.command} failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
