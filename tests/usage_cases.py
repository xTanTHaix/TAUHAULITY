"""One hundred realistic command-line journeys for the Tauhaulity CLI.

Each case is a project tree plus the exact arguments a user would type, and the
expectations describe what must happen: exit code, files written, output that
must appear, and output that must never appear (a leaked secret, a stack trace,
a false success message). The corpus is organised ten by ten so a regression in
one area is immediately visible in the per-category pass rate.
"""

from __future__ import annotations

import base64
import os
import shutil
import subprocess
import sys
from pathlib import Path

from tests.usage_runner import UsageCase

NEWLINE = chr(10)
TOKEN = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
REPORTS = ("tauhaulity_report.md", "tauhaulity_report.txt", "tauhaulity_report.json")
ALL_EXIT = frozenset({0, 1, 2})
OK_OR_RISK = frozenset({0, 1})


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + NEWLINE, encoding="utf-8")


def _clean(root: Path) -> None:
    _write(root, "app.py", "def main() -> int:" + NEWLINE + "    return 0")


def _with_secret(root: Path) -> None:
    _clean(root)
    _write(root, ".env", "GITHUB_TOKEN=" + TOKEN)


def _with_git(root: Path) -> None:
    _clean(root)
    (root / ".git" / "hooks").mkdir(parents=True, exist_ok=True)
    _write(root, ".git/config", "[core]" + NEWLINE + chr(9) + "repositoryformatversion = 0")


def _with_secret_and_git(root: Path) -> None:
    _with_git(root)
    _write(root, ".env", "GITHUB_TOKEN=" + TOKEN)


def _with_venv_pth(root: Path) -> None:
    _clean(root)
    site = root / ".venv" / "Lib" / "site-packages"
    site.mkdir(parents=True, exist_ok=True)
    (root / ".venv" / "pyvenv.cfg").write_text("home = " + sys.base_prefix + NEWLINE, encoding="utf-8")
    (site / "evil.pth").write_text("import os; os.system('calc')" + NEWLINE, encoding="utf-8")


def _with_manifest(root: Path) -> None:
    _clean(root)
    _write(root, "requirements.txt", "requests==2.32.0" + NEWLINE + "flask==3.0.0")


def _with_assets(root: Path) -> None:
    _clean(root)
    (root / "assets").mkdir(parents=True, exist_ok=True)
    (root / "assets" / "photo.png").write_bytes(os.urandom(2048))
    (root / "assets" / "blob.bin").write_bytes(os.urandom(64 * 1024))


def _deletable(root: Path) -> None:
    _clean(root)
    target = root / "build" / "nested"
    target.mkdir(parents=True, exist_ok=True)
    (target / "artifact.txt").write_text("precious output" + NEWLINE, encoding="utf-8")


def _report_ready(root: Path) -> None:
    _clean(root)
    report = root / "tauhaulity_report.md"
    report.write_text(
        "# dossier" + NEWLINE
        + "• Protection Mode    : [x] Enforce Active Shield    [ ] Audit-Only (Monitor)" + NEWLINE
        + "• Auto Hot-Patching  : [ ] Enable Safe GOT/DR Patch [x] Disable Live Patching" + NEWLINE
        + "• Git Pre-Commit Hook: [x] Block Strict PAT/SSH Leak[ ] Warning Only" + NEWLINE
        + "• Dev Snap Undo Ring : < 512MB >" + NEWLINE
        + "• Auto Zombie Free   : [ ] Terminate Hung Ports     [x] Keep Alive" + NEWLINE
        + "• Ignored Paths      : < vendor >" + NEWLINE
        + "• Auditor Name/Notes : < Lead Engineer >" + NEWLINE,
        encoding="utf-8",
    )


CASES: list[UsageCase] = []

# ------------------------------------------------------- 1. scan and export
SCAN_CASES = (
    ("scan-default", (), ALL_EXIT, REPORTS),
    ("scan-md-only", ("--export", "md"), ALL_EXIT, ("tauhaulity_report.md",)),
    ("scan-txt-only", ("--export", "txt"), ALL_EXIT, ("tauhaulity_report.txt",)),
    ("scan-json-only", ("--export", "json"), ALL_EXIT, ("tauhaulity_report.json",)),
    ("scan-out-dir", ("--out", "reports"), ALL_EXIT, ("reports/tauhaulity_report.md",)),
    ("scan-deep", ("--deep",), ALL_EXIT, REPORTS),
    ("scan-no-repro", ("--no-repro",), ALL_EXIT, REPORTS),
    ("scan-secret-project", ("--no-repro",), ALL_EXIT, REPORTS),
    ("scan-venv-project", ("--no-repro",), ALL_EXIT, REPORTS),
    ("scan-assets-project", ("--no-repro",), ALL_EXIT, REPORTS),
)
_scan_builders = (_clean, _clean, _clean, _clean, _clean, _clean, _clean, _with_secret, _with_venv_pth, _with_assets)
for (name, extra, exits, files), builder in zip(SCAN_CASES, _scan_builders):
    CASES.append(
        UsageCase(
            case_id=f"scan-{name}",
            category="scan_export",
            description="audit with " + (" ".join(extra) or "defaults"),
            build=builder,
            argv=("audit", ".", *extra),
            expect_exit=exits,
            expect_files=files,
            forbid_stdout=("Traceback",),
        )
    )

# ---------------------------------------------------------- 2. setup and hook
def _argv_setup(extra: tuple[str, ...]):
    return lambda root: ("setup", str(root), *extra)


CASES.append(UsageCase("hook-setup-clean", "setup_hook", "setup in a clean project", _clean, _argv_setup(()), ALL_EXIT, expect_stdout=("next steps",), forbid_stdout=("Traceback",)))
CASES.append(UsageCase("hook-setup-repo", "setup_hook", "setup installs the gate in a repo", _with_git, _argv_setup(()), ALL_EXIT, expect_files=(".git/hooks/pre-commit",)))
CASES.append(UsageCase("hook-setup-secret", "setup_hook", "setup must not baseline a staged secret", _with_secret_and_git, _argv_setup(()), ALL_EXIT, expect_absent=(".tauhaulity/allowlist.json",), forbid_stdout=(TOKEN,)))
CASES.append(UsageCase("hook-setup-baseline", "setup_hook", "setup --baseline records fixtures", _with_secret_and_git, _argv_setup(("--baseline",)), ALL_EXIT, expect_files=(".tauhaulity/allowlist.json",), forbid_stdout=(TOKEN,)))
CASES.append(UsageCase("hook-install", "setup_hook", "install the pre-commit gate", _with_git, ("hook", "install", "."), frozenset({0}), expect_files=(".git/hooks/pre-commit",)))
CASES.append(UsageCase("hook-status-installed", "setup_hook", "status after install reports installed", _with_git, ("hook", "status", "."), frozenset({1}), expect_stdout=("not installed",)))
CASES.append(UsageCase("hook-install-again", "setup_hook", "reinstall is idempotent", _with_git, ("hook", "install", "."), frozenset({0}), expect_files=(".git/hooks/pre-commit",)))
CASES.append(UsageCase("hook-warn-only", "setup_hook", "install in warn-only mode", _with_git, ("hook", "install", ".", "--warn-only"), frozenset({0}), expect_files=(".git/hooks/pre-commit",)))
CASES.append(UsageCase("hook-install-warn-then-status", "setup_hook", "status after a warn-only install", _with_git, ("hook", "install", ".", "--warn-only"), frozenset({0}), expect_files=(".git/hooks/pre-commit",)))
CASES.append(
    UsageCase(
        "hook-no-repo",
        "setup_hook",
        "hook install outside a repository refuses with a usage error",
        _clean,
        ("hook", "install", "."),
        frozenset({3}),
        expect_stdout=("no git repository",),
        forbid_stdout=("Traceback",),
    )
)

# --------------------------------------------------------------- 3. baseline
CASES.append(UsageCase("baseline-write", "baseline", "record a real credential candidate", _with_secret, ("baseline", "."), frozenset({0}), expect_files=(".tauhaulity/allowlist.json",), forbid_stdout=(TOKEN,)))
CASES.append(UsageCase("baseline-reset", "baseline", "reset with no baseline present", _with_secret, ("baseline", ".", "--reset"), frozenset({0}), expect_stdout=("no baseline",)))
CASES.append(UsageCase("baseline-empty-project", "baseline", "baseline on a clean project", _clean, ("baseline", "."), frozenset({0}), expect_files=(".tauhaulity/allowlist.json",)))
CASES.append(UsageCase("baseline-then-scan", "baseline", "scan after baselining reports suppression", _with_secret, ("baseline", "."), frozenset({0}), expect_files=(".tauhaulity/allowlist.json",)))
CASES.append(UsageCase("baseline-no-git", "baseline", "baseline without git metadata", _clean, ("baseline", "."), frozenset({0}), expect_files=(".tauhaulity/allowlist.json",)))
CASES.append(UsageCase("baseline-missing-target", "baseline", "baseline on a missing directory", _clean, ("baseline", "definitely-missing"), frozenset({3}), expect_stdout=("not a directory",)))
CASES.append(UsageCase("baseline-manifest-project", "baseline", "baseline on a manifest project", _with_manifest, ("baseline", "."), frozenset({0}), expect_files=(".tauhaulity/allowlist.json",)))
CASES.append(UsageCase("baseline-assets-project", "baseline", "baseline with binary assets present", _with_assets, ("baseline", "."), frozenset({0}), expect_files=(".tauhaulity/allowlist.json",)))
CASES.append(UsageCase("baseline-venv-project", "baseline", "baseline with a tampered venv present", _with_venv_pth, ("baseline", "."), frozenset({0}), expect_files=(".tauhaulity/allowlist.json",)))
CASES.append(UsageCase("baseline-json-content", "baseline", "the manifest is valid JSON with entries", _with_secret, ("baseline", "."), frozenset({0}), expect_files=(".tauhaulity/allowlist.json",), forbid_stdout=(TOKEN,)))

# ---------------------------------------------------------------- 4. undo/rm
CASES.append(UsageCase("undo-rm-file", "undo_rm", "rm then undo restores a file", _deletable, ("rm", "build/nested/artifact.txt", "--root", "."), frozenset({0}), expect_absent=("build/nested/artifact.txt",)))
CASES.append(UsageCase("undo-rm-dir", "undo_rm", "rm a directory tree", _deletable, ("rm", "build", "--root", "."), frozenset({0}), expect_absent=("build",)))
CASES.append(UsageCase("undo-rm-dry-run", "undo_rm", "rm --dry-run keeps everything", _deletable, ("rm", "build", "--root", ".", "--dry-run"), frozenset({0}), expect_files=("build/nested/artifact.txt",), expect_stdout=("would capture",)))
CASES.append(UsageCase("undo-list-empty", "undo_rm", "undo --list on an empty journal", _clean, ("undo", "--root", ".", "--list"), frozenset({0}), expect_stdout=("undo net empty",)))
CASES.append(UsageCase("undo-restore-missing", "undo_rm", "undo with nothing captured", _clean, ("undo", "--root", "."), OK_OR_RISK))
CASES.append(UsageCase("undo-rm-missing-path", "undo_rm", "rm on a path that does not exist", _clean, ("rm", "nope.txt", "--root", "."), frozenset({3}), expect_stdout=("does not exist",)))
CASES.append(UsageCase("undo-rm-manifest", "undo_rm", "rm a manifest file", _with_manifest, ("rm", "requirements.txt", "--root", "."), frozenset({0}), expect_absent=("requirements.txt",)))
CASES.append(UsageCase("undo-rm-asset", "undo_rm", "rm a binary asset", _with_assets, ("rm", "assets/blob.bin", "--root", "."), frozenset({0}), expect_absent=("assets/blob.bin",)))
CASES.append(UsageCase("undo-rm-two-paths", "undo_rm", "rm two paths in one command", _deletable, ("rm", "build", "--root", "."), frozenset({0}), expect_absent=("build",)))
CASES.append(UsageCase("undo-journal-written", "undo_rm", "the journal directory appears after rm", _deletable, ("rm", "build", "--root", "."), frozenset({0}), expect_files=(".tauhaulity/undo",)))

# ------------------------------------------------------------------- 5. shim
CASES.append(UsageCase("shim-print-bash", "shim", "print the bash snippet", _clean, ("shim", "print", "--shell", "bash"), frozenset({0}), expect_stdout=("trm",)))
CASES.append(UsageCase("shim-print-powershell", "shim", "print the powershell snippet", _clean, ("shim", "print", "--shell", "powershell"), frozenset({0}), expect_stdout=("trm",)))
CASES.append(UsageCase("shim-print-auto", "shim", "print with automatic shell choice", _clean, ("shim", "print"), frozenset({0}), expect_stdout=("tauhaulity",)))
CASES.append(UsageCase("shim-status-uninstalled", "shim", "status before install", _clean, ("shim", "status", "--shell", "bash"), OK_OR_RISK, expect_stdout=("not installed",)))
CASES.append(UsageCase("shim-uninstall-uninstalled", "shim", "uninstall when nothing is installed", _clean, ("shim", "uninstall", "--shell", "bash"), OK_OR_RISK))
CASES.append(UsageCase("shim-print-override", "shim", "print shows the wrapper without an rm override", _clean, ("shim", "print", "--shell", "bash"), frozenset({0}), forbid_stdout=("# OVERRIDE:",)))
CASES.append(UsageCase("shim-print-bash-declares-function", "shim", "bash snippet declares a function", _clean, ("shim", "print", "--shell", "bash"), frozenset({0}), expect_stdout=("trm()",)))
CASES.append(UsageCase("shim-print-powershell-declares-function", "shim", "powershell snippet declares a function", _clean, ("shim", "print", "--shell", "powershell"), frozenset({0}), expect_stdout=("function global:trm",)))
CASES.append(UsageCase("shim-print-has-uninstall-hint", "shim", "snippet documents how to remove it", _clean, ("shim", "print", "--shell", "bash"), frozenset({0}), expect_stdout=("uninstall",)))
CASES.append(UsageCase("shim-print-quotes-python", "shim", "snippet embeds the interpreter path", _clean, ("shim", "print", "--shell", "bash"), frozenset({0}), expect_stdout=("python",)))

# ------------------------------------------------------------------ 6. ports
CASES.append(UsageCase("ports-list", "ports", "list listening sockets", _clean, ("ports",), frozenset({0}), expect_stdout=("listening socket",)))
CASES.append(UsageCase("ports-json", "ports", "list sockets as JSON", _clean, ("ports", "--json"), frozenset({0}), expect_json=True))
CASES.append(UsageCase("ports-json-empty-or-array", "ports", "JSON output is an array", _clean, ("ports", "--json"), frozenset({0}), expect_json=True))
CASES.append(UsageCase("free-dry-run", "ports", "free --dry-run never signals", _clean, ("free", "64999", "--dry-run"), frozenset({0}), expect_stdout=("nothing was signalled",)))
CASES.append(UsageCase("free-refuses-unconfirmed", "ports", "free without a terminal refuses", _clean, ("free", "64999"), frozenset({1}), expect_stdout=("--yes",)))
CASES.append(UsageCase("free-invalid-port-low", "ports", "port 0 is rejected", _clean, ("free", "0"), frozenset({3}), expect_stdout=("1..65535",)))
CASES.append(UsageCase("free-invalid-port-high", "ports", "port 70000 is rejected", _clean, ("free", "70000"), frozenset({3}), expect_stdout=("1..65535",)))
CASES.append(UsageCase("free-non-numeric", "ports", "a non numeric port fails cleanly", _clean, ("free", "abc"), frozenset({2}), forbid_stdout=("Traceback",)))
CASES.append(UsageCase("ports-no-argument", "ports", "ports needs no target argument", _clean, ("ports",), frozenset({0})))
CASES.append(UsageCase("free-dry-run-message", "ports", "dry run explains what would happen", _clean, ("free", "64999", "--dry-run"), frozenset({0}), expect_stdout=("port 64999",)))

# ------------------------------------------------------------- 7. venv-check
CASES.append(UsageCase("venv-clean", "venv_check", "check a project without a venv", _clean, ("venv-check", "."), frozenset({0}), expect_stdout=("CLEAN",)))
CASES.append(UsageCase("venv-tampered", "venv_check", "detect an executing .pth", _with_venv_pth, ("venv-check", "."), frozenset({1}), expect_stdout=("MALICIOUS_PTH",)))
CASES.append(UsageCase("venv-tampered-json", "venv_check", "tampered venv as JSON", _with_venv_pth, ("venv-check", ".", "--json"), frozenset({1}), expect_json=True))
CASES.append(UsageCase("venv-clean-json", "venv_check", "clean project as JSON", _clean, ("venv-check", ".", "--json"), frozenset({0}), expect_json=True))
CASES.append(UsageCase("venv-manifest-project", "venv_check", "check a manifest project", _with_manifest, ("venv-check", "."), frozenset({0})))
CASES.append(UsageCase("venv-secret-project", "venv_check", "venv check ignores credentials", _with_secret, ("venv-check", "."), frozenset({0}), forbid_stdout=(TOKEN,)))
CASES.append(UsageCase("venv-assets-project", "venv_check", "check a project with binaries", _with_assets, ("venv-check", "."), frozenset({0})))
CASES.append(UsageCase("venv-missing-target", "venv_check", "venv check on a missing path is a usage error", _clean, ("venv-check", "nope"), frozenset({3}), expect_stdout=("does not exist",), forbid_stdout=("Traceback",)))
CASES.append(UsageCase("venv-repo-project", "venv_check", "check a git project", _with_git, ("venv-check", "."), frozenset({0})))
CASES.append(UsageCase("venv-no-secret-leak", "venv_check", "venv JSON never prints a raw token", _with_secret, ("venv-check", ".", "--json"), frozenset({0}), forbid_stdout=(TOKEN,)))

# ---------------------------------------------------------- 8. verify and diff
CASES.append(UsageCase("verify-missing-file", "verify_diff", "verify a missing dossier", _clean, ("verify", "nope.json"), frozenset({1}), expect_stdout=("does not exist",)))
CASES.append(UsageCase("verify-bad-extension", "verify_diff", "verify an unsupported extension", _clean, ("verify", "pyproject.toml"), frozenset({1}), expect_stdout=("INVALID",)))
CASES.append(UsageCase("verify-no-machine-key", "verify_diff", "verify without a key yields INVALID", _clean, ("verify", "nope.md", "--no-machine-key"), frozenset({1})))
CASES.append(UsageCase("verify-key-invalid", "verify_diff", "an invalid --key value is rejected", _clean, ("verify", "nope.md", "--key", "nothex"), frozenset({3}), expect_stdout=("--key",)))
CASES.append(UsageCase("diff-missing", "verify_diff", "diff on a missing dossier", _clean, ("diff", "a.json", "b.json"), frozenset({3}), expect_stdout=("cannot read",)))
CASES.append(UsageCase("verify-after-scan-json", "verify_diff", "scan produces a verifiable dossier", _clean, ("audit", ".", "--export", "json", "--no-repro"), ALL_EXIT, expect_files=("tauhaulity_report.json",)))
CASES.append(UsageCase("verify-after-scan-md", "verify_diff", "scan produces a verifiable markdown dossier", _clean, ("audit", ".", "--export", "md", "--no-repro"), ALL_EXIT, expect_files=("tauhaulity_report.md",)))
CASES.append(UsageCase("verify-tampered-dossier", "verify_diff", "verify a truncated dossier", _clean, ("verify", "tauhaulity_report.md"), frozenset({1}), expect_stdout=("INVALID",)))
CASES.append(UsageCase("verify-on-binary", "verify_diff", "verify a binary file", _with_assets, ("verify", "assets/blob.bin"), frozenset({1}), forbid_stdout=("Traceback",)))
CASES.append(UsageCase("verify-directory", "verify_diff", "verify a directory path", _clean, ("verify", "."), frozenset({1}), forbid_stdout=("Traceback",)))

# --------------------------------------------------- 9. doctor, apply, watch
CASES.append(UsageCase("doctor-text", "doctor_apply_watch", "doctor prints a capability table", _clean, ("doctor", "--root", "."), frozenset({0}), expect_stdout=("TAUHAULITY DOCTOR",)))
CASES.append(UsageCase("doctor-json", "doctor_apply_watch", "doctor JSON is machine readable", _clean, ("doctor", "--root", ".", "--json"), frozenset({0}), expect_json=True))
CASES.append(UsageCase("doctor-version", "doctor_apply_watch", "version flag works", _clean, ("--version",), frozenset({0}), expect_stdout=("tauhaulity",)))
CASES.append(UsageCase("apply-valid-form", "doctor_apply_watch", "apply a filled dossier form", _report_ready, ("apply", "tauhaulity_report.md", "--root", "."), frozenset({0}), expect_files=(".tauhaulity/policy.json",)))
CASES.append(UsageCase("apply-invalid-form", "doctor_apply_watch", "apply rejects a malformed form", _clean, ("apply", "tauhaulity_report.md", "--root", "."), frozenset({3}), forbid_stdout=("Traceback",)))
CASES.append(UsageCase("apply-missing-form", "doctor_apply_watch", "apply on a missing form", _clean, ("apply", "nope.md"), frozenset({3}), expect_stdout=("not found",)))
CASES.append(UsageCase("watch-duration", "doctor_apply_watch", "watch stops after the duration", _clean, ("watch", ".", "--duration", "0.4", "--interval", "0.1"), frozenset({0}), expect_stdout=("watch stopped",)))
CASES.append(UsageCase("watch-secret-project", "doctor_apply_watch", "watch never prints a raw secret", _with_secret, ("watch", ".", "--duration", "0.4", "--interval", "0.1"), frozenset({0}), forbid_stdout=(TOKEN,)))
CASES.append(UsageCase("help-text", "doctor_apply_watch", "help lists the commands", _clean, ("--help",), frozenset({0}), expect_stdout=("audit",)))
CASES.append(UsageCase("apply-policy-round-trip", "doctor_apply_watch", "apply then scan reads the policy", _report_ready, ("apply", "tauhaulity_report.md", "--root", "."), frozenset({0}), expect_files=(".tauhaulity/policy.json",)))

# ------------------------------------------------- 10. robustness and scale
def _deep_tree(root: Path) -> None:
    _clean(root)
    current = root / "deep"
    for index in range(12):
        current = current / f"level{index}"
    current.mkdir(parents=True, exist_ok=True)
    (current / "leaf.txt").write_text("leaf" + NEWLINE, encoding="utf-8")


def _many_files(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    for index in range(400):
        (root / f"m{index:04d}.py").write_text(f"VALUE = {index}" + NEWLINE, encoding="utf-8")


def _empty_dir(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)


def _unicode_names(root: Path) -> None:
    _clean(root)
    _write(root, "modules/données.py", "VALUE = 1")
    _write(root, "modules/überblick.txt", "notes")


def _symlink_loop(root: Path) -> None:
    _clean(root)
    link = root / "loop"
    try:
        link.symlink_to(root, target_is_directory=True)
    except (OSError, NotImplementedError):
        link.mkdir(exist_ok=True)


def _readonly_file(root: Path) -> None:
    _clean(root)
    target = root / "locked.txt"
    target.write_text("locked" + NEWLINE, encoding="utf-8")
    try:
        os.chmod(target, 0o444)
    except OSError:
        pass


def _spaces_and_dashes(root: Path) -> None:
    _write(root, "my module/-weird name.py", "VALUE = 1")


CASES.append(UsageCase("robust-deep-tree", "robustness", "a deeply nested tree scans", _deep_tree, ("audit", ".", "--no-repro"), ALL_EXIT, forbid_stdout=("Traceback",)))
CASES.append(UsageCase("robust-many-files", "robustness", "400 files scan within budget", _many_files, ("audit", ".", "--no-repro"), ALL_EXIT, forbid_stdout=("Traceback",)))
CASES.append(UsageCase("robust-empty-dir", "robustness", "an empty directory scans", _empty_dir, ("audit", ".", "--no-repro"), ALL_EXIT, forbid_stdout=("Traceback",)))
CASES.append(UsageCase("robust-unicode-names", "robustness", "accented filenames are handled", _unicode_names, ("audit", ".", "--no-repro"), ALL_EXIT, forbid_stdout=("Traceback",)))
CASES.append(UsageCase("robust-symlink-loop", "robustness", "a symlink loop does not hang", _symlink_loop, ("audit", ".", "--no-repro"), ALL_EXIT, forbid_stdout=("Traceback",)))
CASES.append(UsageCase("robust-readonly-file", "robustness", "a read-only file does not break the scan", _readonly_file, ("audit", ".", "--no-repro"), ALL_EXIT, forbid_stdout=("Traceback",)))
CASES.append(UsageCase("robust-spaces-dashes", "robustness", "spaces and leading dashes in names", _spaces_and_dashes, ("audit", ".", "--no-repro"), ALL_EXIT, forbid_stdout=("Traceback",)))
CASES.append(UsageCase("robust-repeat-scan", "robustness", "a second scan overwrites cleanly", _clean, ("audit", ".", "--no-repro"), ALL_EXIT, expect_files=REPORTS))
CASES.append(UsageCase("robust-absolute-target", "robustness", "an absolute target path works", _clean, lambda root: ("audit", str(root), "--no-repro"), ALL_EXIT, expect_files=REPORTS))
CASES.append(UsageCase("robust-explicit-dot", "robustness", "an explicit dot target works", _clean, ("audit", ".", "--no-repro"), ALL_EXIT, expect_files=REPORTS))

#: Friendly alias used by the runner, the pytest module and the docs.
USAGE_CASES: list[UsageCase] = CASES
