"""I/O entropy radar: detect files that turned into ciphertext.

Ransomware encrypts file content, which raises Shannon entropy from prose-like
values (about 4 to 5 bits per byte) to near random levels (above 7.5). Media,
archives and compiled objects are already high entropy, so they are skipped by
suffix: flagging every PNG would make the pillar useless.

The scan is bounded three ways, because the Python Shannon estimator is a byte
counting loop that costs roughly one second per 17 MiB at the ctypes tier:

  * by file count, so a huge checkout cannot turn the walk into the probe cost;
  * by bytes read per file, so one large binary cannot dominate the sample;
  * by a total byte budget across the whole scan (32 MiB by default), so the
    worst case wall clock cost of a scan is a constant instead of growing with
    the size of the project. The budget is checked before every read and the
    scan stops as soon as it is spent; the accounting is returned in
    EntropyReport so a caller can state exactly how much of the tree was seen.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from tauhaulity.core.entropy import block_entropies

MAX_FILE_BYTES = 512 * 1024
MIN_FILE_BYTES = 512
DEFAULT_THRESHOLD = 7.2
DEFAULT_BLOCK_SIZE = 4096

#: Total payload bytes one scan may read. At the measured ~17 MiB/s cost of the
#: pure Python Shannon estimator this caps a scan at roughly two seconds of work
#: on a machine where the native engine is unavailable.
DEFAULT_MAX_TOTAL_BYTES = 32 * 1024 * 1024
_MAX_FILES_DEFAULT = 512

# Formats whose payload is already random or compressed. Flagging them would
# bury a real encryption event under a mountain of photography and build output.
_SKIP_SUFFIXES: frozenset[str] = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".webp",
        ".ico",
        ".bmp",
        ".tif",
        ".tiff",
        ".psd",
        ".mp3",
        ".mp4",
        ".mkv",
        ".avi",
        ".mov",
        ".flac",
        ".ogg",
        ".zip",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".zst",
        ".tar",
        ".pdf",
        ".docx",
        ".xlsx",
        ".pptx",
        ".jar",
        ".whl",
        ".pyc",
        ".pyo",
        ".so",
        ".dll",
        ".pyd",
        ".dylib",
        ".exe",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".db",
        ".sqlite",
        ".sqlite3",
        ".bin",
        ".dat",
    }
)

_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "__pycache__",
        "site-packages",
        "dist",
        "build",
        "target",
        ".tauhaulity",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tooling",
        ".toolchains",
        "toolchains",
        ".pyenv",
        ".asdf",
    }
)


@dataclass(frozen=True, slots=True)
class EntropyAlert:
    """One file whose content entropy looks like encryption output.

    Attributes:
        rel_path: Project relative path with forward slashes.
        entropy: Mean entropy of the sampled blocks in bits per byte.
        size: File size in bytes.
        detail: Explanation with the block ratio and the threshold used.
    """

    rel_path: str
    entropy: float
    size: int
    detail: str


def _read_sample(path: Path, limit: int = MAX_FILE_BYTES) -> bytes:
    """Read at most limit bytes from a file, returning empty bytes on failure.

    The caller passes the remaining total budget, so the bound is enforced by the
    read itself instead of by an accounting step that runs after the bytes were
    already paid for.
    """

    allowance = max(0, min(int(limit), MAX_FILE_BYTES))
    if allowance <= 0:
        return b""
    try:
        with path.open("rb") as handle:
            return handle.read(allowance)
    except OSError:
        return b""


@dataclass(frozen=True, slots=True)
class EntropyReport:
    """Result of one bounded radar scan.

    Attributes:
        alerts: Ciphertext-like files, ordered by descending entropy.
        files_inspected: Files whose content was actually read and measured.
        bytes_inspected: Payload bytes read; never above max_total_bytes.
        max_total_bytes: Byte budget the scan was allowed to spend.
        exhausted: True when the budget stopped the walk before the tree ended.
    """

    alerts: tuple[EntropyAlert, ...] = ()
    files_inspected: int = 0
    bytes_inspected: int = 0
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    exhausted: bool = False

    @property
    def detail(self) -> str:
        """Render the inspection accounting for a dossier or a log line."""

        text = (
            "inspected "
            + str(self.files_inspected)
            + " file(s) and "
            + str(self.bytes_inspected)
            + " byte(s) of a "
            + str(self.max_total_bytes)
            + " byte budget"
        )
        if self.exhausted:
            text += "; budget exhausted before the tree was fully walked"
        text += "; " + str(len(self.alerts)) + " ciphertext-like file(s)"
        return text


def scan_with_budget(
    root: Path,
    *,
    block_size: int = DEFAULT_BLOCK_SIZE,
    threshold: float = DEFAULT_THRESHOLD,
    max_files: int = _MAX_FILES_DEFAULT,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> EntropyReport:
    """Scan a project tree for ciphertext-like files under a total byte budget.

    The walk stops as soon as the byte budget is exhausted, so the worst case
    wall clock cost of a scan is a constant instead of a function of project
    size. Files that are skipped for their suffix, size or type cost no budget,
    because nothing of them is read.

    Parameters:
        root: Project root to scan.
        block_size: Window size used to average entropy.
        threshold: Entropy in bits per byte above which a block counts as
            ciphertext-like.
        max_files: Maximum number of files analyzed.
        max_total_bytes: Maximum payload bytes read across the whole scan.

    Returns:
        Alerts plus the exact inspection accounting.

    Raises:
        ValueError: When a bound is not positive or the threshold is outside
            zero to eight bits per byte.
    """

    if int(block_size) <= 0:
        raise ValueError("block_size must be positive")
    if not 0.0 <= float(threshold) <= 8.0:
        raise ValueError("threshold must be within 0..8 bits per byte")
    if isinstance(max_files, bool) or int(max_files) <= 0:
        raise ValueError("max_files must be a positive integer")
    if isinstance(max_total_bytes, bool) or int(max_total_bytes) <= 0:
        raise ValueError("max_total_bytes must be a positive integer")
    budget = int(max_total_bytes)

    root = Path(root)
    if not root.is_dir():
        return EntropyReport((), 0, 0, budget, False)

    alerts: list[EntropyAlert] = []
    analyzed = 0
    consumed = 0
    exhausted = False
    for current, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(name for name in dirnames if name.lower() not in _SKIP_DIRS)
        base = Path(current)
        for filename in sorted(filenames):
            if analyzed >= int(max_files):
                break
            remaining = budget - consumed
            if remaining <= 0:
                exhausted = True
                break
            path = base / filename
            if path.suffix.lower() in _SKIP_SUFFIXES:
                continue
            try:
                if path.is_symlink() or not path.is_file():
                    continue
                size = path.stat().st_size
            except OSError:
                continue
            if size < MIN_FILE_BYTES:
                continue
            if remaining < MIN_FILE_BYTES:
                # Less budget than one measurable sample: stop instead of handing
                # the entropy estimator a truncated block it cannot judge.
                exhausted = True
                break
            payload = _read_sample(path, remaining)
            if len(payload) < MIN_FILE_BYTES:
                continue
            consumed += len(payload)
            analyzed += 1
            blocks = block_entropies(payload, int(block_size))
            if not blocks:
                continue
            mean = sum(blocks) / len(blocks)
            high = sum(1 for value in blocks if value >= float(threshold))
            ratio = high / len(blocks)
            # A single base64 blob in a source file raises only a few blocks; a
            # fully encrypted file raises almost all of them. Requiring both a
            # high mean and a high block ratio keeps documentation and embedded
            # payloads out of the report.
            if mean < float(threshold) and not (ratio >= 0.75 and mean >= float(threshold) - 0.3):
                continue
            try:
                rel = path.relative_to(root).as_posix()
            except ValueError:
                rel = path.as_posix()
            alerts.append(
                EntropyAlert(
                    rel_path=rel,
                    entropy=round(mean, 3),
                    size=size,
                    detail=format(ratio, ".0%")
                    + " of "
                    + str(len(blocks))
                    + " block(s) above "
                    + format(float(threshold), ".2f")
                    + " bits per byte",
                )
            )
        if analyzed >= int(max_files) or exhausted:
            break
    alerts.sort(key=lambda alert: (-alert.entropy, alert.rel_path))
    return EntropyReport(tuple(alerts), analyzed, consumed, budget, exhausted)


def scan_for_ransomware(
    root: Path,
    *,
    block_size: int = DEFAULT_BLOCK_SIZE,
    threshold: float = DEFAULT_THRESHOLD,
    max_files: int = _MAX_FILES_DEFAULT,
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
) -> list[EntropyAlert]:
    """Scan a project tree for files that look freshly encrypted.

    This is the list only form kept for pillar eight, which reports the worst
    alert and does not need the accounting. Use scan_with_budget when the byte
    and file counts matter.

    Parameters:
        root: Project root to scan.
        block_size: Window size used to average entropy.
        threshold: Entropy in bits per byte above which a block counts as
            ciphertext-like.
        max_files: Maximum number of files analyzed.
        max_total_bytes: Maximum payload bytes read across the whole scan.

    Returns:
        Alerts sorted by descending entropy.

    Raises:
        ValueError: When a bound is not positive or the threshold is outside
            zero to eight bits per byte.
    """

    report = scan_with_budget(
        root,
        block_size=block_size,
        threshold=threshold,
        max_files=max_files,
        max_total_bytes=max_total_bytes,
    )
    return list(report.alerts)
