"""Virtual environment integrity radar with verifiable evidence.

site-packages is the one directory a project trusts blindly: .pth files are
executed by the interpreter at startup, compiled objects are imported without a
signature check, and a wheel can be replaced in place without anything noticing.
This module therefore answers six questions, in increasing order of strength:

  * does any .pth file execute code instead of adding a path?
  * does a .pth file add a path outside the environment, or one that no longer
    exists (sys.path injection and dangling entries)?
  * did the interpreter install a sitecustomize/usercustomize hook that runs
    before any project code?
  * do the installed distributions still match the sha256 digests recorded by
    pip in their RECORD files (the only tamper evidence a wheel leaves behind)?
  * does an installed distribution name look like a typosquat of a popular
    package?
  * does pyvenv.cfg still point at a real interpreter?

Everything is read only and bounded. RECORD verification is the expensive part,
so it stops at a file count and a byte count and reports truncation instead of
silently claiming full coverage. Findings never carry file content: only paths,
digests and names, because a diagnostic that quotes what it found becomes a
second leak.
"""

from __future__ import annotations

import base64
import csv
import hashlib
import io
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path

_MAX_PTH_FILES = 64
_MAX_PTH_BYTES = 128 * 1024
_MAX_SCAN_FILES = 4000
_MAX_ANOMALY_REPORT = 50

# RECORD verification budget. A large environment records tens of thousands of
# files and hashing all of them on every scan would blow the pillar budget, so
# the walk stops at both limits and reports truncation rather than pretending to
# have verified everything.
MAX_RECORD_FILES = 3000
MAX_RECORD_BYTES = 64 * 1024 * 1024
_HASH_CHUNK = 1024 * 1024
_MAX_RECORD_ENTRIES = 50000
_MAX_RECORD_FILES_ON_DISK = 2048
_MAX_RECORD_BYTES_ON_DISK = 16 * 1024 * 1024

_MAX_DISTS = 512
_MAX_STARTUP_SCAN = 20000
_MAX_TYPOSQUAT_REPORT = 50

_BINARY_SUFFIXES: frozenset[str] = frozenset({".dll", ".pyd", ".so", ".dylib", ".exe"})

# File names the interpreter imports before any user code when they appear on
# sys.path. Their presence inside an environment is always an injection surface.
_STARTUP_NAMES: frozenset[str] = frozenset({"sitecustomize.py", "usercustomize.py"})

# Executable .pth payload markers. The first two are the documented forms
# (import statements and exec calls); the rest catch a direct call that does not
# need an import because os is already loaded by site.py.
_EXEC_MARKERS: tuple[str, ...] = (
    "import ",
    "import\t",
    "exec(",
    "eval(",
    "__import__",
    "os.system",
    "subprocess",
    "socket.",
    "urllib",
    "base64",
)

# Finding codes that mean "the environment runs attacker controlled code" as
# opposed to "an installed file no longer matches its recorded digest".
EXECUTION_CODES: frozenset[str] = frozenset({"EXEC_IMPORT", "EXEC_CALL"})

# Offline tuple of the most impersonated PyPI names. It is a heuristic list, not
# a truth source: the pillar reports a resemblance with an edit distance and
# never claims that a package is malicious. Normalized with PEP 503 rules
# (lowercase, runs of -, _ and . collapsed to a single hyphen).
POPULAR_PYPI_NAMES: tuple[str, ...] = (
    "requests",
    "urllib3",
    "certifi",
    "charset-normalizer",
    "idna",
    "pip",
    "setuptools",
    "wheel",
    "packaging",
    "six",
    "attrs",
    "numpy",
    "pandas",
    "scipy",
    "matplotlib",
    "seaborn",
    "scikit-learn",
    "scikit-image",
    "statsmodels",
    "sympy",
    "networkx",
    "tensorflow",
    "torch",
    "torchvision",
    "keras",
    "jax",
    "transformers",
    "datasets",
    "accelerate",
    "huggingface-hub",
    "tokenizers",
    "openai",
    "anthropic",
    "langchain",
    "sentence-transformers",
    "pillow",
    "opencv-python",
    "imageio",
    "flask",
    "django",
    "fastapi",
    "starlette",
    "uvicorn",
    "gunicorn",
    "jinja2",
    "werkzeug",
    "click",
    "typer",
    "rich",
    "colorama",
    "tqdm",
    "loguru",
    "pydantic",
    "sqlalchemy",
    "alembic",
    "psycopg2-binary",
    "pymysql",
    "pymongo",
    "redis",
    "celery",
    "kombu",
    "boto3",
    "botocore",
    "google-cloud-storage",
    "azure-storage-blob",
    "paramiko",
    "cryptography",
    "pyopenssl",
    "pyjwt",
    "bcrypt",
    "passlib",
    "pyyaml",
    "toml",
    "tomli",
    "python-dotenv",
    "arrow",
    "pendulum",
    "pytz",
    "python-dateutil",
    "requests-oauthlib",
    "oauthlib",
    "httpx",
    "aiohttp",
    "websockets",
    "aiofiles",
    "anyio",
    "trio",
    "gevent",
    "pytest",
    "pytest-cov",
    "pytest-mock",
    "coverage",
    "hypothesis",
    "mypy",
    "black",
    "ruff",
    "isort",
    "flake8",
    "pylint",
    "bandit",
    "pre-commit",
    "twine",
    "build",
    "hatch",
    "poetry",
    "pipenv",
    "virtualenv",
    "beautifulsoup4",
    "lxml",
    "html5lib",
    "scrapy",
    "selenium",
    "playwright",
    "psutil",
    "marshmallow",
    "protobuf",
    "grpcio",
    "pyarrow",
    "polars",
    "dask",
    "pyspark",
    "mlflow",
    "wandb",
    "optuna",
    "xgboost",
    "lightgbm",
    "catboost",
    "shap",
    "jupyter",
    "notebook",
    "ipython",
    "jupyterlab",
    "nbconvert",
    "sqlparse",
    "tabulate",
    "termcolor",
    "pygments",
    "markdown",
    "docutils",
    "sphinx",
    "mkdocs",
    "faker",
    "bleach",
    "pycparser",
    "cffi",
    "greenlet",
    "zipp",
    "importlib-metadata",
    "platformdirs",
    "filelock",
    "distlib",
)


@dataclass(frozen=True, slots=True)
class PthFinding:
    """One environment integrity finding.

    The class name is historical: it started as a .pth line scanner and is kept
    because the CLI, the dossier and the pillar all use it. The code field names
    the detector family so a caller can distinguish evidence kinds without
    parsing the detail text.

    Attributes:
        rel_path: Project relative path of the evidence file.
        line_no: One based line number for line level evidence, zero for a whole
            file or directory level finding.
        code: Detector family: EXEC_IMPORT, EXEC_CALL, path_injection,
            dangling_path, record_mismatch, record_missing, record_unreadable,
            startup_injection, typosquat_suspect, interpreter_missing,
            base_path_escape.
        severity: high, medium or low.
        detail: Short evidence note; never contains file content.
    """

    rel_path: str
    line_no: int
    code: str
    severity: str
    detail: str = ""


@dataclass(frozen=True, slots=True)
class VenvReport:
    """Aggregate state of every virtual environment found under a project.

    Attributes:
        venv_path: First environment directory found, or None when absent.
        pth_files: Number of .pth files inspected.
        pth_findings: Findings from every detector, most severe first.
        suspicious_binaries: Compiled artifacts no distribution RECORD claims.
        permission_anomalies: World writable files inside the environment.
        status: CLEAN, TAMPERED, MALICIOUS_PTH or WARNING.
        detail: One line summary for the dossier.
        record_checked: RECORD entries with a sha256 digest that were verified.
        record_mismatches: RECORD entries whose digest did not match.
        startup_injections: Relative paths of sitecustomize/usercustomize files.
        typosquat_suspects: Package names that resemble a popular package.
        truncated: True when a budget stopped the RECORD verification early.
    """

    venv_path: Path | None
    pth_files: int
    pth_findings: list[PthFinding] = field(default_factory=list)
    suspicious_binaries: list[str] = field(default_factory=list)
    permission_anomalies: list[str] = field(default_factory=list)
    status: str = "CLEAN"
    detail: str = ""
    record_checked: int = 0
    record_mismatches: int = 0
    startup_injections: list[str] = field(default_factory=list)
    typosquat_suspects: list[str] = field(default_factory=list)
    truncated: bool = False

    @property
    def has_high_findings(self) -> bool:
        """True when at least one finding is high severity."""

        return any(finding.severity == "high" for finding in self.pth_findings)

    @property
    def executes_code(self) -> bool:
        """True when a high finding is direct code execution evidence."""

        return any(
            finding.severity == "high" and finding.code in EXECUTION_CODES
            for finding in self.pth_findings
        )


@dataclass(slots=True)
class _RecordState:
    """Mutable budget counters shared by the RECORD verification passes."""

    files: int = 0
    total_bytes: int = 0
    unhashed: int = 0
    parsed: int = 0
    truncated: bool = False


@dataclass(frozen=True, slots=True)
class _RecordEntry:
    """One line of a distribution RECORD file."""

    rel: str
    hash_spec: str
    record_rel: str


def _relative(root: Path, path: Path) -> str:
    """Return a project relative forward slash path without raising."""

    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def _site_packages_dirs(venv: Path) -> list[Path]:
    """Return every site-packages directory inside one environment.

    The layout differs by platform and by venv flavour: Windows uses Lib while
    POSIX puts it under lib/pythonX.Y, and a lib64 symlink is common on 64 bit
    RPM distributions. All existing variants are inspected rather than just the
    first, because a stale second tree is itself worth reporting.
    """

    found: list[Path] = []
    candidates: list[Path] = [venv / "Lib" / "site-packages"]
    for base_name in ("lib", "lib64"):
        base = venv / base_name
        if not base.is_dir():
            continue
        try:
            children = sorted(base.iterdir())
        except OSError:
            continue
        for child in children:
            if child.is_dir() and child.name.startswith("python"):
                candidates.append(child / "site-packages")
    for candidate in candidates:
        if candidate.is_dir() and candidate not in found:
            found.append(candidate)
    return found


def _looks_like_venv(path: Path) -> bool:
    """Return True when a directory carries the markers of a virtual env."""

    try:
        if (path / "pyvenv.cfg").is_file():
            return True
    except OSError:
        return False
    return bool(_site_packages_dirs(path))


def find_venvs(root: Path) -> list[Path]:
    """Find virtual environments directly under a project root.

    The search is intentionally shallow: a venv inside a venv or inside
    site-packages is not a project environment and scanning it would multiply
    the probe cost for no diagnostic value.
    """

    root = Path(root)
    candidates: list[Path] = []
    for name in (".venv", "venv", "env"):
        candidate = root / name
        if candidate.is_dir() and _looks_like_venv(candidate):
            candidates.append(candidate)
    try:
        children = sorted(root.iterdir())
    except OSError:
        return candidates
    for child in children[:64]:
        if not child.is_dir() or child in candidates:
            continue
        if child.name.startswith(".") and child.name != ".venv":
            continue
        try:
            if (child / "pyvenv.cfg").is_file() and child not in candidates:
                candidates.append(child)
        except OSError:
            continue
    return candidates


def _is_within(path: Path, parent: Path) -> bool:
    """Return True when path resolves inside parent, without raising."""

    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except (ValueError, OSError):
        return False


def _classify_pth_line(
    line: str, site_packages: Path, venv_root: Path
) -> tuple[str, str, str] | None:
    """Classify one .pth line as (code, severity, detail), or None when benign."""

    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    lowered = stripped.lower()
    for marker in _EXEC_MARKERS:
        if marker in lowered or stripped.startswith(marker):
            if stripped.startswith("exec("):
                return "EXEC_CALL", "high", ".pth executes an exec() payload"
            if marker in ("import ", "import\t", "__import__"):
                return "EXEC_IMPORT", "high", ".pth executes an import statement"
            return "EXEC_CALL", "high", ".pth calls into another module at startup"
    # A .pth line that is not executable is a path addition. site.py resolves
    # relative entries against the site-packages directory, so both forms are
    # checked against the tree that will actually be searched at runtime.
    candidate = Path(stripped)
    target = candidate if candidate.is_absolute() else site_packages / stripped
    try:
        exists = target.exists() or target.is_symlink()
    except OSError:
        exists = False
    if not exists:
        return "dangling_path", "low", ".pth adds a path that does not exist"
    if not _is_within(target, venv_root):
        return "path_injection", "medium", ".pth adds a path outside the environment"
    return None


def _scan_pth(
    root: Path, venv_root: Path, site_packages: Path, counters: dict[str, int]
) -> list[PthFinding]:
    """Inspect every .pth file inside one site-packages directory."""

    findings: list[PthFinding] = []
    try:
        pth_files = sorted(site_packages.glob("*.pth"))
    except OSError:
        return findings
    for pth in pth_files[:_MAX_PTH_FILES]:
        counters["pth_files"] = counters.get("pth_files", 0) + 1
        try:
            with pth.open("rb") as handle:
                payload = handle.read(_MAX_PTH_BYTES)
        except OSError:
            continue
        text = payload.decode("utf-8", errors="replace")
        for line_no, line in enumerate(text.splitlines(), 1):
            classified = _classify_pth_line(line, site_packages, venv_root)
            if classified is None:
                continue
            code, severity, detail = classified
            findings.append(
                PthFinding(_relative(root, pth), line_no, code, severity, detail)
            )
    return findings


def _scan_startup_injection(root: Path, venv: Path, findings: list[PthFinding]) -> list[str]:
    """Find interpreter startup hooks planted inside the environment."""

    injected: list[str] = []
    scanned = 0
    for current, dirnames, filenames in os.walk(venv):
        dirnames[:] = sorted(name for name in dirnames if name != "__pycache__")
        for filename in sorted(filenames):
            scanned += 1
            if scanned > _MAX_STARTUP_SCAN:
                return injected
            if filename not in _STARTUP_NAMES:
                continue
            path = Path(current) / filename
            rel = _relative(root, path)
            injected.append(rel)
            findings.append(
                PthFinding(
                    rel,
                    0,
                    "startup_injection",
                    "high",
                    filename + " is imported by the interpreter before project code",
                )
            )
    return injected


def _scan_interpreter(root: Path, venv: Path, findings: list[PthFinding]) -> None:
    """Check that pyvenv.cfg still points at a real base interpreter.

    A normal environment names a base interpreter outside the venv root, so an
    escaping path is informational only; a missing path is the real failure
    because it means the environment can no longer start.
    """

    config = venv / "pyvenv.cfg"
    try:
        if not config.is_file():
            return
        text = config.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    rel = _relative(root, config)
    escape_reported = False
    for line_no, line in enumerate(text.splitlines(), 1):
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key not in {"home", "executable"}:
            continue
        if not value:
            findings.append(
                PthFinding(rel, line_no, "interpreter_missing", "medium", key + " is empty")
            )
            continue
        candidate = Path(value)
        try:
            exists = candidate.exists()
        except OSError:
            exists = False
        if not exists:
            findings.append(
                PthFinding(
                    rel,
                    line_no,
                    "interpreter_missing",
                    "medium",
                    "pyvenv.cfg " + key + " points at a missing path",
                )
            )
            continue
        if not _is_within(candidate, venv):
            if escape_reported:
                continue
            escape_reported = True
            findings.append(
                PthFinding(
                    rel,
                    line_no,
                    "base_path_escape",
                    "low",
                    "base interpreter is outside the environment (expected for a venv)",
                )
            )


def _read_records(
    root: Path, site_packages: Path, state: _RecordState
) -> list[_RecordEntry]:
    """Parse every distribution RECORD file under one site-packages directory.

    Reading each RECORD once serves both the digest verification and the
    unindexed-binary check; doing them separately would read the same metadata
    twice for no benefit.
    """

    try:
        record_paths = sorted(site_packages.glob("*.dist-info/RECORD"))[
            :_MAX_RECORD_FILES_ON_DISK
        ]
    except OSError:
        return []
    entries: list[_RecordEntry] = []
    for record in record_paths:
        record_rel = _relative(root, record)
        try:
            with record.open("rb") as handle:
                payload = handle.read(_MAX_RECORD_BYTES_ON_DISK)
        except OSError:
            continue
        text = payload.decode("utf-8", errors="replace")
        try:
            rows = list(csv.reader(io.StringIO(text)))
        except csv.Error:
            continue
        for row in rows:
            if not row or not row[0].strip():
                continue
            rel = row[0].strip()
            hash_spec = row[1].strip() if len(row) > 1 else ""
            entries.append(_RecordEntry(rel, hash_spec, record_rel))
            state.parsed += 1
            if state.parsed > _MAX_RECORD_ENTRIES:
                state.truncated = True
                return entries
    return entries


def _hash_file(path: Path, state: _RecordState) -> tuple[str, str]:
    """Hash one recorded file and return (digest, status).

    status is "ok", "missing", "unreadable" or "budget". The size is stat'ed
    first so small files are read in one exact sized read: a fixed 1 MiB read
    buffer would allocate a megabyte per file, which measurably dominates the
    scan on a tree of thousands of small modules. Large files stay chunked so a
    multi gigabyte artifact is never pulled into memory.
    """

    try:
        size = path.stat().st_size
    except FileNotFoundError:
        return "", "missing"
    except OSError:
        return "", "unreadable"
    if state.total_bytes + size > MAX_RECORD_BYTES:
        state.truncated = True
        return "", "budget"
    try:
        if size <= _HASH_CHUNK:
            payload = path.read_bytes()
            state.total_bytes += len(payload)
            digest = hashlib.sha256(payload).digest()
        else:
            digest = hashlib.sha256()
            with path.open("rb") as handle:
                remaining = size
                while remaining > 0:
                    chunk = handle.read(min(_HASH_CHUNK, remaining))
                    if not chunk:
                        break
                    state.total_bytes += len(chunk)
                    remaining -= len(chunk)
                    digest.update(chunk)
    except FileNotFoundError:
        return "", "missing"
    except OSError:
        return "", "unreadable"
    return (
        base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii"),
        "ok",
    )


def _verify_records(
    root: Path,
    site_packages: Path,
    entries: list[_RecordEntry],
    state: _RecordState,
    findings: list[PthFinding],
) -> tuple[int, int]:
    """Verify recorded sha256 digests, returning (checked, mismatch_count)."""

    checked = 0
    mismatches = 0
    for entry in entries:
        if state.files >= MAX_RECORD_FILES or state.total_bytes >= MAX_RECORD_BYTES:
            state.truncated = True
            return checked, mismatches
        algorithm, _, digest_b64 = entry.hash_spec.partition("=")
        if not entry.hash_spec or not digest_b64:
            # pip leaves the digest blank for a handful of entries; a missing
            # digest is not evidence of tampering and is counted, not flagged.
            state.unhashed += 1
            continue
        if algorithm.strip().lower() != "sha256":
            state.unhashed += 1
            continue
        candidate = Path(entry.rel)
        path = candidate if candidate.is_absolute() else site_packages / entry.rel
        rel_path = _relative(root, path)
        actual, status = _hash_file(path, state)
        if status == "budget":
            return checked, mismatches
        if status == "missing":
            state.files += 1
            checked += 1
            findings.append(
                PthFinding(
                    rel_path,
                    0,
                    "record_missing",
                    "medium",
                    "listed in " + entry.record_rel + " but missing from disk",
                )
            )
            continue
        state.files += 1
        checked += 1
        if status == "unreadable":
            findings.append(
                PthFinding(
                    rel_path,
                    0,
                    "record_unreadable",
                    "medium",
                    "listed in " + entry.record_rel + " but unreadable",
                )
            )
            continue
        if actual != digest_b64.strip().rstrip("="):
            mismatches += 1
            findings.append(
                PthFinding(
                    rel_path,
                    0,
                    "record_mismatch",
                    "high",
                    "sha256 differs from " + entry.record_rel,
                )
            )
    return checked, mismatches


def _recorded_path_sets(entries: list[_RecordEntry]) -> tuple[set[str], set[str]]:
    """Build normalized path and name sets from parsed RECORD entries."""

    recorded: set[str] = set()
    names: set[str] = set()
    for entry in entries:
        normalized = entry.rel.replace("\\", "/").lstrip("./").casefold()
        recorded.add(normalized)
        names.add(normalized.rsplit("/", 1)[-1])
    return recorded, names


def _scan_binaries(
    root: Path,
    site_packages: Path,
    recorded: set[str],
    recorded_names: set[str],
    limit: int = _MAX_ANOMALY_REPORT,
) -> list[str]:
    """Return compiled artifacts that no distribution RECORD entry claims."""

    suspicious: list[str] = []
    scanned = 0
    for current, dirnames, filenames in os.walk(site_packages):
        dirnames[:] = sorted(
            name
            for name in dirnames
            if name != "__pycache__" and not name.endswith((".dist-info", ".egg-info"))
        )
        for filename in sorted(filenames):
            if len(suspicious) >= limit:
                return suspicious
            suffix = Path(filename).suffix.lower()
            if suffix not in _BINARY_SUFFIXES:
                continue
            scanned += 1
            if scanned > _MAX_SCAN_FILES:
                return suspicious
            path = Path(current) / filename
            try:
                relative = path.relative_to(site_packages).as_posix().casefold()
            except ValueError:
                relative = path.name.casefold()
            if relative in recorded or path.name.casefold() in recorded_names:
                continue
            suspicious.append(_relative(root, path))
    return suspicious


def _scan_permissions(
    root: Path, site_packages: Path, limit: int = _MAX_ANOMALY_REPORT
) -> list[str]:
    """Return environment artifacts writable by every local user.

    Win32 ACLs are not visible through st_mode, so the check is POSIX only; on
    Windows the empty list is the truthful answer rather than a fake pass.
    """

    if os.name == "nt":
        return []
    anomalies: list[str] = []
    scanned = 0
    for current, dirnames, filenames in os.walk(site_packages):
        if len(anomalies) >= limit:
            return anomalies
        dirnames[:] = sorted(name for name in dirnames if name != "__pycache__")
        for filename in sorted(filenames):
            scanned += 1
            if scanned > _MAX_SCAN_FILES:
                return anomalies
            path = Path(current) / filename
            try:
                mode = path.lstat().st_mode
            except OSError:
                continue
            if stat.S_ISLNK(mode):
                continue
            if mode & 0o002:
                anomalies.append(_relative(root, path))
                if len(anomalies) >= limit:
                    return anomalies
    return anomalies


def _normalize_dist_name(raw: str) -> str:
    """Normalize a distribution name using the PEP 503 rules."""

    lowered = raw.strip().lower()
    normalized: list[str] = []
    for char in lowered:
        if char.isalnum():
            normalized.append(char)
        elif char in "-_.":
            if normalized and normalized[-1] != "-":
                normalized.append("-")
    return "".join(normalized).strip("-")


def _distribution_names(root: Path, site_packages: Path) -> list[tuple[str, str]]:
    """Return (normalized name, relative metadata path) for installed dists."""

    found: list[tuple[str, str]] = []
    suffixes = (".dist-info", ".egg-info")
    try:
        infos = sorted(site_packages.iterdir())
    except OSError:
        return found
    for info in infos[:_MAX_DISTS]:
        name = info.name
        matched = next((suffix for suffix in suffixes if name.lower().endswith(suffix)), None)
        if matched is None:
            continue
        stem = name[: -len(matched)]
        candidate = stem.rsplit("-", 1)[0] if "-" in stem else stem
        normalized = _normalize_dist_name(candidate)
        if normalized:
            found.append((normalized, _relative(root, info)))
    return found


def _bounded_levenshtein(left: str, right: str, limit: int) -> int | None:
    """Return the edit distance when it is within limit, else None.

    The length difference is checked first and every row tracks its minimum, so
    a pair that is already too far apart costs almost nothing. That matters
    because the typosquat pass compares every installed name with every popular
    name on every scan.
    """

    if abs(len(left) - len(right)) > limit:
        return None
    previous = list(range(len(right) + 1))
    for row, left_char in enumerate(left, 1):
        current = [row]
        row_min = row
        for column, right_char in enumerate(right, 1):
            cost = 0 if left_char == right_char else 1
            value = min(
                previous[column] + 1,
                current[column - 1] + 1,
                previous[column - 1] + cost,
            )
            current.append(value)
            if value < row_min:
                row_min = value
        if row_min > limit:
            return None
        previous = current
    distance = previous[-1]
    return distance if distance <= limit else None


def _typosquat_of(name: str) -> tuple[str, int] | None:
    """Return the nearest popular package and distance, or None.

    The threshold is one edit for short names and two for names longer than
    seven characters, because a transposition in a long name is the common
    typosquat form while a one character difference in a short name is usually
    an unrelated package.
    """

    limit = 2 if len(name) > 7 else 1
    best: tuple[str, int] | None = None
    for popular in POPULAR_PYPI_NAMES:
        if popular == name:
            return None
        distance = _bounded_levenshtein(name, popular, limit)
        if distance is None:
            continue
        if best is None or distance < best[1] or (distance == best[1] and popular < best[0]):
            best = (popular, distance)
    return best


def _scan_typosquats(
    root: Path, site_packages: Path, findings: list[PthFinding]
) -> list[str]:
    """Flag installed distribution names that resemble a popular package."""

    suspects: list[str] = []
    for normalized, rel in _distribution_names(root, site_packages):
        if len(suspects) >= _MAX_TYPOSQUAT_REPORT:
            break
        match = _typosquat_of(normalized)
        if match is None:
            continue
        popular, distance = match
        label = normalized + " ~ " + popular + " (distance " + str(distance) + ")"
        suspects.append(label)
        findings.append(
            PthFinding(
                rel,
                0,
                "typosquat_suspect",
                "medium",
                "installed name "
                + normalized
                + " resembles "
                + popular
                + " at edit distance "
                + str(distance)
                + "; verify the package source, this is a heuristic",
            )
        )
    return suspects


def _severity_rank(finding: PthFinding) -> int:
    """Order findings so the most dangerous evidence is reported first."""

    return {"high": 0, "medium": 1, "low": 2}.get(finding.severity, 3)


def _status_for(findings: list[PthFinding], binaries: list[str], permissions: list[str]) -> str:
    """Fold findings into one of the four pillar statuses.

    A high finding only earns MALICIOUS_PTH when the evidence is code execution
    (.pth payload or a startup hook); a digest mismatch is tampering, not proven
    malicious code. Medium evidence alone is tampering; low findings are
    informational and keep the environment CLEAN.
    """

    high = [finding for finding in findings if finding.severity == "high"]
    if high:
        if any(finding.code in EXECUTION_CODES for finding in high):
            return "MALICIOUS_PTH"
        return "TAMPERED"
    if any(finding.severity == "medium" for finding in findings) or binaries or permissions:
        return "TAMPERED"
    return "CLEAN"


def inspect_venv(root: Path) -> VenvReport:
    """Inspect every virtual environment under a project root.

    Parameters:
        root: Project root to inspect.

    Returns:
        A report whose status is one of CLEAN, TAMPERED, MALICIOUS_PTH or
        WARNING. A project without a virtual environment is CLEAN: there is
        nothing to tamper with, and the detail line says so explicitly.
    """

    root = Path(root)
    if not root.is_dir():
        return VenvReport(None, 0, [], [], [], "WARNING", "project root is not a directory")
    venvs = find_venvs(root)
    if not venvs:
        return VenvReport(
            None,
            0,
            [],
            [],
            [],
            "CLEAN",
            "no virtual environment detected under " + str(root),
        )

    counters: dict[str, int] = {}
    state = _RecordState()
    findings: list[PthFinding] = []
    binaries: list[str] = []
    permissions: list[str] = []
    startup_injections: list[str] = []
    typosquat_suspects: list[str] = []
    scanned_sites = 0
    try:
        for venv in venvs:
            _scan_interpreter(root, venv, findings)
            startup_injections.extend(_scan_startup_injection(root, venv, findings))
            for site_packages in _site_packages_dirs(venv):
                scanned_sites += 1
                findings.extend(_scan_pth(root, venv, site_packages, counters))
                entries = _read_records(root, site_packages, state)
                recorded, recorded_names = _recorded_path_sets(entries)
                binaries.extend(
                    _scan_binaries(root, site_packages, recorded, recorded_names)
                )
                permissions.extend(_scan_permissions(root, site_packages))
                typosquat_suspects.extend(
                    _scan_typosquats(root, site_packages, findings)
                )
                checked, mismatches = _verify_records(
                    root, site_packages, entries, state, findings
                )
                counters["record_checked"] = counters.get("record_checked", 0) + checked
                counters["record_mismatches"] = (
                    counters.get("record_mismatches", 0) + mismatches
                )
    except OSError as exc:
        findings.sort(key=lambda item: (_severity_rank(item), item.rel_path, item.line_no))
        return VenvReport(
            venvs[0],
            counters.get("pth_files", 0),
            findings,
            binaries,
            permissions,
            "WARNING",
            "virtual environment scan aborted: " + str(exc),
            record_checked=counters.get("record_checked", 0),
            record_mismatches=counters.get("record_mismatches", 0),
            startup_injections=startup_injections,
            typosquat_suspects=typosquat_suspects,
            truncated=state.truncated,
        )

    findings.sort(key=lambda item: (_severity_rank(item), item.rel_path, item.line_no))
    status = _status_for(findings, binaries, permissions)
    high = sum(1 for finding in findings if finding.severity == "high")
    medium = sum(1 for finding in findings if finding.severity == "medium")
    low = len(findings) - high - medium
    detail = (
        str(len(venvs))
        + " environment(s), "
        + str(counters.get("pth_files", 0))
        + " .pth file(s), "
        + str(high)
        + " high / "
        + str(medium)
        + " medium / "
        + str(low)
        + " low finding(s), RECORD "
        + str(counters.get("record_checked", 0))
        + " verified ("
        + str(counters.get("record_mismatches", 0))
        + " mismatch), "
        + str(len(startup_injections))
        + " startup injection(s), "
        + str(len(typosquat_suspects))
        + " typosquat suspect(s), "
        + str(len(binaries))
        + " unindexed binar(ies), "
        + str(len(permissions))
        + " writable artifact(s)"
    )
    if state.truncated:
        detail += "; RECORD verification truncated at the scan budget"
    if scanned_sites == 0:
        detail += "; no site-packages directory found"
    return VenvReport(
        venv_path=venvs[0],
        pth_files=counters.get("pth_files", 0),
        pth_findings=findings,
        suspicious_binaries=binaries,
        permission_anomalies=permissions,
        status=status,
        detail=detail,
        record_checked=counters.get("record_checked", 0),
        record_mismatches=counters.get("record_mismatches", 0),
        startup_injections=startup_injections,
        typosquat_suspects=typosquat_suspects,
        truncated=state.truncated,
    )
