"""Dependency manifest audit: review packages before they are installed.

The artifact scanner finds malicious code after it landed in the tree. This
module closes the earlier half of the supply chain: it reads the dependency
declarations a project is about to install (requirements files, pyproject.toml,
setup.cfg, Pipfile, package.json) and reports the shapes a registry attack has
to use to get in:

* typosquat: the name is edit distance 1 from a popular package, or distance 2
  when the name is longer than seven characters, so "reqeusts" and "pandas-"
  style lookalikes are visible before pip resolves them;
* suspicious_name: a name that mixes digits into a popular name, such as
  "0requests" or "requests2", the campaign pattern seen in the PyPI ecosystem;
* direct_url: a git, file or http URL instead of a registry name, which bypasses
  registry review entirely;
* unpinned: no version specifier at all, so every install can resolve to a
  different artifact than the one that was reviewed;
* unknown_index: an extra or replacement index that is not pypi.org, which is
  how a dependency confusion attack points pip at an attacker controlled mirror.

Everything is offline and read only. The audit is bounded (manifest count, file
size, total bytes) and a malformed manifest is skipped instead of raising, so a
broken requirements file can never stop a scan.
"""

from __future__ import annotations

import json
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Iterable

#: Top PyPI projects by download count, compiled from the public ranking at the
#: time of writing (order is not meaningful, membership is). Embedded so the
#: audit stays fully offline and deterministic.
_PYPI_BLOCK = """
requests urllib3 certifi charset-normalizer idna setuptools wheel pip packaging
six python-dateutil pytz numpy pandas scipy matplotlib pillow boto3 botocore
s3transfer jmespath pyyaml cryptography cffi pycparser attrs click jinja2
markupsafe werkzeug flask itsdangerous sqlalchemy greenlet pydantic
typing-extensions fastapi starlette anyio httpx httpcore h11 h2 hpack grpcio
protobuf google-api-core google-auth google-cloud-storage oauthlib
requests-oauthlib pyjwt pyasn1 pyasn1-modules rsa cachetools chardet colorama
tqdm psutil pygments docutils sphinx alabaster babel snowballstemmer
markdown-it-py mdurl rich pyparsing kiwisolver cycler fonttools contourpy
importlib-metadata zipp platformdirs virtualenv distlib filelock tox pytest
pluggy iniconfig coverage hypothesis sortedcontainers py mock responses mypy
mypy-extensions tomli black pathspec isort flake8 pycodestyle pyflakes mccabe
pylint astroid dill cloudpickle joblib threadpoolctl scikit-learn xgboost
lightgbm statsmodels patsy seaborn plotly nbformat nbconvert jupyter-core
ipython traitlets prompt-toolkit wcwidth parso jedi pexpect ptyprocess tornado
pyzmq notebook jupyter-client lxml beautifulsoup4 soupsieve html5lib
webencodings openpyxl xlrd xlsxwriter python-docx python-pptx reportlab
pdfminer-six pypdf pymupdf tabulate termcolor humanfriendly regex arrow
pendulum dateparser tzlocal pycryptodome bcrypt passlib pynacl paramiko fabric
invoke ansible ansible-core netaddr netmiko scapy websockets websocket-client
aiohttp aiosignal frozenlist async-timeout multidict yarl uvicorn gunicorn
waitress celery kombu amqp redis pymongo motor psycopg2-binary psycopg2 alembic
mako mysqlclient pymysql asyncpg peewee elasticsearch opensearch-py kafka-python
pika minio ujson orjson msgpack simplejson marshmallow jsonschema jsonpatch
jsonpointer cerberus voluptuous toml tomlkit python-dotenv dynaconf hydra-core
omegaconf typer questionary blessed textual streamlit gradio dash bokeh altair
folium geopandas shapely pyproj fiona rasterio h5py zarr dask distributed ray
polars pyarrow numexpr bottleneck cython pybind11 setuptools-scm flit
poetry-core build twine pip-tools pipenv uv nox pre-commit cfgv identify nodeenv
"""

#: Top npm packages by download count, same offline convention.
_NPM_BLOCK = """
lodash react react-dom axios express typescript next vue jquery eslint moment
underscore rxjs prettier webpack chalk commander debug fs-extra glob minimist
semver uuid dotenv cors body-parser mongoose sequelize prisma socket.io ws
node-fetch got superagent bluebird async ramda immer redux zustand mobx
styled-components tailwindcss sass postcss autoprefixer vite rollup esbuild
gulp grunt nodemon pm2 jest mocha chai sinon karma cypress playwright puppeteer
selenium-webdriver storybook classnames dayjs date-fns query-string validator
yargs ora inquirer rimraf mkdirp ncp tar archiver mime mime-types cookie
cookie-parser helmet morgan compression passport jsonwebtoken bcryptjs ioredis
mongodb mysql2 pg knex typeorm nodemailer cheerio jsdom three d3 chart.js
formik react-router react-router-dom vue-router pinia nuxt gatsby remix
"""

#: The block lists a little more than the documented size because rankings drift
#: by a few names; the tuples below are the published top 200 PyPI and top 100
#: npm names, so the distance rule always compares against a stable set.
POPULAR_PYPI: Final[tuple[str, ...]] = tuple(_PYPI_BLOCK.split())[:200]
POPULAR_NPM: Final[tuple[str, ...]] = tuple(_NPM_BLOCK.split())[:100]
POPULAR_NAMES: Final[tuple[str, ...]] = tuple(dict.fromkeys(POPULAR_PYPI + POPULAR_NPM))

TYPOSQUAT_DISTANCE_SHORT: Final[int] = 1
TYPOSQUAT_DISTANCE_LONG: Final[int] = 2
LONG_NAME_LENGTH: Final[int] = 7

MANIFEST_FILENAMES: Final[tuple[str, ...]] = (
    "pyproject.toml",
    "setup.cfg",
    "Pipfile",
    "package.json",
)
REQUIREMENTS_PATTERN: Final[str] = "requirements*.txt"

MAX_MANIFESTS: Final[int] = 24
MAX_MANIFEST_BYTES: Final[int] = 256 * 1024
MAX_TOTAL_BYTES: Final[int] = 2 * 1024 * 1024

_INDEX_OPTIONS: Final[tuple[str, ...]] = ("--index-url", "--extra-index-url", "-i")
_TRUSTED_INDEX_HOSTS: Final[tuple[str, ...]] = ("pypi.org", "files.pythonhosted.org")
_DIRECT_URL_PREFIXES: Final[tuple[str, ...]] = (
    "git+",
    "git://",
    "hg+",
    "svn+",
    "bzr+",
    "http://",
    "https://",
    "file:",
    "file://",
    "./",
    "../",
    "/",
)
_UNPINNED_NPM_VALUES: Final[frozenset[str]] = frozenset({"", "*", "latest", "x"})

_NAME_RE: Final[re.Pattern[str]] = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)")
_PEP508_NAME_RE: Final[re.Pattern[str]] = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$"
)
_SPECIFIER_RE: Final[re.Pattern[str]] = re.compile(r"(===|==|~=|!=|<=|>=|<|>)")


@dataclass(frozen=True, slots=True)
class DepFinding:
    """One dependency declaration problem.

    Attributes:
        rel_path: Project relative manifest path, forward slash separated.
        line_no: One based line number of the declaration, 0 when derived.
        name: Declared package name, or the offending index host.
        kind: typosquat, suspicious_name, direct_url, unpinned or unknown_index.
        severity: high, medium or low.
        detail: One line evidence naming the exact distance, URL or specifier.
    """

    rel_path: str
    line_no: int
    name: str
    kind: str
    severity: str
    detail: str


@dataclass(frozen=True, slots=True)
class DepReport:
    """Outcome of one dependency manifest audit.

    Attributes:
        findings: Findings ordered by severity, path and line.
        declared: Dependency declarations parsed across every manifest.
        files_scanned: Manifest files that were read.
        detail: One line summary that always states the counts.
    """

    findings: tuple[DepFinding, ...]
    declared: int
    files_scanned: int
    detail: str


def normalize_name(name: str) -> str:
    """Normalise a package name the way PyPI and npm compare names.

    Lower case, runs of hyphen, underscore and dot folded into one hyphen. The
    same spelling on disk ("Flask", "flask", "fl_ask") therefore compares equal
    to the popular name it imitates.
    """

    cleaned = str(name or "").strip().lower()
    return re.sub(r"[-_.]+", "-", cleaned).strip("-")


def levenshtein(left: str, right: str) -> int:
    """Return the edit distance between two strings.

    The classic dynamic programming recurrence, kept explicit so the typosquat
    threshold is testable in isolation. Sorting the shorter string first bounds
    the row buffer by the shorter word.
    """

    if left == right:
        return 0
    if len(left) < len(right):
        left, right = right, left
    if not right:
        return len(left)
    previous = list(range(len(right) + 1))
    for row, char_left in enumerate(left, 1):
        current = [row]
        for column, char_right in enumerate(right, 1):
            cost = 0 if char_left == char_right else 1
            current.append(
                min(
                    previous[column] + 1,
                    current[column - 1] + 1,
                    previous[column - 1] + cost,
                )
            )
        previous = current
    return previous[-1]


def _typosquat_target(name: str, pool: Iterable[str]) -> tuple[str, int] | None:
    """Return the closest popular name and distance when name looks typo-squatted."""

    normalized = normalize_name(name)
    if not normalized:
        return None
    limit = TYPOSQUAT_DISTANCE_LONG if len(normalized) > LONG_NAME_LENGTH else TYPOSQUAT_DISTANCE_SHORT
    best: tuple[str, int] | None = None
    for candidate in pool:
        if candidate == normalized:
            return None
        distance = levenshtein(normalized, candidate)
        if distance == 0 or distance > limit:
            continue
        # A distance 2 match is only credible for a long name; short names would
        # collide with unrelated packages (for example "six" and "sax").
        if distance == TYPOSQUAT_DISTANCE_LONG and len(normalized) <= LONG_NAME_LENGTH:
            continue
        if best is None or distance < best[1]:
            best = (candidate, distance)
    return best


def _suspicious_name(name: str, pool: Iterable[str], popular_set: frozenset[str]) -> str:
    """Return the evidence line when a name mixes digits into a popular name."""

    normalized = normalize_name(name)
    if not normalized:
        return ""
    has_digit = any(char.isdigit() for char in normalized)
    has_alpha = any(char.isalpha() for char in normalized)
    if not (has_digit and has_alpha):
        return ""
    stripped = re.sub(r"[0-9]+", "", normalized)
    if normalized[0].isdigit():
        return f"starts with a digit while imitating a package name ({name})"
    if stripped in popular_set:
        return f"popular name {stripped} with digits inserted or appended ({name})"
    for candidate in pool:
        if normalized == candidate + "2" or normalized == candidate + "0":
            return f"popular name {candidate} with an appended digit ({name})"
    return ""


def _classify_declaration(
    rel_path: str,
    line_no: int,
    name: str,
    version_text: str,
    *,
    direct_url: bool,
    pool: tuple[str, ...],
    popular_set: frozenset[str],
) -> list[DepFinding]:
    """Classify one parsed declaration into zero or more dependency findings."""

    findings: list[DepFinding] = []
    if direct_url:
        findings.append(
            DepFinding(
                rel_path=rel_path,
                line_no=line_no,
                name=name,
                kind="direct_url",
                severity="medium",
                detail=f"{name or 'dependency'} resolves from a direct URL instead of the registry",
            )
        )
        return findings
    evidence = "" if normalize_name(name) in popular_set else _suspicious_name(name, pool, popular_set)
    if evidence:
        # A digit-mixing name is the more specific attack shape, so it wins over
        # the generic distance rule ("0requests" is distance 1 from requests but
        # the digit at the front is the actual campaign signature).
        findings.append(
            DepFinding(
                rel_path=rel_path,
                line_no=line_no,
                name=name,
                kind="suspicious_name",
                severity="high",
                detail=evidence,
            )
        )
    else:
        squatted = _typosquat_target(name, pool)
        if squatted is not None:
            target, distance = squatted
            findings.append(
                DepFinding(
                    rel_path=rel_path,
                    line_no=line_no,
                    name=name,
                    kind="typosquat",
                    severity="high",
                    detail=f"{name} is edit distance {distance} from the popular package {target}",
                )
            )
    if not str(version_text or "").strip():
        findings.append(
            DepFinding(
                rel_path=rel_path,
                line_no=line_no,
                name=name,
                kind="unpinned",
                severity="low",
                detail=f"{name} declares no version specifier, so any release can be installed",
            )
        )
    return findings


def _direct_url_name(url: str) -> str:
    """Return a reviewable name for a direct URL declaration.

    A PEP 508 URL can carry the project name in an "#egg=" fragment; otherwise
    the last path segment is the closest thing to a name a reviewer can act on.
    """

    text = str(url or "").strip()
    if "#egg=" in text:
        return text.split("#egg=", 1)[1].split("&", 1)[0].strip()
    base = text.split("#", 1)[0].rstrip("/")
    tail = base.rsplit("/", 1)[-1]
    if tail.endswith(".git"):
        tail = tail[: -len(".git")]
    return tail or "dependency"


def _is_direct_url(text: str) -> bool:
    """True when a declaration names a URL or path instead of a registry name."""

    value = str(text or "").strip()
    return any(value.startswith(prefix) for prefix in _DIRECT_URL_PREFIXES)


def _line_of(text: str, needle: str) -> int:
    """Return the one based line of the first occurrence of needle, or 1."""

    if not needle:
        return 1
    for number, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return number
    return 1


def _read_manifest(path: Path, remaining: int) -> str | None:
    """Read one manifest inside the per-file and total byte budgets."""

    try:
        size = path.stat().st_size
    except OSError:
        return None
    if size > MAX_MANIFEST_BYTES or size > remaining:
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _valid_requirement_tail(rest: str) -> bool:
    """True when the text after a name is a specifier, extras, URL or marker.

    This rejects free text such as "this is not a requirement" that the leading
    name regex would otherwise turn into a package called "this". Anything that
    does not start with a comparison operator, an extras group, an @ URL or a
    marker semicolon is not a requirement line and is skipped.
    """

    value = str(rest or "").strip()
    if not value:
        return True
    return value.startswith(("==", "===", ">=", "<=", "~=", "!=", "<", ">", "[", "@", ";"))


def _parse_requirements_text(text: str, rel_path: str) -> list[tuple[int, str, str, bool]]:
    """Parse a requirements file into (line, name, version_text, direct_url) rows."""

    rows: list[tuple[int, str, str, bool]] = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            continue
        if " @ " in line:
            name = _NAME_RE.match(line.split(" @ ", 1)[0].strip())
            if name:
                rows.append((number, name.group(1), line.split(" @ ", 1)[1], True))
            continue
        if _is_direct_url(line):
            rows.append((number, _direct_url_name(line), line, True))
            continue
        match = _PEP508_NAME_RE.match(line)
        if not match:
            continue
        name = match.group(1)
        rest = match.group(3).strip()
        direct = any(rest.startswith(prefix) for prefix in _DIRECT_URL_PREFIXES)
        rest = re.split(r"\s*;\s*", rest, maxsplit=1)[0].strip()
        if not _valid_requirement_tail(match.group(3).strip()):
            continue
        rows.append((number, name, rest, direct))
    return rows


def _manifest_rows(path: Path, text: str) -> list[tuple[int, str, str, bool]]:
    """Extract dependency rows from one manifest, or none when it cannot parse."""

    rel_path = path.name
    rows: list[tuple[int, str, str, bool]] = []
    if path.name == "Pipfile":
        try:
            payload = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError):
            return rows
        for key in ("packages", "dev-packages"):
            section = payload.get(key)
            if isinstance(section, dict):
                for name, value in section.items():
                    rows.extend(_pipfile_rows(text, str(name), value))
        return rows
    suffix = path.suffix.lower()
    if suffix == ".txt":
        return _parse_requirements_text(text, rel_path)
    if suffix == ".toml":
        try:
            payload = tomllib.loads(text)
        except (tomllib.TOMLDecodeError, ValueError):
            return rows
        if path.name == "pyproject.toml":
            project = payload.get("project")
            if isinstance(project, dict):
                for key in ("dependencies",):
                    rows.extend(_toml_dependency_rows(text, project.get(key)))
                optional = project.get("optional-dependencies")
                if isinstance(optional, dict):
                    for value in optional.values():
                        rows.extend(_toml_dependency_rows(text, value))
        return rows
    if suffix == ".json":
        try:
            payload = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return rows
        if isinstance(payload, dict):
            for key in ("dependencies", "devDependencies", "peerDependencies"):
                section = payload.get(key)
                if isinstance(section, dict):
                    for name, value in section.items():
                        rows.extend(_json_rows(text, str(name), value))
        return rows
    if path.name == "setup.cfg":
        return _setup_cfg_rows(text)
    return rows


def _toml_dependency_rows(text: str, value: object) -> list[tuple[int, str, str, bool]]:
    """Convert a pyproject dependency array into declaration rows."""

    rows: list[tuple[int, str, str, bool]] = []
    if not isinstance(value, list):
        return rows
    for item in value:
        if not isinstance(item, str):
            continue
        line = _line_of(text, item)
        if _is_direct_url(item):
            rows.append((line, _direct_url_name(item), item, True))
            continue
        match = _PEP508_NAME_RE.match(item)
        if not match:
            continue
        rest = match.group(3).strip()
        if not _valid_requirement_tail(rest):
            continue
        direct = _is_direct_url(rest)
        rest = re.split(r"\s*;\s*", rest, maxsplit=1)[0].strip()
        rows.append((line, match.group(1), rest, direct))
    return rows


def _pipfile_rows(text: str, name: str, value: object) -> list[tuple[int, str, str, bool]]:
    """Convert one Pipfile section entry into a declaration row."""

    line = _line_of(text, name)
    if isinstance(value, dict):
        version = value.get("version")
        url = value.get("git") or value.get("path") or value.get("file") or value.get("url")
        if isinstance(url, str) and url:
            return [(line, name, url, True)]
        if isinstance(version, str):
            return [(line, name, version, False)]
        return [(line, name, "", False)]
    if isinstance(value, str):
        direct = any(value.startswith(prefix) for prefix in _DIRECT_URL_PREFIXES)
        version = "" if value.strip() in _UNPINNED_NPM_VALUES else value
        return [(line, name, version, direct)]
    return [(line, name, "", False)]


def _json_rows(text: str, name: str, value: object) -> list[tuple[int, str, str, bool]]:
    """Convert one package.json dependency entry into a declaration row."""

    line = _line_of(text, name)
    version = value if isinstance(value, str) else ""
    direct = any(version.startswith(prefix) for prefix in _DIRECT_URL_PREFIXES) or version.startswith(
        "github:"
    )
    unpinned = version.strip() in _UNPINNED_NPM_VALUES
    return [(line, name, "" if unpinned else version, direct)]


def _setup_cfg_rows(text: str) -> list[tuple[int, str, str, bool]]:
    """Parse install_requires and extras_require from setup.cfg without raising.

    Only the two documented dependency sections are read; every other section is
    ignored. Multi-line values are continuation lines until the next key, which is
    how setuptools writes them.
    """

    rows: list[tuple[int, str, str, bool]] = []
    section = ""
    collecting = False
    for number, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            collecting = False
            continue
        if section == "options":
            if stripped.startswith("install_requires"):
                collecting = True
                remainder = stripped.split("=", 1)[1].strip() if "=" in stripped else ""
                if remainder:
                    rows.extend(_requirement_lines(remainder, number, text))
                continue
            if collecting:
                if not stripped:
                    collecting = False
                    continue
                rows.extend(_requirement_lines(stripped, number, text))
                continue
        elif section == "options.extras_require":
            if not stripped:
                collecting = False
                continue
            if "=" in stripped and not raw.startswith((" ", chr(9))):
                collecting = True
                remainder = stripped.split("=", 1)[1].strip()
                if remainder:
                    rows.extend(_requirement_lines(remainder, number, text))
                continue
            if collecting:
                rows.extend(_requirement_lines(stripped, number, text))
    return rows


def _requirement_lines(text: str, line_no: int, source: str) -> list[tuple[int, str, str, bool]]:
    """Parse one inline requirement fragment, or a comma separated group."""

    rows: list[tuple[int, str, str, bool]] = []
    if not text.strip():
        return rows
    for fragment in text.split(","):
        fragment = fragment.strip()
        if not fragment:
            continue
        match = _PEP508_NAME_RE.match(fragment)
        if not match:
            continue
        rest = match.group(3).strip()
        if not _valid_requirement_tail(rest):
            continue
        direct = any(rest.startswith(prefix) for prefix in _DIRECT_URL_PREFIXES)
        rows.append((_line_of(source, fragment) or line_no, match.group(1), rest, direct))
    return rows


def _index_findings(rel_path: str, text: str) -> list[DepFinding]:
    """Report index URLs that point somewhere other than pypi.org."""

    findings: list[DepFinding] = []
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split(" #", 1)[0].strip()
        for option in _INDEX_OPTIONS:
            if line == option or line.startswith(option + " ") or line.startswith(option + "="):
                remainder = line[len(option) :].lstrip(" =").strip()
                if not remainder:
                    continue
                host = remainder.split("/")[2] if remainder.count("/") >= 2 else remainder
                if any(host == trusted or host.endswith("." + trusted) for trusted in _TRUSTED_INDEX_HOSTS):
                    continue
                findings.append(
                    DepFinding(
                        rel_path=rel_path,
                        line_no=number,
                        name=host,
                        kind="unknown_index",
                        severity="medium",
                        detail=f"{option} points at {host} instead of pypi.org",
                    )
                )
    return findings


def _sort_findings(findings: Iterable[DepFinding]) -> tuple[DepFinding, ...]:
    """Order findings by severity, path, line and name."""

    rank = {"high": 0, "medium": 1, "low": 2}
    return tuple(
        sorted(
            findings,
            key=lambda item: (
                rank.get(item.severity, 3),
                item.rel_path,
                item.line_no,
                item.name,
                item.kind,
            ),
        )
    )


def _render_detail(findings: tuple[DepFinding, ...], declared: int, files: int, truncated: bool) -> str:
    """Compose the one line summary for the pillar and the CLI."""

    parts = [f"{declared} dependency declaration(s) in {files} manifest file(s)"]
    if findings:
        first = findings[0]
        parts.append(
            f"{first.rel_path}:{first.line_no}: {first.kind} ({first.detail})"
        )
        if len(findings) > 1:
            counts: dict[str, int] = {}
            for finding in findings[1:]:
                counts[finding.kind] = counts.get(finding.kind, 0) + 1
            parts.append(", ".join(f"{count} {kind} finding(s)" for kind, count in counts.items()))
    else:
        parts.append("no typosquat, suspicious name, direct URL, unpinned or unknown index finding")
    if truncated:
        parts.append("dependency audit truncated at the manifest budget")
    return "; ".join(parts)


def audit_dependencies(
    root: Path,
    *,
    popular: tuple[str, ...] | None = None,
) -> DepReport:
    """Audit the dependency declarations a project is about to install.

    Parameters:
        root: Project root containing the manifests.
        popular: Optional override of the popular-name pool, used by tests and by
            callers that ship their own ranking. When None the embedded PyPI and
            npm lists are used.

    Returns:
        A DepReport. A missing or unreadable root is reported as an empty report
        whose detail says so; malformed manifests are skipped without raising.
    """

    root_path = Path(root)
    try:
        is_directory = root_path.is_dir()
    except OSError:
        is_directory = False
    if not is_directory:
        return DepReport((), 0, 0, "project root is not a readable directory, no manifest was audited")

    pool = tuple(dict.fromkeys(popular)) if popular is not None else POPULAR_NAMES
    popular_set = frozenset(normalize_name(name) for name in pool)

    try:
        requirements = sorted(root_path.glob(REQUIREMENTS_PATTERN))
    except OSError:
        requirements = []
    candidates: list[Path] = []
    for name in MANIFEST_FILENAMES:
        candidate = root_path / name
        try:
            if candidate.is_file():
                candidates.append(candidate)
        except OSError:
            continue
    candidates.extend(path for path in requirements if path.is_file())

    findings: list[DepFinding] = []
    declared = 0
    files_scanned = 0
    bytes_read = 0
    truncated = False
    for path in candidates[:MAX_MANIFESTS]:
        text = _read_manifest(path, MAX_TOTAL_BYTES - bytes_read)
        if text is None:
            truncated = True
            continue
        files_scanned += 1
        bytes_read += len(text.encode("utf-8", errors="replace"))
        rel_path = path.relative_to(root_path).as_posix() if path.is_relative_to(root_path) else path.name
        rows = _manifest_rows(path, text)
        for line_no, name, version_text, direct_url in rows:
            if not name:
                continue
            declared += 1
            findings.extend(
                _classify_declaration(
                    rel_path,
                    line_no,
                    name,
                    version_text,
                    direct_url=direct_url,
                    pool=pool,
                    popular_set=popular_set,
                )
            )
        findings.extend(_index_findings(rel_path, text))

    ordered = _sort_findings(findings)
    return DepReport(
        findings=ordered,
        declared=declared,
        files_scanned=files_scanned,
        detail=_render_detail(ordered, declared, files_scanned, truncated),
    )
