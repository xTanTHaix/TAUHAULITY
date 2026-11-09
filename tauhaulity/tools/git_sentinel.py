"""Credential scanner for git staged blobs, working trees, history and remotes.

The pre-commit gate and pillar eleven share one scanner so that what the gate
blocks and what the dossier reports can never disagree. Detection is pattern
first and entropy second: an exact pattern hit is cheap and precise, while the
high-entropy assignment rule catches tokens whose issuer we do not know yet.
Every hit is masked before it leaves this module because findings travel into
dossier files, logs and CI output, and a scanner that echoes the secret it found
turns a diagnostic into a second leak.

Each detector family carries a stable kind token and a short revocation hint, so
a finding tells the operator what to revoke instead of only that something looks
wrong. History scanning is bounded by commits, distinct blobs and bytes per blob:
the scanner reports what it could still find inside that window instead of
pretending a repository has no past.

Accepted findings are handled by tauhaulity.tools.allowlist: a candidate whose
fingerprint is recorded there is reported as suppressed instead of active, so a
project can adopt the scanner without a permanent red dossier while a genuinely
new secret in the same file stays visible.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Sequence

from tauhaulity.core.entropy import shannon_entropy

if TYPE_CHECKING:
    from tauhaulity.tools.allowlist import Baseline

REDACTED_MARKER = "****REDACTED****"

# Directories that never belong to a project's own credentials scan: version
# control metadata, virtual environments, dependency caches, provisioning trees
# and our own journal.
#
# The provisioning names matter for coverage, not only for speed: a toolchain
# directory such as .tooling holds a whole Python installation (tens of thousands
# of files), and because dot directories sort first the scanner would spend its
# bounded file budget there and never reach src/ or tests/. The generic
# interpreter probe in _looks_like_installation catches the same trees under any
# other name.
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
        ".tox",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tauhaulity",
        "dist",
        "build",
        "target",
        ".tooling",
        ".toolchains",
        "toolchains",
        ".pyenv",
        ".asdf",
    }
)

# Working tree files worth scanning. The set is intentionally small: it covers
# the places developers actually paste credentials (env files, configs, scripts,
# keys) without walking a whole source tree and blowing the probe budget.
_SCAN_SUFFIXES: frozenset[str] = frozenset(
    {
        ".env",
        ".ini",
        ".cfg",
        ".conf",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".properties",
        ".txt",
        ".md",
        ".py",
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".jsx",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".bat",
        ".cmd",
        ".pem",
        ".key",
        ".crt",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".pgpass",
        ".htpasswd",
    }
)
_SCAN_NAMES: frozenset[str] = frozenset(
    {
        ".env",
        ".npmrc",
        ".pypirc",
        ".netrc",
        ".pgpass",
        ".htpasswd",
        "id_rsa",
        "id_ed25519",
        "id_dsa",
        "credentials",
        "config",
    }
)

_MAX_SCAN_BYTES = 256 * 1024
_MAX_SCAN_FILES = 200
_MAX_STAGED_FILES = 400

#: History scanning is bounded three ways: commits examined, distinct blobs read
#: and bytes read per blob. The public scan_history defaults are generous; a
#: dossier probe passes smaller values because it runs on every audit.
_HISTORY_MAX_BLOBS = 500

#: Blobs fetched per batched cat-file process. Chunking keeps the in memory
#: payload of one batch at roughly sixteen mebibytes at the default blob bound.
_HISTORY_BATCH_BLOBS = 64
_HISTORY_SHORT_SHA = 8
_COMMIT_RE = re.compile(r"^[0-9a-fA-F]{7,64}$")
_ZERO_SHA_RE = re.compile(r"^0+$")

# ---------------------------------------------------------------------------
# Credential rule set
#
# Every rule is a (kind, pattern) pair. The kind token is stable: it appears in
# allowlist fingerprints, dossier slots and the revocation hint table, so it is
# never renamed without an allowlist migration. The patterns are deliberately
# exact because a scanner that flags the word GITHUB_TOKEN in a README trains its
# reader to ignore the whole report.
# ---------------------------------------------------------------------------

# GitHub fine grained tokens are exactly 82 characters after the prefix, but
# fixtures and truncation artefacts show up shorter, so the minimum is generous
# in the other direction and stays anchored on the issuer prefix.
_GITHUB_PAT_RE = re.compile(r"github_pat_[A-Za-z0-9_]{82}")
_GITHUB_CLASSIC_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}")
_GITLAB_TOKEN_RE = re.compile(r"\bglpat-[A-Za-z0-9_.\-]{20,}")
_GOOGLE_API_KEY_RE = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")
_SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}")
_DISCORD_WEBHOOK_RE = re.compile(
    r"https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/"
    r"(?P<webhook_id>\d{17,20})/(?P<token>[A-Za-z0-9_\-]{30,})"
)
_STRIPE_KEY_RE = re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}")
_SENDGRID_KEY_RE = re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")
_TWILIO_KEY_RE = re.compile(r"\bSK[0-9a-fA-F]{32}\b")
_NPM_TOKEN_RE = re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")
_PYPI_TOKEN_RE = re.compile(r"\bpypi-[A-Za-z0-9_\-]{40,}")
_AWS_ACCESS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b")
_AWS_SECRET_KEY_RE = re.compile(
    r"(?i)(?:aws[_-]?)?secret[_-]?access[_-]?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"
)
_AZURE_DEVOPS_PAT_RE = re.compile(
    r"(?i)(?:azure[_-]?(?:devops[_-]?)?pat|azdo[_-]?pat|devops[_-]?pat|"
    r"system[_-]?access[_-]?token)\s*[:=]\s*['\"]?([A-Za-z0-9]{52})['\"]?"
)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|PGP) PRIVATE KEY(?: BLOCK)?-----"
)
_DATABASE_URI_RE = re.compile(
    r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?)://"
    r"[^\s:@/'\"]+:(?P<password>[^\s@/'\"]{3,})@[^\s'\"]+",
    re.IGNORECASE,
)

_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github_pat", _GITHUB_PAT_RE),
    ("github_token", _GITHUB_CLASSIC_RE),
    ("gitlab_token", _GITLAB_TOKEN_RE),
    ("google_api_key", _GOOGLE_API_KEY_RE),
    ("slack_token", _SLACK_TOKEN_RE),
    ("discord_webhook", _DISCORD_WEBHOOK_RE),
    ("stripe_key", _STRIPE_KEY_RE),
    ("sendgrid_key", _SENDGRID_KEY_RE),
    ("twilio_key", _TWILIO_KEY_RE),
    ("npm_token", _NPM_TOKEN_RE),
    ("pypi_token", _PYPI_TOKEN_RE),
    ("aws_access_key", _AWS_ACCESS_KEY_RE),
    ("aws_secret_key", _AWS_SECRET_KEY_RE),
    ("azure_devops_pat", _AZURE_DEVOPS_PAT_RE),
    ("jwt", _JWT_RE),
    ("private_key", _PRIVATE_KEY_RE),
    ("database_uri", _DATABASE_URI_RE),
)

# A named assignment whose right hand side looks like an opaque credential. The
# name is matched with surrounding word characters allowed so that
# GITHUB_TOKEN=... and AWS_SECRET_ACCESS_KEY=... both match.
#
# The surrounding name runs are bounded. An unbounded run in front of the
# keyword alternation makes the expression quadratic on a long identifier that
# never contains a keyword, so a single minified line could stall the scanner for
# minutes; 64 characters on each side covers real configuration names and keeps
# the match linear.
_ASSIGNMENT_RE = re.compile(
    r"(?i)([A-Za-z0-9_.\-]{0,64}(?:api[_-]?key|secret|token|passw(?:or)?d|credential|"
    r"private[_-]?key|access[_-]?key|client[_-]?secret)[A-Za-z0-9_.\-]{0,64})"
    r"\s*[:=]\s*['\"]?([A-Za-z0-9+/=_\-]{16,512})['\"]?"
)

#: Cheap linear pre filter for the assignment rule. A minified bundle or a base64
#: payload has no credential keyword at all, and skipping the full expression on
#: those lines is what keeps a single long line from dominating the scan cost.
_ASSIGNMENT_HINT_RE = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|passw(?:or)?d|credential|private[_-]?key|"
    r"access[_-]?key|client[_-]?secret)"
)

_PLACEHOLDER_VALUES: frozenset[str] = frozenset(
    {
        "changeme",
        "change_me",
        "example",
        "examplesecret",
        "none",
        "null",
        "password",
        "placeholder",
        "redacted",
        "secret",
        "test",
        "token",
        "undefined",
        "your_token_here",
        "yourkeyhere",
    }
)

#: What the operator should revoke or rotate for each detector family. The text
#: is short enough for a dossier detail line and contains no secret material, so
#: it can be printed verbatim.
REVOCATION_HINTS: dict[str, str] = {
    "github_pat": "revoke the fine-grained GitHub token at github.com/settings/tokens",
    "github_token": "revoke the GitHub token at github.com/settings/tokens",
    "gitlab_token": "revoke the GitLab personal access token in GitLab user settings",
    "google_api_key": "delete or rotate the Google API key in the Google Cloud console",
    "slack_token": "revoke the Slack bot or user token in the Slack app admin page",
    "discord_webhook": "delete the Discord webhook in the channel integration settings",
    "stripe_key": "roll the Stripe live secret key in the Stripe dashboard",
    "sendgrid_key": "delete the SendGrid API key in the SendGrid account settings",
    "twilio_key": "revoke the Twilio API key in the Twilio console",
    "npm_token": "revoke the npm access token with npm token revoke",
    "pypi_token": "revoke the PyPI API token in the PyPI account settings",
    "aws_access_key": "deactivate the AWS access key pair in IAM",
    "aws_secret_key": "rotate the AWS secret access key in IAM",
    "azure_devops_pat": "revoke the Azure DevOps personal access token in user settings",
    "jwt": "invalidate the JWT by rotating its signing key and revoking sessions",
    "private_key": "regenerate the private key and revoke its certificate or deploy key",
    "database_uri": "rotate the database password and replace the leaked connection string",
    "generic_secret": "rotate the reported credential at its issuing service",
    "remote_url": "rotate the credential embedded in the git remote URL",
}

_GENERIC_HINT = REVOCATION_HINTS["generic_secret"]

# Prefixes that the masker keeps because they identify the credential issuer
# without revealing any part of the secret material itself. Order matters: the
# longer prefixes are tested first so sk_live_ is not shortened to sk-.
_MASK_PREFIXES: tuple[str, ...] = (
    "github_pat_",
    "glpat-",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "sk_live_",
    "rk_live_",
    "sk-",
    "SG.",
    "npm_",
    "pypi-",
    "xoxb-",
    "xoxp-",
    "AKIA",
    "ASIA",
    "AIza",
    "SK",
    "-----BEGIN",
)


class GitSentinelError(RuntimeError):
    """Raised when a repository level operation cannot be performed."""


@dataclass(frozen=True, slots=True)
class SecretHit:
    """One credential candidate located inside a text source.

    Attributes:
        rel_path: Project relative path, always forward slash separated. History
            hits use "<commit>:<path>" so the offending revision is locatable.
        line_no: One based line number of the hit.
        kind: Stable detector token such as github_pat or database_uri.
        masked: Renderable form of the secret; never the secret itself.
        hint: Short revocation hint supplied by the detector; empty means the
            property resolves the family default.
    """

    rel_path: str
    line_no: int
    kind: str
    masked: str
    hint: str = ""

    @property
    def revocation_hint(self) -> str:
        """Return the short action that revokes this credential family."""

        if self.hint:
            return self.hint
        return REVOCATION_HINTS.get(self.kind, _GENERIC_HINT)


@dataclass(frozen=True, slots=True)
class GitSentinelReport:
    """Result of inspecting a repository for leaked credentials.

    Attributes:
        hook_installed: True when our pre-commit gate is in place.
        hook_path: Expected or installed hook path, or None for a non-git tree.
        secrets: Credential hits from staged blobs and project files.
        scanned_files: Number of text sources actually inspected.
        remote_credentials: Masked remote URLs that embed a password or token.
        findings_text: Human readable summary used by the dossier.
        suppressed: Candidates that the allowlist baseline accepted, so they are
            not part of the active finding count.
        baseline_entries: Number of fingerprints the loaded baseline carried.
        baseline_path: Allowlist file that was consulted, or None when no
            baseline was loaded.
        history_hits: Active credential hits found in commit history only.
        history_scanned: Commits examined by the history scan.
        history_truncated: True when a history bound stopped the walk early, so
            older commits were not examined.
        revoked_hints: Deduplicated revocation hints for the active findings,
            ordered by discovery and never containing secret material.
        history_secrets: The masked history hits, in path order.
    """

    hook_installed: bool
    hook_path: Path | None
    secrets: list[SecretHit] = field(default_factory=list)
    scanned_files: int = 0
    remote_credentials: list[str] = field(default_factory=list)
    findings_text: str = ""
    suppressed: int = 0
    baseline_entries: int = 0
    baseline_path: Path | None = None
    history_hits: int = 0
    history_scanned: int = 0
    history_truncated: bool = False
    revoked_hints: list[str] = field(default_factory=list)
    history_secrets: list[SecretHit] = field(default_factory=list)

    @property
    def leak_count(self) -> int:
        """Total number of credentials that would be exposed by a push."""

        return len(self.secrets) + len(self.remote_credentials)


def mask_secret(secret: str) -> str:
    """Return a renderable form of a credential that keeps only its issuer.

    Keeping a short prefix matters for the operator (ghp_ versus AKIA tells them
    which account to rotate) while the fixed marker guarantees that neither the
    length nor the secret alphabet leaks into a shared report.
    """

    text = (secret or "").strip()
    if not text:
        return REDACTED_MARKER
    upper = text.upper()
    for prefix in _MASK_PREFIXES:
        if upper.startswith(prefix.upper()):
            return prefix + REDACTED_MARKER
    if len(text) <= 8:
        return REDACTED_MARKER
    return text[:4] + REDACTED_MARKER


def _mask_database_uri(raw: str, match: re.Match[str]) -> str:
    """Mask only the password inside a database URI.

    Keeping the scheme, user and host makes the finding actionable without
    revealing the secret, and it keeps the masked rendering stable across
    commits, which is what the allowlist fingerprint is built from.
    """

    password = match.group("password") or ""
    if not password:
        return REDACTED_MARKER
    # raw is only the password when this is a capture-group rule, so the masked
    # rendering is built from the whole match to keep the host visible.
    return match.group(0).replace(password, REDACTED_MARKER, 1)


def _mask_discord_webhook(raw: str, match: re.Match[str]) -> str:
    """Mask the webhook token but keep the URL so the channel stays identifiable."""

    token = match.group("token") or ""
    if not token:
        return REDACTED_MARKER
    return match.group(0).replace(token, REDACTED_MARKER, 1)


def _mask_capture_group(_raw: str, match: re.Match[str]) -> str:
    """Mask the first capture group of a rule that wraps its secret in syntax."""

    value = match.group(1) or ""
    if not value:
        return REDACTED_MARKER
    return mask_secret(value)


_MASKERS: dict[str, Callable[[str, "re.Match[str]"], str]] = {
    "database_uri": _mask_database_uri,
    "discord_webhook": _mask_discord_webhook,
    "aws_secret_key": _mask_capture_group,
    "azure_devops_pat": _mask_capture_group,
}


def _looks_random(value: str) -> bool:
    """Decide whether an assignment value is credential-like.

    The entropy floor is deliberately below the network covert channel default
    because configuration tokens mix base64 with punctuation; the placeholder
    veto removes the documentation and sample values that would otherwise spam
    every report.
    """

    if len(value) < 16:
        return False
    if value.lower() in _PLACEHOLDER_VALUES:
        return False
    if "..." in value or "<" in value or value.count("/") > 6:
        return False
    if value.startswith(("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")):
        return True
    entropy = shannon_entropy(value.encode("utf-8", errors="replace"))
    if entropy >= 4.2:
        return True
    # Long values built from a narrow alphabet (hex digests, UUIDs) can fall
    # below the Shannon floor, so require a wide alphabet as a second signal.
    distinct = len(set(value))
    return len(value) >= 32 and distinct >= 16


#: Long lines are scanned in overlapping windows. Token patterns are bounded far
#: below the window size, so a credential split across two windows is still found
#: whole in the window that contains it, while per window regex cost stays
#: constant instead of growing with a minified line.
_MAX_REGEX_LINE = 4096
_REGEX_OVERLAP = 512


def _classify_segment(segment: str) -> list[tuple[str, str, int, int]]:
    """Run every rule over one bounded text segment."""

    found: list[tuple[str, str, int, int]] = []
    for kind, pattern in _RULES:
        for match in pattern.finditer(segment):
            raw = match.group(0)
            start, end = match.span(0)
            if not raw:
                continue
            masker = _MASKERS.get(kind)
            masked = masker(raw, match) if masker is not None else mask_secret(raw)
            found.append((kind, masked, start, end))
    if not _ASSIGNMENT_HINT_RE.search(segment):
        return found
    covered = [(item[2], item[3]) for item in found]
    for match in _ASSIGNMENT_RE.finditer(segment):
        value = match.group(2)
        start, end = match.span(2)
        if any(start < stop and end > begin for begin, stop in covered):
            continue
        if not _looks_random(value):
            continue
        found.append(("generic_secret", mask_secret(value), start, end))
    found.sort(key=lambda item: item[2])
    return found


def _classify_line(line: str) -> list[tuple[str, str, int, int]]:
    """Return detector hits for one line as (kind, masked, start, end) tuples.

    The masked rendering is computed where the detector knows which part of the
    match is secret material: a database URI keeps its scheme, user and host but
    not its password, a Discord webhook keeps its URL but not its token, and every
    other family masks the credential itself. Callers never see the raw value, so
    no later refactor can accidentally print it.

    A line longer than the window is scanned in overlapping windows. Every token
    pattern is shorter than the overlap, so a credential that crosses a window
    boundary is still matched whole in the window that contains it; duplicate
    matches from the overlap are collapsed on their absolute span.
    """

    if len(line) <= _MAX_REGEX_LINE:
        return _classify_segment(line)
    found: list[tuple[str, str, int, int]] = []
    seen: set[tuple[str, int, int]] = set()
    step = _MAX_REGEX_LINE - _REGEX_OVERLAP
    window_start = 0
    while window_start < len(line):
        window_end = min(window_start + _MAX_REGEX_LINE, len(line))
        for kind, masked, start, end in _classify_segment(line[window_start:window_end]):
            absolute_start = window_start + start
            absolute_end = window_start + end
            key = (kind, absolute_start, absolute_end)
            if key in seen:
                continue
            seen.add(key)
            found.append((kind, masked, absolute_start, absolute_end))
        if window_end >= len(line):
            break
        window_start += step
    found.sort(key=lambda item: item[2])
    return found


def scan_text(text: str, rel_path: str) -> list[SecretHit]:
    """Scan one decoded text source for credential candidates.

    Parameters:
        text: Decoded file or blob content.
        rel_path: Project relative path recorded in each hit.

    Returns:
        Hits ordered by line number; each carries a masked rendering only.
    """

    if not text:
        return []
    hits: list[SecretHit] = []
    normalized = rel_path.replace("\\", "/")
    for line_no, line in enumerate(text.splitlines(), 1):
        for kind, masked, _, _ in _classify_line(line):
            hits.append(
                SecretHit(
                    normalized,
                    line_no,
                    kind,
                    masked,
                    REVOCATION_HINTS.get(kind, _GENERIC_HINT),
                )
            )
    return hits


def redact_text(text: str) -> tuple[str, int]:
    """Replace every detected credential in a text block with its masked form.

    Dossier detail lines are assembled from counts and scanner output, but a
    future template may embed raw source; sanitizing at the boundary means the
    pillar never has to trust its inputs. Spans are replaced right to left so
    earlier offsets stay valid, and the returned count is the number of
    substitutions actually performed.

    Parameters:
        text: Text that may contain credential material.

    Returns:
        A (redacted_text, count) pair.
    """

    if not text:
        return text, 0
    lines = text.split("\n")
    total = 0
    for index, line in enumerate(lines):
        hits = _classify_line(line)
        if not hits:
            continue
        rebuilt = line
        for _kind, masked, start, end in sorted(
            hits, key=lambda item: item[2], reverse=True
        ):
            rebuilt = rebuilt[:start] + masked + rebuilt[end:]
            total += 1
        lines[index] = rebuilt
    return "\n".join(lines), total


def git_dir(root: Path) -> Path | None:
    """Return the repository metadata directory for a work tree.

    A plain directory is used for submodules and for tests; a .git file appears
    in worktrees and contains a gitdir pointer, so both forms must resolve or
    the hook installer would silently write into the wrong place.
    """

    root = Path(root)
    candidate = root / ".git"
    try:
        if candidate.is_dir():
            return candidate
        if candidate.is_file():
            for line in candidate.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if stripped.lower().startswith("gitdir:"):
                    target = Path(stripped.split(":", 1)[1].strip())
                    if not target.is_absolute():
                        target = (root / target).resolve()
                    return target
    except OSError:
        return None
    return None


def _coerce_git_result(result: object) -> tuple[int, bytes]:
    """Normalize an injected or real git invocation result into (code, stdout).

    The runner hook exists so the test suite never needs a git binary; accepting
    both subprocess.CompletedProcess shaped objects and (code, stdout) tuples
    keeps that injection point trivial without special casing tests.
    """

    if isinstance(result, tuple) and result:
        code = int(result[0]) if len(result) > 0 else 1
        payload = result[1] if len(result) > 1 else b""
        if isinstance(payload, str):
            return code, payload.encode("utf-8", errors="replace")
        return code, bytes(payload or b"")
    code = getattr(result, "returncode", 1)
    payload = getattr(result, "stdout", b"")
    if isinstance(payload, str):
        return int(code or 0), payload.encode("utf-8", errors="replace")
    return int(code or 0), bytes(payload or b"")


def _default_runner(args: Sequence[str], cwd: Path) -> tuple[int, bytes]:
    """Run git without a shell and with a bounded timeout.

    A missing git binary or a timeout degrades to a failed invocation instead of
    an exception, because the scanner also runs on machines where git is absent
    and the dossier must still render.
    """

    try:
        completed = subprocess.run(
            list(args),
            cwd=str(cwd),
            capture_output=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return 1, b""
    return int(completed.returncode), bytes(completed.stdout or b"")


def _default_runner_stdin(
    args: Sequence[str], cwd: Path, payload: bytes
) -> tuple[int, bytes]:
    """Run git with a stdin payload, used by the batched cat-file plumbing.

    The history scan feeds object ids to "git cat-file --batch-check" and
    "--batch" so a window of hundreds of blobs costs two git processes instead of
    two per blob. On Windows, where process creation dominates the wall clock,
    that is the difference between a multi second probe and a fast one.
    """

    try:
        completed = subprocess.run(
            list(args),
            cwd=str(cwd),
            input=payload,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return 1, b""
    return int(completed.returncode), bytes(completed.stdout or b"")


def _run(
    runner: Callable[[Sequence[str], Path], object] | None,
    args: list[str],
    cwd: Path,
) -> tuple[int, bytes]:
    """Invoke the configured runner, normalizing every failure to exit code 1."""

    if runner is None:
        return _default_runner(args, cwd)
    try:
        return _coerce_git_result(runner(args, cwd))
    except (OSError, RuntimeError, ValueError, TypeError):
        return 1, b""


def _decode_blob(payload: bytes) -> str | None:
    """Decode a staged blob, refusing binary content.

    Commit objects are binary, and running the text detectors over compressed or
    executable bytes produces pure noise, so anything with a NUL in the first
    kilobytes is skipped.
    """

    if not payload:
        return ""
    if b"\x00" in payload[:4096]:
        return None
    return payload.decode("utf-8", errors="replace")


def _resolve_baseline(
    root: Path,
    baseline: "Baseline | None",
    use_baseline: bool,
) -> "Baseline | None":
    """Return the baseline to apply, loading the project allowlist on demand.

    An explicit baseline always wins. Passing use_baseline=False is the escape
    hatch used by the baseline writer itself: recording the current findings must
    see every candidate, including the ones already accepted, or a refresh would
    silently delete every previously accepted entry.
    """

    if baseline is not None:
        return baseline
    if not use_baseline:
        return None
    try:
        from tauhaulity.tools.allowlist import load_baseline
    except ImportError:
        return None
    try:
        return load_baseline(root)
    except (OSError, ValueError, RuntimeError):
        return None


def _apply_baseline(
    hits: Sequence[SecretHit],
    baseline: "Baseline | None",
) -> tuple[list[SecretHit], int]:
    """Split hits into active ones and baseline suppressed ones.

    The allowlist module is imported lazily so this module keeps working when a
    sibling tool is missing, and any failure inside it degrades to "suppress
    nothing" rather than silently hiding candidates.
    """

    raw = list(hits)
    if baseline is None or not getattr(baseline, "entries", ()):
        return raw, 0
    try:
        from tauhaulity.tools.allowlist import filter_hits
    except ImportError:
        return raw, 0
    try:
        return filter_hits(raw, baseline)
    except (TypeError, ValueError, RuntimeError):
        return raw, 0


def scan_staged(
    root: Path,
    runner: Callable[[Sequence[str], Path], object] | None = None,
    *,
    baseline: "Baseline | None" = None,
) -> list[SecretHit]:
    """Scan the blobs currently staged in the index without touching the tree.

    Reading index blobs rather than the working tree is what makes the gate
    meaningful: the commit object is built from the index, so a secret that was
    staged and then fixed only in the worktree must still be reported.

    Parameters:
        root: Repository work tree root.
        runner: Optional injectable git invocation (args, cwd) -> result.
        baseline: Accepted fingerprints; None suppresses nothing. The pre-commit
            gate loads the project baseline so an accepted candidate does not
            block every future commit, while a new candidate still does.

    Returns:
        Hits ordered by path then line number. A non-repository or a missing git
        binary yields an empty list rather than an exception.
    """

    root = Path(root)
    if git_dir(root) is None:
        return []
    code, raw = _run(
        runner,
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
        root,
    )
    if code != 0:
        return []
    names = [name for name in raw.decode("utf-8", errors="replace").splitlines() if name.strip()]
    hits: list[SecretHit] = []
    for name in names[:_MAX_STAGED_FILES]:
        rel = name.strip().replace("\\", "/")
        code, payload = _run(runner, ["git", "show", ":" + rel], root)
        if code != 0:
            continue
        text = _decode_blob(payload)
        if text is None:
            continue
        hits.extend(scan_text(text, rel))
    hits.sort(key=lambda hit: (hit.rel_path, hit.line_no))
    if baseline is None:
        return hits
    active, _suppressed = _apply_baseline(hits, baseline)
    return active


#: Marker script prints before each commit id in the merged history log.
_HISTORY_FORMAT = chr(1)


def _is_zero_sha(value: str) -> bool:
    """True when a raw diff row names the null object id."""

    return not value or _ZERO_SHA_RE.match(value) is not None


def _parse_history_log(
    text: str, max_commits: int
) -> tuple[list[str], dict[str, list[tuple[str, str, str]]]]:
    """Parse one "--format=%x01%H --raw" log into commits and changed blobs.

    The single log call replaces one git process per commit, which on Windows is
    the difference between a usable probe and a multi second one. Malformed lines
    and malformed commit ids are skipped rather than raising, so a git version
    that changes a separator detail cannot break the scan.
    """

    commits: list[str] = []
    rows: dict[str, list[tuple[str, str, str]]] = {}
    current = ""
    for line in text.splitlines():
        if line.startswith(_HISTORY_FORMAT):
            candidate = line[len(_HISTORY_FORMAT) :].strip()
            if _COMMIT_RE.match(candidate) and candidate not in rows:
                current = candidate
                commits.append(candidate)
                rows[candidate] = []
            else:
                current = ""
            continue
        if not current or not line.startswith(":"):
            continue
        meta, tab, path = line.partition(chr(9))
        if not tab or not path:
            continue
        fields = meta[1:].split()
        if len(fields) < 5:
            continue
        rows[current].append((fields[2], fields[3], path))
    return commits[: int(max_commits)], rows


def _scan_history_blob(payload: bytes, short: str, path: str) -> list[SecretHit] | None:
    """Decode and scan one history blob; None means binary content."""

    text = _decode_blob(payload)
    if text is None:
        # Binary content has no lines to judge and only produces noise.
        return None
    if not text:
        return []
    return scan_text(text, short + ":" + path)


def _read_blobs_one_by_one(
    root: Path,
    blob_paths: dict[str, tuple[str, str]],
    max_blob_bytes: int,
    runner: Callable[[Sequence[str], Path], object] | None,
) -> tuple[list[SecretHit], int]:
    """Read each candidate blob with one size call and one content call.

    The size check runs before the content read, so a large binary in history is
    never loaded into this process.
    """

    hits: list[SecretHit] = []
    inspected = 0
    for blob_sha, (short, path) in blob_paths.items():
        code, size_raw = _run(runner, ["git", "cat-file", "-s", blob_sha], root)
        if code != 0:
            continue
        try:
            size = int(size_raw.decode("utf-8", errors="replace").strip() or "0")
        except ValueError:
            continue
        if size <= 0 or size > int(max_blob_bytes):
            continue
        code, payload = _run(runner, ["git", "cat-file", "blob", blob_sha], root)
        if code != 0:
            continue
        scanned = _scan_history_blob(payload, short, path)
        if scanned is None:
            continue
        inspected += 1
        hits.extend(scanned)
    return hits, inspected


def _read_blobs_batched(
    root: Path,
    blob_paths: dict[str, tuple[str, str]],
    max_blob_bytes: int,
) -> tuple[list[SecretHit], int]:
    """Read candidate blobs with two batched cat-file processes.

    The size pass never reads content, so a huge blob in history costs one line of
    --batch-check output instead of memory, and the content pass requests only the
    blobs that fit the per blob bound, in chunks that bound the in memory payload.
    Any batch failure degrades to the one by one plumbing for that chunk.
    """

    if not blob_paths:
        return [], 0
    shas = list(blob_paths)
    code, raw = _default_runner_stdin(
        ["git", "cat-file", "--batch-check"],
        root,
        (chr(10).join(shas) + chr(10)).encode("utf-8"),
    )
    if code != 0:
        return _read_blobs_one_by_one(root, blob_paths, max_blob_bytes, _default_runner)

    wanted: list[str] = []
    for sha, line in zip(shas, raw.decode("utf-8", errors="replace").splitlines()):
        parts = line.split()
        if len(parts) < 3 or parts[1] != "blob":
            continue
        try:
            size = int(parts[2])
        except ValueError:
            continue
        if 0 < size <= int(max_blob_bytes):
            wanted.append(sha)

    hits: list[SecretHit] = []
    inspected = 0
    for start in range(0, len(wanted), _HISTORY_BATCH_BLOBS):
        chunk = wanted[start : start + _HISTORY_BATCH_BLOBS]
        code, raw = _default_runner_stdin(
            ["git", "cat-file", "--batch"],
            root,
            (chr(10).join(chunk) + chr(10)).encode("utf-8"),
        )
        if code != 0:
            fallback = {sha: blob_paths[sha] for sha in chunk}
            chunk_hits, chunk_inspected = _read_blobs_one_by_one(
                root, fallback, max_blob_bytes, _default_runner
            )
            hits.extend(chunk_hits)
            inspected += chunk_inspected
            continue
        position = 0
        for sha in chunk:
            newline = raw.find(b"\n", position)
            if newline < 0:
                break
            header = raw[position:newline].decode("utf-8", errors="replace").split()
            position = newline + 1
            if len(header) < 3 or header[1] != "blob":
                continue
            try:
                size = int(header[2])
            except ValueError:
                continue
            if size < 0 or position + size > len(raw):
                break
            payload = raw[position : position + size]
            position += size + 1
            short, path = blob_paths[sha]
            scanned = _scan_history_blob(payload, short, path)
            if scanned is None:
                continue
            inspected += 1
            hits.extend(scanned)
    return hits, inspected


def _scan_history_details(
    root: Path,
    *,
    max_commits: int,
    max_blobs: int,
    max_blob_bytes: int,
    runner: Callable[[Sequence[str], Path], object] | None,
) -> tuple[list[SecretHit], int, int, bool]:
    """Walk bounded history and return (hits, commits, blobs, truncated).

    One merged raw log names the commits and the blobs each commit added or
    removed, so exactly those blobs are read. That is the opposite of walking the
    pack file blindly and it keeps the cost proportional to the number of changed
    files inside the window.

    Commits are visited oldest first so a secret is attributed to the revision
    that introduced it instead of the later one that removed it. Both the old and
    the new blob of a change are candidates, because a credential that was deleted
    in the newest commit still exists in history and still has to be revoked.
    """

    code, raw = _run(
        runner,
        [
            "git",
            "log",
            "--max-count=" + str(int(max_commits)),
            "--raw",
            "--no-abbrev",
            "--no-renames",
            "--root",
            "--format=" + _HISTORY_FORMAT + "%H",
            "HEAD",
        ],
        root,
    )
    if code != 0:
        return [], 0, 0, False
    commits, rows = _parse_history_log(raw.decode("utf-8", errors="replace"), max_commits)
    if not commits:
        return [], 0, 0, False
    # Reaching the commit cap means the walk stopped before the root commit, so
    # older history exists and the result is explicitly partial.
    truncated = len(commits) >= int(max_commits)

    blob_paths: dict[str, tuple[str, str]] = {}
    commits_scanned = 0
    for sha in reversed(commits):
        commits_scanned += 1
        short = sha[:_HISTORY_SHORT_SHA]
        for old_sha, new_sha, path in rows.get(sha, ()):
            for candidate in (new_sha, old_sha):
                if _is_zero_sha(candidate) or candidate in blob_paths:
                    continue
                if len(blob_paths) >= int(max_blobs):
                    truncated = True
                    break
                blob_paths[candidate] = (short, path)
        if len(blob_paths) >= int(max_blobs):
            truncated = True
            break

    if runner is None:
        # Production path: two batched cat-file processes instead of two per blob.
        hits, blobs_scanned = _read_blobs_batched(root, blob_paths, max_blob_bytes)
    else:
        # Injected path: simple one call per blob plumbing, so a fake runner only
        # has to answer the two obvious commands.
        hits, blobs_scanned = _read_blobs_one_by_one(
            root, blob_paths, max_blob_bytes, runner
        )
    hits.sort(key=lambda hit: (hit.rel_path, hit.line_no, hit.kind))
    return hits, commits_scanned, blobs_scanned, truncated


def _require_positive_int(value: object, name: str) -> int:
    """Return a validated positive integer bound or raise ValueError."""

    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(name + " must be a positive integer")
    if int(value) <= 0:
        raise ValueError(name + " must be a positive integer")
    return int(value)


def scan_history(
    root: Path,
    *,
    max_commits: int = 200,
    max_blobs: int = 1500,
    max_blob_bytes: int = 256 * 1024,
    runner: Callable[[Sequence[str], Path], object] | None = None,
    baseline: "Baseline | None" = None,
) -> list[SecretHit]:
    """Scan recent commit history for credentials that the tree no longer holds.

    A secret that was committed and then deleted from the working tree is still
    in the repository, still fetchable and still valid until it is revoked, so the
    sentinel has to look there too. The scan is bounded by commits, by distinct
    blobs and by bytes per blob; when a bound is reached the walk stops instead of
    degrading into a full pack file traversal.

    History hits carry rel_path "<commit>:<path>" using a short commit id, so a
    finding points at the revision a reviewer can inspect. Their fingerprint comes
    from the shared allowlist helper and therefore ignores line numbers: a
    baselined history finding stays suppressed as unrelated commits are added,
    because the introducing commit and the path do not change.

    Candidate blobs are deduplicated by object id, so identical content committed
    to several paths is read once and reported once; the finding is about the
    credential, and a repository that copies one token everywhere has one secret
    to revoke.

    Parameters:
        root: Repository work tree root.
        max_commits: Maximum number of commits examined.
        max_blobs: Maximum number of distinct blob contents read.
        max_blob_bytes: Maximum size of a blob that is read and scanned.
        runner: Optional injectable git invocation (args, cwd) -> result.
        baseline: Accepted fingerprints to subtract from the returned hits. None
            loads <root>/.tauhaulity/allowlist.json, so a standalone call honours
            the project baseline exactly like inspect_repository does.

    Returns:
        Active history hits ordered by path, line and kind. A non repository, a
        missing git binary or a repository without history yields an empty list.

    Raises:
        ValueError: When a bound is not a positive integer.
    """

    root = Path(root)
    commits = _require_positive_int(max_commits, "max_commits")
    blobs = _require_positive_int(max_blobs, "max_blobs")
    blob_bytes = _require_positive_int(max_blob_bytes, "max_blob_bytes")
    if git_dir(root) is None:
        return []
    hits, _commits, _blobs, _truncated = _scan_history_details(
        root,
        max_commits=commits,
        max_blobs=blobs,
        max_blob_bytes=blob_bytes,
        runner=runner,
    )
    resolved = _resolve_baseline(root, baseline, True)
    if resolved is None or not getattr(resolved, "entries", ()):
        return hits
    active, _suppressed = _apply_baseline(hits, resolved)
    return active


#: Files that mark a directory as a bundled interpreter or a virtual environment.
_INSTALL_MARKERS: tuple[str, ...] = ("pyvenv.cfg", "python.exe", "python3.exe")

#: Entry point names of a POSIX interpreter installation.
_POSIX_INTERPRETERS: tuple[str, ...] = ("python3", "python", "python3.exe")


def _looks_like_installation(directory: Path) -> bool:
    """True when a directory is a bundled interpreter or a virtual environment.

    A provisioning tree holds an entire Python installation, which is not project
    source and must not consume the credential scanner's bounded file budget.
    Name based skipping catches the common layouts; this probe catches the same
    trees under any other name. It is deliberately cheap: one stat per marker
    file, and the POSIX layout check only runs when both bin and lib exist.
    """

    try:
        for marker in _INSTALL_MARKERS:
            if (directory / marker).is_file():
                return True
        bin_dir = directory / "bin"
        lib_dir = directory / "lib"
        if not (bin_dir.is_dir() and lib_dir.is_dir()):
            return False
        if not any((bin_dir / name).is_file() for name in _POSIX_INTERPRETERS):
            return False
        for child in lib_dir.iterdir():
            if child.name.startswith("python3") and child.is_dir():
                return True
    except OSError:
        return False
    return False


def _candidate_files(root: Path) -> list[Path]:
    """Return a bounded list of project files worth scanning for credentials.

    Directories are pruned before the walk descends, so a provisioning tree (a
    vendored interpreter or a virtual environment under an unexpected name)
    cannot fill the file budget before the project's own code is reached. The
    order matters: dot directories sort first, which is exactly how an unpruned
    toolchain tree used to hide src/ and tests/ from the scan.
    """

    candidates: list[Path] = []
    for current, dirnames, filenames in os.walk(root):
        base = Path(current)
        kept: list[str] = []
        for name in sorted(dirnames):
            if name.lower() in _SKIP_DIRS:
                continue
            if _looks_like_installation(base / name):
                continue
            kept.append(name)
        dirnames[:] = kept
        for filename in sorted(filenames):
            suffix = Path(filename).suffix.lower()
            if filename.lower() in _SCAN_NAMES or suffix in _SCAN_SUFFIXES:
                candidates.append(base / filename)
                if len(candidates) >= _MAX_SCAN_FILES:
                    return candidates
    return candidates


def _read_text_limited(path: Path, limit: int = _MAX_SCAN_BYTES) -> str | None:
    """Read at most limit bytes and decode lossily, skipping binaries."""

    try:
        with path.open("rb") as handle:
            payload = handle.read(limit)
    except OSError:
        return None
    if b"\x00" in payload[:4096]:
        return None
    return payload.decode("utf-8", errors="replace")


def _remote_credentials(config_text: str) -> list[str]:
    """Extract and mask remote URLs whose userinfo embeds a password or token."""

    found: list[str] = []
    for line in config_text.splitlines():
        stripped = line.strip()
        lowered = stripped.lower()
        if not lowered.startswith("url") or "=" not in stripped:
            continue
        url = stripped.split("=", 1)[1].strip().strip('"')
        if "://" not in url:
            continue
        scheme, _, remainder = url.partition("://")
        authority, slash, tail = remainder.partition("/")
        userinfo, at, hostport = authority.rpartition("@")
        if not at or not userinfo:
            continue
        user, colon, secret = userinfo.partition(":")
        if colon:
            masked_userinfo = user + ":" + mask_secret(secret)
        else:
            # A token used as the username is the GitHub HTTPS convention.
            masked_userinfo = mask_secret(user)
        masked_url = scheme + "://" + masked_userinfo + "@" + hostport + slash + tail
        if masked_url not in found:
            found.append(masked_url)
    return found


def _hook_state(root: Path) -> tuple[bool, Path | None]:
    """Return the gate state and hook path, or (False, None) outside a repo.

    A directory without git metadata has no hooks directory, so reporting a
    conventional path there would be a fabricated location. The CLI asks
    hook_status directly and does want the conventional path for display, but a
    dossier must not claim a hook location that does not exist.
    """

    directory = git_dir(root)
    if directory is None:
        return False, None
    try:
        from tauhaulity.tools.hook_installer import hook_status
    except ImportError:
        return False, directory / "hooks" / "pre-commit"
    try:
        return hook_status(root)
    except OSError:
        return False, directory / "hooks" / "pre-commit"


def inspect_repository(
    root: Path,
    *,
    check_hook: bool = True,
    baseline: "Baseline | None" = None,
    use_baseline: bool = True,
    history: bool = False,
    history_max_commits: int = 200,
) -> GitSentinelReport:
    """Inspect staged content, project files, remotes and optionally history.

    The project file walk is bounded (200 files, 256 KiB each) so pillar eleven
    stays under its probe budget even on a large checkout, and version control
    internals are handled separately: .git/config is parsed for embedded remote
    credentials instead of being byte-scanned as ordinary source.

    Parameters:
        root: Project root to inspect.
        check_hook: Also resolve whether the pre-commit gate is installed.
        baseline: Accepted fingerprints to subtract from the active hits. None
            with use_baseline=True loads <root>/.tauhaulity/allowlist.json.
        use_baseline: Set False to report every candidate even when an allowlist
            exists; the baseline writer relies on this.
        history: Also scan recent commit history for deleted credentials.
        history_max_commits: Commit bound for the history walk; non positive
            values skip history instead of scanning unbounded.

    Returns:
        A report whose secrets, credentials and history hits are already masked,
        with the number of baseline suppressed candidates in the suppressed field
        and the revocation hints of the active findings in revoked_hints.
    """

    root = Path(root)
    accepted = _resolve_baseline(root, baseline, use_baseline)
    secrets: list[SecretHit] = []
    scanned = 0
    staged_paths: set[str] = set()

    staged = scan_staged(root)
    secrets.extend(staged)
    staged_paths.update(hit.rel_path for hit in staged)

    if root.is_dir():
        for path in _candidate_files(root):
            text = _read_text_limited(path)
            if text is None:
                continue
            scanned += 1
            try:
                rel = path.relative_to(root).as_posix()
            except ValueError:
                rel = path.as_posix()
            secrets.extend(scan_text(text, rel))

    # A staged blob and the working tree copy of the same file produce duplicate
    # findings; deduplicate on (path, line, kind) so the dossier count is honest.
    unique: dict[tuple[str, int, str], SecretHit] = {}
    for hit in secrets:
        unique.setdefault((hit.rel_path, hit.line_no, hit.kind), hit)
    ordered = [unique[key] for key in sorted(unique)]

    # The baseline is applied after deduplication so the suppressed count counts
    # real candidates, not the staged plus working tree duplicate of one file.
    ordered, suppressed = _apply_baseline(ordered, accepted)

    credentials: list[str] = []
    directory = git_dir(root)
    hook_path = (directory / "hooks" / "pre-commit") if directory else None
    if directory is not None:
        config = directory / "config"
        text = _read_text_limited(config) if config.is_file() else None
        if text:
            credentials = _remote_credentials(text)
    if credentials:
        # Remote URL credentials are candidates too, recorded under the path git
        # stores them in, so the allowlist can accept a deliberately public URL.
        try:
            from tauhaulity.tools.allowlist import (
                REMOTE_CREDENTIAL_KIND,
                REMOTE_CREDENTIAL_PATH,
            )
        except ImportError:
            REMOTE_CREDENTIAL_KIND = "remote_url"
            REMOTE_CREDENTIAL_PATH = ".git/config"
        pseudo_hits = [
            SecretHit(REMOTE_CREDENTIAL_PATH, 0, REMOTE_CREDENTIAL_KIND, credential)
            for credential in credentials
        ]
        active_credentials, remote_suppressed = _apply_baseline(pseudo_hits, accepted)
        credentials = [hit.masked for hit in active_credentials]
        suppressed += remote_suppressed

    history_secrets: list[SecretHit] = []
    history_commits = 0
    history_blobs = 0
    history_truncated = False
    if history and int(history_max_commits) > 0 and git_dir(root) is not None:
        try:
            history_all, history_commits, history_blobs, history_truncated = (
                _scan_history_details(
                    root,
                    max_commits=int(history_max_commits),
                    max_blobs=_HISTORY_MAX_BLOBS,
                    max_blob_bytes=_MAX_SCAN_BYTES,
                    runner=None,
                )
            )
        except (OSError, RuntimeError, ValueError):
            history_all = []
        active_history, history_suppressed = _apply_baseline(history_all, accepted)
        suppressed += history_suppressed
        unique_history: dict[tuple[str, int, str], SecretHit] = {}
        for hit in active_history:
            unique_history.setdefault((hit.rel_path, hit.line_no, hit.kind), hit)
        history_secrets = [unique_history[key] for key in sorted(unique_history)]

    hints: list[str] = []
    for hit in ordered:
        if hit.revocation_hint and hit.revocation_hint not in hints:
            hints.append(hit.revocation_hint)
    if credentials:
        remote_hint = REVOCATION_HINTS["remote_url"]
        if remote_hint not in hints:
            hints.append(remote_hint)
    for hit in history_secrets:
        if hit.revocation_hint and hit.revocation_hint not in hints:
            hints.append(hit.revocation_hint)

    installed = False
    if check_hook:
        installed, resolved = _hook_state(root)
        if resolved is not None:
            hook_path = resolved

    lines: list[str] = []
    if ordered:
        files_with_hits = len({hit.rel_path for hit in ordered})
        lines.append(
            str(len(ordered))
            + " credential candidate(s) across "
            + str(files_with_hits)
            + " file(s)"
        )
    else:
        lines.append("no credential candidates found")
    if history:
        if history_secrets:
            lines.append(
                str(len(history_secrets))
                + " candidate(s) in git history across "
                + str(history_commits)
                + " commit(s) and "
                + str(history_blobs)
                + " blob(s)"
            )
        else:
            lines.append("no credential candidates in git history")
        if history_truncated:
            lines.append("history scan truncated at the configured bound")
    if suppressed:
        lines.append(str(suppressed) + " candidate(s) suppressed by the baseline")
    if credentials:
        lines.append(str(len(credentials)) + " remote URL(s) embed credentials")
    if check_hook:
        lines.append("pre-commit gate installed" if installed else "pre-commit gate not installed")

    return GitSentinelReport(
        hook_installed=installed,
        hook_path=hook_path,
        secrets=ordered,
        scanned_files=scanned,
        remote_credentials=credentials,
        findings_text="; ".join(lines),
        suppressed=suppressed,
        baseline_entries=len(accepted.entries) if accepted is not None else 0,
        baseline_path=getattr(accepted, "path", None),
        history_hits=len(history_secrets),
        history_scanned=history_commits,
        history_truncated=bool(history_truncated),
        revoked_hints=hints[:8],
        history_secrets=history_secrets,
    )
