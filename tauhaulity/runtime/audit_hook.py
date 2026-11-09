"""PEP-578 audit guard: a cheap interpreter level recorder and policy gate.

Why this module is so careful about cost: a PEP-578 hook is called for every
audited event in the process, including events raised by unrelated libraries, and
it can never be removed. The dormant path is therefore a single boolean test
followed by a set membership test: when the guard is not installed, or has been
deactivated, nothing is allocated, no frame is walked and no lock is taken.

Why enforcement is off by default: silently raising PermissionError inside an
unrelated application is a defect, not a feature. Enforce mode only blocks a
policy defined violation (a third-party package frame reading .env or SSH key
material) and only when the caller opted in.

Recursion trap: reading the calling frame with sys._getframe itself raises the
"sys._getframe" audit event, which would re-enter this hook. A busy flag makes the
nested call a no-op. The flag is a plain integer because it is only ever set for
the duration of one event; under free-threaded builds a concurrent event may be
skipped, which is an acceptable diagnostic loss and never a correctness problem.

Snapshot contract: the recorded event ring is bounded (256 entries) and snapshots
are taken under a lock so a reader never observes a deque mutated mid-iteration.

Honeypot contract: an optional set of watched absolute paths (deployed decoy
credentials) is checked for "open" events only. When no path is registered the
check is a single falsy attribute test, so the dormant hot path is unchanged.
When a watched path is opened the guard appends an alert with the event name,
path, pid and calling module; the calling module is resolved lazily, only on a
match, and the busy flag makes the resulting frame lookup a no-op. Blocking is
opt-in twice over: the guard must be in enforce mode and the environment variable
TAUHAULITY_HONEYPOT_ENFORCE must be truthy, because a decoy read by a diagnostic
tool should be recorded first and block only when the operator asked for it.

Containment contract (0.3.0): the 2026 PyPI typosquat campaign documented by
OpenSSF reads environment variables, opens a raw socket and spawns a shell from a
package frame. Detecting that after the fact is useless, so the guard now resolves
the provenance of the triggering frame and, when enforcement is on, refuses the
operation from a site-packages frame before the kernel sees it. Only an exact
policy flag can block, the interpreter's own frames are never blocked, and the
allowlist exists so a signed package can be granted an exception by name. Every
denial is recorded with its provenance and flag so the dossier can report what was
stopped instead of merely what happened.

Cost contract: provenance resolution walks at most twelve frames, classifies the
first frame outside this module and caches the classification per filename. It is
reached only for the four enforced event families and only when enforcement is on,
so watch mode keeps the original hot path: a boolean, a set lookup and the envelope
record.
"""

from __future__ import annotations

import hashlib
import os
import re
import sys
import threading
import time
from collections import deque
from collections.abc import Iterable
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Final, Iterator

from tauhaulity.runtime import _bootstrap

__all__ = [
    "DEFAULT_EGRESS_WINDOW",
    "BURST_TRACKER_CAPACITY",
    "BurstTracker",
    "BurstVerdict",
    "DENY_CONNECT_ENV",
    "PROPAGATION_MARKER",
    "DENY_DESERIALIZE_ENV",
    "DENY_RANSOM_BURST_ENV",
    "DENY_SECRET_EGRESS_ENV",
    "DENY_SUBPROCESS_ENV",
    "EGRESS_SECRETS_ENV",
    "ENFORCE_ENV",
    "GUARD_ALLOW_ENV",
    "GuardPolicy",
    "TRUSTED_PICKLES_ENV",
    "cleanup_propagation",
    "clear_secrets",
    "deserialization_gate_active",
    "egress_gate_active",
    "guard_propagation",
    "harvest_secrets",
    "propagation_sitecustomize",
    "register_secrets",
    "unpatch_deserialization",
    "unpatch_egress",
    "HONEYPOT_ENFORCE_ENV",
    "HONEYPOT_RING_SIZE",
    "PROJECT_ROOTS_ENV",
    "Provenance",
    "SENSITIVE_NAMES",
    "WATCHED_EVENTS",
    "active",
    "arm_shield",
    "burst_summary",
    "classify_origin",
    "deactivate",
    "denials",
    "enforce_enabled",
    "events",
    "guard",
    "honeypot_events",
    "install",
    "is_sensitive_path",
    "reset",
    "resolve_provenance",
    "set_honeypot_paths",
    "shield",
    "stats",
]

WATCHED_EVENTS: Final[frozenset[str]] = frozenset(
    {
        "open",
        "sys._getframe",
        "compile",
        "exec",
        "subprocess.Popen",
        "socket.connect",
        "socket.getaddrinfo",
        "os.system",
        "os.exec",
        "os.spawn",
        "import",
        "pickle.loads",
        "marshal.loads",
        "os.remove",
        "os.unlink",
        "os.rename",
        "os.replace",
        "os.rmdir",
        "os.mkdir",
    }
)

EVENT_RING_SIZE: Final[int] = 256

#: Honeypot alerts are rarer than ordinary events, so a smaller ring is enough and
#: keeps the extra memory cost negligible.
HONEYPOT_RING_SIZE: Final[int] = 128

#: Environment flag that, together with the guard enforce mode, upgrades a decoy
#: read from a recorded alert to a PermissionError. This is a separate opt-in so a
#: mistaken honeytoken deployment cannot block an application by accident.
HONEYPOT_ENFORCE_ENV: Final[str] = "TAUHAULITY_HONEYPOT_ENFORCE"

_HONEYPOT_ENFORCE_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})

# Credential material a third-party package has no business reading. Names are
# matched case-insensitively against the final path component, plus a few
# directory based rules for SSH and cloud credential stores.
SENSITIVE_NAMES: Final[frozenset[str]] = frozenset(
    {
        ".env",
        ".netrc",
        ".pgpass",
        ".git-credentials",
        "id_rsa",
        "id_dsa",
        "id_ecdsa",
        "id_ed25519",
        "secrets.json",
        "secrets.yaml",
        "secrets.yml",
        "credentials",
        ".npmrc",
        ".pypirc",
    }
)
_SENSITIVE_SUFFIXES: Final[tuple[str, ...]] = (".pem", ".key", ".p12", ".pfx")
_THIRD_PARTY_MARKERS: Final[tuple[str, ...]] = (
    "site-packages",
    "dist-packages",
    "node_modules",
    ".venv",
    "virtualenv",
)
_SELF_SUFFIX: Final[str] = os.path.join("tauhaulity", "runtime", "audit_hook.py")


def _coerce_path(value: Any) -> str | None:
    """Best effort conversion of an audited path argument to text.

    The path may be a str, bytes, path-like or a raw file descriptor integer. A
    descriptor is not resolvable without /proc, and guessing would be wrong, so it
    returns None and the caller records the event without a path.
    """

    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode(sys.getfilesystemencoding(), "replace")
        except (UnicodeDecodeError, LookupError):
            return None
    if isinstance(value, int):
        return None
    try:
        raw = os.fspath(value)
    except (TypeError, ValueError):
        return None
    if isinstance(raw, bytes):
        try:
            return raw.decode(sys.getfilesystemencoding(), "replace")
        except (UnicodeDecodeError, LookupError):
            return None
    return str(raw)


def _normalize_watch_path(value: Any) -> str | None:
    """Normalize one honeypot path for comparison with an audited open path.

    Normalization is abspath plus normcase, never realpath: realpath performs
    readlink syscalls on every open, which would defeat the cheap hot path. A
    decoy opened through an unresolved symlink is therefore not matched, which is
    documented as a limitation rather than papered over.
    """

    text = _coerce_path(value)
    if text is None:
        return None
    try:
        return os.path.normcase(os.path.abspath(text))
    except (OSError, ValueError):
        return None


def _honeypot_block_enabled() -> bool:
    """True when the operator explicitly opted into blocking decoy reads."""

    try:
        raw = os.environ.get(HONEYPOT_ENFORCE_ENV, "")
    except (OSError, TypeError):
        return False
    return raw.strip().lower() in _HONEYPOT_ENFORCE_VALUES


def is_sensitive_path(path: str | os.PathLike[str] | None) -> bool:
    """Return True when a path names credential material worth protecting.

    The rules are intentionally narrow: a false positive blocks a legitimate
    package read, so only well known secret files qualify.
    """

    if path is None:
        return False
    try:
        text = os.fspath(path)
    except (TypeError, ValueError):
        return False
    if isinstance(text, bytes):
        try:
            text = text.decode(sys.getfilesystemencoding(), "replace")
        except (UnicodeDecodeError, LookupError):
            return False
    normalized = str(text).replace("\\", "/")
    parts = [part for part in normalized.split("/") if part]
    if not parts:
        return False
    name = parts[-1].lower()
    if name in SENSITIVE_NAMES:
        return True
    if name.startswith(".env.") or name.endswith(".env"):
        return True
    if name.endswith(_SENSITIVE_SUFFIXES):
        return True
    if ".ssh" in {part.lower() for part in parts[:-1]}:
        return True
    if name in {"credentials", "config"} and ".aws" in {part.lower() for part in parts[:-1]}:
        return True
    return False


def classify_origin(filename: str, root: Path | None = None) -> str:
    """Classify a code object filename into a provenance bucket.

    Buckets are runtime (this guard), stdlib, third-party (anything under a
    site-packages style directory), project (under root) and unknown. Third-party
    packages are checked before stdlib because a virtual environment places
    site-packages below the interpreter prefix and would otherwise be misclassified.
    """

    normalized = filename.replace("\\", "/")
    lowered = normalized.lower()
    if lowered.endswith(_SELF_SUFFIX.replace("\\", "/").lower()):
        return "runtime"
    if normalized.startswith("<"):
        return "builtin"
    for marker in _THIRD_PARTY_MARKERS:
        if marker in lowered:
            return "third-party"
    if root is not None:
        try:
            candidate = os.path.realpath(normalized)
            root_text = os.path.realpath(str(root))
            if os.path.commonpath([candidate, root_text]) == root_text:
                return "project"
        except (OSError, ValueError):
            pass
    try:
        import sysconfig

        stdlib = os.path.realpath(sysconfig.get_paths().get("stdlib", "") or "")
        if stdlib:
            candidate = os.path.realpath(normalized)
            if candidate.startswith(stdlib + os.sep) or candidate.startswith(stdlib + "/"):
                return "stdlib"
    except (ImportError, OSError, ValueError):
        pass
    return "unknown"


# ---------------------------------------------------------------------------
# Provenance resolution and enforcement policy (containment layer)
# ---------------------------------------------------------------------------

#: Extra project roots for provenance classification, os.pathsep separated.
PROJECT_ROOTS_ENV: Final[str] = "TAUHAULITY_PROJECT_ROOTS"
#: Comma separated module prefixes that are never blocked when enforcement is on.
GUARD_ALLOW_ENV: Final[str] = "TAUHAULITY_GUARD_ALLOW"
#: Master enforcement switch consumed by GuardPolicy.from_env.
ENFORCE_ENV: Final[str] = "TAUHAULITY_ENFORCE"
#: Per family switches consumed by GuardPolicy.from_env.
DENY_CONNECT_ENV: Final[str] = "TAUHAULITY_DENY_CONNECT"
DENY_SUBPROCESS_ENV: Final[str] = "TAUHAULITY_DENY_SUBPROCESS"
#: Deserialization gate switch and its trusted source path list.
DENY_DESERIALIZE_ENV: Final[str] = "TAUHAULITY_DENY_DESERIALIZE"
TRUSTED_PICKLES_ENV: Final[str] = "TAUHAULITY_TRUSTED_PICKLES"
#: Secret egress gate switch and the environment list of secret files.
DENY_SECRET_EGRESS_ENV: Final[str] = "TAUHAULITY_DENY_SECRET_EGRESS"
EGRESS_SECRETS_ENV: Final[str] = "TAUHAULITY_EGRESS_SECRETS"
#: Ransomware-style write burst enforcement switch (off by default).
DENY_RANSOM_BURST_ENV: Final[str] = "TAUHAULITY_DENY_RANSOM_BURST"

#: Ransom burst tracker limits. The capacity bounds process memory; the window and
#: the threshold are policy fields so an embedding host can tune sensitivity.
BURST_TRACKER_CAPACITY: Final[int] = 512
BURST_KNOWN_SUFFIX_LIMIT: Final[int] = 64
BURST_EXAMPLE_LIMIT: Final[int] = 5
BURST_MIN_RENAME_SAMPLE: Final[int] = 10
BURST_DOMINANCE: Final[float] = 0.80
BURST_PATH_LIMIT: Final[int] = 200

#: Outbound bytes inspected per send when the policy leaves the window at zero.
DEFAULT_EGRESS_WINDOW: Final[int] = 65536

#: Environment marker written by guard_propagation(); a propagated environment is
#: never prefixed with a second shim directory.
PROPAGATION_MARKER: Final[str] = _bootstrap.PROPAGATION_MARKER

_TRUTHY_VALUES: Final[frozenset[str]] = frozenset({"1", "true", "yes", "on"})
_FALSY_VALUES: Final[frozenset[str]] = frozenset({"0", "false", "no", "off", ""})

_CONNECT_EVENTS: Final[frozenset[str]] = frozenset({"socket.connect", "socket.getaddrinfo"})
_SUBPROCESS_EVENTS: Final[frozenset[str]] = frozenset(
    {"subprocess.Popen", "os.system", "os.exec", "os.spawn"}
)
_ENFORCEMENT_EVENTS: Final[frozenset[str]] = _CONNECT_EVENTS | _SUBPROCESS_EVENTS | {"open"}

#: Provenance walks are bounded so a hostile deep stack cannot turn an enforced
#: event into an unbounded frame walk.
_MAX_FRAME_WALK: Final[int] = 12
_PROVENANCE_CACHE_LIMIT: Final[int] = 256
_DENIAL_RING_SIZE: Final[int] = 128

#: Filename -> (kind, package) cache. Only the provenance layer touches it, which
#: is why watch mode pays nothing for it.
_PROVENANCE_CACHE: dict[str, tuple[str, str]] = {}
_PROVENANCE_CACHE_HITS: int = 0
_PROVENANCE_CACHE_MISSES: int = 0
_PROVENANCE_LOCK = threading.Lock()
_STDLIB_ROOTS_CACHE: tuple[str, ...] | None = None
_PROJECT_ROOT_OVERRIDE: str | None = None

_UNKNOWN_PROVENANCE = None  # assigned after Provenance is defined


def _env_flag(name: str, default: bool) -> bool:
    """Read a boolean environment flag, falling back to a documented default."""

    try:
        raw = os.environ.get(name)
    except (OSError, TypeError):
        return default
    if raw is None:
        return default
    text = raw.strip().lower()
    if text in _TRUTHY_VALUES:
        return True
    if text in _FALSY_VALUES:
        return False
    return default


@dataclass(frozen=True, slots=True)
class Provenance:
    """Where an audited operation originated.

    Attributes:
        kind: stdlib, project, site-packages or unknown.
        path: Absolute path of the code object filename (unchanged for builtins).
        module: Module name from the frame globals, or a filename stem fallback.
        package: Top level package name for a site-packages frame, else empty.
    """

    kind: str
    path: str
    module: str
    package: str

    def as_dict(self) -> dict[str, str]:
        """Return a JSON friendly mapping used by denial records and dossiers."""

        return {
            "kind": self.kind,
            "path": self.path,
            "module": self.module,
            "package": self.package,
        }


_UNKNOWN_PROVENANCE = Provenance("unknown", "", "", "")


@dataclass(frozen=True, slots=True)
class GuardPolicy:
    """Complete enforcement policy for the interpreter guard.

    The policy is immutable so an embedding application can hand a value to the
    guard without worrying about later mutation. Every denial family has its own
    switch because a deployment may trust network egress from its dependencies but
    still refuse credential reads.

    Attributes:
        enforce: Master switch; when False the guard only records.
        deny_third_party_connect: Block socket.connect/socket.getaddrinfo from
            site-packages frames.
        deny_third_party_subprocess: Block subprocess.Popen and the os.system,
            os.exec and os.spawn audit events from site-packages frames.
        deny_sensitive_reads: Block reads of .env, SSH key material, cloud
            credential stores and package manager credential files.
        deny_unsafe_deserialization: Wrap pickle/marshal/dill/yaml/torch loaders
            and refuse streams that contain an execution opcode.
        trusted_paths: Paths whose deserialization sources are trusted; entries
            are resolved against the project root and project-owned files are
            allowed without being listed.
        deny_egress_with_secrets: Wrap socket/ssl send paths and refuse an
            outbound buffer that contains a registered secret value verbatim.
        secret_redaction_bytes: Outbound bytes inspected per send; zero selects
            DEFAULT_EGRESS_WINDOW. Only this prefix is copied and scanned.
        burst_window_s: Sliding window used by the ransomware burst tracker.
        burst_threshold: Destructive operations inside the window required before a
            burst verdict is even considered.
        deny_ransom_burst: Refuse the operation that confirms a burst. Off by
            default even when enforcing, because a heuristic that kills builds on
            day one is worse than no heuristic.
        allowlist: Module or package prefixes that are never blocked; tauhaulity
            itself is always present.
    """

    enforce: bool = False
    deny_third_party_connect: bool = True
    deny_third_party_subprocess: bool = True
    deny_sensitive_reads: bool = True
    allowlist: tuple[str, ...] = ("tauhaulity",)
    deny_unsafe_deserialization: bool = True
    trusted_paths: tuple[str, ...] = ()
    deny_egress_with_secrets: bool = True
    secret_redaction_bytes: int = 0
    burst_window_s: float = 5.0
    burst_threshold: int = 30
    deny_ransom_burst: bool = False

    def __post_init__(self) -> None:
        if isinstance(self.secret_redaction_bytes, bool) or not isinstance(
            self.secret_redaction_bytes, int
        ):
            raise ValueError("secret_redaction_bytes must be an integer")
        if self.secret_redaction_bytes < 0:
            raise ValueError("secret_redaction_bytes must not be negative")
        if isinstance(self.burst_window_s, bool) or not isinstance(
            self.burst_window_s, (int, float)
        ):
            raise ValueError("burst_window_s must be a number")
        if float(self.burst_window_s) <= 0:
            raise ValueError("burst_window_s must be positive")
        if isinstance(self.burst_threshold, bool) or not isinstance(
            self.burst_threshold, int
        ):
            raise ValueError("burst_threshold must be an integer")
        if self.burst_threshold < 1:
            raise ValueError("burst_threshold must be at least one")
        cleaned: list[str] = []
        for entry in self.allowlist:
            text = str(entry).strip()
            if text and text not in cleaned:
                cleaned.append(text)
        if "tauhaulity" not in cleaned:
            cleaned.insert(0, "tauhaulity")
        object.__setattr__(self, "allowlist", tuple(cleaned))
        trusted: list[str] = []
        for entry in self.trusted_paths:
            text = str(entry).strip()
            if text and text not in trusted:
                trusted.append(text)
        object.__setattr__(self, "trusted_paths", tuple(trusted))

    @classmethod
    def from_env(cls) -> "GuardPolicy":
        """Build a policy from the documented environment variables.

        Unset denial flags keep their default (on), because the flags only take
        effect together with the enforce switch. The allowlist is comma separated
        and always keeps tauhaulity so the guard can never block itself.
        """

        try:
            raw_allow = os.environ.get(GUARD_ALLOW_ENV, "")
        except (OSError, TypeError):
            raw_allow = ""
        entries = tuple(
            part.strip() for part in raw_allow.replace(";", ",").split(",") if part.strip()
        )
        try:
            raw_trusted = os.environ.get(TRUSTED_PICKLES_ENV, "")
        except (OSError, TypeError):
            raw_trusted = ""
        trusted = tuple(
            part.strip() for part in raw_trusted.split(os.pathsep) if part.strip()
        )
        return cls(
            enforce=_env_flag(ENFORCE_ENV, False),
            deny_third_party_connect=_env_flag(DENY_CONNECT_ENV, True),
            deny_third_party_subprocess=_env_flag(DENY_SUBPROCESS_ENV, True),
            deny_sensitive_reads=True,
            allowlist=entries if entries else ("tauhaulity",),
            deny_unsafe_deserialization=_env_flag(DENY_DESERIALIZE_ENV, True),
            trusted_paths=trusted,
            deny_egress_with_secrets=_env_flag(DENY_SECRET_EGRESS_ENV, True),
            deny_ransom_burst=_env_flag(DENY_RANSOM_BURST_ENV, False),
        )

    def allows(self, provenance: Provenance) -> bool:
        """True when provenance is covered by an allowlist prefix."""

        for prefix in self.allowlist:
            for candidate in (provenance.module, provenance.package):
                if candidate and (candidate == prefix or candidate.startswith(prefix + ".")):
                    return True
        return False

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON friendly mapping for guard stats and the dossier."""

        return {
            "enforce": self.enforce,
            "deny_third_party_connect": self.deny_third_party_connect,
            "deny_third_party_subprocess": self.deny_third_party_subprocess,
            "deny_sensitive_reads": self.deny_sensitive_reads,
            "deny_unsafe_deserialization": self.deny_unsafe_deserialization,
            "trusted_paths": list(self.trusted_paths),
            "deny_egress_with_secrets": self.deny_egress_with_secrets,
            "secret_redaction_bytes": self.secret_redaction_bytes,
            "burst_window_s": float(self.burst_window_s),
            "burst_threshold": self.burst_threshold,
            "deny_ransom_burst": self.deny_ransom_burst,
            "allowlist": list(self.allowlist),
        }


def _is_self_filename(filename: str) -> bool:
    """True when a code object filename belongs to this module."""

    return filename.replace("\\", "/").lower().endswith(
        _SELF_SUFFIX.replace("\\", "/").lower()
    )


def _normalized_path(text: str) -> str | None:
    """Normalize a path for prefix comparison without resolving symlinks.

    realpath would perform readlink syscalls during an enforced event; abspath plus
    normcase is enough for the directory prefixes this guard compares against and
    is documented as not resolving symlinked project roots.
    """

    try:
        return os.path.normcase(os.path.abspath(text))
    except (OSError, ValueError):
        return None


def _project_roots() -> tuple[str, ...]:
    """Return the project roots used for provenance classification."""

    roots: list[str] = []
    candidates: list[str] = []
    try:
        candidates.append(os.getcwd())
    except OSError:
        pass
    if _PROJECT_ROOT_OVERRIDE:
        candidates.append(_PROJECT_ROOT_OVERRIDE)
    try:
        raw = os.environ.get(PROJECT_ROOTS_ENV, "")
    except (OSError, TypeError):
        raw = ""
    for entry in raw.split(os.pathsep):
        if entry.strip():
            candidates.append(entry.strip())
    for candidate in candidates:
        normalized = _normalized_path(candidate)
        if normalized and normalized not in roots:
            roots.append(normalized)
    return tuple(roots)


def _site_packages_roots() -> tuple[str, ...]:
    """Return sys.path entries that look like a venv or site-packages directory."""

    roots: list[str] = []
    for entry in sys.path:
        if not entry:
            continue
        normalized = _normalized_path(entry)
        if normalized is None:
            continue
        marker = normalized.replace("\\", "/").lower()
        if any(token in marker for token in _THIRD_PARTY_MARKERS):
            if normalized not in roots:
                roots.append(normalized)
    return tuple(roots)


def _stdlib_roots() -> tuple[str, ...]:
    """Return the interpreter's standard library roots, computed once."""

    global _STDLIB_ROOTS_CACHE
    if _STDLIB_ROOTS_CACHE is not None:
        return _STDLIB_ROOTS_CACHE
    roots: list[str] = []
    try:
        import sysconfig

        base = getattr(sys, "base_prefix", sys.prefix)
        paths = sysconfig.get_paths(vars={"base": base, "platbase": base})
        for key in ("stdlib", "platstdlib"):
            value = paths.get(key)
            if value:
                normalized = _normalized_path(value)
                if normalized and normalized not in roots:
                    roots.append(normalized)
    except (ImportError, OSError, ValueError):
        pass
    try:
        os_file = getattr(os, "__file__", "") or ""
        if os_file:
            normalized = _normalized_path(os.path.dirname(os_file))
            if normalized and normalized not in roots:
                roots.append(normalized)
    except (OSError, ValueError):
        pass
    _STDLIB_ROOTS_CACHE = tuple(roots)
    return _STDLIB_ROOTS_CACHE


def _path_is_under(candidate: str, root: str) -> bool:
    """True when a normalized candidate path is root or below it."""

    if not root:
        return False
    if candidate == root:
        return True
    try:
        return os.path.commonpath([candidate, root]) == root
    except (OSError, ValueError):
        return False


def _classify_path(path: str) -> tuple[str, str]:
    """Classify one normalized path into (kind, package)."""

    for index, root in enumerate(_site_packages_roots()):
        if _path_is_under(path, root):
            relative = path[len(root) :].lstrip("\\/")
            parts = [part for part in relative.replace("\\", "/").split("/") if part]
            if len(parts) >= 2:
                package = parts[0]
            elif parts:
                package = os.path.splitext(parts[0])[0]
            else:
                package = ""
            return "site-packages", package
    for root in _project_roots():
        if _path_is_under(path, root):
            return "project", ""
    for root in _stdlib_roots():
        if _path_is_under(path, root):
            return "stdlib", ""
    return "unknown", ""


def _classify_filename(filename: str) -> tuple[str, str]:
    """Classify a code object filename with a bounded positive cache.

    The cache is a plain dict guarded by a lock. It is only consulted during
    enforcement, never on the dormant path, and it is cleared by reset() so a test
    or an embedding host can force a fresh view after changing sys.path.
    """

    global _PROVENANCE_CACHE_HITS, _PROVENANCE_CACHE_MISSES
    if filename.startswith("<"):
        return "stdlib", ""
    key = _normalized_path(filename)
    if key is None:
        return "unknown", ""
    with _PROVENANCE_LOCK:
        cached = _PROVENANCE_CACHE.get(key)
        if cached is not None:
            _PROVENANCE_CACHE_HITS += 1
            return cached
    result = _classify_path(key)
    with _PROVENANCE_LOCK:
        if len(_PROVENANCE_CACHE) >= _PROVENANCE_CACHE_LIMIT:
            _PROVENANCE_CACHE.clear()
        _PROVENANCE_CACHE[key] = result
        _PROVENANCE_CACHE_MISSES += 1
    return result


def _provenance_for_frame(frame: Any) -> Provenance:
    """Build the Provenance of an already selected frame."""

    filename = frame.f_code.co_filename
    kind, package = _classify_filename(filename)
    module: Any = None
    try:
        module = frame.f_globals.get("__name__")
    except (AttributeError, AttributeError, TypeError):
        module = None
    if not isinstance(module, str) or not module:
        base = filename.replace("\\", "/").rsplit("/", 1)[-1]
        module = os.path.splitext(base)[0] or base or "unknown"
    if filename.startswith("<"):
        path = filename
    else:
        try:
            path = os.path.abspath(filename)
        except (OSError, ValueError):
            path = filename
    return Provenance(kind, path, module[:120], package[:120])


def _provenance_walk(frame: Any) -> Provenance:
    """Walk outwards from frame, skipping this module, and classify the first hit.

    The walk is bounded to twelve frames. Skipping only this module keeps the
    helper usable from both the audit hook and from application code that calls
    resolve_provenance directly.
    """

    for _ in range(_MAX_FRAME_WALK):
        if frame is None:
            break
        try:
            filename = frame.f_code.co_filename
        except (AttributeError, ValueError):
            break
        if _is_self_filename(filename):
            frame = frame.f_back
            continue
        return _provenance_for_frame(frame)
    return _UNKNOWN_PROVENANCE


def _clear_provenance_cache() -> None:
    """Drop the classification cache and its counters."""

    global _PROVENANCE_CACHE_HITS, _PROVENANCE_CACHE_MISSES, _STDLIB_ROOTS_CACHE
    with _PROVENANCE_LOCK:
        _PROVENANCE_CACHE.clear()
        _PROVENANCE_CACHE_HITS = 0
        _PROVENANCE_CACHE_MISSES = 0
    _STDLIB_ROOTS_CACHE = None


def resolve_provenance(depth_hint: int = 0) -> Provenance:
    """Return the provenance of the frame that called this function.

    Parameters:
        depth_hint: Extra frames to skip above the immediate caller. The guard
            itself never needs it; wrappers that delegate to this function use it
            to report the frame that called the wrapper.

    Returns:
        Provenance of the first frame outside this module, or an unknown
        provenance when the walk cannot start or every frame is ours.
    """

    try:
        offset = 1 + max(0, int(depth_hint))
        frame = sys._getframe(offset)
    except (AttributeError, ValueError, TypeError):
        return _UNKNOWN_PROVENANCE
    return _provenance_walk(frame)


def _format_target(event: str, args: tuple[Any, ...]) -> str:
    """Build a bounded human readable target for a denial message."""

    try:
        if event == "socket.connect":
            address = args[1] if len(args) > 1 else None
            return repr(address)[:160]
        if event == "socket.getaddrinfo":
            host = args[0] if args else None
            port = args[1] if len(args) > 1 else None
            return f"{host}:{port}"[:160]
        if event == "subprocess.Popen":
            executable = args[0] if args else None
            argv = args[1] if len(args) > 1 else None
            if executable is None and argv is not None:
                if isinstance(argv, (list, tuple)):
                    executable = argv[0] if argv else None
                else:
                    executable = argv
            return str(executable)[:160]
        if event == "os.system":
            return str(args[0])[:160] if args else "<unknown>"
        if event == "os.exec":
            return str(args[0])[:160] if args else "<unknown>"
        if event == "os.spawn":
            return str(args[1])[:160] if len(args) > 1 else "<unknown>"
        if event == "open":
            path = _coerce_path(args[0]) if args else None
            return (path or "<unknown>")[:160]
    except (IndexError, TypeError, ValueError, AttributeError):
        return "<unknown>"
    return "<unknown>"


def _denial_message(kind: str, package: str, event: str, target: str, flag: str) -> str:
    """Return the exact English denial message for one policy violation.

    The message names the package, the audited event, the target and the policy
    flag that blocked it. It never contains file contents or secret values.
    """

    label = package or "unknown"
    if kind == "sensitive_read":
        return (
            f"Tauhaulity policy: site-packages package '{label}' blocked from reading "
            f"credential material {target} by {flag} (event {event})"
        )
    if kind == "connect":
        return (
            f"Tauhaulity policy: site-packages package '{label}' blocked from {event} "
            f"to {target} by {flag}"
        )
    return (
        f"Tauhaulity policy: site-packages package '{label}' blocked from {event} "
        f"({target}) by {flag}"
    )


# ---------------------------------------------------------------------------
# In-process deserialization gate
# ---------------------------------------------------------------------------
#
# The 2026 assessment rated "application calls pickle.loads on that file" as not
# prevented: an audit hook sees the "pickle.loads" event but cannot stop the
# object graph from being built. This gate wraps the loader callables instead, so
# the stream is inspected before the loader runs and an execution opcode is
# refused with a PermissionError.
#
# Trust rule: the decision is about the stream plus where it came from, never
# about which package called the loader. A project module loading a malicious
# pickle is still refused, because the risk is the object graph; the escape hatch
# is a source path under a trusted_paths entry or a project-owned file, which is
# how an application opts specific data files back in.

#: Longest stream prefix inspected. A pickle executes only if its dangerous
#: opcodes are parsed, and a prefix beyond this cannot make a stream safe again,
#: so inspecting the head keeps the gate linear in a bounded amount of work.
_MAX_INSPECT_BYTES: Final[int] = 4 * 1024 * 1024

#: (module name, attribute, call style). The call style selects how the first
#: argument becomes inspectable bytes and an optional source path.
_DESERIALIZATION_TARGETS: Final[tuple[tuple[str, str, str], ...]] = (
    ("pickle", "loads", "bytes"),
    ("pickle", "load", "file"),
    ("_pickle", "loads", "bytes"),
    ("marshal", "loads", "marshal"),
    ("dill", "loads", "bytes"),
    ("dill", "load", "file"),
    ("yaml", "load", "yaml"),
    ("torch", "load", "torch"),
)

#: YAML loaders that construct arbitrary objects. yaml.load() with one of these
#: is unsafe deserialization regardless of the bytes it happens to contain.
_UNSAFE_YAML_LOADERS: Final[frozenset[str]] = frozenset({"Loader", "FullLoader", "UnsafeLoader"})

#: Contract copy of the pillar six opcode blocklist. The pillar is used when it is
#: already imported; this fallback keeps the gate working when it is not, without
#: importing a pillar from inside a loader that the import machinery may be using.
_FALLBACK_BLOCKED_OPCODES: Final[frozenset[str]] = frozenset(
    {
        "GLOBAL",
        "STACK_GLOBAL",
        "REDUCE",
        "INSTANTIATE",
        "OBJ",
        "NEWOBJ",
        "NEWOBJ_EX",
        "BUILD",
        "INST",
        "PERSID",
        "BINPERSID",
        "EXT1",
        "EXT2",
        "EXT4",
    }
)

_DESERIALIZATION_PATCHES: dict[tuple[str, str], tuple[Any, Any]] = {}
_DESERIALIZATION_LOCK = threading.Lock()
_SCANNER_IMPORT_DEPTH = 0
_PICKLETOOLS_MODULE: Any = None


def _pickletools_module() -> Any:
    """Import and cache pickletools without letting the gate re-enter itself.

    pickletools is imported by the first inspected stream rather than at module
    import, but the import machinery itself loads marshalled bytecode through the
    wrapped marshal.loads. The depth flag tells the wrapper to pass those calls
    through untouched while the scanner is still loading.

    Returns:
        The pickletools module, or None when it cannot be imported.
    """

    global _PICKLETOOLS_MODULE, _SCANNER_IMPORT_DEPTH
    module = _PICKLETOOLS_MODULE
    if module is not None:
        return module
    _SCANNER_IMPORT_DEPTH += 1
    try:
        import pickletools as module
    except ImportError:
        return None
    finally:
        _SCANNER_IMPORT_DEPTH -= 1
    _PICKLETOOLS_MODULE = module
    return module


@dataclass(frozen=True, slots=True)
class _DeserializationDecision:
    """Result of inspecting one loader call.

    Attributes:
        allowed: True when the call may proceed (benign, trusted or uninspectable).
        opcode: Unsafe opcode that justifies a refusal, empty when allowed.
        offset: Byte offset of that opcode inside the inspected stream.
        source: Source path or "<memory stream>" used in the refusal record.
        trusted: True when the source path matched a trust rule.
        note: Optional context such as a YAML loader name.
    """

    allowed: bool
    opcode: str = ""
    offset: int = 0
    source: str = ""
    trusted: bool = False
    note: str = ""


def deserialization_gate_active() -> bool:
    """True when at least one loader callable is currently wrapped."""

    return bool(_DESERIALIZATION_PATCHES)


def _blocked_deserialization_opcodes() -> frozenset[str]:
    """Return the opcode blocklist, preferring the pillar six contract when loaded."""

    pillar = sys.modules.get("tauhaulity.pillars.p06_supply")
    if pillar is not None:
        blocked = getattr(pillar, "BLOCKED_PICKLE_OPCODES", None)
        if isinstance(blocked, frozenset):
            return blocked
    return _FALLBACK_BLOCKED_OPCODES


def _scan_pickle_bytes(data: bytes) -> tuple[str, int] | None:
    """Return (opcode, offset) for the first execution opcode, or None.

    The pillar six PickleGate is used when it is already imported so the two
    gates cannot drift; otherwise an equivalent pickletools scan runs with the
    same blocklist. A stream that is not a valid pickle is treated as allowed:
    the real loader raises its own error, and the opcode gate is not a parser for
    arbitrary formats.
    """

    pillar = sys.modules.get("tauhaulity.pillars.p06_supply")
    gate_class = getattr(pillar, "PickleGate", None) if pillar is not None else None
    if callable(gate_class):
        try:
            verdict = gate_class().scan(data)
        except (TypeError, ValueError):
            verdict = None
        if verdict is not None:
            blocked = [
                finding for finding in verdict.findings if finding.opcode != "<malformed>"
            ]
            if blocked:
                return blocked[0].opcode, int(blocked[0].position)
            return None
    pickletools = _pickletools_module()
    if pickletools is None:
        return None
    try:
        for opcode, _argument, position in pickletools.genops(data):
            if opcode.name in _blocked_deserialization_opcodes():
                return opcode.name, int(position)
    except (ValueError, IndexError, TypeError, UnicodeDecodeError):
        return None
    return None


def _preferred_project_root() -> str:
    """Return the root relative trusted paths are resolved against.

    Order: the root passed to install()/apply_policy(), then the first
    TAUHAULITY_PROJECT_ROOTS entry, then the current working directory. One root
    is chosen deliberately instead of joining every candidate, because a relative
    trust entry must not silently widen to every project root the process knows.
    """

    if _PROJECT_ROOT_OVERRIDE:
        return _PROJECT_ROOT_OVERRIDE
    try:
        raw = os.environ.get(PROJECT_ROOTS_ENV, "")
    except (OSError, TypeError):
        raw = ""
    for entry in raw.split(os.pathsep):
        if entry.strip():
            return entry.strip()
    try:
        return os.getcwd()
    except OSError:
        return ""


def _resolved_trusted_paths(policy: GuardPolicy) -> tuple[str, ...]:
    """Resolve trusted_paths against the preferred project root, once per check.

    Relative entries are joined to the armed project root when one exists and to
    the preferred project root otherwise; this is documented so an operator knows
    which directory a relative trust entry covers.
    """

    resolved: list[str] = []
    base = _preferred_project_root()
    for entry in policy.trusted_paths:
        text = str(entry).strip()
        if not text:
            continue
        expanded = os.path.expanduser(text)
        if not os.path.isabs(expanded) and base:
            expanded = os.path.join(base, expanded)
        normalized = _normalized_path(expanded)
        if normalized is not None and normalized not in resolved:
            resolved.append(normalized)
    return tuple(resolved)


def _source_is_trusted(source: str | None, policy: GuardPolicy) -> bool:
    """True when a deserialization source path is trusted or project owned."""

    if not source:
        return False
    text = str(source)
    if not text or text.startswith("<"):
        return False
    normalized = _normalized_path(text)
    if normalized is None:
        return False
    for root in _resolved_trusted_paths(policy):
        if _path_is_under(normalized, root):
            return True
    for root in _project_roots():
        if _path_is_under(normalized, root):
            return True
    return False


def _read_stream_bytes(file_object: Any) -> tuple[str | None, bytes | None]:
    """Read a seekable stream without consuming it and return (path, prefix).

    The read is capped and the position is restored, because a benign pickle.load
    must see exactly the stream object the application passed in. A stream that
    cannot tell or seek is reported as uninspectable instead of being consumed;
    the caller then lets the real loader run and the refusal is not attempted.
    """

    path: str | None = None
    name = getattr(file_object, "name", None)
    if isinstance(name, (str, os.PathLike)):
        path = str(name)
    try:
        position = file_object.tell()
    except (AttributeError, OSError, ValueError):
        return path, None
    try:
        data = file_object.read(_MAX_INSPECT_BYTES)
    except (OSError, ValueError, TypeError, AttributeError):
        return path, None
    try:
        file_object.seek(position)
    except (AttributeError, OSError, ValueError):
        return path, None
    if isinstance(data, str):
        return path, data.encode("utf-8", "replace")
    if isinstance(data, (bytes, bytearray, memoryview)):
        return path, bytes(data)
    return path, None


def _read_file_prefix(path: str) -> bytes | None:
    """Read at most the inspected prefix of a file, or None when unreadable."""

    try:
        with open(path, "rb") as handle:
            return handle.read(_MAX_INSPECT_BYTES)
    except (OSError, ValueError):
        return None


def _torch_inner_pickle(raw: bytes | None) -> bytes | None:
    """Return the pickled data.pkl member of a torch zip archive, when present.

    torch.save writes a zip container whose data.pkl member is the actual pickle
    stream; scanning the container bytes themselves would never find an opcode.
    """

    if not raw or len(raw) < 4 or raw[:2] != b"PK":
        return None
    try:
        import io
        import zipfile

        with zipfile.ZipFile(io.BytesIO(raw)) as bundle:
            for member in bundle.namelist():
                if member.endswith("/data.pkl") or member == "data.pkl":
                    with bundle.open(member) as handle:
                        return handle.read(_MAX_INSPECT_BYTES)
    except (OSError, ValueError, zipfile.BadZipFile, RuntimeError):
        return None
    return None


def _extract_source(
    mode: str, args: tuple[Any, ...], kwargs: dict[str, Any]
) -> tuple[str | None, bytes | None, str]:
    """Extract (source path, inspectable prefix, note) from a loader call."""

    if mode == "yaml":
        stream = args[0] if args else kwargs.get("stream")
        loader = kwargs.get("Loader")
        if loader is None and len(args) > 1:
            loader = args[1]
        note = getattr(loader, "__name__", "") or ""
        if isinstance(stream, (bytes, bytearray, memoryview)):
            return None, bytes(stream)[:_MAX_INSPECT_BYTES], note
        if isinstance(stream, str):
            return None, stream.encode("utf-8", "replace")[:_MAX_INSPECT_BYTES], note
        path, data = _read_stream_bytes(stream)
        return path, data, note
    first: Any = None
    if args:
        first = args[0]
    else:
        for key in ("data", "s", "stream", "file", "filename", "f"):
            if key in kwargs:
                first = kwargs[key]
                break
    if mode in {"bytes", "marshal"}:
        if isinstance(first, (bytes, bytearray, memoryview)):
            return None, bytes(first)[:_MAX_INSPECT_BYTES], ""
        if isinstance(first, str):
            return None, first.encode("utf-8", "replace")[:_MAX_INSPECT_BYTES], ""
        return _read_stream_bytes(first)
    if mode == "file":
        return _read_stream_bytes(first)
    if mode == "torch":
        if isinstance(first, (str, os.PathLike)):
            path = str(first)
            raw = _read_file_prefix(path)
        else:
            path, raw = _read_stream_bytes(first)
        inner = _torch_inner_pickle(raw)
        return path, inner if inner is not None else raw, ""
    return None, None, ""


def _inspect_deserialization(
    call_name: str,
    mode: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    policy: GuardPolicy,
) -> _DeserializationDecision:
    """Decide whether one loader call may proceed.

    Trust is evaluated before any inspection, so a trusted large file costs one
    path comparison. The refusal itself is decided by the opcode gate; malformed
    or non-pickle payloads are allowed through so the real loader raises the error
    the application expects.
    """

    source, data, note = _extract_source(mode, args, kwargs)
    if source is not None and _source_is_trusted(source, policy):
        return _DeserializationDecision(True, source=source, trusted=True)
    if mode == "yaml" and note in _UNSAFE_YAML_LOADERS:
        return _DeserializationDecision(
            False,
            opcode="YAML_" + note.upper(),
            offset=0,
            source=source or "<yaml-stream>",
            note=note,
        )
    if not data:
        return _DeserializationDecision(True, source=source or "")
    blocked = _scan_pickle_bytes(bytes(data))
    if blocked is None:
        return _DeserializationDecision(True, source=source or "")
    opcode, offset = blocked
    return _DeserializationDecision(
        False,
        opcode=opcode,
        offset=offset,
        source=source or "<memory stream>",
    )


def _deserialization_message(
    call_name: str, opcode: str, offset: int, package: str, flag: str
) -> str:
    """Return the exact refusal message for an unsafe deserialization attempt.

    The message names the loader, the triggering opcode, its byte offset, the
    caller package and the policy flag. It never contains payload bytes.
    """

    label = package or "unknown"
    return (
        f"Tauhaulity policy: unsafe deserialization via {call_name} blocked at opcode "
        f"{opcode} (offset {offset}) from package '{label}' by {flag}"
    )


def _install_deserialization_gate() -> int:
    """Wrap every already imported loader, without nesting a second wrapper.

    Returns:
        Number of callables wrapped by this call (zero when already armed).
    """

    installed = 0
    with _DESERIALIZATION_LOCK:
        for module_name, attribute, mode in _DESERIALIZATION_TARGETS:
            module = sys.modules.get(module_name)
            if module is None:
                continue
            try:
                current = getattr(module, attribute)
            except AttributeError:
                continue
            key = (module_name, attribute)
            record = _DESERIALIZATION_PATCHES.get(key)
            if record is not None:
                if record[1] is current or getattr(
                    current, "__tauhaulity_deserialization_gate__", False
                ):
                    continue
                _DESERIALIZATION_PATCHES.pop(key, None)
            if getattr(current, "__tauhaulity_deserialization_gate__", False):
                continue
            wrapper = _make_deserializer_wrapper(f"{module_name}.{attribute}", mode, current)
            try:
                setattr(module, attribute, wrapper)
            except (AttributeError, TypeError):
                continue
            _DESERIALIZATION_PATCHES[key] = (current, wrapper)
            installed += 1
    return installed


def unpatch_deserialization() -> int:
    """Restore every wrapped loader to the exact callable it was before.

    Returns:
        Number of callables restored. Safe to call when the gate is not armed.
    """

    restored = 0
    with _DESERIALIZATION_LOCK:
        for key, (original, wrapper) in list(_DESERIALIZATION_PATCHES.items()):
            module_name, attribute = key
            module = sys.modules.get(module_name)
            if module is not None:
                try:
                    if getattr(module, attribute) is wrapper:
                        setattr(module, attribute, original)
                        restored += 1
                except (AttributeError, TypeError, ValueError):
                    pass
            _DESERIALIZATION_PATCHES.pop(key, None)
    return restored


def _make_deserializer_wrapper(call_name: str, mode: str, original: Any) -> Any:
    """Build the guarded replacement for one loader callable.

    The wrapper is inert when the guard is dormant, never raises for a gate
    failure, and lets the real loader make every decision it normally would once
    the stream passed the opcode gate.
    """

    def guarded(*args: Any, **kwargs: Any) -> Any:
        target_guard = guard
        if not target_guard.active or _SCANNER_IMPORT_DEPTH:
            return original(*args, **kwargs)
        policy = target_guard.policy
        if not policy.deny_unsafe_deserialization:
            return original(*args, **kwargs)
        try:
            decision = _inspect_deserialization(call_name, mode, args, kwargs, policy)
        except BaseException:
            return original(*args, **kwargs)
        if decision.allowed:
            return original(*args, **kwargs)
        provenance = target_guard._enforce_provenance()
        target = decision.source or "<memory stream>"
        message = _deserialization_message(
            call_name,
            decision.opcode,
            decision.offset,
            provenance.package,
            "deny_unsafe_deserialization",
        )
        extra = {
            "opcode": decision.opcode,
            "offset": decision.offset,
            "call": call_name,
        }
        if policy.enforce:
            target_guard._deny(
                "deserialization",
                call_name,
                target[:160],
                provenance,
                "deny_unsafe_deserialization",
                extra=extra,
                message=message,
            )
        target_guard._record_deserialization_watch(
            call_name,
            target[:160],
            provenance,
            "deny_unsafe_deserialization",
            message,
            extra,
        )
        return original(*args, **kwargs)

    guarded.__name__ = getattr(original, "__name__", "guarded_deserializer")
    guarded.__qualname__ = getattr(original, "__qualname__", guarded.__name__)
    guarded.__doc__ = getattr(original, "__doc__", None)
    guarded.__module__ = getattr(original, "__module__", __name__)
    guarded.__tauhaulity_deserialization_gate__ = True
    return guarded


# ---------------------------------------------------------------------------
# Outbound secret egress gate
# ---------------------------------------------------------------------------
#
# Blocking socket.connect stops a package that opens its own channel, but it does
# not stop a credential leaving through a connection the application already
# allowed: a dependency making a legitimate HTTP call can put a token in the body
# or a header. This gate inspects the bytes handed to the send family and refuses
# a buffer that contains a registered secret value verbatim.
#
# Cost contract: the registry is empty by default and the wrapper then costs one
# attribute read and a tuple truthiness test. With secrets registered, a bounded
# window (default 64 KiB) is copied once, rejected in one regex pass when it has no
# printable ASCII run, and then scanned with bytes.find (a C substring search) per
# registered value. The rest of the buffer is never copied or scanned.

#: Secrets are credentials: a window with no printable ASCII run cannot contain one.
_PRINTABLE_RUN: Final[re.Pattern[bytes]] = re.compile(rb"[\x20-\x7e]{8,}")

_MAX_SECRETS: Final[int] = 256
_SECRET_MAX_LENGTH: Final[int] = 4096
_SECRET_READ_LIMIT: Final[int] = 1024 * 1024


@dataclass(frozen=True, slots=True)
class _SecretEntry:
    """One registered secret value plus the metadata allowed in records.

    Attributes:
        value: Raw bytes of the credential. Never written to a ring or a dossier.
        label: Operator facing label such as "env" or a registered tag.
        sha256_prefix: First 16 hex characters of the value digest, safe to log.
    """

    value: bytes
    label: str
    sha256_prefix: str


_SECRET_REGISTRY: tuple[_SecretEntry, ...] = ()
_SECRET_LOCK = threading.Lock()
_EGRESS_PATCHES: dict[tuple[str, str], tuple[Any, Any]] = {}
_EGRESS_LOCK = threading.Lock()

#: (module name, class name, attribute, call style). Class methods are patched on
#: the class itself because socket.send is not a module level function.
_EGRESS_TARGETS: Final[tuple[tuple[str, str, str, str], ...]] = (
    ("socket", "socket", "send", "send"),
    ("socket", "socket", "sendall", "sendall"),
    ("socket", "socket", "sendto", "sendto"),
    ("socket", "socket", "sendmsg", "sendmsg"),
    ("socket", "socket", "sendfile", "sendfile"),
    ("ssl", "SSLSocket", "send", "send"),
    ("ssl", "SSLSocket", "sendall", "sendall"),
    ("ssl", "SSLSocket", "sendmsg", "sendmsg"),
)


def egress_gate_active() -> bool:
    """True when at least one socket send callable is currently wrapped."""

    return bool(_EGRESS_PATCHES)


def secret_registry_size() -> int:
    """Return how many secret values are registered, without exposing any value."""

    return len(_SECRET_REGISTRY)


def register_secrets(
    values: Iterable[str | bytes | bytearray | memoryview],
    *,
    label: str = "env",
) -> int:
    """Register credential values that must not leave the process in cleartext.

    Values are stored as bytes; duplicates are ignored. The registry is bounded so
    a hostile caller cannot grow memory without limit, and values longer than the
    largest inspectable window are still accepted but documented as unmatchable
    when they exceed the window.

    Parameters:
        values: Credential strings or bytes-like objects.
        label: Operator facing label recorded with a match.

    Returns:
        The number of registered values after the call.

    Raises:
        TypeError: When a value is not a string or bytes-like object.
    """

    global _SECRET_REGISTRY
    cleaned_label = (str(label).strip() or "env")[:64]
    added: list[_SecretEntry] = []
    with _SECRET_LOCK:
        existing = {entry.value for entry in _SECRET_REGISTRY}
        for raw in values:
            if isinstance(raw, str):
                material = raw.encode("utf-8", "replace")
            elif isinstance(raw, (bytes, bytearray, memoryview)):
                material = bytes(raw)
            else:
                raise TypeError(
                    f"secret values must be str or bytes-like, got {type(raw).__name__}"
                )
            if not material:
                continue
            if len(material) > _SECRET_MAX_LENGTH:
                continue
            if material in existing:
                continue
            if len(existing) >= _MAX_SECRETS:
                break
            prefix = hashlib.sha256(material).hexdigest()[:16]
            added.append(_SecretEntry(material, cleaned_label, prefix))
            existing.add(material)
        if added:
            _SECRET_REGISTRY = _SECRET_REGISTRY + tuple(added)
        return len(_SECRET_REGISTRY)


def clear_secrets() -> int:
    """Remove every registered secret value and return how many were removed."""

    global _SECRET_REGISTRY
    with _SECRET_LOCK:
        removed = len(_SECRET_REGISTRY)
        _SECRET_REGISTRY = ()
    return removed


def _credential_like(value: str) -> bool:
    """True when a value looks like a credential rather than prose.

    The heuristic is deliberately strict: at least twelve characters, no
    whitespace, and at least two character classes. A short word, an empty value or
    a sentence is therefore never registered, which keeps a .env comment or a
    filesystem path from turning into a false positive.
    """

    if len(value) < 12:
        return False
    if any(character.isspace() for character in value):
        return False
    has_lower = any("a" <= character <= "z" for character in value)
    has_upper = any("A" <= character <= "Z" for character in value)
    has_digit = any("0" <= character <= "9" for character in value)
    has_symbol = any(not character.isalnum() for character in value)
    return sum((has_lower, has_upper, has_digit, has_symbol)) >= 2


def _extract_credentials(text: str) -> list[str]:
    """Extract credential-looking values from KEY=VALUE or one-per-line content.

    Comments, blank lines, an optional export prefix, surrounding quotes and an
    inline assignment are handled. Order is preserved and duplicates are removed.
    """

    found: list[str] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        value = line
        if "=" in line:
            _key, _separator, value = line.partition("=")
            value = value.strip().strip('"').strip("'")
        if _credential_like(value) and value not in found:
            found.append(value)
    return found


def _read_text_safely(path: str | os.PathLike[str]) -> str:
    """Read a credential file defensively; unreadable files yield an empty string."""

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(_SECRET_READ_LIMIT)
    except (OSError, ValueError):
        return ""


def harvest_secrets(root: Path) -> int:
    """Read root/.env and root/.env.* and register the credentials they carry.

    Only values that pass the credential heuristic are registered; short values,
    whitespace containing values and prose are skipped. Values are never written to
    an event ring, a denial record or a dossier.

    Parameters:
        root: Project directory to harvest.

    Returns:
        The number of registered values after the call.
    """

    root_path = Path(root)
    paths: list[Path] = []
    try:
        candidate = root_path / ".env"
        if candidate.is_file():
            paths.append(candidate)
        for extra in sorted(root_path.glob(".env.*")):
            try:
                if extra.is_file():
                    paths.append(extra)
            except OSError:
                continue
    except OSError:
        return secret_registry_size()
    values: list[str] = []
    for path in paths:
        values.extend(_extract_credentials(_read_text_safely(path)))
    if not values:
        return secret_registry_size()
    return register_secrets(values, label="env")


def _load_egress_secret_sources(explicit_files: Iterable[str | os.PathLike[str]]) -> int:
    """Load arm-time secret files from the explicit list, env or project .env.

    Explicit files win; otherwise TAUHAULITY_EGRESS_SECRETS is split on os.pathsep;
    otherwise the project .env is used when it exists. Loading never raises.
    """

    paths: list[Path] = []
    for entry in explicit_files:
        try:
            paths.append(Path(entry))
        except TypeError:
            continue
    if not paths:
        try:
            raw = os.environ.get(EGRESS_SECRETS_ENV, "")
        except (OSError, TypeError):
            raw = ""
        if raw.strip():
            paths = [Path(part.strip()) for part in raw.split(os.pathsep) if part.strip()]
    if not paths:
        root = _preferred_project_root()
        if root:
            candidate = Path(root) / ".env"
            try:
                if candidate.is_file():
                    paths.append(candidate)
            except OSError:
                pass
    values: list[str] = []
    for path in paths:
        values.extend(_extract_credentials(_read_text_safely(path)))
    if not values:
        return secret_registry_size()
    return register_secrets(values, label="env")


def _egress_window(policy: GuardPolicy) -> int:
    """Return the number of outbound bytes inspected for one send."""

    configured = int(policy.secret_redaction_bytes or 0)
    return configured if configured > 0 else DEFAULT_EGRESS_WINDOW


def _inspect_outbound(data: Any, window: int) -> tuple[str, int, str] | None:
    """Return (label, offset, sha256_prefix) when the window holds a secret.

    Only the first window bytes are copied. A payload with no printable ASCII run
    is rejected in one regex pass, which is what keeps binary uploads cheap.
    """

    if window <= 0 or not isinstance(data, (bytes, bytearray, memoryview)):
        return None
    try:
        view = memoryview(data)
    except TypeError:
        return None
    total = view.nbytes
    if total <= 0:
        return None
    limit = min(window, total)
    window_bytes = bytes(view[:limit])
    if not window_bytes or _PRINTABLE_RUN.search(window_bytes) is None:
        return None
    for entry in _SECRET_REGISTRY:
        if len(entry.value) > limit:
            continue
        position = window_bytes.find(entry.value)
        if position >= 0:
            return entry.label, int(position), entry.sha256_prefix
    return None


def _inspect_sendmsg(buffers: Any, window: int) -> tuple[str, int, str] | None:
    """Inspect the concatenation of a sendmsg buffer list up to the window.

    Concatenating the first window across the buffers is what catches a secret
    split between two entries of one sendmsg call. A secret split across two
    separate calls is still not reconstructed, because no cross-call state is kept.

    The returned offset is a byte offset inside the concatenated stream, which is
    the only offset that is meaningful without materialising every buffer.
    """

    if buffers is None:
        return None
    if isinstance(buffers, (bytes, bytearray, memoryview)):
        return _inspect_outbound(buffers, window)
    try:
        entries = list(buffers)
    except TypeError:
        return None
    collected = bytearray()
    for entry in entries:
        if len(collected) >= window:
            break
        if not isinstance(entry, (bytes, bytearray, memoryview)):
            return None
        remaining = window - len(collected)
        try:
            collected.extend(bytes(memoryview(entry)[:remaining]))
        except (TypeError, ValueError):
            return None
    return _inspect_outbound(bytes(collected), window)


def _sendfile_source(file_object: Any) -> str | None:
    """Return the path backing a sendfile argument, or None when uninspectable."""

    if isinstance(file_object, (str, os.PathLike)):
        try:
            return str(file_object)
        except (TypeError, ValueError):
            return None
    name = getattr(file_object, "name", None)
    if isinstance(name, (str, os.PathLike)):
        return str(name)
    return None


def _inspect_sendfile(file_object: Any, offset: int, window: int) -> tuple[str, int, str] | None:
    """Inspect the first window of a file that is about to be transferred.

    The file is opened read-only by path, seeked to the transfer offset and read for
    at most window bytes. The file is never fully read, and the caller's file object
    is never read, rewound or otherwise disturbed. A file without a name (an
    in-memory buffer) cannot be attributed to a path and is allowed through.
    """

    source = _sendfile_source(file_object)
    if source is None or window <= 0:
        return None
    try:
        with open(source, "rb") as handle:
            if offset > 0:
                handle.seek(offset)
            data = handle.read(window)
    except (OSError, ValueError):
        return None
    match = _inspect_outbound(data or b"", window)
    if match is None:
        return None
    label, position, prefix = match
    return label, max(0, offset) + position, prefix


def _outbound_match(
    style: str,
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    window: int,
) -> tuple[str, int, str] | None:
    """Dispatch one send family call to the buffer, sendmsg or sendfile inspector."""

    if style == "sendmsg":
        buffers = args[0] if args else kwargs.get("buffers")
        return _inspect_sendmsg(buffers, window)
    if style == "sendfile":
        file_object = args[0] if args else kwargs.get("file")
        offset = 0
        if len(args) > 1 and isinstance(args[1], int) and not isinstance(args[1], bool):
            offset = int(args[1])
        else:
            raw_offset = kwargs.get("offset", 0)
            if isinstance(raw_offset, int) and not isinstance(raw_offset, bool):
                offset = int(raw_offset)
        return _inspect_sendfile(file_object, max(0, offset), window)
    data = args[0] if args else kwargs.get("data")
    return _inspect_outbound(data, window)


def _send_peer(style: str, socket_object: Any, args: tuple[Any, ...], kwargs: dict[str, Any]) -> str:
    """Return the destination peer for a denial message, best effort.

    For sendto the address is part of the call. For send/sendall getpeername() is
    only called after a match, so the common path pays no syscall.
    """

    if style == "sendto":
        address: Any = None
        if len(args) >= 3:
            address = args[2]
        elif len(args) == 2:
            address = args[1]
        else:
            address = kwargs.get("address")
        if address is not None:
            return str(address)[:120]
    try:
        peer = socket_object.getpeername()
    except (OSError, ValueError, AttributeError, TypeError):
        peer = None
    return str(peer)[:120] if peer is not None else "<unknown peer>"


def _secret_egress_message(
    call_name: str, label: str, offset: int, peer: str, flag: str
) -> str:
    """Return the exact refusal message for a secret bearing outbound buffer.

    The message names the matched secret label, the byte offset inside the
    inspected window, the destination peer and the policy flag. It never contains
    the secret value.
    """

    return (
        f"Tauhaulity policy: secret egress blocked: label '{label}' matched at byte "
        f"offset {offset} for {call_name} to {peer} by {flag}"
    )


def _install_egress_gate() -> int:
    """Wrap every already imported socket/ssl send callable, without nesting.

    Returns:
        Number of callables wrapped by this call (zero when already armed).
    """

    installed = 0
    if "socket" not in sys.modules:
        # socket is core stdlib, unlike the optional dill/yaml/torch modules: the
        # egress gate is meaningless without it and every application that sends
        # has it imported. Importing it here is the one deliberate exception to
        # the lazy rule; ssl stays lazy because TLS users import it themselves.
        try:
            import socket  # noqa: F401  (local import: the gate needs the class)
        except ImportError:
            pass
    with _EGRESS_LOCK:
        for module_name, class_name, attribute, style in _EGRESS_TARGETS:
            module = sys.modules.get(module_name)
            if module is None:
                continue
            try:
                owner = getattr(module, class_name)
            except AttributeError:
                continue
            try:
                current = getattr(owner, attribute)
            except AttributeError:
                continue
            if getattr(current, "__tauhaulity_egress_gate__", False):
                continue
            key = (module_name, f"{class_name}.{attribute}")
            record = _EGRESS_PATCHES.get(key)
            if record is not None:
                if record[1] is current:
                    continue
                _EGRESS_PATCHES.pop(key, None)
            wrapper = _make_egress_wrapper(class_name, attribute, current, style)
            try:
                setattr(owner, attribute, wrapper)
            except (AttributeError, TypeError):
                continue
            _EGRESS_PATCHES[key] = (current, wrapper)
            installed += 1
    return installed


def unpatch_egress() -> int:
    """Restore every wrapped send callable to the exact original object.

    Returns:
        Number of callables restored. Safe when the gate is not armed.
    """

    restored = 0
    with _EGRESS_LOCK:
        for key, (original, wrapper) in list(_EGRESS_PATCHES.items()):
            module_name, dotted = key
            class_name, _separator, attribute = dotted.partition(".")
            module = sys.modules.get(module_name)
            if module is not None:
                try:
                    owner = getattr(module, class_name)
                    if getattr(owner, attribute) is wrapper:
                        setattr(owner, attribute, original)
                        restored += 1
                except (AttributeError, TypeError, ValueError):
                    pass
            _EGRESS_PATCHES.pop(key, None)
    return restored


def _make_egress_wrapper(
    class_name: str, attribute: str, original: Any, style: str
) -> Any:
    """Build the guarded replacement for one socket send method.

    The wrapper is inert when the guard is dormant, never raises for a gate
    failure, and forwards the exact original argument list on every allowed send.
    """

    call_name = f"{class_name}.{attribute}"

    def guarded(socket_object: Any, *args: Any, **kwargs: Any) -> Any:
        target_guard = guard
        if not target_guard.active:
            return original(socket_object, *args, **kwargs)
        policy = target_guard.policy
        if not policy.deny_egress_with_secrets:
            return original(socket_object, *args, **kwargs)
        if not _SECRET_REGISTRY:
            return original(socket_object, *args, **kwargs)
        try:
            match = _outbound_match(style, args, kwargs, _egress_window(policy))
        except BaseException:
            match = None
        if match is None:
            return original(socket_object, *args, **kwargs)
        label, offset, prefix = match
        peer = _send_peer(style, socket_object, args, kwargs)
        message = _secret_egress_message(
            call_name, label, offset, peer, "deny_egress_with_secrets"
        )
        provenance = target_guard._enforce_provenance()
        extra = {
            "label": label,
            "offset": offset,
            "sha256_prefix": prefix,
            "call": call_name,
        }
        if style == "sendfile":
            source = _sendfile_source(args[0] if args else kwargs.get("file"))
            if source:
                extra["source"] = source
        if policy.enforce:
            target_guard._deny(
                "secret_egress",
                call_name,
                peer,
                provenance,
                "deny_egress_with_secrets",
                extra=extra,
                message=message,
            )
        target_guard._record_watch_denial(
            "secret_egress",
            call_name,
            peer,
            provenance,
            "deny_egress_with_secrets",
            message,
            extra,
        )
        return original(socket_object, *args, **kwargs)

    guarded.__name__ = getattr(original, "__name__", "guarded_send")
    guarded.__qualname__ = getattr(original, "__qualname__", guarded.__name__)
    guarded.__doc__ = getattr(original, "__doc__", None)
    guarded.__module__ = getattr(original, "__module__", __name__)
    guarded.__tauhaulity_egress_gate__ = True
    return guarded


# ---------------------------------------------------------------------------
# Ransomware-style write burst detector
# ---------------------------------------------------------------------------
#
# The guard recorded opens, execs, sockets and pickles but not a single write-side
# event, so a process renaming thousands of files to one new suffix was invisible.
# The tracker below watches the destructive filesystem events and requires TWO
# independent signals before it reports anything:
#
#   volume     at least burst_threshold destructive operations inside window_s
#   uniformity at least 80 percent of the rename targets inside the window share
#              one suffix that the tracker has not learned as an existing suffix
#
# Requiring both is what keeps a legitimate bulk build from firing: a build writes
# thousands of files but keeps reusing suffixes it already used (".py", ".js",
# ".o", ".tmp"), and the tracker learns those suffixes during its warm-up window
# and any calm activity. A uniform rename wave to a suffix the process has never
# used before is the ransomware shape.
#
# Cost contract: the tracker is a bounded deque of at most BURST_TRACKER_CAPACITY
# operations. The dormant guard never reaches this code (the audit callback returns
# on the first boolean), and when armed, a write event costs one deque append, an
# amortised prune and an O(capacity) volume count.

_WRITE_EVENTS: Final[frozenset[str]] = frozenset(
    {
        "os.remove",
        "os.unlink",
        "os.rename",
        "os.replace",
        "os.rmdir",
        "os.mkdir",
    }
)

#: CPython normalises the aliases: os.replace raises "os.rename" and os.unlink
#: raises "os.remove". The alias names stay in the watched set for forward
#: compatibility, but on CPython 3.12-3.15 only the canonical names fire.
_WRITE_KIND: Final[dict[str, str]] = {
    "os.remove": "remove",
    "os.unlink": "remove",
    "os.rename": "rename",
    "os.replace": "rename",
    "os.rmdir": "rmdir",
    "os.mkdir": "mkdir",
}

_VOLUME_KINDS: Final[frozenset[str]] = frozenset({"remove", "rename", "rmdir"})
_RENAME_KINDS: Final[frozenset[str]] = frozenset({"rename"})
_SUFFIX_PATTERN: Final[re.Pattern[str]] = re.compile(r"^\.[a-z0-9][a-z0-9_-]{0,15}$")


def _trim_path(value: str) -> str:
    """Bound one path stored by the tracker so a hostile name cannot grow memory."""

    return value[:BURST_PATH_LIMIT]


def _path_suffix(path: str) -> str:
    """Return a lowercased file suffix such as ".locked", or "" when there is none.

    Only short alphanumeric suffixes are considered. A suffix longer than the
    pattern allows is treated as no signal instead of being truncated, because a
    truncated suffix would merge unrelated names into one bucket.
    """

    if not path:
        return ""
    base = path.replace("\\", "/").rsplit("/", 1)[-1]
    if "." not in base or base.startswith(".") and base.count(".") == 1:
        return ""
    suffix = "." + base.rsplit(".", 1)[-1].lower()
    if not _SUFFIX_PATTERN.match(suffix):
        return ""
    return suffix


@dataclass(frozen=True, slots=True)
class BurstVerdict:
    """One confirmed ransomware-shaped write burst.

    Attributes:
        detected_at: Wall clock time of the verdict (epoch seconds).
        volume: Destructive operations counted inside the window.
        window_s: Sliding window length in seconds at verdict time.
        rename_count: Rename targets counted inside the window.
        suffix: Dominant new suffix shared by the rename targets.
        dominance: Fraction of rename targets carrying that suffix (0.0-1.0).
        threshold: Volume threshold policy that was in force.
        examples: Up to five rename target paths, never file contents.
    """

    detected_at: float
    volume: int
    window_s: float
    rename_count: int
    suffix: str
    dominance: float
    threshold: int
    examples: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON friendly mapping for the dossier and denial records."""

        return {
            "detected_at": self.detected_at,
            "volume": self.volume,
            "window_s": self.window_s,
            "rename_count": self.rename_count,
            "suffix": self.suffix,
            "dominance": round(self.dominance, 4),
            "threshold": self.threshold,
            "examples": list(self.examples),
        }


class BurstTracker:
    """Bounded sliding window detector for destructive filesystem activity.

    The tracker is deliberately stateful about suffixes but stateless about paths:
    it learns suffixes, never filenames, which is enough to separate a build wave
    from a rename wave and keeps memory proportional to the capacity.

    Attributes:
        capacity: Maximum number of operations retained.
    """

    def __init__(
        self,
        capacity: int = BURST_TRACKER_CAPACITY,
        known_suffix_limit: int = BURST_KNOWN_SUFFIX_LIMIT,
        example_limit: int = BURST_EXAMPLE_LIMIT,
    ) -> None:
        if capacity < 1:
            raise ValueError("capacity must be at least one")
        if known_suffix_limit < 1:
            raise ValueError("known_suffix_limit must be at least one")
        if example_limit < 1:
            raise ValueError("example_limit must be at least one")
        self._capacity = int(capacity)
        self._example_limit = int(example_limit)
        self._known: deque[str] = deque(maxlen=int(known_suffix_limit))
        self._ops: deque[tuple[float, str, str, str]] = deque(maxlen=self._capacity)
        self._volume = 0
        self._rename_total = 0
        self._suffix_counts: dict[str, int] = {}
        self._suffix_examples: dict[str, deque[str]] = {}
        self._started_at: float | None = None
        self._last_verdict: BurstVerdict | None = None
        self._verdicts = 0

    @property
    def capacity(self) -> int:
        """Maximum number of retained operations."""

        return self._capacity

    @property
    def size(self) -> int:
        """Current number of retained operations (never above capacity)."""

        return len(self._ops)

    @property
    def verdicts(self) -> int:
        """Number of confirmed burst verdicts since the last reset."""

        return self._verdicts

    @property
    def last_verdict(self) -> BurstVerdict | None:
        """Most recent verdict, or None."""

        return self._last_verdict

    @property
    def known_suffixes(self) -> tuple[str, ...]:
        """Suffixes learned as existing activity, oldest first."""

        return tuple(self._known)

    def reset(self) -> None:
        """Forget every operation, learned suffix and counter."""

        self._clear_window()
        self._known.clear()
        self._started_at = None
        self._last_verdict = None
        self._verdicts = 0

    def snapshot(self) -> dict[str, Any]:
        """Return a JSON friendly view of the tracker state for the dossier."""

        return {
            "capacity": self._capacity,
            "size": self.size,
            "verdicts": self._verdicts,
            "known_suffixes": list(self._known),
            "last_verdict": self._last_verdict.as_dict() if self._last_verdict else None,
        }

    def observe(
        self,
        kind: str,
        source: str,
        target: str,
        *,
        now: float,
        window_s: float,
        threshold: int,
    ) -> BurstVerdict | None:
        """Feed one filesystem operation and return a verdict when one confirms.

        Parameters:
            kind: One of remove, rename, rmdir or mkdir.
            source: Source or target path of the operation.
            target: Rename destination, empty for the other kinds.
            now: Monotonic timestamp in seconds.
            window_s: Sliding window length in seconds.
            threshold: Destructive operations required inside the window.

        Returns:
            A BurstVerdict the first time both signals hold, else None. After a
            verdict the window is cleared and the dominant suffix is learned, so a
            sustained burst yields one verdict per full threshold window instead of
            one verdict per operation.
        """

        moment = float(now)
        window = float(window_s)
        limit = int(threshold)
        if self._started_at is None:
            self._started_at = moment
        self._ops.append(
            (
                moment,
                kind,
                _trim_path(source or ""),
                _trim_path(target or ""),
            )
        )
        suffix = ""
        if kind in _VOLUME_KINDS:
            self._volume += 1
        if kind in _RENAME_KINDS:
            self._rename_total += 1
            suffix = _path_suffix(target)
            if suffix:
                self._suffix_counts[suffix] = self._suffix_counts.get(suffix, 0) + 1
                bucket = self._suffix_examples.get(suffix)
                if bucket is None:
                    bucket = deque(maxlen=self._example_limit)
                    self._suffix_examples[suffix] = bucket
                bucket.append(_trim_path(target or ""))
        self._prune(moment, window)
        volume = self._volume
        warming_up = (moment - self._started_at) <= window
        if warming_up:
            # The first window is the learning phase: suffixes seen here are part
            # of the process's existing activity and may never justify a verdict.
            if suffix:
                self._learn(suffix)
            return None
        if volume < limit:
            return None
        if self._rename_total < BURST_MIN_RENAME_SAMPLE or not self._suffix_counts:
            return None
        dominant_suffix, dominant_count = max(
            self._suffix_counts.items(), key=lambda item: (item[1], item[0])
        )
        dominance = dominant_count / self._rename_total
        if dominance < BURST_DOMINANCE:
            return None
        if dominant_suffix in self._known:
            return None
        examples = self._suffix_examples.get(dominant_suffix)
        verdict = BurstVerdict(
            detected_at=time.time(),
            volume=volume,
            window_s=window,
            rename_count=self._rename_total,
            suffix=dominant_suffix,
            dominance=dominance,
            threshold=limit,
            examples=tuple(examples) if examples else (),
        )
        self._verdicts += 1
        self._last_verdict = verdict
        self._learn(dominant_suffix)
        self._clear_window()
        return verdict

    def _learn(self, suffix: str) -> None:
        """Remember an existing suffix, keeping the bounded FIFO order."""

        if not suffix or suffix in self._known:
            return
        self._known.append(suffix)

    def _clear_window(self) -> None:
        """Drop every retained operation and reset the incremental counters."""

        self._ops.clear()
        self._volume = 0
        self._rename_total = 0
        self._suffix_counts.clear()
        self._suffix_examples.clear()

    def _prune(self, now: float, window_s: float) -> None:
        """Drop operations older than the window and keep every counter exact."""

        while self._ops and (now - self._ops[0][0]) > window_s:
            _moment, kind, _source, target = self._ops.popleft()
            if kind in _VOLUME_KINDS:
                self._volume -= 1
            if kind in _RENAME_KINDS:
                self._rename_total -= 1
                suffix = _path_suffix(target)
                if suffix:
                    remaining = self._suffix_counts.get(suffix, 0) - 1
                    if remaining > 0:
                        self._suffix_counts[suffix] = remaining
                    else:
                        self._suffix_counts.pop(suffix, None)
                        self._suffix_examples.pop(suffix, None)
                    bucket = self._suffix_examples.get(suffix)
                    if bucket:
                        try:
                            bucket.popleft()
                        except IndexError:
                            pass
        if self._volume < 0:
            self._volume = 0
        if self._rename_total < 0:
            self._rename_total = 0


class AuditGuard:
    """Bounded, never-raising recorder with an opt-in enforcement gate.

    Attributes:
        installed: True once the hook has been added to the interpreter.
        active: True while the hook records events (deactivate() clears it).
    """

    def __init__(self) -> None:
        self.installed = False
        self.active = False
        self._root: Path | None = None
        self._lock = threading.Lock()
        self._ring: deque[dict[str, Any]] = deque(maxlen=EVENT_RING_SIZE)
        self._counts: dict[str, int] = {name: 0 for name in WATCHED_EVENTS}
        self._recorded = 0
        self._sequence = 0
        self._violations = 0
        self._errors = 0
        self._busy = 0
        self._honeypot_paths: frozenset[str] = frozenset()
        self._honeypot_ring: deque[dict[str, Any]] = deque(maxlen=HONEYPOT_RING_SIZE)
        self._honeypot_count = 0
        self._honeypot_sequence = 0
        self._policy: GuardPolicy = GuardPolicy()
        self._denials: deque[dict[str, Any]] = deque(maxlen=_DENIAL_RING_SIZE)
        self._denials_count = 0
        self._blocked_count = 0
        self._denial_sequence = 0
        self._watch_counts: dict[str, int] = {"deserialization": 0, "secret_egress": 0}
        self._burst = BurstTracker()
        self._burst_events = 0

    def install(self, enforce: bool = False, root: Path | None = None) -> None:
        """Arm the guard, adding the audit hook on first use.

        Backward compatible entry point: only the enforce gate changes, while the
        deny flags and allowlist of the current policy are preserved. Use
        apply_policy() to replace the whole policy.

        A CPython audit hook cannot be removed, so a second install only updates
        the policy and re-arms a deactivated guard. On an interpreter without
        sys.addaudithook the guard stays dormant instead of raising.
        """

        self.apply_policy(replace(self._policy, enforce=bool(enforce)), root=root)

    def apply_policy(self, policy: GuardPolicy, root: Path | None = None) -> None:
        """Arm the guard with a complete policy and optionally a project root.

        Raises:
            TypeError: When policy is not a GuardPolicy instance.
        """

        global _PROJECT_ROOT_OVERRIDE
        if not isinstance(policy, GuardPolicy):
            raise TypeError("policy must be a GuardPolicy")
        if root is not None:
            try:
                self._root = Path(root).resolve()
            except (OSError, ValueError):
                self._root = Path(root)
        self._policy = policy
        _PROJECT_ROOT_OVERRIDE = str(self._root) if self._root is not None else None
        self.active = True
        self._ensure_hook()
        if policy.deny_unsafe_deserialization:
            _install_deserialization_gate()
        else:
            unpatch_deserialization()
        if policy.deny_egress_with_secrets:
            _install_egress_gate()
        else:
            unpatch_egress()

    def _ensure_hook(self) -> None:
        """Add the audit callback once, leaving the guard dormant if impossible."""

        if self.installed:
            return
        add_hook = getattr(sys, "addaudithook", None)
        if not callable(add_hook):
            self.active = False
            return
        try:
            add_hook(self._on_audit)
        except (RuntimeError, TypeError, ValueError):
            self.active = False
            return
        self.installed = True

    @property
    def policy(self) -> GuardPolicy:
        """The active enforcement policy."""

        return self._policy

    def deactivate(self) -> None:
        """Put the guard to sleep; the hook stays registered but does nothing."""

        self.active = False

    def enforce_enabled(self) -> bool:
        """True when policy violations raise PermissionError."""

        return bool(self._policy.enforce)

    def reset(self) -> None:
        """Clear recorded events and counters without touching the install state."""

        with self._lock:
            self._ring.clear()
            for name in self._counts:
                self._counts[name] = 0
            self._recorded = 0
            self._sequence = 0
            self._violations = 0
            self._errors = 0
            self._honeypot_ring.clear()
            self._honeypot_count = 0
            self._honeypot_sequence = 0
            self._denials.clear()
            self._denials_count = 0
            self._blocked_count = 0
            self._denial_sequence = 0
            for family in self._watch_counts:
                self._watch_counts[family] = 0
            self._burst.reset()
            self._burst_events = 0
        _clear_provenance_cache()

    def stats(self) -> dict[str, Any]:
        """Return a snapshot of the guard state for diagnostics and tests."""

        with self._lock:
            recorded = self._recorded
            counts = dict(self._counts)
            ring_size = len(self._ring)
            violations = self._violations
            errors = self._errors
            sequence = self._sequence
            watch_counts = dict(self._watch_counts)
        with self._lock:
            denials_count = self._denials_count
            blocked_events = self._blocked_count
            denial_ring_size = len(self._denials)
            provenance_hits = _PROVENANCE_CACHE_HITS
            provenance_misses = _PROVENANCE_CACHE_MISSES
        return {
            "installed": self.installed,
            "active": self.active,
            "enforce": self._policy.enforce,
            "root": str(self._root) if self._root is not None else None,
            "watched": sorted(WATCHED_EVENTS),
            "recorded": recorded,
            "ring_size": ring_size,
            "ring_capacity": EVENT_RING_SIZE,
            "events_ring_size": ring_size,
            "sequence": sequence,
            "counts": counts,
            "violations": violations,
            "errors": errors,
            "honeypot_paths": len(self._honeypot_paths),
            "honeypot_alerts": self._honeypot_count,
            "denials": denials_count,
            "blocked_events": blocked_events,
            "denial_ring_size": denial_ring_size,
            "provenance_cache_hits": provenance_hits,
            "provenance_cache_misses": provenance_misses,
            "deserialization_gate_active": deserialization_gate_active(),
            "deserialization_watch_events": watch_counts.get("deserialization", 0),
            "egress_gate_active": egress_gate_active(),
            "secret_registry_size": secret_registry_size(),
            "secret_egress_watch_events": watch_counts.get("secret_egress", 0),
            "burst_events": self._burst_events,
            "burst_verdicts": self._burst.verdicts,
            "burst_tracker_size": self._burst.size,
            "policy": self._policy.as_dict(),
        }

    def events(self, limit: int = 32) -> list[dict[str, Any]]:
        """Return the most recent recorded events, oldest first.

        Raises:
            ValueError: When limit is negative.
        """

        if limit < 0:
            raise ValueError("limit must not be negative")
        with self._lock:
            if limit == 0:
                return []
            material = list(self._ring)
        return material[-limit:]

    def denials(self, limit: int = 32) -> list[dict[str, Any]]:
        """Return the most recent policy denials, oldest first.

        Each record carries the time, denial kind, target, provenance mapping,
        policy flag and audited event so the dossier can report what was blocked.

        Raises:
            ValueError: When limit is negative.
        """

        if limit < 0:
            raise ValueError("limit must not be negative")
        with self._lock:
            if limit == 0:
                return []
            material = list(self._denials)
        return material[-limit:]

    def burst_summary(self) -> dict[str, Any]:
        """Return the write burst tracker state for the dossier.

        The summary carries counters, the active window and threshold, the learned
        suffix set and the last verdict (paths only, never file contents).
        """

        summary = self._burst.snapshot()
        summary.update(
            {
                "burst_events": self._burst_events,
                "window_s": float(self._policy.burst_window_s),
                "threshold": self._policy.burst_threshold,
                "deny_ransom_burst": self._policy.deny_ransom_burst,
            }
        )
        return summary

    def set_honeypot_paths(self, paths: Iterable[Any]) -> int:
        """Register the absolute decoy paths watched on the next file open.

        Registration replaces the previous set. Paths are normalized with abspath
        and normcase so the same file spelled differently still matches; the
        comparison deliberately avoids realpath to keep the hot path syscall free.

        Parameters:
            paths: Absolute decoy paths, as returned by honeytoken.token_paths.

        Returns:
            The number of distinct normalized paths now registered.
        """

        normalized: set[str] = set()
        for value in paths:
            token = _normalize_watch_path(value)
            if token is not None:
                normalized.add(token)
        with self._lock:
            self._honeypot_paths = frozenset(normalized)
        return len(normalized)

    def honeypot_events(self, limit: int = 32) -> list[dict[str, Any]]:
        """Return the most recent honeypot alerts, oldest first.

        Each alert carries the seq number, the audited event name, the opened
        path, the pid and the module that opened it.

        Raises:
            ValueError: When limit is negative.
        """

        if limit < 0:
            raise ValueError("limit must not be negative")
        with self._lock:
            if limit == 0:
                return []
            material = list(self._honeypot_ring)
        return material[-limit:]

    def _check_honeypot(self, args: tuple[Any, ...]) -> None:
        """Record an open of a watched decoy path and optionally block it.

        Only called when at least one path is registered, so the dormant path pays
        nothing. The calling module is resolved after the match, never before.
        """

        if not args:
            return
        raw = _coerce_path(args[0])
        if raw is None:
            return
        try:
            if os.path.isabs(raw):
                # Absolute paths are the common case and only need string
                # normalization, not the getcwd syscall that abspath performs.
                absolute = os.path.normcase(os.path.normpath(raw))
            else:
                absolute = os.path.normcase(os.path.abspath(raw))
        except (OSError, ValueError):
            return
        if absolute not in self._honeypot_paths:
            return
        caller = self._caller_module()
        with self._lock:
            self._honeypot_sequence += 1
            self._honeypot_count += 1
            self._honeypot_ring.append(
                {
                    "seq": self._honeypot_sequence,
                    "event": "open",
                    "path": raw,
                    "pid": os.getpid(),
                    "caller": caller,
                }
            )
        if self._policy.enforce and _honeypot_block_enabled():
            raise PermissionError(
                "Tauhaulity policy: honeytoken decoy opened by "
                + caller
                + " ("
                + raw
                + ")"
            )

    def _caller_module(self) -> str:
        """Return the module that triggered the event, resolved only on a hit."""

        try:
            frame = sys._getframe(2)
        except (AttributeError, ValueError):
            return "unknown"
        while frame is not None:
            filename = frame.f_code.co_filename
            if not filename.replace(chr(92), "/").lower().endswith(
                _SELF_SUFFIX.replace(chr(92), "/").lower()
            ):
                module = frame.f_globals.get("__name__")
                if isinstance(module, str) and module:
                    return module[:120]
                base = filename.replace(chr(92), "/").rsplit("/", 1)[-1]
                return base[:120] if base else "unknown"
            frame = frame.f_back
        return "unknown"

    def _on_audit(self, event: str, args: tuple[Any, ...]) -> None:
        """Audit callback; the dormant path is a boolean and a set lookup.

        The callback never raises for unexpected failures, because an exception
        escaping an audit hook would surface at the random call site that raised the
        audited event. PermissionError is the single intentional exception and is
        only raised for an enforced policy violation.
        """

        if not self.active:
            return
        if event not in WATCHED_EVENTS:
            return
        if self._busy:
            return
        self._busy = 1
        try:
            if event == "open" and self._honeypot_paths:
                self._check_honeypot(args)
            self._record(event, args)
            if event in _WRITE_EVENTS:
                self._observe_write_event(event, args)
            if self._policy.enforce and event in _ENFORCEMENT_EVENTS:
                self._enforce_event(event, args)
        except PermissionError:
            raise
        except BaseException:
            self._errors += 1
        finally:
            self._busy = 0

    def _record(self, event: str, args: tuple[Any, ...]) -> None:
        """Append one event to the bounded ring and bump its counter."""

        detail = self._describe(event, args)
        with self._lock:
            self._sequence += 1
            entry = {
                "seq": self._sequence,
                "event": event,
                "detail": detail,
                "origin": None,
                "blocked": False,
            }
            self._ring.append(entry)
            self._recorded += 1
            self._counts[event] = self._counts.get(event, 0) + 1

    def _describe(self, event: str, args: tuple[Any, ...]) -> str:
        """Build a short, allocation bounded description for one event."""

        try:
            if event == "open":
                path = _coerce_path(args[0]) if args else None
                mode = args[1] if len(args) > 1 else None
                return f"open {path or '<fd>'} mode={mode!r}"[:200]
            if event == "import":
                return f"import {args[0]}"[:200] if args else "import"
            if event == "compile":
                name = args[1] if len(args) > 1 else "<unknown>"
                return f"compile {name}"[:200]
            if event == "exec":
                kind = type(args[0]).__name__ if args else "unknown"
                return f"exec {kind}"
            if event == "subprocess.Popen":
                executable = args[0] if args else "<unknown>"
                text = executable if isinstance(executable, str) else repr(executable)
                return f"spawn {text}"[:200]
            if event == "socket.connect":
                address = args[1] if len(args) > 1 else "<unknown>"
                return f"connect {address!r}"[:200]
            if event == "pickle.loads":
                size = len(args[0]) if args and hasattr(args[0], "__len__") else -1
                return f"pickle.loads {size} byte(s)"
            if event == "marshal.loads":
                size = len(args[0]) if args and hasattr(args[0], "__len__") else -1
                return f"marshal.loads {size} byte(s)"
            if event == "sys._getframe":
                return "frame lookup"
        except (IndexError, TypeError, ValueError, ReferenceError):
            return f"{event} <uninspectable>"
        return event

    def _enforce_provenance(self) -> Provenance:
        """Return the initiating frame's provenance for enforcement.

        Many audited operations are wrapped by a standard library Python frame:
        subprocess.Popen raises its event inside subprocess.py, socket.getaddrinfo
        inside socket.py, and pathlib-based reads raise "open" inside pathlib.py.
        The immediate caller is therefore the interpreter, not the package, and a
        literal first-frame rule would let a package bypass the gate by using the
        stdlib wrapper. The walk skips interpreter frames and stops at the first
        project, site-packages or unknown frame, which is the code that actually
        initiated the operation. It stays bounded to twelve frames.

        sys._getframe itself raises the "sys._getframe" audit event, which
        re-enters the hook; the busy flag makes that nested call a no-op.
        """

        try:
            frame = sys._getframe(1)
        except (AttributeError, ValueError):
            return _UNKNOWN_PROVENANCE
        for _ in range(_MAX_FRAME_WALK):
            if frame is None:
                break
            try:
                filename = frame.f_code.co_filename
            except (AttributeError, ValueError):
                break
            if _is_self_filename(filename):
                frame = frame.f_back
                continue
            provenance = _provenance_for_frame(frame)
            if provenance.kind == "stdlib":
                frame = frame.f_back
                continue
            return provenance
        return _UNKNOWN_PROVENANCE

    def _enforce_event(self, event: str, args: tuple[Any, ...]) -> None:
        """Block a policy violation from a site-packages frame.

        The sensitive-read branch first applies the cheap path and mode tests, and
        only then resolves provenance. The network and subprocess branches resolve
        provenance first because those events are rare and there is no cheaper
        discriminator.

        Raises:
            PermissionError: When the active policy blocks the operation.
        """

        if event == "open":
            if not self._policy.deny_sensitive_reads or not args:
                return
            path_text = _coerce_path(args[0])
            if path_text is None or not is_sensitive_path(path_text):
                return
            if not _is_read_mode(args[1] if len(args) > 1 else None):
                return
            provenance = self._enforce_provenance()
            if provenance.kind != "site-packages" or self._policy.allows(provenance):
                return
            self._deny(
                "sensitive_read", event, path_text[:160], provenance, "deny_sensitive_reads"
            )
            return
        if event in _CONNECT_EVENTS:
            if not self._policy.deny_third_party_connect:
                return
            kind = "connect"
            flag = "deny_third_party_connect"
        elif event in _SUBPROCESS_EVENTS:
            if not self._policy.deny_third_party_subprocess:
                return
            kind = "subprocess"
            flag = "deny_third_party_subprocess"
        else:
            return
        provenance = self._enforce_provenance()
        if provenance.kind != "site-packages" or self._policy.allows(provenance):
            return
        self._deny(kind, event, _format_target(event, args), provenance, flag)

    def _deny(
        self,
        kind: str,
        event: str,
        target: str,
        provenance: Provenance,
        flag: str,
        *,
        extra: dict[str, Any] | None = None,
        message: str | None = None,
    ) -> None:
        """Record one denial and raise the policy PermissionError.

        Two records are kept: a structured denial entry for the dossier and a
        blocked entry in the ordinary event ring so the existing reporting path
        continues to see it. Extra fields carry per-family evidence such as the
        deserialization opcode and its offset.

        Raises:
            PermissionError: Always, with the exact English policy message.
        """

        final_message = message or _denial_message(
            kind, provenance.package, event, target, flag
        )
        detail_prefix = {
            "sensitive_read": "blocked sensitive read",
            "connect": "blocked third-party connect",
            "subprocess": "blocked third-party subprocess",
            "deserialization": "blocked unsafe deserialization",
        }.get(kind, "blocked third-party operation")
        stamp = time.time()
        with self._lock:
            self._sequence += 1
            ring_entry = {
                "seq": self._sequence,
                "event": event,
                "detail": f"{detail_prefix}: {target}"[:200],
                "origin": "third-party",
                "blocked": True,
                "flag": flag,
                "package": provenance.package,
                "provenance": provenance.as_dict(),
            }
            if extra:
                ring_entry.update(extra)
            self._ring.append(ring_entry)
            self._recorded += 1
            self._counts[event] = self._counts.get(event, 0) + 1
            self._blocked_count += 1
            self._violations += 1
            self._denial_sequence += 1
            denial = {
                "seq": self._denial_sequence,
                "time": stamp,
                "kind": kind,
                "target": target,
                "provenance": provenance.as_dict(),
                "flag": flag,
                "event": event,
                "package": provenance.package,
                "module": provenance.module,
                "message": final_message,
            }
            if extra:
                denial.update(extra)
            self._denials.append(denial)
            self._denials_count += 1
        raise PermissionError(final_message)

    def _record_watch_denial(
        self,
        kind: str,
        event: str,
        target: str,
        provenance: Provenance,
        flag: str,
        message: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Record a policy violation observed in watch mode without blocking it.

        The entry is denial shaped so a dossier can group it with real blocks, but
        it is marked watch=True and does not count as a denial or a blocked event.
        Records carry the label and digest prefix for secrets, and the opcode and
        offset for deserialization; they never carry a secret value.
        """

        stamp = time.time()
        with self._lock:
            self._sequence += 1
            ring_entry = {
                "seq": self._sequence,
                "event": event,
                "detail": f"watch: {kind.replace('_', ' ')}: {target}"[:200],
                "origin": "third-party",
                "blocked": False,
                "watch": True,
                "flag": flag,
                "package": provenance.package,
                "provenance": provenance.as_dict(),
            }
            if extra:
                ring_entry.update(extra)
            self._ring.append(ring_entry)
            self._recorded += 1
            self._counts[kind] = self._counts.get(kind, 0) + 1
            self._watch_counts[kind] = self._watch_counts.get(kind, 0) + 1
            self._denial_sequence += 1
            denial = {
                "seq": self._denial_sequence,
                "time": stamp,
                "kind": kind,
                "target": target,
                "provenance": provenance.as_dict(),
                "flag": flag,
                "event": event,
                "package": provenance.package,
                "module": provenance.module,
                "message": message,
                "blocked": False,
                "watch": True,
            }
            if extra:
                denial.update(extra)
            self._denials.append(denial)

    def _record_deserialization_watch(
        self,
        event: str,
        target: str,
        provenance: Provenance,
        flag: str,
        message: str,
        extra: dict[str, Any] | None = None,
    ) -> None:
        """Backward compatible entry point used by the deserialization gate."""

        self._record_watch_denial(
            "deserialization", event, target, provenance, flag, message, extra
        )


    def _observe_write_event(self, event: str, args: tuple[Any, ...]) -> None:
        """Feed one destructive filesystem event to the burst tracker.

        The tracker is only reached while the guard is active: the audit callback
        returns on its first boolean when dormant, so an inactive process pays
        nothing for this detector.
        """

        kind = _WRITE_KIND.get(event)
        if kind is None:
            return
        try:
            source = _coerce_path(args[0]) if args else None
            target = None
            if kind == "rename" and len(args) > 1:
                target = _coerce_path(args[1])
            verdict = self._burst.observe(
                kind,
                source or "",
                target or "",
                now=time.monotonic(),
                window_s=self._policy.burst_window_s,
                threshold=self._policy.burst_threshold,
            )
        except BaseException:
            self._errors += 1
            return
        if verdict is not None:
            self._record_ransom_burst(verdict)

    def _record_ransom_burst(self, verdict: "BurstVerdict") -> None:
        """Record one confirmed burst and enforce it when the policy asks.

        The record is denial shaped with blocked=False (a burst is a detection; the
        operations that already happened are never retroactively blocked). When
        deny_ransom_burst and enforce are both on, only the operation that crosses
        the threshold raises, after the record is written.
        """

        provenance = self._enforce_provenance()
        detection = (
            f"ransomware-shaped write burst detected: {verdict.volume} destructive "
            f"operations in {verdict.window_s:.1f}s with {verdict.dominance:.0%} of "
            f"{verdict.rename_count} rename targets sharing suffix '{verdict.suffix}'"
        )
        extra = verdict.as_dict()
        extra["flag"] = "deny_ransom_burst"
        enforce = self._policy.enforce and self._policy.deny_ransom_burst
        message = detection + (" by deny_ransom_burst" if enforce else "")
        self._burst_events += 1
        self._record_watch_denial(
            "ransom_burst",
            "ransom_burst",
            f"suffix '{verdict.suffix}'",
            provenance,
            "deny_ransom_burst",
            message,
            extra,
        )
        if enforce:
            raise PermissionError(message)


def _is_read_mode(mode: Any) -> bool:
    """Return True when the audited open mode is a read-only intent.

    The open event passes either a mode string or the raw os.open flags integer.
    Both forms are accepted; an unknown form is treated as a write intent so the
    guard never blocks an operation it does not understand.
    """

    if isinstance(mode, str):
        lowered = mode.lower()
        return not any(flag in lowered for flag in ("w", "a", "x", "+"))
    if isinstance(mode, int):
        write_flags = os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND
        return (mode & write_flags) == 0
    return True


guard = AuditGuard()


def install(enforce: bool = False, root: Path | None = None) -> None:
    """Arm the module level guard (see AuditGuard.install)."""

    guard.install(enforce=enforce, root=root)


def deactivate() -> None:
    """Deactivate the module level guard."""

    guard.deactivate()


def active() -> bool:
    """True while the module level guard records events."""

    return guard.active


def enforce_enabled() -> bool:
    """True when the module level guard raises PermissionError on violations."""

    return guard.enforce_enabled()


def stats() -> dict[str, Any]:
    """Snapshot the module level guard state."""

    return guard.stats()


def events(limit: int = 32) -> list[dict[str, Any]]:
    """Return the most recent events recorded by the module level guard."""

    return guard.events(limit)


def reset() -> None:
    """Clear the module level guard ring and counters."""

    guard.reset()


def set_honeypot_paths(paths: Iterable[str]) -> int:
    """Register honeypot decoy paths on the module level guard (see AuditGuard)."""

    return guard.set_honeypot_paths(paths)


def honeypot_events(limit: int = 32) -> list[dict[str, Any]]:
    """Return the most recent honeypot alerts recorded by the module level guard."""

    return guard.honeypot_events(limit)

def denials(limit: int = 32) -> list[dict[str, Any]]:
    """Return the most recent policy denials recorded by the module level guard."""

    return guard.denials(limit)


def arm_shield(
    policy: GuardPolicy | None = None,
    *,
    secret_files: Iterable[str | os.PathLike[str]] = (),
) -> None:
    """Arm the process wide containment shield for embedding.

    Parameters:
        policy: Complete policy to apply. When omitted the environment is read
            through GuardPolicy.from_env, which keeps enforcement off unless
            TAUHAULITY_ENFORCE is set.
        secret_files: Credential files to harvest into the egress registry.
            When empty, TAUHAULITY_EGRESS_SECRETS (os.pathsep separated) is used,
            and if that is unset too the project .env is used when it exists.
            Values are registered with the label "env" and never logged.
    """

    guard.apply_policy(policy if policy is not None else GuardPolicy.from_env())
    _load_egress_secret_sources(secret_files)


@contextmanager
def shield(policy: GuardPolicy | None = None) -> Iterator[AuditGuard]:
    """Scope an enforcement policy to one block without leaking it.

    The guard is installed on entry and the previous policy is restored on exit.
    When the guard was dormant before the block it is deactivated again, because
    an embedding host should not be left with an armed containment layer it did
    not ask for.

    Parameters:
        policy: Policy to apply inside the block; defaults to GuardPolicy.from_env().

    Yields:
        The module level AuditGuard so the block can inspect denials and stats.
    """

    active_policy = policy if policy is not None else GuardPolicy.from_env()
    previous_policy = guard.policy
    was_active = guard.active
    gate_was_active = deserialization_gate_active()
    egress_gate_was_active = egress_gate_active()
    guard.apply_policy(active_policy)
    try:
        yield guard
    finally:
        guard.apply_policy(previous_policy)
        if not gate_was_active:
            unpatch_deserialization()
        if not egress_gate_was_active:
            unpatch_egress()
        if not was_active:
            guard.deactivate()


def propagation_sitecustomize(directory: Path | None = None) -> Path:
    """Materialise the child propagation shim and return its directory.

    The directory contains one sitecustomize.py that arms this guard from the
    environment in any Python child whose PYTHONPATH starts with the returned path.
    The shim is idempotent (a process that already armed is left alone), swallows
    every failure so a broken guard cannot break a build step, and writes nothing
    outside its own directory.

    Parameters:
        directory: Shim directory to use. When omitted a unique temporary directory
            is created (tempfile.mkdtemp), which is the concurrent safe default on
            every platform including Windows. A supplied directory is used as-is and
            created when missing; the caller then owns its uniqueness.

    Returns:
        The shim directory, ready to be put first on PYTHONPATH.

    Raises:
        PropagationError: When the directory or the shim file cannot be written.
    """

    return _bootstrap.materialise(directory)


def guard_propagation(
    env: dict[str, str],
    *,
    directory: Path | None = None,
) -> dict[str, str]:
    """Return a copy of env that arms the guard inside Python children.

    The returned environment:
      * has the fresh shim directory first on PYTHONPATH (os.pathsep preserved),
      * carries TAUHAULITY_GUARD_PROPAGATED=1 so a second call never prepends a
        second directory,
      * mirrors the active policy into the documented GuardPolicy.from_env()
        variables (TAUHAULITY_ENFORCE, TAUHAULITY_DENY_CONNECT,
        TAUHAULITY_DENY_SUBPROCESS, TAUHAULITY_DENY_DESERIALIZE,
        TAUHAULITY_DENY_SECRET_EGRESS, TAUHAULITY_GUARD_ALLOW) so the child enforces
        exactly what the parent enforces rather than whatever a stale shell export
        said,
      * inherits the armed project root as TAUHAULITY_PROJECT_ROOTS when the parent
        was installed with one and the caller did not set it.

    A marker already present in env means the environment was propagated before:
    the copy is returned unchanged, without creating another shim directory.

    The outbound secret registry itself is NOT propagated: secret values cannot be
    put into an environment without leaking them. Children harvest the project .env
    through arm_shield() and honour TAUHAULITY_EGRESS_SECRETS when it is inherited.

    Parameters:
        env: Parent environment mapping (for example os.environ).
        directory: Optional shim directory, forwarded to propagation_sitecustomize.

    Returns:
        A new environment mapping for subprocess.Popen(env=...).
    """

    result = dict(env)
    if _bootstrap.is_propagated(result):
        return result
    shim = _bootstrap.materialise(directory)
    result = _bootstrap.apply_env(result, shim)
    # The mirror never weakens what the caller asked for. Reading audit_hook arms a
    # watch-mode guard on import, so a caller that builds the environment before
    # arming enforcement (the CLI does exactly that) would otherwise see its own
    # TAUHAULITY_ENFORCE=1 overwritten with the dormant 0, and the child would
    # watch instead of enforce. A flag is therefore on when either side says on.
    policy = guard.policy if guard.active else None

    def combined(name: str, parent_flag: bool | None) -> str:
        current = str(result.get(name, "")).strip().lower()
        by_env = current in {"1", "true", "yes", "on"}
        if by_env or bool(parent_flag):
            return "1"
        return "0"

    result.update(
        {
            "TAUHAULITY_ENFORCE": combined(ENFORCE_ENV, policy.enforce if policy else None),
            "TAUHAULITY_DENY_CONNECT": combined(
                DENY_CONNECT_ENV, policy.deny_third_party_connect if policy else None
            ),
            "TAUHAULITY_DENY_SUBPROCESS": combined(
                DENY_SUBPROCESS_ENV, policy.deny_third_party_subprocess if policy else None
            ),
            "TAUHAULITY_DENY_DESERIALIZE": combined(
                DENY_DESERIALIZE_ENV, policy.deny_unsafe_deserialization if policy else None
            ),
            "TAUHAULITY_DENY_SECRET_EGRESS": combined(
                DENY_SECRET_EGRESS_ENV, policy.deny_egress_with_secrets if policy else None
            ),
        }
    )
    # The allowlist is always present so a child never blocks tauhaulity itself,
    # even when this process has not armed a policy of its own yet.
    if not result.get("TAUHAULITY_GUARD_ALLOW"):
        default_allow = ",".join(policy.allowlist) if policy is not None else "tauhaulity"
        result["TAUHAULITY_GUARD_ALLOW"] = default_allow
    project_root = getattr(guard, "_root", None)
    if project_root is not None:
        result.setdefault("TAUHAULITY_PROJECT_ROOTS", str(project_root))
    return result


def cleanup_propagation(directory: Path) -> bool:
    """Remove a shim directory created by propagation_sitecustomize().

    Leaving the directory in place is harmless: it holds one small file and only
    affects children the caller spawned with the propagated environment. Cleanup
    exists so a long running embedding host can keep its temporary directory tidy.

    Returns:
        True when the directory existed and was removed, False otherwise.
    """

    return _bootstrap.cleanup(directory)


def burst_summary() -> dict[str, Any]:
    """Return the module level write burst tracker summary for the dossier."""

    return guard.burst_summary()



