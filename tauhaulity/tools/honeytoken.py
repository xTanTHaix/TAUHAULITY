"""Honeytoken traps: decoy credential files whose first read is a loud signal.

A honeytoken is a credential shaped file that no legitimate program has any
reason to open. Polling canaries catch a writer that rewrites the tree, but a
honeytoken catches a reader on the exact system call that opens it, which is a
much stronger signal: credential stealers, backup daemons and careless scripts
globbing for secrets are all observed at the moment they touch the decoy.

Design constraints:

  * every decoy is obviously fake and never a usable credential. Each file
    carries a unique marker of the form th-honeytoken-<hex>; the SSH decoy uses a
    FAKE PEM header and a base64 body that decodes to plain text, so no parser
    accepts it and no scanner mistakes it for a real key;
  * deploy never silently destroys data. It refuses an occupied path unless
    force=True, and it re-deploys its own decoys idempotently (the marker in the
    file proves ownership);
  * the manifest is the single source of truth and is written atomically with
    0600 permissions under <root>/.tauhaulity/honeytokens.json. It stores project
    relative paths only, so moving the checkout does not invalidate the traps;
  * every read degrades gracefully. A missing, corrupt or hand edited manifest
    loads as None instead of raising, because a guard that crashes on a bad state
    file protects nothing.

The runtime half lives in tauhaulity.runtime.audit_hook: token_paths() is the
list the caller registers with set_honeypot_paths() to observe the first open.
"""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

HONEYTOKEN_KINDS: tuple[str, ...] = (
    "dotenv",
    "aws_credentials",
    "ssh_key",
    "npmrc",
    "pypirc",
)

MARKER_PREFIX = "th-honeytoken-"
MANIFEST_DIRNAME = ".tauhaulity"
MANIFEST_FILENAME = "honeytokens.json"
MANIFEST_VERSION = 1
GENERATOR = "tauhaulity.tools.honeytoken"

#: File mode for decoys and the manifest where the platform supports it.
FILE_MODE = 0o600

#: Project relative location of each decoy. The trailing .honeytoken suffix is
#: deliberate: no tool reads such a file by accident, so the first access is
#: always suspicious, while the content is shaped like the real credential.
_DECOY_PATHS: dict[str, str] = {
    "dotenv": ".env.honeytoken",
    "aws_credentials": ".aws/credentials.honeytoken",
    "ssh_key": ".ssh/id_rsa.honeytoken",
    "npmrc": ".npmrc.honeytoken",
    "pypirc": ".pypirc.honeytoken",
}

_MARKER_RE = re.compile(re.escape(MARKER_PREFIX) + r"[0-9a-f]{6,64}")
_MARKER_HEX_CHARS = 12


class HoneytokenError(RuntimeError):
    """Raised when decoys cannot be deployed or removed safely."""


@dataclass(frozen=True, slots=True)
class Honeytoken:
    """One deployed decoy credential file.

    Attributes:
        kind: Decoy family, one of HONEYTOKEN_KINDS.
        rel_path: Project relative path, forward slash separated.
        absolute_path: Absolute path the runtime guard watches.
        created_at: UTC ISO timestamp of the first deployment.
        marker: Unique th-honeytoken-<hex> string embedded in the content.
    """

    kind: str
    rel_path: str
    absolute_path: Path
    created_at: str
    marker: str


@dataclass(frozen=True, slots=True)
class HoneytokenSet:
    """The decoys armed for one project.

    Attributes:
        root: Absolute project root the decoys belong to.
        tokens: Deployed decoys in deployment order.
        manifest_path: Absolute path of the JSON manifest.
        created_at: UTC ISO timestamp recorded by the last deployment.
    """

    root: Path
    tokens: tuple[Honeytoken, ...]
    manifest_path: Path
    created_at: str


def _utc_now() -> str:
    """Return an ISO 8601 UTC timestamp with second precision."""

    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _abspath(value: Path) -> Path:
    """Return an absolute path without following symlinks."""

    return Path(os.path.abspath(str(value)))


def manifest_path(root: Path) -> Path:
    """Return the conventional manifest path for a project root."""

    return _abspath(Path(root)) / MANIFEST_DIRNAME / MANIFEST_FILENAME


def _new_marker() -> str:
    """Return a fresh unique marker; 12 hex characters keeps it short and unique."""

    return MARKER_PREFIX + secrets.token_hex(_MARKER_HEX_CHARS // 2)


def _decoy_text(kind: str, marker: str) -> str:
    """Render one decoy file shaped like the real credential but obviously fake.

    The marker appears verbatim in a comment and again as the credential value, so
    a leaked copy is traceable back to this deployment. Values are the marker
    itself, never a token the issuing service would accept.
    """

    header = (
        "# tauhaulity honeytoken decoy; not a real credential."
        " marker: " + marker + chr(10)
    )
    if kind == "dotenv":
        return (
            header
            + "API_TOKEN=\"" + marker + "\"" + chr(10)
            + "AWS_ACCESS_KEY_ID=\"" + marker + "\"" + chr(10)
            + "AWS_SECRET_ACCESS_KEY=\"" + marker + "\"" + chr(10)
            + "NPM_TOKEN=\"" + marker + "\"" + chr(10)
        )
    if kind == "aws_credentials":
        return (
            header
            + "[default]" + chr(10)
            + "aws_access_key_id = " + marker + chr(10)
            + "aws_secret_access_key = " + marker + chr(10)
            + "region = us-east-1" + chr(10)
        )
    if kind == "ssh_key":
        body = base64.b64encode(
            ("tauhaulity honeytoken " + marker + " not a usable key").encode("ascii")
        ).decode("ascii")
        wrapped = chr(10).join(
            body[index : index + 64] for index in range(0, len(body), 64)
        )
        return (
            header
            + "-----BEGIN FAKE SSH PRIVATE KEY-----" + chr(10)
            + wrapped + chr(10)
            + "-----END FAKE SSH PRIVATE KEY-----" + chr(10)
        )
    if kind == "npmrc":
        return (
            header
            + "registry=https://registry.npmjs.org/" + chr(10)
            + "//registry.npmjs.org/:_authToken=" + marker + chr(10)
        )
    if kind == "pypirc":
        return (
            header
            + "[pypi]" + chr(10)
            + "username = __token__" + chr(10)
            + "password = " + marker + chr(10)
            + "repository = https://upload.pypi.org/legacy/" + chr(10)
        )
    raise HoneytokenError("unknown honeytoken kind: " + kind)


def _existing_marker(path: Path) -> str | None:
    """Return the marker already present in a file, or None when it is foreign."""

    try:
        with path.open("rb") as handle:
            payload = handle.read(4096)
    except OSError:
        return None
    if b"\x00" in payload[:4096]:
        return None
    match = _MARKER_RE.search(payload.decode("utf-8", errors="replace"))
    return match.group(0) if match is not None else None


def _write_atomic(path: Path, text: str, mode: int = FILE_MODE) -> None:
    """Write a file atomically with the given mode, surfacing failures."""

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise HoneytokenError(
            "cannot create directory " + str(path.parent) + ": " + str(exc)
        ) from exc
    tmp = path.with_name(path.name + ".honeytoken-tmp")
    try:
        with tmp.open("w", encoding="utf-8", newline=chr(10)) as handle:
            handle.write(text)
        try:
            os.chmod(tmp, mode)
        except OSError:
            pass
        os.replace(tmp, path)
    except OSError as exc:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise HoneytokenError(
            "cannot write honeytoken file " + str(path) + ": " + str(exc)
        ) from exc
    try:
        os.chmod(path, mode)
    except OSError:
        # A filesystem without POSIX mode bits is not a reason to fail the deploy.
        pass


def _normalize_kinds(kinds: Sequence[str] | None) -> tuple[str, ...]:
    """Validate and deduplicate the requested decoy families."""

    if kinds is None:
        return HONEYTOKEN_KINDS
    selected: list[str] = []
    for value in kinds:
        kind = str(value)
        if kind not in HONEYTOKEN_KINDS:
            raise HoneytokenError(
                "unknown honeytoken kind: " + kind + " (expected "
                + ", ".join(HONEYTOKEN_KINDS) + ")"
            )
        if kind not in selected:
            selected.append(kind)
    return tuple(selected)


def _safe_rel_path(value: object) -> str | None:
    """Return a normalized project relative path, or None when it escapes root."""

    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace(chr(92), "/")
    if normalized.startswith("/") or (len(normalized) > 1 and normalized[1] == ":"):
        return None
    parts = [part for part in normalized.split("/") if part and part != "."]
    if not parts or any(part == ".." for part in parts):
        return None
    return "/".join(parts)


def deploy(
    root: Path,
    *,
    kinds: Sequence[str] | None = None,
    force: bool = False,
) -> HoneytokenSet:
    """Deploy decoy credential files and write the manifest.

    Deployment is idempotent for decoys that are already ours: the marker in the
    file proves ownership, so a second call keeps the same marker and timestamp.
    A path occupied by a foreign file is refused unless force=True, which is the
    caller explicitly taking responsibility for replacing it.

    Parameters:
        root: Project root to deploy into.
        kinds: Families to deploy; None deploys all HONEYTOKEN_KINDS.
        force: Replace a path that exists but is not one of our decoys.

    Returns:
        The armed decoy set, including the manifest path.

    Raises:
        HoneytokenError: When the root is unusable, a decoy path is a directory,
            an occupied path is refused, or a file cannot be written.
    """

    root_path = _abspath(Path(root))
    try:
        is_directory = root_path.is_dir()
    except OSError:
        is_directory = False
    if not is_directory:
        raise HoneytokenError("honeytoken root is not a directory: " + str(root_path))

    selected = _normalize_kinds(kinds)
    manifest = manifest_path(root_path)
    previous = load(root_path)
    previous_by_kind: dict[str, Honeytoken] = (
        {token.kind: token for token in previous.tokens} if previous is not None else {}
    )
    created_at = (
        previous.created_at if previous is not None and previous.created_at else _utc_now()
    )

    planned: list[Honeytoken] = []
    for kind in selected:
        rel_path = _DECOY_PATHS[kind]
        absolute = _abspath(root_path / rel_path)
        prior = previous_by_kind.get(kind)
        marker = _existing_marker(absolute)
        occupied = absolute.is_dir() or absolute.is_file() or absolute.is_symlink()
        if absolute.is_dir():
            raise HoneytokenError(
                "refusing to replace a directory with a honeytoken: " + str(absolute)
            )
        if marker is not None:
            token_created = (
                prior.created_at if prior is not None and prior.marker == marker else created_at
            )
        elif occupied:
            if not force:
                raise HoneytokenError(
                    "refusing to overwrite an existing file: "
                    + str(absolute)
                    + " (pass force=True to replace it)"
                )
            marker = _new_marker()
            token_created = _utc_now()
        elif prior is not None:
            # The file is gone but the manifest still names it: keep the marker so
            # a previously leaked copy remains traceable to this token.
            marker = prior.marker
            token_created = prior.created_at or created_at
        else:
            marker = _new_marker()
            token_created = _utc_now()
        planned.append(
            Honeytoken(
                kind=kind,
                rel_path=rel_path,
                absolute_path=absolute,
                created_at=token_created,
                marker=marker,
            )
        )

    for token in planned:
        _write_atomic(token.absolute_path, _decoy_text(token.kind, token.marker))

    payload = {
        "version": MANIFEST_VERSION,
        "generator": GENERATOR,
        "created_at": created_at,
        "tokens": [
            {
                "kind": token.kind,
                "rel_path": token.rel_path,
                "created_at": token.created_at,
                "marker": token.marker,
            }
            for token in planned
        ],
    }
    _write_atomic(manifest, json.dumps(payload, indent=2, sort_keys=True) + chr(10))
    return HoneytokenSet(
        root=root_path,
        tokens=tuple(planned),
        manifest_path=manifest,
        created_at=created_at,
    )


def load(root: Path) -> HoneytokenSet | None:
    """Load the deployed decoy set, degrading to None on any unusable manifest.

    A missing file, invalid JSON, wrong shape or a manifest whose every entry is
    malformed all return None. That is deliberate: the traps are optional, so a
    damaged state file must disable them without breaking the caller.
    """

    root_path = _abspath(Path(root))
    path = manifest_path(root_path)
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return None
    try:
        payload = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(payload, Mapping):
        return None
    raw_tokens = payload.get("tokens")
    if not isinstance(raw_tokens, list):
        return None
    tokens: list[Honeytoken] = []
    for item in raw_tokens:
        if not isinstance(item, Mapping):
            continue
        kind = item.get("kind")
        marker = item.get("marker")
        rel_path = _safe_rel_path(item.get("rel_path"))
        if (
            not isinstance(kind, str)
            or not kind
            or not isinstance(marker, str)
            or not marker
            or rel_path is None
        ):
            continue
        stamp = item.get("created_at")
        tokens.append(
            Honeytoken(
                kind=kind,
                rel_path=rel_path,
                absolute_path=_abspath(root_path / rel_path),
                created_at=stamp if isinstance(stamp, str) else "",
                marker=marker,
            )
        )
    if not tokens and raw_tokens:
        return None
    stamp = payload.get("created_at")
    return HoneytokenSet(
        root=root_path,
        tokens=tuple(tokens),
        manifest_path=path,
        created_at=stamp if isinstance(stamp, str) else "",
    )


def list_tokens(root: Path) -> list[Honeytoken]:
    """Return the deployed decoys, or an empty list when nothing is armed."""

    loaded = load(root)
    if loaded is None:
        return []
    return list(loaded.tokens)


def token_paths(root: Path) -> tuple[Path, ...]:
    """Return the absolute paths the runtime guard should watch."""

    return tuple(token.absolute_path for token in list_tokens(root))


def remove(root: Path) -> bool:
    """Delete the decoys and the manifest.

    Only files that still carry our marker are deleted, so a hand edited manifest
    can never turn remove() into an arbitrary file deletion.

    Returns:
        True when a manifest was found and removed, False otherwise.
    """

    root_path = _abspath(Path(root))
    loaded = load(root_path)
    if loaded is None:
        return False
    for token in loaded.tokens:
        if _existing_marker(token.absolute_path) is None:
            continue
        try:
            token.absolute_path.unlink()
        except OSError:
            continue
    try:
        loaded.manifest_path.unlink()
    except OSError:
        return False
    return True


def _honeypot_alert_count() -> int:
    """Return the number of honeypot alerts recorded by the runtime guard.

    The runtime module is imported lazily and every failure degrades to zero, so a
    build without the guard still renders a status line.
    """

    try:
        from tauhaulity.runtime import audit_hook
    except ImportError:
        return 0
    try:
        snapshot = audit_hook.stats()
    except (OSError, RuntimeError, ValueError, TypeError):
        return 0
    try:
        return int(snapshot.get("honeypot_alerts", 0) or 0)
    except (TypeError, ValueError):
        return 0


def honeytoken_status(root: Path) -> str:
    """Return one English line describing the armed decoys and alert count."""

    tokens = list_tokens(root)
    alerts = _honeypot_alert_count()
    if not tokens:
        return "honeytokens: none armed; " + str(alerts) + " alert(s) since guard start"
    counts: dict[str, int] = {}
    for token in tokens:
        counts[token.kind] = counts.get(token.kind, 0) + 1
    listing = ", ".join(
        kind + (" x" + str(count) if count > 1 else "")
        for kind, count in sorted(counts.items())
    )
    return (
        "honeytokens: "
        + str(len(tokens))
        + " armed ("
        + listing
        + "); "
        + str(alerts)
        + " alert(s) since guard start"
    )


def deploy_report(root: Path, force: bool = False) -> str:
    """Deploy decoys and return a one line report for the command line."""

    armed = deploy(root, force=force)
    kinds = ", ".join(token.kind for token in armed.tokens)
    if not armed.tokens:
        return "deployed 0 honeytokens; manifest: " + str(armed.manifest_path)
    return (
        "deployed "
        + str(len(armed.tokens))
        + " honeytoken(s) ("
        + kinds
        + ") under "
        + str(armed.root)
        + "; manifest: "
        + str(armed.manifest_path)
    )
