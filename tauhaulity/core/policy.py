"""Declarative policy shared by the CLI, the pillar probes and the dossier form.

The dossier form is only useful if the values a developer checks in the report
drive the running engine, so the policy object is the single source of truth for
what Tauhaulity is allowed to do. Keeping persistence in this module means the
form parser and the CLI never write configuration independently.
"""

from __future__ import annotations

import fnmatch
import json
import os
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Mapping

POLICY_DIRNAME = ".tauhaulity"
POLICY_FILENAME = "policy.json"

MIN_UNDO_RING_MB = 16
MAX_UNDO_RING_MB = 4096


class PolicyError(ValueError):
    """Raised when a policy file or override carries an invalid value."""


@dataclass(slots=True)
class Policy:
    """Effective runtime policy.

    Attributes:
        enforce_active: Block instead of only recording violations.
        auto_hotpatch: Allow pointer table patching when a pillar supports it.
        block_git_secrets: Pre-commit gate blocks detected credentials.
        undo_ring_mb: Circular undo store budget in megabytes.
        auto_zombie_free: Terminate processes that hold conflicting ports.
        ignored_paths: Relative glob patterns excluded from scans.
        auditor: Free-form sign-off string embedded in dossiers.
        watch_egress: Observe outbound cleartext for secrets.
        canary_freeze: Suspend the writer when a canary trap fires.
    """

    enforce_active: bool = False
    auto_hotpatch: bool = False
    block_git_secrets: bool = True
    undo_ring_mb: int = 512
    auto_zombie_free: bool = False
    ignored_paths: tuple[str, ...] = ()
    auditor: str = "Unspecified"
    watch_egress: bool = True
    canary_freeze: bool = False

    def validate(self) -> "Policy":
        """Return a normalized copy, rejecting impossible values.

        Raises:
            PolicyError: When the undo ring budget or an ignored path is invalid.
        """

        if isinstance(self.undo_ring_mb, bool) or not isinstance(self.undo_ring_mb, int):
            raise PolicyError("undo_ring_mb must be an integer")
        if not MIN_UNDO_RING_MB <= self.undo_ring_mb <= MAX_UNDO_RING_MB:
            raise PolicyError(
                f"undo_ring_mb {self.undo_ring_mb} outside {MIN_UNDO_RING_MB}..{MAX_UNDO_RING_MB}"
            )
        cleaned: list[str] = []
        for pattern in self.ignored_paths:
            if not isinstance(pattern, str):
                raise PolicyError("ignored_paths entries must be strings")
            stripped = pattern.replace(chr(92), "/").strip().strip("/")
            if stripped and stripped != ".":
                cleaned.append(stripped)
        return replace(self, ignored_paths=tuple(dict.fromkeys(cleaned)))

    def to_dict(self) -> dict[str, Any]:
        """Serialize the policy to a JSON friendly mapping."""

        return {
            "enforce_active": self.enforce_active,
            "auto_hotpatch": self.auto_hotpatch,
            "block_git_secrets": self.block_git_secrets,
            "undo_ring_mb": self.undo_ring_mb,
            "auto_zombie_free": self.auto_zombie_free,
            "ignored_paths": list(self.ignored_paths),
            "auditor": self.auditor,
            "watch_egress": self.watch_egress,
            "canary_freeze": self.canary_freeze,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Policy":
        """Build a policy from a mapping, ignoring unknown keys.

        Raises:
            PolicyError: When a known key carries a value of the wrong type.
        """

        known: dict[str, Any] = {}
        for key in (
            "enforce_active",
            "auto_hotpatch",
            "block_git_secrets",
            "undo_ring_mb",
            "auto_zombie_free",
            "ignored_paths",
            "auditor",
            "watch_egress",
            "canary_freeze",
        ):
            if key not in data:
                continue
            value = data[key]
            if key == "undo_ring_mb":
                if isinstance(value, bool) or not isinstance(value, int):
                    raise PolicyError("undo_ring_mb must be an integer")
            elif key == "ignored_paths":
                if isinstance(value, str) or not isinstance(value, (list, tuple)):
                    raise PolicyError("ignored_paths must be a list of strings")
                value = tuple(str(item) for item in value)
            elif key == "auditor":
                if not isinstance(value, str):
                    raise PolicyError("auditor must be a string")
            elif not isinstance(value, bool):
                raise PolicyError(f"{key} must be a boolean")
            known[key] = value
        return cls(**known).validate()

    def save(self, path: Path) -> Path:
        """Write the policy atomically to disk and return the written path.

        Raises:
            PolicyError: When the policy is invalid or the file cannot be written.
        """

        normalized = self.validate()
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        payload = json.dumps(normalized.to_dict(), indent=2, sort_keys=True) + chr(10)
        try:
            tmp.write_text(payload, encoding="utf-8")
            os.replace(tmp, path)
        except OSError as exc:
            raise PolicyError(f"cannot write policy file {path}: {exc}") from exc
        return path

    @classmethod
    def load(cls, path: Path, *, strict: bool = False) -> "Policy":
        """Load a policy file, falling back to defaults when absent.

        Parameters:
            path: Policy JSON path.
            strict: When True a malformed file raises instead of falling back.

        Raises:
            PolicyError: When strict is True and the file is malformed.
        """

        path = Path(path)
        if not path.is_file():
            return cls()
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            if strict:
                raise PolicyError(f"cannot read policy file {path}: {exc}") from exc
            return cls()
        if not isinstance(raw, Mapping):
            if strict:
                raise PolicyError(f"policy file {path} must contain an object")
            return cls()
        try:
            return cls.from_dict(raw)
        except PolicyError:
            if strict:
                raise
            return cls()

    def with_overrides(self, overrides: "PolicyOverrides") -> "Policy":
        """Return a new policy with explicitly provided overrides applied.

        Raises:
            PolicyError: When the merged policy is invalid.
        """

        changes = dict(overrides.as_items())
        merged = replace(self, **changes)
        return merged.validate()

    def is_ignored(self, relative_path: str) -> bool:
        """Return True when a project relative path matches an ignore pattern.

        Matching is performed on the forward-slash form so the same policy file
        behaves identically on Windows and inside WSL.
        """

        candidate = relative_path.replace(chr(92), "/").lstrip("./")
        for pattern in self.ignored_paths:
            if fnmatch.fnmatch(candidate, pattern):
                return True
            if candidate == pattern or candidate.startswith(pattern + "/"):
                return True
        return False


@dataclass(frozen=True, slots=True)
class PolicyOverrides:
    """Partial policy produced by the dossier form or CLI flags.

    Every field is optional: None means the caller expressed no opinion and the
    existing policy value survives the merge.
    """

    enforce_active: bool | None = None
    auto_hotpatch: bool | None = None
    block_git_secrets: bool | None = None
    undo_ring_mb: int | None = None
    auto_zombie_free: bool | None = None
    ignored_paths: tuple[str, ...] | None = None
    auditor: str | None = None
    watch_egress: bool | None = None
    canary_freeze: bool | None = None

    def as_items(self) -> list[tuple[str, Any]]:
        """Return the explicitly provided fields as key/value pairs."""

        return [
            (key, value)
            for key, value in (
                ("enforce_active", self.enforce_active),
                ("auto_hotpatch", self.auto_hotpatch),
                ("block_git_secrets", self.block_git_secrets),
                ("undo_ring_mb", self.undo_ring_mb),
                ("auto_zombie_free", self.auto_zombie_free),
                ("ignored_paths", self.ignored_paths),
                ("auditor", self.auditor),
                ("watch_egress", self.watch_egress),
                ("canary_freeze", self.canary_freeze),
            )
            if value is not None
        ]


def policy_dir(root: Path) -> Path:
    """Return the runtime state directory used inside a project."""

    return Path(root) / POLICY_DIRNAME


def policy_path(root: Path) -> Path:
    """Return the policy file path used inside a project."""

    return policy_dir(root) / POLICY_FILENAME
