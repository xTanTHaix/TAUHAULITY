"""Bidirectional parser for the dossier sign-off form.

The form is the only part of a dossier a human edits, so a typo must fail loudly
instead of silently producing an empty policy override: an auditor who ticks a box
needs to know the tick was understood. Every recognised key therefore either parses
completely or raises FormError carrying the one based line number, while bullet
lines from other dossier sections (actionable slots, evidence rows) are ignored.

The layout uses fixed key widths so the Markdown and plain text dossiers can share
one renderer, and so parse_form can round-trip what render_form_lines produced.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final

from tauhaulity.core.policy import (
    MAX_UNDO_RING_MB,
    MIN_UNDO_RING_MB,
    Policy,
    PolicyOverrides,
)

if TYPE_CHECKING:
    from tauhaulity.dossier.model import DossierReport

# Width of the key column. Nineteen is the longest key plus the one space the
# blueprint template shows before the colon, which keeps the sign-off block
# readable without a table renderer.
KEY_WIDTH: Final[int] = 19

# Width of the first option / value field so the second option starts on the
# same column for every row.
OPTION_WIDTH: Final[int] = 30

# (display key, kind, policy field, options or note)
_FORM_ROWS: Final[
    tuple[tuple[str, str, str, object], ...]
] = (
    (
        "Protection Mode",
        "bool",
        "enforce_active",
        ("Enforce Active Shield", "Audit-Only (Monitor)"),
    ),
    (
        "Auto Hot-Patching",
        "bool",
        "auto_hotpatch",
        ("Enable Safe GOT/DR Patch", "Disable Live Patching"),
    ),
    (
        "Git Pre-Commit Hook",
        "bool",
        "block_git_secrets",
        ("Block Strict PAT/SSH Leak", "Warning Only"),
    ),
    ("Dev Snap Undo Ring", "value", "undo_ring_mb", "Undo buffer size for deleted files"),
    (
        "Auto Zombie Free",
        "bool",
        "auto_zombie_free",
        ("Terminate Hung Ports", "Keep Alive"),
    ),
    ("Ignored Paths", "value", "ignored_paths", "Directories excluded from inspection"),
    ("Auditor Name/Notes", "value", "auditor", "Auditor sign-off string"),
)

# Normalised key to row. Normalisation strips case, surrounding space and the
# spaces around the slash so "Auditor Name / Notes" is accepted as the same key.
_KEY_ALIASES: Final[dict[str, str]] = {
    "protection mode": "Protection Mode",
    "auto hot-patching": "Auto Hot-Patching",
    "auto hot patching": "Auto Hot-Patching",
    "git pre-commit hook": "Git Pre-Commit Hook",
    "git pre commit hook": "Git Pre-Commit Hook",
    "dev snap undo ring": "Dev Snap Undo Ring",
    "dev-snap undo ring": "Dev Snap Undo Ring",
    "auto zombie free": "Auto Zombie Free",
    "ignored paths": "Ignored Paths",
    "auditor name/notes": "Auditor Name/Notes",
    "auditor name / notes": "Auditor Name/Notes",
    "auditor": "Auditor Name/Notes",
}

_BOX_PATTERN: Final[re.Pattern[str]] = re.compile(r"\[([ xX]?)\]")
_VALUE_PATTERN: Final[re.Pattern[str]] = re.compile(r"^<([^<>]*)>(?:\s*\(.*\))?\s*$")
_RING_PATTERN: Final[re.Pattern[str]] = re.compile(r"^(\d{1,6})\s*(?:MB|mb|Mb|M|m)?$")
_BULLET_PREFIXES: Final[tuple[str, ...]] = ("\u2022", "-", "*")


class FormError(ValueError):
    """Raised when a sign-off form line cannot be parsed.

    Attributes:
        line_number: One based line number inside the parsed document.
        line: The offending line text, stripped of surrounding whitespace.
    """

    def __init__(self, line_number: int, reason: str, line: str = "") -> None:
        self.line_number = int(line_number)
        self.reason = reason
        self.line = line
        message = f"form line {self.line_number}: {reason}"
        if line:
            message += f" ({line.strip()!r})"
        super().__init__(message)


def _normalise_key(text: str) -> str:
    """Normalise a display key for alias lookup."""

    return " ".join(text.replace("\t", " ").split()).lower()


def _display_key(row: tuple[str, str, str, object]) -> str:
    return row[0]


def _row_for(key: str) -> tuple[str, str, str, object] | None:
    display = _KEY_ALIASES.get(_normalise_key(key))
    if display is None:
        return None
    for row in _FORM_ROWS:
        if row[0] == display:
            return row
    return None


def _strip_bullet(line: str) -> tuple[str, bool]:
    """Return the line without a leading bullet and whether one was present."""

    stripped = line.strip()
    for prefix in _BULLET_PREFIXES:
        if stripped.startswith(prefix):
            return stripped[len(prefix) :].strip(), True
    return stripped, False


def _parse_bool(rest: str, line_number: int, line: str) -> bool | None:
    """Parse a two checkbox row into a boolean or None for no opinion.

    Raises:
        FormError: When the row does not contain exactly two checkboxes, when
            both are ticked, or when the marker is malformed.
    """

    boxes = _BOX_PATTERN.findall(rest)
    if len(boxes) < 2:
        raise FormError(
            line_number,
            f"expected two checkboxes, found {len(boxes)}",
            line,
        )
    if len(boxes) > 2:
        raise FormError(
            line_number,
            f"expected two checkboxes, found {len(boxes)}",
            line,
        )
    # Remove every well formed marker and inspect the remainder: a stray
    # bracket means the row was hand edited into something ambiguous.
    remainder = _BOX_PATTERN.sub("", rest)
    if "[" in remainder or "]" in remainder:
        raise FormError(line_number, "malformed checkbox syntax", line)
    checked = [index for index, marker in enumerate(boxes) if marker.strip().lower() == "x"]
    if len(checked) == 2:
        raise FormError(line_number, "both options are ticked; tick exactly one", line)
    if not checked:
        return None
    return checked[0] == 0


def _parse_ring(inner: str, line_number: int, line: str) -> int:
    """Parse the undo ring size field, which must carry a megabyte unit.

    Raises:
        FormError: When the value is not a number in the supported range.
    """

    match = _RING_PATTERN.match(inner.strip())
    if match is None:
        raise FormError(
            line_number,
            f"undo ring size {inner.strip()!r} is not a megabyte count",
            line,
        )
    megabytes = int(match.group(1))
    if not MIN_UNDO_RING_MB <= megabytes <= MAX_UNDO_RING_MB:
        raise FormError(
            line_number,
            f"undo ring size {megabytes}MB outside {MIN_UNDO_RING_MB}..{MAX_UNDO_RING_MB}MB",
            line,
        )
    return megabytes


def _parse_paths(inner: str) -> tuple[str, ...]:
    """Split the ignored paths field into normalised forward slash patterns.

    A value of None, an empty field or a single dash means no exclusions, which
    is what the template prints by default.
    """

    cleaned = inner.strip()
    if cleaned.lower() in {"", "none", "n/a", "-"}:
        return ()
    parts = [part.strip() for part in re.split(r"[,;\n]", cleaned)]
    return tuple(part.replace("\\", "/").strip("/") for part in parts if part)


def _parse_value(
    row: tuple[str, str, str, object],
    rest: str,
    line_number: int,
    line: str,
) -> object:
    """Parse an angle bracket value row.

    Raises:
        FormError: When the row is not a value row or the field is malformed.
    """

    field = row[2]
    match = _VALUE_PATTERN.match(rest.strip())
    if match is None:
        raise FormError(
            line_number,
            f"expected a value in angle brackets, found {rest.strip()!r}",
            line,
        )
    inner = match.group(1)
    if field == "undo_ring_mb":
        return _parse_ring(inner, line_number, line)
    if field == "ignored_paths":
        return _parse_paths(inner)
    if field == "auditor":
        return inner.strip()
    raise FormError(line_number, f"unknown value field {field!r}", line)


def parse_form(text: str) -> PolicyOverrides:
    """Parse a dossier sign-off form into policy overrides.

    Parameters:
        text: Whole Markdown or plain text dossier, or just its SEC 4 block.
            Bullet lines from other sections are ignored by key, so parsing a
            full document is safe.

    Returns:
        A PolicyOverrides holding only the fields the form expressed. A checkbox
        row with no tick means no opinion and yields None for that field, which
        lets a partially filled form preserve the current policy value.

    Raises:
        FormError: When a recognised key is present but malformed. The error
            carries the one based line number so a reviewer can find the typo.
        TypeError: When text is not a string.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")

    values: dict[str, object] = {}
    for line_number, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if not stripped:
            continue
        if stripped.startswith("#") or stripped.startswith("=") or stripped.startswith("|"):
            continue
        body, had_bullet = _strip_bullet(stripped)
        if ":" not in body:
            # Detect a form key that lost its colon instead of ignoring it: a
            # bullet whose normalised text starts with a known key is a broken
            # form row, while other bullets are ordinary dossier prose.
            normalised = _normalise_key(body)
            if any(normalised.startswith(alias) for alias in _KEY_ALIASES):
                raise FormError(line_number, "missing ':' after the form key", raw)
            continue
        key_text, _, rest = body.partition(":")
        row = _row_for(key_text)
        if row is None:
            # Non form bullet such as "Slot #01 : Location : ..." is expected.
            if had_bullet:
                continue
            normalised = _normalise_key(key_text)
            for alias in _KEY_ALIASES:
                if normalised.startswith(alias) or alias.startswith(normalised):
                    raise FormError(
                        line_number,
                        f"unknown form key {key_text.strip()!r}",
                        raw,
                    )
            continue
        kind = row[1]
        field = row[2]
        if kind == "bool":
            parsed = _parse_bool(rest, line_number, raw)
        else:
            parsed = _parse_value(row, rest, line_number, raw)
        if parsed is not None:
            values[field] = parsed
        else:
            # An explicitly unticked row is an explicit "no opinion": remove any
            # earlier value so a later duplicate row still parses cleanly.
            values.pop(field, None)
    return PolicyOverrides(**values)  # type: ignore[arg-type]


def _box(checked: bool) -> str:
    return "[x]" if checked else "[ ]"


def _bool_line(
    key: str,
    options: tuple[str, str],
    current: bool,
    note: str,
) -> str:
    """Render one checkbox row with the checked option matching the policy."""

    first = f"{_box(current)} {options[0]}"
    second = f"{_box(not current)} {options[1]}"
    return (
        "\u2022 "
        + key.ljust(KEY_WIDTH)
        + ": "
        + first.ljust(OPTION_WIDTH)
        + second
        + (f"    ({note})" if note else "")
    )


def _value_line(key: str, value: str, note: str) -> str:
    """Render one angle bracket value row."""

    return (
        "\u2022 "
        + key.ljust(KEY_WIDTH)
        + ": "
        + value.ljust(OPTION_WIDTH)
        + f"({note})"
    )


def render_form_lines(policy: Policy) -> list[str]:
    """Render the sign-off form for a policy as display lines.

    The keys, checkbox pairs and angle bracket values match what parse_form
    expects, so a generated dossier can be edited and applied without any
    intermediate format.

    Parameters:
        policy: Effective policy used to seed the current ticks.

    Returns:
        One line per form row, bullet prefixed.
    """

    lines: list[str] = []
    for row in _FORM_ROWS:
        key, kind, field, extra = row
        if kind == "bool":
            options = extra  # type: ignore[assignment]
            current = bool(getattr(policy, field))
            note = ""
            lines.append(_bool_line(key, options, current, note))
            continue
        note = str(extra)
        if field == "undo_ring_mb":
            value = f"< {policy.undo_ring_mb}MB >"
        elif field == "ignored_paths":
            if policy.ignored_paths:
                value = "< " + ", ".join(policy.ignored_paths) + " >"
            else:
                value = "< None >"
        elif field == "auditor":
            value = f"< {policy.auditor} >"
        else:
            raise ValueError(f"unhandled form value field {field!r}")
        lines.append(_value_line(key, value, note))
    return lines


def render_form_updates(report: "DossierReport") -> str:
    """Render the sign-off form block for a dossier report.

    Parameters:
        report: Dossier whose policy seeds the ticks.

    Returns:
        The form block as text with a trailing newline.
    """

    return "\n".join(render_form_lines(report.policy)) + "\n"
