"""Format independent INTEGRITY trailer for the human readable dossiers.

A Markdown or plain text dossier is evidence a reviewer reads and forwards, so it
carries a trailer that is independent of the format and of the canonical report
payload. The trailer is the final line of the file:

    INTEGRITY: sha256=<hex of every preceding byte> hmac=<hex hmac of those bytes>

The sha256 half can be checked by anybody, which catches an accidental edit even
when the reader does not hold the signing key. The hmac half ties those same bytes
to the resolved signing key (explicit, environment or machine derived), so a
deliberate rewrite is visible to a holder of the key. The JSON dossier keeps its
canonical hmac_sha256 field instead, because machine readers parse it as data.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Final

from tauhaulity.dossier.redactor import resolve_signing_key

# Scheme token reported by the verifier for a file carrying this trailer.
FILE_STAMP_SCHEME: Final[str] = "file-stamp"

# The trailer starts with this label so a reader can locate it by prefix alone.
INTEGRITY_LABEL: Final[str] = "INTEGRITY:"

_STAMP_LINE: Final[re.Pattern[str]] = re.compile(
    r"^INTEGRITY: sha256=(?P<sha256>[0-9a-f]{64}) hmac=(?P<hmac>[0-9a-f]{64})$"
)


class StampError(ValueError):
    """Raised when a dossier file has no usable INTEGRITY trailer.

    Attributes:
        reason: One line English explanation suitable for a verification report.
    """

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class FileStamp:
    """Parsed contents of one dossier file.

    Attributes:
        payload: Every byte preceding the trailer line.
        sha256_hex: Recorded sha256 digest of payload.
        hmac_hex: Recorded HMAC-SHA256 digest of payload.
    """

    payload: bytes
    sha256_hex: str
    hmac_hex: str


def normalise_body(text: str) -> str:
    """Return dossier text without a BOM and with exactly one trailing newline.

    Parameters:
        text: Rendered dossier body, with or without a trailing newline.

    Raises:
        TypeError: When text is not a string.
    """

    if not isinstance(text, str):
        raise TypeError("dossier text must be a string")
    return text.lstrip("\ufeff").rstrip("\r\n") + "\n"


def build_file_stamp(text: str, key: bytes) -> str:
    """Append the INTEGRITY trailer to a rendered dossier body.

    Parameters:
        text: Complete dossier body without a trailer.
        key: Signing key resolved by redactor.resolve_signing_key.

    Returns:
        The body with exactly one trailing newline followed by the final trailer
        line and one newline.

    Raises:
        ValueError: When the key is empty or not bytes-like.
        TypeError: When text is not a string.
    """

    if not isinstance(key, (bytes, bytearray)):
        raise TypeError("integrity stamp key must be bytes")
    if not key:
        raise ValueError("integrity stamp key must not be empty")
    body = normalise_body(text)
    payload = body.encode("utf-8")
    sha256_hex = hashlib.sha256(payload).hexdigest()
    mac = hmac.new(bytes(key), payload, hashlib.sha256).hexdigest()
    return body + f"INTEGRITY: sha256={sha256_hex} hmac={mac}\n"


def signing_key_for(report: object, explicit: bytes | None = None) -> bytes:
    """Return the key a report file stamp must use.

    The key stored on the report is preferred so a dossier signed with an
    explicit or environment key is stamped with that same key when it is later
    rendered. Hosts that pass a detached report fall back to normal resolution.

    Parameters:
        report: Report snapshot, possibly carrying a signing_key attribute.
        explicit: Optional key overriding both the report and the environment.

    Raises:
        ValueError: When an explicitly supplied key is empty.
        TypeError: When an explicitly supplied key is not bytes-like.
    """

    if explicit is not None:
        if not isinstance(explicit, (bytes, bytearray)):
            raise TypeError("signing key must be bytes")
        if not explicit:
            raise ValueError("signing key must not be empty")
        return bytes(explicit)
    stored = getattr(report, "signing_key", None)
    if isinstance(stored, (bytes, bytearray)) and stored:
        return bytes(stored)
    return resolve_signing_key()[0]


def stamp_report_text(text: str, report: object, explicit: bytes | None = None) -> str:
    """Stamp a rendered report body with the key that report was signed with."""

    return build_file_stamp(text, signing_key_for(report, explicit))


def split_file_stamp(raw: bytes) -> FileStamp:
    """Parse the INTEGRITY trailer of an already read dossier file.

    Parameters:
        raw: Complete file bytes.

    Returns:
        The parsed stamp, with payload holding every preceding byte.

    Raises:
        StampError: When the file is empty, binary, uses CRLF line endings, does
            not end with a newline, or its final line is not a valid trailer.
        TypeError: When raw is not bytes-like.
    """

    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError("dossier bytes are required")
    material = bytes(raw)
    if not material:
        raise StampError("dossier file is empty")
    if b"\x00" in material:
        raise StampError("dossier file contains NUL bytes and is not a text dossier")
    if not material.endswith(b"\n"):
        raise StampError(
            "file does not end with a newline; the INTEGRITY trailer must be the final line"
        )
    trimmed = material[:-1]
    if b"\r" in trimmed:
        raise StampError(
            "file uses CRLF or stray carriage returns; "
            "the INTEGRITY stamp is computed over LF bytes"
        )
    boundary = trimmed.rfind(b"\n")
    line_bytes = trimmed[boundary + 1 :]
    payload = trimmed[: boundary + 1]
    try:
        line = line_bytes.decode("ascii")
    except UnicodeDecodeError:
        raise StampError(
            "missing INTEGRITY trailer (the final line is not ASCII)"
        ) from None
    if not line.startswith(INTEGRITY_LABEL):
        raise StampError("missing INTEGRITY trailer (the final line is not a file stamp)")
    match = _STAMP_LINE.match(line)
    if match is None:
        raise StampError(
            "malformed INTEGRITY trailer: expected "
            "'INTEGRITY: sha256=<64 hex> hmac=<64 hex>'"
        )
    if not payload:
        raise StampError("file contains no dossier body before the INTEGRITY trailer")
    return FileStamp(
        payload=payload,
        sha256_hex=match.group("sha256"),
        hmac_hex=match.group("hmac"),
    )


__all__ = [
    "FILE_STAMP_SCHEME",
    "INTEGRITY_LABEL",
    "FileStamp",
    "StampError",
    "build_file_stamp",
    "normalise_body",
    "signing_key_for",
    "split_file_stamp",
    "stamp_report_text",
]
