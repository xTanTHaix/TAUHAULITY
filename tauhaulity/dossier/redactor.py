"""Secret redaction, signing key resolution and dossier integrity stamping.

Two jobs live together because they share one threat model. Redaction removes
credential material from evidence that leaves the process, and the HMAC makes
casual edits to a finished dossier visible.

A signing key comes from one of three places, in order of precedence: an explicit
byte string supplied by the caller, the TAUHAULITY_SIGNING_KEY environment value
(64 hex characters or a path to a key file), or the derived machine key. The
machine key is built from host and user identifiers, which makes it
tamper-evident rather than secret: anybody who can read the dossier can recompute
the key, so the stamp proves that a report was produced by this machine and later
altered, not that it came from a trusted third party. Calling it a secret would be
a lie, which is why every dossier records which source produced its key.
"""

from __future__ import annotations

import base64
import getpass
import hashlib
import hmac
import os
import platform
import re
import uuid
from pathlib import Path
from typing import Final

# Ordered from most specific to least specific so a PEM block is removed before
# the generic SSH header rule can leave its body behind.
_PEM_BLOCK: Final[re.Pattern[str]] = re.compile(
    r"-----BEGIN (?:[A-Z0-9 ]* )?PRIVATE KEY-----.*?-----END (?:[A-Z0-9 ]* )?PRIVATE KEY-----",
    re.DOTALL,
)
_PEM_HEADER: Final[re.Pattern[str]] = re.compile(
    r"-----BEGIN (?:OPENSSH|RSA|EC|DSA|PGP) PRIVATE KEY-----"
)
_GITHUB_FINE_GRAINED: Final[re.Pattern[str]] = re.compile(r"github_pat_[A-Za-z0-9_]{18,}")
_GITHUB_CLASSIC: Final[re.Pattern[str]] = re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}")
_OPENAI_STYLE: Final[re.Pattern[str]] = re.compile(r"sk-[A-Za-z0-9_\-]{16,}")
_AWS_ACCESS_KEY: Final[re.Pattern[str]] = re.compile(r"AKIA[0-9A-Z]{16}")
_BEARER_TOKEN: Final[re.Pattern[str]] = re.compile(
    r"(?i)bearer[ \t]+([A-Za-z0-9\-._~+/]{16,}=*)"
)
_URL_USERINFO: Final[re.Pattern[str]] = re.compile(
    r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*://)(?P<user>[^/\s:@]+):(?P<secret>[^/\s@]+)@"
)

# The literal every masked credential collapses to. Keeping a short family
# prefix (ghp_, sk-, AKIA) helps a reviewer identify the credential type while
# guaranteeing that not one byte of the secret survives the redaction.
MASK: Final[str] = "****REDACTED****"

_KNOWN_PREFIXES: Final[tuple[str, ...]] = (
    "github_pat_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "sk-",
    "AKIA",
    "Bearer ",
)

_MACHINE_KEY_SALT: Final[bytes] = b"tauhaulity-machine-key-v1"
_MACHINE_ID_PATHS: Final[tuple[str, ...]] = (
    "/etc/machine-id",
    "/var/lib/dbus/machine-id",
    "/proc/sys/kernel/random/boot_id",
)

# Environment variable that lets CI and release engineering sign dossiers with a
# real secret instead of the reproducible machine key.
SIGNING_KEY_ENV: Final[str] = "TAUHAULITY_SIGNING_KEY"

_HEX_KEY_LENGTH: Final[int] = 64
_HEX_DIGITS: Final[frozenset[str]] = frozenset("0123456789abcdefABCDEF")
_BASE64_TEXT: Final[re.Pattern[str]] = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def mask_secret(secret: str) -> str:
    """Return a masked form of a credential that keeps only its family prefix.

    Parameters:
        secret: Raw credential material. Any value is accepted, including one
            that is already masked, which keeps repeated redaction idempotent.

    Returns:
        The family prefix (when recognised) followed by the fixed mask marker.
        Unknown secrets are masked completely, because even a few leading
        characters are a useful crib for an attacker.
    """

    if not isinstance(secret, str):
        raise TypeError("secret must be a string")
    if not secret:
        return ""
    for prefix in _KNOWN_PREFIXES:
        if secret.startswith(prefix):
            return prefix + MASK
    return MASK


def redact_text(text: str) -> tuple[str, int]:
    """Replace every recognised credential in a text blob.

    Parameters:
        text: Arbitrary text, typically a finding detail or a dossier excerpt.

    Returns:
        A tuple of the redacted text and the number of replacements performed.
        The count is the number of matched credential spans, not the number of
        changed characters, so a dossier can report how many secrets were
        neutralised.

    Raises:
        TypeError: When text is not a string.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    if not text:
        return "", 0
    total = 0

    def _substitute(pattern: re.Pattern[str], replacement, material: str) -> str:
        nonlocal total
        result, count = pattern.subn(replacement, material)
        total += count
        return result

    redacted = _substitute(
        _PEM_BLOCK,
        "-----BEGIN PRIVATE KEY-----" + MASK + "-----END PRIVATE KEY-----",
        text,
    )
    redacted = _substitute(
        _PEM_HEADER,
        lambda match: match.group(0) + MASK,
        redacted,
    )
    redacted = _substitute(
        _URL_USERINFO,
        lambda match: match.group("scheme") + match.group("user") + ":" + MASK + "@",
        redacted,
    )
    redacted = _substitute(
        _GITHUB_FINE_GRAINED,
        lambda match: mask_secret(match.group(0)),
        redacted,
    )
    redacted = _substitute(
        _GITHUB_CLASSIC,
        lambda match: mask_secret(match.group(0)),
        redacted,
    )
    redacted = _substitute(
        _OPENAI_STYLE,
        lambda match: mask_secret(match.group(0)),
        redacted,
    )
    redacted = _substitute(
        _AWS_ACCESS_KEY,
        lambda match: mask_secret(match.group(0)),
        redacted,
    )
    redacted = _substitute(
        _BEARER_TOKEN,
        lambda match: "Bearer " + MASK,
        redacted,
    )
    return redacted, total


def _read_first_line(path: str) -> str:
    """Read the first line of a machine identifier file, or an empty string.

    Every OS read is wrapped because the dossier must render inside containers
    where /etc/machine-id is absent or unreadable.
    """

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.readline().strip()
    except OSError:
        return ""


def _machine_components() -> list[str]:
    """Collect stable host and user identifiers without ever raising."""

    parts: list[str] = []
    for reader in (platform.node,):
        try:
            value = reader()
        except (OSError, RuntimeError):
            value = ""
        if value:
            parts.append(str(value))
    try:
        user = getpass.getuser()
    except (OSError, KeyError, RuntimeError):
        user = ""
    if user:
        parts.append(user)
    for name in ("COMPUTERNAME", "USERDOMAIN", "USERNAME"):
        value = os.environ.get(name, "").strip()
        if value:
            parts.append(value)
    for path in _MACHINE_ID_PATHS:
        machine_id = _read_first_line(path)
        if machine_id:
            parts.append(machine_id)
            break
    try:
        node = uuid.getnode()
    except (OSError, RuntimeError):
        node = 0
    parts.append(f"{node:012x}")
    return parts


def machine_key() -> bytes:
    """Derive the dossier signing key from this host and user account.

    The key is intentionally reproducible: it is a tamper-evident tie to the
    machine and the account that generated a dossier, not a cryptographic
    secret. Anybody able to read a dossier on the same host can recompute it, so
    it detects accidental or casual edits, not a determined forger. This is
    documented in the dossier itself so a reader cannot mistake it for a
    certificate.

    Returns:
        A 32 byte SHA-256 digest of the machine components.
    """

    material = "\x1f".join(_machine_components()).encode("utf-8", errors="replace")
    return hashlib.sha256(_MACHINE_KEY_SALT + b"\x1f" + material).digest()


def _is_hex_key(text: str) -> bool:
    """Return True when text is exactly one 64 character hexadecimal key."""

    return len(text) == _HEX_KEY_LENGTH and all(char in _HEX_DIGITS for char in text)


def _decode_key_material(raw: bytes, origin: str) -> bytes:
    """Decode key material from a file holding hex, base64 or raw key bytes.

    Parameters:
        raw: Complete file contents.
        origin: Human readable description used in error messages; the key
            material itself is never echoed.

    Returns:
        The key bytes. Hex text is decoded first, then base64 text, and any other
        content is returned verbatim so a binary key file works unchanged.

    Raises:
        ValueError: When the file is empty.
    """

    if not raw:
        raise ValueError(f"{origin} is empty; expected key material")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return raw
    compact = text.strip()
    if _is_hex_key(compact):
        return bytes.fromhex(compact)
    candidate = "".join(text.split())
    # A base64 key is recognised by its alphabet and padding only; anything that
    # fails the strict decoder falls through to the raw bytes instead of being
    # silently mangled.
    if (
        len(candidate) >= 16
        and len(candidate) % 4 == 0
        and _BASE64_TEXT.match(candidate) is not None
    ):
        try:
            decoded = base64.b64decode(candidate, validate=True)
        except ValueError:
            decoded = b""
        if decoded:
            return decoded
    return raw


def _env_signing_key(value: str) -> bytes:
    """Resolve the value of SIGNING_KEY_ENV into key bytes.

    Parameters:
        value: Stripped environment value: 64 hex characters or a file path.

    Returns:
        The decoded key bytes.

    Raises:
        ValueError: When the value is neither a hex key nor a readable key file,
            or when the file holds no key material. Messages never include the
            secret value itself.
    """

    if _is_hex_key(value):
        return bytes.fromhex(value)
    candidate = Path(value)
    try:
        is_file = candidate.is_file()
    except OSError:
        is_file = False
    if not is_file:
        raise ValueError(
            f"{SIGNING_KEY_ENV} must be 64 hex characters or a path to an existing "
            f"key file; the value has {len(value)} character(s) and no such file exists"
        )
    try:
        material = candidate.read_bytes()
    except OSError as exc:
        raise ValueError(f"{SIGNING_KEY_ENV} key file is not readable: {candidate}") from exc
    return _decode_key_material(material, f"{SIGNING_KEY_ENV} key file {candidate}")


def resolve_signing_key(explicit: bytes | None = None) -> tuple[bytes, str]:
    """Resolve the key used to sign and verify a dossier.

    Precedence is deliberate and documented in the dossier itself: an explicit
    caller supplied key wins, then the TAUHAULITY_SIGNING_KEY environment value,
    and only then the derived machine key. The machine key is reproducible on the
    host, so it is a tamper-evident tie rather than a secret; the returned source
    string lets a reader of the dossier tell the two cases apart.

    Parameters:
        explicit: Optional key supplied by the caller. When given it always wins.

    Returns:
        A tuple of the key bytes and one of the source tokens 'explicit', 'env'
        or 'machine'.

    Raises:
        TypeError: When explicit is not bytes-like.
        ValueError: When explicit is empty, or when SIGNING_KEY_ENV is set to a
            value that is neither 64 hex characters nor a readable key file.
    """

    if explicit is not None:
        if not isinstance(explicit, (bytes, bytearray)):
            raise TypeError("explicit signing key must be bytes")
        if not explicit:
            raise ValueError("explicit signing key must not be empty")
        return bytes(explicit), "explicit"
    raw = os.environ.get(SIGNING_KEY_ENV, "")
    stripped = raw.strip()
    if stripped:
        return _env_signing_key(stripped), "env"
    return machine_key(), "machine"


def hmac_sha256_hex(text: str, key: bytes | None = None) -> str:
    """Return the HMAC-SHA256 hex digest of a text payload.

    Parameters:
        text: Payload to authenticate, always UTF-8 encoded.
        key: Optional explicit key. When omitted the machine key is used.

    Raises:
        TypeError: When text is not a string or the key is not bytes-like.
    """

    if not isinstance(text, str):
        raise TypeError("text must be a string")
    material = machine_key() if key is None else key
    if not isinstance(material, (bytes, bytearray)):
        raise TypeError("key must be bytes")
    digest = hmac.new(bytes(material), text.encode("utf-8"), hashlib.sha256)
    return digest.hexdigest()


def verify_hmac(text: str, signature: str, key: bytes | None = None) -> bool:
    """Constant-time verification of a dossier signature.

    Parameters:
        text: Payload that was signed.
        signature: Hex digest to compare against.
        key: Optional explicit key, defaults to the machine key.

    Returns:
        True only when the signature matches. Malformed signatures and wrong
        payload types return False instead of raising, because a verification
        helper must never crash a report reader.
    """

    if not isinstance(text, str) or not isinstance(signature, str):
        return False
    if not signature:
        return False
    try:
        expected = hmac_sha256_hex(text, key)
    except (TypeError, ValueError, OSError):
        return False
    try:
        return hmac.compare_digest(expected, signature.strip().lower())
    except TypeError:
        return False
