"""Pillar 7 - EGRESS-DLP: pre-TLS capture, DNS and ICMP entropy gates, secret patterns.

Data leaves a developer machine in three places that a file scanner cannot see:
the cleartext handed to TLS before encryption, DNS labels, and ICMP echo payloads.
This pillar implements one mechanism per path:

1. PreTlsHook wraps ssl.SSLSocket.send. The wrapper observes a bounded prefix of
   the cleartext into an SPSC ring (the same bounded structure the rest of the
   engine uses) and then always calls the original send: watch mode must never
   change network behaviour. Payloads are truncated to the ring slot size instead
   of raising, and a full ring drops with a counter rather than growing memory.

2. DnsGate evaluates entropy per label with the shared 256-LUT EntropyGate. A
   normal hostname has short low entropy labels; a DNS tunnel needs long random
   labels, so the gate rejects a label that is both long and dense. Per-label
   scoring matters because the total name entropy is diluted by the parent domain.

3. IcmpGate applies the same policy to echo payloads and rejects payload data on
   non-echo ICMP types, where an echo style payload is simply not protocol legal.

4. SecretPatternDetector finds cleartext credentials (GitHub PATs, AWS keys, PEM
   private key headers, bearer tokens, password assignments and base64 blobs) and
   always reports them masked, so a dossier can show a finding without copying the
   credential into a report that might itself be committed.

Everything is passive: no socket is opened, no packet is sent, and the ssl wrapper
is removed by uninstall().
"""

from __future__ import annotations

import functools
import re
import ssl
from dataclasses import dataclass
from typing import Any, Callable, Final, Iterable, Pattern

from tauhaulity.core.contracts import Finding, PillarSpec, ScanContext, SPEC_BY_KEY, make_finding
from tauhaulity.core.entropy import EntropyGate, looks_like_base64
from tauhaulity.core.spsc import ConsumerViolation, PayloadTooLarge, ProducerViolation, SpscRing

SPEC: PillarSpec = SPEC_BY_KEY["egress_dlp"]

DEFAULT_DNS_THRESHOLD: Final[float] = 4.2
DEFAULT_DNS_MIN_LABEL: Final[int] = 20
DEFAULT_DNS_MAX_LABEL: Final[int] = 63
DEFAULT_DNS_MAX_NAME: Final[int] = 253
DEFAULT_ICMP_THRESHOLD: Final[float] = 6.8
DEFAULT_ICMP_MIN_LENGTH: Final[int] = 32
DEFAULT_ICMP_MAX_PAYLOAD: Final[int] = 512
_REDACTED: Final[str] = "****REDACTED****"


@dataclass(frozen=True, slots=True)
class SecretHit:
    """One credential pattern found in a cleartext payload.

    Attributes:
        kind: Pattern identifier such as github-pat or pem-private-key.
        start: Byte offset of the match.
        masked: Masked preview that never contains the full credential.
        reason: Why the pattern is sensitive.
    """

    kind: str
    start: int
    masked: str
    reason: str


# (kind, compiled bytes pattern, reason). Patterns are anchored on the modern
# prefix forms so prose mentioning the word token does not trigger a hit.
_SECRET_PATTERNS: Final[tuple[tuple[str, Pattern[bytes], str], ...]] = (
    (
        "github-fine-grained-pat",
        re.compile(rb"github_pat_[A-Za-z0-9_]{20,}"),
        "GitHub fine-grained personal access token",
    ),
    (
        "github-classic-pat",
        re.compile(rb"gh[pousr]_[A-Za-z0-9]{20,}"),
        "GitHub classic personal access token",
    ),
    (
        "openai-key",
        re.compile(rb"sk-[A-Za-z0-9]{20,}"),
        "OpenAI style secret key",
    ),
    (
        "aws-access-key",
        re.compile(rb"AKIA[0-9A-Z]{16}"),
        "AWS access key id",
    ),
    (
        "pem-private-key",
        re.compile(rb"-----BEGIN (?:RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----"),
        "PEM encoded private key header",
    ),
    (
        "slack-token",
        re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,}"),
        "Slack API token",
    ),
    (
        "bearer-token",
        re.compile(rb"(?i)bearer\s+[A-Za-z0-9._~+/-]{20,}=*"),
        "HTTP bearer credential",
    ),
    (
        "password-assignment",
        re.compile(rb"(?i)(password|passwd|pwd|secret|token)\s*[=:]\s*['\"]?[A-Za-z0-9._~+/=-]{8,}"),
        "plaintext credential assignment",
    ),
    (
        "base64-blob",
        re.compile(rb"[A-Za-z0-9+/]{40,}={0,2}"),
        "high entropy base64 blob that may be encoded data",
    ),
)

_MAX_HITS: Final[int] = 32


def _mask(material: bytes) -> str:
    """Return a masked preview of a matched credential.

    Only a short prefix survives so an operator can identify the credential type
    without the dossier becoming a second copy of the secret.
    """

    try:
        text = material.decode("utf-8", "replace")
    except (UnicodeDecodeError, AttributeError):
        text = repr(material)
    prefix = text[:4] if len(text) > 8 else text[:1]
    return f"{prefix}{_REDACTED}"


class SecretPatternDetector:
    """Detect and redact cleartext credentials using compiled byte patterns."""

    def __init__(self, patterns: Iterable[tuple[str, Pattern[bytes], str]] | None = None) -> None:
        self.patterns = tuple(patterns) if patterns is not None else _SECRET_PATTERNS

    def detect(self, payload: bytes | bytearray | memoryview | str) -> list[SecretHit]:
        """Return every credential hit in payload order, capped at 32 entries.

        A base64 candidate has to pass the shared entropy heuristic as well, so a
        long identifier or a checksum is not reported as encoded exfiltration.
        """

        try:
            material = payload.encode("utf-8") if isinstance(payload, str) else bytes(payload)
        except (TypeError, ValueError):
            return []
        hits: list[SecretHit] = []
        for kind, pattern, reason in self.patterns:
            for match in pattern.finditer(material):
                matched = match.group(0)
                if kind == "base64-blob":
                    try:
                        candidate = matched.decode("ascii")
                    except UnicodeDecodeError:
                        continue
                    if not looks_like_base64(candidate, minimum=40):
                        continue
                hits.append(
                    SecretHit(
                        kind=kind,
                        start=int(match.start()),
                        masked=_mask(matched),
                        reason=reason,
                    )
                )
                if len(hits) >= _MAX_HITS:
                    return sorted(hits, key=lambda hit: hit.start)
        return sorted(hits, key=lambda hit: hit.start)

    def has_secrets(self, payload: bytes | bytearray | memoryview | str) -> bool:
        """True when at least one credential pattern matches."""

        return bool(self.detect(payload))

    def redact(self, payload: bytes | bytearray | memoryview) -> tuple[bytes, int]:
        """Replace every match with a mask and return (redacted bytes, hit count)."""

        try:
            material = bytes(payload)
        except (TypeError, ValueError):
            return b"", 0
        spans: list[tuple[int, int]] = []
        for _kind, pattern, _reason in self.patterns:
            for match in pattern.finditer(material):
                spans.append((match.start(), match.end()))
        if not spans:
            return material, 0
        spans.sort()
        merged: list[tuple[int, int]] = []
        for start, end in spans:
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        pieces: list[bytes] = []
        cursor = 0
        for start, end in merged:
            pieces.append(material[cursor:start])
            pieces.append(_REDACTED.encode("ascii"))
            cursor = end
        pieces.append(material[cursor:])
        return b"".join(pieces), len(merged)


@dataclass(frozen=True, slots=True)
class DnsVerdict:
    """Result of evaluating one outbound DNS name.

    Attributes:
        allowed: False when the name looks like a tunnel.
        label: The most suspicious label.
        entropy: Entropy of that label in bits per byte.
        length: Length of that label.
        reasons: Human readable rejection reasons.
        max_entropy: Highest label entropy observed in the name.
    """

    allowed: bool
    label: str
    entropy: float
    length: int
    reasons: tuple[str, ...]
    max_entropy: float


class DnsGate:
    """Per-label entropy gate for DNS exfiltration detection.

    Attributes:
        entropy_threshold: Bits per byte above which a long label is rejected.
        min_label_length: Labels shorter than this are always allowed.
    """

    def __init__(
        self,
        *,
        entropy_threshold: float = DEFAULT_DNS_THRESHOLD,
        min_label_length: int = DEFAULT_DNS_MIN_LABEL,
        max_label_length: int = DEFAULT_DNS_MAX_LABEL,
        max_name_length: int = DEFAULT_DNS_MAX_NAME,
    ) -> None:
        if not 0.0 <= entropy_threshold <= 8.0:
            raise ValueError("entropy_threshold must be within 0..8")
        if min_label_length < 0 or max_label_length < 1 or max_name_length < 1:
            raise ValueError("DNS gate lengths must be non-negative")
        self._entropy_gate = EntropyGate(threshold=entropy_threshold, min_length=min_label_length)
        self.entropy_threshold = float(entropy_threshold)
        self.min_label_length = int(min_label_length)
        self.max_label_length = int(max_label_length)
        self.max_name_length = int(max_name_length)

    def evaluate(self, name: str | bytes) -> DnsVerdict:
        """Score a DNS name label by label and decide whether it may leave.

        The trailing dot of a fully qualified name is ignored, and an empty label
        (a doubled dot) is rejected because it usually indicates hand crafted
        tunnel encoding rather than a resolvable name.
        """

        text = name.decode("ascii", "replace") if isinstance(name, bytes) else str(name)
        stripped = text.rstrip(".")
        reasons: list[str] = []
        if not stripped:
            return DnsVerdict(False, "", 0.0, 0, ("empty DNS name",), 0.0)
        if len(stripped) > self.max_name_length:
            reasons.append(f"name length {len(stripped)} exceeds {self.max_name_length}")
        labels = stripped.split(".")
        worst_label = ""
        worst_entropy = 0.0
        worst_length = 0
        worst_reason = ""
        for label in labels:
            if not label:
                reasons.append("empty label in DNS name")
                continue
            if len(label) > self.max_label_length:
                reasons.append(f"label of {len(label)} characters exceeds {self.max_label_length}")
            encoded = label.encode("utf-8", "replace")
            verdict = self._entropy_gate.evaluate(encoded)
            if verdict.entropy > worst_entropy:
                worst_entropy = verdict.entropy
                worst_label = label
                worst_length = len(label)
            if not verdict.allowed:
                worst_reason = verdict.reason
                reasons.append(f"label {label[:24]!r} rejected: {verdict.reason}")
        return DnsVerdict(
            not reasons,
            worst_label,
            worst_entropy,
            worst_length,
            tuple(dict.fromkeys(reasons)),
            worst_entropy,
        )

    def allows(self, name: str | bytes) -> bool:
        """True when the DNS name passes the gate."""

        return self.evaluate(name).allowed


@dataclass(frozen=True, slots=True)
class IcmpVerdict:
    """Result of evaluating one ICMP payload.

    Attributes:
        allowed: False when the payload violates the echo policy.
        icmp_type: ICMP type byte the payload was classified as.
        length: Payload length in bytes.
        entropy: Payload entropy in bits per byte.
        reasons: Human readable rejection reasons.
    """

    allowed: bool
    icmp_type: int
    length: int
    entropy: float
    reasons: tuple[str, ...]


class IcmpGate:
    """Payload policy for ICMP: echo may carry little, other types carry nothing.

    Attributes:
        max_payload: Largest echo payload considered legitimate.
        entropy_threshold: Entropy above which an echo payload is suspicious.
    """

    def __init__(
        self,
        *,
        max_payload: int = DEFAULT_ICMP_MAX_PAYLOAD,
        entropy_threshold: float = DEFAULT_ICMP_THRESHOLD,
        min_entropy_length: int = DEFAULT_ICMP_MIN_LENGTH,
    ) -> None:
        if max_payload < 0:
            raise ValueError("max_payload must not be negative")
        if not 0.0 <= entropy_threshold <= 8.0:
            raise ValueError("entropy_threshold must be within 0..8")
        self.max_payload = int(max_payload)
        self._entropy_gate = EntropyGate(threshold=entropy_threshold, min_length=min_entropy_length)
        self.entropy_threshold = float(entropy_threshold)

    def evaluate(self, payload: bytes | bytearray | memoryview, *, icmp_type: int = 8) -> IcmpVerdict:
        """Apply the echo payload policy and return the verdict."""

        try:
            material = bytes(payload)
        except (TypeError, ValueError):
            return IcmpVerdict(False, int(icmp_type), 0, 0.0, ("payload is not bytes-like",))
        reasons: list[str] = []
        if not 0 <= icmp_type <= 255:
            reasons.append(f"ICMP type {icmp_type} outside 0..255")
        echo = icmp_type in (0, 8)
        if not echo:
            if material:
                reasons.append(f"payload data on non-echo ICMP type {icmp_type} is not protocol legal")
            entropy = 0.0
        else:
            if len(material) > self.max_payload:
                reasons.append(f"echo payload of {len(material)} bytes exceeds {self.max_payload}")
            verdict = self._entropy_gate.evaluate(material)
            entropy = verdict.entropy
            if not verdict.allowed:
                reasons.append(f"echo payload rejected: {verdict.reason}")
        return IcmpVerdict(not reasons, int(icmp_type), len(material), entropy, tuple(reasons))

    def allows(self, payload: bytes, *, icmp_type: int = 8) -> bool:
        """True when the payload passes the ICMP policy."""

        return self.evaluate(payload, icmp_type=icmp_type).allowed


class PreTlsHook:
    """Observe cleartext handed to ssl.SSLSocket.send without blocking it.

    Attributes:
        capacity: Ring capacity in slots.
        slot_bytes: Maximum captured prefix per send call.
    """

    def __init__(
        self,
        *,
        capacity: int = 64,
        slot_bytes: int = 160,
        detector: SecretPatternDetector | None = None,
    ) -> None:
        self._ring = SpscRing(capacity=capacity, slot_bytes=slot_bytes)
        self.capacity = int(capacity)
        self.slot_bytes = int(slot_bytes)
        self._detector = detector if detector is not None else SecretPatternDetector()
        self._original: Any = None
        self._active = False
        self._observed = 0
        self._dropped = 0
        self._secret_hits = 0
        self._hit_log: list[SecretHit] = []

    @property
    def active(self) -> bool:
        """True while ssl.SSLSocket.send is wrapped."""

        return self._active

    def install(self) -> bool:
        """Replace ssl.SSLSocket.send with the observing wrapper.

        Returns:
            True when the wrapper is installed. The original method is stored so
            uninstall() restores the exact object that was there before.
        """

        if self._active:
            return True
        try:
            current = ssl.SSLSocket.send
        except (AttributeError, TypeError):
            return False
        original = getattr(current, "__tauhaulity_original__", current)
        hook = self

        def observing_send(self_socket, *args, **kwargs):
            # SSLSocket.send(self, data, flags=0) passes the cleartext as the
            # first positional argument; a keyword call is accepted as well so
            # the wrapper never alters the call signature it forwards.
            payload = args[0] if args else kwargs.get("data", b"")
            hook._observe(payload)
            return original(self_socket, *args, **kwargs)

        try:
            functools.update_wrapper(observing_send, original)
        except (AttributeError, TypeError, ValueError):
            pass
        observing_send.__tauhaulity_original__ = original
        try:
            ssl.SSLSocket.send = observing_send
        except (AttributeError, TypeError):
            return False
        self._original = original
        self._active = True
        return True

    def uninstall(self) -> bool:
        """Restore the original ssl.SSLSocket.send.

        Returns:
            True when the hook was active and has been removed.
        """

        if not self._active:
            return False
        try:
            current = ssl.SSLSocket.send
            original = getattr(current, "__tauhaulity_original__", self._original)
            if original is not None:
                ssl.SSLSocket.send = original
        except (AttributeError, TypeError):
            return False
        finally:
            self._active = False
            self._original = None
        return True

    def watch_callable(self, send: Callable[..., Any], *, payload_index: int = 0) -> Callable[..., Any]:
        """Wrap an arbitrary send-like callable with the same observation logic.

        This is the test seam: it exercises the capture path without opening a
        socket or performing a TLS handshake.
        """

        hook = self

        def instrumented(*args, **kwargs):
            payload = args[payload_index] if len(args) > payload_index else kwargs.get("data", b"")
            hook._observe(payload)
            return send(*args, **kwargs)

        return instrumented

    def _observe(self, payload: Any) -> None:
        """Capture a bounded prefix of one outbound payload into the ring."""

        try:
            material = bytes(payload)
        except (TypeError, ValueError):
            return
        if not material:
            return
        self._observed += 1
        hits = self._detector.detect(material)
        if hits:
            self._secret_hits += len(hits)
            for hit in hits[:4]:
                if len(self._hit_log) >= _MAX_HITS:
                    break
                self._hit_log.append(hit)
        try:
            accepted = self._ring.put(material[: self.slot_bytes])
        except (PayloadTooLarge, ProducerViolation, RuntimeError):
            self._dropped += 1
            return
        if not accepted:
            self._dropped += 1

    def drain(self, limit: int | None = None) -> list[bytes]:
        """Remove captured payload prefixes, oldest first."""

        try:
            return self._ring.drain(limit)
        except (ConsumerViolation, RuntimeError):
            return []

    def recent_hits(self, limit: int = 8) -> list[SecretHit]:
        """Return the most recent credential hits seen on the send path."""

        return list(self._hit_log[-max(0, limit) :])

    def stats(self) -> dict[str, Any]:
        """Return capture counters and ring statistics."""

        ring = self._ring.stats()
        return {
            "active": self._active,
            "capacity": self.capacity,
            "slot_bytes": self.slot_bytes,
            "observed": self._observed,
            "dropped": self._dropped,
            "secret_hits": self._secret_hits,
            "ring_produced": ring.produced,
            "ring_consumed": ring.consumed,
            "ring_dropped": ring.dropped,
            "ring_high_water": ring.high_water,
        }

    def close(self) -> None:
        """Uninstall the hook and release the ring."""

        self.uninstall()
        self._ring.close()


def _probe_self_tests() -> tuple[bool, dict[str, Any]]:
    """Run the fixed egress samples and return (healthy, measurements)."""

    measurements: dict[str, Any] = {}
    healthy = True

    hook = PreTlsHook(capacity=16, slot_bytes=128)
    try:
        sink: list[bytes] = []
        instrumented = hook.watch_callable(lambda data, flags=0: sink.append(data) or len(data))
        token = b"ghp_ProbeTokenValue0123456789ABCDEF"
        payload = b"GET /v1/me HTTP/1.1\r\nAuthorization: Bearer " + token + b"\r\n\r\n"
        instrumented(payload, 0)
        captured = hook.drain()
        measurements["pre_tls_captured"] = bool(captured)
        measurements["pre_tls_secrets"] = hook.stats()["secret_hits"]
        healthy = healthy and bool(captured) and hook.stats()["secret_hits"] >= 1
        hook_installs = hook.install()
        measurements["pre_tls_install"] = hook_installs
        if hook_installs:
            hook.uninstall()
    finally:
        hook.close()

    dns = DnsGate()
    normal = dns.evaluate("api.github.com")
    tunnel = dns.evaluate("dGhpcyBpcyBhIHR1bm5lbCBwYXlsb2Fk.example.com")
    measurements["dns_normal_allowed"] = normal.allowed
    measurements["dns_tunnel_allowed"] = tunnel.allowed
    healthy = healthy and normal.allowed and not tunnel.allowed

    icmp = IcmpGate()
    benign = icmp.evaluate(b"tauhaulity ping payload", icmp_type=8)
    # bytes(range(256)) is maximally dense (8.0 bits per byte) with a fixed,
    # reproducible payload, so the probe does not depend on random bytes to fail.
    tunnelish = icmp.evaluate(bytes(range(256)), icmp_type=8)
    measurements["icmp_benign_allowed"] = benign.allowed
    measurements["icmp_tunnel_allowed"] = tunnelish.allowed
    healthy = healthy and benign.allowed and not tunnelish.allowed

    detector = SecretPatternDetector()
    planted = detector.detect(b"key=AKIAABCDEFGHIJKLMNOP password=hunter2hunter2")
    clean = detector.detect(b"GET /health HTTP/1.1 Host: api.example.test")
    measurements["secret_hits"] = len(planted)
    measurements["secret_clean_false_positives"] = len(clean)
    healthy = healthy and bool(planted) and not clean
    return healthy, measurements


def probe(ctx: ScanContext) -> Finding:
    """Run the egress gates against fixed samples and report the DLP state.

    LEAK_DETECTED means a sample that must be blocked escaped the gate, which is
    the only condition that justifies the critical status: the mechanism, not the
    sample, is what the dossier is reporting.
    """

    try:
        healthy, measurements = _probe_self_tests()
    except (OSError, ValueError, TypeError, RuntimeError) as exc:
        detail = f"egress self-test raised {type(exc).__name__}: {exc}"
        return make_finding(
            SPEC,
            "WARNING",
            detail,
            risk=4.0,
            slots={"detail": detail},
            repro_hint="Feed a DNS tunnel name and a planted GitHub token through the gates.",
        )
    dns_blocked = not measurements["dns_tunnel_allowed"]
    icmp_blocked = not measurements["icmp_tunnel_allowed"]
    secrets_found = measurements["secret_hits"] > 0
    false_positive = measurements["secret_clean_false_positives"] > 0
    capture_ok = bool(measurements["pre_tls_captured"])
    install_ok = bool(measurements["pre_tls_install"])
    detail = (
        f"pre-tls capture={'yes' if capture_ok else 'no'}, ssl hook={'yes' if install_ok else 'no'}, "
        f"dns tunnel blocked={dns_blocked}, icmp tunnel blocked={icmp_blocked}, "
        f"secret patterns found={measurements['secret_hits']}, false positives={measurements['secret_clean_false_positives']}"
    )
    if not (dns_blocked and icmp_blocked and secrets_found and capture_ok):
        status = "LEAK_DETECTED"
        risk = 8.0
        detail = f"egress gate failed to block a known sample: {detail}"
    elif false_positive:
        status = "WARNING"
        risk = 3.0
        detail = f"egress gate produced a false positive on a clean sample: {detail}"
    elif not install_ok:
        status = "WARNING"
        risk = 2.5
        detail = f"pre-tls hook could not wrap ssl.SSLSocket.send: {detail}"
    else:
        status = "SAFE"
        risk = 0.0
    return make_finding(
        SPEC,
        status,
        detail,
        risk=risk,
        slots={"detail": detail},
        repro_hint="Capture one ssl send payload and run the DNS and ICMP tunnel samples through the gates.",
    )
