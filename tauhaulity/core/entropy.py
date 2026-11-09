"""Shannon entropy primitives backed by a 256 entry logarithm lookup table.

The mathematics is trivial (H = log2(n) - sum(c * log2(c)) / n) but calling
math.log2 per byte dominates the cost inside a network or file write path. A
precomputed table over the only 256 possible byte counts removes the logarithm
from the hot loop and keeps the gate affordable for 4 KiB sliding windows.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from typing import Sequence

# The table is indexed by an observed byte count, not by a byte value: a 4 KiB
# block can contain the same symbol 4096 times, so a 256 entry table would raise
# IndexError on any real log line. The limit covers the default block size and
# the fallback keeps arbitrarily large inputs correct.
_LUT_LIMIT = 4096
LOG2_LUT: tuple[float, ...] = (0.0,) + tuple(math.log2(value) for value in range(1, _LUT_LIMIT + 1))


def _log2_count(count: int) -> float:
    """Return log2 of an observed count, using the table when possible.

    The fallback is deliberate: memory profiling payloads can exceed the table
    limit, and correctness of the entropy estimate matters more than avoiding a
    single math.log2 call for those rare large counts.
    """

    if count < len(LOG2_LUT):
        return LOG2_LUT[count]
    return math.log2(count)

DEFAULT_HIGH_ENTROPY = 7.2
DEFAULT_MIN_LENGTH = 16


def shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of a byte string in bits per byte.

    Parameters:
        data: Raw bytes to measure.

    Returns:
        Entropy in the range zero to eight. An empty input yields zero.
    """

    if not data:
        return 0.0
    total = len(data)
    # Counter over a bytes object counts through the C helper, which is roughly
    # twenty times faster than a Python per-byte loop on multi megabyte buffers.
    accumulator = 0.0
    for count in Counter(data).values():
        accumulator += count * _log2_count(count)
    value = math.log2(total) - accumulator / total
    return 0.0 if value < 0.0 else value


def block_entropies(data: bytes, block_size: int = 4096) -> list[float]:
    """Return per block entropy for a buffer.

    Parameters:
        data: Buffer to segment.
        block_size: Window size in bytes, must be positive.

    Raises:
        ValueError: When block_size is not positive.
    """

    if block_size <= 0:
        raise ValueError("block_size must be positive")
    return [shannon_entropy(data[offset : offset + block_size]) for offset in range(0, len(data), block_size)]


def is_high_entropy(data: bytes, threshold: float = DEFAULT_HIGH_ENTROPY) -> bool:
    """Return True when the payload is denser than the threshold allows."""

    return shannon_entropy(data) >= threshold


def looks_like_base64(text: str, minimum: int = 32) -> bool:
    """Heuristically detect a base64 blob without decoding it.

    The check is intentionally conservative: it requires a plausible alphabet, a
    length that is a multiple of four and enough high entropy to rule out prose.
    """

    payload = text.strip()
    if len(payload) < minimum or len(payload) % 4 != 0:
        return False
    alphabet = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if any(char not in alphabet for char in payload):
        return False
    return is_high_entropy(payload.encode("ascii"), threshold=4.8)


@dataclass(frozen=True, slots=True)
class EntropyVerdict:
    """Result of evaluating one payload against the covert channel gate."""

    allowed: bool
    entropy: float
    length: int
    reason: str


class EntropyGate:
    """Sliding window entropy gate for outbound DNS, ICMP and file payloads.

    Attributes:
        threshold: Entropy in bits per byte above which a payload is suspicious.
        min_length: Payloads shorter than this are always allowed because their
            entropy estimate is statistically meaningless.
    """

    def __init__(self, threshold: float = DEFAULT_HIGH_ENTROPY, min_length: int = DEFAULT_MIN_LENGTH) -> None:
        if not 0.0 <= threshold <= 8.0:
            raise ValueError("threshold must be within 0..8 bits per byte")
        if min_length < 0:
            raise ValueError("min_length must not be negative")
        self.threshold = float(threshold)
        self.min_length = int(min_length)

    def evaluate(self, payload: bytes) -> EntropyVerdict:
        """Score a payload and decide whether it may pass the gate.

        Parameters:
            payload: Cleartext candidate about to leave the process.

        Returns:
            EntropyVerdict carrying the decision and the measured entropy.
        """

        if not payload:
            return EntropyVerdict(True, 0.0, 0, "empty payload")
        if len(payload) < self.min_length:
            return EntropyVerdict(True, shannon_entropy(payload), len(payload), "below minimum length")
        value = shannon_entropy(payload)
        if value >= self.threshold:
            return EntropyVerdict(False, value, len(payload), f"entropy {value:.3f} above {self.threshold:.3f}")
        return EntropyVerdict(True, value, len(payload), "within entropy budget")

    def scan_blocks(self, payload: bytes, block_size: int = 4096) -> list[EntropyVerdict]:
        """Evaluate every block of a large buffer and return the verdicts."""

        return [self.evaluate(payload[offset : offset + block_size]) for offset in range(0, len(payload), block_size)]


def entropy_of_sequence(values: Sequence[int]) -> float:
    """Return entropy for an arbitrary byte value sequence.

    Protocols such as DNS labels arrive as tuples of integers; measuring them
    directly avoids an intermediate bytes copy.

    Raises:
        ValueError: When a value falls outside the byte range.
    """

    material = bytes(values)
    return shannon_entropy(material)
