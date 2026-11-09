"""Delta debugging minimizer for replay cases.

A flight recorder captures far more events than the trigger needs, so a repro
script built from the raw case is noisy. Classic ddmin removes chunks of events
while the failure still reproduces, then refines the granularity, which turns a
thousand event case into the three or four events that actually matter. The
predicate is injected instead of imported so a caller can reproduce with its own
engine, subprocess or dry run.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Callable

from tauhaulity.repro.recorder import ReplayCase


@dataclass(frozen=True, slots=True)
class MinimizedCase:
    """Result of minimizing a replay case.

    Attributes:
        case: The minimal case. It keeps the original case_id so a reviewer can
            trace it back to the full recording.
        removed: Number of events dropped from the original case.
        iterations: Number of predicate evaluations performed, used as a cost
            metric because each evaluation may replay an exploit.
    """

    case: ReplayCase
    removed: int
    iterations: int


def delta_minimize(
    case: ReplayCase,
    predicate: Callable[[ReplayCase], bool],
) -> MinimizedCase:
    """Reduce a replay case with the ddmin algorithm.

    Parameters:
        case: Full replay case whose failure should be reproduced.
        predicate: Callable that returns True when the failure reproduces for the
            candidate case. It must be side effect free and deterministic or the
            minimizer may return a non minimal (but still valid) subset.

    Returns:
        The minimal case together with the removed event count and the number of
        predicate evaluations. A case with a single event is returned unchanged.

    Raises:
        TypeError: When predicate is not callable.
        ValueError: When the case has no events: an empty case cannot cause a
            failure, so minimizing it would be meaningless.
    """

    if not callable(predicate):
        raise TypeError("predicate must be callable")
    original = tuple(case.events)
    if not original:
        raise ValueError("cannot minimize an empty replay case")

    current = list(original)
    iterations = 0
    granularity = 2

    while len(current) >= 2:
        chunk_size = max(1, math.ceil(len(current) / granularity))
        chunks = [current[index : index + chunk_size] for index in range(0, len(current), chunk_size)]
        reduced = False
        for index in range(len(chunks)):
            candidate_events = tuple(
                event
                for other_index, chunk in enumerate(chunks)
                if other_index != index
                for event in chunk
            )
            # An empty candidate cannot reproduce a failure, and the predicate
            # would almost certainly reject it; skipping it also guarantees the
            # minimized case keeps at least one event.
            if not candidate_events:
                continue
            iterations += 1
            candidate = ReplayCase(
                case_id=case.case_id,
                events=candidate_events,
                target=case.target,
            )
            if predicate(candidate):
                current = list(candidate_events)
                granularity = max(granularity - 1, 2)
                reduced = True
                break
        if reduced:
            continue
        if granularity >= len(current):
            break
        granularity = min(granularity * 2, len(current))

    minimized = ReplayCase(
        case_id=case.case_id,
        events=tuple(current),
        target=case.target,
    )
    return MinimizedCase(
        case=minimized,
        removed=len(original) - len(current),
        iterations=iterations,
    )


__all__ = ["MinimizedCase", "delta_minimize"]
