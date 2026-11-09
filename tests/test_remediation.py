"""Tests for the hardening action catalogue."""

from __future__ import annotations

from pathlib import Path

from tauhaulity.core.contracts import SPEC_BY_NUMBER, ScanContext, ScanOptions, make_finding
from tauhaulity.core.platform_probe import detect_platform
from tauhaulity.core.policy import Policy
from tauhaulity.core.scorecard import compute_scorecard
from tauhaulity.remediation import PRIORITY_NOW, actions_for, render_actions, summarize


def _context(findings: list[tuple[int, str, str, float]]) -> ScanContext:
    ctx = ScanContext(target=Path("."), platform=detect_platform(), policy=Policy(), options=ScanOptions())
    for number, status, detail, risk in findings:
        spec = SPEC_BY_NUMBER[number]
        ctx.record(make_finding(spec, status, detail, risk=risk))
    return ctx


def test_clean_context_yields_no_actions() -> None:
    ctx = _context([(11, "SECURE", "hook gate installed; 0 credential candidate(s) redacted", 0.0)])
    assert actions_for(ctx) == ()
    assert "nothing to harden" in summarize(())


def test_gate_and_credential_actions() -> None:
    ctx = _context(
        [
            (11, "LEAK_DETECTED", "hook gate MISSING; 3 credential candidate(s) redacted", 9.0),
        ]
    )
    actions = actions_for(ctx)
    ids = [action.id for action in actions]
    assert "install-git-gate" in ids
    assert "rotate-exposed-credential" in ids
    rotate = next(action for action in actions if action.id == "rotate-exposed-credential")
    assert rotate.manual is True and rotate.priority == PRIORITY_NOW


def test_ordering_puts_priority_then_points_first() -> None:
    ctx = _context(
        [
            (11, "LEAK_DETECTED", "hook gate MISSING; 3 credential candidate(s)", 9.0),
            (1, "WARNING", "no baseline recorded", 2.0),
        ]
    )
    scorecard = compute_scorecard(ctx)
    actions = actions_for(ctx, scorecard)
    assert actions[0].priority == 1
    priorities = [action.priority for action in actions]
    assert priorities == sorted(priorities)


def test_every_action_is_complete() -> None:
    ctx = _context(
        [
            (1, "WARNING", "no baseline recorded", 2.0),
            (6, "CRITICAL", "evil.pkl: pickle_unsafe (GLOBAL, REDUCE)", 8.0),
            (8, "PROTECTED", "undo ring armed; 0 canary trap(s)", 1.0),
            (9, "WARNING", "listener on 0.0.0.0:8000", 3.0),
            (10, "TAMPERED", "record mismatch in site-packages", 6.0),
        ]
    )
    actions = actions_for(ctx, compute_scorecard(ctx))
    assert actions
    for action in actions:
        assert action.title and action.detail
        assert action.id.replace("-", "").isalnum()
        assert action.effort in {"minutes", "hour", "session"}
        if action.command:
            assert "tauhaulity" in action.command
        else:
            assert action.manual is True
    assert len({action.id for action in actions}) == len(actions)


def test_render_and_summarize() -> None:
    ctx = _context([(11, "LEAK_DETECTED", "hook gate MISSING; 3 credential candidate(s)", 9.0)])
    actions = actions_for(ctx)
    lines = render_actions(actions, width=60)
    assert lines and all(len(line) <= 80 for line in lines)
    text = summarize(actions)
    assert "action(s)" in text
