"""Tests for the framework mapping table."""

from __future__ import annotations

import re

from tauhaulity.core.contracts import PILLAR_SPECS
from tauhaulity.standards import (
    ATTACK,
    OWASP,
    PILLAR_STANDARDS,
    STATUS_STANDARDS,
    coverage,
    explain,
    format_refs,
    refs_for,
)

IDENTIFIER = re.compile(r"^(T\d{4}(\.\d{3})?|A\d{2}:\d{4}|\d+(\.\d+)?)$")


def test_all_twelve_pillars_are_registered() -> None:
    assert set(PILLAR_STANDARDS) == {spec.number for spec in PILLAR_SPECS}


def test_every_reference_is_complete_and_published_shaped() -> None:
    for refs in (*PILLAR_STANDARDS.values(), *STATUS_STANDARDS.values()):
        for ref in refs:
            assert ref.framework in {ATTACK, OWASP, "CIS Controls v8"}
            assert IDENTIFIER.match(ref.identifier), ref.identifier
            assert ref.title
            assert ref.url.startswith("https://")


def test_refs_for_is_deduplicated_and_stable() -> None:
    first = refs_for(11, "LEAK_DETECTED")
    second = refs_for(11, "LEAK_DETECTED")
    assert first == second
    keys = [(ref.framework, ref.identifier) for ref in first]
    assert len(keys) == len(set(keys))
    assert any(ref.identifier == "T1552.001" for ref in first)


def test_unknown_pillar_has_no_references() -> None:
    assert refs_for(99) == ()


def test_format_refs_is_short_and_ordered() -> None:
    text = format_refs(refs_for(6))
    assert text.startswith("T")
    assert len(text) < 80


def test_explain_names_a_limit_for_every_pillar() -> None:
    for spec in PILLAR_SPECS:
        sentence = explain(spec.number)
        assert sentence.endswith(".")
        assert len(sentence) > 60
        assert "not" in sentence or "does" in sentence


def test_coverage_returns_twelve_rows() -> None:
    rows = coverage()
    assert len(rows) == 12
    assert all(row.name and row.note for row in rows)
    assert coverage(gaps_only=True)
