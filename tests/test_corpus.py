"""Runs the red-team corpus as a pytest module (marker: corpus).

The default suite excludes it because one hundred real scans take about a minute;
run it explicitly with:  python -m pytest tests/test_corpus.py -m corpus
"""

from __future__ import annotations

import pytest

from tests.corpus_cases import CASES
from tests.corpus_runner import run_case

pytestmark = pytest.mark.corpus


@pytest.mark.parametrize("case", CASES, ids=[case.case_id for case in CASES])
def test_corpus_case(case, tmp_path) -> None:
    outcome = run_case(case, tmp_path)
    detail = outcome.error or "; ".join(outcome.mismatches)
    assert outcome.passed, f"{case.case_id}: {detail} (verdict {outcome.verdict})"
