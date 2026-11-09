"""Runs the usage corpus as a pytest module (marker: corpus).

The default suite excludes it because one hundred real command invocations take
a couple of minutes. Run it with:  python -m pytest tests/test_usage.py -m corpus
"""

from __future__ import annotations

import pytest

from tests.usage_cases import USAGE_CASES
from tests.usage_runner import run_usage_case

pytestmark = pytest.mark.corpus


@pytest.mark.parametrize("case", USAGE_CASES, ids=[case.case_id for case in USAGE_CASES])
def test_usage_case(case, tmp_path) -> None:
    outcome = run_usage_case(case, tmp_path)
    detail = outcome.error or "; ".join(outcome.mismatches)
    assert outcome.passed, f"{case.case_id}: {detail} (exit {outcome.exit_code})"
