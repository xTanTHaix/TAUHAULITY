"""Runs the runtime detector corpus (marker: corpus)."""

from __future__ import annotations

import pytest

from tests.runtime_cases import RUNTIME_CASES
from tests.corpus_runner import run_case

pytestmark = pytest.mark.corpus


@pytest.mark.parametrize("case", RUNTIME_CASES, ids=[case.case_id for case in RUNTIME_CASES])
def test_runtime_case(case, tmp_path) -> None:
    outcome = run_case(case, tmp_path)
    detail = outcome.error or "; ".join(outcome.mismatches)
    assert outcome.passed, f"{case.case_id}: {detail}"
