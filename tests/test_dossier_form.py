"""Tests for the dossier sign-off form parser and renderer round-trip."""

from __future__ import annotations

from pathlib import Path

import pytest

from tauhaulity.core.contracts import PILLAR_SPECS, ScanContext, ScanOptions, make_finding
from tauhaulity.core.platform_probe import detect_platform
from tauhaulity.core.policy import Policy, PolicyOverrides
from tauhaulity.dossier.form_parser import FormError, parse_form, render_form_lines
from tauhaulity.dossier.report import build_report, render_markdown, render_text

# A Latin auditor name written with real combining marks: Z plus U+0308 COMBINING
# DIAERESIS, A plus U+030A COMBINING RING ABOVE and o plus U+0308 in the surname.
# It exercises non-ASCII form values without relying on any non-Latin script.
AUDITOR_WITH_MARKS = "Zoe\u0308 A\u030angstro\u0308m"


def _context(root: Path, policy: Policy) -> ScanContext:
    root.mkdir(parents=True, exist_ok=True)
    ctx = ScanContext(
        target=root,
        platform=detect_platform(),
        policy=policy,
        options=ScanOptions(),
    )
    for spec in PILLAR_SPECS:
        ctx.record(make_finding(spec, spec.statuses[0], f"evidence {spec.number}"))
    return ctx


def test_default_form_round_trip_yields_policy_defaults() -> None:
    form = "\n".join(render_form_lines(Policy())) + "\n"
    overrides = parse_form(form)
    assert overrides == PolicyOverrides(
        enforce_active=False,
        auto_hotpatch=False,
        block_git_secrets=True,
        undo_ring_mb=512,
        auto_zombie_free=False,
        ignored_paths=(),
        auditor="Unspecified",
    )


FORM_TEXT = """
\u2022 Protection Mode    : [x] Enforce Active Shield    [ ] Audit-Only (Monitor)
\u2022 Auto Hot-Patching  : [x] Enable Safe GOT/DR Patch [ ] Disable Live Patching
\u2022 Git Pre-Commit Hook: [ ] Block Strict PAT/SSH Leak[ ] Warning Only
\u2022 Dev Snap Undo Ring : < 1024MB >                    (Undo buffer size for deleted files)
\u2022 Auto Zombie Free   : [x] Terminate Hung Ports     [ ] Keep Alive
\u2022 Ignored Paths      : < build, node_modules >      (Directories excluded from inspection)
\u2022 Auditor Name/Notes : < Ada Lovelace >             (Auditor sign-off string)
"""


def test_parse_ticks_and_values() -> None:
    overrides = parse_form(FORM_TEXT)
    assert overrides.enforce_active is True
    assert overrides.auto_hotpatch is True
    # Neither box is ticked on the git row: the form expressed no opinion.
    assert overrides.block_git_secrets is None
    assert overrides.undo_ring_mb == 1024
    assert overrides.auto_zombie_free is True
    assert overrides.ignored_paths == ("build", "node_modules")
    assert overrides.auditor == "Ada Lovelace"


def test_parse_ignores_non_form_bullets() -> None:
    document = (
        "# DOSSIER\n"
        "- Target Name / Path        : /tmp/project\n"
        "| 1 | AEGIS-VMI | SAFE | 0.0 |\n"
        "\u2022 Slot #01 : Location : somewhere\n"
        "\u2022 Protection Mode    : [ ] Enforce Active Shield    [x] Audit-Only (Monitor)\n"
    )
    overrides = parse_form(document)
    assert overrides.enforce_active is False
    assert overrides.auditor is None
    assert overrides.undo_ring_mb is None


MALFORMED_CASES = [
    ("\u2022 Protection Mode    : Enforce Active Shield", "two checkboxes"),
    ("\u2022 Protection Mode    : [x] Enforce Active Shield [x] Audit-Only (Monitor)", "both options"),
    ("\u2022 Protection Mode    : [x] Enforce Active Shield", "two checkboxes"),
    ("\u2022 Protection Mode    : [x Enforce Active Shield [ ] Audit-Only", "two checkboxes"),
    ("\u2022 Dev Snap Undo Ring : < 8MB >", "outside"),
    ("\u2022 Dev Snap Undo Ring : < lots >", "not a megabyte"),
    ("\u2022 Auditor Name/Notes : Ada Lovelace", "angle brackets"),
    ("\u2022 Ignored Paths      : None", "angle brackets"),
]


@pytest.mark.parametrize("line,needle", MALFORMED_CASES)
def test_malformed_form_lines_raise_with_line_number(line: str, needle: str) -> None:
    document = "# HEAD\n\n" + line + "\n"
    with pytest.raises(FormError) as caught:
        parse_form(document)
    assert caught.value.line_number == 3
    assert needle in str(caught.value).lower()


def test_missing_colon_is_not_silently_ignored() -> None:
    document = "\u2022 Protection Mode [x] Enforce Active Shield [ ] Audit-Only\n"
    with pytest.raises(FormError) as caught:
        parse_form(document)
    assert caught.value.line_number == 1
    assert "missing" in str(caught.value)


def test_duplicate_rows_apply_last_value() -> None:
    document = (
        "\u2022 Auto Zombie Free  : [x] Terminate Hung Ports     [ ] Keep Alive\n"
        "\u2022 Auto Zombie Free  : [ ] Terminate Hung Ports     [x] Keep Alive\n"
    )
    overrides = parse_form(document)
    assert overrides.auto_zombie_free is False


def test_markdown_report_round_trips_through_policy(tmp_path: Path) -> None:
    policy = Policy(
        enforce_active=True,
        auto_hotpatch=True,
        block_git_secrets=False,
        undo_ring_mb=256,
        auto_zombie_free=True,
        ignored_paths=("build", "node_modules"),
        auditor="Ada Lovelace",
    )
    report = build_report(_context(tmp_path / "project", policy))
    overrides = parse_form(render_markdown(report))
    merged = policy.with_overrides(overrides)
    assert merged == policy


def test_text_report_round_trips_through_policy(tmp_path: Path) -> None:
    policy = Policy(enforce_active=False, undo_ring_mb=4096, auditor="Grace Hopper")
    report = build_report(_context(tmp_path / "project", policy))
    overrides = parse_form(render_text(report))
    merged = policy.with_overrides(overrides)
    assert merged == policy
    assert merged.undo_ring_mb == 4096
    assert merged.auditor == "Grace Hopper"


def test_auditor_name_with_combining_marks_round_trips(tmp_path: Path) -> None:
    policy = Policy(auditor=AUDITOR_WITH_MARKS)
    report = build_report(_context(tmp_path / "project", policy))
    for rendered in (render_markdown(report), render_text(report)):
        assert AUDITOR_WITH_MARKS in rendered
        merged = policy.with_overrides(parse_form(rendered))
        assert merged.auditor == AUDITOR_WITH_MARKS


def test_parse_form_rejects_non_text() -> None:
    with pytest.raises(TypeError):
        parse_form(b"not text")  # type: ignore[arg-type]
