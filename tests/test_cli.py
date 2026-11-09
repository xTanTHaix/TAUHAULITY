"""CLI tests: dispatch, exit codes and stable machine readable output."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tauhaulity.cli import EXIT_USAGE, build_parser, main


def test_parser_lists_every_command() -> None:
    parser = build_parser()
    actions = [action for action in parser._actions if action.dest == "command"]
    assert actions
    choices = set(actions[0].choices or {})
    assert {"audit", "undo", "rm", "free", "ports", "hook", "venv-check", "apply", "doctor", "diff"} <= choices


def test_version_exits_zero(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert "tauhaulity" in capsys.readouterr().out


def test_unknown_command_exits_with_argparse_code(capsys) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["definitely-not-a-command"])
    assert excinfo.value.code == 2


def test_invalid_export_formats_return_usage_error(tmp_path, capsys) -> None:
    assert main(["audit", str(tmp_path), "--export", ",,,"]) == EXIT_USAGE
    assert "no export formats" in capsys.readouterr().err


def test_missing_scan_target_reports_error(tmp_path, capsys) -> None:
    missing = tmp_path / "nope"
    assert main(["audit", str(missing)]) == EXIT_USAGE
    assert "does not exist" in capsys.readouterr().err


def test_audit_json_summary(tmp_path, capsys) -> None:
    pytest.importorskip("tauhaulity.dossier.report")
    code = main(["audit", str(tmp_path), "--export", "json", "--no-repro", "--json"])
    assert code in {0, 1, 2}
    payload = json.loads(capsys.readouterr().out)
    assert payload["verdict"] in {"SAFE", "AT_RISK", "CRITICAL"}
    assert len(payload["findings"]) == 12
    assert payload["reports"]["json"].endswith("tauhaulity_report.json")
    assert Path(payload["reports"]["json"]).is_file()


def test_doctor_json_output(tmp_path, capsys) -> None:
    code = main(["doctor", "--root", str(tmp_path), "--json"])
    assert code in {0, 1}
    payload = json.loads(capsys.readouterr().out)
    assert isinstance(payload["checks"], list) and payload["checks"]


def test_diff_reports_changes(tmp_path, capsys) -> None:
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps({"verdict": "SAFE", "pillars": [{"pillar": 1, "status": "SAFE"}]}), encoding="utf-8")
    new.write_text(json.dumps({"verdict": "AT_RISK", "pillars": [{"pillar": 1, "status": "WARNING"}]}), encoding="utf-8")
    assert main(["diff", str(old), str(new)]) in {0, 1}
    assert "SAFE" in capsys.readouterr().out


def test_diff_rejects_malformed_json(tmp_path, capsys) -> None:
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    new = tmp_path / "new.json"
    new.write_text("{}", encoding="utf-8")
    assert main(["diff", str(broken), str(new)]) == EXIT_USAGE
    assert "cannot read dossier" in capsys.readouterr().err
