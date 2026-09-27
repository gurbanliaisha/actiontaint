from __future__ import annotations

import json
from pathlib import Path

from actiontaint import cli
from actiontaint.backends.codeql import CodeQLBackend
from actiontaint.evaluation import EvaluationHarness
from actiontaint.models import AnalysisResult, Finding, ProjectInfo
from actiontaint.reporter import Reporter
from conftest import BENCHMARKS


def test_missing_target_exits_with_error(tmp_path, capsys):
    missing = tmp_path / "does-not-exist"
    assert cli.main(["scan", str(missing)]) == 2
    assert "does not exist" in capsys.readouterr().err
    assert not missing.exists()


def test_missing_codeql_is_an_error_not_a_clean_scan(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(CodeQLBackend, "executable", lambda self: None)
    target = BENCHMARKS / "synthetic" / "inline_sql"
    code = cli.main(["scan", str(target), "--model-dir", str(tmp_path / "model")])
    captured = capsys.readouterr()
    assert code == 2
    assert "CodeQL CLI was not found" in captured.err
    assert "No findings." not in captured.out


def _result(findings):
    project = ProjectInfo(Path.cwd(), True, "15.0.0", True, False, [])
    return AnalysisResult(project, [], [], [], [], findings, "codeql")


def _finding(kind, rule, severity="HIGH"):
    return Finding(
        severity=severity,
        vulnerability_type=kind,
        source_function="app/actions.ts::save",
        source_parameter="formData",
        sink_file="app/actions.ts",
        sink_line=7,
        sink_snippet="await db.query(sql);",
        taint_path=['app/actions.ts:5 formData.get("q")', "app/actions.ts:7 sql"],
        explanation="test",
        rule_id=rule,
    )


def test_sarif_has_one_rule_per_vulnerability_type():
    result = _result(
        [_finding("SQL Injection", "actiontaint/sql-injection"), _finding("Command Injection", "actiontaint/command-injection", "CRITICAL")]
    )
    sarif = json.loads(Reporter().render(result, "sarif"))
    rules = {rule["id"]: rule["name"] for rule in sarif["runs"][0]["tool"]["driver"]["rules"]}
    assert rules == {"actiontaint/sql-injection": "SQL Injection", "actiontaint/command-injection": "Command Injection"}
    step = sarif["runs"][0]["results"][0]["codeFlows"][0]["threadFlows"][0]["locations"][0]["location"]
    assert step["physicalLocation"] == {"artifactLocation": {"uri": "app/actions.ts"}, "region": {"startLine": 5}}


def test_json_report_has_no_absolute_paths():
    rendered = Reporter().render(_result([_finding("SQL Injection", "actiontaint/sql-injection")]), "json")
    assert str(Path.home()) not in rendered
    assert json.loads(rendered)["project"]["root"] == "."


def test_baseline_findings_of_expected_type_are_true_positives():
    expected = {"expected_findings": [{"type": "SSRF", "source_function": "refreshPreview"}]}
    harness = EvaluationHarness()
    assert harness._score_findings([("SSRF", None), ("js/xss", None)], expected) == (1, 1)
    assert harness._score_findings([("SSRF", "app/actions.ts::other")], expected) == (0, 1)
