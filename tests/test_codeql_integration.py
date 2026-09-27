"""End-to-end tests that run the real CodeQL CLI. Skipped unless CodeQL is available (slow: ~1-2 min per project)."""

from __future__ import annotations

import json

import pytest

from actiontaint.backends.codeql import CodeQLBackend
from actiontaint.pipeline import ActionTaintAnalyzer
from conftest import FIXTURES

pytestmark = pytest.mark.skipif(not CodeQLBackend().available(), reason="CodeQL CLI not available")


def test_regression_app_findings_exactly(tmp_path):
    app = FIXTURES / "regression_app"
    expected = json.loads((app / "expected.json").read_text(encoding="utf-8"))
    result = ActionTaintAnalyzer().analyze(app, output_dir=tmp_path / "model")
    assert result.errors == []
    found = sorted((f.vulnerability_type, f.source_function.split("::")[-1]) for f in result.findings)
    wanted = sorted((item["type"], item["source_function"]) for item in expected["expected_findings"])
    assert found == wanted
    reported_functions = {f.source_function.split("::")[-1] for f in result.findings}
    assert not reported_functions & set(expected["must_not_report"])
