from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, asdict
from pathlib import Path

from .backends.codeql import CodeQLBackend
from .pipeline import ActionTaintAnalyzer
from .reporter import Reporter

# Default CodeQL baseline: the standard JavaScript security-extended suite, pinned for reproducibility.
DEFAULT_CODEQL_SUITE = "codeql/javascript-queries@2.3.9:codeql-suites/javascript-security-extended.qls"

# Maps baseline rule identifiers / CWE numbers to ActionTaint vulnerability types, so baseline
# findings of the expected class are credited as true positives.
CODEQL_RULE_TYPES = {
    "js/sql-injection": "SQL Injection",
    "js/request-forgery": "SSRF",
    "js/client-side-request-forgery": "SSRF",
    "js/path-injection": "Path Traversal",
    "js/command-line-injection": "Command Injection",
    "js/shell-command-injection-from-environment": "Command Injection",
    "js/server-side-unvalidated-url-redirection": "Open Redirect",
}
CWE_TYPES = {
    "89": "SQL Injection",
    "918": "SSRF",
    "22": "Path Traversal",
    "78": "Command Injection",
    "601": "Open Redirect",
    "639": "Broken Authorization / IDOR",
}


@dataclass(slots=True)
class EvaluationRow:
    benchmark: str
    tool: str
    server_actions_found: int
    client_reachable_actions: int
    findings: int
    true_positives: int
    false_positives: int
    missed_findings_by_baseline: int
    runtime_seconds: float
    status: str


class EvaluationHarness:
    def run(self, benchmarks_dir: Path, tools: list[str] | None = None) -> list[EvaluationRow]:
        tools = tools or ["actiontaint", "codeql", "semgrep"]
        self.output_root = benchmarks_dir / ".actiontaint-eval"
        rows: list[EvaluationRow] = []
        benchmarks = sorted(path for path in benchmarks_dir.iterdir() if path.is_dir() and (path / "expected.json").exists())
        if not benchmarks:
            # A directory of suites (e.g. benchmarks/) runs every suite below it.
            suites = sorted(path for path in benchmarks_dir.iterdir() if path.is_dir() and not path.name.startswith("."))
            for suite in suites:
                rows.extend(self.run(suite, tools))
            return rows
        for benchmark in benchmarks:
            expected = self._read_expected(benchmark)
            if "actiontaint" in tools:
                rows.append(self._run_actiontaint(benchmark, expected))
            if "codeql" in tools:
                rows.append(self._run_codeql_baseline(benchmark, expected))
            if "semgrep" in tools:
                rows.append(self._run_semgrep_baseline(benchmark, expected))
        return rows

    def render_table(self, rows: list[EvaluationRow]) -> str:
        headers = [
            "benchmark",
            "tool",
            "actions",
            "reachable",
            "findings",
            "tp",
            "fp",
            "missed",
            "runtime",
            "status",
        ]
        data = [
            [
                row.benchmark,
                row.tool,
                str(row.server_actions_found),
                str(row.client_reachable_actions),
                str(row.findings),
                str(row.true_positives),
                str(row.false_positives),
                str(row.missed_findings_by_baseline),
                f"{row.runtime_seconds:.2f}s",
                row.status,
            ]
            for row in rows
        ]
        widths = [max(len(headers[i]), *(len(row[i]) for row in data)) if data else len(headers[i]) for i in range(len(headers))]
        lines = [" | ".join(headers[i].ljust(widths[i]) for i in range(len(headers)))]
        lines.append("-+-".join("-" * width for width in widths))
        for row in data:
            lines.append(" | ".join(row[i].ljust(widths[i]) for i in range(len(headers))))
        return "\n".join(lines)

    def render_json(self, rows: list[EvaluationRow]) -> str:
        return json.dumps([asdict(row) for row in rows], indent=2, sort_keys=True)

    def _run_actiontaint(self, benchmark: Path, expected: dict) -> EvaluationRow:
        start = time.perf_counter()
        output_dir = self.output_root / benchmark.name
        result = ActionTaintAnalyzer().analyze(benchmark, backend="codeql", output_dir=output_dir)
        elapsed = time.perf_counter() - start
        (output_dir / "actiontaint.json").write_text(Reporter().render(result, "json"), encoding="utf-8")
        tp, fp = self._score_findings([(f.vulnerability_type, f.source_function) for f in result.findings], expected)
        status = "ok" if not result.errors else "failed: " + "; ".join(result.errors)
        return EvaluationRow(
            benchmark=benchmark.name,
            tool="ActionTaint",
            server_actions_found=len(result.actions),
            client_reachable_actions=len(result.reachable_actions),
            findings=len(result.findings),
            true_positives=tp,
            false_positives=fp,
            missed_findings_by_baseline=max(0, len(expected.get("expected_findings", [])) - tp),
            runtime_seconds=elapsed,
            status=status,
        )

    def _run_codeql_baseline(self, benchmark: Path, expected: dict) -> EvaluationRow:
        codeql = CodeQLBackend().executable()
        if codeql is None:
            return self._skipped(benchmark.name, "Default CodeQL", expected, "codeql not installed")
        start = time.perf_counter()
        out_dir = self.output_root / benchmark.name
        out_dir.mkdir(parents=True, exist_ok=True)
        output = out_dir / "default-codeql.sarif"
        db = out_dir / "default-codeql-db"
        create = self._run(
            [codeql, "database", "create", str(db), "--language=javascript-typescript", f"--source-root={benchmark}", "--overwrite"]
        )
        if create.returncode != 0:
            return self._skipped(benchmark.name, "Default CodeQL", expected, "codeql database create failed")
        analyze = self._run(
            [codeql, "database", "analyze", str(db), DEFAULT_CODEQL_SUITE, "--download", "--format=sarif-latest", f"--output={output}"]
        )
        elapsed = time.perf_counter() - start
        if analyze.returncode != 0 or not output.exists():
            return self._skipped(benchmark.name, "Default CodeQL", expected, "codeql analyze failed")
        found = [(CODEQL_RULE_TYPES.get(rule, rule), None) for rule in self._sarif_rule_ids(output)]
        tp, fp = self._score_findings(found, expected)
        return EvaluationRow(
            benchmark=benchmark.name,
            tool="Default CodeQL",
            server_actions_found=0,
            client_reachable_actions=0,
            findings=len(found),
            true_positives=tp,
            false_positives=fp,
            missed_findings_by_baseline=max(0, len(expected.get("expected_findings", [])) - tp),
            runtime_seconds=elapsed,
            status="ok",
        )

    def _run_semgrep_baseline(self, benchmark: Path, expected: dict) -> EvaluationRow:
        if shutil.which("semgrep") is None:
            return self._skipped(benchmark.name, "Default Semgrep", expected, "semgrep not installed")
        start = time.perf_counter()
        proc = self._run(["semgrep", "--config=p/default", "--json", "--metrics=off", str(benchmark)])
        elapsed = time.perf_counter() - start
        if proc.returncode not in {0, 1}:
            return self._skipped(benchmark.name, "Default Semgrep", expected, "semgrep failed")
        try:
            results = json.loads(proc.stdout or "{}").get("results", [])
        except json.JSONDecodeError:
            return self._skipped(benchmark.name, "Default Semgrep", expected, "semgrep returned invalid JSON")
        found = [(self._semgrep_type(result), None) for result in results]
        tp, fp = self._score_findings(found, expected)
        return EvaluationRow(
            benchmark=benchmark.name,
            tool="Default Semgrep",
            server_actions_found=0,
            client_reachable_actions=0,
            findings=len(found),
            true_positives=tp,
            false_positives=fp,
            missed_findings_by_baseline=max(0, len(expected.get("expected_findings", [])) - tp),
            runtime_seconds=elapsed,
            status="ok",
        )

    def _run(self, cmd: list[str]) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env.setdefault("CODEQL_ALLOW_INSTALLATION_ANYWHERE", "true")
        return subprocess.run(
            cmd, env=env, text=True, encoding="utf-8", errors="replace", capture_output=True, check=False
        )

    def _semgrep_type(self, result: dict) -> str:
        for cwe in result.get("extra", {}).get("metadata", {}).get("cwe", []) or []:
            match = re.search(r"CWE-(\d+)", str(cwe))
            if match and match.group(1) in CWE_TYPES:
                return CWE_TYPES[match.group(1)]
        return str(result.get("check_id", "semgrep"))

    def _skipped(self, benchmark: str, tool: str, expected: dict, reason: str) -> EvaluationRow:
        return EvaluationRow(
            benchmark=benchmark,
            tool=tool,
            server_actions_found=0,
            client_reachable_actions=0,
            findings=0,
            true_positives=0,
            false_positives=0,
            missed_findings_by_baseline=len(expected.get("expected_findings", [])),
            runtime_seconds=0.0,
            status=f"skipped: {reason}",
        )

    def _read_expected(self, benchmark: Path) -> dict:
        path = benchmark / "expected.json"
        if not path.exists():
            return {"expected_findings": []}
        return json.loads(path.read_text(encoding="utf-8"))

    def _score_findings(self, findings: list[tuple[str, str | None]], expected: dict) -> tuple[int, int]:
        """Scores (vulnerability_type, source_function) pairs. A None function (baselines) matches on type only."""
        expected_items = expected.get("expected_findings", [])
        matched = set()
        false_positives = 0
        for vulnerability_type, source_function in findings:
            match_index = None
            for index, item in enumerate(expected_items):
                if index in matched:
                    continue
                type_ok = vulnerability_type == item.get("type")
                function_ok = source_function is None or item.get("source_function", "") in source_function
                if type_ok and function_ok:
                    match_index = index
                    break
            if match_index is None:
                false_positives += 1
            else:
                matched.add(match_index)
        return len(matched), false_positives

    def _sarif_rule_ids(self, path: Path) -> list[str]:
        data = json.loads(path.read_text(encoding="utf-8"))
        return [result.get("ruleId", "") for run in data.get("runs", []) for result in run.get("results", [])]
