from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .comparison import (
    compare_reports,
    compare_results_dir,
    render_compare_csv,
    render_compare_table,
    render_converted_report,
    semgrep_to_actiontaint_report,
)
from .evaluation import EvaluationHarness
from .pipeline import ActionTaintAnalyzer
from .reporter import Reporter


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="actiontaint", description="Analyze Next.js Server Actions for tainted flows.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan = subparsers.add_parser("scan", help="Scan a Next.js project.")
    scan.add_argument("target", nargs="?", default=".", help="Project directory to scan.")
    scan.add_argument("--backend", choices=["codeql"], default="codeql", help="Taint backend to use.")
    scan.add_argument(
        "--parser",
        choices=["auto", "typescript", "regex"],
        default="auto",
        help="Parser to use for framework reconstruction.",
    )
    scan.add_argument("--format", choices=["cli", "json", "sarif", "csv", "html"], default="cli", help="Report format.")
    scan.add_argument("--output", help="Write report to this path.")
    scan.add_argument("--model-dir", help="Directory for generated ActionTaint models and CodeQL query.")

    evaluate = subparsers.add_parser("eval", help="Run the synthetic benchmark harness.")
    evaluate.add_argument("benchmarks", nargs="?", default="benchmarks", help="Benchmark directory.")
    evaluate.add_argument("--tools", default="actiontaint,codeql,semgrep", help="Comma-separated tools to run.")
    evaluate.add_argument("--format", choices=["table", "json"], default="table", help="Evaluation output format.")
    evaluate.add_argument("--output", help="Write evaluation report to this path.")

    convert_semgrep = subparsers.add_parser("convert-semgrep", help="Normalize a Semgrep JSON report into ActionTaint-like output.")
    convert_semgrep.add_argument("semgrep_json", help="Path to Semgrep JSON output.")
    convert_semgrep.add_argument("--repo-name", help="Optional repository name for the normalized report.")
    convert_semgrep.add_argument("--format", choices=["json", "cli", "csv"], default="json", help="Output format.")
    convert_semgrep.add_argument("--output", help="Write normalized report to this path.")

    compare = subparsers.add_parser("compare", help="Compare ActionTaint, Semgrep, and optional CodeQL reports.")
    compare.add_argument("--actiontaint", help="Path to one ActionTaint JSON report.")
    compare.add_argument("--semgrep", help="Path to one Semgrep JSON report.")
    compare.add_argument("--codeql", help="Path to one CodeQL SARIF report.")
    compare.add_argument("--results-dir", help="Directory containing <repo>-actiontaint.json and <repo>-semgrep.json files.")
    compare.add_argument("--repos", help="Comma-separated repo names when using --results-dir.")
    compare.add_argument("--format", choices=["table", "json", "csv"], default="table", help="Comparison output format.")
    compare.add_argument("--output", help="Write comparison report to this path.")

    args = parser.parse_args(argv) 

    if args.command == "scan":
        target = Path(args.target)
        if not target.is_dir():
            print(f"actiontaint: error: target directory does not exist: {target}", file=sys.stderr)
            return 2
        model_dir = Path(args.model_dir) if args.model_dir else None
        result = ActionTaintAnalyzer().analyze(target, backend=args.backend, output_dir=model_dir, parser=args.parser)
        reporter = Reporter()
        output = Path(args.output) if args.output else None
        rendered = reporter.write_or_print(result, args.format, output)
        if output is None:
            print(rendered)
        if result.errors:
            # The taint analysis did not complete: never report this as a clean scan.
            for error in result.errors:
                print(f"actiontaint: error: {error}", file=sys.stderr)
            return 2
        return 1 if result.findings else 0

    if args.command == "eval":
        tools = [tool.strip().lower() for tool in args.tools.split(",") if tool.strip()]
        rows = EvaluationHarness().run(Path(args.benchmarks), tools=tools)
        rendered = EvaluationHarness().render_json(rows) if args.format == "json" else EvaluationHarness().render_table(rows)
        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered)
        return 0

    if args.command == "convert-semgrep":
        report = semgrep_to_actiontaint_report(Path(args.semgrep_json), repo_name=args.repo_name)
        rendered = render_converted_report(report, args.format)
        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered)
        return 0

    if args.command == "compare":
        if args.results_dir:
            repos = [repo.strip() for repo in args.repos.split(",") if repo.strip()] if args.repos else None
            rows = compare_results_dir(Path(args.results_dir), repos=repos)
        else:
            rows = [
                compare_reports(
                    actiontaint_path=Path(args.actiontaint) if args.actiontaint else None,
                    semgrep_path=Path(args.semgrep) if args.semgrep else None,
                    codeql_path=Path(args.codeql) if args.codeql else None,
                )
            ]
        if args.format == "json":
            rendered = json.dumps(rows, indent=2, sort_keys=True)
        elif args.format == "csv":
            rendered = render_compare_csv(rows)
        else:
            rendered = render_compare_table(rows)
        if args.output:
            output = Path(args.output)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered)
        return 0

    return 2
