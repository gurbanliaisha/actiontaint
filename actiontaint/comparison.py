from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def semgrep_to_actiontaint_report(path: Path, repo_name: str | None = None) -> dict[str, Any]:
    data = load_json(path)
    findings = [semgrep_result_to_finding(result) for result in data.get("results", [])]
    scanned = data.get("paths", {}).get("scanned", [])
    errors = data.get("errors", [])
    return {
        "tool": "Semgrep",
        "source_report": str(path),
        "project": {
            "root": repo_name or _common_root(scanned) or "<unknown>",
            "source_file_count": len(scanned),
            "is_next_project": None,
            "next_version": None,
            "has_app_router": None,
            "has_pages_router": None,
        },
        "backend_used": "semgrep",
        "parser_used": data.get("engine_requested", "semgrep"),
        "counts": {
            "server_actions": None,
            "client_reachable_actions": None,
            "findings": len(findings),
        },
        "findings": findings,
        "warnings": [error.get("message", str(error)) for error in errors],
    }


def semgrep_result_to_finding(result: dict[str, Any]) -> dict[str, Any]:
    extra = result.get("extra", {})
    metadata = extra.get("metadata", {})
    message = extra.get("message", "")
    vulnerability_type = _semgrep_vulnerability_type(result, metadata, message)
    severity = _semgrep_severity(extra.get("severity"))
    path = result.get("path", "<unknown>")
    line = result.get("start", {}).get("line", 0)
    snippet = extra.get("lines") or message
    return {
        "severity": severity,
        "vulnerability_type": vulnerability_type,
        "source_function": "<semgrep-rule>",
        "source_parameter": "<not-modeled>",
        "sink_file": path,
        "sink_line": line,
        "sink_snippet": snippet,
        "taint_path": [message] if message else [],
        "explanation": message or f"Semgrep rule {result.get('check_id', '<unknown>')} matched.",
        "rule_id": result.get("check_id", "<unknown>"),
        "semgrep": {
            "confidence": metadata.get("confidence"),
            "cwe": metadata.get("cwe", []),
            "owasp": metadata.get("owasp", []),
            "category": metadata.get("category"),
            "technology": metadata.get("technology", []),
        },
    }


def compare_reports(
    actiontaint_path: Path | None = None,
    semgrep_path: Path | None = None,
    codeql_path: Path | None = None,
    repo_name: str | None = None,
) -> dict[str, Any]:
    actiontaint = load_json(actiontaint_path) if actiontaint_path and actiontaint_path.exists() else None
    semgrep = semgrep_to_actiontaint_report(semgrep_path, repo_name=repo_name) if semgrep_path and semgrep_path.exists() else None
    codeql = load_json(codeql_path) if codeql_path and codeql_path.exists() else None
    codeql_count = _codeql_count(codeql) if codeql else None

    return {
        "repo": repo_name or _repo_name(actiontaint_path, semgrep_path, codeql_path),
        "actiontaint": {
            "source_files": _nested(actiontaint, "project", "source_file_count"),
            "server_actions": _nested(actiontaint, "counts", "server_actions"),
            "client_reachable_actions": _nested(actiontaint, "counts", "client_reachable_actions"),
            "findings": _nested(actiontaint, "counts", "findings"),
            "parser": actiontaint.get("parser_used") if actiontaint else None,
            "warnings": actiontaint.get("warnings", []) if actiontaint else [],
        },
        "semgrep": {
            "findings": len(semgrep.get("findings", [])) if semgrep else None,
            "warnings": semgrep.get("warnings", []) if semgrep else [],
        },
        "codeql": {
            "findings": codeql_count,
        },
        "interpretation": _interpret(actiontaint, semgrep, codeql_count),
    }


def compare_results_dir(results_dir: Path, repos: list[str] | None = None) -> list[dict[str, Any]]:
    if repos is None:
        repos = sorted(
            path.name.removesuffix("-actiontaint.json")
            for path in results_dir.glob("*-actiontaint.json")
        )
    rows = []
    for repo in repos:
        rows.append(
            compare_reports(
                actiontaint_path=results_dir / f"{repo}-actiontaint.json",
                semgrep_path=results_dir / f"{repo}-semgrep.json",
                codeql_path=results_dir / f"{repo}-codeql.sarif",
                repo_name=repo,
            )
        )
    return rows


def render_compare_table(rows: list[dict[str, Any]]) -> str:
    headers = [
        "repo",
        "files",
        "actions",
        "reachable",
        "actiontaint",
        "semgrep",
        "codeql",
        "parser",
        "note",
    ]
    data = []
    for row in rows:
        at = row["actiontaint"]
        data.append(
            [
                str(row["repo"]),
                _cell(at["source_files"]),
                _cell(at["server_actions"]),
                _cell(at["client_reachable_actions"]),
                _cell(at["findings"]),
                _cell(row["semgrep"]["findings"]),
                _cell(row["codeql"]["findings"]),
                _cell(at["parser"]),
                row["interpretation"],
            ]
        )
    widths = [max(len(headers[i]), *(len(row[i]) for row in data)) if data else len(headers[i]) for i in range(len(headers))]
    lines = [" | ".join(headers[i].ljust(widths[i]) for i in range(len(headers)))]
    lines.append("-+-".join("-" * width for width in widths))
    for row in data:
        lines.append(" | ".join(row[i].ljust(widths[i]) for i in range(len(headers))))
    return "\n".join(lines)


def render_compare_csv(rows: list[dict[str, Any]]) -> str:
    stream = io.StringIO()
    fieldnames = [
        "repo",
        "source_files",
        "server_actions",
        "client_reachable_actions",
        "actiontaint_findings",
        "semgrep_findings",
        "codeql_findings",
        "parser",
        "interpretation",
    ]
    writer = csv.DictWriter(stream, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        at = row["actiontaint"]
        writer.writerow(
            {
                "repo": row["repo"],
                "source_files": at["source_files"],
                "server_actions": at["server_actions"],
                "client_reachable_actions": at["client_reachable_actions"],
                "actiontaint_findings": at["findings"],
                "semgrep_findings": row["semgrep"]["findings"],
                "codeql_findings": row["codeql"]["findings"],
                "parser": at["parser"],
                "interpretation": row["interpretation"],
            }
        )
    return stream.getvalue()


def render_converted_report(report: dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(report, indent=2, sort_keys=True)
    if fmt == "cli":
        lines = [
            "Semgrep normalized report",
            f"Source: {report['source_report']}",
            f"Findings: {report['counts']['findings']}",
            "",
        ]
        for finding in report["findings"]:
            lines.extend(
                [
                    f"[{finding['severity']}] {finding['vulnerability_type']}",
                    f"Rule: {finding['rule_id']}",
                    f"Location: {finding['sink_file']}:{finding['sink_line']}",
                    f"Snippet: {finding['sink_snippet']}",
                    f"Explanation: {finding['explanation']}",
                    "",
                ]
            )
        return "\n".join(lines).rstrip()
    if fmt == "csv":
        stream = io.StringIO()
        fieldnames = [
            "severity",
            "vulnerability_type",
            "rule_id",
            "sink_file",
            "sink_line",
            "sink_snippet",
            "explanation",
        ]
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for finding in report["findings"]:
            writer.writerow({key: finding.get(key) for key in fieldnames})
        return stream.getvalue()
    raise ValueError(f"Unsupported format: {fmt}")


def _semgrep_severity(value: str | None) -> str:
    mapping = {
        "ERROR": "HIGH",
        "WARNING": "MEDIUM",
        "INFO": "LOW",
    }
    return mapping.get((value or "").upper(), value or "UNKNOWN")


def _semgrep_vulnerability_type(result: dict[str, Any], metadata: dict[str, Any], message: str) -> str:
    classes = metadata.get("vulnerability_class")
    if isinstance(classes, list) and classes:
        return str(classes[0])
    cwe = metadata.get("cwe")
    if isinstance(cwe, list) and cwe:
        return str(cwe[0])
    if message:
        return message
    check_id = result.get("check_id", "Semgrep Finding")
    return str(check_id).split(".")[-1].replace("-", " ").title()


def _common_root(paths: list[str]) -> str | None:
    if not paths:
        return None
    try:
        return str(Path(paths[0]).parent)
    except Exception:
        return None


def _repo_name(*paths: Path | None) -> str:
    for path in paths:
        if path:
            name = path.name
            for suffix in ("-actiontaint.json", "-semgrep.json", "-codeql.sarif"):
                if name.endswith(suffix):
                    return name.removesuffix(suffix)
    return "<unknown>"


def _nested(data: dict[str, Any] | None, *keys: str) -> Any:
    current: Any = data
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _codeql_count(data: dict[str, Any] | None) -> int | None:
    if not data:
        return None
    return sum(len(run.get("results", [])) for run in data.get("runs", []))


def _interpret(actiontaint: dict[str, Any] | None, semgrep: dict[str, Any] | None, codeql_count: int | None) -> str:
    at_count = _nested(actiontaint, "counts", "findings") or 0
    sg_count = len(semgrep.get("findings", [])) if semgrep else 0
    ql_count = codeql_count or 0
    if at_count and not sg_count and not ql_count:
        return "ActionTaint-only findings; manually inspect as strongest evidence."
    if at_count and sg_count:
        return "Both found issues, likely different vulnerability classes."
    if not at_count and sg_count:
        return "Semgrep found non-Server-Action issues or generic patterns."
    if not at_count and not sg_count and ql_count:
        return "Only CodeQL found issues."
    if not at_count and not sg_count and not ql_count:
        return "No tool findings."
    return "Mixed results; inspect finding details."


def _cell(value: Any) -> str:
    return "-" if value is None else str(value)
