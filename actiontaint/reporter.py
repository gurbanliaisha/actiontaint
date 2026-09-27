from __future__ import annotations

import csv
import html
import io
import json
import os
import re
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any

from .models import AnalysisResult, Finding


FLOW_STEP_RE = re.compile(r"(?P<uri>[^\s:][^:]*):(?P<line>\d+)\s?(?P<message>.*)$", re.DOTALL)


class Reporter:
    def render(self, result: AnalysisResult, fmt: str) -> str:
        fmt = fmt.lower()
        if fmt in {"cli", "text", "table"}:
            return self._render_cli(result)
        if fmt == "json":
            return json.dumps(self._result_dict(result), indent=2, sort_keys=True)
        if fmt == "sarif":
            return json.dumps(self._render_sarif(result), indent=2, sort_keys=True)
        if fmt == "csv":
            return self._render_csv(result.findings)
        if fmt == "html":
            return self._render_html(result)
        raise ValueError(f"Unsupported format: {fmt}")

    def write_or_print(self, result: AnalysisResult, fmt: str, output: Path | None) -> str:
        rendered = self.render(result, fmt)
        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8")
        return rendered

    def _render_cli(self, result: AnalysisResult) -> str:
        lines = [
            "ActionTaint analysis",
            f"Target: {result.project.root}",
            f"Next.js: {result.project.next_version or 'unknown'} | app router: {result.project.has_app_router} | pages router: {result.project.has_pages_router}",
            f"Parser: {result.parser_used}",
            f"Backend: {result.backend_used}",
            f"Server Actions: {len(result.actions)} | Client-reachable: {len(result.reachable_actions)} | Findings: {len(result.findings)}",
        ]
        if result.warnings:
            lines.append("Warnings:")
            for warning in result.warnings:
                lines.append(f"  - {warning}")
        if result.errors:
            lines.append("Errors (analysis incomplete):")
            for error in result.errors:
                lines.append(f"  - {error}")
        lines.append("")
        if result.errors:
            lines.append("Taint analysis did not complete; findings are not available.")
            return "\n".join(lines)
        if not result.findings:
            lines.append("No findings.")
            return "\n".join(lines)
        for finding in result.findings:
            lines.extend(
                [
                    f"[{finding.severity}] {finding.vulnerability_type}",
                    f"Source: {finding.source_function}({finding.source_parameter})",
                    f"Sink: {finding.sink_file}:{finding.sink_line} {finding.sink_snippet}",
                    f"Path: {' -> '.join(finding.taint_path)}",
                    f"Explanation: {finding.explanation}",
                    "",
                ]
            )
        return "\n".join(lines).rstrip()

    def _render_csv(self, findings: list[Finding]) -> str:
        stream = io.StringIO()
        fieldnames = [
            "severity",
            "vulnerability_type",
            "source_function",
            "source_parameter",
            "sink_file",
            "sink_line",
            "sink_snippet",
            "taint_path",
            "explanation",
            "rule_id",
        ]
        writer = csv.DictWriter(stream, fieldnames=fieldnames)
        writer.writeheader()
        for finding in findings:
            row = asdict(finding)
            row["taint_path"] = " -> ".join(finding.taint_path)
            writer.writerow(row)
        return stream.getvalue()

    def _render_sarif(self, result: AnalysisResult) -> dict[str, Any]:
        rules: dict[str, dict[str, Any]] = {}
        results = []
        for finding in result.findings:
            rules.setdefault(
                finding.rule_id,
                {
                    "id": finding.rule_id,
                    "name": finding.vulnerability_type,
                    "shortDescription": {"text": finding.vulnerability_type},
                    "fullDescription": {
                        "text": f"Client-controlled Next.js Server Action input reaches a {finding.vulnerability_type} sink."
                    },
                    "defaultConfiguration": {"level": self._sarif_level(finding.severity)},
                },
            )
            results.append(
                {
                    "ruleId": finding.rule_id,
                    "level": self._sarif_level(finding.severity),
                    "message": {"text": f"{finding.vulnerability_type}: {finding.explanation}"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": finding.sink_file},
                                "region": {"startLine": max(1, finding.sink_line)},
                            }
                        }
                    ],
                    "codeFlows": [
                        {"threadFlows": [{"locations": [self._sarif_flow_location(step) for step in finding.taint_path]}]}
                    ],
                }
            )
        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "ActionTaint", "rules": list(rules.values())}},
                    "results": results,
                }
            ],
        }

    def _sarif_flow_location(self, step: str) -> dict[str, Any]:
        match = FLOW_STEP_RE.match(step)
        if not match:
            return {"location": {"message": {"text": step}}}
        return {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": match.group("uri")},
                    "region": {"startLine": max(1, int(match.group("line")))},
                },
                "message": {"text": match.group("message") or step},
            }
        }

    def _render_html(self, result: AnalysisResult) -> str:
        findings_html = []
        for finding in result.findings:
            findings_html.append(
                f"""
                <article class="finding">
                  <h2><span>{html.escape(finding.severity)}</span> {html.escape(finding.vulnerability_type)}</h2>
                  <p><strong>Source:</strong> {html.escape(finding.source_function)}({html.escape(finding.source_parameter)})</p>
                  <p><strong>Sink:</strong> {html.escape(finding.sink_file)}:{finding.sink_line} <code>{html.escape(finding.sink_snippet)}</code></p>
                  <p><strong>Path:</strong> {html.escape(' -> '.join(finding.taint_path))}</p>
                  <p>{html.escape(finding.explanation)}</p>
                </article>
                """
            )
        if result.errors:
            body = (
                "<p><strong>Taint analysis did not complete:</strong></p><ul>"
                + "".join(f"<li>{html.escape(error)}</li>" for error in result.errors)
                + "</ul>"
            )
        else:
            body = "\n".join(findings_html) if findings_html else "<p>No findings.</p>"
        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>ActionTaint Report</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, sans-serif; margin: 2rem; color: #172033; }}
    header {{ border-bottom: 1px solid #d6dbe5; margin-bottom: 1.5rem; padding-bottom: 1rem; }}
    .finding {{ border: 1px solid #d6dbe5; border-radius: 8px; padding: 1rem; margin: 1rem 0; }}
    h1, h2 {{ margin: 0 0 .65rem; }}
    h2 span {{ color: #9b1c1c; font-size: .85em; }}
    code {{ background: #f4f6f8; padding: .12rem .28rem; border-radius: 4px; }}
  </style>
</head>
<body>
  <header>
    <h1>ActionTaint Report</h1>
    <p>Target: {html.escape(str(result.project.root))}</p>
    <p>Server Actions: {len(result.actions)} | Client-reachable: {len(result.reachable_actions)} | Findings: {len(result.findings)}</p>
  </header>
  {body}
</body>
</html>"""

    def _result_dict(self, result: AnalysisResult) -> dict[str, Any]:
        return {
            "project": {
                "root": self._display_path(result.project.root),
                "is_next_project": result.project.is_next_project,
                "next_version": result.project.next_version,
                "has_app_router": result.project.has_app_router,
                "has_pages_router": result.project.has_pages_router,
                "source_file_count": len(result.project.source_files),
            },
            "backend_used": result.backend_used,
            "parser_used": result.parser_used,
            "model_path": self._display_path(result.model_path),
            "codeql_query_path": self._display_path(result.codeql_query_path),
            "codeql_pack_path": self._display_path(result.codeql_pack_path),
            "counts": {
                "server_actions": len(result.actions),
                "client_reachable_actions": len(result.reachable_actions),
                "findings": len(result.findings),
            },
            "server_actions": [self._action_dict(action) for action in result.actions],
            "boundaries": [self._dataclass_dict(boundary) for boundary in result.boundaries],
            "findings": [self._dataclass_dict(finding) for finding in result.findings],
            "warnings": result.warnings,
            "errors": result.errors,
        }

    def _action_dict(self, action: Any) -> dict[str, Any]:
        # Function bodies and absolute file paths are omitted so reports can be shared safely.
        data = self._dataclass_dict(action)
        data.pop("body", None)
        data["file"] = action.rel_path
        return data

    def _display_path(self, path: Path | None) -> str | None:
        """Paths relative to the working directory, so reports do not embed user home directories."""
        if path is None:
            return None
        try:
            return Path(os.path.relpath(path)).as_posix()
        except ValueError:
            return Path(path).as_posix()

    def _dataclass_dict(self, value: Any) -> Any:
        if is_dataclass(value):
            data = asdict(value)
            return self._dataclass_dict(data)
        if isinstance(value, dict):
            return {key: self._dataclass_dict(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self._dataclass_dict(item) for item in value]
        if isinstance(value, Path):
            return self._display_path(value)
        return value

    def _sarif_level(self, severity: str) -> str:
        if severity in {"CRITICAL", "HIGH"}:
            return "error"
        if severity == "MEDIUM":
            return "warning"
        return "note"
