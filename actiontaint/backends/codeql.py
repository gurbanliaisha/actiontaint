from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

from actiontaint.models import Finding, ProjectInfo


RULE_IDS = {
    "SQL Injection": "actiontaint/sql-injection",
    "SSRF": "actiontaint/ssrf",
    "Open Redirect": "actiontaint/open-redirect",
    "Path Traversal": "actiontaint/path-traversal",
    "Command Injection": "actiontaint/command-injection",
    "Broken Authorization / IDOR": "actiontaint/idor",
}

MESSAGE_RE = re.compile(
    r"ActionTaint:\s+(?P<kind>.+?)\s+from\s+(?P<file>.+?)::(?P<fun>[^:\s]+)::(?P<param>\S+)\s+to\s+"
    r"(?P<sink>.+?)\s+dangerous sink"
)


class CodeQLBackend:
    """Runs generated ActionTaint CodeQL queries when the CodeQL CLI exists."""

    def available(self) -> bool:
        return self.executable() is not None

    def executable(self) -> str | None:
        candidates = [
            os.environ.get("ACTIONTAINT_CODEQL"),
            shutil.which("codeql"),
            shutil.which("codeql.exe"),
        ]
        for candidate in candidates:
            if not candidate:
                continue
            path = Path(candidate)
            if path.exists() and path.is_file():
                return str(path)
        return None

    def run(self, project: ProjectInfo, pack_path: Path, output_dir: Path) -> tuple[list[Finding], list[str], list[str]]:
        """Returns (findings, warnings, errors). Any error means the taint analysis did not complete."""
        warnings: list[str] = []
        codeql = self.executable()
        if codeql is None:
            return [], warnings, ["CodeQL CLI was not found. Set ACTIONTAINT_CODEQL or install codeql on PATH."]

        db_dir = output_dir / "codeql-db"
        sarif_path = output_dir / "codeql-results.sarif"
        if sarif_path.exists():
            sarif_path.unlink()

        # Always rebuild the database so results reflect the current source code.
        create_cmd = [
            codeql,
            "database",
            "create",
            str(db_dir),
            "--language=javascript-typescript",
            f"--source-root={project.root}",
            "--overwrite",
        ]
        created = self._run_command(create_cmd, project.root)
        if created.returncode != 0:
            return [], warnings, [f"CodeQL database create failed: {self._tail(created)}"]

        # Resolves (and, if needed, downloads) the pinned codeql/javascript-all dependency.
        installed = self._run_command([codeql, "pack", "install", str(pack_path)], project.root)
        if installed.returncode != 0:
            return [], warnings, [f"CodeQL pack install failed: {self._tail(installed)}"]

        analyze_cmd = [
            codeql,
            "database",
            "analyze",
            str(db_dir),
            str(pack_path),
            "--format=sarif-latest",
            f"--output={sarif_path}",
        ]
        start = time.perf_counter()
        analyzed = self._run_command(analyze_cmd, project.root)
        elapsed = time.perf_counter() - start
        if analyzed.returncode != 0 or not sarif_path.exists():
            return [], warnings, [f"CodeQL analyze failed: {self._tail(analyzed)}"]
        warnings.append(f"CodeQL completed in {elapsed:.2f}s.")
        return self._parse_sarif(sarif_path, project.root), warnings, []

    def _tail(self, proc: subprocess.CompletedProcess, lines: int = 15) -> str:
        text = (proc.stderr or "").strip() or (proc.stdout or "").strip() or f"exit code {proc.returncode}"
        return "\n".join(text.splitlines()[-lines:])

    def _run_command(self, cmd: list[str], cwd: Path) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env.setdefault("CODEQL_ALLOW_INSTALLATION_ANYWHERE", "true")
        return subprocess.run(
            cmd,
            cwd=str(cwd),
            env=env,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )

    def _parse_sarif(self, sarif_path: Path, root: Path) -> list[Finding]:
        if not sarif_path.exists():
            return []
        data = json.loads(sarif_path.read_text(encoding="utf-8"))
        findings: list[Finding] = []
        for run in data.get("runs", []):
            for result in run.get("results", []):
                location = result.get("locations", [{}])[0].get("physicalLocation", {})
                artifact = location.get("artifactLocation", {}).get("uri", "<unknown>")
                region = location.get("region", {})
                line = int(region.get("startLine", 0))
                message = result.get("message", {}).get("text", "")
                kind, source_function, source_parameter = self._parse_message(message)
                taint_path = self._extract_taint_path(result)
                findings.append(
                    Finding(
                        severity=self._severity_for(kind),
                        vulnerability_type=kind,
                        source_function=source_function,
                        source_parameter=source_parameter,
                        sink_file=artifact,
                        sink_line=line,
                        sink_snippet=self._source_line(root, artifact, line) or message,
                        taint_path=taint_path or ([message] if message else []),
                        explanation=self._explanation(kind, source_function, source_parameter),
                        rule_id=RULE_IDS.get(kind, result.get("ruleId", "actiontaint/codeql")),
                    )
                )
        return findings

    def _source_line(self, root: Path, artifact: str, line: int) -> str:
        path = root / artifact
        if line <= 0 or not path.is_file():
            return ""
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        return lines[line - 1].strip() if line <= len(lines) else ""

    def _explanation(self, kind: str, source_function: str, source_parameter: str) -> str:
        return (
            f"Client-controlled input '{source_parameter}' of Server Action {source_function} "
            f"reaches a {kind} sink (framework-derived taint path reported by the generated CodeQL query)."
        )

    def _extract_taint_path(self, result: dict) -> list[str]:
        path: list[str] = []
        for code_flow in result.get("codeFlows", []):
            for thread_flow in code_flow.get("threadFlows", []):
                for location in thread_flow.get("locations", []):
                    physical = location.get("location", {}).get("physicalLocation", {})
                    artifact = physical.get("artifactLocation", {}).get("uri", "<unknown>")
                    region = physical.get("region", {})
                    line = region.get("startLine", 0)
                    message = location.get("location", {}).get("message", {}).get("text", "")
                    label = f"{artifact}:{line}"
                    if message:
                        label = f"{label} {message}"
                    path.append(label)
        return path

    def _parse_message(self, message: str) -> tuple[str, str, str]:
        match = MESSAGE_RE.search(message)
        if not match:
            return "CodeQL Finding", "<codeql>", "<generated-source>"
        return match.group("kind"), f"{match.group('file')}::{match.group('fun')}", match.group("param")

    def _severity_for(self, kind: str) -> str:
        if kind == "Command Injection":
            return "CRITICAL"
        if kind in {"SQL Injection", "SSRF", "Path Traversal", "Broken Authorization / IDOR"}:
            return "HIGH"
        if kind == "Open Redirect":
            return "MEDIUM"
        return "WARNING"
