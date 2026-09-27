from __future__ import annotations

from pathlib import Path

from .backends.codeql import CodeQLBackend
from .boundary import BoundaryModelBuilder
from .callsite import CallsiteLinker
from .discovery import ServerActionDiscovery
from .models import AnalysisResult
from .scanner import ProjectScanner
from .taint_model import TaintModelGenerator
from .utils import ensure_dir


class ActionTaintAnalyzer:
    """Coordinates scanner, framework modeling, taint model generation, and backend analysis."""

    def analyze(
        self,
        target: Path,
        backend: str = "codeql",
        output_dir: Path | None = None,
        parser: str = "auto",
    ) -> AnalysisResult:
        if backend != "codeql":
            raise ValueError("ActionTaint only supports the generated CodeQL backend.")
        if not target.is_dir():
            raise FileNotFoundError(f"Target directory does not exist: {target}")

        scanner = ProjectScanner()
        project = scanner.scan(target)
        warnings: list[str] = []
        if not project.is_next_project:
            warnings.append("Target does not look like a Next.js project; analysis continued with JS/TS files found.")

        discovery = ServerActionDiscovery()
        functions, imports_by_file, ast_result, parser_used, parser_warnings = discovery.discover(project, parser=parser)
        warnings.extend(parser_warnings)
        actions = [fn for fn in functions if fn.server_action]

        linker = CallsiteLinker()
        reachable = linker.link(project.root, project.source_files, functions, imports_by_file, ast_result=ast_result)

        boundaries = BoundaryModelBuilder().build(reachable)
        source_specs = [spec for boundary_model in boundaries for spec in boundary_model.source_specs]

        output_dir = (output_dir or (project.root / ".actiontaint")).resolve()
        ensure_dir(output_dir)
        model_path, query_path, pack_path = TaintModelGenerator().emit(output_dir, boundaries)

        codeql = CodeQLBackend()
        findings, codeql_warnings, errors = codeql.run(project, pack_path, output_dir)
        warnings.extend(codeql_warnings)

        return AnalysisResult(
            project=project,
            actions=actions,
            reachable_actions=reachable,
            boundaries=boundaries,
            source_specs=source_specs,
            findings=findings,
            backend_used="codeql",
            parser_used=parser_used,
            model_path=model_path,
            codeql_query_path=query_path,
            codeql_pack_path=pack_path,
            warnings=warnings,
            errors=errors,
        )
