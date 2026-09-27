from __future__ import annotations

from pathlib import Path

import pytest

from actiontaint.boundary import BoundaryModelBuilder
from actiontaint.callsite import CallsiteLinker
from actiontaint.discovery import ServerActionDiscovery
from actiontaint.scanner import ProjectScanner

REPO_ROOT = Path(__file__).resolve().parents[1]
BENCHMARKS = REPO_ROOT / "benchmarks"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def reconstruct(target: Path, parser: str = "typescript"):
    """Runs the framework-reconstruction stages (no CodeQL) and returns (functions, reachable, boundaries, parser_used)."""
    project = ProjectScanner().scan(target)
    functions, imports, ast_result, parser_used, _ = ServerActionDiscovery().discover(project, parser=parser)
    if parser == "typescript" and not parser_used.startswith("typescript-compiler-api"):
        pytest.skip("TypeScript parser unavailable (run `npm ci`)")
    reachable = CallsiteLinker().link(project.root, project.source_files, functions, imports, ast_result=ast_result)
    boundaries = BoundaryModelBuilder().build(reachable)
    return functions, reachable, boundaries, parser_used


@pytest.fixture(params=["typescript", "regex"])
def parser(request):
    return request.param
