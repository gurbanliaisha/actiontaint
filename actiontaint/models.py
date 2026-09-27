from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class ProjectInfo:
    root: Path
    is_next_project: bool
    next_version: str | None
    has_app_router: bool
    has_pages_router: bool
    source_files: list[Path]
    package_json: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Parameter:
    name: str
    index: int
    raw: str
    type_hint: str | None = None


@dataclass(slots=True)
class FunctionDef:
    name: str
    file: Path
    rel_path: str
    start_line: int
    end_line: int
    body_start_line: int
    params: list[Parameter]
    exported: bool
    async_function: bool
    server_action: bool = False
    directive_kind: str | None = None
    body: str = ""
    export_names: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.rel_path}::{self.name}"


@dataclass(slots=True)
class ImportBinding:
    local: str
    imported: str
    source: str
    resolved_path: Path | None


@dataclass(slots=True)
class BindArgument:
    expr: str
    classification: str = "unknown"
    reason: str = ""


@dataclass(slots=True)
class HiddenInput:
    name: str
    value: str | None
    file: str
    line: int


@dataclass(slots=True)
class Callsite:
    file: Path
    rel_path: str
    line: int
    kind: str
    action_name: str
    action_key: str
    reason: str
    bind_args: list[BindArgument] = field(default_factory=list)
    hidden_inputs: list[HiddenInput] = field(default_factory=list)


@dataclass(slots=True)
class ReachableAction:
    action: FunctionDef
    callsites: list[Callsite] = field(default_factory=list)

    @property
    def reasons(self) -> list[str]:
        return [callsite.reason for callsite in self.callsites]


@dataclass(slots=True)
class SourceSpec:
    function_key: str
    function_name: str
    file: str
    parameter: str
    index: int | None
    kind: str
    reason: str
    confidence: str = "medium"
    expression: str | None = None


@dataclass(slots=True)
class BoundaryModel:
    function: str
    function_key: str
    file: str
    boundary_type: str
    client_callable: bool
    source_parameters: list[str]
    source_specs: list[SourceSpec]
    reason: str
    input_semantics: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    severity: str
    vulnerability_type: str
    source_function: str
    source_parameter: str
    sink_file: str
    sink_line: int
    sink_snippet: str
    taint_path: list[str]
    explanation: str
    rule_id: str


@dataclass(slots=True)
class AnalysisResult:
    project: ProjectInfo
    actions: list[FunctionDef]
    reachable_actions: list[ReachableAction]
    boundaries: list[BoundaryModel]
    source_specs: list[SourceSpec]
    findings: list[Finding]
    backend_used: str
    parser_used: str = "unknown"
    model_path: Path | None = None
    codeql_query_path: Path | None = None
    codeql_pack_path: Path | None = None
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
