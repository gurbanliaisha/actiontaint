from __future__ import annotations

import json
import re
from pathlib import Path

from .ast_parser import AstParseResult, TypeScriptAstParser
from .models import FunctionDef, ImportBinding, Parameter, ProjectInfo
from .utils import (
    find_matching_brace,
    first_statement_directive,
    line_number_for_index,
    parse_parameters,
    read_text,
    rel_path,
    top_level_directive,
)


FUNCTION_PATTERNS = [
    re.compile(
        r"(?P<export>export\s+)?(?:default\s+)?async\s+function\s+"
        r"(?P<name>[A-Za-z_$][\w$]*)\s*\((?P<params>[^)]*)\)\s*\{",
        re.MULTILINE,
    ),
    re.compile(
        r"(?P<export>export\s+)?(?:const|let|var)\s+"
        r"(?P<name>[A-Za-z_$][\w$]*)\s*=\s*async\s*"
        r"\((?P<params>[^)]*)\)\s*=>\s*\{",
        re.MULTILINE,
    ),
    re.compile(
        r"(?P<export>export\s+)?(?:const|let|var)\s+"
        r"(?P<name>[A-Za-z_$][\w$]*)\s*=\s*async\s+function\s*"
        r"\((?P<params>[^)]*)\)\s*\{",
        re.MULTILINE,
    ),
]

IMPORT_NAMED_RE = re.compile(
    r"import\s*\{(?P<names>[^}]+)\}\s*from\s*['\"](?P<source>[^'\"]+)['\"]",
    re.MULTILINE,
)
IMPORT_DEFAULT_RE = re.compile(
    r"import\s+(?P<local>[A-Za-z_$][\w$]*)\s+from\s*['\"](?P<source>[^'\"]+)['\"]",
    re.MULTILINE,
)
IMPORT_NAMESPACE_RE = re.compile(
    r"import\s*\*\s*as\s+(?P<local>[A-Za-z_$][\w$]*)\s+from\s*['\"](?P<source>[^'\"]+)['\"]",
    re.MULTILINE,
)
EXPORT_SPECIFIERS_RE = re.compile(r"^\s*export\s*\{(?P<names>[^}]*)\}\s*;?\s*$", re.MULTILINE)
EXPORT_DEFAULT_IDENT_RE = re.compile(r"^\s*export\s+default\s+(?P<name>[A-Za-z_$][\w$]*)\s*;?\s*$", re.MULTILINE)


class ServerActionDiscovery:
    """Discovers async functions and marks Next.js Server Actions."""

    def discover(
        self, project: ProjectInfo, parser: str = "auto"
    ) -> tuple[list[FunctionDef], dict[Path, list[ImportBinding]], AstParseResult | None, str, list[str]]:
        warnings: list[str] = []
        ast_result: AstParseResult | None = None
        if parser in {"auto", "typescript"}:
            ast_result = TypeScriptAstParser().parse(project)
            if ast_result and ast_result.files:
                functions, imports_by_file = self._discover_from_ast(project, ast_result)
                warnings.extend(ast_result.warnings)
                return functions, imports_by_file, ast_result, ast_result.parser, warnings
            if ast_result:
                warnings.extend(ast_result.warnings)
            if parser == "typescript":
                warnings.append("TypeScript parser was requested but unavailable; falling back to regex parser.")

        functions, imports_by_file = self._discover_with_regex(project)
        return functions, imports_by_file, ast_result, "regex-fallback" if parser != "regex" else "regex", warnings

    def _discover_with_regex(self, project: ProjectInfo) -> tuple[list[FunctionDef], dict[Path, list[ImportBinding]]]:
        functions: list[FunctionDef] = []
        imports_by_file: dict[Path, list[ImportBinding]] = {}
        for path in project.source_files:
            text = read_text(path)
            file_has_use_server = top_level_directive(text, "use server")
            imports_by_file[path] = self.parse_imports(project.root, path, text)
            file_functions = self._extract_functions(project.root, path, text, file_has_use_server)
            functions.extend(file_functions)
        return functions, imports_by_file

    def _discover_from_ast(
        self, project: ProjectInfo, ast_result: AstParseResult
    ) -> tuple[list[FunctionDef], dict[Path, list[ImportBinding]]]:
        functions: list[FunctionDef] = []
        imports_by_file: dict[Path, list[ImportBinding]] = {}
        for rel, file_fact in ast_result.files.items():
            path = (project.root / rel).resolve()
            imports_by_file[path] = [
                ImportBinding(
                    local=item["local"],
                    imported=item["imported"],
                    source=item["source"],
                    resolved_path=self._resolve_import(project.root, path, item["source"]),
                )
                for item in file_fact.get("imports", [])
            ]
            for fact in file_fact.get("functions", []):
                params = [
                    Parameter(
                        name=param["name"],
                        index=int(param["index"]),
                        raw=param["raw"],
                        type_hint=param.get("typeHint"),
                    )
                    for param in fact.get("params", [])
                ]
                functions.append(
                    FunctionDef(
                        name=fact["name"],
                        file=path,
                        rel_path=rel,
                        start_line=int(fact["startLine"]),
                        end_line=int(fact["endLine"]),
                        body_start_line=int(fact["bodyStartLine"]),
                        params=params,
                        exported=bool(fact["exported"]),
                        async_function=bool(fact["asyncFunction"]),
                        server_action=bool(fact["serverAction"]),
                        directive_kind=fact.get("directiveKind"),
                        body=fact.get("body", ""),
                        export_names=list(fact.get("exportNames", [])),
                    )
                )
        return sorted(functions, key=lambda item: (item.rel_path, item.start_line, item.name)), imports_by_file

    def parse_imports(self, root: Path, file: Path, text: str) -> list[ImportBinding]:
        imports: list[ImportBinding] = []
        for match in IMPORT_NAMED_RE.finditer(text):
            source = match.group("source")
            resolved = self._resolve_import(root, file, source)
            for part in match.group("names").split(","):
                part = part.strip()
                if not part:
                    continue
                if " as " in part:
                    imported, local = [p.strip() for p in part.split(" as ", 1)]
                else:
                    imported = local = part
                imports.append(ImportBinding(local=local, imported=imported, source=source, resolved_path=resolved))
        for match in IMPORT_DEFAULT_RE.finditer(text):
            source = match.group("source")
            imports.append(
                ImportBinding(
                    local=match.group("local"),
                    imported="default",
                    source=source,
                    resolved_path=self._resolve_import(root, file, source),
                )
            )
        for match in IMPORT_NAMESPACE_RE.finditer(text):
            source = match.group("source")
            imports.append(
                ImportBinding(
                    local=match.group("local"),
                    imported="*",
                    source=source,
                    resolved_path=self._resolve_import(root, file, source),
                )
            )
        return imports

    def _export_specifiers(self, text: str) -> dict[str, list[str]]:
        """Maps local names to exported names for `export { a, b as c }` and `export default a`."""
        exports: dict[str, list[str]] = {}
        for match in EXPORT_SPECIFIERS_RE.finditer(text):
            for part in match.group("names").split(","):
                part = part.strip()
                if not part:
                    continue
                if " as " in part:
                    local, exported = [p.strip() for p in part.split(" as ", 1)]
                else:
                    local = exported = part
                exports.setdefault(local, []).append(exported)
        for match in EXPORT_DEFAULT_IDENT_RE.finditer(text):
            exports.setdefault(match.group("name"), []).append("default")
        return exports

    def _extract_functions(
        self, root: Path, path: Path, text: str, file_has_use_server: bool
    ) -> list[FunctionDef]:
        functions: list[FunctionDef] = []
        seen_starts: set[int] = set()
        export_specifiers = self._export_specifiers(text)
        for pattern in FUNCTION_PATTERNS:
            for match in pattern.finditer(text):
                if match.start() in seen_starts:
                    continue
                seen_starts.add(match.start())
                open_brace = text.find("{", match.end() - 1)
                close_brace = find_matching_brace(text, open_brace)
                if close_brace is None:
                    continue
                body = text[open_brace + 1 : close_brace]
                params = [
                    Parameter(name=name, type_hint=type_hint, raw=raw, index=index)
                    for index, (name, type_hint, raw) in enumerate(parse_parameters(match.group("params")))
                ]
                start_line = line_number_for_index(text, match.start())
                body_start_line = line_number_for_index(text, open_brace) + 1
                end_line = line_number_for_index(text, close_brace)
                name = match.group("name")
                top_level = match.start() == 0 or text[match.start() - 1] == "\n"
                export_names = export_specifiers.get(name, []) if top_level else []
                exported = bool(match.groupdict().get("export")) or bool(export_names)
                inline_server = first_statement_directive(body, "use server")
                is_action = inline_server or (file_has_use_server and exported)
                directive_kind = "inline" if inline_server else ("file" if file_has_use_server and exported else None)
                functions.append(
                    FunctionDef(
                        name=name,
                        file=path,
                        rel_path=rel_path(path, root),
                        start_line=start_line,
                        end_line=end_line,
                        body_start_line=body_start_line,
                        params=params,
                        exported=exported,
                        async_function=True,
                        server_action=is_action,
                        directive_kind=directive_kind,
                        body=body,
                        export_names=export_names,
                    )
                )
        return sorted(functions, key=lambda item: (item.rel_path, item.start_line, item.name))

    def _resolve_import(self, root: Path, file: Path, source: str) -> Path | None:
        bases: list[Path]
        if source.startswith("@/"):
            relative = source[2:]
            # Many Next.js projects map "@/*" to either the repository root or
            # to "src/*" through tsconfig/jsconfig paths. Try both so framework
            # callsite linking works on common real-world layouts.
            bases = [root / relative, root / "src" / relative]
        elif source.startswith("."):
            bases = [(file.parent / source).resolve()]
        else:
            bases = self._path_alias_bases(root, source)
            if not bases:
                return None
        candidates = []
        for base in bases:
            candidates.append(base)
            for ext in (".ts", ".tsx", ".js", ".jsx"):
                candidates.append(base.with_suffix(ext))
            for ext in (".ts", ".tsx", ".js", ".jsx"):
                candidates.append(base / f"index{ext}")
        for candidate in candidates:
            if candidate.exists() and candidate.is_file():
                return candidate.resolve()
        return None

    def _path_alias_bases(self, root: Path, source: str) -> list[Path]:
        config = self._read_ts_path_config(root)
        if not config:
            return []
        base_url = config.get("baseUrl") or "."
        paths = config.get("paths") or {}
        bases: list[Path] = []
        for alias, targets in paths.items():
            if not isinstance(targets, list):
                continue
            remainder: str | None = None
            if "*" in alias:
                prefix, suffix = alias.split("*", 1)
                if source.startswith(prefix) and source.endswith(suffix):
                    remainder = source[len(prefix) : len(source) - len(suffix) if suffix else len(source)]
                else:
                    continue
            elif alias == source:
                remainder = ""
            else:
                continue
            for target in targets:
                if not isinstance(target, str):
                    continue
                mapped = target.replace("*", remainder or "")
                bases.append((root / base_url / mapped).resolve())
        return bases

    def _read_ts_path_config(self, root: Path) -> dict:
        for name in ("tsconfig.json", "jsconfig.json"):
            path = root / name
            if not path.exists():
                continue
            try:
                data = json.loads(strip_jsonc(path.read_text(encoding="utf-8-sig")))
            except json.JSONDecodeError:
                continue
            options = data.get("compilerOptions", {}) if isinstance(data, dict) else {}
            if isinstance(options, dict):
                return options
        return {}


def strip_jsonc(text: str) -> str:
    """Removes // and /* */ comments and trailing commas (tsconfig.json is JSONC), leaving strings intact."""
    out: list[str] = []
    i = 0
    in_string = False
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if in_string:
            out.append(ch)
            if ch == "\\":
                out.append(nxt)
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and nxt == "/":
            end = text.find("\n", i)
            i = len(text) if end == -1 else end
            continue
        if ch == "/" and nxt == "*":
            end = text.find("*/", i + 2)
            i = len(text) if end == -1 else end + 2
            continue
        out.append(ch)
        i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))
