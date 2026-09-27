from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import ProjectInfo


@dataclass(slots=True)
class AstParseResult:
    parser: str
    files: dict[str, dict[str, Any]]
    warnings: list[str] = field(default_factory=list)


class TypeScriptAstParser:
    """Extracts syntax facts through the TypeScript compiler API.

    The Python analyzer consumes normalized facts instead of depending on regexes
    for function/import/JSX discovery. This keeps the orchestration language
    Python while using the JavaScript ecosystem's own parser for JS/TS syntax.
    """

    def parse(self, project: ProjectInfo) -> AstParseResult | None:
        node = shutil.which("node")
        if node is None:
            return AstParseResult(
                parser="typescript-unavailable",
                files={},
                warnings=["Node.js was not found; TypeScript AST parser is unavailable."],
            )

        script = Path(__file__).parent / "parsers" / "ts_ast_extractor.cjs"
        payload = {
            "root": str(project.root),
            "files": [str(path) for path in project.source_files],
        }
        # Let `require("typescript")` resolve from the ActionTaint checkout, the scanned
        # project, or the working directory, so a non-editable install still finds it.
        module_dirs = [
            Path(__file__).resolve().parents[1] / "node_modules",
            project.root / "node_modules",
            Path.cwd() / "node_modules",
        ]
        env = os.environ.copy()
        node_path = [str(path) for path in module_dirs if path.is_dir()]
        if env.get("NODE_PATH"):
            node_path.append(env["NODE_PATH"])
        env["NODE_PATH"] = os.pathsep.join(node_path)
        proc = subprocess.run(
            [node, str(script)],
            env=env,
            input=json.dumps(payload),
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
        if proc.returncode != 0:
            message = proc.stderr.strip() or proc.stdout.strip() or "unknown TypeScript AST parser failure"
            return AstParseResult(
                parser="typescript-unavailable",
                files={},
                warnings=[message],
            )
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            return AstParseResult(
                parser="typescript-unavailable",
                files={},
                warnings=[f"TypeScript AST parser returned invalid JSON: {exc}"],
            )
        files = {item["relPath"]: item for item in data.get("files", [])}
        return AstParseResult(
            parser=data.get("parser", "typescript-compiler-api"),
            files=files,
            warnings=data.get("warnings", []),
        )
