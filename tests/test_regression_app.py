"""Reachability patterns beyond the paper benchmarks (namespace imports, re-exports, default exports, closures)."""

from __future__ import annotations

from conftest import FIXTURES, reconstruct

APP = FIXTURES / "regression_app"


def _by_name(boundaries):
    return {boundary.function: boundary for boundary in boundaries}


def test_typescript_parser_reconstructs_all_patterns():
    functions, reachable, boundaries, parser_used = reconstruct(APP, "typescript")
    assert parser_used.startswith("typescript-compiler-api")
    actions = {fn.name for fn in functions if fn.server_action}
    assert len(actions) == 17
    assert {"reexported", "nsAction", "default", "closureAction"} <= actions

    reachable_names = {item.action.name for item in reachable}
    assert "unusedAction" not in reachable_names
    assert len(reachable_names) == 16

    boundaries = _by_name(boundaries)
    assert "used in <form action={NS.nsAction}>" in boundaries["nsAction"].reason
    assert "used in <form action={reexported}>" in boundaries["reexported"].reason
    closure_specs = boundaries["closureAction"].source_specs
    assert [(spec.parameter, spec.index, spec.expression) for spec in closure_specs] == [
        ("$closure:searchParams", None, "searchParams")
    ]
    bind_specs = {(spec.parameter, spec.kind) for spec in boundaries["bindInline"].source_specs}
    assert ("id", "bind_search_param") in bind_specs


def test_regex_parser_handles_namespace_and_reexport():
    functions, reachable, _, _ = reconstruct(APP, "regex")
    reachable_names = {item.action.name for item in reachable}
    assert {"nsAction", "reexported"} <= reachable_names
    # Anonymous default-exported actions need the TypeScript parser.
    assert "default" not in {fn.name for fn in functions if fn.server_action}


def test_tsconfig_with_comments_and_trailing_commas(tmp_path):
    import json

    from actiontaint.discovery import ServerActionDiscovery, strip_jsonc

    text = """{
      // Next.js default config
      "$schema": "https://json.schemastore.org/tsconfig", /* keep URL */
      "compilerOptions": {
        "baseUrl": ".",
        "paths": { "@lib/*": ["src/lib/*"], },
      },
    }"""
    assert json.loads(strip_jsonc(text))["$schema"] == "https://json.schemastore.org/tsconfig"
    (tmp_path / "tsconfig.json").write_text(text, encoding="utf-8")
    (tmp_path / "src" / "lib").mkdir(parents=True)
    (tmp_path / "src" / "lib" / "db.ts").write_text("export const db = {};", encoding="utf-8")
    resolved = ServerActionDiscovery()._resolve_import(tmp_path, tmp_path / "app" / "page.tsx", "@lib/db")
    assert resolved == (tmp_path / "src" / "lib" / "db.ts").resolve()
