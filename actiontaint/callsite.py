from __future__ import annotations

import re
from pathlib import Path

from .ast_parser import AstParseResult
from .models import BindArgument, Callsite, FunctionDef, HiddenInput, ImportBinding, ReachableAction
from .utils import line_number_for_index, read_text, rel_path, split_top_level_args, top_level_directive


FORM_ACTION_RE = re.compile(r"<form\b[^>]*\baction\s*=\s*\{(?P<expr>[^}]+)\}", re.IGNORECASE | re.DOTALL)
BUTTON_FORM_ACTION_RE = re.compile(
    r"<(?:button|input)\b[^>]*\bformAction\s*=\s*\{(?P<expr>[^}]+)\}",
    re.IGNORECASE | re.DOTALL,
)
JSX_ACTION_PROP_RE = re.compile(
    r"<(?P<component>[A-Z][A-Za-z0-9_$]*)\b[^>]*\b"
    r"(?P<prop>[A-Za-z0-9_$]*(?:action|Action|formAction)[A-Za-z0-9_$]*)\s*=\s*\{(?P<expr>[^}]+)\}",
    re.DOTALL,
)
USE_ACTION_STATE_RE = re.compile(
    r"(?:const|let|var)\s+\[[^\]]*?,\s*(?P<alias>[A-Za-z_$][\w$]*)[^\]]*\]\s*=\s*"
    r"(?P<hook>useActionState|useFormState)\s*\((?P<expr>[^,)\n]+)",
    re.MULTILINE,
)
BIND_ASSIGN_RE = re.compile(
    r"(?:const|let|var)\s+(?P<alias>[A-Za-z_$][\w$]*)\s*=\s*"
    r"(?P<target>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\.bind\s*\((?P<args>[^)]*)\)",
    re.MULTILINE,
)
HIDDEN_INPUT_RE = re.compile(r"<input\b(?P<attrs>[^>]*\btype\s*=\s*['\"]hidden['\"][^>]*)>", re.IGNORECASE | re.DOTALL)
ATTR_RE = re.compile(r"(?P<name>[A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*(?:['\"](?P<q>[^'\"]*)['\"]|\{(?P<braced>[^}]*)\})")


class CallsiteLinker:
    """Links Server Actions to framework-level client reachability."""

    def link(
        self,
        root: Path,
        source_files: list[Path],
        functions: list[FunctionDef],
        imports_by_file: dict[Path, list[ImportBinding]],
        ast_result: AstParseResult | None = None,
    ) -> list[ReachableAction]:
        actions = [fn for fn in functions if fn.server_action]
        actions_by_key = {fn.key: fn for fn in actions}
        action_by_file_name: dict[tuple[Path, str], FunctionDef] = {}
        for fn in actions:
            action_by_file_name[(fn.file.resolve(), fn.name)] = fn
            for exported in fn.export_names:
                action_by_file_name[(fn.file.resolve(), exported)] = fn
        reachable: dict[str, ReachableAction] = {}

        for file in source_files:
            local_symbols = self._local_action_symbols(file, actions, imports_by_file.get(file, []), action_by_file_name)
            file_fact = self._ast_file_fact(root, file, ast_result)
            if file_fact:
                bound_aliases = self._bound_aliases_from_ast(file_fact, local_symbols)
                hook_aliases = self._hook_aliases_from_ast(root, file, file_fact, local_symbols, reachable, actions_by_key)
                hidden_inputs = self._hidden_inputs_from_ast(root, file, file_fact)
                self._scan_ast_jsx_actions(
                    root,
                    file,
                    file_fact,
                    local_symbols,
                    bound_aliases,
                    hook_aliases,
                    hidden_inputs,
                    reachable,
                    actions_by_key,
                )
                if file_fact.get("fileUseClient"):
                    self._scan_ast_client_direct_calls(root, file, file_fact, local_symbols, reachable, actions_by_key)
            else:
                text = read_text(file)
                bound_aliases = self._bound_aliases(text, local_symbols)
                hook_aliases = self._hook_aliases(root, file, text, local_symbols, reachable, actions_by_key)
                hidden_inputs = self._hidden_inputs(root, file, text)
                self._scan_jsx_forms(root, file, text, local_symbols, bound_aliases, hook_aliases, hidden_inputs, reachable, actions_by_key)
                self._scan_component_props(root, file, text, local_symbols, bound_aliases, hidden_inputs, reachable, actions_by_key)
                if top_level_directive(text, "use client"):
                    self._scan_client_direct_calls(root, file, text, local_symbols, reachable, actions_by_key)

        return sorted(reachable.values(), key=lambda item: item.action.key)

    def _local_action_symbols(
        self,
        file: Path,
        actions: list[FunctionDef],
        imports: list[ImportBinding],
        action_by_file_name: dict[tuple[Path, str], FunctionDef],
    ) -> dict[str, str]:
        symbols: dict[str, str] = {}
        for action in actions:
            if action.file.resolve() == file.resolve():
                symbols[action.name] = action.key
        for binding in imports:
            if binding.resolved_path is None:
                continue
            if binding.imported == "*":
                # import * as NS from "./actions"  ->  NS.save refers to the save action
                resolved = binding.resolved_path.resolve()
                for (action_file, exported_name), action in action_by_file_name.items():
                    if action_file == resolved:
                        symbols[f"{binding.local}.{exported_name}"] = action.key
                continue
            target = action_by_file_name.get((binding.resolved_path.resolve(), binding.imported))
            if target:
                symbols[binding.local] = target.key
        return symbols

    def _ast_file_fact(self, root: Path, file: Path, ast_result: AstParseResult | None) -> dict | None:
        if not ast_result:
            return None
        return ast_result.files.get(rel_path(file, root))

    def _bound_aliases_from_ast(
        self, file_fact: dict, local_symbols: dict[str, str]
    ) -> dict[str, tuple[str, list[BindArgument]]]:
        aliases: dict[str, tuple[str, list[BindArgument]]] = {}
        for item in file_fact.get("callsites", {}).get("bindAliases", []):
            target = item["target"]
            if target not in local_symbols:
                continue
            args = item.get("args", [])
            bind_args = [BindArgument(expr=arg) for arg in args[1:]] if args and args[0] == "null" else [BindArgument(expr=arg) for arg in args]
            aliases[item["alias"]] = (local_symbols[target], bind_args)
        return aliases

    def _hook_aliases_from_ast(
        self,
        root: Path,
        file: Path,
        file_fact: dict,
        local_symbols: dict[str, str],
        reachable: dict[str, ReachableAction],
        actions_by_key: dict[str, FunctionDef],
    ) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for item in file_fact.get("callsites", {}).get("hooks", []):
            expr = item["expr"].strip()
            resolved = self._resolve_expr(expr, local_symbols, {}, {})
            if not resolved:
                continue
            action_key, bind_args = resolved
            aliases[item["alias"]] = action_key
            self._add_callsite(
                reachable,
                actions_by_key,
                Callsite(
                    file=file,
                    rel_path=rel_path(file, root),
                    line=int(item["line"]),
                    kind=item["hook"],
                    action_name=actions_by_key[action_key].name,
                    action_key=action_key,
                    reason=f"used in {item['hook']}({expr}, ...)",
                    bind_args=bind_args,
                ),
            )
        return aliases

    def _hidden_inputs_from_ast(self, root: Path, file: Path, file_fact: dict) -> list[HiddenInput]:
        return [
            HiddenInput(
                name=item["name"],
                value=item.get("value"),
                file=rel_path(file, root),
                line=int(item["line"]),
            )
            for item in file_fact.get("callsites", {}).get("hiddenInputs", [])
        ]

    def _scan_ast_jsx_actions(
        self,
        root: Path,
        file: Path,
        file_fact: dict,
        local_symbols: dict[str, str],
        bound_aliases: dict[str, tuple[str, list[BindArgument]]],
        hook_aliases: dict[str, str],
        hidden_inputs: list[HiddenInput],
        reachable: dict[str, ReachableAction],
        actions_by_key: dict[str, FunctionDef],
    ) -> None:
        for item in file_fact.get("callsites", {}).get("jsxActions", []):
            expr = item["expr"].strip()
            resolved = self._resolve_expr(expr, local_symbols, bound_aliases, hook_aliases)
            if not resolved:
                continue
            action_key, bind_args = resolved
            kind = item["kind"]
            if kind == "form_action":
                reason = f"used in <form action={{{expr}}}>"
            elif kind == "button_form_action":
                reason = f"used in <{item['tag']} formAction={{{expr}}}>"
            else:
                reason = f"passed to client-reachable component <{item['tag']} {item['prop']}={{{expr}}}>"
            self._add_callsite(
                reachable,
                actions_by_key,
                Callsite(
                    file=file,
                    rel_path=rel_path(file, root),
                    line=int(item["line"]),
                    kind=kind,
                    action_name=actions_by_key[action_key].name,
                    action_key=action_key,
                    reason=reason,
                    bind_args=bind_args,
                    hidden_inputs=hidden_inputs,
                ),
            )

    def _scan_ast_client_direct_calls(
        self,
        root: Path,
        file: Path,
        file_fact: dict,
        local_symbols: dict[str, str],
        reachable: dict[str, ReachableAction],
        actions_by_key: dict[str, FunctionDef],
    ) -> None:
        for item in file_fact.get("callsites", {}).get("directCalls", []):
            local = item["name"]
            if local not in local_symbols:
                continue
            action_key = local_symbols[local]
            self._add_callsite(
                reachable,
                actions_by_key,
                Callsite(
                    file=file,
                    rel_path=rel_path(file, root),
                    line=int(item["line"]),
                    kind="client_direct_call",
                    action_name=actions_by_key[action_key].name,
                    action_key=action_key,
                    reason=f"imported Server Action called from 'use client' file as {local}(...)",
                ),
            )

    def _bound_aliases(self, text: str, local_symbols: dict[str, str]) -> dict[str, tuple[str, list[BindArgument]]]:
        aliases: dict[str, tuple[str, list[BindArgument]]] = {}
        for match in BIND_ASSIGN_RE.finditer(text):
            target = match.group("target")
            if target not in local_symbols:
                continue
            args = split_top_level_args(match.group("args"))
            bind_args = [BindArgument(expr=arg) for arg in args[1:]] if args and args[0] == "null" else [BindArgument(expr=arg) for arg in args]
            aliases[match.group("alias")] = (local_symbols[target], bind_args)
        return aliases

    def _hook_aliases(
        self,
        root: Path,
        file: Path,
        text: str,
        local_symbols: dict[str, str],
        reachable: dict[str, ReachableAction],
        actions_by_key: dict[str, FunctionDef],
    ) -> dict[str, str]:
        aliases: dict[str, str] = {}
        for match in USE_ACTION_STATE_RE.finditer(text):
            expr = match.group("expr").strip()
            resolved = self._resolve_expr(expr, local_symbols, {}, {})
            if not resolved:
                continue
            action_key, bind_args = resolved
            aliases[match.group("alias")] = action_key
            self._add_callsite(
                reachable,
                actions_by_key,
                Callsite(
                    file=file,
                    rel_path=rel_path(file, root),
                    line=line_number_for_index(text, match.start()),
                    kind=match.group("hook"),
                    action_name=actions_by_key[action_key].name,
                    action_key=action_key,
                    reason=f"used in {match.group('hook')}({expr}, ...)",
                    bind_args=bind_args,
                ),
            )
        return aliases

    def _scan_jsx_forms(
        self,
        root: Path,
        file: Path,
        text: str,
        local_symbols: dict[str, str],
        bound_aliases: dict[str, tuple[str, list[BindArgument]]],
        hook_aliases: dict[str, str],
        hidden_inputs: list[HiddenInput],
        reachable: dict[str, ReachableAction],
        actions_by_key: dict[str, FunctionDef],
    ) -> None:
        for kind, pattern, label in (
            ("form_action", FORM_ACTION_RE, "<form action={...}>"),
            ("button_form_action", BUTTON_FORM_ACTION_RE, "<button formAction={...}>"),
        ):
            for match in pattern.finditer(text):
                expr = match.group("expr").strip()
                resolved = self._resolve_expr(expr, local_symbols, bound_aliases, hook_aliases)
                if not resolved:
                    continue
                action_key, bind_args = resolved
                reason = f"used in {label.replace('...', expr)}"
                self._add_callsite(
                    reachable,
                    actions_by_key,
                    Callsite(
                        file=file,
                        rel_path=rel_path(file, root),
                        line=line_number_for_index(text, match.start()),
                        kind=kind,
                        action_name=actions_by_key[action_key].name,
                        action_key=action_key,
                        reason=reason,
                        bind_args=bind_args,
                        hidden_inputs=hidden_inputs,
                    ),
                )

    def _scan_component_props(
        self,
        root: Path,
        file: Path,
        text: str,
        local_symbols: dict[str, str],
        bound_aliases: dict[str, tuple[str, list[BindArgument]]],
        hidden_inputs: list[HiddenInput],
        reachable: dict[str, ReachableAction],
        actions_by_key: dict[str, FunctionDef],
    ) -> None:
        for match in JSX_ACTION_PROP_RE.finditer(text):
            expr = match.group("expr").strip()
            resolved = self._resolve_expr(expr, local_symbols, bound_aliases, {})
            if not resolved:
                continue
            action_key, bind_args = resolved
            component = match.group("component")
            prop = match.group("prop")
            self._add_callsite(
                reachable,
                actions_by_key,
                Callsite(
                    file=file,
                    rel_path=rel_path(file, root),
                    line=line_number_for_index(text, match.start()),
                    kind="component_prop",
                    action_name=actions_by_key[action_key].name,
                    action_key=action_key,
                    reason=f"passed to client-reachable component <{component} {prop}={{{expr}}}>",
                    bind_args=bind_args,
                    hidden_inputs=hidden_inputs,
                ),
            )

    def _scan_client_direct_calls(
        self,
        root: Path,
        file: Path,
        text: str,
        local_symbols: dict[str, str],
        reachable: dict[str, ReachableAction],
        actions_by_key: dict[str, FunctionDef],
    ) -> None:
        for local, action_key in local_symbols.items():
            for match in re.finditer(rf"\b{re.escape(local)}\s*\(", text):
                self._add_callsite(
                    reachable,
                    actions_by_key,
                    Callsite(
                        file=file,
                        rel_path=rel_path(file, root),
                        line=line_number_for_index(text, match.start()),
                        kind="client_direct_call",
                        action_name=actions_by_key[action_key].name,
                        action_key=action_key,
                        reason=f"imported Server Action called from 'use client' file as {local}(...)",
                    ),
                )

    def _resolve_expr(
        self,
        expr: str,
        local_symbols: dict[str, str],
        bound_aliases: dict[str, tuple[str, list[BindArgument]]],
        hook_aliases: dict[str, str],
    ) -> tuple[str, list[BindArgument]] | None:
        expr = expr.strip()
        direct_bind = re.fullmatch(
            r"(?P<target>[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\.bind\s*\((?P<args>.*)\)", expr, re.DOTALL
        )
        if direct_bind:
            target = direct_bind.group("target")
            if target not in local_symbols:
                return None
            args = split_top_level_args(direct_bind.group("args"))
            bind_args = [BindArgument(expr=arg) for arg in args[1:]] if args and args[0] == "null" else [BindArgument(expr=arg) for arg in args]
            return local_symbols[target], bind_args
        if expr in bound_aliases:
            return bound_aliases[expr]
        if expr in hook_aliases:
            return hook_aliases[expr], []
        if expr in local_symbols:
            return local_symbols[expr], []
        return None

    def _hidden_inputs(self, root: Path, file: Path, text: str) -> list[HiddenInput]:
        inputs: list[HiddenInput] = []
        for match in HIDDEN_INPUT_RE.finditer(text):
            attrs = {m.group("name"): (m.group("q") if m.group("q") is not None else m.group("braced")) for m in ATTR_RE.finditer(match.group("attrs"))}
            name = attrs.get("name")
            if not name:
                continue
            inputs.append(
                HiddenInput(
                    name=name,
                    value=attrs.get("value"),
                    file=rel_path(file, root),
                    line=line_number_for_index(text, match.start()),
                )
            )
        return inputs

    def _add_callsite(
        self,
        reachable: dict[str, ReachableAction],
        actions_by_key: dict[str, FunctionDef],
        callsite: Callsite,
    ) -> None:
        action = actions_by_key.get(callsite.action_key)
        if not action:
            return
        reachable.setdefault(callsite.action_key, ReachableAction(action=action)).callsites.append(callsite)
