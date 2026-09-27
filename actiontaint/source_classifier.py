from __future__ import annotations

import re

from .models import BoundaryModel, Callsite, FunctionDef, ReachableAction, SourceSpec
from .utils import is_literal_expr


class SourceClassifier:
    """Classifies which values cross the reconstructed Server Action boundary."""

    def build_boundary(self, reachable: ReachableAction) -> BoundaryModel:
        action = reachable.action
        callsites = reachable.callsites
        source_specs: list[SourceSpec] = []
        input_semantics: dict = {
            "callsite_reasons": [callsite.reason for callsite in callsites],
            "hidden_inputs": [
                {
                    "name": hidden.name,
                    "value": hidden.value,
                    "file": hidden.file,
                    "line": hidden.line,
                }
                for callsite in callsites
                for hidden in callsite.hidden_inputs
            ],
            "bind_arguments": [],
        }

        max_bind_args = max((len(callsite.bind_args) for callsite in callsites), default=0)
        for callsite in callsites:
            for offset, bind_arg in enumerate(callsite.bind_args):
                classification, reason = self._classify_bind_arg(bind_arg.expr, callsite)
                bind_arg.classification = classification
                bind_arg.reason = reason
                param = action.params[offset] if offset < len(action.params) else None
                input_semantics["bind_arguments"].append(
                    {
                        "expression": bind_arg.expr,
                        "classification": classification,
                        "target_parameter": param.name if param else f"$bind{offset}",
                        "reason": reason,
                    }
                )
                if classification != "trusted":
                    source_specs.append(
                        self._source_spec(
                            action,
                            param.name if param else f"$bind{offset}",
                            param.index if param else offset,
                            f"bind_{classification}",
                            reason,
                            confidence="high" if classification in {"route_param", "search_param", "form_data_derived"} else "medium",
                            expression=bind_arg.expr,
                        )
                    )

        has_form_callsite = any(c.kind in {"form_action", "button_form_action", "useActionState", "useFormState"} for c in callsites)
        has_state_hook = any(c.kind in {"useActionState", "useFormState"} for c in callsites)
        formdata_indices = self._formdata_param_indices(action)
        for index in formdata_indices:
            param = action.params[index]
            if self._already_specified(source_specs, index):
                continue
            source_specs.append(
                self._source_spec(
                    action,
                    param.name,
                    index,
                    "form_data_parameter",
                    f"{param.name} is a FormData parameter of a client-reachable Server Action",
                    confidence="high",
                )
            )

        if has_form_callsite and not formdata_indices and action.params:
            guessed_index = min(max_bind_args + (1 if has_state_hook and len(action.params) > max_bind_args + 1 else 0), len(action.params) - 1)
            if not self._already_specified(source_specs, guessed_index):
                param = action.params[guessed_index]
                source_specs.append(
                    self._source_spec(
                        action,
                        param.name,
                        guessed_index,
                        "inferred_form_data_parameter",
                        "parameter inferred as form payload because the action is used as a form action",
                        confidence="medium",
                    )
                )

        if any(c.kind == "client_direct_call" for c in callsites):
            for param in action.params[max_bind_args:]:
                if not self._already_specified(source_specs, param.index):
                    source_specs.append(
                        self._source_spec(
                            action,
                            param.name,
                            param.index,
                            "client_argument",
                            "parameter is callable from a 'use client' component",
                            confidence="medium",
                        )
                    )

        for closure_name, kind in self._closure_sources(action):
            source_specs.append(
                self._source_spec(
                    action,
                    f"$closure:{closure_name}",
                    None,
                    kind,
                    f"Server Action closes over client-controlled {closure_name}",
                    confidence="medium",
                    expression=closure_name,
                )
            )

        source_parameters = []
        seen = set()
        for spec in source_specs:
            if spec.parameter not in seen:
                source_parameters.append(spec.parameter)
                seen.add(spec.parameter)

        return BoundaryModel(
            function=action.name,
            function_key=action.key,
            file=action.rel_path,
            boundary_type="implicit_http_endpoint",
            client_callable=True,
            source_parameters=source_parameters,
            source_specs=source_specs,
            reason="; ".join(reachable.reasons),
            input_semantics=input_semantics,
        )

    def _formdata_param_indices(self, action: FunctionDef) -> list[int]:
        indices: list[int] = []
        for param in action.params:
            type_hint = param.type_hint or ""
            if "FormData" in type_hint or param.name.lower() in {"formdata", "form", "fd"}:
                indices.append(param.index)
        return indices

    def _classify_bind_arg(self, expr: str, callsite: Callsite) -> tuple[str, str]:
        compact = expr.strip()
        if is_literal_expr(compact):
            return "trusted", "literal bind argument"
        if re.search(r"\bsearchParams\b|URLSearchParams", compact):
            return "search_param", "bind argument is derived from route search params"
        if re.search(r"\bparams\b", compact):
            return "route_param", "bind argument is derived from route params"
        if re.search(r"\bformData\b|\.get\s*\(", compact):
            return "form_data_derived", "bind argument is derived from form data"
        if re.search(r"\b(session|auth|currentUser)\b", compact):
            return "trusted", "bind argument appears to come from server-side auth/session state"
        if re.search(r"\b(cookies|headers)\s*\(", compact):
            return "request_metadata", "bind argument is derived from client-controlled request metadata"
        if callsite.rel_path.endswith((".tsx", ".jsx")):
            return "possibly_tainted", "non-literal bind argument in a UI component"
        return "possibly_tainted", "non-literal bind argument"

    def _closure_sources(self, action: FunctionDef) -> list[tuple[str, str]]:
        sources: list[tuple[str, str]] = []
        # Only inline actions nested in a page/component can capture its searchParams/params props.
        if action.directive_kind != "inline":
            return sources
        if re.search(r"\bsearchParams\b", action.body):
            sources.append(("searchParams", "closure_search_param"))
        if re.search(r"\bparams\b", action.body):
            sources.append(("params", "closure_route_param"))
        return sources

    def _source_spec(
        self,
        action: FunctionDef,
        parameter: str,
        index: int | None,
        kind: str,
        reason: str,
        confidence: str = "medium",
        expression: str | None = None,
    ) -> SourceSpec:
        return SourceSpec(
            function_key=action.key,
            function_name=action.name,
            file=action.rel_path,
            parameter=parameter,
            index=index,
            kind=kind,
            reason=reason,
            confidence=confidence,
            expression=expression,
        )

    def _already_specified(self, specs: list[SourceSpec], index: int | None) -> bool:
        return any(spec.index == index for spec in specs)
