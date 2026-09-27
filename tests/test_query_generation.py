from __future__ import annotations

from actiontaint.models import BoundaryModel, SourceSpec
from actiontaint.taint_model import CODEQL_JAVASCRIPT_ALL_VERSION, TaintModelGenerator


def _boundary(specs):
    return BoundaryModel(
        function="save",
        function_key="app/actions.ts::save",
        file="app/actions.ts",
        boundary_type="implicit_http_endpoint",
        client_callable=True,
        source_parameters=[spec.parameter for spec in specs],
        source_specs=specs,
        reason="used in <form action={save}>",
    )


def _spec(parameter, index, kind, expression=None):
    return SourceSpec("app/actions.ts::save", "save", "app/actions.ts", parameter, index, kind, "test", expression=expression)


def test_generated_pack_layout(tmp_path):
    specs = [_spec("formData", 0, "form_data_parameter"), _spec("$closure:params", None, "closure_route_param", "params")]
    model_path, query_path, pack_path = TaintModelGenerator().emit(tmp_path, [_boundary(specs)])
    assert model_path.is_file()
    assert (pack_path / "qlpack.yml").read_text().count(f"codeql/javascript-all: {CODEQL_JAVASCRIPT_ALL_VERSION}") == 1
    query = query_path.read_text()
    assert 'file = "app/actions.ts" and fun = "save" and idx = 0 and label = "formData"' in query
    assert 'name = "params" and label = "$closure:params"' in query


def test_query_never_matches_on_abbreviated_tostring(tmp_path):
    # CodeQL abbreviates Expr.toString() for long expressions ("prisma. ... wUnsafe"),
    # so sink/source matching must use method and callee names instead.
    _, query_path, _ = TaintModelGenerator().emit(tmp_path, [_boundary([_spec("formData", 0, "form_data_parameter")])])
    query = query_path.read_text()
    assert "toString()" not in query
    assert '"$queryRawUnsafe"' in query
    assert "SystemCommandExecution" in query


def test_empty_model_still_compiles_to_none_predicates(tmp_path):
    _, query_path, _ = TaintModelGenerator().emit(tmp_path, [])
    query = query_path.read_text()
    assert "predicate actionTaintSourceSpec(string file, string fun, int idx, string label) { none() }" in query
    assert "predicate actionTaintClosureSpec(string file, string fun, string name, string label) { none() }" in query
