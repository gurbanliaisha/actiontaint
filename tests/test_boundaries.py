"""Framework-reconstruction facts for every paper benchmark (runs without CodeQL)."""

from __future__ import annotations

import json

import pytest

from conftest import BENCHMARKS, reconstruct

# Expected source specifications: function:parameter#index:kind
EXPECTED_SOURCES = {
    "synthetic/bind_argument": {"updateTenant:formData#1:form_data_parameter", "updateTenant:tenantId#0:bind_search_param"},
    "synthetic/file_level_sql": {"saveProfile:formData#0:form_data_parameter"},
    "synthetic/formdata_fetch_ssrf": {"previewUrl:formData#0:form_data_parameter"},
    "synthetic/helper_wrapper_sql": {"searchUsers:formData#0:form_data_parameter"},
    "synthetic/hidden_input": {"readAttachment:formData#0:form_data_parameter"},
    "synthetic/idor_prisma_delete": {"deletePost:formData#0:form_data_parameter"},
    "synthetic/inline_sql": {"createPost:formData#0:form_data_parameter"},
    "synthetic/object_entries_sql": {"inviteUser:formData#0:form_data_parameter"},
    "synthetic/prisma_raw_unsafe": {"searchUsers:formData#0:form_data_parameter"},
    "synthetic/safe_authorized_delete": {"deletePost:formData#0:form_data_parameter"},
    "synthetic/safe_parameterized_query": {"saveProfile:formData#0:form_data_parameter"},
    "synthetic/use_action_state": {"createUser:formData#1:form_data_parameter"},
    "synthetic/zod_validation": {"saveProfile:formData#0:form_data_parameter"},
    "complex/client_preview_ssrf": {"refreshPreview:input#0:client_argument"},
    "complex/complex_order_search_sql": {"searchOrders:formData#1:form_data_parameter"},
    "complex/project_member_idor": {"removeMember:formData#0:form_data_parameter"},
    "complex/safe_policy_layer_update": {
        "renameTask:formData#1:form_data_parameter",
        "renameTask:workspaceId#0:bind_route_param",
    },
    "complex/tenant_document_path_traversal": {
        "downloadTenantDocument:formData#1:form_data_parameter",
        "downloadTenantDocument:tenantId#0:bind_route_param",
    },
}


def test_every_benchmark_is_covered():
    on_disk = {f"{p.parent.parent.name}/{p.parent.name}" for p in BENCHMARKS.glob("*/*/expected.json")}
    assert on_disk == set(EXPECTED_SOURCES)


@pytest.mark.parametrize("benchmark", sorted(EXPECTED_SOURCES))
def test_benchmark_boundaries(benchmark, parser):
    target = BENCHMARKS / benchmark
    expected = json.loads((target / "expected.json").read_text(encoding="utf-8"))
    functions, reachable, boundaries, _ = reconstruct(target, parser)

    assert sum(fn.server_action for fn in functions) == expected["expected_actions"]
    assert len(reachable) == expected["expected_reachable"]
    sources = {
        f"{spec.function_name}:{spec.parameter}#{spec.index}:{spec.kind}"
        for boundary in boundaries
        for spec in boundary.source_specs
    }
    assert sources == EXPECTED_SOURCES[benchmark]
    for boundary in boundaries:
        assert boundary.boundary_type == "implicit_http_endpoint"
        assert boundary.reason
