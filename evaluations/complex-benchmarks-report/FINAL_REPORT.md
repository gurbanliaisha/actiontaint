# Complex Benchmark Comparison Report

Generated: 2026-05-30

Scope: 5 complex Next.js Server Action benchmarks under `benchmarks/`. Each benchmark was tested with ActionTaint using its generated CodeQL backend and with default CodeQL `javascript-security-extended.qls`.

## Commands

- ActionTaint: `python -B -m actiontaint scan <benchmark> --backend codeql --format json --output <out>/actiontaint.json --model-dir <out>/actiontaint-model`
- Default CodeQL: `codeql database create <db> --language=javascript-typescript --source-root=<benchmark> --overwrite`, then `codeql database analyze <db> javascript-security-extended.qls --format=sarif-latest --output=<out>/default-codeql.sarif`

## Summary

| Benchmark | Expected | ActionTaint actions | ActionTaint reachable | ActionTaint findings | Default CodeQL findings | Result |
|---|---:|---:|---:|---:|---:|---|
| `complex_order_search_sql` | SQL Injection | 1 | 1 | 1 | 0 | matches expected |
| `tenant_document_path_traversal` | Path Traversal | 1 | 1 | 1 | 1 | matches expected |
| `project_member_idor` | Broken Authorization / IDOR | 1 | 1 | 1 | 0 | matches expected |
| `client_preview_ssrf` | SSRF | 1 | 1 | 1 | 1 | matches expected |
| `safe_policy_layer_update` | 0 findings | 1 | 1 | 0 | 0 | matches expected |

## ActionTaint Findings

### complex_order_search_sql

- Server actions discovered: 1
- Client-reachable actions: 1
- Findings: 1
- [HIGH] SQL Injection
  - Source: `app/actions.ts::searchOrders(formData)`
  - Sink: `app/order-repository.ts:16`
  - Rule: `js/actiontaint/generated-server-action-taint`
  - Taint path:
    - `app/actions.ts:6 Object. ... rmData)`
    - `app/actions.ts:6 payload`
    - `app/actions.ts:7 payload`
    - `app/actions.ts:7 String( ...  ?? "")`
    - `app/actions.ts:7 tenantId`
    - `app/actions.ts:11 tenantId`
    - `app/actions.ts:11 { tenan ... tatus } [tenantId]`
    - `app/order-service.ts:3 input [tenantId]`
    - `app/order-service.ts:10 input [tenantId]`
    - `app/order-service.ts:10 input.tenantId`
    - `app/order-service.ts:9 {\n    t ... tus\n  }`
    - `app/order-repository.ts:9 filters`
    - `app/order-repository.ts:11 filters`
    - `app/order-repository.ts:11 `tenant ... ntId}'``
    - `app/order-repository.ts:10 [\n    ` ... ')`\n  ] [0]`
    - `app/order-repository.ts:10 [\n    ` ...  AND ")`
    - `app/order-repository.ts:10 where`
    - `app/order-repository.ts:16 where`
    - `app/order-repository.ts:16 `SELECT ... t DESC``
    - `app/actions.ts:6 Object. ... rmData)`
    - `app/actions.ts:6 payload`
    - `app/actions.ts:8 payload`
    - `app/actions.ts:8 String( ...  ?? "")`
    - `app/actions.ts:8 term`
    - `app/actions.ts:11 term`
    - `app/actions.ts:11 { tenan ... tatus }`
    - `app/order-service.ts:3 input`
    - `app/order-service.ts:11 input`
    - `app/order-service.ts:11 input.term.trim()`
    - `app/order-service.ts:9 {\n    t ... tus\n  } [term]`
    - `app/order-repository.ts:9 filters [term]`
    - `app/order-repository.ts:13 filters [term]`
    - `app/order-repository.ts:13 filters.term`
    - `app/order-repository.ts:13 `(custo ... rm}%')``
    - `app/order-repository.ts:10 [\n    ` ... ')`\n  ] [2]`
    - `app/order-repository.ts:10 [\n    ` ...  AND ")`
    - `app/order-repository.ts:10 where`
    - `app/order-repository.ts:16 where`
    - `app/order-repository.ts:16 `SELECT ... t DESC``
    - `app/actions.ts:6 Object. ... rmData)`
    - `app/actions.ts:6 payload`
    - `app/actions.ts:9 payload`
    - `app/actions.ts:9 String( ... "open")`
    - `app/actions.ts:9 status`
    - `app/actions.ts:11 status`
    - `app/actions.ts:11 { tenan ... tatus } [status]`
    - `app/order-service.ts:3 input [status]`
    - `app/order-service.ts:8 input [status]`
    - `app/order-service.ts:8 input.status`
    - `app/order-service.ts:8 input.status.trim()`
    - `app/order-service.ts:8 input.s ... rCase()`
    - `app/order-service.ts:8 normalizedStatus`
    - `app/order-service.ts:12 normalizedStatus`
    - `app/order-service.ts:9 {\n    t ... tus\n  } [status]`
    - `app/order-repository.ts:9 filters [status]`
    - `app/order-repository.ts:12 filters [status]`
    - `app/order-repository.ts:12 filters.status`
    - `app/order-repository.ts:12 `status ... atus}'``
    - `app/order-repository.ts:10 [\n    ` ... ')`\n  ] [1]`
    - `app/order-repository.ts:10 [\n    ` ...  AND ")`
    - `app/order-repository.ts:10 where`
    - `app/order-repository.ts:16 where`
    - `app/order-repository.ts:16 `SELECT ... t DESC``
    - `app/actions.ts:6 Object. ... rmData)`
    - `app/actions.ts:6 payload`
    - `app/actions.ts:7 payload`
    - `app/actions.ts:7 String( ...  ?? "")`
    - `app/actions.ts:7 tenantId`
    - `app/actions.ts:11 tenantId`
    - `app/actions.ts:11 { tenan ... tatus }`
    - `app/order-service.ts:3 input`
    - `app/order-service.ts:10 input`
    - `app/order-service.ts:10 input.tenantId`
    - `app/order-service.ts:9 {\n    t ... tus\n  } [tenantId]`
    - `app/order-repository.ts:9 filters [tenantId]`
    - `app/order-repository.ts:11 filters [tenantId]`
    - `app/order-repository.ts:11 filters.tenantId`
    - `app/order-repository.ts:11 `tenant ... ntId}'``
    - `app/order-repository.ts:10 [\n    ` ... ')`\n  ] [0]`
    - `app/order-repository.ts:10 [\n    ` ...  AND ")`
    - `app/order-repository.ts:10 where`
    - `app/order-repository.ts:16 where`
    - `app/order-repository.ts:16 `SELECT ... t DESC``
- Reconstructed client-reachable boundaries:
  - `app/actions.ts::searchOrders` sources: `formData`

### tenant_document_path_traversal

- Server actions discovered: 1
- Client-reachable actions: 1
- Findings: 1
- [HIGH] Path Traversal
  - Source: `app/actions.ts::downloadTenantDocument(tenantId)`
  - Sink: `app/storage.ts:5`
  - Rule: `js/actiontaint/generated-server-action-taint`
  - Taint path:
    - `app/actions.ts:5 tenantId`
    - `app/actions.ts:7 tenantId`
    - `app/storage.ts:3 tenantId`
    - `app/storage.ts:4 tenantId`
    - `app/storage.ts:4 path`
    - `app/storage.ts:5 path`
    - `app/actions.ts:6 formDat ... ument")`
    - `app/actions.ts:6 documentName`
    - `app/actions.ts:7 documentName`
    - `app/storage.ts:3 documentName`
    - `app/storage.ts:4 documentName`
    - `app/storage.ts:4 path`
    - `app/storage.ts:5 path`
- Reconstructed client-reachable boundaries:
  - `app/actions.ts::downloadTenantDocument` sources: `tenantId, formData`

### project_member_idor

- Server actions discovered: 1
- Client-reachable actions: 1
- Findings: 1
- [HIGH] Broken Authorization / IDOR
  - Source: `app/actions.ts::removeMember(formData)`
  - Sink: `app/actions.ts:18`
  - Rule: `js/actiontaint/generated-server-action-taint`
  - Taint path:
    - `app/actions.ts:8 formDat ... berId")`
    - `app/actions.ts:8 memberId`
    - `app/actions.ts:20 memberId`
    - `app/actions.ts:19 {\n      ... d\n    }`
    - `app/actions.ts:18 {\n    w ...   }\n  }`
- Reconstructed client-reachable boundaries:
  - `app/actions.ts::removeMember` sources: `formData`

### client_preview_ssrf

- Server actions discovered: 1
- Client-reachable actions: 1
- Findings: 1
- [HIGH] SSRF
  - Source: `app/actions.ts::refreshPreview(input)`
  - Sink: `app/http.ts:2`
  - Rule: `js/actiontaint/generated-server-action-taint`
  - Taint path:
    - `app/actions.ts:5 input`
    - `app/actions.ts:6 input`
    - `app/actions.ts:6 input.url`
    - `app/http.ts:1 url`
    - `app/http.ts:2 url`
- Reconstructed client-reachable boundaries:
  - `app/actions.ts::refreshPreview` sources: `input`

### safe_policy_layer_update

- Server actions discovered: 1
- Client-reachable actions: 1
- Findings: 0
- No ActionTaint findings.
- Reconstructed client-reachable boundaries:
  - `app/actions.ts::renameTask` sources: `workspaceId, formData`

## Default CodeQL Findings

### complex_order_search_sql

- Findings: 0
- No default CodeQL findings.

### tenant_document_path_traversal

- Findings: 1
- `js/path-injection` at `app/storage.ts:5`: This path depends on a [user-provided value](1).

### project_member_idor

- Findings: 0
- No default CodeQL findings.

### client_preview_ssrf

- Findings: 1
- `js/request-forgery` at `app/http.ts:2`: The [URL](1) of this request depends on a [user-provided value](2).

### safe_policy_layer_update

- Findings: 0
- No default CodeQL findings.

## Interpretation

- ActionTaint found all 4 intentionally vulnerable framework-aware Server Action flows and correctly produced 0 findings for the safe policy-layer update benchmark.
- Default CodeQL produced 2 findings across these 5 benchmarks: `js/path-injection` for `tenant_document_path_traversal` and `js/request-forgery` for `client_preview_ssrf`. It missed the SQL injection and IDOR cases that ActionTaint reported, while matching the safe benchmark with 0 findings.
- ActionTaint still uses CodeQL as the taint backend; the difference is that ActionTaint generates the Server Action source model and sink query pack before CodeQL solves the flow. In this benchmark set, that framework model adds coverage for the SQL and IDOR cases.

## Artifacts

- `complex_order_search_sql`: `evaluations/complex-benchmarks-report/complex_order_search_sql/actiontaint.json`, `evaluations/complex-benchmarks-report/complex_order_search_sql/default-codeql.sarif`
- `tenant_document_path_traversal`: `evaluations/complex-benchmarks-report/tenant_document_path_traversal/actiontaint.json`, `evaluations/complex-benchmarks-report/tenant_document_path_traversal/default-codeql.sarif`
- `project_member_idor`: `evaluations/complex-benchmarks-report/project_member_idor/actiontaint.json`, `evaluations/complex-benchmarks-report/project_member_idor/default-codeql.sarif`
- `client_preview_ssrf`: `evaluations/complex-benchmarks-report/client_preview_ssrf/actiontaint.json`, `evaluations/complex-benchmarks-report/client_preview_ssrf/default-codeql.sarif`
- `safe_policy_layer_update`: `evaluations/complex-benchmarks-report/safe_policy_layer_update/actiontaint.json`, `evaluations/complex-benchmarks-report/safe_policy_layer_update/default-codeql.sarif`

