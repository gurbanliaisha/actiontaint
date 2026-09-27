# Evaluation Summary

This page summarizes the archived results in [`evaluations/`](../evaluations/). The full per-artifact discussion is in [MASTER_EVALUATION_REPORT.md](../evaluations/MASTER_EVALUATION_REPORT.md). To reproduce the benchmark numbers, see [how-to-run.md](how-to-run.md#3-reproduce-the-benchmark-results).

"Default CodeQL" always means the standard `javascript-security-extended.qls` suite.

## Overview

| Evaluation | Scope | ActionTaint | Default CodeQL | Produced with |
|---|---|---|---|---|
| Synthetic benchmarks | 13 (10 vulnerable, 3 safe) | 10/10 found, 3/3 clean | 0 findings | development build |
| Complex benchmarks | 5 (4 vulnerable, 1 safe) | 4/4 found, 1/1 clean | 2/4 found | CodeQL backend |
| Seeded vulnerabilities | 4 real apps, 1 inserted flow each | 4/4 detected | no change where measured (3 of 4) | 2 × CodeQL backend, 2 × prototype backend |
| Real projects, round 1 | 5 projects | 5 triage findings (Medusa) | 0 | prototype backend |
| Real projects, round 2 | 5 large apps | 1 triage finding | 118 | prototype backend |
| Real projects, round 3 | 3 projects | 0 | 8 | CodeQL backend |
| Semgrep comparison | 5 projects | 0 | Semgrep: 3 | prototype backend |

**Provenance.** ActionTaint v0.1.0 ships only the CodeQL backend. Results marked *prototype backend* came from an earlier, lighter-weight backend that has since been removed (`"backend_used": "local"` in their JSON files). They are kept as historical evidence, and their reports carry a note saying so. The benchmark suites can be re-run with v0.1.0 using `actiontaint eval`.

## Benchmarks

### Synthetic (13)

| Benchmark | Pattern | Expected | ActionTaint | Default CodeQL |
|---|---|---|---:|---:|
| `bind_argument` | `.bind(null, searchParams.tenant)` | SQL injection | 1 | 0 |
| `file_level_sql` | file-level `"use server"` | SQL injection | 1 | 0 |
| `formdata_fetch_ssrf` | `formData.get` → `fetch` | SSRF | 1 | 0 |
| `helper_wrapper_sql` | action → helper → query | SQL injection | 1 | 0 |
| `hidden_input` | hidden form field → `fs.readFile` | Path traversal | 1 | 0 |
| `idor_prisma_delete` | `prisma.post.delete({ where: { id } })` | IDOR | 1 | 0 |
| `inline_sql` | inline `"use server"` | SQL injection | 1 | 0 |
| `object_entries_sql` | `Object.fromEntries(formData)` | SQL injection | 1 | 0 |
| `prisma_raw_unsafe` | `$queryRawUnsafe` | SQL injection | 1 | 0 |
| `use_action_state` | `useActionState` | SQL injection | 1 | 0 |
| `safe_authorized_delete` | delete with `userId` in `where` | safe | 0 | 0 |
| `safe_parameterized_query` | parameterized query | safe | 0 | 0 |
| `zod_validation` | zod, then a parameterized query | safe | 0 | 0 |

`zod_validation` is safe because of the parameterized query. Zod itself is deliberately not a sanitizer.

### Complex (5)

| Benchmark | What makes it harder | Expected | ActionTaint | Default CodeQL |
|---|---|---|---:|---:|
| `complex_order_search_sql` | `Object.fromEntries` → service → repository query builder | SQL injection | 1 | 0 |
| `tenant_document_path_traversal` | route param via `.bind`, storage helper | Path traversal | 1 | 1 |
| `project_member_idor` | hidden input, audit log, then an unguarded delete | IDOR | 1 | 0 |
| `client_preview_ssrf` | `"use client"` component calls the action directly | SSRF | 1 | 1 |
| `safe_policy_layer_update` | ownership fields in `where` (plus a policy call) | safe | 0 | 0 |

Default CodeQL reports the SSRF (`js/request-forgery`) and path traversal (`js/path-injection`) cases but not the SQL injection and IDOR cases. Default CodeQL has no IDOR query.

## Seeded experiments

An SSRF or IDOR flow, shaped like a real Server Action, was inserted into an unmodified real project. Both tools ran before and after the insertion.

| Project | Inserted flow | ActionTaint findings | Default CodeQL findings |
|---|---|---|---|
| `next-saas-stripe-starter` | SSRF | 0 → 1 | 0 → 0 |
| `dub/apps/web` | IDOR (`useActionState` + ORM delete) | 0 → 1 | 32 → 32 |
| `formbricks/apps/web` | IDOR | 0 → 1 | 4 → 4 |
| `nextjs-starter-medusa` | SSRF | 5 → 6 | not measured |

These are the clearest evidence for the framework-boundary claim: each inserted flow is detected, and default CodeQL's result set does not change.

## Real projects

| Round | Projects | Server Actions / reachable | ActionTaint | Default CodeQL |
|---|---|---|---:|---:|
| 1 | medusa, next-saas-stripe, saas-starter, nextjs-auth, postgres-next | 59 / 28 | 5 | 0 |
| 2 | saas-starter-kit, papermark, documenso, dub, formbricks | 37 / 10 | 1 | 118 |
| 3 | next-saas-stripe, next-shadcn-dashboard, skateshop | 35 / 13 | 0 | 8 |

The 6 ActionTaint findings are **triage findings**, not confirmed vulnerabilities:

- the 5 Medusa findings are medium-severity open redirects
- the saas-starter-kit finding is likely over-taint around a Stripe-generated URL

The default CodeQL findings are broad JavaScript findings. Where they were inspected (Formbricks, and all of round 3), none were Server Action flows. For example, round 3's 8 findings are all `js/file-system-race` warnings in `scripts/cleanup.js`.

The Semgrep comparison (`evaluations/static-analyzer-comparison/`) is supplementary: Semgrep's 3 findings are secret-detection hits, a different problem class. The Medusa file in that folder predates the path-alias fix (0 reachable actions, versus 22 in round 1).

## Defensible claims

1. On controlled benchmarks, ActionTaint detects client-controlled Server Action flows into SQL, SSRF, path, and IDOR sinks, and stays quiet on the safe cases. Default CodeQL misses most of them.
2. In real applications, inserted framework-shaped SSRF and IDOR flows are detected, while default CodeQL's results do not change.
3. On real projects, ActionTaint is narrow and low-noise. It complements broad scanners rather than replacing them.
4. No real-project finding has been confirmed as a production vulnerability. Present them as review targets.
