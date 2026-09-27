# ActionTaint Real Open-Source Project Evaluation

> **Provenance note (v0.1.0 release):** the ActionTaint results in this report were produced by an earlier prototype *local* backend that is not shipped in v0.1.0 (the CLI now accepts only `--backend codeql`). The numbers are kept as historical evidence; the `--backend local` commands below are not runnable with this release. Re-running with `--backend codeql` requires local checkouts of the upstream projects listed in `datasets/real-projects.json`.

Date: 2026-05-22  
Original evaluation layout: local external project checkouts matching the paths listed in `datasets/real-projects.json`  
Analyzer: ActionTaint prototype with TypeScript compiler API parser and local taint backend  
Baseline: Default CodeQL JavaScript security suite

## Purpose

This report evaluates ActionTaint on five real Next.js open-source projects drawn from a local workspace of external checkouts. The goal is to test whether the tool behaves realistically outside synthetic benchmarks: it should discover Server Actions, reconstruct client reachability, avoid reporting safe flows, and produce useful triage findings when client-controlled Server Action inputs reach dangerous sinks.

The projects were selected to cover high, medium, and low complexity levels based on source file count, Next.js version, and Server Action surface.

## Tool Configuration

Historical ActionTaint command pattern used for this round:

```powershell
python -B -m actiontaint scan <project> --parser typescript --backend local --format json --output evaluations\open-source-real\<project>-actiontaint.json --model-dir <generated-model-dir>
```

Historical default CodeQL command pattern used for this round:

```powershell
$env:CODEQL_ALLOW_INSTALLATION_ANYWHERE = "true"
$codeql = "<codeql-executable>"
$suite = "javascript-security-extended.qls"

& $codeql database create <db> --language=javascript-typescript --source-root=<project> --overwrite --quiet
& $codeql database analyze <db> $suite --format=sarif-latest --output=<project>.sarif --quiet
```

ActionTaint parser used: `typescript-compiler-api 5.9.3`  
CodeQL version used: `2.25.4`  
CodeQL suite used: `javascript-security-extended.qls`

## Project Selection

| Project | Complexity level | Reason |
|---|---:|---|
| `nextjs-starter-medusa` | High | 207 source files, e-commerce/storefront app, 48 discovered Server Actions |
| `next-saas-stripe-starter` | High | 189 source files, SaaS/Stripe/Prisma/Auth stack, 4 discovered Server Actions |
| `saas-starter` | Medium | 41 source files, SaaS/auth/billing app, 1 discovered Server Action |
| `nextjs-auth-starter` | Medium/Low | 23 source files, auth/posts example app, 4 discovered Server Actions |
| `postgres-next-starter` | Low | 12 source files, compact todo/database starter, 2 discovered Server Actions |

## Summary Results

| Project | Next.js version | Source files | Server Actions | Client-reachable Actions | ActionTaint findings | Default CodeQL findings |
|---|---:|---:|---:|---:|---:|---:|
| `nextjs-starter-medusa` | `15.3.9` | 207 | 48 | 22 | 5 | 0 |
| `next-saas-stripe-starter` | `14.2.5` | 189 | 4 | 0 | 0 | 0 |
| `saas-starter` | `15.6.0-canary.59` | 41 | 1 | 1 | 0 | 0 |
| `nextjs-auth-starter` | `16.0.7` | 23 | 4 | 3 | 0 | 0 |
| `postgres-next-starter` | `^15.6.0-canary.58` | 12 | 2 | 2 | 0 | 0 |

Overall:

| Tool | Total Server Actions Observed | Total Client-Reachable Actions | Total Findings |
|---|---:|---:|---:|
| ActionTaint | 59 | 28 | 5 |
| Default CodeQL | N/A | N/A | 0 |

## ActionTaint Findings

All five findings were reported in `nextjs-starter-medusa`. They are Medium severity open redirect triage findings. These should be interpreted as candidate issues requiring manual validation, not automatically as confirmed exploitable vulnerabilities.

| ID | Severity | Type | Source | Sink | Taint path summary | Manual triage note |
|---|---|---|---|---|---|---|
| M-1 | Medium | Open Redirect | `src/lib/data/cart.ts::placeOrder(cartId)` | `src/lib/data/cart.ts:414 redirect(...)` | `cartId -> cartId || getCartId() -> id -> redirect(...)` | May be a false positive if `cartRes.order.shipping_address.country_code` is controlled by the backend and constrained to valid country codes. Review whether a user can influence the country code into a protocol-relative path such as `//host`. |
| M-2 | Medium | Open Redirect | `src/lib/data/cart.ts::setAddresses(formData)` | `src/lib/data/cart.ts:384 redirect(...)` | `formData -> formData.get("shipping_address.country_code") -> redirect(...)` | More interesting: `shipping_address.country_code` comes from submitted form data and is interpolated into the redirect path. Should be allowlisted against supported regions/countries. |
| M-3 | Medium | Open Redirect | `src/lib/data/cart.ts::updateRegion(countryCode)` | `src/lib/data/cart.ts:453 redirect(...)` | `countryCode -> redirect(\`/${countryCode}${currentPath}\`)` | Needs validation that `countryCode` is restricted to known locale/country values and cannot contain slash-like payloads. |
| M-4 | Medium | Open Redirect | `src/lib/data/customer.ts::signout(countryCode)` | `src/lib/data/customer.ts:143 redirect(...)` | `countryCode -> redirect(\`/${countryCode}/account\`)` | Similar to M-3. Likely safe if `countryCode` is always route-derived and normalized, but ActionTaint correctly asks for the trust boundary to be checked. |
| M-5 | Medium | Open Redirect | `src/lib/data/onboarding.ts::resetOnboardingState(orderId)` | `src/lib/data/onboarding.ts:8 redirect(...)` | `orderId -> redirect(\`http://localhost:7001/a/orders/${orderId}\`)` | This is an absolute redirect to localhost/admin-like path. It may be development-only onboarding logic, but in production-like code this deserves review. |

## Per-Project Observations

### `nextjs-starter-medusa`

ActionTaint found 48 Server Actions and 22 client-reachable actions after resolving real-world TypeScript path aliases such as `@lib/*` and `@modules/*`. This project is the strongest real-world validation target because it uses imported Server Actions, `useActionState`, form actions, e-commerce state transitions, and redirect-heavy flows.

ActionTaint produced 5 open redirect triage findings. Default CodeQL produced 0 findings. The difference is consistent with the benchmark result: CodeQL does not reconstruct Next.js Server Action reachability as a framework boundary, while ActionTaint does.

Important caveat: the reported redirects need manual validation against application-level country/locale validation. Some may be false positives if upstream route parameters are strongly constrained.

### `next-saas-stripe-starter`

ActionTaint found 4 Server Actions and 0 client-reachable actions under the currently modeled reachability patterns. No findings were reported. Default CodeQL also reported 0 findings.

This does not prove the project is vulnerability-free. It means ActionTaint did not find supported dangerous sink flows from a client-reachable Server Action boundary. The project should still be manually reviewed for indirect invocation patterns, API routes, middleware, and auth/business-logic bugs outside the Server Action model.

### `saas-starter`

ActionTaint found 1 Server Action and 1 client-reachable action: `app/(login)/actions.ts::signOut`. The action has no untrusted `FormData` source and no supported dangerous sink flow. No findings were reported. Default CodeQL also reported 0 findings.

### `nextjs-auth-starter`

ActionTaint found 4 Server Actions and 3 client-reachable actions:

- `app/posts/[id]/page.tsx::deletePost`
- `app/posts/new/actions.ts::createPost`
- `app/users/new/page.tsx::createUser`

No supported taint flow to SQL, SSRF, redirect, path traversal, command injection, or IDOR sink was reported. Default CodeQL also reported 0 findings.

### `postgres-next-starter`

ActionTaint found 2 Server Actions and 2 client-reachable actions:

- `app/actions.ts::addTodo`
- `app/actions.ts::deleteTodo`

No findings were reported. Default CodeQL also reported 0 findings. This is a useful low-complexity sanity check because the tool recognizes `useActionState` reachability but does not report a vulnerability when no dangerous sink flow exists.

## Interpretation

The open-source test is useful because it shows two things:

1. ActionTaint does not simply report vulnerabilities everywhere. Four of the five real projects produced zero findings, even when Server Actions were found and some were client-reachable.
2. On the largest project, ActionTaint found framework-specific redirect flows that Default CodeQL did not report.

This supports the paper's core claim: framework-aware boundary reconstruction can surface review targets that a general JavaScript analyzer may miss.

However, these real-project findings should not be overstated. They are not confirmed CVEs. They are triage findings that require manual validation of route constraints, country-code allowlists, deployment mode, and whether inputs can actually contain redirect-breaking values.

## Important Tool Improvement From This Test

The first real-project scan revealed a practical weakness: many production Next.js projects use TypeScript path aliases such as `@lib/*`, `@modules/*`, or `@/*`. Without resolving those aliases, the tool can discover Server Actions but fail to link them to client callsites.

ActionTaint was upgraded during this evaluation to resolve:

- `@/*` mapped to project root
- `@/*` mapped to `src/*`
- `tsconfig.json` / `jsconfig.json` `compilerOptions.baseUrl`
- `tsconfig.json` / `jsconfig.json` `compilerOptions.paths`

This upgrade changed `nextjs-starter-medusa` from 0 client-reachable actions to 22 client-reachable actions, showing why path alias support is essential for real-world analysis.

## Limitations

- The ActionTaint findings are static triage results, not runtime exploit proofs.
- The local backend is intentionally lightweight compared with a full CodeQL data-flow run.
- Default CodeQL was run with the standard `javascript-security-extended.qls` suite only; it was not given ActionTaint's generated Server Action source model.
- The current open redirect model is conservative and can flag values that are actually constrained elsewhere.
- The tool currently focuses on Server Action flows into a selected set of sinks. API routes, middleware, client-side vulnerabilities, secrets, dependency issues, and many business-logic bugs are outside this report.

## Artifacts

ActionTaint JSON reports:

- `evaluations/open-source-real/nextjs-starter-medusa-actiontaint.json`
- `evaluations/open-source-real/next-saas-stripe-starter-actiontaint.json`
- `evaluations/open-source-real/saas-starter-actiontaint.json`
- `evaluations/open-source-real/nextjs-auth-starter-actiontaint.json`
- `evaluations/open-source-real/postgres-next-starter-actiontaint.json`

Default CodeQL SARIF reports:

- `evaluations/open-source-real/codeql-baseline/nextjs-starter-medusa.sarif`
- `evaluations/open-source-real/codeql-baseline/next-saas-stripe-starter.sarif`
- `evaluations/open-source-real/codeql-baseline/saas-starter.sarif`
- `evaluations/open-source-real/codeql-baseline/nextjs-auth-starter.sarif`
- `evaluations/open-source-real/codeql-baseline/postgres-next-starter.sarif`

## Conclusion

This real-project evaluation strengthens the ActionTaint paper story. The benchmark suite demonstrates recall on controlled vulnerable Server Action patterns, while the open-source evaluation shows that the tool can scale to real project structures, handle path aliases, identify client-reachable Server Actions, and produce realistic security review findings without flooding every project with alerts.

The strongest claim from this evaluation is not that ActionTaint found confirmed production vulnerabilities. The stronger and more defensible claim is that ActionTaint reconstructs Next.js Server Action trust boundaries that default CodeQL does not model, and this enables it to surface framework-specific taint flows in real Next.js code.
