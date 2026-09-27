# ActionTaint

**Framework-aware taint analysis for Next.js Server Actions.**

A Next.js Server Action looks like an ordinary async function, but the framework exposes it as an HTTP endpoint that any client can call with arbitrary input. General-purpose JavaScript analyzers do not see that boundary, so they do not treat the action's inputs as attacker-controlled.

ActionTaint reconstructs the boundary:

1. it finds Server Actions and proves they are reachable from the client,
2. it marks their client-controlled inputs as taint sources,
3. it generates a CodeQL query from those facts and lets CodeQL's taint tracking find flows into dangerous sinks.

```text
Next.js project ─► find Server Actions ─► link to client call sites ─► classify untrusted inputs
                                                                              │
     report (CLI / JSON / SARIF / CSV / HTML) ◄─ CodeQL taint tracking ◄─ generated CodeQL query pack
```

## Quick start

Requirements: Python 3.10+, Node.js, and the [CodeQL CLI](https://github.com/github/codeql-cli-binaries/releases).

```bash
git clone <this-repo> && cd actiontaint
python -m pip install -e .
npm ci                                              # TypeScript compiler used by the parser
export ACTIONTAINT_CODEQL=/path/to/codeql/codeql    # PowerShell: $env:ACTIONTAINT_CODEQL = 'C:\path\to\codeql.exe'

python -m actiontaint scan benchmarks/synthetic/formdata_fetch_ssrf
```

Expected output (abridged):

```text
Server Actions: 1 | Client-reachable: 1 | Findings: 1

[HIGH] SSRF
Source: app/actions.ts::previewUrl(formData)
Sink: app/actions.ts:5 await fetch(target);
```

The first scan downloads the pinned CodeQL library (`codeql/javascript-all` 2.7.0), so it needs network access once. A scan takes about 1–2 minutes, mostly CodeQL database creation and query compilation.

## What it detects

| Vulnerability | Sinks | Severity |
|---|---|---|
| SQL injection | `.query()`, `.execute()`, `$queryRawUnsafe()`, `$executeRawUnsafe()`, `sql.raw()` | HIGH |
| SSRF | `fetch()`, `axios()`, `axios.get/post/put/patch/delete/head/request()`, `got()` | HIGH |
| Open redirect | `redirect()`, `permanentRedirect()`, `NextResponse.redirect()` | MEDIUM |
| Path traversal | `readFile`, `writeFile`, `unlink`, `createReadStream` (and sync variants) | HIGH |
| Command injection | `child_process` APIs (as modelled by CodeQL), `execa()` | CRITICAL |
| Broken authorization / IDOR | Prisma-style `model.update/delete/upsert(...)` and Supabase `from(t).delete()/update().eq(...)` with no ownership field (`userId`, `ownerId`, `tenantId`, `orgId`, `workspaceId`, ...) | HIGH |

Precision rules that avoid common false positives:

- parameterized queries in object form (`pool.query({ text, values })`) are not SQL sinks
- `fetch("https://fixed.host/" + id)` and `redirect("/posts/" + id)` are not reported, because the client cannot choose the host
- `RegExp.prototype.exec`, `Map.delete`, `cookies().delete`, and `searchParams.delete` are not sinks
- an ownership field is recognized inline or in an object assigned to a variable first (`const where = { id, userId }`)

Validation such as `zod.parse()` is **not** treated as a sanitizer: a well-typed value can still be unsafe in SQL, URLs, paths, or shell commands. Calls whose names contain `assertAllowed`, `allowlist`, `isAllowedHost`, `assertInternalUrl`, `assertRelativePath`, or `trustedServerValue` act as barriers.

## What it understands about Next.js

**Server Actions:** file-level `"use server"` (exported async functions, arrow functions, `export default`, `export { fn }`), and inline `"use server"` inside async functions.

**Client reachability:** `<form action>`, `<button formAction>`, `useActionState` / `useFormState`, `.bind(null, ...)`, action props passed to components, and direct calls from `"use client"` files. It handles named, default, and namespace imports, plus `tsconfig.json` path aliases (`@/*`, `@lib/*`, ...).

**Untrusted inputs:**

- `FormData` parameters, `formData.get()`, and `Object.fromEntries(formData)`
- non-literal `.bind()` arguments (from `searchParams`, `params`, form data, cookies/headers)
- arguments passed from client components
- `searchParams` / `params` captured by inline actions

Server-side values such as `session`, `auth()`, and `currentUser` bound into an action are treated as trusted.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | analysis completed, no findings |
| `1` | analysis completed, findings reported |
| `2` | analysis did **not** complete (target missing, CodeQL not found, or a CodeQL step failed) |

A run that could not analyze the code is never reported as clean, which makes ActionTaint safe to use as a CI gate.

## Evaluation

| Suite | Cases | ActionTaint | Default CodeQL (`javascript-security-extended`) |
|---|---|---|---|
| Synthetic benchmarks | 10 vulnerable, 3 safe | 10/10 found, 0 false positives | 0/10 found |
| Complex benchmarks | 4 vulnerable, 1 safe | 4/4 found, 0 false positives | 2/4 found |
| Seeded vulnerabilities in real apps (Dub, Formbricks, next-saas-stripe, Medusa) | 4 inserted SSRF/IDOR flows | 4/4 found | no new findings where measured |
| Real open-source projects | 13 scans of 12 projects | 6 triage findings in total | 126 general JavaScript findings |

These are the archived results in [`evaluations/`](evaluations/). Some real-world and seeded runs were made with an earlier prototype backend; [docs/evaluation-summary.md](docs/evaluation-summary.md) says which ones, and gives per-project numbers and how to interpret them.

Reproduce the benchmark suites (about 1 minute per benchmark for ActionTaint, 1.5 minutes for default CodeQL):

```bash
python -m actiontaint eval benchmarks/synthetic --tools actiontaint,codeql
python -m actiontaint eval benchmarks/complex --tools actiontaint,codeql
```

## Repository layout

```text
actiontaint/            the tool (Python package + TypeScript AST extractor)
benchmarks/synthetic/   13 micro-benchmarks, each with expected.json
benchmarks/complex/     5 project-like benchmarks
tests/                  unit tests and a regression fixture (python -m pytest)
evaluations/            archived evaluation results (JSON / SARIF / reports)
datasets/               inventory of benchmarks, real projects, and seeded experiments
docs/                   documentation
```

## Documentation

| Document | Contents |
|---|---|
| [docs/how-to-run.md](docs/how-to-run.md) | installation, scanning, reproducing the evaluation, tests |
| [docs/cli-reference.md](docs/cli-reference.md) | every command and option |
| [docs/architecture.md](docs/architecture.md) | pipeline, module map, generated query design |
| [docs/threat-model.md](docs/threat-model.md) | attacker model, scope, what a finding means |
| [docs/evaluation-summary.md](docs/evaluation-summary.md) | results and how to interpret them |

## Limitations

- ActionTaint analyzes Server Actions only. Route handlers, API routes, and middleware are out of scope.
- The IDOR rule is a heuristic: it looks for ownership fields and does not verify authorization logic in shared policy layers.
- The regex fallback parser, used when Node or TypeScript is unavailable, is less precise than the TypeScript parser. For example, it does not detect anonymous default-exported actions.
- Findings are review targets, not proofs of exploitability. See [docs/threat-model.md](docs/threat-model.md).

## License

MIT, see [LICENSE](LICENSE).
