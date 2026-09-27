# ActionTaint Master Evaluation Report

Generated: 2026-05-31  

## Scope

This report consolidates the evaluation artifacts already present in the workspace. No scans were rerun for this document. It gathers the main evaluation stories we produced while developing and testing ActionTaint:

1. original synthetic benchmarks,
2. newer complex benchmarks,
3. real open-source project scans,
4. additional real-project rounds,
5. seeded vulnerability experiments,
6. supplementary static-analyzer comparisons.

This report intentionally excludes internal scratch artifacts such as `codeql-only-*`, `manual-codeql`, and one-off model-debugging runs, because those are development-support experiments rather than paper-facing evaluation sections.

## Method Note

The consolidated artifacts span two phases of the project:

- early evaluations using the ActionTaint prototype with the local backend,
- later evaluations using ActionTaint with its generated CodeQL backend.

Release note (v0.1.0): the local backend is no longer shipped. Artifacts produced with it are real-world rounds 1 and 2, the Medusa and next-saas-stripe seeded SSRF experiments, and the Semgrep comparison. They carry `"backend_used": "local"` and are kept as historical evidence. The complex benchmarks, round 3, and the Dub and Formbricks seeded IDOR experiments used the CodeQL backend. The benchmark suites can be re-run with `python -m actiontaint eval benchmarks --tools actiontaint,codeql`.

Where a baseline is mentioned as "default CodeQL," it refers to the standard JavaScript CodeQL suite `javascript-security-extended.qls`.

Because the evaluation history spans multiple dates and backend configurations, the safest interpretation is comparative rather than strictly pooled: the report shows what each evaluation demonstrated, not a single uniform end-to-end benchmark campaign executed under one frozen configuration.

## High-Level Inventory

| Evaluation set | Date | Scope | ActionTaint result | Baseline result | Main takeaway |
|---|---|---|---|---|---|
| Original synthetic benchmarks | existing artifact | 13 benchmarks | 10 vulnerable findings, 3 safe clean | 0 findings | Good recall on core Server Action patterns |
| Complex benchmarks | 2026-05-30 | 5 harder benchmarks | 4/4 vulnerable found, 1 safe clean | 2/4 vulnerable found | Stronger framework-aware benchmark evidence |
| Real open-source round 1 | 2026-05-22 | 5 projects | 5 triage findings in Medusa, 0 elsewhere | 0 findings | ActionTaint can surface framework-specific review targets |
| Real open-source round 2 | 2026-05-23 | 5 projects/subapps | 1 triage finding total | 118 findings total | ActionTaint stayed low-noise on large apps |
| Round 3 project comparison | 2026-05-30 | 3 repos | 0 findings | 8 findings | Default CodeQL findings were generic, not Server Action-specific |
| Seeded SSRF / IDOR experiments | 2026-05-22 to 2026-05-31 | 4 seeded cases | all seeded flows detected | default CodeQL did not add seeded findings in the cases where it was measured | Best evidence for the framework-boundary claim |
| Static analyzer comparison | existing artifact | 5 projects | 0 findings | Semgrep 3 findings | Supplementary comparison only; different detection model |

## 1. Original Synthetic Benchmark Suite

Artifact: `evaluations/benchmark-actiontaint-vs-default-codeql-summary.json`

### Summary

| Metric | Value |
|---|---:|
| Benchmarks | 13 |
| Vulnerable cases | 10 |
| Safe cases | 3 |
| ActionTaint total findings | 10 |
| Default CodeQL total findings | 0 |

### Vulnerability Breakdown

| Type | Count |
|---|---:|
| SQL Injection | 7 |
| SSRF | 1 |
| Path Traversal | 1 |
| Broken Authorization / IDOR | 1 |
| Safe | 3 |

### Interpretation

This was the first strong signal that ActionTaint's Server Action boundary reconstruction mattered. The benchmark suite contains direct framework patterns such as `FormData`, `useActionState`, hidden inputs, bind arguments, inline actions, and helper-wrapper flows. ActionTaint found the intended vulnerable flows and stayed quiet on the safe cases. Default CodeQL reported nothing on this suite.

## 2. Complex Benchmark Suite

Artifact: `evaluations/complex-benchmarks-report/FINAL_REPORT.md`

### Summary

| Benchmark | Expected | ActionTaint | Default CodeQL |
|---|---|---:|---:|
| `complex_order_search_sql` | SQL Injection | 1 | 0 |
| `tenant_document_path_traversal` | Path Traversal | 1 | 1 |
| `project_member_idor` | Broken Authorization / IDOR | 1 | 0 |
| `client_preview_ssrf` | SSRF | 1 | 1 |
| `safe_policy_layer_update` | safe | 0 | 0 |

### Interpretation

This is the strongest controlled benchmark result in the workspace.

- ActionTaint found all 4 intentionally vulnerable flows.
- ActionTaint produced 0 findings for the safe case.
- Default CodeQL found only the path traversal and SSRF cases.
- Default CodeQL missed the SQL injection and IDOR cases.

This suite is especially useful because the benchmarks are more "project-like" than the original micro-benchmarks: they include service layers, repository helpers, `.bind(...)`, route params, and client-to-action links that better resemble real Next.js applications.

## 3. Real Open-Source Evaluation: Round 1

Artifact: `evaluations/open-source-real/OPEN_SOURCE_REAL_PROJECT_REPORT.md`

### Projects

| Project | Source files | Server Actions | Client-reachable | ActionTaint findings | Default CodeQL findings |
|---|---:|---:|---:|---:|---:|
| `nextjs-starter-medusa` | 207 | 48 | 22 | 5 | 0 |
| `next-saas-stripe-starter` | 189 | 4 | 0 | 0 | 0 |
| `saas-starter` | 41 | 1 | 1 | 0 | 0 |
| `nextjs-auth-starter` | 23 | 4 | 3 | 0 | 0 |
| `postgres-next-starter` | 12 | 2 | 2 | 0 | 0 |

### Aggregate

| Metric | Value |
|---|---:|
| Total Server Actions observed | 59 |
| Total client-reachable actions | 28 |
| Total ActionTaint findings | 5 |
| Total default CodeQL findings | 0 |

### Interpretation

All 5 ActionTaint findings came from `nextjs-starter-medusa`, and all 5 were Medium-severity open redirect triage findings rather than confirmed vulnerabilities. This round is still valuable:

- it proved ActionTaint could scale to a nontrivial real app,
- it surfaced framework-specific redirect review targets,
- and it stayed quiet on four other projects.

This round also drove an important engineering improvement: TypeScript path-alias resolution. The report notes that alias support changed Medusa from 0 client-reachable actions to 22 client-reachable actions, which is a major practical win for real-world analysis.

## 4. Real Open-Source Evaluation: Round 2

Artifact: `evaluations/open-source-round2/ROUND2_REAL_PROJECT_REPORT.md`

### Projects

| Project | Source files | Server Actions | Client-reachable | ActionTaint findings | Default CodeQL findings |
|---|---:|---:|---:|---:|---:|
| `saas-starter-kit` | 40 | 8 | 6 | 1 | 4 |
| `papermark` | 1272 | 0 | 0 | 0 | 78 |
| `documenso-openpage-api` | 26 | 0 | 0 | 0 | 0 |
| `dub-web` | 3185 | 10 | 3 | 0 | 32 |
| `formbricks-web` | 2058 | 19 | 1 | 0 | 4 |

### Aggregate

| Metric | Value |
|---|---:|
| Projects | 5 |
| Total Server Actions | 37 |
| Total client-reachable actions | 10 |
| Total ActionTaint findings | 1 |
| Total default CodeQL findings | 118 |

### Interpretation

Round 2 did not produce a confirmed production vulnerability. ActionTaint reported only one triage finding, in `saas-starter-kit`, and the report explicitly treats it as likely over-taint around a Stripe-generated redirect URL.

This round is useful because it shows a very different property from the benchmark suites:

- large real apps generated many broad default CodeQL findings,
- but ActionTaint remained extremely narrow and low-noise,
- and in `formbricks-web` the default CodeQL findings were not `use server` / Server Action findings at all.

That is a good paper point if it is phrased carefully: the tool is not a replacement for broad JavaScript scanning, but it is much more targeted for Server Action trust-boundary analysis.

## 5. Round 3 Project Comparison

Artifact folder: `evaluations/round3-comparison`

### Projects

| Project | Next.js | Source files | Server Actions | Client-reachable | ActionTaint findings | Default CodeQL findings |
|---|---:|---:|---:|---:|---:|---:|
| `next-saas-stripe-starter` | 14.2.5 | 189 | 4 | 0 | 0 | 0 |
| `next-shadcn-dashboard-starter` | 16.2.6 | 265 | 0 | 0 | 0 | 8 |
| `skateshop` | 14.2.5 | 312 | 31 | 13 | 0 | 0 |

### Aggregate

| Metric | Value |
|---|---:|
| Projects | 3 |
| Total Server Actions | 35 |
| Total client-reachable actions | 13 |
| Total ActionTaint findings | 0 |
| Total default CodeQL findings | 8 |

### Interpretation

Round 3 is useful mostly as a negative result:

- ActionTaint found no dangerous Server Action flows.
- Default CodeQL reported 8 findings total.
- Those 8 findings were all in `next-shadcn-dashboard-starter`, and they were generic `js/file-system-race` warnings in a script file rather than Server Action findings.

So this round reinforces a recurring pattern: ActionTaint and default CodeQL are often reporting very different classes of issues.

## 6. Seeded Vulnerability Experiments

These are the clearest differentiating evaluations in the workspace because the ground truth is controlled.

### Seeded Experiment Summary

| Project | Date | Vulnerability | ActionTaint backend | Before -> After (ActionTaint findings) | Default CodeQL delta | Result |
|---|---|---|---|---|---|---|
| `nextjs-starter-medusa` | 2026-05-22 | SSRF | local | 5 -> 6 | not recorded for seeded copy | seeded SSRF detected |
| `next-saas-stripe-starter` | 2026-05-22 | SSRF | local | 0 -> 1 | 0 -> 0 | seeded SSRF detected, default CodeQL missed |
| `dub/apps/web` | 2026-05-30 | IDOR | CodeQL backend | 0 -> 1 | 32 -> 32 | seeded IDOR detected, default CodeQL unchanged |
| `formbricks/apps/web` | 2026-05-31 | IDOR | CodeQL backend | 0 -> 1 | 4 -> 4 | seeded IDOR detected, default CodeQL unchanged |

### 6.1 Medusa Seeded SSRF

Artifact: `evaluations/seeded-medusa-ssrf/SEEDED_SSRF_EVALUATION_REPORT.md`

Key result:

- Server Actions: `48 -> 49`
- Client-reachable actions: `22 -> 23`
- Findings: `5 -> 6`
- Added finding: seeded SSRF from `formData.get("preview_url")` into `fetch(target)`

This is useful as an early proof that ActionTaint could still detect a newly inserted Server Action flow inside a large real-world project layout.

### 6.2 Next SaaS Starter Seeded SSRF

Artifact: `evaluations/seeded-next-saas-stripe-ssrf/SEEDED_SSRF_EVALUATION_REPORT.md`

Key result:

- Server Actions: `4 -> 5`
- Client-reachable actions: `0 -> 1`
- ActionTaint findings: `0 -> 1`
- Default CodeQL findings: `0 -> 0`

This is a very clean seeded case because the baseline project had zero ActionTaint findings. The report is especially paper-friendly because the delta is attributable to the inserted flow only.

### 6.3 Dub Seeded IDOR

Artifact: `evaluations/seeded-dub-idor/SEEDED_IDOR_EVALUATION_REPORT.md`

Key result:

- Server Actions: `10 -> 11`
- Client-reachable actions: `3 -> 4`
- ActionTaint findings: `0 -> 1`
- Default CodeQL findings: `32 -> 32`
- Default CodeQL findings on seeded file: `0`

This is one of the strongest differentiating cases in the workspace: ActionTaint reconstructed a `useActionState` + `FormData` + ORM delete flow and reported `Broken Authorization / IDOR`, while the default CodeQL result set stayed unchanged.

### 6.4 Formbricks Seeded IDOR

Artifact: `evaluations/seeded-formbricks-idor/SEEDED_IDOR_EVALUATION_REPORT.md`

Key result:

- Server Actions: `19 -> 20`
- Client-reachable actions: `1 -> 2`
- ActionTaint findings: `0 -> 1`
- Default CodeQL findings: `4 -> 4`
- Default CodeQL findings on seeded file: `0`

This is the newest and cleanest CodeQL-backed IDOR evaluation. It shows the same pattern as the Dub seed, but on a different project shape and with a different ORM target.

## 7. Supplementary Static-Analyzer Comparison

Artifact folder: `evaluations/static-analyzer-comparison`

### Summary

| Project | ActionTaint findings | Semgrep findings |
|---|---:|---:|
| `next-saas-stripe-starter` | 0 | 0 |
| `nextjs-auth-starter` | 0 | 3 |
| `nextjs-starter-medusa` | 0 | 0 |
| `postgres-next-starter` | 0 | 0 |
| `saas-starter` | 0 | 0 |

Aggregate:

| Metric | Value |
|---|---:|
| Projects | 5 |
| ActionTaint findings | 0 |
| Semgrep findings | 3 |

### Interpretation

This should be treated as supplementary, not a one-to-one headline comparison. Semgrep and ActionTaint do not model the same problem in the same way. Still, the artifact is useful for showing that framework-specific Server Action analysis is distinct from generic static-rule matching.

## Overall Takeaways

Across the evaluation history captured in this artifact set, the most defensible claims are:

1. In the included evaluations, ActionTaint consistently reconstructs Next.js Server Action trust boundaries that broad default CodeQL runs do not model.
2. On controlled synthetic and complex benchmarks, ActionTaint has strong recall and stays quiet on the included safe cases.
3. On real open-source projects, ActionTaint is much narrower and lower-noise than broad default CodeQL scanning.
4. The strongest evidence comes from seeded experiments: when a framework-shaped SSRF or IDOR is deliberately inserted, ActionTaint detects it, and in the seeded cases where default CodeQL was also measured, the default CodeQL result set did not change.
5. Real-project findings should be described as triage or review targets unless manually validated. The workspace does not support a claim that ActionTaint found a confirmed production vulnerability in an upstream project.

## Recommended Paper Framing

If this evaluation is used in a paper, poster, or SRC submission, the safest framing is:

> We evaluate ActionTaint on synthetic benchmarks, more realistic complex benchmarks, real open-source Next.js projects, and seeded vulnerability experiments. The benchmark suites show that ActionTaint detects client-controlled Server Action flows to SQL injection, SSRF, path traversal, and IDOR sinks while remaining quiet on included safe cases. In real open-source projects, ActionTaint finds Server Actions and client-reachable boundaries at scale while producing low noise. In seeded experiments, ActionTaint detects intentionally inserted Server Action SSRF and IDOR flows, and in the seeded cases where default CodeQL was also measured, the default CodeQL result set did not change.

## Primary Artifact Index

- Original benchmarks: `evaluations/benchmark-actiontaint-vs-default-codeql-summary.json`
- Complex benchmarks: `evaluations/complex-benchmarks-report/FINAL_REPORT.md`
- Real open-source round 1: `evaluations/open-source-real/OPEN_SOURCE_REAL_PROJECT_REPORT.md`
- Real open-source round 2: `evaluations/open-source-round2/ROUND2_REAL_PROJECT_REPORT.md`
- Round 3: `evaluations/round3-comparison/`
- Seeded Medusa SSRF: `evaluations/seeded-medusa-ssrf/SEEDED_SSRF_EVALUATION_REPORT.md`
- Seeded next-saas SSRF: `evaluations/seeded-next-saas-stripe-ssrf/SEEDED_SSRF_EVALUATION_REPORT.md`
- Seeded Dub IDOR: `evaluations/seeded-dub-idor/SEEDED_IDOR_EVALUATION_REPORT.md`
- Seeded Formbricks IDOR: `evaluations/seeded-formbricks-idor/SEEDED_IDOR_EVALUATION_REPORT.md`
- Supplementary static-analyzer comparison: `evaluations/static-analyzer-comparison/`
