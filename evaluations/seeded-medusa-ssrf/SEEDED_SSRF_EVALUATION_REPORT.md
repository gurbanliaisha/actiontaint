# Seeded SSRF Evaluation in a Real Next.js Project

> **Provenance note (v0.1.0 release):** the ActionTaint results in this report were produced by an earlier prototype *local* backend that is not shipped in v0.1.0 (the CLI now accepts only `--backend codeql`). The numbers are kept as historical evidence; the `--backend local` commands below are not runnable with this release. Re-running with `--backend codeql` requires local checkouts of the upstream projects listed in `datasets/real-projects.json`.

Date: 2026-05-22  
Project: `nextjs-starter-medusa`  
Experiment type: Seeded vulnerability / mutation-based evaluation  
Analyzer: ActionTaint with TypeScript compiler API parser and local backend

## Purpose

This experiment tests whether ActionTaint can detect an intentionally seeded SSRF vulnerability inside a real open-source Next.js project structure. This is not a claim that the upstream Medusa starter contains this vulnerability. The vulnerable code was deliberately added in the local workspace for evaluation.

## Seeded Code

Seeded Server Action:

`nextjs-starter-medusa/src/lib/data/actiontaint-seeded-ssrf.ts`

```ts
"use server"

export async function actionTaintSeededPreview(
  _currentState: unknown,
  formData: FormData
) {
  const target = formData.get("preview_url") as string

  await fetch(target, { cache: "no-store" })

  return { ok: true }
}
```

Seeded client callsite:

`nextjs-starter-medusa/src/modules/actiontaint-seeded/seeded-ssrf-form.tsx`

```tsx
"use client"

import { useActionState } from "react"
import { actionTaintSeededPreview } from "@lib/data/actiontaint-seeded-ssrf"

export default function ActionTaintSeededSsrfForm() {
  const [, formAction] = useActionState(actionTaintSeededPreview, null)

  return (
    <form action={formAction}>
      <input type="url" name="preview_url" />
      <button type="submit">Preview</button>
    </form>
  )
}
```

The seeded flow is intentionally vulnerable:

```text
client form field preview_url
-> FormData parameter
-> formData.get("preview_url")
-> target
-> fetch(target)
```

Because `target` is fully controlled by the client and passed directly to `fetch`, this models a classic server-side request forgery sink.

## Command

```powershell
python -B -m actiontaint scan nextjs-starter-medusa `
  --parser typescript `
  --backend local `
  --format json `
  --output evaluations\seeded-medusa-ssrf\nextjs-starter-medusa-seeded-ssrf-actiontaint.json `
  --model-dir <generated-model-dir>
```

## Result

ActionTaint detected the seeded SSRF.

Overall scan result after seeding:

| Metric | Before seed | After seed | Delta |
|---|---:|---:|---:|
| Server Actions | 48 | 49 | +1 |
| Client-reachable Server Actions | 22 | 23 | +1 |
| Findings | 5 | 6 | +1 |

The additional finding is the seeded SSRF:

| Field | Value |
|---|---|
| Severity | HIGH |
| Vulnerability type | SSRF |
| Source function | `src/lib/data/actiontaint-seeded-ssrf.ts::actionTaintSeededPreview` |
| Source parameter | `formData` |
| Sink | `src/lib/data/actiontaint-seeded-ssrf.ts:11` |
| Sink snippet | `await fetch(target, { cache: "no-store" })` |

Reported taint path:

```text
formData
-> formData.get("preview_url") as string
-> target
-> await fetch(target, { cache: "no-store" })
```

Boundary model reconstructed by ActionTaint:

```json
{
  "function": "actionTaintSeededPreview",
  "boundary_type": "implicit_http_endpoint",
  "client_callable": true,
  "source_parameters": ["formData"],
  "reason": "used in useActionState(actionTaintSeededPreview, ...); used in <form action={formAction}>"
}
```

## Interpretation

This experiment demonstrates that ActionTaint can detect a seeded Server Action SSRF inside a real Next.js project layout. The important part is not only the `fetch(target)` sink, but the framework reconstruction:

1. ActionTaint detected the file-level `"use server"` action.
2. It resolved the real project path alias `@lib/data/...`.
3. It linked the action to a `"use client"` component through `useActionState`.
4. It recognized the `<form action={formAction}>` callsite.
5. It classified the `FormData` parameter as client-controlled.
6. It tracked `formData.get("preview_url")` into `fetch(target)`.

## Paper-Ready Sentence

In a seeded-vulnerability experiment on a local copy of the `nextjs-starter-medusa` open-source project, we inserted a small Server Action SSRF flow using `useActionState` and `FormData`. ActionTaint reconstructed the implicit Server Action boundary and reported the flow from `formData.get("preview_url")` to `fetch(target)`, increasing the project scan from 48 to 49 Server Actions, 22 to 23 client-reachable actions, and 5 to 6 findings.

## Ethical Note

This is not a vulnerability disclosure against the upstream project. The SSRF code was deliberately inserted into the local workspace for controlled evaluation and should not be shipped, deployed, or submitted upstream.

## Artifact

Full JSON result:

`evaluations/seeded-medusa-ssrf/nextjs-starter-medusa-seeded-ssrf-actiontaint.json`
