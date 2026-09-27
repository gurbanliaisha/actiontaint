# Seeded SSRF Evaluation in `next-saas-stripe-starter`

> **Provenance note (v0.1.0 release):** the ActionTaint results in this report were produced by an earlier prototype *local* backend that is not shipped in v0.1.0 (the CLI now accepts only `--backend codeql`). The numbers are kept as historical evidence; the `--backend local` commands below are not runnable with this release. Re-running with `--backend codeql` requires local checkouts of the upstream projects listed in `datasets/real-projects.json`.

Date: 2026-05-22  
Project: `next-saas-stripe-starter`  
Experiment type: Seeded vulnerability / mutation-based evaluation  
Analyzer: ActionTaint with TypeScript compiler API parser and local backend
Baseline: Default CodeQL JavaScript security suite

## Why This Project Was Selected

This project is a better seeded-evaluation target than the Medusa project because the original ActionTaint scan produced no findings:

| Metric | Before seed |
|---|---:|
| Source files | 189 |
| Server Actions | 4 |
| Client-reachable Server Actions | 0 |
| ActionTaint findings | 0 |

This makes the seeded experiment cleaner: any new finding should be caused by the intentionally inserted SSRF flow, not by pre-existing triage findings.

## Seeded Code

Seeded Server Action:

`next-saas-stripe-starter/actions/actiontaint-seeded-ssrf.ts`

```ts
"use server";

export async function actionTaintSeededWebhookPreview(
  _currentState: unknown,
  formData: FormData
) {
  const callbackUrl = formData.get("callbackUrl") as string;

  await fetch(callbackUrl, { cache: "no-store" });

  return { ok: true };
}
```

Seeded client callsite:

`next-saas-stripe-starter/components/actiontaint-seeded/seeded-ssrf-form.tsx`

```tsx
"use client";

import { useFormState } from "react-dom";
import { actionTaintSeededWebhookPreview } from "@/actions/actiontaint-seeded-ssrf";

export function ActionTaintSeededWebhookPreviewForm() {
  const [, formAction] = useFormState(actionTaintSeededWebhookPreview, null);

  return (
    <form action={formAction}>
      <input type="url" name="callbackUrl" />
      <button type="submit">Preview webhook</button>
    </form>
  );
}
```

## Command

```powershell
python -B -m actiontaint scan next-saas-stripe-starter `
  --parser typescript `
  --backend local `
  --format json `
  --output evaluations\seeded-next-saas-stripe-ssrf\next-saas-stripe-starter-seeded-ssrf-actiontaint.json `
  --model-dir <generated-model-dir>
```

## Result

ActionTaint detected exactly the seeded SSRF flow.

| Metric | Before seed | After seed | Delta |
|---|---:|---:|---:|
| Server Actions | 4 | 5 | +1 |
| Client-reachable Server Actions | 0 | 1 | +1 |
| ActionTaint findings | 0 | 1 | +1 |
| Default CodeQL findings | 0 | 0 | 0 |

Finding:

| Field | Value |
|---|---|
| Severity | HIGH |
| Vulnerability type | SSRF |
| Source function | `actions/actiontaint-seeded-ssrf.ts::actionTaintSeededWebhookPreview` |
| Source parameter | `formData` |
| Sink | `actions/actiontaint-seeded-ssrf.ts:11` |
| Sink snippet | `await fetch(callbackUrl, { cache: "no-store" });` |

Reported taint path:

```text
formData
-> formData.get("callbackUrl") as string
-> callbackUrl
-> await fetch(callbackUrl, { cache: "no-store" });
```

Reconstructed boundary:

```json
{
  "function": "actionTaintSeededWebhookPreview",
  "boundary_type": "implicit_http_endpoint",
  "client_callable": true,
  "source_parameters": ["formData"],
  "reason": "used in useFormState(actionTaintSeededWebhookPreview, ...); used in <form action={formAction}>"
}
```

## Interpretation

This experiment shows that ActionTaint can detect an intentionally seeded Server Action SSRF inside a large real-world Next.js SaaS template that originally produced zero findings. The tool did not merely report noise from the project; the result changed from 0 findings to exactly 1 finding after the seeded vulnerable flow was inserted.

Default CodeQL was also run after the seed using `javascript-security-extended.qls` and reported 0 findings. This supports the central claim that the missing piece is the framework-specific Server Action source model: CodeQL sees `fetch(callbackUrl)`, but without reconstructing the `useFormState` and Server Action boundary it does not classify `formData` as a remote source in this pattern.

The important framework-aware steps are:

1. Detect file-level `"use server"`.
2. Resolve the `@/actions/...` TypeScript path alias.
3. Link the imported Server Action to a `"use client"` component.
4. Recognize `useFormState(actionTaintSeededWebhookPreview, ...)`.
5. Recognize `<form action={formAction}>`.
6. Classify `formData` as a client-controlled source.
7. Track `formData.get("callbackUrl")` into `fetch(callbackUrl)`.

## Paper-Ready Sentence

In a seeded-vulnerability experiment on the `next-saas-stripe-starter` open-source project, whose original scan produced zero findings, we inserted a small Server Action SSRF using `useFormState` and `FormData`. ActionTaint reconstructed the implicit Server Action boundary and reported the seeded flow from `formData.get("callbackUrl")` to `fetch(callbackUrl)`, increasing the result from 0 to 1 finding, while default CodeQL reported 0 findings under the JavaScript security-extended suite.

## Ethical Note

This is not a vulnerability disclosure against the upstream project. The SSRF code was deliberately inserted into the local workspace for controlled evaluation and should not be shipped, deployed, or submitted upstream.

## Artifact

Full JSON result:

`evaluations/seeded-next-saas-stripe-ssrf/next-saas-stripe-starter-seeded-ssrf-actiontaint.json`

Default CodeQL SARIF:

`evaluations/seeded-next-saas-stripe-ssrf/codeql-baseline/next-saas-stripe-starter-seeded-codeql.sarif`
