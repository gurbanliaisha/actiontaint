# Seeded IDOR Evaluation in `dub/apps/web`

Date: 2026-05-30  
Project: `dub/apps/web`  
Experiment type: Seeded vulnerability / mutation-based evaluation  
Analyzer: ActionTaint with TypeScript compiler API parser and CodeQL backend  
Baseline: Default CodeQL JavaScript security suite

## Why This Project Was Selected

`dub/apps/web` was selected because it was the largest real-world target we had already evaluated, and its clean baseline was a good fit for a controlled seeded experiment.

| Metric | Before seed |
|---|---:|
| Source files | 3185 |
| Server Actions | 10 |
| Client-reachable Server Actions | 3 |
| ActionTaint findings | 0 |

This makes the experiment easy to interpret: if a new finding appears after the seed, we can attribute it to the inserted Server Action flow rather than pre-existing ActionTaint findings.

## Seeded Files

The seeded mutation was added only to the copied repo:

- `real-nextjs-projects-round2/dub-seeded-idor/apps/web/lib/actions/actiontaint-seeded-idor.ts`
- `real-nextjs-projects-round2/dub-seeded-idor/apps/web/ui/actiontaint-seeded/seeded-idor-form.tsx`
- `real-nextjs-projects-round2/dub-seeded-idor/apps/web/app/actiontaint-seeded/page.tsx`

Seeded Server Action:

```ts
"use server";

import { getSession } from "@/lib/auth";
import { prisma } from "@dub/prisma";

export async function actionTaintSeededDeleteWebhook(
  _prevState: unknown,
  formData: FormData,
) {
  const session = await getSession();

  if (!session?.user.id) {
    throw new Error("Unauthorized: Login required.");
  }

  const webhookId = formData.get("webhookId") as string;

  await prisma.webhook.delete({
    where: {
      id: webhookId,
    },
  });

  return { ok: true };
}
```

Seeded client callsite:

```tsx
"use client";

import { useActionState } from "react";
import { actionTaintSeededDeleteWebhook } from "@/lib/actions/actiontaint-seeded-idor";

const initialState = {
  ok: false,
};

export function ActionTaintSeededIdorForm() {
  const [state, formAction] = useActionState(
    actionTaintSeededDeleteWebhook,
    initialState,
  );

  return (
    <form action={formAction} className="flex max-w-md flex-col gap-3">
      <label htmlFor="webhookId" className="text-sm text-neutral-600">
        Webhook ID
      </label>
      <input
        id="webhookId"
        name="webhookId"
        defaultValue="wh_seeded_123"
        className="rounded-md border border-neutral-300 px-3 py-2"
      />
      <button
        type="submit"
        className="rounded-md bg-black px-4 py-2 text-sm text-white"
      >
        Delete webhook
      </button>
      <p className="text-sm text-neutral-500">
        Result: {state?.ok ? "deleted" : "idle"}
      </p>
    </form>
  );
}
```

Dedicated page:

```tsx
import { ActionTaintSeededIdorForm } from "@/ui/actiontaint-seeded/seeded-idor-form";

export default function ActionTaintSeededPage() {
  return (
    <main className="p-10">
      <ActionTaintSeededIdorForm />
    </main>
  );
}
```

## Results

ActionTaint detected exactly one new finding after the seed, and default CodeQL did not add any result on the seeded file.

| Metric | Before seed | After seed | Delta |
|---|---:|---:|---:|
| Source files | 3185 | 3188 | +3 |
| Server Actions | 10 | 11 | +1 |
| Client-reachable Server Actions | 3 | 4 | +1 |
| ActionTaint findings | 0 | 1 | +1 |
| Default CodeQL findings | 32 | 32 | 0 |
| Default CodeQL findings on seeded file | 0 | 0 | 0 |

## ActionTaint Finding

ActionTaint reported one `Broken Authorization / IDOR` finding in the seeded Server Action.

| Field | Value |
|---|---|
| Severity | HIGH |
| Vulnerability type | `Broken Authorization / IDOR` |
| Source function | `lib/actions/actiontaint-seeded-idor.ts::actionTaintSeededDeleteWebhook` |
| Source parameter | `formData` |
| Sink file | `lib/actions/actiontaint-seeded-idor.ts` |
| Sink line | `18` |
| Dangerous sink | `await prisma.webhook.delete({ where: { id: webhookId } })` |

Reported taint path:

```text
formData
-> formData.get("webhookId")
-> webhookId
-> prisma.webhook.delete({ where: { id: webhookId } })
```

Reconstructed boundary:

```json
{
  "function": "actionTaintSeededDeleteWebhook",
  "boundary_type": "implicit_http_endpoint",
  "client_callable": true,
  "source_parameters": ["formData"],
  "reason": "used in useActionState(actionTaintSeededDeleteWebhook, ...); used in <form action={formAction}>"
}
```

## Default CodeQL Result

Default CodeQL was run on both the clean baseline and the seeded copy with `javascript-security-extended.qls`.

Observed result:

- Clean baseline SARIF results: `32`
- Seeded copy SARIF results: `32`
- Findings referencing `actiontaint-seeded-idor.ts`: `0`

So the seeded IDOR did not produce a new default CodeQL result, and no CodeQL finding pointed to the inserted Server Action file.

## Interpretation

This is a clean differentiating case for ActionTaint.

ActionTaint succeeded because it reconstructed the Next.js Server Action trust boundary:

1. Detect file-level `"use server"`.
2. Recognize the exported async Server Action.
3. Link the imported action into a `"use client"` component.
4. Recognize `useActionState(actionTaintSeededDeleteWebhook, ...)`.
5. Recognize `<form action={formAction}>`.
6. Classify `formData` as a client-controlled Server Action source.
7. Match the Prisma delete on attacker-controlled `id` with no visible ownership constraint as an IDOR sink.

Default CodeQL did not report the seeded case because the standard JavaScript security suite does not reconstruct this Server Action boundary and does not model this authorization-specific sink pattern in a way that connects the `FormData` source to the missing ownership check.

## Acceptance Check

The seeded run satisfied the experiment goals:

- ActionTaint discovered one new Server Action.
- ActionTaint discovered one new client-reachable Server Action boundary.
- ActionTaint reported one new `Broken Authorization / IDOR` finding on the seeded file.
- The source parameter was the `FormData`-derived input.
- The sink was the seeded Prisma `delete` call.
- Default CodeQL did not produce a finding on the seeded file.
- The deltas were isolated to the seeded copy.

## Ethical Note

This is not a vulnerability disclosure against the upstream project. The IDOR code was deliberately inserted into a local copied checkout for controlled evaluation and should not be shipped, deployed, or submitted upstream.

## Artifacts

- `evaluations/seeded-dub-idor/dub-web-baseline-actiontaint.json`
- `evaluations/seeded-dub-idor/dub-web-baseline-default-codeql.sarif`
- `evaluations/seeded-dub-idor/dub-web-seeded-idor-actiontaint.json`
- `evaluations/seeded-dub-idor/dub-web-seeded-idor-default-codeql.sarif`
- `evaluations/seeded-dub-idor/SEEDED_IDOR_EVALUATION_REPORT.md`
