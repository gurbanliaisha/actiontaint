# Seeded IDOR Evaluation in `formbricks/apps/web`

Date: 2026-05-31  
Project: `formbricks/apps/web`  
Experiment type: Seeded vulnerability / mutation-based evaluation  
Analyzer: ActionTaint with TypeScript compiler API parser and CodeQL backend  
Baseline: Default CodeQL JavaScript security-extended suite

## Why This Project Was Selected

`formbricks/apps/web` was already part of the real-project evaluation set and is a strong seeded target:

- it is a large production-style Next.js app,
- it contains real Server Actions and form-heavy workflows,
- and the clean ActionTaint baseline produced no findings.

That makes the seeded result easy to interpret: if a new finding appears after the mutation, it is attributable to the inserted Server Action flow rather than pre-existing ActionTaint noise.

## Seeded Files

The mutation was added only to the copied repo:

- `real-nextjs-projects-round2/formbricks-seeded-idor/apps/web/lib/actions/actiontaint-seeded-idor.ts`
- `real-nextjs-projects-round2/formbricks-seeded-idor/apps/web/modules/actiontaint-seeded/seeded-idor-form.tsx`
- `real-nextjs-projects-round2/formbricks-seeded-idor/apps/web/app/actiontaint-seeded/page.tsx`

Seeded Server Action:

```ts
"use server";

import { getServerSession } from "next-auth";
import { prisma } from "@formbricks/database";
import { authOptions } from "@/modules/auth/lib/authOptions";

export async function actionTaintSeededDeleteDashboard(
  _prevState: unknown,
  formData: FormData
) {
  const session = await getServerSession(authOptions);

  if (!session?.user?.id) {
    throw new Error("Unauthorized");
  }

  const dashboardId = formData.get("dashboardId") as string;

  await prisma.dashboard.delete({
    where: {
      id: dashboardId,
    },
  });

  return { ok: true };
}
```

Seeded client callsite:

```tsx
"use client";

import { useActionState } from "react";
import { actionTaintSeededDeleteDashboard } from "@/lib/actions/actiontaint-seeded-idor";

const initialState = {
  ok: false,
};

export function ActionTaintSeededIdorForm() {
  const [state, formAction] = useActionState(actionTaintSeededDeleteDashboard, initialState);

  return (
    <form action={formAction} className="flex max-w-md flex-col gap-3">
      <label htmlFor="dashboardId" className="text-sm text-slate-600">
        Dashboard ID
      </label>
      <input
        id="dashboardId"
        name="dashboardId"
        defaultValue="dash_seeded_123"
        className="rounded-md border border-slate-300 px-3 py-2"
      />
      <button type="submit" className="rounded-md bg-slate-900 px-4 py-2 text-sm text-white">
        Delete dashboard
      </button>
      <p className="text-sm text-slate-500">Result: {state?.ok ? "deleted" : "idle"}</p>
    </form>
  );
}
```

This is an authenticated IDOR seed: the action checks that the user is logged in, but it deletes a dashboard by attacker-controlled `id` with no visible ownership or workspace constraint.

## Commands

ActionTaint:

```powershell
python -B -m actiontaint scan real-nextjs-projects-round2/formbricks/apps/web `
  --parser typescript `
  --backend codeql `
  --format json `
  --output evaluations/seeded-formbricks-idor/formbricks-web-baseline-actiontaint.json `
  --model-dir evaluations/seeded-formbricks-idor/baseline-model

python -B -m actiontaint scan real-nextjs-projects-round2/formbricks-seeded-idor/apps/web `
  --parser typescript `
  --backend codeql `
  --format json `
  --output evaluations/seeded-formbricks-idor/formbricks-web-seeded-idor-actiontaint.json `
  --model-dir evaluations/seeded-formbricks-idor/seeded-model
```

Default CodeQL:

```powershell
codeql database analyze evaluations/seeded-formbricks-idor/baseline-model/codeql-db `
  javascript-security-extended.qls `
  --format=sarif-latest `
  --output evaluations/seeded-formbricks-idor/formbricks-web-baseline-default-codeql.sarif `
  --rerun

codeql database analyze evaluations/seeded-formbricks-idor/seeded-model/codeql-db `
  javascript-security-extended.qls `
  --format=sarif-latest `
  --output evaluations/seeded-formbricks-idor/formbricks-web-seeded-idor-default-codeql.sarif `
  --rerun
```

## Results

The seeded run produced exactly one new ActionTaint finding and no new default CodeQL finding.

| Metric | Before seed | After seed | Delta |
|---|---:|---:|---:|
| Source files | 2058 | 2061 | +3 |
| Server Actions | 19 | 20 | +1 |
| Client-reachable Server Actions | 1 | 2 | +1 |
| ActionTaint findings | 0 | 1 | +1 |
| Default CodeQL findings | 4 | 4 | 0 |
| Default CodeQL findings on seeded file | 0 | 0 | 0 |

## ActionTaint Finding

ActionTaint reported one new `Broken Authorization / IDOR` finding in the seeded Server Action.

| Field | Value |
|---|---|
| Severity | `HIGH` |
| Vulnerability type | `Broken Authorization / IDOR` |
| Source function | `lib/actions/actiontaint-seeded-idor.ts::actionTaintSeededDeleteDashboard` |
| Source parameter | `formData` |
| Sink file | `lib/actions/actiontaint-seeded-idor.ts` |
| Sink line | `19` |
| Dangerous sink | `await prisma.dashboard.delete({ where: { id: dashboardId } })` |

Reported taint path:

```text
formData
-> formData.get("dashboardId")
-> dashboardId
-> prisma.dashboard.delete({ where: { id: dashboardId } })
```

Reconstructed boundary:

```json
{
  "function": "actionTaintSeededDeleteDashboard",
  "boundary_type": "implicit_http_endpoint",
  "client_callable": true,
  "source_parameters": ["formData"],
  "reason": "used in useActionState(actionTaintSeededDeleteDashboard, ...); used in <form action={formAction}>"
}
```

## Default CodeQL Result

Default CodeQL produced the same four findings on the clean baseline and the seeded copy. The result set was identical before and after the mutation.

Observed result:

- Clean baseline SARIF results: `4`
- Seeded copy SARIF results: `4`
- New findings added by seed: `0`
- Findings referencing `actiontaint-seeded-idor.ts`: `0`

The four baseline findings remained the same unrelated warnings:

- `js/incomplete-multi-character-sanitization`
- `js/incomplete-sanitization`
- `js/insufficient-password-hash`
- `js/regex/missing-regexp-anchor`

None of them point to the seeded Server Action or its client callsite.

## Interpretation

This is a clean differentiating case for ActionTaint.

ActionTaint succeeded because it reconstructed the Next.js Server Action boundary and then delegated the actual taint solving to CodeQL:

1. Detect file-level `"use server"`.
2. Recognize the exported async Server Action.
3. Link the imported action into a `"use client"` component.
4. Recognize `useActionState(actionTaintSeededDeleteDashboard, ...)`.
5. Recognize `<form action={formAction}>`.
6. Classify `formData` as a client-controlled Server Action source.
7. Track `formData.get("dashboardId")` into `prisma.dashboard.delete({ where: { id: dashboardId } })`.
8. Classify the ORM delete with no visible ownership constraint as an IDOR sink.

Default CodeQL did not report the seeded case because the standard JavaScript security suite does not reconstruct this Server Action trust boundary and does not model this authorization-specific sink pattern in a way that ties the `FormData` input to the missing object-ownership check.

## Acceptance Check

This seeded evaluation met the intended goals:

- ActionTaint discovered one new Server Action.
- ActionTaint discovered one new client-reachable Server Action boundary.
- ActionTaint reported one new `Broken Authorization / IDOR` finding on the seeded file.
- The source parameter was the `FormData`-derived input.
- The sink was the seeded Prisma `delete` call.
- Default CodeQL produced no finding on the seeded file.
- The default CodeQL result set was unchanged by the mutation.

## Ethical Note

This is not a vulnerability disclosure against the upstream Formbricks project. The IDOR code was deliberately inserted into a local copied checkout for controlled evaluation and should not be shipped, deployed, or submitted upstream.

## Artifacts

- `evaluations/seeded-formbricks-idor/formbricks-web-baseline-actiontaint.json`
- `evaluations/seeded-formbricks-idor/formbricks-web-baseline-default-codeql.sarif`
- `evaluations/seeded-formbricks-idor/formbricks-web-seeded-idor-actiontaint.json`
- `evaluations/seeded-formbricks-idor/formbricks-web-seeded-idor-default-codeql.sarif`
- `evaluations/seeded-formbricks-idor/SEEDED_IDOR_EVALUATION_REPORT.md`
