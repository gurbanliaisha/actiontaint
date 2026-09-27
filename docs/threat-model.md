# Threat Model

ActionTaint answers one question:

> Can a client-controlled value cross a client-reachable Next.js Server Action boundary and reach a security-sensitive server-side operation?

It is a specialized Server Action analyzer, not a general JavaScript security scanner.

## Attacker

A remote client who can call any client-reachable Server Action with arbitrary arguments. Next.js serializes these calls as HTTP POST requests, so the attacker controls:

- every submitted form field, **including hidden inputs** (they can be edited in the browser)
- arguments sent from client components
- values carried through `.bind(...)` when they come from the URL (`searchParams`, route `params`), form data, cookies, or headers
- `searchParams` / `params` captured by inline Server Actions

The attacker does **not** control server-side state such as the session, `auth()`, or `currentUser`, or literal values bound on the server.

## When a finding is reported

All four conditions must hold:

1. **Server Action:** an async function marked by a file-level or inline `"use server"`
2. **Client-reachable:** referenced by a form action, a `formAction`, `useActionState` / `useFormState`, a component action prop, or a call from a `"use client"` file (see [architecture.md](architecture.md#reachability-stage-4))
3. **Untrusted input:** a parameter or captured value classified as client-controlled (see [architecture.md](architecture.md#source-classification-stage-5))
4. **Taint reaches a sink:** CodeQL finds a path to a modelled sink that no modelled barrier blocks

## Sinks

| Class | Risk | Severity |
|---|---|---|
| SQL query execution | SQL injection | HIGH |
| Outbound HTTP request | SSRF | HIGH |
| Redirect | Open redirect | MEDIUM |
| File system read / write / delete | Path traversal | HIGH |
| OS command execution | Command injection | CRITICAL |
| ORM mutation without an ownership constraint | Broken authorization / IDOR | HIGH |

The exact matching rules are in [architecture.md](architecture.md#generated-codeql-query-stage-6).

## Assumptions that shape the results

- **The IDOR rule is a heuristic.** A mutation counts as protected when an ownership-like field (`userId`, `ownerId`, `tenantId`, `orgId`, `workspaceId`, ...) appears in its filter. It does not check that the value is correct, and it cannot see authorization enforced elsewhere, for example in a policy function. Treat IDOR findings as review targets.
- **Sanitizers are conservative.** Only explicit allowlist or assertion calls (`assertAllowed…`, `allowlist…`, `isAllowedHost`, `assertInternalUrl`, `assertRelativePath`, `trustedServerValue`) stop taint. Schema or type validation such as zod does not, because well-typed input can still be malicious. This can produce findings where custom validation actually protects the code.
- **Fixed prefixes are trusted.** `fetch("https://api.example.com/" + id)` and `redirect("/posts/" + id)` are not reported, because the client cannot change the host. Path-level manipulation on the same host is out of scope.
- **Unreferenced actions are skipped.** Actions that no client code references are not analyzed.

## What a finding means, and what it does not

A finding means that a modelled, client-controlled input of a client-reachable Server Action has a static taint path to a modelled sink, with no modelled barrier in between.

It does **not** prove:

- that the issue is exploitable in production
- that no validation exists in code the model does not understand
- that authorization is missing (for IDOR)

Findings are candidates for manual review.

## Out of scope

- route handlers, API routes, middleware, and `getServerSideProps`
- client-side issues (XSS, DOM-based bugs)
- dependency and supply-chain vulnerabilities, and secrets
- business-logic flaws and full authorization proofs
- sink classes not listed above
