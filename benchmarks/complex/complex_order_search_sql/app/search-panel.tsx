"use client";

import { useActionState } from "react";
import { searchOrders } from "./actions";

export function SearchPanel() {
  const [state, formAction] = useActionState(searchOrders, { rows: [] });

  return (
    <form action={formAction}>
      <input type="hidden" name="tenantId" value="tenant_123" />
      <input name="q" />
      <select name="status" defaultValue="open">
        <option value="open">Open</option>
        <option value="closed">Closed</option>
      </select>
      <button type="submit">Search</button>
      <pre>{JSON.stringify(state)}</pre>
    </form>
  );
}
