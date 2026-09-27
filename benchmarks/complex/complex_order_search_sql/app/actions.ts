"use server";

import { searchTenantOrders } from "./order-service";

export async function searchOrders(previousState: unknown, formData: FormData) {
  const payload = Object.fromEntries(formData);
  const tenantId = String(payload.tenantId ?? "");
  const term = String(payload.q ?? "");
  const status = String(payload.status ?? "open");

  const rows = await searchTenantOrders({ tenantId, term, status });
  return { rows };
}
