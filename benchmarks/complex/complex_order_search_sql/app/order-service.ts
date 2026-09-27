import { findOrders } from "./order-repository";

export async function searchTenantOrders(input: {
  tenantId: string;
  term: string;
  status: string;
}) {
  const normalizedStatus = input.status.trim().toLowerCase() || "open";
  return findOrders({
    tenantId: input.tenantId,
    term: input.term.trim(),
    status: normalizedStatus
  });
}
