import { db } from "./db";

type SearchFilters = {
  tenantId: string;
  term: string;
  status: string;
};

export async function findOrders(filters: SearchFilters) {
  const where = [
    `tenant_id = '${filters.tenantId}'`,
    `status = '${filters.status}'`,
    `(customer_email LIKE '%${filters.term}%' OR notes LIKE '%${filters.term}%')`
  ].join(" AND ");

  return db.query(`SELECT * FROM orders WHERE ${where} ORDER BY created_at DESC`);
}
