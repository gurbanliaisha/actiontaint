"use server";

import { db } from "./db";

export async function updateTenant(tenantId: string, formData: FormData) {
  const name = formData.get("name") as string;
  await db.query(`UPDATE tenants SET name = '${name}' WHERE id = '${tenantId}'`);
}
