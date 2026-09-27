"use server";

import { readTenantDocument } from "./storage";

export async function downloadTenantDocument(tenantId: string, formData: FormData) {
  const documentName = formData.get("document") as string;
  const file = await readTenantDocument(tenantId, documentName);
  return { size: file.byteLength };
}
