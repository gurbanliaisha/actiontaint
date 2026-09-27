import { readFile } from "fs/promises";

export async function readTenantDocument(tenantId: string, documentName: string) {
  const path = `./data/${tenantId}/documents/${documentName}`;
  return readFile(path);
}
