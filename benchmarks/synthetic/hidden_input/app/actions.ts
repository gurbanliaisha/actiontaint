"use server";

import fs from "fs/promises";

export async function readAttachment(formData: FormData) {
  const path = formData.get("path") as string;
  await fs.readFile(path);
}
