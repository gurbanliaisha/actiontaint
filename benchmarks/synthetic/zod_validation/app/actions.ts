"use server";

import { z } from "zod";
import { db } from "./db";

const schema = z.object({
  username: z.string().min(1).max(64)
});

export async function saveProfile(formData: FormData) {
  const parsed = schema.parse({
    username: formData.get("username")
  });
  await db.query("UPDATE users SET name = ? WHERE id = ?", [parsed.username, 1]);
}
