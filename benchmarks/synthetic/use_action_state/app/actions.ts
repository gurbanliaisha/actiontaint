"use server";

import { db } from "./db";

export async function createUser(previousState: unknown, formData: FormData) {
  const email = formData.get("email") as string;
  await db.query(`INSERT INTO users(email) VALUES ('${email}')`);
  return { ok: true };
}
