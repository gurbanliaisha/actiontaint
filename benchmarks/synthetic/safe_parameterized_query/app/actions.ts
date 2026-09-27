"use server";

import { db } from "./db";

export async function saveProfile(formData: FormData) {
  const username = formData.get("username") as string;
  await db.query("UPDATE users SET name = ? WHERE id = ?", [username, 1]);
}
