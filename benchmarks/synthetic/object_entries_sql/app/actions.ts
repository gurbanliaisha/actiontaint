"use server";

import { db } from "./db";

export async function inviteUser(formData: FormData) {
  const body = Object.fromEntries(formData);
  await db.query(`INSERT INTO invites(email) VALUES ('${body.email}')`);
}
