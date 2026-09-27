"use server";
import { db } from "./db";
// C16 default-exported anonymous Server Action (TRUE SQLi)
export default async function (formData: FormData) {
  await db.query("SELECT " + formData.get("q"));
}
