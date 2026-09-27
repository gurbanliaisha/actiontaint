"use server";
import { db } from "../db";
// C15 used through namespace import (TRUE SQLi)
export async function nsAction(formData: FormData) {
  await db.query("SELECT " + formData.get("q"));
}
