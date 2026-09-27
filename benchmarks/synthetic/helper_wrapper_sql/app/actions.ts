"use server";

import { findUsersByTerm } from "./db";

export async function searchUsers(formData: FormData) {
  const term = formData.get("term") as string;
  await findUsersByTerm(term);
}
