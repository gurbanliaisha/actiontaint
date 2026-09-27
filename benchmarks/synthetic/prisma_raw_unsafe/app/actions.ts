"use server";

import { prisma } from "./db";

export async function searchUsers(formData: FormData) {
  const term = formData.get("term") as string;
  const query = `SELECT * FROM users WHERE email LIKE '%${term}%'`;
  await prisma.$queryRawUnsafe(query);
}
