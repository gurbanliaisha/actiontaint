"use server";

import { prisma } from "./db";

export async function deletePost(formData: FormData) {
  const postId = formData.get("postId") as string;
  await prisma.post.delete({
    where: { id: postId }
  });
}
