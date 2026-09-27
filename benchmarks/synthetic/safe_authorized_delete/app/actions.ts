"use server";

import { auth } from "./auth";
import { prisma } from "./db";

export async function deletePost(formData: FormData) {
  const session = await auth();
  const postId = formData.get("postId") as string;
  await prisma.post.delete({
    where: {
      id: postId,
      userId: session.user.id
    }
  });
}
