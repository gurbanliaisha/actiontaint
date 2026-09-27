"use server";

import { prisma } from "./db";
import { requireWorkspaceAccess } from "./policy";

export async function renameTask(workspaceId: string, formData: FormData) {
  const user = await requireWorkspaceAccess(workspaceId);
  const taskId = formData.get("taskId") as string;
  const title = formData.get("title") as string;

  await prisma.task.update({
    where: {
      id: taskId,
      workspaceId,
      ownerId: user.id
    },
    data: {
      title
    }
  });
}
