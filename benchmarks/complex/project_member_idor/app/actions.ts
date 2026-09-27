"use server";

import { requireUser } from "./auth";
import { prisma } from "./db";

export async function removeMember(formData: FormData) {
  const user = await requireUser();
  const memberId = formData.get("memberId") as string;

  await prisma.auditLog.create({
    data: {
      actorId: user.id,
      action: "member.remove",
      targetId: memberId
    }
  });

  await prisma.projectMember.delete({
    where: {
      id: memberId
    }
  });
}
