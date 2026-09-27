import { currentUser } from "./auth";

export async function requireWorkspaceAccess(workspaceId: string) {
  const user = await currentUser();
  if (user.workspaceId !== workspaceId) {
    throw new Error("Forbidden");
  }
  return user;
}
