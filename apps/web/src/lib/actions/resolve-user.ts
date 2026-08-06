"use server";

import "@/lib/init/server";
import { headers } from "next/headers";
import { db } from "@onecli/db";
import { getSessionEnforcer } from "@onecli/api/providers";
import {
  resolveProjectId,
  resolveOrganizationIdFromProject,
} from "@onecli/api/middleware/auth/resolve";
import { getServerSession } from "@/lib/auth/server";

export interface UserContext {
  userId: string;
  userEmail: string;
  organizationId: string;
  projectId: string;
}

export interface ResolveOptions {
  fallbackToDefault?: boolean;
}

/**
 * Resolves the current user, their organization and the active project for a
 * server action.
 *
 * Delegates to the same `resolveProjectId` and session enforcer the `/v1/*`
 * middleware uses: server actions bypass the API app, and `x-project-id` is
 * client-supplied on any path without a `/p/<id>` prefix.
 */
export const resolveProjectContext = async (
  options?: ResolveOptions,
): Promise<UserContext> => {
  void options;
  const session = await getServerSession();
  if (!session) throw new Error("Not authenticated");

  const user = await db.user.findUnique({
    where: { externalAuthId: session.id },
    select: { id: true, email: true },
  });

  if (!user) throw new Error("User not found");

  const enforcer = getSessionEnforcer();
  if (enforcer) {
    const denial = await enforcer(session, user);
    if (denial) throw new Error(denial.error);
  }

  const projectId = await resolveProjectId(await headers(), user.id);
  if (!projectId) throw new Error("No project found");

  const organizationId = await resolveOrganizationIdFromProject(projectId);
  if (!organizationId) throw new Error("No project found");

  return {
    userId: user.id,
    userEmail: user.email,
    organizationId,
    projectId,
  };
};
