import "@/lib/init/server";
import { resolveOrgRoleAtLeast } from "@onecli/api/services/org-authorization";
import type { OrgRole } from "@onecli/api/providers";
import { resolveProjectContext, type UserContext } from "./resolve-user";

export interface AuthorizedContext extends UserContext {
  role: OrgRole;
}

/** Thrown rather than returned so a caller cannot forget to check. */
export class OrgRoleError extends Error {}

/**
 * The org-role gate for server actions, over the same decision the `/v1/*`
 * middleware makes. Not a server action itself — it is a guard the actions
 * call, so it must not become an endpoint of its own.
 *
 * Inherits `resolveProjectContext`'s failure modes, including its throw for a
 * user with no project.
 */
export const requireOrgRole = async (
  minimum: OrgRole,
): Promise<AuthorizedContext> => {
  const context = await resolveProjectContext();
  const decision = await resolveOrgRoleAtLeast(
    context.userId,
    context.organizationId,
    minimum,
  );
  if (!decision.ok) {
    throw new OrgRoleError(
      decision.reason === "insufficient"
        ? `This action requires the ${minimum} role.`
        : "You are not a member of this organization.",
    );
  }
  return { ...context, role: decision.role };
};
