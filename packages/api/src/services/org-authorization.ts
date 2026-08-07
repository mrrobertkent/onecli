import { getRoleResolver, ROLE_HIERARCHY, type OrgRole } from "../providers";

/**
 * Why a caller was refused. The two are distinct to the person reading the
 * message: "you are not in this organization" and "your role is too low" call
 * for different next steps.
 */
export type OrgRoleRefusal = "not-a-member" | "insufficient";

export type OrgRoleDecision =
  | { ok: true; role: OrgRole }
  | { ok: false; reason: OrgRoleRefusal };

/**
 * The single minimum-org-role decision. Both edges call it: the `/v1/*` auth
 * middleware, and Next server actions, which never reach that middleware and
 * would otherwise carry a second copy of the rule that agrees only until one of
 * them is edited.
 *
 * Fail-closed on every uncertainty. An unregistered resolver refuses rather
 * than admits — that state is a misconfiguration, and under D-2 a
 * misconfiguration denies.
 */
export const resolveOrgRoleAtLeast = async (
  userId: string,
  organizationId: string,
  minimum: OrgRole,
): Promise<OrgRoleDecision> => {
  const resolver = getRoleResolver();
  if (!resolver) return { ok: false, reason: "not-a-member" };

  const role = await resolver.getUserRole(userId, organizationId);
  if (!role) return { ok: false, reason: "not-a-member" };

  if (ROLE_HIERARCHY[role] < ROLE_HIERARCHY[minimum]) {
    return { ok: false, reason: "insufficient" };
  }
  return { ok: true, role };
};
