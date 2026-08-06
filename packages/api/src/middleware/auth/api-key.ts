import { db } from "@onecli/db";
import type { AuthContext } from "../../providers";
import { getRoleResolver, ROLE_HIERARCHY } from "../../providers";
import { CAPS } from "../../lib/env";
import { resolveUserEmail, canAccessProjectAsUser } from "./resolve";

/**
 * API-key authentication result:
 *
 * - `AuthContext` — a valid key resolved its scope.
 * - `"missing-project"` — a valid org key hit a `requireProject` route with no
 *   `X-Project-Id` header.
 * - `"invalid-key"` — an `oc_` bearer was presented but failed authentication.
 * - `null` — the request carried no `oc_` bearer at all.
 *
 * Non-strict callers treat both string sentinels like `null` and fall through to
 * session auth; strict mode turns them into precise 401s.
 */
export type ApiKeyAuthResult =
  | AuthContext
  | "missing-project"
  | "invalid-key"
  | null;

export const authenticateApiKey = async (
  request: Request,
  requireProject: boolean,
): Promise<ApiKeyAuthResult> => {
  const header = request.headers.get("authorization");
  if (!header) return null;

  const token = header.startsWith("Bearer ") ? header.slice(7).trim() : null;
  if (!token || !token.startsWith("oc_")) return null;

  // Org key (oc_org_*)
  if (token.startsWith("oc_org_")) {
    const apiKey = await db.apiKey.findUnique({
      where: { key: token },
      select: { userId: true, organizationId: true, scope: true },
    });
    if (!apiKey || apiKey.scope !== "organization" || !apiKey.organizationId)
      return "invalid-key";

    // Re-check that the key's user still holds admin/owner, so a key stops
    // working once its holder is demoted.
    if (CAPS.rbac) {
      const resolver = getRoleResolver();
      const role = resolver
        ? await resolver.getUserRole(apiKey.userId, apiKey.organizationId)
        : null;
      if (!role || ROLE_HIERARCHY[role] < ROLE_HIERARCHY.admin)
        return "invalid-key";
    }

    const userEmail = await resolveUserEmail(apiKey.userId);
    const headerProjectId = request.headers.get("x-project-id");

    if (requireProject && !headerProjectId) return "missing-project";

    if (headerProjectId) {
      const project = await db.project.findFirst({
        where: {
          id: headerProjectId,
          organizationId: apiKey.organizationId,
        },
        select: { id: true },
      });
      if (!project) return "invalid-key";

      return {
        userId: apiKey.userId,
        userEmail,
        projectId: project.id,
        organizationId: apiKey.organizationId,
        scope: "organization",
      };
    }

    return {
      userId: apiKey.userId,
      userEmail,
      projectId: undefined,
      organizationId: apiKey.organizationId,
      scope: "organization",
    };
  }

  // Project key (oc_*)
  const apiKey = await db.apiKey.findUnique({
    where: { key: token },
    select: { userId: true, projectId: true },
  });
  if (!apiKey || !apiKey.projectId) return "invalid-key";

  const project = await db.project.findUnique({
    where: { id: apiKey.projectId },
    select: { id: true, organizationId: true },
  });
  if (!project) return "invalid-key";

  // Re-check access at request time, so the key authenticates only while its
  // user still has access to the project.
  if (!(await canAccessProjectAsUser(apiKey.userId, project)))
    return "invalid-key";

  const userEmail = await resolveUserEmail(apiKey.userId);

  return {
    userId: apiKey.userId,
    userEmail,
    projectId: apiKey.projectId,
    organizationId: project.organizationId,
    scope: "project",
  };
};
