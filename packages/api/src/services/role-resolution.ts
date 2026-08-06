import { db } from "@onecli/db";
import { logger } from "../lib/logger";
import type { OrgRole, RoleResolver } from "../providers/types";
import { activeMembershipWhere } from "./organization-service";

/**
 * Role resolution, split in two: a login-time WRITER that reads the IdP claim
 * once and persists the result, and a flat per-request READER that only ever
 * looks at what was persisted.
 *
 * The session model forces the split. A claim carried in a session is captured
 * at sign-in and never refreshed, so it can be stale without bound, and
 * authorization must never read it. Hence `RoleResolver` is deliberately not
 * group-aware.
 */

// ── The reader ───────────────────────────────────────────────────────────

/**
 * The OSS `RoleResolver`: one indexed read of the persisted membership role.
 *
 * Suspended members resolve to `null` (no role), not to their stale role —
 * `canAccessProjectAsUser` treats a null role as denied, and a ProjectAccess
 * binding never rescues them because the binding check lives inside the
 * active-member gate.
 */
export const ossRoleResolver: RoleResolver = {
  async getUserRole(userId, organizationId): Promise<OrgRole | null> {
    const member = await db.organizationMember.findFirst({
      where: { userId, organizationId, ...activeMembershipWhere },
      select: { role: true },
    });
    if (!member) return null;
    return isOrgRole(member.role) ? member.role : null;
  },
};

const ORG_ROLES: readonly OrgRole[] = ["owner", "admin", "member"];

const isOrgRole = (value: string): value is OrgRole =>
  (ORG_ROLES as readonly string[]).includes(value);

// ── The writer ───────────────────────────────────────────────────────────

/**
 * Read a claim by path, not by name.
 *
 * Authentik and Okta put groups at a flat `groups`; Keycloak puts roles at
 * `realm_access.roles`. A configuration storing a claim NAME cannot express the
 * second, so this walks a dotted path. Better Auth's `mapping.extraFields` is
 * flat-key only and is not used for role resolution.
 */
export const readClaimPath = (
  claims: Record<string, unknown>,
  path: string,
): string[] => {
  const segments = path.split(".").filter(Boolean);
  let cursor: unknown = claims;
  for (const segment of segments) {
    if (cursor === null || typeof cursor !== "object") return [];
    cursor = (cursor as Record<string, unknown>)[segment];
  }
  if (typeof cursor === "string") return [cursor];
  if (!Array.isArray(cursor)) return [];
  return cursor.filter((v): v is string => typeof v === "string");
};

/**
 * Resolve the IdP's group names to a role via the persisted group→role
 * mappings, highest `priority` wins.
 *
 * Returns `null` when nothing matches. That is not the same as "member": an
 * identity mapping to nothing is not admitted at all, so the caller must treat
 * null as a denial rather than substituting a default.
 *
 * Mapped roles are `admin | member` only — never `owner`. Owner is the
 * bootstrap admin's, and letting an IdP group confer it would mean anyone who
 * can edit a group in the directory can take the instance.
 */
export const resolveRoleFromGroups = async (
  organizationId: string,
  groupNames: string[],
): Promise<OrgRole | null> => {
  if (groupNames.length === 0) return null;

  const mappings = await db.groupRoleMapping.findMany({
    where: {
      organizationId,
      group: { organizationId, name: { in: groupNames } },
    },
    select: { role: true, priority: true },
    orderBy: { priority: "desc" },
  });

  for (const mapping of mappings) {
    if (mapping.role === "admin" || mapping.role === "member") {
      return mapping.role;
    }
    logger.warn(
      { role: mapping.role },
      "group role mapping has a non-assignable role; skipping",
    );
  }
  return null;
};

/**
 * Persist a resolved role onto an existing membership.
 *
 * Never promotes to or demotes FROM `owner`: the bootstrap admin's authority
 * does not answer to the directory, so an owner whose groups change in the IdP
 * keeps the instance reachable.
 */
export const writeResolvedRole = async (
  organizationId: string,
  userId: string,
  role: OrgRole,
): Promise<{ changed: boolean; from: OrgRole | null }> => {
  const existing = await db.organizationMember.findFirst({
    where: { organizationId, userId },
    select: { role: true },
  });
  const from = existing && isOrgRole(existing.role) ? existing.role : null;

  if (from === "owner") return { changed: false, from };
  if (from === role) return { changed: false, from };

  await db.organizationMember.update({
    where: { organizationId_userId: { organizationId, userId } },
    data: { role },
  });
  return { changed: true, from };
};
