import { db } from "@onecli/db";
import { logger } from "../lib/logger";
import type { OrgRole, RoleResolver } from "../providers/types";
import { activeMembershipWhere } from "./organization-service";

/**
 * Role resolution, split in two: a login-time writer that reads the IdP claim
 * once and persists the result, and a per-request reader that only ever looks
 * at what was persisted. A claim carried in a session is captured at sign-in
 * and never refreshed, so authorization must not read it — which is why
 * `RoleResolver` is not group-aware.
 */

// ── The reader ───────────────────────────────────────────────────────────

/**
 * The OSS `RoleResolver`: one indexed read of the persisted membership role.
 * Suspended members resolve to `null` rather than their stale role, which
 * callers treat as denied.
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
 * Read a claim by dotted path rather than by name: Authentik and Okta put
 * groups at a flat `groups`, but Keycloak puts roles at `realm_access.roles`.
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
 * mappings; highest `priority` wins.
 *
 * Returns `null` when nothing matches — a denial, not a default of "member".
 * Mapped roles are `admin | member` only: letting an IdP group confer `owner`
 * would hand the instance to anyone who can edit a group in the directory.
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
 * Persist a resolved role onto an existing membership, reinstating it if the
 * directory had previously stopped mapping the user.
 *
 * Never promotes to or demotes from `owner`, so an owner whose groups change
 * in the IdP keeps the instance reachable.
 */
export const writeResolvedRole = async (
  organizationId: string,
  userId: string,
  role: OrgRole,
): Promise<{ changed: boolean; from: OrgRole | null }> => {
  const existing = await db.organizationMember.findFirst({
    where: { organizationId, userId },
    select: { role: true, status: true },
  });
  const from = existing && isOrgRole(existing.role) ? existing.role : null;

  if (from === "owner") return { changed: false, from };
  const suspended = existing?.status === "suspended";
  if (from === role && !suspended) return { changed: false, from };

  await db.organizationMember.update({
    where: { organizationId_userId: { organizationId, userId } },
    data: { role, status: "active", suspendedAt: null },
  });
  return { changed: true, from };
};

/**
 * Suspend a membership the directory no longer maps to any role. Suspended
 * rather than deleted so the grant can be reinstated and audited; authorization
 * already treats a suspended member as a non-member. An `owner` is never
 * suspended.
 */
export const revokeResolvedRole = async (
  organizationId: string,
  userId: string,
): Promise<{ changed: boolean; from: OrgRole | null }> => {
  const existing = await db.organizationMember.findFirst({
    where: { organizationId, userId },
    select: { role: true, status: true },
  });
  if (!existing) return { changed: false, from: null };

  const from = isOrgRole(existing.role) ? existing.role : null;
  if (from === "owner") return { changed: false, from };
  if (existing.status === "suspended") return { changed: false, from };

  await db.organizationMember.update({
    where: { organizationId_userId: { organizationId, userId } },
    data: { status: "suspended", suspendedAt: new Date() },
  });
  return { changed: true, from };
};
