import { db } from "@onecli/db";
import { logger } from "../lib/logger";
import { OIDC_GROUPS_CLAIM_PATH } from "../lib/env";
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

// ── The directory read ───────────────────────────────────────────────────

/**
 * Group names from the most recent OIDC `id_token` each user signed in with, or
 * null for a user with no directory identity at all.
 *
 * The distinction decides whether the directory governs that user: an empty
 * array means it grants them nothing, null means it has no opinion. Collapse
 * the two and a password account is suspended at its next login.
 */
export const readIdpGroupsFor = async (
  userIds: string[],
): Promise<Map<string, string[] | null>> => {
  const resolved = new Map<string, string[] | null>(
    userIds.map((id) => [id, null]),
  );
  if (userIds.length === 0) return resolved;

  const accounts = await db.authAccount.findMany({
    where: { userId: { in: userIds }, idToken: { not: null } },
    select: { userId: true, idToken: true },
    orderBy: { updatedAt: "asc" },
  });
  // Ascending order leaves the newest token as the last write per user.
  for (const account of accounts) {
    if (!account.idToken) continue;
    const claims = decodeJwtPayload(account.idToken);
    resolved.set(
      account.userId,
      claims ? readClaimPath(claims, OIDC_GROUPS_CLAIM_PATH) : [],
    );
  }
  return resolved;
};

export const readIdpGroups = async (userId: string): Promise<string[] | null> =>
  (await readIdpGroupsFor([userId])).get(userId) ?? null;

/**
 * Decode a JWT payload without verifying it. Only safe on a persisted token
 * that was verified before storage — never on one that arrived in a request.
 */
const decodeJwtPayload = (token: string): Record<string, unknown> | null => {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const json = Buffer.from(payload, "base64url").toString("utf8");
    const parsed: unknown = JSON.parse(json);
    if (typeof parsed !== "object" || parsed === null) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
};

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

/** One group→role mapping, reduced to what resolution actually reads. */
export interface RoleMappingRule {
  groupName: string;
  role: string;
  priority: number;
}

/** Every mapping in the org, highest priority first, ties broken by age. */
export const listRoleMappingRules = async (
  organizationId: string,
): Promise<RoleMappingRule[]> => {
  const mappings = await db.groupRoleMapping.findMany({
    where: { organizationId, group: { organizationId } },
    select: { role: true, priority: true, group: { select: { name: true } } },
    orderBy: [{ priority: "desc" }, { createdAt: "asc" }],
  });
  return mappings.map((m) => ({
    groupName: m.group.name,
    role: m.role,
    priority: m.priority,
  }));
};

/**
 * The role a set of directory group names resolves to; highest priority wins.
 *
 * Returns `null` when nothing matches — a denial, not a default of "member".
 * Mapped roles are `admin | member` only: letting an IdP group confer `owner`
 * would hand the instance to anyone who can edit a group in the directory.
 *
 * Rules must already be priority-ordered.
 */
export const pickRoleFromMappings = (
  rules: RoleMappingRule[],
  groupNames: string[],
): OrgRole | null => {
  if (groupNames.length === 0) return null;
  const names = new Set(groupNames);

  for (const rule of rules) {
    if (!names.has(rule.groupName)) continue;
    if (rule.role === "admin" || rule.role === "member") return rule.role;
    logger.warn(
      { role: rule.role },
      "group role mapping has a non-assignable role; skipping",
    );
  }
  return null;
};

export const resolveRoleFromGroups = async (
  organizationId: string,
  groupNames: string[],
): Promise<OrgRole | null> => {
  if (groupNames.length === 0) return null;
  return pickRoleFromMappings(
    await listRoleMappingRules(organizationId),
    groupNames,
  );
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
