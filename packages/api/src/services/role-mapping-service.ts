import { db } from "@onecli/db";
import { ServiceError } from "./errors";
import { activeMembershipWhere } from "./organization-service";
import { MEMBERSHIP_MODES } from "./group-modes";
import {
  listRoleMappingRules,
  pickRoleFromMappings,
  readIdpGroupsFor,
  type RoleMappingRule,
} from "./role-resolution";

export interface RoleMappingRecord {
  id: string;
  groupId: string;
  groupName: string;
  role: string;
  priority: number;
  memberCount: number;
  createdAt: string;
  updatedAt: string;
}

const mappingSelect = {
  id: true,
  groupId: true,
  role: true,
  priority: true,
  createdAt: true,
  updatedAt: true,
  group: { select: { name: true, membershipMode: true } },
} as const;

type MappingFields = {
  id: string;
  groupId: string;
  role: string;
  priority: number;
  createdAt: Date;
  updatedAt: Date;
  group: { name: string; membershipMode: string };
};

const decorate = async (
  organizationId: string,
  mappings: MappingFields[],
): Promise<RoleMappingRecord[]> => {
  const counts = new Map<string, number>();

  const explicitIds = mappings
    .filter((m) => m.group.membershipMode !== MEMBERSHIP_MODES.ALL_USERS)
    .map((m) => m.groupId);
  if (explicitIds.length > 0) {
    const rows = await db.groupMember.groupBy({
      by: ["groupId"],
      where: {
        groupId: { in: explicitIds },
        user: {
          organizationMemberships: {
            some: { organizationId, ...activeMembershipWhere },
          },
        },
      },
      _count: { userId: true },
    });
    for (const row of rows) counts.set(row.groupId, row._count.userId);
  }

  const hasAllUsers = mappings.some(
    (m) => m.group.membershipMode === MEMBERSHIP_MODES.ALL_USERS,
  );
  const orgTotal = hasAllUsers
    ? await db.organizationMember.count({
        where: { organizationId, ...activeMembershipWhere },
      })
    : 0;

  return mappings.map((m) => ({
    id: m.id,
    groupId: m.groupId,
    groupName: m.group.name,
    role: m.role,
    priority: m.priority,
    memberCount:
      m.group.membershipMode === MEMBERSHIP_MODES.ALL_USERS
        ? orgTotal
        : (counts.get(m.groupId) ?? 0),
    createdAt: m.createdAt.toISOString(),
    updatedAt: m.updatedAt.toISOString(),
  }));
};

/** Highest priority first — the order resolution walks. */
export const listRoleMappings = async (
  organizationId: string,
): Promise<RoleMappingRecord[]> => {
  const mappings = await db.groupRoleMapping.findMany({
    where: { organizationId },
    select: mappingSelect,
    orderBy: [{ priority: "desc" }, { createdAt: "asc" }],
  });
  return decorate(organizationId, mappings);
};

const requireMapping = async (organizationId: string, id: string) => {
  const mapping = await db.groupRoleMapping.findFirst({
    where: { id, organizationId },
    select: mappingSelect,
  });
  if (!mapping) throw new ServiceError("NOT_FOUND", "Role mapping not found");
  return mapping;
};

/**
 * A new mapping lands at the bottom of the order. Adding one must never
 * silently outrank a decision the administrator already made.
 */
const nextPriority = async (organizationId: string): Promise<number> => {
  const lowest = await db.groupRoleMapping.findFirst({
    where: { organizationId },
    select: { priority: true },
    orderBy: { priority: "asc" },
  });
  return lowest ? lowest.priority - 1 : 0;
};

export const createRoleMapping = async (
  organizationId: string,
  input: { groupId: string; role: "admin" | "member"; priority?: number },
): Promise<RoleMappingRecord> => {
  const group = await db.group.findFirst({
    where: { id: input.groupId, organizationId },
    select: { id: true },
  });
  if (!group) throw new ServiceError("NOT_FOUND", "Group not found");

  const existing = await db.groupRoleMapping.findUnique({
    where: { groupId: input.groupId },
    select: { id: true },
  });
  if (existing) {
    throw new ServiceError("CONFLICT", "This group already maps to a role");
  }

  const mapping = await db.groupRoleMapping.create({
    data: {
      organizationId,
      groupId: input.groupId,
      role: input.role,
      priority: input.priority ?? (await nextPriority(organizationId)),
    },
    select: mappingSelect,
  });
  const [record] = await decorate(organizationId, [mapping]);
  if (!record) throw new ServiceError("NOT_FOUND", "Role mapping not found");
  return record;
};

export const updateRoleMapping = async (
  organizationId: string,
  id: string,
  input: { role: "admin" | "member"; priority?: number },
): Promise<RoleMappingRecord> => {
  await requireMapping(organizationId, id);
  const mapping = await db.groupRoleMapping.update({
    where: { id },
    data: {
      role: input.role,
      ...(input.priority === undefined ? {} : { priority: input.priority }),
    },
    select: mappingSelect,
  });
  const [record] = await decorate(organizationId, [mapping]);
  if (!record) throw new ServiceError("NOT_FOUND", "Role mapping not found");
  return record;
};

export const deleteRoleMapping = async (
  organizationId: string,
  id: string,
): Promise<RoleMappingRecord> => {
  const mapping = await requireMapping(organizationId, id);
  const [record] = await decorate(organizationId, [mapping]);
  await db.groupRoleMapping.delete({ where: { id } });
  if (!record) throw new ServiceError("NOT_FOUND", "Role mapping not found");
  return record;
};

/**
 * Renumber the whole order from a full list, index 0 highest. Every mapping in
 * the org must appear: a partial order would leave the omitted ones at
 * priorities that no longer mean anything.
 */
export const reorderRoleMappings = async (
  organizationId: string,
  orderedIds: string[],
): Promise<RoleMappingRecord[]> => {
  const mappings = await db.groupRoleMapping.findMany({
    where: { organizationId },
    select: { id: true },
  });
  const known = new Set(mappings.map((m) => m.id));
  const supplied = new Set(orderedIds);
  if (
    supplied.size !== orderedIds.length ||
    supplied.size !== known.size ||
    orderedIds.some((id) => !known.has(id))
  ) {
    throw new ServiceError(
      "UNPROCESSABLE",
      "The order must list every role mapping in this organization exactly once",
    );
  }

  await db.$transaction(
    orderedIds.map((id, index) =>
      db.groupRoleMapping.update({
        where: { id },
        data: { priority: orderedIds.length - index },
      }),
    ),
  );
  return listRoleMappings(organizationId);
};

/**
 * How many members would change role if this mapping were applied.
 *
 * Evaluated the way login does — against each member's directory groups, not
 * against local group rows, because that is what `resolveRoleFromGroups` reads.
 * Owners are excluded: their role is never rewritten from the directory.
 */
export const previewRoleMapping = async (
  organizationId: string,
  input: { groupId: string; role: "admin" | "member" },
): Promise<{ affectedCount: number }> => {
  const group = await db.group.findFirst({
    where: { id: input.groupId, organizationId },
    select: { name: true },
  });
  if (!group) throw new ServiceError("NOT_FOUND", "Group not found");

  const existing = await db.groupRoleMapping.findUnique({
    where: { groupId: input.groupId },
    select: { priority: true },
  });
  const priority = existing?.priority ?? (await nextPriority(organizationId));

  const rules: RoleMappingRule[] = [
    ...(await listRoleMappingRules(organizationId)).filter(
      (r) => r.groupName !== group.name,
    ),
    { groupName: group.name, role: input.role, priority },
  ].sort((a, b) => b.priority - a.priority);

  const members = await db.organizationMember.findMany({
    where: { organizationId, role: { not: "owner" } },
    select: { userId: true, role: true, status: true },
  });
  const directory = await readIdpGroupsFor(members.map((m) => m.userId));

  let affectedCount = 0;
  for (const member of members) {
    const groups = directory.get(member.userId);
    // No directory identity: login would leave this member exactly as they are.
    if (groups === null || groups === undefined) continue;
    const resolved = pickRoleFromMappings(rules, groups);
    const current = member.status === "suspended" ? null : member.role;
    if (resolved !== current) affectedCount += 1;
  }
  return { affectedCount };
};
