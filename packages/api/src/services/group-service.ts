import { db, Prisma } from "@onecli/db";
import { ServiceError } from "./errors";
import { activeMembershipWhere } from "./organization-service";
import {
  groupIncludesUser,
  MEMBERSHIP_MODES,
  PROJECT_ACCESS_MODES,
} from "./group-modes";

export interface GroupRecord {
  id: string;
  name: string;
  source: string;
  externalId: string | null;
  membershipMode: string;
  projectAccessMode: string;
  memberCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface GroupMemberRecord {
  userId: string;
  email: string;
  name: string | null;
  addedAt: string;
}

export interface DirectoryPage<T> {
  data: T[];
  nextCursor: string | null;
}

export interface DirectoryListParams {
  limit: number;
  cursor?: string;
  q?: string;
}

const groupSelect = {
  id: true,
  name: true,
  source: true,
  externalId: true,
  membershipMode: true,
  projectAccessMode: true,
  createdAt: true,
  updatedAt: true,
} as const;

type GroupFields = Prisma.GroupGetPayload<{ select: typeof groupSelect }>;

/**
 * Member counts for a page of groups in two reads: one grouped count over the
 * explicit rows, and — only if some group is in all-users mode — one count of
 * the organization's active members. Suspended members count for neither.
 */
const countMembers = async (
  organizationId: string,
  groups: GroupFields[],
): Promise<Map<string, number>> => {
  const counts = new Map<string, number>();

  const explicitIds = groups
    .filter((g) => g.membershipMode !== MEMBERSHIP_MODES.ALL_USERS)
    .map((g) => g.id);
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
    for (const id of explicitIds) if (!counts.has(id)) counts.set(id, 0);
  }

  const hasAllUsers = groups.some(
    (g) => g.membershipMode === MEMBERSHIP_MODES.ALL_USERS,
  );
  if (hasAllUsers) {
    const total = await db.organizationMember.count({
      where: { organizationId, ...activeMembershipWhere },
    });
    for (const group of groups) {
      if (group.membershipMode === MEMBERSHIP_MODES.ALL_USERS) {
        counts.set(group.id, total);
      }
    }
  }

  return counts;
};

const toGroupRecord = (
  group: GroupFields,
  memberCount: number,
): GroupRecord => ({
  id: group.id,
  name: group.name,
  source: group.source,
  externalId: group.externalId,
  membershipMode: group.membershipMode,
  projectAccessMode: group.projectAccessMode,
  memberCount,
  createdAt: group.createdAt.toISOString(),
  updatedAt: group.updatedAt.toISOString(),
});

const decorate = async (
  organizationId: string,
  groups: GroupFields[],
): Promise<GroupRecord[]> => {
  const counts = await countMembers(organizationId, groups);
  return groups.map((g) => toGroupRecord(g, counts.get(g.id) ?? 0));
};

/** One extra row is read to decide whether a further page exists. */
const paginate = <T extends { id: string }>(
  rows: T[],
  limit: number,
): { page: T[]; nextCursor: string | null } => {
  if (rows.length <= limit) return { page: rows, nextCursor: null };
  const page = rows.slice(0, limit);
  return { page, nextCursor: page[page.length - 1]?.id ?? null };
};

export const listGroups = async (
  organizationId: string,
  params: DirectoryListParams & { source?: string },
): Promise<DirectoryPage<GroupRecord>> => {
  const rows = await db.group.findMany({
    where: {
      organizationId,
      ...(params.source ? { source: params.source } : {}),
      ...(params.q
        ? { name: { contains: params.q, mode: "insensitive" as const } }
        : {}),
    },
    select: groupSelect,
    orderBy: [{ name: "asc" }, { id: "asc" }],
    take: params.limit + 1,
    ...(params.cursor ? { cursor: { id: params.cursor }, skip: 1 } : {}),
  });

  const { page, nextCursor } = paginate(rows, params.limit);
  return { data: await decorate(organizationId, page), nextCursor };
};

/** The groups a user belongs to, explicit rows and all-users groups alike. */
export const listGroupsForUser = async (
  organizationId: string,
  userId: string,
): Promise<DirectoryPage<GroupRecord>> => {
  const rows = await db.group.findMany({
    where: { organizationId, ...groupIncludesUser(userId) },
    select: groupSelect,
    orderBy: [{ name: "asc" }, { id: "asc" }],
  });
  return { data: await decorate(organizationId, rows), nextCursor: null };
};

const requireGroup = async (
  organizationId: string,
  groupId: string,
): Promise<GroupFields> => {
  const group = await db.group.findFirst({
    where: { id: groupId, organizationId },
    select: groupSelect,
  });
  if (!group) throw new ServiceError("NOT_FOUND", "Group not found");
  return group;
};

/** Directory-owned groups keep their shape from the IdP, not from us. */
const requireManaged = (group: GroupFields): void => {
  if (group.source !== "manual") {
    throw new ServiceError(
      "CONFLICT",
      "This group is managed by the identity provider and cannot be edited here",
    );
  }
};

export const createGroup = async (
  organizationId: string,
  input: {
    name: string;
    membershipMode?: string;
    projectAccessMode?: string;
  },
): Promise<GroupRecord> => {
  const existing = await db.group.findFirst({
    where: { organizationId, name: input.name },
    select: { id: true },
  });
  if (existing) {
    throw new ServiceError("CONFLICT", "A group with that name already exists");
  }

  const group = await db.group.create({
    data: {
      organizationId,
      name: input.name,
      membershipMode: input.membershipMode ?? MEMBERSHIP_MODES.EXPLICIT,
      projectAccessMode:
        input.projectAccessMode ?? PROJECT_ACCESS_MODES.SELECTED,
    },
    select: groupSelect,
  });
  const counts = await countMembers(organizationId, [group]);
  return toGroupRecord(group, counts.get(group.id) ?? 0);
};

export const updateGroup = async (
  organizationId: string,
  groupId: string,
  input: {
    name?: string;
    membershipMode?: string;
    projectAccessMode?: string;
  },
): Promise<GroupRecord> => {
  const group = await requireGroup(organizationId, groupId);
  requireManaged(group);

  if (input.name && input.name !== group.name) {
    const clash = await db.group.findFirst({
      where: { organizationId, name: input.name, id: { not: groupId } },
      select: { id: true },
    });
    if (clash) {
      throw new ServiceError(
        "CONFLICT",
        "A group with that name already exists",
      );
    }
  }

  const updated = await db.group.update({
    where: { id: groupId },
    data: {
      ...(input.name ? { name: input.name } : {}),
      ...(input.membershipMode ? { membershipMode: input.membershipMode } : {}),
      ...(input.projectAccessMode
        ? { projectAccessMode: input.projectAccessMode }
        : {}),
    },
    select: groupSelect,
  });
  const counts = await countMembers(organizationId, [updated]);
  return toGroupRecord(updated, counts.get(updated.id) ?? 0);
};

/** Cascades to the group's members, project bindings and role mapping. */
export const deleteGroup = async (
  organizationId: string,
  groupId: string,
): Promise<GroupRecord> => {
  const group = await requireGroup(organizationId, groupId);
  requireManaged(group);
  const counts = await countMembers(organizationId, [group]);
  await db.group.delete({ where: { id: groupId } });
  return toGroupRecord(group, counts.get(group.id) ?? 0);
};

export const listGroupMembers = async (
  organizationId: string,
  groupId: string,
  params: DirectoryListParams,
): Promise<DirectoryPage<GroupMemberRecord>> => {
  const group = await requireGroup(organizationId, groupId);

  const search = params.q
    ? {
        OR: [
          { email: { contains: params.q, mode: "insensitive" as const } },
          { name: { contains: params.q, mode: "insensitive" as const } },
        ],
      }
    : {};

  // An all-users group has no rows to read: its members are the organization's
  // active members, resolved here and never written down.
  if (group.membershipMode === MEMBERSHIP_MODES.ALL_USERS) {
    const rows = await db.user.findMany({
      where: {
        ...search,
        organizationMemberships: {
          some: { organizationId, ...activeMembershipWhere },
        },
      },
      select: { id: true, email: true, name: true, createdAt: true },
      orderBy: [{ email: "asc" }, { id: "asc" }],
      take: params.limit + 1,
      ...(params.cursor ? { cursor: { id: params.cursor }, skip: 1 } : {}),
    });
    const { page, nextCursor } = paginate(rows, params.limit);
    return {
      data: page.map((u) => ({
        userId: u.id,
        email: u.email,
        name: u.name,
        addedAt: u.createdAt.toISOString(),
      })),
      nextCursor,
    };
  }

  const rows = await db.user.findMany({
    where: {
      ...search,
      groupMemberships: { some: { groupId } },
      organizationMemberships: {
        some: { organizationId, ...activeMembershipWhere },
      },
    },
    select: {
      id: true,
      email: true,
      name: true,
      groupMemberships: {
        where: { groupId },
        select: { createdAt: true },
        take: 1,
      },
    },
    orderBy: [{ email: "asc" }, { id: "asc" }],
    take: params.limit + 1,
    ...(params.cursor ? { cursor: { id: params.cursor }, skip: 1 } : {}),
  });
  const { page, nextCursor } = paginate(rows, params.limit);
  return {
    data: page.map((u) => ({
      userId: u.id,
      email: u.email,
      name: u.name,
      addedAt: (u.groupMemberships[0]?.createdAt ?? new Date()).toISOString(),
    })),
    nextCursor,
  };
};

/** Only users who are active members of the organization may be added. */
const requireOrgMembers = async (
  organizationId: string,
  userIds: string[],
): Promise<string[]> => {
  if (userIds.length === 0) return [];
  const members = await db.organizationMember.findMany({
    where: {
      organizationId,
      userId: { in: userIds },
      ...activeMembershipWhere,
    },
    select: { userId: true },
  });
  const found = new Set(members.map((m) => m.userId));
  const missing = userIds.filter((id) => !found.has(id));
  if (missing.length > 0) {
    throw new ServiceError(
      "UNPROCESSABLE",
      `Not an active member of this organization: ${missing.join(", ")}`,
    );
  }
  return userIds;
};

export const setGroupMembers = async (
  organizationId: string,
  groupId: string,
  userIds: string[],
  actingUserId: string,
): Promise<{ added: number; removed: number }> => {
  const group = await requireGroup(organizationId, groupId);
  requireManaged(group);

  const wanted = new Set(await requireOrgMembers(organizationId, userIds));
  const current = await db.groupMember.findMany({
    where: { groupId },
    select: { userId: true },
  });
  const held = new Set(current.map((m) => m.userId));

  const toAdd = [...wanted].filter((id) => !held.has(id));
  const toRemove = [...held].filter((id) => !wanted.has(id));

  await db.$transaction([
    ...(toRemove.length > 0
      ? [
          db.groupMember.deleteMany({
            where: { groupId, userId: { in: toRemove } },
          }),
        ]
      : []),
    ...(toAdd.length > 0
      ? [
          db.groupMember.createMany({
            data: toAdd.map((userId) => ({
              groupId,
              userId,
              createdByUserId: actingUserId,
            })),
            skipDuplicates: true,
          }),
        ]
      : []),
  ]);

  return { added: toAdd.length, removed: toRemove.length };
};

export const addGroupMember = async (
  organizationId: string,
  groupId: string,
  userId: string,
  actingUserId: string,
): Promise<void> => {
  const group = await requireGroup(organizationId, groupId);
  requireManaged(group);
  await requireOrgMembers(organizationId, [userId]);
  await db.groupMember.upsert({
    where: { groupId_userId: { groupId, userId } },
    create: { groupId, userId, createdByUserId: actingUserId },
    update: {},
  });
};

export const removeGroupMember = async (
  organizationId: string,
  groupId: string,
  userId: string,
): Promise<void> => {
  const group = await requireGroup(organizationId, groupId);
  requireManaged(group);
  await db.groupMember.deleteMany({ where: { groupId, userId } });
};
