import { db } from "@onecli/db";

// TS mirror of the gateway's `find_principal_set` CTE (apps/gateway/src/db.rs);
// keep the two in lockstep. The principals an agent's requests are matched
// against: the humans it inherits from its project's ProjectAccess (direct
// users plus members of granted groups, active org members only) and every
// directory group those humans belong to. Every arm is org-fenced, and the
// result is agent-independent, so one resolution covers a whole project.

export interface PrincipalSet {
  userIds: string[];
  groupIds: string[];
}

export const resolvePrincipalSet = async (
  projectId: string,
  organizationId: string,
): Promise<PrincipalSet> => {
  // ProjectAccess rows: direct users + candidate granted groups.
  const accessRows = await db.projectAccess.findMany({
    where: { projectId },
    select: { userId: true, groupId: true },
  });
  const directUserIds = accessRows.flatMap((r) => (r.userId ? [r.userId] : []));
  const groupCandidates = accessRows.flatMap((r) =>
    r.groupId ? [r.groupId] : [],
  );

  // direct_groups: org-fenced — a granted group must belong to this org.
  const directGroups = groupCandidates.length
    ? (
        await db.group.findMany({
          where: { id: { in: groupCandidates }, organizationId },
          select: { id: true },
        })
      ).map((g) => g.id)
    : [];

  // candidate_users: direct ProjectAccess users ∪ members of the direct groups.
  const groupMemberUserIds = directGroups.length
    ? (
        await db.groupMember.findMany({
          where: { groupId: { in: directGroups } },
          select: { userId: true },
        })
      ).map((m) => m.userId)
    : [];
  const candidateUserIds = [
    ...new Set([...directUserIds, ...groupMemberUserIds]),
  ];

  // all_users: only active org members contribute — a suspended member is
  // excluded, mirroring `user_can_manage_project`.
  const userIds = candidateUserIds.length
    ? (
        await db.organizationMember.findMany({
          where: {
            userId: { in: candidateUserIds },
            organizationId,
            status: { not: "suspended" },
          },
          select: { userId: true },
        })
      ).map((m) => m.userId)
    : [];

  // all_groups: the direct grants ∪ every group the inherited users belong to —
  // org-fenced, because a user can belong to OTHER orgs' groups.
  const userGroupIds = userIds.length
    ? (
        await db.groupMember.findMany({
          where: { userId: { in: userIds }, group: { organizationId } },
          select: { groupId: true },
        })
      ).map((m) => m.groupId)
    : [];
  const groupIds = [...new Set([...directGroups, ...userGroupIds])];

  return { userIds, groupIds };
};
