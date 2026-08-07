import { db } from "@onecli/db";
import { ServiceError } from "./errors";
import { activeMembershipWhere } from "./organization-service";
import type { DirectoryListParams, DirectoryPage } from "./group-service";

export interface OrgMemberRecord {
  userId: string;
  email: string;
  name: string | null;
  role: string;
  status: string;
  ssoExempt: boolean;
  joinedAt: string;
}

export interface OrgMemberChange {
  userId: string;
  role: string;
  status: string;
  ssoExempt: boolean;
  /** Sessions ended by this change. A revocation that leaves them is not one. */
  sessionsRevoked: number;
}

const statusWhere = (status?: string) => {
  if (status === "suspended") return { status: "suspended" };
  if (status === "active") return activeMembershipWhere;
  return {};
};

export const listOrgMembers = async (
  organizationId: string,
  params: DirectoryListParams & { status?: string },
): Promise<DirectoryPage<OrgMemberRecord>> => {
  const membership = { organizationId, ...statusWhere(params.status) };
  const rows = await db.user.findMany({
    where: {
      ...(params.q
        ? {
            OR: [
              { email: { contains: params.q, mode: "insensitive" as const } },
              { name: { contains: params.q, mode: "insensitive" as const } },
            ],
          }
        : {}),
      organizationMemberships: { some: membership },
    },
    select: {
      id: true,
      email: true,
      name: true,
      organizationMemberships: {
        where: { organizationId },
        select: {
          role: true,
          status: true,
          ssoExempt: true,
          createdAt: true,
        },
        take: 1,
      },
    },
    orderBy: [{ email: "asc" }, { id: "asc" }],
    take: params.limit + 1,
    ...(params.cursor ? { cursor: { id: params.cursor }, skip: 1 } : {}),
  });

  const page = rows.slice(0, params.limit);
  const nextCursor =
    rows.length > params.limit ? (page[page.length - 1]?.id ?? null) : null;

  return {
    data: page.flatMap((user) => {
      const member = user.organizationMemberships[0];
      if (!member) return [];
      return [
        {
          userId: user.id,
          email: user.email,
          name: user.name,
          role: member.role,
          status: member.status,
          ssoExempt: member.ssoExempt,
          joinedAt: member.createdAt.toISOString(),
        },
      ];
    }),
    nextCursor,
  };
};

/**
 * Load a membership this caller is allowed to act on.
 *
 * An admin may not touch an owner row. `owner` is the one role the directory
 * cannot confer (D-11), so letting an admin demote or suspend one would hand
 * back the escalation path that rule closes — an owner may, because appointing
 * or removing a peer needs the top role already and opens no new path.
 *
 * Acting on yourself is refused either way: it is the lockout this surface
 * exists to prevent.
 *
 * Those two rules together are what keeps an owner in the organization. An
 * owner is demotable only by another owner and never by themselves, so there
 * are always at least two at the moment of a demotion and never fewer than one
 * after it. Relax the self-edit rule and that floor needs writing explicitly.
 */
const requireEditableMember = async (
  organizationId: string,
  userId: string,
  actor: MemberActor,
) => {
  if (userId === actor.userId) {
    throw new ServiceError(
      "CONFLICT",
      "You cannot change your own role or access",
    );
  }
  const member = await db.organizationMember.findFirst({
    where: { organizationId, userId },
    select: { role: true, status: true, ssoExempt: true },
  });
  if (!member) throw new ServiceError("NOT_FOUND", "Member not found");
  if (member.role === "owner" && actor.role !== "owner") {
    throw new ServiceError(
      "FORBIDDEN",
      "Only an owner may change another owner's role or access",
    );
  }
  return member;
};

export interface MemberActor {
  userId: string;
  role?: string;
}

export const changeMemberRole = async (
  organizationId: string,
  userId: string,
  role: "owner" | "admin" | "member",
  actor: MemberActor,
): Promise<OrgMemberChange> => {
  const member = await requireEditableMember(organizationId, userId, actor);

  if (role === "owner" && actor.role !== "owner") {
    throw new ServiceError(
      "FORBIDDEN",
      "Only an owner may appoint another owner",
    );
  }

  const updated = await db.organizationMember.update({
    where: { organizationId_userId: { organizationId, userId } },
    data: { role },
    select: { role: true, status: true, ssoExempt: true },
  });
  return {
    userId,
    role: updated.role,
    status: updated.status,
    ssoExempt: member.ssoExempt,
    sessionsRevoked: 0,
  };
};

/**
 * Suspend or reinstate a member. Suspension also deletes their sessions:
 * sessions are database-backed, so without this the member keeps the access
 * they were just refused until their cookie expires.
 */
export const setMemberStatus = async (
  organizationId: string,
  userId: string,
  status: "active" | "suspended",
  actor: MemberActor,
): Promise<OrgMemberChange> => {
  const member = await requireEditableMember(organizationId, userId, actor);

  // Demote first, deliberately: suspension is the directory's revocation, and
  // an owner is exactly who the directory may not revoke.
  if (member.role === "owner" && status === "suspended") {
    throw new ServiceError(
      "CONFLICT",
      "An owner cannot be suspended. Change their role first.",
    );
  }

  const updated = await db.organizationMember.update({
    where: { organizationId_userId: { organizationId, userId } },
    data:
      status === "suspended"
        ? { status: "suspended", suspendedAt: new Date() }
        : { status: "active", suspendedAt: null },
    select: { role: true, status: true, ssoExempt: true },
  });

  const revoked =
    status === "suspended"
      ? await db.authSession.deleteMany({ where: { userId } })
      : { count: 0 };

  return {
    userId,
    role: updated.role,
    status: updated.status,
    ssoExempt: updated.ssoExempt,
    sessionsRevoked: revoked.count,
  };
};

export const setMemberSsoExempt = async (
  organizationId: string,
  userId: string,
  ssoExempt: boolean,
  actor: MemberActor,
): Promise<OrgMemberChange> => {
  await requireEditableMember(organizationId, userId, actor);
  const updated = await db.organizationMember.update({
    where: { organizationId_userId: { organizationId, userId } },
    data: { ssoExempt },
    select: { role: true, status: true, ssoExempt: true },
  });
  return {
    userId,
    role: updated.role,
    status: updated.status,
    ssoExempt: updated.ssoExempt,
    sessionsRevoked: 0,
  };
};
