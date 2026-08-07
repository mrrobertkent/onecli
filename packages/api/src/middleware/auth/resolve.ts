import { db } from "@onecli/db";
import { CAPS } from "../../lib/env";
import {
  activeMembershipWhere,
  findUserDefaultProject,
} from "../../services/organization-service";
import {
  groupIncludesUser,
  PROJECT_ACCESS_MODES,
} from "../../services/group-modes";
import { getRoleResolver, ROLE_HIERARCHY } from "../../providers";

export const resolveUserEmail = async (userId: string): Promise<string> => {
  const user = await db.user.findUnique({
    where: { id: userId },
    select: { email: true },
  });
  return user?.email ?? "";
};

export const resolveOrganizationIdFromProject = async (
  projectId: string,
): Promise<string | null> => {
  const project = await db.project.findUnique({
    where: { id: projectId },
    select: { organizationId: true },
  });
  return project?.organizationId ?? null;
};

/**
 * Just the scope headers these resolvers read. Narrower than `Request` so
 * Next server actions can pass `next/headers`' store and share this code
 * rather than reimplementing the project gate.
 */
export type ScopeHeaders = Pick<Headers, "get">;

export const resolveOrganizationId = async (
  headers: ScopeHeaders,
  userId: string,
): Promise<string | null> => {
  const headerOrgId = headers.get("x-organization-id");
  if (!headerOrgId) return null;

  const membership = await db.organizationMember.findFirst({
    where: { userId, organizationId: headerOrgId, ...activeMembershipWhere },
    select: { organizationId: true },
  });

  return membership?.organizationId ?? null;
};

/**
 * Whether a user holds a ProjectAccess binding on a project, directly or via a
 * group they belong to. Only reached under `CAPS.rbac`.
 *
 * The second read is the all-projects arm: such a group binds to every project
 * in its org without a `ProjectAccess` row, so no first-read filter can find it.
 */
const hasProjectBinding = async (
  userId: string,
  project: { id: string; organizationId: string },
): Promise<boolean> => {
  const binding = await db.projectAccess.findFirst({
    where: {
      projectId: project.id,
      OR: [
        { userId },
        {
          group: {
            organizationId: project.organizationId,
            ...groupIncludesUser(userId),
          },
        },
      ],
    },
    select: { id: true },
  });
  if (binding) return true;

  const unrestricted = await db.group.findFirst({
    where: {
      organizationId: project.organizationId,
      projectAccessMode: PROJECT_ACCESS_MODES.ALL_PROJECTS,
      ...groupIncludesUser(userId),
    },
    select: { id: true },
  });
  return unrestricted !== null;
};

/**
 * Whether a user may access a project: an org admin/owner, or an active member
 * with a ProjectAccess binding (direct or via a group). Always true when the
 * edition does not enforce roles.
 */
export const canAccessProjectAsUser = async (
  userId: string,
  project: {
    id: string;
    organizationId: string;
  },
): Promise<boolean> => {
  if (!CAPS.rbac) return true;
  const resolver = getRoleResolver();
  const role = resolver
    ? await resolver.getUserRole(userId, project.organizationId)
    : null;
  // The binding check sits inside this active-member gate on purpose, so a
  // suspended user's stale binding is never consulted.
  if (!role) return false;
  if (ROLE_HIERARCHY[role] >= ROLE_HIERARCHY.admin) return true;
  return hasProjectBinding(userId, project);
};

export const resolveProjectId = async (
  headers: ScopeHeaders,
  userId: string,
): Promise<string | null> => {
  const headerProjectId = headers.get("x-project-id");
  if (!headerProjectId) {
    if (CAPS.tenancy === "multi-org") return null;
    const fallback = await findUserDefaultProject(userId);
    return fallback?.id ?? null;
  }

  const memberOrgIds = await db.user
    .findUnique({
      where: { id: userId },
      select: {
        organizationMemberships: {
          where: activeMembershipWhere,
          select: { organizationId: true },
        },
      },
    })
    .then((u) => u?.organizationMemberships.map((m) => m.organizationId) ?? []);

  const project = await db.project.findFirst({
    where: {
      id: headerProjectId,
      organizationId: { in: memberOrgIds },
    },
    select: { id: true, organizationId: true },
  });

  if (!project) return null;

  // A member may only target projects they hold a binding on; admins and owners
  // may target any project in their org.
  if (!(await canAccessProjectAsUser(userId, project))) return null;

  return project.id;
};
