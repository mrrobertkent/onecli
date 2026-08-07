import type { Prisma } from "@onecli/db";

/**
 * A group's two independent axes. Both "all" modes are read-time filters, never
 * stored rows — see the fragments below for the single definition every access
 * check and directory read shares.
 */
export const MEMBERSHIP_MODES = {
  EXPLICIT: "explicit",
  ALL_USERS: "all-users",
} as const;

export const PROJECT_ACCESS_MODES = {
  SELECTED: "selected",
  ALL_PROJECTS: "all-projects",
} as const;

export type MembershipMode =
  (typeof MEMBERSHIP_MODES)[keyof typeof MEMBERSHIP_MODES];
export type ProjectAccessMode =
  (typeof PROJECT_ACCESS_MODES)[keyof typeof PROJECT_ACCESS_MODES];

/** A `Group` filter: the groups this user belongs to, under either mode. */
export const groupIncludesUser = (userId: string): Prisma.GroupWhereInput => ({
  OR: [
    { members: { some: { userId } } },
    { membershipMode: MEMBERSHIP_MODES.ALL_USERS },
  ],
});
