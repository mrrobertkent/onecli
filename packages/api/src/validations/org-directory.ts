import { z } from "zod";
import {
  MEMBERSHIP_MODES,
  PROJECT_ACCESS_MODES,
} from "../services/group-modes";

export const DIRECTORY_PAGE_SIZE = 50;

export const directoryListSchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(DIRECTORY_PAGE_SIZE),
  cursor: z.string().min(1).optional(),
  q: z.string().trim().min(1).max(255).optional(),
});

export const groupListSchema = directoryListSchema.extend({
  source: z.enum(["manual", "scim"]).optional(),
});

export const memberListSchema = directoryListSchema.extend({
  status: z.enum(["active", "suspended"]).optional(),
});

const groupName = z.string().trim().min(1).max(255);
const membershipMode = z.enum([
  MEMBERSHIP_MODES.EXPLICIT,
  MEMBERSHIP_MODES.ALL_USERS,
]);
const projectAccessMode = z.enum([
  PROJECT_ACCESS_MODES.SELECTED,
  PROJECT_ACCESS_MODES.ALL_PROJECTS,
]);

export const createGroupSchema = z.object({
  name: groupName,
  membershipMode: membershipMode.optional(),
  projectAccessMode: projectAccessMode.optional(),
});

export const updateGroupSchema = z
  .object({
    name: groupName.optional(),
    membershipMode: membershipMode.optional(),
    projectAccessMode: projectAccessMode.optional(),
  })
  .refine((v) => Object.values(v).some((field) => field !== undefined), {
    message: "Supply at least one of name, membershipMode, projectAccessMode",
  });

export const setGroupMembersSchema = z.object({
  userIds: z.array(z.string().min(1)).max(1000),
});

/**
 * The roles a group mapping or an admin may assign. `owner` is absent by
 * design: the directory must never be able to confer the one role that can
 * edit the mappings.
 */
const assignableRole = z.enum(["admin", "member"]);

export const createRoleMappingSchema = z.object({
  groupId: z.string().min(1),
  role: assignableRole,
  priority: z.number().int().optional(),
});

export const updateRoleMappingSchema = z.object({
  role: assignableRole,
  priority: z.number().int().optional(),
});

export const reorderRoleMappingsSchema = z.object({
  orderedIds: z.array(z.string().min(1)).min(1).max(500),
});

export const previewRoleMappingSchema = z.object({
  groupId: z.string().min(1),
  role: assignableRole,
});

/**
 * `owner` is assignable here and nowhere else. An owner appointing a peer holds
 * the top role already, so it opens no path; the service still refuses it to an
 * admin, and refuses demoting the last owner.
 */
const memberRole = z.enum(["owner", "admin", "member"]);

export const updateOrgMemberSchema = z.union([
  z.object({ status: z.enum(["active", "suspended"]) }),
  z.object({ ssoExempt: z.boolean() }),
  z.object({ role: memberRole }),
]);
