import { Hono } from "hono";
import type { ApiEnv } from "../types";
import { auth } from "../middleware/auth";
import { parseBody, parseQuery } from "../lib/parse-request";
import {
  AUDIT_ACTIONS,
  AUDIT_SERVICES,
  withAudit,
} from "../services/audit-service";
import {
  addGroupMember,
  createGroup,
  deleteGroup,
  listGroupMembers,
  listGroups,
  removeGroupMember,
  setGroupMembers,
  updateGroup,
} from "../services/group-service";
import {
  createGroupSchema,
  directoryListSchema,
  groupListSchema,
  setGroupMembersSchema,
  updateGroupSchema,
} from "../validations/org-directory";

export const orgGroupRoutes = () => {
  const app = new Hono<ApiEnv>();
  app.use("*", auth({ requireProject: false, role: "admin" }));

  app.get("/", async (c) => {
    const { organizationId } = c.get("auth");
    return c.json(
      await listGroups(organizationId, parseQuery(c, groupListSchema)),
    );
  });

  app.post("/", async (c) => {
    const { organizationId, userId, userEmail } = c.get("auth");
    const input = await parseBody(c, createGroupSchema);
    const group = await withAudit(
      () => createGroup(organizationId, input),
      (created) => ({
        organizationId,
        userId,
        userEmail,
        action: AUDIT_ACTIONS.CREATE,
        service: AUDIT_SERVICES.GROUP,
        metadata: {
          groupId: created.id,
          name: created.name,
          membershipMode: created.membershipMode,
          projectAccessMode: created.projectAccessMode,
        },
      }),
    );
    return c.json(group, 201);
  });

  app.patch("/:groupId", async (c) => {
    const { organizationId, userId, userEmail } = c.get("auth");
    const groupId = c.req.param("groupId");
    const input = await parseBody(c, updateGroupSchema);
    const group = await withAudit(
      () => updateGroup(organizationId, groupId, input),
      (updated) => ({
        organizationId,
        userId,
        userEmail,
        action: AUDIT_ACTIONS.UPDATE,
        service: AUDIT_SERVICES.GROUP,
        metadata: {
          groupId,
          name: updated.name,
          membershipMode: updated.membershipMode,
          projectAccessMode: updated.projectAccessMode,
        },
      }),
    );
    return c.json(group);
  });

  app.delete("/:groupId", async (c) => {
    const { organizationId, userId, userEmail } = c.get("auth");
    const groupId = c.req.param("groupId");
    await withAudit(
      () => deleteGroup(organizationId, groupId),
      (deleted) => ({
        organizationId,
        userId,
        userEmail,
        action: AUDIT_ACTIONS.DELETE,
        service: AUDIT_SERVICES.GROUP,
        metadata: { groupId, name: deleted.name },
      }),
    );
    return c.body(null, 204);
  });

  app.get("/:groupId/members", async (c) => {
    const { organizationId } = c.get("auth");
    return c.json(
      await listGroupMembers(
        organizationId,
        c.req.param("groupId"),
        parseQuery(c, directoryListSchema),
      ),
    );
  });

  app.put("/:groupId/members", async (c) => {
    const { organizationId, userId, userEmail } = c.get("auth");
    const groupId = c.req.param("groupId");
    const { userIds } = await parseBody(c, setGroupMembersSchema);
    const result = await withAudit(
      () => setGroupMembers(organizationId, groupId, userIds, userId),
      (changed) => ({
        organizationId,
        userId,
        userEmail,
        action: AUDIT_ACTIONS.UPDATE,
        service: AUDIT_SERVICES.GROUP,
        metadata: { groupId, ...changed },
      }),
    );
    return c.json(result);
  });

  app.put("/:groupId/members/:userId", async (c) => {
    const { organizationId, userId, userEmail } = c.get("auth");
    const groupId = c.req.param("groupId");
    const memberId = c.req.param("userId");
    await withAudit(
      () => addGroupMember(organizationId, groupId, memberId, userId),
      () => ({
        organizationId,
        userId,
        userEmail,
        action: AUDIT_ACTIONS.UPDATE,
        service: AUDIT_SERVICES.GROUP,
        metadata: { groupId, added: memberId },
      }),
    );
    return c.body(null, 204);
  });

  app.delete("/:groupId/members/:userId", async (c) => {
    const { organizationId, userId, userEmail } = c.get("auth");
    const groupId = c.req.param("groupId");
    const memberId = c.req.param("userId");
    await withAudit(
      () => removeGroupMember(organizationId, groupId, memberId),
      () => ({
        organizationId,
        userId,
        userEmail,
        action: AUDIT_ACTIONS.UPDATE,
        service: AUDIT_SERVICES.GROUP,
        metadata: { groupId, removed: memberId },
      }),
    );
    return c.body(null, 204);
  });

  return app;
};
