import { Hono } from "hono";
import type { ApiEnv } from "../types";
import { auth } from "../middleware/auth";
import { parseBody } from "../lib/parse-request";
import {
  AUDIT_ACTIONS,
  AUDIT_SERVICES,
  withAudit,
} from "../services/audit-service";
import {
  createRoleMapping,
  deleteRoleMapping,
  listRoleMappings,
  previewRoleMapping,
  reorderRoleMappings,
  updateRoleMapping,
} from "../services/role-mapping-service";
import {
  createRoleMappingSchema,
  previewRoleMappingSchema,
  reorderRoleMappingsSchema,
  updateRoleMappingSchema,
} from "../validations/org-directory";

/**
 * Reads are open to an admin; every write demands `owner`.
 *
 * An admin who could edit these could grant admin to a directory group they can
 * join, which is admin→admin expansion with the IdP as the lever. Keeping the
 * mappings owner-only puts the authority to delegate behind the one role the
 * directory cannot confer.
 */
export const orgRoleMappingRoutes = () => {
  const app = new Hono<ApiEnv>();
  const requireOwner = auth({ requireProject: false, role: "owner" });

  app.get("/", auth({ requireProject: false, role: "admin" }), async (c) => {
    const { organizationId } = c.get("auth");
    return c.json(await listRoleMappings(organizationId));
  });

  app.post("/", requireOwner, async (c) => {
    const { organizationId, userId, userEmail } = c.get("auth");
    const input = await parseBody(c, createRoleMappingSchema);
    const mapping = await withAudit(
      () => createRoleMapping(organizationId, input),
      (created) => ({
        organizationId,
        userId,
        userEmail,
        action: AUDIT_ACTIONS.CREATE,
        service: AUDIT_SERVICES.ROLE_MAPPING,
        metadata: {
          mappingId: created.id,
          groupId: created.groupId,
          groupName: created.groupName,
          role: created.role,
          priority: created.priority,
        },
      }),
    );
    return c.json(mapping, 201);
  });

  app.put("/order", requireOwner, async (c) => {
    const { organizationId, userId, userEmail } = c.get("auth");
    const { orderedIds } = await parseBody(c, reorderRoleMappingsSchema);
    const mappings = await withAudit(
      () => reorderRoleMappings(organizationId, orderedIds),
      () => ({
        organizationId,
        userId,
        userEmail,
        action: AUDIT_ACTIONS.UPDATE,
        service: AUDIT_SERVICES.ROLE_MAPPING,
        metadata: { orderedIds },
      }),
    );
    return c.json(mappings);
  });

  // A dry run: reads only, so an admin may ask it.
  app.post(
    "/preview",
    auth({ requireProject: false, role: "admin" }),
    async (c) => {
      const { organizationId } = c.get("auth");
      const input = await parseBody(c, previewRoleMappingSchema);
      return c.json(await previewRoleMapping(organizationId, input));
    },
  );

  app.patch("/:id", requireOwner, async (c) => {
    const { organizationId, userId, userEmail } = c.get("auth");
    const id = c.req.param("id");
    const input = await parseBody(c, updateRoleMappingSchema);
    const mapping = await withAudit(
      () => updateRoleMapping(organizationId, id, input),
      (updated) => ({
        organizationId,
        userId,
        userEmail,
        action: AUDIT_ACTIONS.UPDATE,
        service: AUDIT_SERVICES.ROLE_MAPPING,
        metadata: {
          mappingId: id,
          groupId: updated.groupId,
          groupName: updated.groupName,
          role: updated.role,
          priority: updated.priority,
        },
      }),
    );
    return c.json(mapping);
  });

  app.delete("/:id", requireOwner, async (c) => {
    const { organizationId, userId, userEmail } = c.get("auth");
    const id = c.req.param("id");
    await withAudit(
      () => deleteRoleMapping(organizationId, id),
      (deleted) => ({
        organizationId,
        userId,
        userEmail,
        action: AUDIT_ACTIONS.DELETE,
        service: AUDIT_SERVICES.ROLE_MAPPING,
        metadata: {
          mappingId: id,
          groupId: deleted.groupId,
          groupName: deleted.groupName,
          role: deleted.role,
        },
      }),
    );
    return c.body(null, 204);
  });

  return app;
};
