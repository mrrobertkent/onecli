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
  changeMemberRole,
  listOrgMembers,
  setMemberSsoExempt,
  setMemberStatus,
  type OrgMemberChange,
} from "../services/org-member-service";
import { listGroupsForUser } from "../services/group-service";
import {
  memberListSchema,
  updateOrgMemberSchema,
} from "../validations/org-directory";

export const orgMemberRoutes = () => {
  const app = new Hono<ApiEnv>();
  app.use("*", auth({ requireProject: false, role: "admin" }));

  app.get("/", async (c) => {
    const { organizationId } = c.get("auth");
    return c.json(
      await listOrgMembers(organizationId, parseQuery(c, memberListSchema)),
    );
  });

  app.patch("/:userId", async (c) => {
    const { organizationId, userId, userEmail, role } = c.get("auth");
    const targetId = c.req.param("userId");
    const input = await parseBody(c, updateOrgMemberSchema);
    // The middleware resolved this caller's role for the `admin` gate; the
    // owner-only rules below read it rather than resolving it a second time.
    const actor = { userId, role };

    const apply = (): Promise<OrgMemberChange> => {
      if ("role" in input) {
        return changeMemberRole(organizationId, targetId, input.role, actor);
      }
      if ("status" in input) {
        return setMemberStatus(organizationId, targetId, input.status, actor);
      }
      return setMemberSsoExempt(
        organizationId,
        targetId,
        input.ssoExempt,
        actor,
      );
    };

    const changed = await withAudit(apply, (result) => ({
      organizationId,
      userId,
      userEmail,
      action:
        "status" in input && input.status === "suspended"
          ? AUDIT_ACTIONS.DELETE
          : AUDIT_ACTIONS.UPDATE,
      service: AUDIT_SERVICES.MEMBER,
      metadata: {
        memberUserId: targetId,
        role: result.role,
        status: result.status,
        ssoExempt: result.ssoExempt,
        sessionsRevoked: result.sessionsRevoked,
      },
    }));
    return c.json(changed);
  });

  app.get("/:userId/groups", async (c) => {
    const { organizationId } = c.get("auth");
    return c.json(
      await listGroupsForUser(organizationId, c.req.param("userId")),
    );
  });

  return app;
};
