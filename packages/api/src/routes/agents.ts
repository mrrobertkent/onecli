import { Hono } from "hono";
import type { ApiEnv } from "../types";
import { authMiddleware, requireProjectId } from "../middleware/auth";
import { invalidateGatewayCache } from "../lib/gateway-invalidate";
import {
  listAgents,
  createAgent,
  agentExistsByIdentifier,
  getDefaultAgent,
  getAgentDetail,
  setDefaultAgent,
  renameAgent,
  deleteAgent,
  regenerateAgentToken,
} from "../services/agent-service";
import { createAgentSchema, renameAgentSchema } from "../validations/agent";
import { agentsIncludeSchema } from "../validations/grants";
import { listAgentsWithGrantsSummary } from "../services/grants-summary-service";
import { ServiceError } from "../services/errors";
import { getResourceHooks } from "../providers";

export const agentRoutes = () => {
  const app = new Hono<ApiEnv>();
  app.use("*", authMiddleware);

  // GET /agents[?include=grants-summary]
  app.get("/", async (c) => {
    const auth = c.get("auth");
    const projectId = requireProjectId(auth);
    const rawInclude = c.req.query("include");
    const include = agentsIncludeSchema.safeParse(rawInclude);
    if (!include.success) {
      throw new ServiceError(
        "UNPROCESSABLE",
        `Unknown include: ${rawInclude ?? ""}`,
      );
    }
    if (include.data === "grants-summary") {
      return c.json(
        await listAgentsWithGrantsSummary(projectId, auth.organizationId),
      );
    }
    const agents = await listAgents(projectId);
    return c.json(agents);
  });

  // POST /agents
  app.post("/", async (c) => {
    const auth = c.get("auth");
    const body = await c.req.json().catch(() => null);
    const parsed = createAgentSchema.safeParse(body);
    if (!parsed.success) {
      return c.json(
        { error: parsed.error.issues[0]?.message ?? "Invalid request body" },
        400,
      );
    }

    const projectId = requireProjectId(auth);

    // The quota gates new agents only. Skipping the check for an existing
    // identifier keeps createAgent's 409 from being shadowed by a 403 at the
    // cap, which would break idempotent ensureAgent. See onecli/node-sdk#40.
    if (!(await agentExistsByIdentifier(projectId, parsed.data.identifier))) {
      await getResourceHooks().beforeCreateAgent(
        auth.organizationId,
        projectId,
      );
    }

    // `parentIdentifier` is still accepted by the schema because the CLI sends
    // it, but it drives nothing: every new agent is selective.
    const agent = await createAgent(
      projectId,
      parsed.data.name,
      parsed.data.identifier,
    );
    invalidateGatewayCache(c.req.raw);
    return c.json(agent, 201);
  });

  // GET /agents/default
  app.get("/default", async (c) => {
    const auth = c.get("auth");
    const agent = await getDefaultAgent(requireProjectId(auth));
    if (!agent) {
      return c.json({ error: "No default agent found" }, 404);
    }
    return c.json(agent);
  });

  // GET /agents/:agentId — registered after /default so the literal path wins.
  app.get("/:agentId", async (c, next) => {
    const agentId = c.req.param("agentId");
    // Fall through to the 410 shim in `removedAgentEquipmentRoutes` (mounted
    // after this router) rather than answering 404 for a removed path.
    if (agentId === "granular-access") return next();
    const auth = c.get("auth");
    const agent = await getAgentDetail(requireProjectId(auth), agentId);
    return c.json(agent);
  });

  // PATCH /agents/:agentId
  app.patch("/:agentId", async (c) => {
    const auth = c.get("auth");
    const agentId = c.req.param("agentId");
    const body = await c.req.json().catch(() => null);
    const parsed = renameAgentSchema.safeParse(body);
    if (!parsed.success) {
      return c.json(
        { error: parsed.error.issues[0]?.message ?? "Invalid request body" },
        400,
      );
    }

    await renameAgent(requireProjectId(auth), agentId, parsed.data.name);
    return c.json({ success: true });
  });

  // DELETE /agents/:agentId
  app.delete("/:agentId", async (c) => {
    const auth = c.get("auth");
    const agentId = c.req.param("agentId");
    await deleteAgent(requireProjectId(auth), agentId);
    invalidateGatewayCache(c.req.raw);
    return c.body(null, 204);
  });

  // POST /agents/:agentId/set-default
  app.post("/:agentId/set-default", async (c) => {
    const auth = c.get("auth");
    const agentId = c.req.param("agentId");
    await setDefaultAgent(requireProjectId(auth), agentId);
    invalidateGatewayCache(c.req.raw);
    return c.json({ success: true });
  });

  // POST /agents/:agentId/regenerate-token
  app.post("/:agentId/regenerate-token", async (c) => {
    const auth = c.get("auth");
    const agentId = c.req.param("agentId");
    const result = await regenerateAgentToken(requireProjectId(auth), agentId);
    invalidateGatewayCache(c.req.raw);
    return c.json(result);
  });

  // PATCH /:agentId/secret-mode is gone; its 410 lives in
  // `removedAgentEquipmentRoutes`, mounted after this router.

  return app;
};
