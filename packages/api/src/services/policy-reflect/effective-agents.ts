import { db } from "@onecli/db";
import { ServiceError } from "../../services/errors";
import { getAppPermissionDefinition } from "../../apps/app-permissions";
import {
  loadInjectionRules,
  loadRulesForSimulation,
} from "../policy-simulate/load-rules";
import { resolvePrincipalSet } from "../policy-simulate/principal-set";
import { loadConnectionProviders } from "../policy-simulate/connection-providers";
import { loadSecretHosts } from "../policy-simulate/secret-hosts";
import { toSimRule, type SimRule } from "../policy-simulate/sim-rule";
import {
  computeEffectiveGroups,
  rollupToolStatus,
  type ToolRollupStatus,
} from "./effective-tools";
import { buildInjectionProbe, injectionIdentityMatches } from "./injection";
import type { CredentialProvenance } from "./effective-credentials";

// The per-agent reflection behind the connection "agent access" dialog. For
// every agent in the caller's project it reports two axes:
//
// 1. CREDENTIAL: would this connection inject for the agent? It is attached iff
//    a published, enabled allow rule with an explicit matching identity names
//    the connection or its provider pool at the connection's level. Empty
//    identities never inject.
// 2. DECISIONS: the per-tool rollup of the provider's catalog, where "allowed"
//    counts allow/approval/unmanaged verdicts. A catalog-less provider has no
//    rollup (`decisions: null`) — rules can't target its endpoints, so "0 of 0"
//    would be a lie.
//
// Org rule provenance follows the simulate contract: names are org-admin-only
// and multiple org refs collapse to one redacted marker.

export type AgentCredentialStatus =
  | { status: "full" }
  | { status: "viaRule"; provenance: CredentialProvenance[] }
  | { status: "none" };

/** Can the agent actually use this connection under the rules? */
export type AgentAccessStatus =
  /** Attached and every tool reachable. */
  | "usable"
  /** Attached, some tools blocked or need approval. */
  | "limited"
  /** Attached but every tool blocked by a rule. */
  | "blocked"
  /** No credential attached — can't use the connection at all. */
  | "none"
  /** Attached, but a custom app with no catalog to evaluate. */
  | "unknown";

export interface EffectiveAgentEntry {
  agentId: string;
  name: string;
  /** The headline: effective access under the rules. */
  access: AgentAccessStatus;
  /** How the credential is (or isn't) attached — the secondary detail. */
  credential: AgentCredentialStatus;
  decisions: {
    allowedTools: number;
    totalTools: number;
    anyApproval: boolean;
    anyRateLimit: boolean;
  } | null;
}

export interface EffectiveAgentsResult {
  connectionId: string;
  provider: string;
  /** false = no permission catalog, so the decisions axis is absent. */
  catalog: boolean;
  agents: EffectiveAgentEntry[];
}

export interface EffectiveAgentsCtx {
  projectId: string;
  organizationId: string;
  viewerSeesOrgRules: boolean;
}

interface RuleRef {
  scope: "organization" | "project";
  logicalId: string;
  name: string;
}

/** Collapse rule refs into provenance; for non-admins, org refs collapse to a
 * single redacted marker regardless of count. */
const toProvenance = (
  refs: RuleRef[],
  viewerSeesOrgRules: boolean,
): CredentialProvenance[] => {
  const out: CredentialProvenance[] = [];
  const seen = new Set<string>();
  let redactedEmitted = false;
  for (const ref of refs) {
    if (ref.scope === "organization" && !viewerSeesOrgRules) {
      if (!redactedEmitted) {
        out.push({ kind: "rule", scope: "organization", redacted: true });
        redactedEmitted = true;
      }
      continue;
    }
    if (seen.has(ref.logicalId)) continue;
    seen.add(ref.logicalId);
    out.push({
      kind: "rule",
      scope: ref.scope,
      rule: { logicalId: ref.logicalId, name: ref.name },
    });
  }
  return out;
};

export const effectiveAgents = async (
  connectionId: string,
  ctx: EffectiveAgentsCtx,
): Promise<EffectiveAgentsResult> => {
  // Fence: project-owned or org-scoped in the caller's org; a foreign
  // connection is not found, so its existence is never revealed.
  const project = await db.project.findUnique({
    where: { id: ctx.projectId },
    select: { organizationId: true },
  });
  const connection = await db.appConnection.findFirst({
    where: {
      id: connectionId,
      OR: [
        { projectId: ctx.projectId },
        ...(project?.organizationId
          ? [{ organizationId: project.organizationId, scope: "organization" }]
          : []),
      ],
    },
    select: { id: true, provider: true, scope: true },
  });
  if (!connection) throw new ServiceError("NOT_FOUND", "Connection not found");

  const connectionLevel: "organization" | "project" =
    connection.scope === "organization" ? "organization" : "project";
  const def = getAppPermissionDefinition(connection.provider);

  const agents = await db.agent.findMany({
    where: { projectId: ctx.projectId },
    select: { id: true, name: true },
    orderBy: [{ isDefault: "desc" }, { createdAt: "desc" }],
  });

  const [
    orgRows,
    projectRows,
    orgInjectRows,
    projectInjectRows,
    secretHosts,
    connectionProviders,
    principals,
  ] = await Promise.all([
    loadRulesForSimulation(
      { scope: "organization", organizationId: ctx.organizationId },
      "published",
    ),
    loadRulesForSimulation(
      { scope: "project", projectId: ctx.projectId },
      "published",
    ),
    // Injection rules keep `equipment`, which the decision load above drops.
    loadInjectionRules(
      { scope: "organization", organizationId: ctx.organizationId },
      "published",
    ),
    loadInjectionRules(
      { scope: "project", projectId: ctx.projectId },
      "published",
    ),
    loadSecretHosts(ctx.organizationId, ctx.projectId),
    loadConnectionProviders(ctx.organizationId, ctx.projectId),
    resolvePrincipalSet(ctx.projectId, ctx.organizationId),
  ]);

  const allRows = [...orgRows, ...projectRows];
  const injectRows = [...orgInjectRows, ...projectInjectRows];
  const simRules: SimRule[] = allRows.map((row) =>
    toSimRule(row, secretHosts, connectionProviders),
  );
  const engineRules = simRules.map((s) => s.rule);
  const totalTools = def
    ? def.groups.reduce((n, g) => n + g.tools.length, 0)
    : 0;

  // The injection-relevant allow rules, prefiltered to this connection: a
  // connection target naming it, or a provider-pool grant at its level.
  const grantingRules = injectRows
    .filter((row) => !row.isDefault && row.action === "allow")
    .map((row) => ({
      row,
      grants: row.targets.some(
        (t) =>
          (t.kind === "connection" && t.appConnectionId === connectionId) ||
          (t.kind === "app" &&
            t.appProvider === connection.provider &&
            t.appConnectionScope === connectionLevel),
      ),
    }))
    .filter((r) => r.grants)
    .map(({ row }) => row);

  const entries: EffectiveAgentEntry[] = agents.map((agent) => {
    // Every attachment is a rule; there is no all-mode pool arm and no
    // separate "assigned" source to distinguish.
    const refs: RuleRef[] = grantingRules
      .filter((row) =>
        injectionIdentityMatches(row.identities, agent.id, principals),
      )
      .map((row) => ({
        scope: row.scope === "organization" ? "organization" : "project",
        logicalId: row.logicalId,
        name: row.name,
      }));
    const credential: AgentCredentialStatus =
      refs.length > 0
        ? {
            status: "viaRule",
            provenance: toProvenance(refs, ctx.viewerSeesOrgRules),
          }
        : { status: "none" };

    let decisions: EffectiveAgentEntry["decisions"] = null;
    let toolStatus: ToolRollupStatus = "unknown";
    if (def) {
      // The deny-default carve's injectable predicate. An agent draws nothing
      // from the pool — its rules are the whole story — so the decisions
      // rollup can't contradict the credential axis.
      const probe = buildInjectionProbe({
        agent,
        poolSecretHostPatterns: [],
        poolProviders: [],
        rules: injectRows,
        principals,
        secretHosts,
        connectionProviders,
      });
      const { groups } = computeEffectiveGroups({
        def,
        simRules,
        engineRules,
        agentId: agent.id,
        principals,
        probe,
        viewerSeesOrgRules: ctx.viewerSeesOrgRules,
        // This endpoint is scoped to one connection, so reflect it as the
        // winner and per-account rules bind as the gateway would.
        winningConnectionId: connectionId,
      });
      const tools = groups.flatMap((g) => g.tools);
      // Shared with the credential dialog so the two surfaces can't disagree.
      toolStatus = rollupToolStatus(tools.map((t) => t.verdict));
      decisions = {
        allowedTools: tools.filter(
          (t) =>
            t.verdict === "allow" ||
            t.verdict === "approval" ||
            t.verdict === "unmanaged",
        ).length,
        totalTools,
        anyApproval: tools.some((t) => t.verdict === "approval"),
        anyRateLimit: tools.some((t) => t.rateLimit !== null),
      };
    }

    // No credential means unusable; otherwise the per-tool rollup, or
    // "unknown" for a custom app with no catalog.
    const access: AgentAccessStatus =
      credential.status === "none" ? "none" : def ? toolStatus : "unknown";

    return {
      agentId: agent.id,
      name: agent.name,
      access,
      credential,
      decisions,
    };
  });

  return {
    connectionId: connection.id,
    provider: connection.provider,
    catalog: !!def,
    agents: entries,
  };
};
