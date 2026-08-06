import { db } from "@onecli/db";
import { ServiceError } from "../../services/errors";
import {
  getAppPermissionDefinition,
  type AppPermissionDefinition,
} from "../../apps/app-permissions";
import { hostMatches, isLlmHost } from "../../lib/path-match";
import { allRuleVariants } from "../policy-translation/translate/app-catalog";
import { evaluatePolicyOutcome } from "../policy-translation/evaluator";
import type { NewRule, PolicyRequest } from "../policy-translation/types";
import type { ProvenanceRuleRef } from "../policy-simulate/sim-rule";
import {
  loadInjectionRules,
  loadRulesForSimulation,
  type SimRuleRow,
} from "../policy-simulate/load-rules";
import type { SessionPolicyInput } from "../../validations/policy";
import { intersectPolicies } from "../../lib/resource-axis";
import {
  orgResourceBoundary,
  projectResourceSelection,
} from "./org-resource-boundary";
import {
  resolvePrincipalSet,
  type PrincipalSet,
} from "../policy-simulate/principal-set";
import { loadConnectionProviders } from "../policy-simulate/connection-providers";
import { loadSecretHosts } from "../policy-simulate/secret-hosts";
import { toSimRule, type SimRule } from "../policy-simulate/sim-rule";
import { buildInjectionProbe } from "./injection";

// Per-tool effective permissions for the App Permissions panel: what the
// published rules decide for each catalog tool of a provider, using the same
// engine and two-level composition as the gateway. Every catalog path×method
// variant is synthesized into a concrete request (see `synthesizePath`) and
// evaluated; the variants aggregate to one verdict, or `mixed` when they
// disagree.
//
// Limits: a rule targeting a sub-path narrower than a tool's pattern is
// invisible to a representative request, and body conditions cannot be
// exercised without a body.
//
// Redaction: org rule details are org-admin-only — other viewers get
// `redacted: true` provenance and org rules are excluded from
// `variesByIdentity`. Tool endpoint mappings (hostPattern/pathPattern/method)
// never serialize; per-tool id + verdict + provenance only.

export type EffectiveToolVerdict =
  | "allow"
  | "approval"
  | "block"
  /** Variants (or a group's tools) disagree — shown as "Varies"/"Mixed". */
  | "mixed"
  /** No rule applies and the traffic is unmanaged (no credential, or an LLM
   * host) — the enforce-deny carve passes it through. */
  | "unmanaged";

export type EffectiveProvenance =
  | { kind: "rule"; scope: "organization"; redacted: true }
  | { kind: "rule"; scope: "organization" | "project"; rule: ProvenanceRuleRef }
  /** A level's Default Rule blocked (the deny-default terminal). */
  | { kind: "default"; scope: "organization" | "project" };

/** What the org level alone says about a tool — the ceiling a project may
 * tighten under but never loosen past. Carries no rule ref: members may learn
 * that the org constrains, never which rule. `null` = the org is silent. */
export type OrgCeilingVerdict = "allow" | "approval" | "block";

export interface EffectiveToolResult {
  toolId: string;
  verdict: EffectiveToolVerdict;
  /** Modifier values of the deciding allow rule; disclosed even when that
   * rule's name is redacted. */
  rateLimit: number | null;
  rateLimitWindow: string | null;
  /** Attribution; null when variants disagree, or when allowed purely by an
   * allow-posture default / unmanaged pass. */
  decidedBy: EffectiveProvenance | null;
  orgCeiling: OrgCeilingVerdict | null;
}

export interface EffectiveToolGroupResult {
  category: "read" | "write";
  /** The group rollup: the common tool verdict, else "mixed". */
  verdict: EffectiveToolVerdict;
  tools: EffectiveToolResult[];
}

export interface EffectiveAppPermissionsResult {
  provider: string;
  basis: {
    /** null = the agent-less baseline (only any-identity rules match). */
    agentId: string | null;
    /** Whether any of the provider's hosts has a credential attached for this
     * basis. */
    credentialAttached: boolean;
    scope: "organization" | "project";
  };
  /** Identity-scoped rules relevant to this provider that the baseline view
   * cannot show, scoped to the viewer's visibility. */
  variesByIdentity: number;
  /** How far the organization allows this (agent, connection) credential to
   * reach; a project selection narrows within it but never exceeds it. Only
   * computed for an explicit `agentId` + `connectionId`; null = unrestricted.
   * Discloses repo/folder values, never the org rule's name or identity. */
  orgResources: SessionPolicyInput | null;
  /** What the credential actually reaches: the org boundary composed with the
   * project's selection. An empty list means the two do not overlap and the
   * gateway refuses every request. */
  effectiveResources: SessionPolicyInput | null;
  groups: EffectiveToolGroupResult[];
}

export interface EffectiveAppPermissionsInput {
  provider: string;
  agentId?: string;
  /** Reflect for one specific connection: synthesized requests carry it as the
   * winning injected connection, so per-account rules bind as the gateway
   * would. Absent = the provider-level view, where per-account differences fold
   * to `mixed`. Project scope only, like `agentId`. */
  connectionId?: string;
}

export interface EffectiveAppPermissionsCtx {
  scope: "organization" | "project";
  organizationId: string;
  /** Required at project scope; absent at org scope. */
  projectId?: string;
  /** Org-admin viewers see org rule details; everyone else gets redaction. */
  viewerSeesOrgRules: boolean;
}

/** The substitution token for `*` slots when synthesizing a request from a
 * catalog pattern. No catalog pattern or plausible rule path contains the
 * literal segment `oc-any`, so a synthesized request can only match by pattern
 * semantics, never by a literal collision with a concrete rule path. */
const TOKEN = "oc-any";

/** Synthesize a concrete request path that hits `pattern` under `pathMatches`
 * semantics: every `*` is replaced with the token in place. */
export const synthesizePath = (pattern: string): string => {
  if (pattern === "*") return `/${TOKEN}`;
  return pattern
    .split("/")
    .map((segment) => segment.replaceAll("*", TOKEN))
    .join("/");
};

/** Synthesize a concrete host for a (possibly wildcarded) host pattern —
 * `hostMatches` allows a single leading/trailing `*` with ≥1 substituted char. */
export const synthesizeHost = (pattern: string): string =>
  pattern.replaceAll("*", TOKEN);

/** Load the injection pool (host patterns + connected-connection providers) —
 * the whole fenced pool, for the agent-less baseline only. Org scope probes the
 * org-level pool only. */
const loadInjectionPool = async (
  agent: { id: string } | null,
  ctx: EffectiveAppPermissionsCtx,
): Promise<{ secretHostPatterns: string[]; providers: string[] }> => {
  // An agent has no baseline pool: everything it can be handed comes from its
  // rules, which `buildInjectionProbe` folds in from the injection rule set.
  if (agent !== null) {
    return { secretHostPatterns: [], providers: [] };
  }
  const poolWhere =
    ctx.scope === "project"
      ? {
          OR: [
            { projectId: ctx.projectId },
            { organizationId: ctx.organizationId, scope: "organization" },
          ],
        }
      : { organizationId: ctx.organizationId, scope: "organization" };
  const [secrets, connections] = await Promise.all([
    db.secret.findMany({ where: poolWhere, select: { hostPattern: true } }),
    db.appConnection.findMany({
      where: { ...poolWhere, status: "connected" },
      select: { provider: true },
    }),
  ]);
  return {
    secretHostPatterns: secrets.map((s) => s.hostPattern),
    providers: [...new Set(connections.map((c) => c.provider))],
  };
};

interface VariantEval {
  /** Verdict + modifier values folded into one equality key, so a rate or
   * approval difference between variants surfaces as `mixed`. Provenance is
   * excluded: two rules reaching the same verdict must not read as `mixed`,
   * and the verdict must not vary by viewer since org provenance redacts. */
  key: string;
  verdict: Exclude<EffectiveToolVerdict, "mixed">;
  rateLimit: number | null;
  rateLimitWindow: string | null;
  decidedBy: EffectiveProvenance | null;
  orgCeiling: OrgCeilingVerdict | null;
}

/** Strictest-wins fold for ceilings (block > approval > allow > silent):
 * variants or per-account runs that disagree lock at the tightest answer. */
const CEILING_RANK: Record<OrgCeilingVerdict, number> = {
  allow: 1,
  approval: 2,
  block: 3,
};

const foldCeilings = (
  ceilings: (OrgCeilingVerdict | null)[],
): OrgCeilingVerdict | null =>
  ceilings.reduce<OrgCeilingVerdict | null>(
    (a, b) =>
      b === null ? a : a === null || CEILING_RANK[b] > CEILING_RANK[a] ? b : a,
    null,
  );

/** The org level evaluated alone: the same request, org rules only. */
const orgCeilingOf = (
  engineRules: NewRule[],
  request: PolicyRequest,
): OrgCeilingVerdict | null => {
  const outcome = evaluatePolicyOutcome(
    engineRules.filter((r) => r.scope === "organization"),
    request,
  );
  if (outcome.kind === "rule") {
    if (outcome.rule.action === "block") return "block";
    return outcome.rule.requireApproval ? "approval" : "allow";
  }
  if (outcome.kind === "denyDefault") return "block";
  // Managed allow-posture pass or the unmanaged carve: the org imposes nothing.
  return null;
};

const provenanceKey = (p: EffectiveProvenance | null): string => {
  if (p === null) return "none";
  if (p.kind === "default") return `default:${p.scope}`;
  if ("redacted" in p) return "rule:org:redacted";
  return `rule:${p.scope}:${p.rule.logicalId}`;
};

const evaluateVariant = (
  simRules: SimRule[],
  engineRules: NewRule[],
  request: PolicyRequest,
  viewerSeesOrgRules: boolean,
): VariantEval => {
  const outcome = evaluatePolicyOutcome(engineRules, request);
  const orgCeiling = orgCeilingOf(engineRules, request);
  if (outcome.kind === "rule") {
    const sim = simRules.find((s) => s.rule === outcome.rule);
    if (!sim) throw new Error("effective-tools: matched rule lost metadata");
    const decidedBy: EffectiveProvenance =
      sim.meta.scope === "organization" && !viewerSeesOrgRules
        ? { kind: "rule", scope: "organization", redacted: true }
        : {
            kind: "rule",
            scope: sim.meta.scope,
            rule: {
              logicalId: sim.meta.logicalId,
              name: sim.meta.name,
              source: sim.meta.source,
              action: sim.rule.action,
              requireApproval: sim.rule.requireApproval,
              rateLimit: sim.rule.rateLimit,
              rateLimitWindow: sim.rule.rateLimitWindow,
            },
          };
    if (outcome.rule.action === "block") {
      return {
        key: "block",
        verdict: "block",
        rateLimit: null,
        rateLimitWindow: null,
        decidedBy,
        orgCeiling,
      };
    }
    // An approval rule short-circuits before the rate arms, so its stored rate
    // is never enforced — don't disclose it.
    if (outcome.rule.requireApproval) {
      return {
        key: "approval",
        verdict: "approval",
        rateLimit: null,
        rateLimitWindow: null,
        decidedBy,
        orgCeiling,
      };
    }
    const rateLimit = outcome.rule.rateLimit;
    const rateLimitWindow = outcome.rule.rateLimitWindow;
    return {
      key: `allow|${rateLimit ?? ""}|${rateLimitWindow ?? ""}`,
      verdict: "allow",
      rateLimit,
      rateLimitWindow,
      decidedBy,
      orgCeiling,
    };
  }
  if (outcome.kind === "denyDefault") {
    const decidedBy: EffectiveProvenance = {
      kind: "default",
      scope: outcome.level,
    };
    return {
      key: "block",
      verdict: "block",
      rateLimit: null,
      rateLimitWindow: null,
      decidedBy,
      orgCeiling,
    };
  }
  // No rule matched, no default blocked: managed → allowed by the level
  // posture; unmanaged → the enforce-deny carve passes it through untouched.
  const verdict = outcome.managed ? "allow" : "unmanaged";
  return {
    key: verdict === "allow" ? "allow||" : "unmanaged",
    verdict,
    rateLimit: null,
    rateLimitWindow: null,
    decidedBy: null,
    orgCeiling,
  };
};

/** Fold variant evaluations into one per-tool result: identical verdict+modifier
 * keys collapse to that verdict, any disagreement to `mixed`. Attribution is
 * kept only when every variant points at the same rule or default. */
const aggregateVariants = (
  toolId: string,
  evals: VariantEval[],
): EffectiveToolResult => {
  const first = evals[0];
  if (!first) {
    // A catalog tool always has ≥1 variant; defensive only.
    return {
      toolId,
      verdict: "unmanaged",
      rateLimit: null,
      rateLimitWindow: null,
      decidedBy: null,
      orgCeiling: null,
    };
  }
  // The ceiling folds independently of the verdict key: a ceiling difference
  // between variants must not read as `mixed`, and a `mixed` verdict can still
  // carry a definite ceiling lock.
  const orgCeiling = foldCeilings(evals.map((e) => e.orgCeiling));
  if (evals.every((e) => e.key === first.key)) {
    const sameSource = evals.every(
      (e) => provenanceKey(e.decidedBy) === provenanceKey(first.decidedBy),
    );
    return {
      toolId,
      verdict: first.verdict,
      rateLimit: first.rateLimit,
      rateLimitWindow: first.rateLimitWindow,
      decidedBy: sameSource ? first.decidedBy : null,
      orgCeiling,
    };
  }
  return {
    toolId,
    verdict: "mixed",
    rateLimit: null,
    rateLimitWindow: null,
    decidedBy: null,
    orgCeiling,
  };
};

/** Fold the per-account runs of a provider-level view into one: tools that
 * agree across every connected account keep their verdict (and provenance when
 * uniform); any disagreement is `mixed`. */
const foldGroupRuns = (
  runs: EffectiveToolGroupResult[][],
): EffectiveToolGroupResult[] => {
  const first = runs[0];
  if (!first || runs.length === 1) return first ?? [];
  const toolKey = (t: EffectiveToolResult) =>
    `${t.verdict}|${t.rateLimit ?? ""}|${t.rateLimitWindow ?? ""}`;
  return first.map((group, gi) => {
    const tools = group.tools.map((tool, ti) => {
      const across = runs.map((r) => r[gi]?.tools[ti] ?? tool);
      // Per-account ceiling disagreement locks at the strictest and never
      // flips the verdict.
      const orgCeiling = foldCeilings(across.map((t) => t.orgCeiling));
      if (across.every((t) => toolKey(t) === toolKey(tool))) {
        const sameSource = across.every(
          (t) => provenanceKey(t.decidedBy) === provenanceKey(tool.decidedBy),
        );
        return sameSource
          ? { ...tool, orgCeiling }
          : { ...tool, decidedBy: null, orgCeiling };
      }
      return {
        toolId: tool.toolId,
        verdict: "mixed" as const,
        rateLimit: null,
        rateLimitWindow: null,
        decidedBy: null,
        orgCeiling,
      };
    });
    const firstVerdict = tools[0]?.verdict ?? "unmanaged";
    const verdict = tools.every((t) => t.verdict === firstVerdict)
      ? firstVerdict
      : ("mixed" as const);
    return { category: group.category, verdict, tools };
  });
};

/** Effective access to a resource, folded from its per-tool verdicts. All tools
 * blocked → blocked; all reachable (allow/unmanaged) → usable; anything else →
 * limited; no tools → unknown (a catalog-less app). */
export type ToolRollupStatus = "usable" | "limited" | "blocked" | "unknown";

export const rollupToolStatus = (
  verdicts: EffectiveToolVerdict[],
): ToolRollupStatus => {
  if (verdicts.length === 0) return "unknown";
  if (verdicts.every((v) => v === "block")) return "blocked";
  if (verdicts.every((v) => v === "allow" || v === "unmanaged"))
    return "usable";
  return "limited";
};

/** The pure per-request core, shared with the connection reflection: per
 * catalog tool → per variant → synthesize → evaluate → aggregate, plus the
 * credential-attached signal. */
export const computeEffectiveGroups = (input: {
  def: AppPermissionDefinition;
  simRules: SimRule[];
  engineRules: NewRule[];
  /** "" = the agent-less baseline (never matches an explicit agent identity). */
  agentId: string;
  principals: PrincipalSet;
  probe: (host: string) => boolean;
  viewerSeesOrgRules: boolean;
  /** The winning injected connection the synthesized requests carry. Absent =
   * no winner, so resolved connection targets never match. */
  winningConnectionId?: string;
}): { groups: EffectiveToolGroupResult[]; credentialAttached: boolean } => {
  const baseRequest = {
    agentId: input.agentId,
    userIds: input.principals.userIds,
    groupIds: input.principals.groupIds,
  };
  let credentialAttached = false;
  const groups: EffectiveToolGroupResult[] = input.def.groups.map((group) => {
    // Concrete tools only: the wildcard is an authoring alias, not a distinct
    // endpoint, and the group rollup already plays the "All read/write" role.
    const tools = group.tools.map((tool) => {
      const host = synthesizeHost(tool.hostPattern);
      if (input.probe(host)) credentialAttached = true;
      const evals = allRuleVariants(tool).map((variant) =>
        evaluateVariant(
          input.simRules,
          input.engineRules,
          {
            ...baseRequest,
            host,
            path: synthesizePath(variant.pathPattern),
            // Every catalog tool declares a method; GET is a defensive fallback.
            method: variant.method ?? "GET",
            hasInjections: input.probe(host),
            isLlmHost: isLlmHost(host),
            winningConnectionId: input.winningConnectionId,
          },
          input.viewerSeesOrgRules,
        ),
      );
      return aggregateVariants(tool.id, evals);
    });
    const firstVerdict = tools[0]?.verdict ?? "unmanaged";
    const verdict = tools.every((t) => t.verdict === firstVerdict)
      ? firstVerdict
      : "mixed";
    return { category: group.category, verdict, tools };
  });
  return { groups, credentialAttached };
};

export const effectiveAppPermissions = async (
  input: EffectiveAppPermissionsInput,
  ctx: EffectiveAppPermissionsCtx,
): Promise<EffectiveAppPermissionsResult> => {
  const def = getAppPermissionDefinition(input.provider);
  if (!def) {
    throw new ServiceError(
      "NOT_FOUND",
      `No permission catalog for provider: ${input.provider}`,
    );
  }
  if (ctx.scope === "project" && !ctx.projectId) {
    throw new ServiceError("BAD_REQUEST", "Project scope requires a project.");
  }

  // The agent must belong to the caller's project — a foreign id is simply not
  // found (existence is never revealed across the fence). Baseline when omitted.
  let agent: { id: string } | null = null;
  if (input.agentId !== undefined) {
    if (ctx.scope !== "project") {
      throw new ServiceError(
        "BAD_REQUEST",
        "Agent-scoped reflection is project-level.",
      );
    }
    agent = await db.agent.findFirst({
      where: { id: input.agentId, projectId: ctx.projectId },
      select: { id: true },
    });
    if (!agent) throw new ServiceError("NOT_FOUND", "Agent not found.");
  }

  // Same fence for an explicit connection: it must be this provider's and
  // visible to the caller's scope (project-owned or org-shared).
  let connection: { id: string } | null = null;
  if (input.connectionId !== undefined) {
    if (ctx.scope !== "project") {
      throw new ServiceError(
        "BAD_REQUEST",
        "Connection-scoped reflection is project-level.",
      );
    }
    connection = await db.appConnection.findFirst({
      where: {
        id: input.connectionId,
        provider: input.provider,
        OR: [
          { projectId: ctx.projectId },
          { organizationId: ctx.organizationId, scope: "organization" },
        ],
      },
      select: { id: true },
    });
    if (!connection) {
      throw new ServiceError("NOT_FOUND", "Connection not found.");
    }
  }

  const orgBase = {
    scope: "organization" as const,
    organizationId: ctx.organizationId,
  };
  const projectBase =
    ctx.scope === "project" && ctx.projectId
      ? { scope: "project" as const, projectId: ctx.projectId }
      : null;

  const [
    orgRows,
    projectRows,
    orgInjectRows,
    projectInjectRows,
    principals,
    secretHosts,
    connectionProviders,
    pool,
  ] = await Promise.all([
    loadRulesForSimulation(orgBase, "published"),
    projectBase
      ? loadRulesForSimulation(projectBase, "published")
      : Promise.resolve([]),
    // Injection rules keep `equipment`; the decision rules above drop it.
    loadInjectionRules(orgBase, "published"),
    projectBase
      ? loadInjectionRules(projectBase, "published")
      : Promise.resolve([]),
    // The `agent &&` clause is load-bearing even though the set does not
    // depend on the agent: the agent-less baseline must not inherit the
    // project's users/groups, or identity-scoped verdicts leak into it while
    // `variesByIdentity` reports 0.
    agent && ctx.projectId
      ? resolvePrincipalSet(ctx.projectId, ctx.organizationId)
      : Promise.resolve({ userIds: [], groupIds: [] }),
    loadSecretHosts(ctx.organizationId, ctx.projectId ?? ""),
    loadConnectionProviders(ctx.organizationId, ctx.projectId ?? ""),
    loadInjectionPool(agent, ctx),
  ]);

  const allRows = [...orgRows, ...projectRows];
  const injectRows = [...orgInjectRows, ...projectInjectRows];
  const simRules: SimRule[] = allRows.map((row) =>
    toSimRule(row, secretHosts, connectionProviders),
  );
  const engineRules = simRules.map((s) => s.rule);

  // The injectable-credential predicate for the deny-default carve. Fed the
  // injection rules (equipment included), not the decision set — otherwise an
  // agent's credentials are invisible here and its tools read "unmanaged" when
  // the gateway would call them managed.
  const probe = buildInjectionProbe({
    agent,
    poolSecretHostPatterns: pool.secretHostPatterns,
    poolProviders: pool.providers,
    rules: injectRows,
    principals,
    secretHosts,
    connectionProviders,
  });

  const runCompute = (winningConnectionId?: string) =>
    computeEffectiveGroups({
      def,
      simRules,
      engineRules,
      // The baseline's empty-string agent id can never match an explicit agent
      // identity, so only any-identity rules apply.
      agentId: agent?.id ?? "",
      principals,
      probe,
      viewerSeesOrgRules: ctx.viewerSeesOrgRules,
      winningConnectionId,
    });

  // An explicit connection reflects with it as the winner. The provider-level
  // view can vary by account once connection targets name this provider, so
  // evaluate once per connected account and fold disagreements to `mixed`.
  const hasConnectionRules = engineRules.some((r) =>
    r.targets.some(
      (t) => t.kind === "connection" && t.provider === input.provider,
    ),
  );
  const providerConnectionIds = [...connectionProviders.entries()]
    .filter(([, p]) => p === input.provider)
    .map(([id]) => id);
  let folded: {
    groups: EffectiveToolGroupResult[];
    credentialAttached: boolean;
  };
  if (connection) {
    folded = runCompute(connection.id);
  } else if (hasConnectionRules && providerConnectionIds.length > 0) {
    const runs = providerConnectionIds.map((id) => runCompute(id));
    folded = {
      groups: foldGroupRuns(runs.map((r) => r.groups)),
      credentialAttached: runs.some((r) => r.credentialAttached),
    };
  } else {
    folded = runCompute();
  }
  const { groups, credentialAttached } = folded;

  // Identity-scoped rules relevant to this provider — what the baseline view
  // cannot show. Relevance: app targets by provider, secret/network targets
  // when their pattern matches a concrete catalog host (wildcard tool hosts are
  // skipped, being undecidable without intersection machinery).
  const concreteHosts = [
    ...new Set(
      def.groups
        .flatMap((g) => g.tools.map((t) => t.hostPattern))
        .filter((h) => !h.includes("*")),
    ),
  ];
  const disclosable = ctx.viewerSeesOrgRules
    ? simRules
    : simRules.filter((s) => s.meta.scope === "project");
  const variesByIdentity = disclosable.filter((s) => {
    if (s.rule.isDefault || s.rule.identities.length === 0) return false;
    return s.rule.targets.some((t) => {
      if (t.kind === "app") return t.provider === input.provider;
      // A resolved connection target carries its provider; unresolved ones
      // never match anything, so they can't vary either.
      if (t.kind === "connection") return t.provider === input.provider;
      if (t.kind === "network")
        return concreteHosts.some((h) => hostMatches(h, t.hostPattern));
      if (t.kind === "secret")
        return t.hostPatterns.some((p) =>
          concreteHosts.some((h) => hostMatches(h, p)),
        );
      return false;
    });
  }).length;

  return {
    provider: input.provider,
    basis: {
      agentId: agent?.id ?? null,
      credentialAttached,
      scope: ctx.scope,
    },
    variesByIdentity,
    ...resourceScopes(
      agent && connection
        ? {
            orgInjectRows,
            projectInjectRows,
            agentId: agent.id,
            principals,
            connectionId: connection.id,
          }
        : null,
    ),
    groups,
  };
};

/** The org boundary and the effective (composed) scope for the basis, or nulls
 * when the reflection has no explicit (agent, connection) to reason about. */
const resourceScopes = (
  basis: {
    orgInjectRows: SimRuleRow[];
    projectInjectRows: SimRuleRow[];
    agentId: string;
    principals: PrincipalSet;
    connectionId: string;
  } | null,
): {
  orgResources: SessionPolicyInput | null;
  effectiveResources: SessionPolicyInput | null;
} => {
  if (!basis) return { orgResources: null, effectiveResources: null };
  const orgResources = orgResourceBoundary(
    basis.orgInjectRows,
    basis.agentId,
    basis.principals,
    basis.connectionId,
  );
  const projectResources = projectResourceSelection(
    basis.projectInjectRows,
    basis.agentId,
    basis.principals,
    basis.connectionId,
  );
  return {
    orgResources,
    effectiveResources: intersectPolicies(orgResources, projectResources),
  };
};
