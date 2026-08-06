import { db, Prisma } from "@onecli/db";
import { ServiceError } from "./errors";
import { isOssEdition } from "../lib/policy-flags";
import { type ResourceScope } from "./resource-scope";
import { getPolicyValidator, getRuleActionGate } from "../providers";
import type {
  CreatePolicyRuleInput,
  UpdatePolicyRuleInput,
  PolicyIdentityInput,
  PolicyTargetInput,
} from "../validations/policy";
import { isSessionPolicy } from "../validations/policy";

// ── Unified policy engine service (policy_rules_v2) ─────────────────────────
// CRUD + reorder + publish over the priority-ordered, first-match rule model.
// Each scope has a draft (editable) set and published snapshots; the gateway
// reads only the active published generation.

type PolicyStatus = "draft" | "published";

export const RULE_INCLUDE = {
  identities: true,
  targets: true,
} satisfies Prisma.PolicyRuleV2Include;

type RuleRow = Prisma.PolicyRuleV2GetPayload<{ include: typeof RULE_INCLUDE }>;

/** A full policy rule row (identities + targets included). */
export type PolicyRuleRow = RuleRow;

export interface PolicyRuleDto {
  id: string;
  scope: string;
  status: string;
  generation: number;
  priority: number;
  enabled: boolean;
  isDefault: boolean;
  /** Generation-stable identity the editor diffs draft against published by; a
   * publish copies it onto the snapshot, while row `id` regenerates. */
  logicalId: string;
  // Rule origin. The editor treats "custom" as editable and the derived sources
  // (blocklist / equipment / app_permission) as read-only.
  source: string;
  name: string;
  description: string | null;
  action: string;
  rateLimit: number | null;
  rateLimitWindow: string | null;
  requireApproval: boolean;
  conditions: Prisma.JsonValue;
  identities: PolicyIdentityInput[];
  targets: PolicyTargetDto[];
  createdAt: Date;
}

// Mirrors the input union but loosens `method` to a plain string, as stored.
export type PolicyTargetDto =
  | {
      kind: "app";
      provider: string;
      tools: string[];
      connectionScope: "organization" | "project" | null;
    }
  | { kind: "connection"; connectionId: string; tools: string[] }
  | {
      kind: "secret";
      secretId: string | null;
      secretScope: "organization" | "project" | null;
    }
  | {
      kind: "network";
      hostPattern: string;
      pathPattern: string | null;
      method: string | null;
    };

// A rule is scoped to exactly one of org/project (mirrors the scope_shape CHECK);
// the routes always pass exactly one, so partner scope never reaches here.
export const policyScope = (scope: ResourceScope) => {
  if (scope.organizationId) {
    return {
      scope: "organization" as const,
      organizationId: scope.organizationId,
    };
  }
  if (scope.projectId) {
    return { scope: "project" as const, projectId: scope.projectId };
  }
  throw new ServiceError(
    "BAD_REQUEST",
    "A policy scope requires a project or organization.",
  );
};

export type PolicyScopeBase = ReturnType<typeof policyScope>;

const scopeKeyOf = (base: PolicyScopeBase) =>
  base.scope === "organization" ? base.organizationId : base.projectId;

// Serialize per-scope publish/default mutations so concurrent callers can't
// double-create a generation or a second Default Rule. Exported so callers can
// read and write under one lock.
export const lockScope = (
  tx: Prisma.TransactionClient,
  base: PolicyScopeBase,
) =>
  tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`policy:${base.scope}:${scopeKeyOf(base)}`}))`;

const toIdentityDto = (
  row: RuleRow["identities"][number],
): PolicyIdentityInput => {
  if (row.agentId) return { type: "agent", id: row.agentId };
  if (row.userId) return { type: "user", id: row.userId };
  if (row.groupId) return { type: "group", id: row.groupId };
  throw new Error("policy identity row names no principal");
};

const toTargetDto = (row: RuleRow["targets"][number]): PolicyTargetDto => {
  switch (row.kind) {
    case "app":
      if (!row.appProvider) throw new Error("app target missing provider");
      return {
        kind: "app",
        provider: row.appProvider,
        tools: row.appTools,
        connectionScope:
          row.appConnectionScope === "organization" ||
          row.appConnectionScope === "project"
            ? row.appConnectionScope
            : null,
      };
    case "connection":
      if (!row.appConnectionId) throw new Error("connection target missing id");
      return {
        kind: "connection",
        connectionId: row.appConnectionId,
        tools: row.appTools,
      };
    case "secret":
      // A secret target names either a specific secret or "all secrets at a level".
      if (row.secretScope === "organization" || row.secretScope === "project") {
        return { kind: "secret", secretId: null, secretScope: row.secretScope };
      }
      if (!row.secretId) throw new Error("secret target missing id or scope");
      return { kind: "secret", secretId: row.secretId, secretScope: null };
    case "network":
      if (!row.hostPattern) throw new Error("network target missing host");
      return {
        kind: "network",
        hostPattern: row.hostPattern,
        pathPattern: row.pathPattern,
        method: row.method,
      };
    default:
      throw new Error(`unknown policy target kind: ${row.kind}`);
  }
};

const toRuleDto = (rule: RuleRow): PolicyRuleDto => ({
  id: rule.id,
  scope: rule.scope,
  status: rule.status,
  generation: rule.generation,
  priority: rule.priority,
  enabled: rule.enabled,
  isDefault: rule.isDefault,
  logicalId: rule.logicalId,
  source: rule.source,
  name: rule.name,
  description: rule.description,
  action: rule.action,
  rateLimit: rule.rateLimit,
  rateLimitWindow: rule.rateLimitWindow,
  requireApproval: rule.requireApproval,
  conditions: rule.conditions,
  identities: rule.identities.map(toIdentityDto),
  targets: rule.targets.map(toTargetDto),
  createdAt: rule.createdAt,
});

const identityCreate = (
  i: PolicyIdentityInput,
): Prisma.PolicyRuleIdentityCreateWithoutRuleInput => {
  switch (i.type) {
    case "agent":
      return { agent: { connect: { id: i.id } } };
    case "user":
      return { user: { connect: { id: i.id } } };
    case "group":
      return { group: { connect: { id: i.id } } };
  }
};

const targetCreate = (
  t: PolicyTargetInput,
): Prisma.PolicyRuleTargetCreateWithoutRuleInput => {
  switch (t.kind) {
    case "app":
      return {
        kind: "app",
        appProvider: t.provider,
        appTools: t.tools ?? [],
        appConnectionScope: t.connectionScope ?? null,
      };
    case "connection":
      // `appTools` narrow which endpoints the rule matches (empty = the
      // connection's whole app); the FK still injects the whole connection.
      return {
        kind: "connection",
        appConnection: { connect: { id: t.connectionId } },
        appTools: t.tools ?? [],
      };
    case "secret":
      // Specific secret → connect by id; "all secrets at a level" → the scope
      // marker (exactly one, guaranteed by `assertTargetsValid`).
      return t.secretId != null
        ? { kind: "secret", secret: { connect: { id: t.secretId } } }
        : { kind: "secret", secretScope: t.secretScope ?? null };
    case "network":
      return {
        kind: "network",
        hostPattern: t.hostPattern,
        pathPattern: t.pathPattern ?? null,
        method: t.method ?? null,
      };
  }
};

// Copy an existing identity/target row into a new rule (the publish snapshot).
const identityRowToCreate = (
  i: RuleRow["identities"][number],
): Prisma.PolicyRuleIdentityCreateWithoutRuleInput => {
  if (i.agentId) return { agent: { connect: { id: i.agentId } } };
  if (i.userId) return { user: { connect: { id: i.userId } } };
  if (i.groupId) return { group: { connect: { id: i.groupId } } };
  throw new Error("policy identity row names no principal");
};

const targetRowToCreate = (
  t: RuleRow["targets"][number],
): Prisma.PolicyRuleTargetCreateWithoutRuleInput => ({
  kind: t.kind,
  appProvider: t.appProvider,
  appTools: t.appTools,
  appConnectionScope: t.appConnectionScope,
  secretScope: t.secretScope,
  hostPattern: t.hostPattern,
  pathPattern: t.pathPattern,
  method: t.method,
  ...(t.appConnectionId
    ? { appConnection: { connect: { id: t.appConnectionId } } }
    : {}),
  ...(t.secretId ? { secret: { connect: { id: t.secretId } } } : {}),
});

// Drop redundant entries whose (rule, principal) / (rule, connection|secret)
// pair the DB would reject as a unique violation. Same-key entries are
// redundant, not an error; app/network rows carry no such unique.
const dedupeIdentities = (
  items: PolicyIdentityInput[],
): PolicyIdentityInput[] => {
  const seen = new Set<string>();
  return items.filter((i) => {
    const key = `${i.type}:${i.id}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
};

const dedupeTargets = (items: PolicyTargetInput[]): PolicyTargetInput[] => {
  const seenConn = new Set<string>();
  const seenSecret = new Set<string>();
  return items.filter((t) => {
    if (t.kind === "connection") {
      if (seenConn.has(t.connectionId)) return false;
      seenConn.add(t.connectionId);
    } else if (t.kind === "secret" && t.secretId != null) {
      // Only specific-secret targets carry the (rule, secretId) unique; a
      // scope-based "all secrets" target has no id to dedupe.
      if (seenSecret.has(t.secretId)) return false;
      seenSecret.add(t.secretId);
    }
    return true;
  });
};

// True if any identity targets the directory (user / user-group) — the
// enterprise-gated "groups" capability. A plain agent / "any" rule is not.
const hasDirectoryIdentity = (
  identities: PolicyIdentityInput[] | undefined,
): boolean => (identities ?? []).some((i) => i.type !== "agent");

export const rowHasDirectoryIdentity = (rows: RuleRow["identities"]): boolean =>
  rows.some((i) => i.userId != null || i.groupId != null);

// Map a rule's paid modifiers and directory identities onto the RuleActionGate's
// action names.
export const gatedActions = (rule: {
  rateLimit?: number | null;
  requireApproval?: boolean | null;
  hasDirectoryIdentity?: boolean;
}): string[] => {
  const actions: string[] = [];
  if (rule.requireApproval) actions.push("manual_approval");
  if (rule.rateLimit != null) actions.push("rate_limit");
  if (rule.hasDirectoryIdentity) actions.push("identity_directory");
  return actions;
};

// `conditions` is opaque JSON already validated by Zod (or copied straight from
// the DB); this is the single unknown → InputJsonValue boundary cast.
const jsonInput = (
  value: unknown,
): Prisma.InputJsonValue | Prisma.NullTypes.JsonNull => {
  if (value === null || value === undefined) return Prisma.JsonNull;
  return value as Prisma.InputJsonValue;
};

// A referenced identity/resource id that doesn't exist surfaces as P2025 from
// the nested `connect`; turn it into a clean 422 instead of a 500.
const asReferenceError = (err: unknown): never => {
  if (
    err instanceof Prisma.PrismaClientKnownRequestError &&
    err.code === "P2025"
  ) {
    throw new ServiceError(
      "UNPROCESSABLE",
      "A referenced identity or resource does not exist.",
    );
  }
  throw err;
};

// Validate a rule's identities before write: level (a project rule targets a
// specific agent or "any"; an org rule targets a user / user-group or "any")
// and ownership (every referenced principal belongs to the acting org, agents
// to the acting project). `asReferenceError` only proves existence, in any org,
// so the ownership half is what closes the IDOR gap. Empty identities ("any")
// always pass.
export const assertIdentitiesValid = async (
  base: PolicyScopeBase,
  identities: PolicyIdentityInput[],
): Promise<void> => {
  const deduped = dedupeIdentities(identities);
  if (deduped.length === 0) return;

  const idsOf = (type: PolicyIdentityInput["type"]) =>
    deduped.filter((i) => i.type === type).map((i) => i.id);
  const agentIds = idsOf("agent");
  const userIds = idsOf("user");
  const groupIds = idsOf("group");

  // Level restriction. OSS phrases it as the capability lock it is there; EE
  // keeps the scope-shaped wording.
  if (base.scope === "project" && (userIds.length || groupIds.length)) {
    throw new ServiceError(
      "UNPROCESSABLE",
      isOssEdition()
        ? "Group and user identities are available on OneCLI Cloud."
        : "A project rule can target a specific agent or all agents.",
    );
  }
  if (base.scope === "organization" && agentIds.length) {
    throw new ServiceError(
      "UNPROCESSABLE",
      "An organization rule targets users or user-groups — not a specific agent.",
    );
  }

  // Ownership — resolve the acting org (agents are additionally scoped to the
  // acting project).
  const organizationId =
    base.scope === "organization"
      ? base.organizationId
      : (
          await db.project.findUnique({
            where: { id: base.projectId },
            select: { organizationId: true },
          })
        )?.organizationId;
  if (!organizationId) {
    throw new ServiceError(
      "BAD_REQUEST",
      "Could not resolve the acting organization.",
    );
  }
  const projectId = base.scope === "project" ? base.projectId : null;

  const orgReferenceError = (): never => {
    throw new ServiceError(
      "UNPROCESSABLE",
      "A referenced identity does not belong to this organization.",
    );
  };
  // Each kind is deduped, so an exact count match proves every id resolved.
  const verify = async (ids: string[], count: () => Promise<number>) => {
    if (ids.length === 0) return;
    if ((await count()) !== ids.length) orgReferenceError();
  };

  await Promise.all([
    verify(agentIds, () =>
      db.agent.count({
        where: {
          id: { in: agentIds },
          ...(projectId ? { projectId } : { project: { organizationId } }),
        },
      }),
    ),
    verify(userIds, () =>
      db.organizationMember.count({
        // Suspended members are non-members for every other authz check, so a
        // rule can't target one either.
        where: {
          userId: { in: userIds },
          organizationId,
          status: { not: "suspended" },
        },
      }),
    ),
    verify(groupIds, () =>
      db.group.count({ where: { id: { in: groupIds }, organizationId } }),
    ),
  ]);
};

// Validate a rule's connection/secret target references before write — the same
// ownership invariant `assertIdentitiesValid` enforces for identities. `app` and
// `network` targets carry no owned id and are skipped.
export const assertTargetsValid = async (
  base: PolicyScopeBase,
  targets: PolicyTargetInput[],
): Promise<void> => {
  // A secret target names either a `secretId` or a `secretScope` (the XOR the
  // kind_shape CHECK enforces); checking here makes a malformed target a 422
  // rather than a constraint 500.
  if (
    targets.some(
      (t) =>
        t.kind === "secret" && (t.secretId == null) === (t.secretScope == null),
    )
  ) {
    throw new ServiceError(
      "UNPROCESSABLE",
      "A secret target must name either a specific secret or a level, not both.",
    );
  }

  // Level restriction for an "all resources at a level" target: a project rule
  // can only scope to its own project, while an org rule may scope to either
  // level so each agent can still use its own resources.
  if (
    base.scope === "project" &&
    targets.some(
      (t) =>
        (t.kind === "app" && t.connectionScope === "organization") ||
        (t.kind === "secret" && t.secretScope === "organization"),
    )
  ) {
    throw new ServiceError(
      "UNPROCESSABLE",
      "A project rule's target can't scope to organization-level resources.",
    );
  }

  const connectionIds = [
    ...new Set(
      targets.flatMap((t) => (t.kind === "connection" ? [t.connectionId] : [])),
    ),
  ];
  // Only specific-secret targets carry an owned id to fence; a scope-based "all
  // secrets" target is a level marker (guarded above), not a reference.
  const secretIds = [
    ...new Set(
      targets.flatMap((t) =>
        t.kind === "secret" && t.secretId != null ? [t.secretId] : [],
      ),
    ),
  ];
  if (connectionIds.length === 0 && secretIds.length === 0) return;

  // Resolve the acting org — same as the identity ownership check.
  const organizationId =
    base.scope === "organization"
      ? base.organizationId
      : (
          await db.project.findUnique({
            where: { id: base.projectId },
            select: { organizationId: true },
          })
        )?.organizationId;
  if (!organizationId) {
    throw new ServiceError(
      "BAD_REQUEST",
      "Could not resolve the acting organization.",
    );
  }
  const projectId = base.scope === "project" ? base.projectId : null;

  // A project rule may name only its own project's resources; org-level ones are
  // governed by org rules. Either way a foreign id is simply absent from the
  // count.
  const ownerScope = projectId
    ? { projectId }
    : { organizationId, scope: "organization" as const };

  const targetReferenceError = (): never => {
    throw new ServiceError(
      "UNPROCESSABLE",
      "A referenced connection or secret does not belong to this organization.",
    );
  };
  // Each set is deduped, so an exact count match proves every id resolved.
  const verify = async (ids: string[], count: () => Promise<number>) => {
    if (ids.length === 0) return;
    if ((await count()) !== ids.length) targetReferenceError();
  };

  await Promise.all([
    verify(connectionIds, () =>
      db.appConnection.count({
        where: { id: { in: connectionIds }, ...ownerScope },
      }),
    ),
    verify(secretIds, () =>
      db.secret.count({ where: { id: { in: secretIds }, ...ownerScope } }),
    ),
  ]);
};

/**
 * Validate a rule's granular session policy (object `conditions` — repos/folders
 * scoping a connection's injected credential): it applies only to an allow with
 * a connection target, then the wired policy validator runs per connection
 * target. A no-op for behavioral or absent conditions.
 *
 * Callers pass the merged (post-update) action/targets/conditions, so no PATCH
 * ordering can pair an object policy with a connection while skipping the gates.
 */
export const assertSessionPolicyValid = async (
  base: PolicyScopeBase,
  targets: PolicyTargetInput[] | undefined,
  conditions: unknown,
  action: "allow" | "block",
): Promise<void> => {
  if (!isSessionPolicy(conditions)) return;
  if (action !== "allow") {
    // A block injects nothing, so the scope would be silently inert.
    throw new ServiceError(
      "UNPROCESSABLE",
      "resource scoping (repositories/folders) applies only to Allow rules",
    );
  }
  const connectionIds = [
    ...new Set(
      (targets ?? []).flatMap((t) =>
        t.kind === "connection" ? [t.connectionId] : [],
      ),
    ),
  ];
  if (connectionIds.length === 0) {
    // Create is covered by a Zod refine, update is not — so enforce it here
    // against the merged state, or a later PATCH adding a connection target
    // would pair with a stored policy while skipping the gate below.
    throw new ServiceError(
      "UNPROCESSABLE",
      "resource scoping (repositories/folders) requires a connection target",
    );
  }
  const organizationId =
    base.scope === "organization"
      ? base.organizationId
      : (
          await db.project.findUnique({
            where: { id: base.projectId },
            select: { organizationId: true },
          })
        )?.organizationId;
  if (!organizationId) {
    throw new ServiceError(
      "BAD_REQUEST",
      "Could not resolve the acting organization.",
    );
  }
  const ownerScope =
    base.scope === "project"
      ? { projectId: base.projectId }
      : { organizationId, scope: "organization" as const };
  const conns = await db.appConnection.findMany({
    where: { id: { in: connectionIds }, ...ownerScope },
    select: { provider: true, metadata: true },
  });
  const validator = getPolicyValidator();
  for (const c of conns) {
    await validator.validate(
      organizationId,
      c.provider,
      c.metadata as Record<string, unknown> | null,
      conditions as Record<string, unknown>,
    );
  }
};

export const listPolicyRules = async (
  scope: ResourceScope,
  status: PolicyStatus,
): Promise<PolicyRuleDto[]> => {
  const base = policyScope(scope);
  const where: Prisma.PolicyRuleV2WhereInput = {
    ...base,
    status,
    isDefault: false,
  };
  // Published rows accumulate per generation; return only the active one.
  if (status === "published") {
    const agg = await db.policyRuleV2.aggregate({
      where: { ...base, status: "published" },
      _max: { generation: true },
    });
    if (agg._max.generation === null) return [];
    where.generation = agg._max.generation;
  }
  const rules = await db.policyRuleV2.findMany({
    where,
    orderBy: [{ priority: "asc" }, { id: "asc" }],
    include: RULE_INCLUDE,
  });
  return rules.map(toRuleDto);
};

export const getPolicyRule = async (
  scope: ResourceScope,
  id: string,
): Promise<PolicyRuleDto> => {
  const rule = await db.policyRuleV2.findFirst({
    where: { id, ...policyScope(scope), status: "draft", isDefault: false },
    include: RULE_INCLUDE,
  });
  if (!rule) throw new ServiceError("NOT_FOUND", "Policy rule not found.");
  return toRuleDto(rule);
};

export const createPolicyRule = async (
  scope: ResourceScope,
  input: CreatePolicyRuleInput,
  userId: string,
): Promise<PolicyRuleDto> => {
  const base = policyScope(scope);
  await assertIdentitiesValid(base, input.identities ?? []);
  // An empty target list matches nothing at the gateway, never "any". Only the
  // terminal Default Rule is target-less, and it is created by `setDefault`.
  if (!input.targets || input.targets.length === 0) {
    throw new ServiceError(
      "UNPROCESSABLE",
      "A rule must name at least one target.",
    );
  }
  await assertTargetsValid(base, input.targets);
  await getPolicyValidator().validateTargets?.(input.targets);
  await assertSessionPolicyValid(
    base,
    input.targets,
    input.conditions,
    input.action,
  );
  await getRuleActionGate().assertAllowed(
    scope,
    gatedActions({
      rateLimit: input.rateLimit,
      requireApproval: input.requireApproval,
      hasDirectoryIdentity: hasDirectoryIdentity(input.identities),
    }),
  );
  try {
    // The max-read and insert run under the per-scope lock every other priority
    // writer takes: an unlocked read-then-append could mint duplicate
    // priorities, and ties make the gateway's first-match order nondeterministic.
    const rule = await db.$transaction(async (tx) => {
      await lockScope(tx, base);
      const agg = await tx.policyRuleV2.aggregate({
        where: { ...base, status: "draft", isDefault: false },
        _max: { priority: true },
      });
      return tx.policyRuleV2.create({
        data: {
          ...base,
          status: "draft",
          generation: 0,
          priority: (agg._max.priority ?? 0) + 1,
          isDefault: false,
          enabled: input.enabled ?? true,
          name: input.name,
          description: input.description ?? null,
          action: input.action,
          rateLimit: input.rateLimit ?? null,
          rateLimitWindow: input.rateLimitWindow ?? null,
          requireApproval: input.requireApproval ?? false,
          conditions: jsonInput(input.conditions),
          createdByUserId: userId,
          identities: {
            create: dedupeIdentities(input.identities ?? []).map(
              identityCreate,
            ),
          },
          targets: {
            create: dedupeTargets(input.targets ?? []).map(targetCreate),
          },
        },
        include: RULE_INCLUDE,
      });
    });
    // A new rule appends; order changes only via an explicit reorder.
    return toRuleDto(rule);
  } catch (err) {
    return asReferenceError(err);
  }
};

export const updatePolicyRule = async (
  scope: ResourceScope,
  id: string,
  input: UpdatePolicyRuleInput,
): Promise<PolicyRuleDto> => {
  const base = policyScope(scope);
  const existing = await db.policyRuleV2.findFirst({
    where: { id, ...base, status: "draft", isDefault: false },
    include: { targets: true },
  });
  if (!existing) throw new ServiceError("NOT_FOUND", "Policy rule not found.");

  const nextAction = input.action ?? existing.action;
  const nextRateLimit =
    input.rateLimit !== undefined ? input.rateLimit : existing.rateLimit;
  const nextWindow =
    input.rateLimitWindow !== undefined
      ? input.rateLimitWindow
      : existing.rateLimitWindow;
  const nextApproval =
    input.requireApproval !== undefined
      ? input.requireApproval
      : existing.requireApproval;

  if (
    nextAction === "block" &&
    (nextRateLimit != null || nextWindow != null || nextApproval)
  ) {
    throw new ServiceError(
      "UNPROCESSABLE",
      "rate-limit and approval modifiers require action = allow",
    );
  }
  if ((nextRateLimit == null) !== (nextWindow == null)) {
    throw new ServiceError(
      "UNPROCESSABLE",
      "rateLimit and rateLimitWindow must be provided together",
    );
  }
  // Validate identities (level + ownership) only when they're being changed.
  if (input.identities !== undefined) {
    await assertIdentitiesValid(base, input.identities);
  }
  // Only when targets are being changed. A provided list must be non-empty —
  // [] would leave the rule matching nothing at the gateway; the editor
  // preserves a rule's targets by omitting them.
  if (input.targets !== undefined) {
    if (input.targets.length === 0) {
      throw new ServiceError(
        "UNPROCESSABLE",
        "A rule must name at least one target.",
      );
    }
    await assertTargetsValid(base, input.targets);
    await getPolicyValidator().validateTargets?.(input.targets);
  }
  // Re-checked whenever conditions, targets or action change, so a later PATCH
  // can't pair a stored session policy with a connection target un-gated.
  if (
    input.conditions !== undefined ||
    input.targets !== undefined ||
    input.action !== undefined
  ) {
    const mergedConditions =
      input.conditions !== undefined ? input.conditions : existing.conditions;
    const mergedTargets =
      input.targets ??
      existing.targets
        .filter((t) => t.kind === "connection" && t.appConnectionId != null)
        .map((t) => ({
          kind: "connection" as const,
          connectionId: t.appConnectionId as string,
        }));
    await assertSessionPolicyValid(
      base,
      mergedTargets,
      mergedConditions,
      input.action ?? (existing.action as "allow" | "block"),
    );
  }
  // Gate only the paid modifiers / directory identities this update actually
  // enables — a name-only edit of a grandfathered rule shouldn't re-check the plan.
  await getRuleActionGate().assertAllowed(
    scope,
    gatedActions({
      rateLimit: input.rateLimit,
      requireApproval: input.requireApproval,
      hasDirectoryIdentity: hasDirectoryIdentity(input.identities),
    }),
  );

  try {
    const rule = await db.$transaction(async (tx) => {
      if (input.identities !== undefined) {
        await tx.policyRuleIdentity.deleteMany({ where: { ruleId: id } });
      }
      if (input.targets !== undefined) {
        await tx.policyRuleTarget.deleteMany({ where: { ruleId: id } });
      }
      return tx.policyRuleV2.update({
        where: { id },
        data: {
          ...(input.name !== undefined ? { name: input.name } : {}),
          ...(input.description !== undefined
            ? { description: input.description }
            : {}),
          ...(input.enabled !== undefined ? { enabled: input.enabled } : {}),
          ...(input.action !== undefined ? { action: input.action } : {}),
          ...(input.rateLimit !== undefined
            ? { rateLimit: input.rateLimit }
            : {}),
          ...(input.rateLimitWindow !== undefined
            ? { rateLimitWindow: input.rateLimitWindow }
            : {}),
          ...(input.requireApproval !== undefined
            ? { requireApproval: input.requireApproval }
            : {}),
          ...(input.conditions !== undefined
            ? { conditions: jsonInput(input.conditions) }
            : {}),
          ...(input.identities !== undefined
            ? {
                identities: {
                  create: dedupeIdentities(input.identities).map(
                    identityCreate,
                  ),
                },
              }
            : {}),
          ...(input.targets !== undefined
            ? {
                targets: {
                  create: dedupeTargets(input.targets).map(targetCreate),
                },
              }
            : {}),
        },
        include: RULE_INCLUDE,
      });
    });
    // An edit never moves the rule: the position the user chose is part of the
    // policy.
    return toRuleDto(rule);
  } catch (err) {
    return asReferenceError(err);
  }
};

export const deletePolicyRule = async (
  scope: ResourceScope,
  id: string,
): Promise<void> => {
  const existing = await db.policyRuleV2.findFirst({
    where: { id, ...policyScope(scope), status: "draft", isDefault: false },
    select: { id: true },
  });
  if (!existing) throw new ServiceError("NOT_FOUND", "Policy rule not found.");
  await db.policyRuleV2.delete({ where: { id } });
  // Deleting leaves a priority gap: only relative order matters to first-match,
  // and the next reorder renumbers densely.
};

export const reorderPolicyRules = async (
  scope: ResourceScope,
  orderedIds: string[],
): Promise<PolicyRuleDto[]> => {
  const base = policyScope(scope);
  try {
    await db.$transaction(async (tx) => {
      // Under the per-scope lock, so a reorder can't interleave with a
      // concurrent snapshot rewriting the same draft.
      await lockScope(tx, base);
      const draft = await tx.policyRuleV2.findMany({
        where: { ...base, status: "draft", isDefault: false },
        select: { id: true },
      });
      const draftIds = new Set(draft.map((r) => r.id));
      const uniqueOrdered = new Set(orderedIds);
      const namesEveryRuleOnce =
        orderedIds.length === draftIds.size &&
        uniqueOrdered.size === orderedIds.length &&
        orderedIds.every((id) => draftIds.has(id));
      if (!namesEveryRuleOnce) {
        throw new ServiceError(
          "CONFLICT",
          "Rule set changed — refresh and try again.",
        );
      }
      // Ascending: index 0 → priority 1 (lowest = evaluated first / wins).
      for (const [i, id] of orderedIds.entries()) {
        await tx.policyRuleV2.update({
          where: { id },
          data: { priority: i + 1 },
        });
      }
    });
  } catch (err) {
    // A delete committed between the in-tx read and an update (deletes don't
    // take the scope lock) surfaces as P2025 — same staleness, same 409.
    if (
      err instanceof Prisma.PrismaClientKnownRequestError &&
      err.code === "P2025"
    ) {
      throw new ServiceError(
        "CONFLICT",
        "Rule set changed — refresh and try again.",
      );
    }
    throw err;
  }
  return listPolicyRules(scope, "draft");
};

// The terminal Default Rule is a per-scope singleton. Both scopes default to
// allow; deny-by-default is an admin's opt-in flip on the org Default Rule. The
// unused parameter keeps every call site naming its scope base.
const defaultAction: (base: PolicyScopeBase) => "allow" | "block" = () =>
  "allow";

const findDefault = async (
  client: Prisma.TransactionClient | typeof db,
  base: PolicyScopeBase,
  status: PolicyStatus = "draft",
) => {
  const where: Prisma.PolicyRuleV2WhereInput = {
    ...base,
    status,
    isDefault: true,
  };
  // Published rows accumulate one default per generation; pin the active one
  // (max generation), mirroring listPolicyRules — else drift compares a stale gen.
  if (status === "published") {
    const agg = await client.policyRuleV2.aggregate({
      where: { ...base, status: "published" },
      _max: { generation: true },
    });
    if (agg._max.generation === null) return null;
    where.generation = agg._max.generation;
  }
  return client.policyRuleV2.findFirst({ where, include: RULE_INCLUDE });
};

// Create the default if absent — callers hold the per-scope lock.
export const ensureDefault = async (
  tx: Prisma.TransactionClient,
  base: PolicyScopeBase,
): Promise<RuleRow> => {
  const existing = await findDefault(tx, base);
  if (existing) return existing;
  return tx.policyRuleV2.create({
    data: {
      ...base,
      status: "draft",
      generation: 0,
      priority: 0,
      isDefault: true,
      enabled: true,
      source: "default",
      name: "Default Rule",
      action: defaultAction(base),
      requireApproval: false,
    },
    include: RULE_INCLUDE,
  });
};

// A computed default returned by GET when none is persisted (id "" = virtual),
// so reads never mutate. Persisted on the first PATCH /default or publish.
const virtualDefault = (base: PolicyScopeBase): PolicyRuleDto => ({
  id: "",
  logicalId: "",
  scope: base.scope,
  status: "draft",
  generation: 0,
  priority: 0,
  enabled: true,
  isDefault: true,
  source: "default",
  name: "Default Rule",
  description: null,
  action: defaultAction(base),
  rateLimit: null,
  rateLimitWindow: null,
  requireApproval: false,
  conditions: null,
  identities: [],
  targets: [],
  createdAt: new Date(0),
});

export const getPolicyDefault = async (
  scope: ResourceScope,
  status: PolicyStatus = "draft",
): Promise<PolicyRuleDto> => {
  const base = policyScope(scope);
  const existing = await findDefault(db, base, status);
  return existing ? toRuleDto(existing) : virtualDefault(base);
};

export const setPolicyDefaultAction = async (
  scope: ResourceScope,
  action: "allow" | "block",
): Promise<PolicyRuleDto> => {
  const base = policyScope(scope);
  const updated = await db.$transaction(async (tx) => {
    await lockScope(tx, base);
    const def = await ensureDefault(tx, base);
    return tx.policyRuleV2.update({
      where: { id: def.id },
      data: { action },
      include: RULE_INCLUDE,
    });
  });
  return toRuleDto(updated);
};

export interface PublishResult {
  generation: number;
  ruleCount: number;
}

// How many published generations to retain per scope for rollback; older ones
// are pruned on publish so frequent republishes don't grow the table unbounded.
const PUBLISHED_GENERATION_RETENTION = 10;

// Snapshot the given draft rows into a fresh published generation (the active
// set is max(generation)). Callers hold the scope lock; the plan gate, if any,
// is the caller's job.
export const snapshotDraftRules = async (
  tx: Prisma.TransactionClient,
  base: PolicyScopeBase,
  draftRules: RuleRow[],
  userId: string | null,
): Promise<PublishResult> => {
  const maxGen = await tx.policyRuleV2.aggregate({
    where: { ...base, status: "published" },
    _max: { generation: true },
  });
  const generation = (maxGen._max.generation ?? 0) + 1;
  for (const r of draftRules) {
    await tx.policyRuleV2.create({
      data: {
        ...base,
        status: "published",
        generation,
        priority: r.priority,
        isDefault: r.isDefault,
        source: r.source,
        // Stable across generations — the rate counter keys on it.
        logicalId: r.logicalId,
        enabled: r.enabled,
        name: r.name,
        description: r.description,
        action: r.action,
        rateLimit: r.rateLimit,
        rateLimitWindow: r.rateLimitWindow,
        requireApproval: r.requireApproval,
        conditions: jsonInput(r.conditions),
        createdByUserId: userId,
        identities: { create: r.identities.map(identityRowToCreate) },
        targets: { create: r.targets.map(targetRowToCreate) },
      },
    });
  }
  // The gateway reads only max(generation); older ones exist for rollback.
  if (generation > PUBLISHED_GENERATION_RETENTION) {
    await tx.policyRuleV2.deleteMany({
      where: {
        ...base,
        status: "published",
        generation: { lte: generation - PUBLISHED_GENERATION_RETENTION },
      },
    });
  }
  return { generation, ruleCount: draftRules.length };
};

// "Apply Changes": snapshot the scope's draft set into a fresh published
// generation. Draft rows keep their ids — they stay the working copy.
export const publishPolicy = async (
  scope: ResourceScope,
  userId: string,
): Promise<PublishResult> => {
  const base = policyScope(scope);
  return db.$transaction(async (tx) => {
    await lockScope(tx, base);
    await ensureDefault(tx, base);
    const draftRules = await tx.policyRuleV2.findMany({
      where: { ...base, status: "draft" },
      include: RULE_INCLUDE,
    });
    // Re-assert the plan gate: what's about to go live must still be entitled.
    const actions = [
      ...new Set(
        draftRules.flatMap((r) =>
          gatedActions({
            rateLimit: r.rateLimit,
            requireApproval: r.requireApproval,
            hasDirectoryIdentity: rowHasDirectoryIdentity(r.identities),
          }),
        ),
      ),
    ];
    if (actions.length > 0) {
      await getRuleActionGate().assertAllowed(scope, actions);
    }
    // Likewise the granular-scoping entitlement: a session policy entitled at
    // author time must still be entitled, and still valid against its
    // connection, to go live.
    for (const r of draftRules) {
      if (!isSessionPolicy(r.conditions)) continue;
      const connTargets = r.targets
        .filter((t) => t.kind === "connection" && t.appConnectionId != null)
        .map((t) => ({
          kind: "connection" as const,
          connectionId: t.appConnectionId as string,
        }));
      await assertSessionPolicyValid(
        base,
        connTargets,
        r.conditions,
        r.action as "allow" | "block",
      );
    }
    return snapshotDraftRules(tx, base, draftRules, userId);
  });
};

// ── Cutover backfill ─────────────────────────────────────────────────────────

/** A target to materialize. Unlike `PolicyTargetInput`'s strict enum, `method`
 * is the verbatim free string the translator carries, so a legacy row's method
 * survives exactly. The `secret` arm keeps the stored `secretId`. */
export type BackfillTargetInput =
  | {
      kind: "network";
      hostPattern: string;
      pathPattern: string | null;
      method: string | null;
    }
  | {
      kind: "app";
      provider: string;
      tools: string[];
      connectionScope: "organization" | "project" | null;
    }
  | { kind: "connection"; connectionId: string; tools: string[] }
  | { kind: "secret"; secretId: string };

/** One translated rule to materialize. */
export interface BackfillRuleInput {
  priority: number;
  isDefault: boolean;
  /** Rule origin: custom/default, or one of the derived sources. */
  source: "custom" | "app_permission" | "blocklist" | "default" | "equipment";
  name: string;
  action: "allow" | "block";
  rateLimit: number | null;
  rateLimitWindow: "minute" | "hour" | "day" | null;
  requireApproval: boolean;
  conditions: unknown;
  identities: PolicyIdentityInput[];
  targets: BackfillTargetInput[];
  /** Omitted = true. Disabled legacy rows are carried with `false` so the data
   * survives into the editor; the gateway loads `enabled = true` rows only. */
  enabled?: boolean;
  /** Omitted = null. The cutover stamps its migrated Default Rules so a user
   * publish that pre-empted it is detectable. */
  description?: string | null;
}

// Method stays a verbatim string — see BackfillTargetInput. connection/secret
// connect by id, mirroring `targetCreate`.
const backfillTargetCreate = (
  t: BackfillTargetInput,
): Prisma.PolicyRuleTargetCreateWithoutRuleInput => {
  switch (t.kind) {
    case "app":
      return {
        kind: "app",
        appProvider: t.provider,
        appTools: t.tools,
        appConnectionScope: t.connectionScope,
      };
    case "network":
      return {
        kind: "network",
        hostPattern: t.hostPattern,
        pathPattern: t.pathPattern,
        method: t.method,
      };
    case "connection":
      return {
        kind: "connection",
        appConnection: { connect: { id: t.connectionId } },
        appTools: t.tools,
      };
    case "secret":
      return { kind: "secret", secret: { connect: { id: t.secretId } } };
  }
};

export interface BackfillResult {
  skipped: boolean;
  generation: number | null;
  ruleCount: number;
}

/**
 * Materialize a scope's translated rules as the draft working copy plus
 * published generation 1. Idempotent: a scope that already has a published
 * generation is skipped. Bypasses the `RuleActionGate` because it materializes
 * existing, already-entitled policy — not for user writes, which go through
 * create/update/publish.
 */
export const backfillPublishScope = async (
  scope: ResourceScope,
  rules: BackfillRuleInput[],
): Promise<BackfillResult> => {
  const base = policyScope(scope);
  return db.$transaction(
    async (tx) => {
      await lockScope(tx, base);
      const published = await tx.policyRuleV2.count({
        where: { ...base, status: "published" },
      });
      if (published > 0) {
        return { skipped: true, generation: null, ruleCount: 0 };
      }
      for (const r of rules) {
        const common = {
          ...base,
          priority: r.priority,
          isDefault: r.isDefault,
          source: r.source,
          enabled: r.enabled ?? true,
          description: r.description ?? null,
          name: r.name,
          action: r.action,
          rateLimit: r.rateLimit ?? null,
          rateLimitWindow: r.rateLimitWindow ?? null,
          requireApproval: r.requireApproval,
          conditions: jsonInput(r.conditions),
        };
        // Draft (gen 0) plus the published snapshot (gen 1), identical at
        // cutover. The published row copies the draft's logicalId so the rate
        // counter stays stable across future republishes.
        const draft = await tx.policyRuleV2.create({
          data: {
            ...common,
            status: "draft",
            generation: 0,
            identities: { create: r.identities.map(identityCreate) },
            targets: { create: r.targets.map(backfillTargetCreate) },
          },
          select: { logicalId: true },
        });
        await tx.policyRuleV2.create({
          data: {
            ...common,
            status: "published",
            generation: 1,
            logicalId: draft.logicalId,
            identities: { create: r.identities.map(identityCreate) },
            targets: { create: r.targets.map(backfillTargetCreate) },
          },
        });
      }
      // An empty scope publishes nothing; generation null reads to the verifier
      // as vacuously OK rather than "not backfilled".
      return {
        skipped: false,
        generation: rules.length > 0 ? 1 : null,
        ruleCount: rules.length,
      };
      // A large scope can exceed the default interactive-tx timeout, and would
      // then fail identically on every boot, stranding the scope on legacy.
    },
    { timeout: 60_000, maxWait: 10_000 },
  );
};

export interface LastPublishDto {
  generation: number;
  ruleCount: number;
  appliedAt: Date;
  /** Who clicked Apply — null for a system publish (the new-scope seeder) or a
   * pre-provenance generation. */
  appliedBy: { name: string | null; email: string } | null;
}

/** The scope's most recent publish — who applied it and when. Null = never
 * published. */
export const getLastPublish = async (
  scope: ResourceScope,
): Promise<LastPublishDto | null> => {
  const base = policyScope(scope);
  const newest = await db.policyRuleV2.findFirst({
    where: { ...base, status: "published" },
    orderBy: { generation: "desc" },
    select: {
      generation: true,
      createdAt: true,
      createdByUser: { select: { name: true, email: true } },
    },
  });
  if (!newest) return null;
  const ruleCount = await db.policyRuleV2.count({
    where: { ...base, status: "published", generation: newest.generation },
  });
  return {
    generation: newest.generation,
    ruleCount,
    appliedAt: newest.createdAt,
    appliedBy: newest.createdByUser
      ? { name: newest.createdByUser.name, email: newest.createdByUser.email }
      : null,
  };
};
