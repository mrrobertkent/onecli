import { z } from "zod";
import { ruleConditionSchema } from "./policy-rule";

// ── Unified policy engine (policy_rules_v2) request shapes ──────────────────
// The discriminated unions mirror the DB CHECK constraints, so malformed input
// is rejected with a 422 before it reaches the database.

/** A rule names exactly one principal per identity — a uniform {type, id}. */
export const policyIdentitySchema = z.discriminatedUnion("type", [
  z.object({ type: z.literal("agent"), id: z.string().min(1) }),
  z.object({ type: z.literal("user"), id: z.string().min(1) }),
  z.object({ type: z.literal("group"), id: z.string().min(1) }),
]);
export type PolicyIdentityInput = z.infer<typeof policyIdentitySchema>;

const methodSchema = z.enum(["GET", "POST", "PUT", "PATCH", "DELETE"]);

/** A target's populated fields are shaped by `kind` (the kind_shape CHECK). */
export const policyTargetSchema = z.discriminatedUnion("kind", [
  z.object({
    kind: z.literal("app"),
    provider: z.string().min(1).max(255),
    tools: z.array(z.string().min(1)).max(100).optional(),
    // When set, this app target injects every one of the agent's connections of
    // `provider` at the given level; absent, the rule injects nothing.
    // `assertTargetsValid` fences the level.
    connectionScope: z.enum(["organization", "project"]).optional(),
  }),
  z.object({
    kind: z.literal("connection"),
    connectionId: z.string().min(1),
    // `tools` narrow which endpoints the rule matches; empty means the
    // provider's whole app. Injection ignores them and always injects the whole
    // connection.
    tools: z.array(z.string().min(1)).max(100).optional(),
  }),
  z.object({
    kind: z.literal("secret"),
    // A secret target names either a specific `secretId` or a `secretScope`.
    // `assertTargetsValid` enforces exactly one of them, plus the level fence.
    secretId: z.string().min(1).optional(),
    secretScope: z.enum(["organization", "project"]).optional(),
  }),
  z.object({
    kind: z.literal("network"),
    hostPattern: z.string().min(1).max(1000),
    pathPattern: z.string().max(1000).optional(),
    method: methodSchema.optional(),
  }),
]);
export type PolicyTargetInput = z.infer<typeof policyTargetSchema>;

export const policyActionSchema = z.enum(["allow", "block"]);
const rateLimitWindowSchema = z.enum(["minute", "hour", "day"]);

// Granular per-resource scoping (the "session policy") a connection target can
// carry: an object keyed by the provider's resource axis — GitHub → repos,
// Dropbox → folders. It rides in `conditions`, distinct from the behavioral
// RuleCondition[] the block/allow engine evaluates. Structural bounds only; the
// per-provider deep checks and the entitlement gate run in the EE policy
// validator. Absent means unrestricted.
//
// An empty list is refused: clearing a restriction sends `null`, so an empty
// list can only arrive as a scope no UI can author.
const resourceList = (max: number, itemMax: number) =>
  z.array(z.string().min(1).max(itemMax)).min(1).max(max);

export const sessionPolicySchema = z.union([
  z.object({ repositories: resourceList(1000, 400) }).strict(),
  z.object({ folders: resourceList(100, 1024) }).strict(),
]);
export type SessionPolicyInput = z.infer<typeof sessionPolicySchema>;

/** A rule's `conditions`: either behavioral rules or a connection target's
 * granular session policy. An array is behavioral, an object is a session
 * policy; they never mix on one rule. */
const ruleConditionsSchema = z.union([
  z.array(ruleConditionSchema).max(10),
  sessionPolicySchema,
]);

export const isSessionPolicy = (c: unknown): c is SessionPolicyInput =>
  c != null && typeof c === "object" && !Array.isArray(c);

const ruleShape = {
  name: z.string().trim().min(1).max(255),
  description: z.string().max(1000).optional(),
  enabled: z.boolean().optional(),
  action: policyActionSchema,
  // Empty identities mean "any agent", but an empty target list matches nothing
  // at the gateway, so `createPolicyRule` rejects it.
  rateLimit: z.number().int().min(1).max(1_000_000).optional(),
  rateLimitWindow: rateLimitWindowSchema.optional(),
  requireApproval: z.boolean().optional(),
  conditions: ruleConditionsSchema.optional(),
  identities: z.array(policyIdentitySchema).max(100).optional(),
  targets: z.array(policyTargetSchema).max(100).optional(),
};

const modifiersRequireAllow = {
  check: (d: {
    action: "allow" | "block";
    rateLimit?: number | null;
    requireApproval?: boolean | null;
    rateLimitWindow?: string | null;
  }) =>
    d.action !== "block" ||
    (d.rateLimit == null && d.rateLimitWindow == null && !d.requireApproval),
  message: "rate-limit and approval modifiers require action = allow",
};
const rateLimitPaired = {
  check: (d: { rateLimit?: number | null; rateLimitWindow?: string | null }) =>
    (d.rateLimit == null) === (d.rateLimitWindow == null),
  message: "rateLimit and rateLimitWindow must be provided together",
};
const sessionPolicyNeedsConnection = {
  // A session policy scopes a connection's injected credential, so it is
  // meaningless without a connection target.
  check: (d: { conditions?: unknown; targets?: { kind: string }[] }) =>
    !isSessionPolicy(d.conditions) ||
    (d.targets ?? []).some((t) => t.kind === "connection"),
  message:
    "resource scoping (repositories/folders) requires a connection target",
};

export const createPolicyRuleSchema = z
  .object(ruleShape)
  .refine(modifiersRequireAllow.check, {
    message: modifiersRequireAllow.message,
  })
  .refine(rateLimitPaired.check, { message: rateLimitPaired.message })
  .refine(sessionPolicyNeedsConnection.check, {
    message: sessionPolicyNeedsConnection.message,
  });
export type CreatePolicyRuleInput = z.infer<typeof createPolicyRuleSchema>;

// Every field optional; `null` clears a nullable field. `action`-vs-modifier
// consistency is re-checked in the service against the merged rule, since a
// partial update may change only one side.
export const updatePolicyRuleSchema = z
  .object({
    name: z.string().trim().min(1).max(255).optional(),
    description: z.string().max(1000).nullable().optional(),
    enabled: z.boolean().optional(),
    action: policyActionSchema.optional(),
    rateLimit: z.number().int().min(1).max(1_000_000).nullable().optional(),
    rateLimitWindow: rateLimitWindowSchema.nullable().optional(),
    requireApproval: z.boolean().optional(),
    conditions: ruleConditionsSchema.nullable().optional(),
    identities: z.array(policyIdentitySchema).max(100).optional(),
    targets: z.array(policyTargetSchema).max(100).optional(),
  })
  .refine((d) => Object.keys(d).length > 0, {
    message: "At least one field must be provided",
  });
export type UpdatePolicyRuleInput = z.infer<typeof updatePolicyRuleSchema>;

export const reorderPolicyRulesSchema = z.object({
  orderedIds: z.array(z.string().min(1)).min(1),
});

export const setDefaultRuleSchema = z.object({
  action: policyActionSchema,
});

export const policyStatusSchema = z.enum(["draft", "published"]);
