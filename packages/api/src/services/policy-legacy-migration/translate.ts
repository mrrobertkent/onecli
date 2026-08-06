/**
 * The pure old→new mapping for an OSS project's legacy policy state — custom
 * rules, app-permission tool rows, blocklist rows, equipment assignments and
 * the org-row `policyMode` — into `BackfillRuleInput`s.
 *
 * Ordering: agent-scoped rules above all-agents rules, then strictness
 * (block < approval < rate < allow), stable on input order — so callers must
 * feed rows `createdAt asc` for ties to resolve the same on every run.
 */
import { getApp } from "../../apps/registry";
import type { BackfillRuleInput, BackfillTargetInput } from "../policy-service";

/** The raw project `policy_rules` row subset the OSS cutover reads. */
export interface OssOldRule {
  id: string;
  name: string;
  agentId: string | null;
  hostPattern: string;
  pathPattern: string | null;
  method: string | null;
  action: string;
  enabled: boolean;
  rateLimit: number | null;
  rateLimitWindow: string | null;
  metadata: unknown;
  conditions: unknown;
}

/** A selective agent's equipment; the caller applies the project-scope fence. */
export interface OssAgentEquipment {
  agentId: string;
  secretMode: string;
  secretIds: string[];
  connections: { appConnectionId: string; sessionPolicy: unknown }[];
}

const metadataOf = (row: OssOldRule): Record<string, unknown> | null =>
  row.metadata && typeof row.metadata === "object"
    ? (row.metadata as Record<string, unknown>)
    : null;

/** Whether a row is a host-wide blocklist row (`metadata.type = "blocklist"`). */
export const isOssBlocklistRow = (row: OssOldRule): boolean =>
  metadataOf(row)?.type === "blocklist";

const collapsed = (
  action: "allow" | "block",
  requireApproval: boolean,
  rateLimit: number | null,
  rateLimitWindow: "minute" | "hour" | "day" | null,
) => ({ action, requireApproval, rateLimit, rateLimitWindow });

/**
 * Collapse an old action to the v2 binary plus modifiers. Returns null for a
 * malformed rate row (limit ≤ 0 or an unknown window) or an unknown action —
 * the legacy gateway drops those too.
 */
export const collapseOssAction = (row: OssOldRule) => {
  switch (row.action) {
    case "block":
      return collapsed("block", false, null, null);
    case "manual_approval":
      return collapsed("allow", true, null, null);
    case "rate_limit": {
      if (row.rateLimit === null || row.rateLimit <= 0) return null;
      if (
        row.rateLimitWindow !== "minute" &&
        row.rateLimitWindow !== "hour" &&
        row.rateLimitWindow !== "day"
      ) {
        return null;
      }
      return collapsed("allow", false, row.rateLimit, row.rateLimitWindow);
    }
    case "allow":
      return collapsed("allow", false, null, null);
    default:
      return null;
  }
};

/** Strictness rank: block 0 < approval 1 < rate 2 < allow 3. */
const strictness = (r: BackfillRuleInput): number => {
  if (r.action === "block") return 0;
  if (r.requireApproval) return 1;
  if (r.rateLimit !== null) return 2;
  return 3;
};

/** Project ordering: agent-scoped above all-agents, then strictness; stable on
 * input order. */
export const ossRuleOrderComparator = (
  a: BackfillRuleInput,
  b: BackfillRuleInput,
): number => {
  const ai = a.identities.length > 0 ? 0 : 1;
  const bi = b.identities.length > 0 ? 0 : 1;
  if (ai !== bi) return ai - bi;
  return strictness(a) - strictness(b);
};

/**
 * One legacy row → one v2 rule carrying its host/path/method verbatim as a
 * network target. Custom and app-permission tool rows both map with
 * `source: "custom"`; blocklist rows keep `source: "blocklist"`. Returns null
 * for rows the legacy gateway dropped.
 */
export const translateOssRow = (row: OssOldRule): BackfillRuleInput | null => {
  const action = collapseOssAction(row);
  if (!action) return null;
  return {
    priority: 0, // assigned by translateOssProjectRules
    isDefault: false,
    source: isOssBlocklistRow(row) ? "blocklist" : "custom",
    name: row.name,
    ...action,
    // Legacy conditions are arrays; an object would read as a session policy
    // and 422 on publish.
    conditions: Array.isArray(row.conditions) ? row.conditions : null,
    identities: row.agentId ? [{ type: "agent", id: row.agentId }] : [],
    targets: [
      {
        kind: "network",
        hostPattern: row.hostPattern,
        pathPattern: row.pathPattern,
        method: row.method,
      },
    ],
    enabled: row.enabled,
  };
};

/**
 * An app-permission tool row's provider, or null for anything else. Blocklist
 * rows carry `source` but no `toolId`, so they never match.
 */
export const ossAppToolProvider = (row: OssOldRule): string | null => {
  const md = metadataOf(row);
  if (!md || md.source !== "app_permission") return null;
  if (typeof md.toolId !== "string" || typeof md.provider !== "string") {
    return null;
  }
  return md.provider;
};

type OssCollapsedAction = NonNullable<ReturnType<typeof collapseOssAction>>;

interface OssToolGroup {
  provider: string;
  collapsed: OssCollapsedAction;
  rows: OssOldRule[];
}

/**
 * The grouped app rule's display name, action-suffixed so an allow group and a
 * block group of the same provider stay tellable apart.
 */
export const mergedAppRuleName = (
  provider: string,
  action: "allow" | "block",
  requireApproval: boolean,
): string => {
  const suffix =
    action === "block" ? " (blocked)" : requireApproval ? " (approval)" : "";
  return `${getApp(provider)?.name ?? provider}${suffix}`;
};

/** One tool-row group → its single grouped rule, carrying every member's stored
 * endpoint as a network target, deduped on (host, path, method). The caller
 * guarantees the group's key fields are uniform; the first member is the
 * representative. */
const groupedOssRule = (group: OssToolGroup): BackfillRuleInput => {
  const first = group.rows[0];
  const seen = new Set<string>();
  const targets: BackfillTargetInput[] = [];
  for (const row of group.rows) {
    const key = JSON.stringify([row.hostPattern, row.pathPattern, row.method]);
    if (seen.has(key)) continue;
    seen.add(key);
    targets.push({
      kind: "network",
      hostPattern: row.hostPattern,
      pathPattern: row.pathPattern,
      method: row.method,
    });
  }
  return {
    priority: 0, // assigned by translateOssProjectRules
    isDefault: false,
    source: "custom",
    name: mergedAppRuleName(
      group.provider,
      group.collapsed.action,
      group.collapsed.requireApproval,
    ),
    ...group.collapsed,
    conditions:
      first && Array.isArray(first.conditions) ? first.conditions : null,
    identities: first?.agentId ? [{ type: "agent", id: first.agentId }] : [],
    targets,
    enabled: true,
  };
};

/**
 * The ordered policy set of one project's legacy rows (customs +
 * app-permission-derived + enabled blocklist), priorities `0..n-1`.
 *
 * Enabled non-rate app-permission rows sharing an (agent, provider, action,
 * approval, conditions) signature collapse into one rule at the first member's
 * position; rate rows stay per-row so each keeps its own counter. Disabled
 * custom/app-permission rows are carried with `enabled: false`; disabled
 * blocklist rows are not derived at all — the old row stays the blocklist
 * panel's source of truth.
 */
export const translateOssProjectRules = (
  rows: OssOldRule[],
): BackfillRuleInput[] => {
  const eligible = rows.filter((r) => r.enabled || !isOssBlocklistRow(r));

  // Collapse before grouping, so a malformed row is dropped rather than
  // poisoning a group key.
  const toolGroups = new Map<string, OssToolGroup>();
  const groupKeyOfRow = new Map<OssOldRule, string>();
  for (const row of eligible) {
    if (isOssBlocklistRow(row) || !row.enabled) continue;
    const provider = ossAppToolProvider(row);
    if (provider === null) continue;
    const collapsedAction = collapseOssAction(row);
    if (!collapsedAction || collapsedAction.rateLimit !== null) continue;
    const key = stableJson([
      row.agentId,
      provider,
      collapsedAction.action,
      collapsedAction.requireApproval,
      Array.isArray(row.conditions) ? row.conditions : null,
    ]);
    groupKeyOfRow.set(row, key);
    const group = toolGroups.get(key);
    if (group) group.rows.push(row);
    else
      toolGroups.set(key, {
        provider,
        collapsed: collapsedAction,
        rows: [row],
      });
  }

  const emitted = new Set<string>();
  const translated: BackfillRuleInput[] = [];
  for (const row of eligible) {
    const key = groupKeyOfRow.get(row);
    const group = key === undefined ? undefined : toolGroups.get(key);
    if (key === undefined || !group || group.rows.length < 2) {
      const rule = translateOssRow(row);
      if (rule) translated.push(rule);
      continue;
    }
    if (emitted.has(key)) continue; // absorbed into the group's first slot
    emitted.add(key);
    translated.push(groupedOssRule(group));
  }

  const ordered = [...translated].sort(ossRuleOrderComparator);
  ordered.forEach((r, i) => {
    r.priority = i;
  });
  return ordered;
};

/** The enabled blocklist rows alone, unordered. */
export const translateOssBlocklistRows = (
  rows: OssOldRule[],
): BackfillRuleInput[] =>
  rows
    .filter((r) => r.enabled && isOssBlocklistRow(r))
    .map(translateOssRow)
    .filter((r): r is BackfillRuleInput => r !== null);

/** Stamped on every migrated/seeded Default Rule so the migration can tell its
 * own generations from a user publish that pre-empted it. */
export const OSS_MIGRATED_DEFAULT_DESCRIPTION =
  "Migrated from the legacy rules model";

/**
 * The per-project Default Rule, seeded from the org-row `policyMode`. Written
 * for every project, even rule-less ones: its presence in the published
 * generation is the gateway's per-project cutover signal.
 */
export const ossProjectDefaultRule = (
  policyMode: string,
): BackfillRuleInput => ({
  priority: 0, // assigned by the caller (last)
  isDefault: true,
  source: "default",
  name: "Default Rule",
  description: OSS_MIGRATED_DEFAULT_DESCRIPTION,
  action: policyMode === "deny" ? "block" : "allow",
  rateLimit: null,
  rateLimitWindow: null,
  requireApproval: false,
  conditions: null,
  identities: [],
  targets: [],
});

/** An equipment translation result: the rules, plus every `sessionPolicy` that
 * was dropped for the caller to report. */
export interface OssEquipmentTranslation {
  rules: BackfillRuleInput[];
  droppedSessionPolicies: { agentId: string; appConnectionId: string }[];
}

const equipmentRule = (
  agentId: string,
  target: BackfillTargetInput,
): BackfillRuleInput => ({
  // Assigned by the caller; equipment order is irrelevant to injection.
  priority: 0,
  isDefault: false,
  source: "equipment",
  name: "Equipment access",
  action: "allow",
  rateLimit: null,
  rateLimitWindow: null,
  requireApproval: false,
  conditions: null,
  identities: [{ type: "agent", id: agentId }],
  targets: [target],
});

/**
 * A selective agent's equipment → one `allow` rule per assigned secret and
 * connection (`source: "equipment"`, injection-only). All-mode agents get no
 * rules: `secretMode` stays the live all-vs-rules switch the gateway reads, and
 * an all-mode agent draws the whole fenced pool. Stored `sessionPolicy` values
 * are dropped and reported.
 */
export const translateOssEquipment = (
  agents: OssAgentEquipment[],
): OssEquipmentTranslation => {
  const rules: BackfillRuleInput[] = [];
  const droppedSessionPolicies: OssEquipmentTranslation["droppedSessionPolicies"] =
    [];
  for (const agent of agents) {
    if (agent.secretMode !== "selective") continue;
    for (const secretId of agent.secretIds) {
      rules.push(equipmentRule(agent.agentId, { kind: "secret", secretId }));
    }
    for (const c of agent.connections) {
      if (
        c.sessionPolicy &&
        typeof c.sessionPolicy === "object" &&
        Object.keys(c.sessionPolicy).length > 0
      ) {
        droppedSessionPolicies.push({
          agentId: agent.agentId,
          appConnectionId: c.appConnectionId,
        });
      }
      rules.push(
        equipmentRule(agent.agentId, {
          kind: "connection",
          connectionId: c.appConnectionId,
          tools: [],
        }),
      );
    }
  }
  return { rules, droppedSessionPolicies };
};

/** JSON with recursively-sorted object keys — `jsonb` does not round-trip key
 * order, so comparing raw `JSON.stringify` output would false-diverge. */
const stableJson = (value: unknown): string => {
  if (Array.isArray(value)) {
    return `[${value.map(stableJson).join(",")}]`;
  }
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([k, v]) => `${JSON.stringify(k)}:${stableJson(v)}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value) ?? "null";
};

const sortedJson = (values: unknown[]): string =>
  stableJson([...values.map(stableJson)].sort());

/**
 * Canonical form of one rule's decision-bearing fields for the boot verify —
 * order-insensitive on identities/targets, key-order-insensitive on JSON.
 */
export const ossCanonRule = (r: BackfillRuleInput): string =>
  stableJson({
    priority: r.priority,
    isDefault: r.isDefault,
    source: r.source,
    name: r.name,
    description: r.description ?? null,
    action: r.action,
    rateLimit: r.rateLimit,
    rateLimitWindow: r.rateLimitWindow,
    requireApproval: r.requireApproval,
    enabled: r.enabled ?? true,
    conditions: r.conditions ?? null,
    identities: sortedJson(r.identities),
    targets: sortedJson(r.targets),
  });
