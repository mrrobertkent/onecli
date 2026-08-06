import { endpointMatches } from "./endpoint-match";
import { hostMatches } from "../../lib/path-match";
import { strictnessRank } from "./strictness";
import { appTargetMatches, providerHostMatches } from "./translate/app-catalog";
import type {
  Decision,
  NewRule,
  NewTarget,
  PolicyOutcome,
  PolicyRequest,
} from "./types";

// ── The first-match policy engine ───────────────────────────────────────────
// Two-level: per-scope first-match (org, then project), combined by strictest,
// with each level's Default Rule as its fallback verdict (deny wins).
//
// Two levels rather than one merged list because a single merged first-match
// can honor either "an agent rule loosens an all-agents rule" (identity beats
// strictness) or "an org rule is un-overridable" (strictness beats identity),
// not both.

const identityMatches = (rule: NewRule, request: PolicyRequest): boolean =>
  rule.identities.length === 0 ||
  rule.identities.some((i) => {
    switch (i.type) {
      case "agent":
        return i.id === request.agentId;
      case "user":
        return (request.userIds ?? []).includes(i.id);
      case "group":
        return (request.groupIds ?? []).includes(i.id);
    }
  });

const targetMatches = (
  target: NewTarget,
  rule: NewRule,
  request: PolicyRequest,
): boolean => {
  switch (target.kind) {
    case "network":
      return (
        hostMatches(request.host, target.hostPattern) &&
        endpointMatches(request, {
          pathPattern: target.pathPattern ?? "*",
          method: target.method,
          conditions: rule.conditions,
        })
      );
    case "app":
      // No tools means the whole app: host-only against every catalog tool host
      // of the provider, ignoring path/method/conditions. Named tools fan out
      // and honor them. `connectionScope` is injection-only either way.
      if (target.tools.length === 0) {
        return providerHostMatches(request.host, target.provider);
      }
      return appTargetMatches(
        request,
        target.provider,
        target.tools,
        rule.conditions,
      );
    case "connection": {
      // A resolved connection target binds to the account that won injection:
      // it matches only when the request's winning connection is this one and
      // the provider/tools fan-out hits. No winner, or a provider-less target
      // (deleted/foreign connection), never matches — fail-closed.
      const provider = target.provider;
      if (
        provider === undefined ||
        request.winningConnectionId === undefined ||
        request.winningConnectionId !== target.connectionId
      ) {
        return false;
      }
      if (target.tools.length === 0) {
        return providerHostMatches(request.host, provider);
      }
      return appTargetMatches(request, provider, target.tools, rule.conditions);
    }
    case "secret":
      // A secret gates its host, like an `app` target: host-only, mirroring the
      // connect-time injection filter. Empty patterns mean an unresolved or
      // deleted secret, which never matches.
      return target.hostPatterns.some((h) => hostMatches(request.host, h));
  }
};

// A non-default rule matches only when it names at least one target and one of
// them matches. Empty targets match nothing, which is also what neutralizes a
// rule whose sole connection/secret target was deleted. "Match everything" is
// the Default Rule or an explicit wildcard, never an empty target list.
const ruleMatches = (rule: NewRule, request: PolicyRequest): boolean =>
  identityMatches(rule, request) &&
  rule.targets.length > 0 &&
  rule.targets.some((t) => targetMatches(t, rule, request));

interface LevelMatch {
  rank: number;
  rule: NewRule;
}

/** First matching rule in priority order within one scope. */
const firstMatch = (
  rules: NewRule[],
  request: PolicyRequest,
): LevelMatch | null => {
  // Ties keep loader order, which is `ORDER BY priority, id` — the row id isn't
  // on NewRule, so that half of the ordering comes from the loaders.
  const ordered = [...rules].sort((a, b) => a.priority - b.priority);
  for (const rule of ordered) {
    if (ruleMatches(rule, request)) {
      return { rank: strictnessRank(rule), rule };
    }
  }
  return null;
};

const toDecision = (rule: NewRule): Decision => {
  if (rule.action === "block") return { action: "block" };
  if (rule.requireApproval) return { action: "allow", requireApproval: true };
  if (rule.rateLimit !== null && rule.rateLimitWindow !== null) {
    return {
      action: "allow",
      rateLimit: rule.rateLimit,
      rateLimitWindow: rule.rateLimitWindow,
    };
  }
  return { action: "allow" };
};

/**
 * Decide `request` against a translated rule set, attributed: the outcome names
 * the deciding rule (or Default Rule). `evaluateNew` collapses it to a bare
 * `Decision`.
 *
 * Each level's verdict is its first matching rule, else its Default Rule; the
 * stricter verdict wins. A level with no rules and no Default Rule contributes
 * nothing. Default-Block verdicts are gated by the `enforceDeny` carve;
 * explicit rule blocks are unconditional.
 */
export const evaluatePolicyOutcome = (
  rules: NewRule[],
  request: PolicyRequest,
): PolicyOutcome => {
  const orgDefault = rules.find(
    (r) => r.isDefault && r.scope === "organization",
  );
  const projectDefault = rules.find(
    (r) => r.isDefault && r.scope === "project",
  );
  const orgExplicit = rules.filter(
    (r) => !r.isDefault && r.scope === "organization",
  );
  const projectExplicit = rules.filter(
    (r) => !r.isDefault && r.scope === "project",
  );

  const orgMatch = firstMatch(orgExplicit, request);
  const projectMatch = firstMatch(projectExplicit, request);

  // A Default Rule Block is a hard floor at its level: neither level's default
  // block can be opened by the other level's allow.
  const enforceDeny = request.hasInjections && !request.isLlmHost;
  const orgDefaultBlocks = orgDefault?.action === "block" && enforceDeny;
  const projectDefaultBlocks =
    projectDefault?.action === "block" && enforceDeny;

  // A lone org allow can't punch through the project default block; drop it so
  // it falls through to the deny-default. An org block still applies. Approval
  // and rate rules have action "allow", so they defer too.
  const effectiveOrg =
    projectMatch === null &&
    orgMatch?.rule.action === "allow" &&
    projectDefaultBlocks
      ? null
      : orgMatch;

  // The mirror image: a lone project allow can't punch through the org default
  // block. An allow-posture org lets the project allow win.
  const effectiveProject =
    orgMatch === null &&
    projectMatch?.rule.action === "allow" &&
    orgDefaultBlocks
      ? null
      : projectMatch;

  // Strictest wins (lower rank = stricter); a tie keeps the org match, so an
  // org rate modifier beats a project one.
  const candidates = [effectiveOrg, effectiveProject].filter(
    (m): m is LevelMatch => m !== null,
  );
  if (candidates.length > 0) {
    const best = candidates.reduce((a, b) => (b.rank < a.rank ? b : a));
    return { kind: "rule", rule: best.rule };
  }

  // No explicit rule survived, so the level defaults decide; deny wins, and
  // attribution is org-first.
  if (orgDefaultBlocks) {
    return {
      kind: "denyDefault",
      level: "organization",
      rule: orgDefault ?? null,
    };
  }
  if (projectDefaultBlocks) {
    return {
      kind: "denyDefault",
      level: "project",
      rule: projectDefault ?? null,
    };
  }
  return { kind: "allow", managed: enforceDeny };
};

/** Collapse an attributed outcome to a bare `Decision`. */
export const outcomeToDecision = (outcome: PolicyOutcome): Decision => {
  switch (outcome.kind) {
    case "rule":
      return toDecision(outcome.rule);
    case "denyDefault":
      return { action: "block", byDefault: true };
    case "allow":
      return { action: "allow" };
  }
};

/**
 * Decide `request` against a translated rule set. A collapsing wrapper over
 * `evaluatePolicyOutcome`.
 */
export const evaluateNew = (
  rules: NewRule[],
  request: PolicyRequest,
): Decision => outcomeToDecision(evaluatePolicyOutcome(rules, request));
