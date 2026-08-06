import { asciiLower, hostMatches, pathMatches } from "./path-match";

// Overlap/shadow analysis for the manually-ordered first-match policy list.
// A warning is emitted only when the literal rule data proves the later rule can
// never take effect; undecidable comparisons are skipped, costing recall but
// never precision.

/** The structural slice the analysis reads — `PolicyRuleV2`/`PolicyRuleDto`
 * satisfy it as-is. */
export interface OverlapRule {
  logicalId: string;
  isDefault: boolean;
  enabled: boolean;
  priority: number;
  name: string;
  action: "allow" | "block";
  requireApproval: boolean;
  rateLimit: number | null;
  rateLimitWindow: string | null;
  identities: { type: string; id: string }[];
  targets: OverlapTarget[];
  conditions: unknown;
}

export type OverlapTarget =
  | {
      kind: "app";
      provider: string;
      tools: string[];
      connectionScope: string | null;
    }
  | { kind: "connection"; connectionId: string; tools: string[] }
  | { kind: "secret"; secretId: string | null; secretScope: string | null }
  | {
      kind: "network";
      hostPattern: string;
      pathPattern: string | null;
      method: string | null;
    };

export interface OverlapWarning {
  /** The rule that can never take effect. */
  logicalId: string;
  /**
   * duplicate — an identical earlier rule with the same verdict; conflict — an
   * identical earlier rule with a different verdict; shadowed — a broader
   * earlier rule matches everything this rule matches.
   */
  kind: "duplicate" | "conflict" | "shadowed";
  /** The earlier rule responsible. */
  byLogicalId: string;
  byName: string;
}

// ── Canonical signatures (duplicate detection) ──────────────────────────────

const identitySig = (r: OverlapRule): string =>
  r.identities
    .map((i) => `${i.type}:${i.id}`)
    .sort()
    .join(",");

const targetEntry = (t: OverlapTarget): string => {
  switch (t.kind) {
    case "app":
      return `app|${t.provider}|${[...t.tools].sort().join("+")}|${t.connectionScope ?? ""}`;
    case "connection":
      return `connection|${t.connectionId}|${[...t.tools].sort().join("+")}`;
    case "secret":
      return `secret|${t.secretId ?? ""}|${t.secretScope ?? ""}`;
    case "network":
      return `network|${t.hostPattern}|${t.pathPattern ?? ""}|${t.method ?? ""}`;
  }
};

const targetSig = (r: OverlapRule): string =>
  r.targets.map(targetEntry).sort().join(",");

/**
 * Canonical condition set. A non-array, or any element missing
 * target/operator/value strings, makes the whole conditions match
 * unconditionally (an empty set).
 */
const conditionSet = (conditions: unknown): Set<string> => {
  if (!Array.isArray(conditions)) return new Set();
  const entries: string[] = [];
  for (const c of conditions) {
    if (
      typeof c !== "object" ||
      c === null ||
      typeof (c as Record<string, unknown>).target !== "string" ||
      typeof (c as Record<string, unknown>).operator !== "string" ||
      typeof (c as Record<string, unknown>).value !== "string"
    ) {
      return new Set();
    }
    const e = c as { target: string; operator: string; value: string };
    entries.push(`${e.target}|${e.operator}|${e.value}`);
  }
  return new Set(entries);
};

const conditionSig = (r: OverlapRule): string =>
  [...conditionSet(r.conditions)].sort().join(",");

const matchSig = (r: OverlapRule): string =>
  `${identitySig(r)}\n${targetSig(r)}\n${conditionSig(r)}`;

const verdictSig = (r: OverlapRule): string =>
  `${r.action}|${r.requireApproval}|${r.rateLimit ?? ""}|${r.rateLimitWindow ?? ""}`;

// ── Sound cover rules (shadow detection) ────────────────────────────────────

/** A subset of AND-ed conditions matches a superset of requests — sound
 * without knowing what the entries mean. */
const conditionsCover = (r1: OverlapRule, r2: OverlapRule): boolean => {
  const c1 = conditionSet(r1.conditions);
  const c2 = conditionSet(r2.conditions);
  return [...c1].every((e) => c2.has(e));
};

const identitiesCover = (r1: OverlapRule, r2: OverlapRule): boolean => {
  if (r1.identities.length === 0) return true;
  if (r2.identities.length === 0) return false;
  const set1 = new Set(r1.identities.map((i) => `${i.type}:${i.id}`));
  return r2.identities.every((i) => set1.has(`${i.type}:${i.id}`));
};

/** Whether a target can match a request at all. Every kind currently can; kept
 * as a switch so a future inert kind has an obvious home. */
const isLive = (t: OverlapTarget): boolean => {
  switch (t.kind) {
    case "connection":
    case "app":
    case "secret":
    case "network":
      return true;
  }
};

/** Whether the rule drives credential injection at connect: an allow rule with
 * a connection target, a secret target, or an app target with a
 * `connectionScope`. Such a rule keeps effect even when its decision surface is
 * shadowed, so it is never reported as a shadow victim. */
const hasInjectionEffect = (r: OverlapRule): boolean =>
  r.action === "allow" &&
  r.targets.some(
    (t) =>
      t.kind === "connection" ||
      t.kind === "secret" ||
      (t.kind === "app" && t.connectionScope !== null),
  );

/** Targets that match with the rule's conditions ignored: whole-app and secret.
 * Connection is included conservatively — it is injection-bearing and so never
 * a shadow victim, making the inclusion inert. */
const ignoresConditions = (t: OverlapTarget): boolean =>
  (t.kind === "app" && t.tools.length === 0) ||
  t.kind === "secret" ||
  t.kind === "connection";

/** A network target that matches every request — host "*", any path, any
 * method. The one coverer that soundly covers app/secret targets too. */
const isUniversal = (t: OverlapTarget): boolean =>
  t.kind === "network" &&
  t.hostPattern === "*" &&
  (t.pathPattern === null || t.pathPattern === "*") &&
  t.method === null;

const hostCover = (pattern1: string, pattern2: string): boolean => {
  if (pattern1 === "*") return true;
  // ASCII fold like the real matcher; `toLowerCase` folds Unicode (K→k) and
  // would claim covers `hostMatches` does not deliver.
  if (asciiLower(pattern1) === asciiLower(pattern2)) return true;
  // A wildcard-free later host is a one-element set, so the real matcher decides
  // it. wildcard ⊇ wildcard is skipped as undecidable.
  return !pattern2.includes("*") && hostMatches(pattern2, pattern1);
};

const GIT_PUSH_SUFFIX = "/git-receive-pack";

const networkCover = (
  t1: {
    hostPattern: string;
    pathPattern: string | null;
    method: string | null;
  },
  t2: {
    hostPattern: string;
    pathPattern: string | null;
    method: string | null;
  },
): boolean => {
  if (!hostCover(t1.hostPattern, t2.hostPattern)) return false;

  const p1 = t1.pathPattern;
  const p2 = t2.pathPattern;
  // A git-receive-pack pattern also matches the GET info/refs push-discovery
  // request regardless of its own method, so only an any-path/any-method earlier
  // target, or the identical path, soundly covers it.
  if (p2 !== null && p2.endsWith(GIT_PUSH_SUFFIX)) {
    const universalPath = (p1 === null || p1 === "*") && t1.method === null;
    const samePath =
      p1 === p2 && (t1.method === null || methodEq(t1.method, t2.method));
    return universalPath || samePath;
  }

  const pathOk =
    p1 === null ||
    p1 === "*" ||
    (p2 !== null &&
      (p1 === p2 ||
        // A wildcard-free later path is a one-element set.
        (!p2.includes("*") &&
          !p1.endsWith(GIT_PUSH_SUFFIX) &&
          pathMatches(p2, p1))));
  if (!pathOk) return false;

  return t1.method === null || methodEq(t1.method, t2.method);
};

const methodEq = (m1: string, m2: string | null): boolean =>
  m2 !== null && asciiLower(m1) === asciiLower(m2);

/** Can earlier target t1 provably match every request the later target t2
 * matches? Sound comparisons only — anything else returns false. */
const targetCover = (t1: OverlapTarget, t2: OverlapTarget): boolean => {
  if (isUniversal(t1)) return true;
  if (t1.kind === "network" && t2.kind === "network") {
    return networkCover(t1, t2);
  }
  if (t1.kind === "app" && t2.kind === "app") {
    // A whole-app t1 (no tools) covers any same-provider t2; a tools-named t1
    // covers only a tools-subset t2. `connectionScope` is injection-only and
    // plays no part in coverage.
    return (
      t1.provider === t2.provider &&
      (t1.tools.length === 0 ||
        (t2.tools.length > 0 &&
          t2.tools.every((tool) => t1.tools.includes(tool))))
    );
  }
  // Cross-kind, secret hosts and connection targets are undecidable here.
  return false;
};

/** Does the earlier rule r1 provably match every request the later r2 matches
 * (r2 unreachable)? Requires identity + conditions + every live target cover. */
const ruleCovers = (r1: OverlapRule, r2: OverlapRule): boolean => {
  if (!identitiesCover(r1, r2)) return false;
  if (!conditionsCover(r1, r2)) return false;
  const liveTargets = r2.targets.filter(isLive);
  // A rule with no live targets matches nothing — a different phenomenon.
  if (liveTargets.length === 0) return false;
  // A whole-app/secret victim matches with its conditions ignored, so only an
  // unconditioned coverer can provably cover it.
  if (
    liveTargets.some(ignoresConditions) &&
    conditionSet(r1.conditions).size > 0
  ) {
    return false;
  }
  const coverers = r1.targets.filter(isLive);
  return liveTargets.every((t2) => coverers.some((t1) => targetCover(t1, t2)));
};

// ── The analysis ────────────────────────────────────────────────────────────

/**
 * Analyze one level's rules for provably-dead rules. Input order is irrelevant:
 * rules are re-sorted by priority like the evaluator's first-match walk.
 * Disabled rules and the Default Rule are excluded on both sides. At most one
 * warning per rule, most specific first: conflict > duplicate > shadowed.
 */
export const findPolicyOverlaps = (
  rules: readonly OverlapRule[],
): OverlapWarning[] => {
  const ordered = rules
    .filter((r) => r.enabled && !r.isDefault)
    .slice()
    .sort((a, b) => a.priority - b.priority);

  const warnings: OverlapWarning[] = [];
  const warned = new Set<string>();

  // Duplicates/conflicts: identical match signature, so the first occurrence
  // wins and every later twin is dead.
  const firstBySig = new Map<string, OverlapRule>();
  for (const r of ordered) {
    const sig = matchSig(r);
    const head = firstBySig.get(sig);
    if (!head) {
      firstBySig.set(sig, r);
      continue;
    }
    const kind = verdictSig(head) === verdictSig(r) ? "duplicate" : "conflict";
    // An opposite-action conflict on an injection-bearing allow twin is
    // suppressed: the block head injects nothing while the allow twin still
    // injects, so warning here would invite deleting a rule with live effect.
    if (
      kind === "conflict" &&
      head.action !== r.action &&
      hasInjectionEffect(r)
    ) {
      continue;
    }
    warnings.push({
      logicalId: r.logicalId,
      kind,
      byLogicalId: head.logicalId,
      byName: head.name,
    });
    warned.add(r.logicalId);
  }

  // Shadows: an earlier rule provably matches everything a later one matches.
  // Injection-bearing rules are exempt as victims (but still act as coverers).
  for (let i = 1; i < ordered.length; i++) {
    const r2 = ordered[i];
    if (!r2 || warned.has(r2.logicalId) || hasInjectionEffect(r2)) continue;
    for (let j = 0; j < i; j++) {
      const r1 = ordered[j];
      if (!r1) continue;
      if (ruleCovers(r1, r2)) {
        warnings.push({
          logicalId: r2.logicalId,
          kind: "shadowed",
          byLogicalId: r1.logicalId,
          byName: r1.name,
        });
        warned.add(r2.logicalId);
        break;
      }
    }
  }

  return warnings;
};
