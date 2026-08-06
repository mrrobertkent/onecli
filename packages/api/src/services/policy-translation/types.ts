// ── Policy shapes: the first-match engine's rule / request / decision types ──

export type RateWindow = "minute" | "hour" | "day";
export type Method = "GET" | "POST" | "PUT" | "PATCH" | "DELETE";

export interface OldCondition {
  target: string;
  operator: string;
  value: string;
  key?: string;
}

/** The request context the evaluator decides against. */
export interface PolicyRequest {
  host: string;
  path: string;
  method: string;
  /** Request body, for `body contains` conditions (cloud only). */
  body?: string;
  /** Which agent the request is from (identity + shadowing). */
  agentId: string;
  /**
   * The agent's resolved principal set: the users and directory groups its
   * project inherits via ProjectAccess. Empty for pure-agent traffic, where
   * only agent/"any" rules match.
   */
  userIds?: string[];
  groupIds?: string[];
  /** A credential was injected for this host — the deny-default precondition. */
  hasInjections: boolean;
  /** Host is a known LLM provider — bypasses deny-default. */
  isLlmHost: boolean;
  /**
   * The app connection that won injection for this request; absent when none
   * serves it. A resolved `connection` target matches only against this id.
   */
  winningConnectionId?: string;
}

/** The normalized decision an evaluation produces. */
export interface Decision {
  action: "allow" | "block";
  requireApproval?: boolean;
  rateLimit?: number;
  rateLimitWindow?: RateWindow;
  /** Blocked by deny-default (vs an explicit block rule). */
  byDefault?: boolean;
}

/**
 * The attributed result of an evaluation — which rule (or default) decided.
 * `evaluateNew` collapses this to a `Decision`; the reflections keep it to name
 * the deciding rule.
 */
export type PolicyOutcome =
  /** An explicit rule decided (its action/modifiers are the verdict). */
  | { kind: "rule"; rule: NewRule }
  /** A Default Rule's Block decided — org-first when both levels block. */
  | {
      kind: "denyDefault";
      level: "organization" | "project";
      rule: NewRule | null;
    }
  /** Nothing matched and no default blocks. `managed` = the deny-default carve
   * was armed (credential-managed, non-LLM) but every default allows. */
  | { kind: "allow"; managed: boolean };

// Internal new-model shapes for the evaluator. The user/group kinds are matched
// against the request's resolved principal set.
export type NewIdentity =
  | { type: "agent"; id: string }
  | { type: "user"; id: string }
  | { type: "group"; id: string };

/** Where a rule came from. `equipment` rules are the injection allowlist —
 * connection/secret-target allow rules. */
export type RuleSource =
  | "custom"
  | "app_permission"
  | "blocklist"
  | "default"
  | "equipment"
  // Grant stacks, compiled per (agent, credential) by the grants service; they
  // decide and inject like custom rules.
  | "grant";

// A `connection` target names a credential to inject and binds decisions to
// that account: it matches only when it is the request's winning injected
// connection and its provider/tools fan-out hits. Provider-less means
// unresolved (deleted or foreign) and never matches. `method` stays looser than
// the API's enum so an old row's method carries verbatim to the matcher.
export type NewTarget =
  | {
      kind: "network";
      hostPattern: string;
      pathPattern: string | null;
      method: string | null;
    }
  | {
      kind: "app";
      provider: string;
      // Named tools → the per-tool (host, path, method) fan-out; empty → the
      // whole app, host-only against every catalog tool host.
      tools: string[];
      // "All connections at a level" injection scope; null = no injection. The
      // evaluator ignores it — the level picks the pool, never the host set.
      connectionScope: "organization" | "project" | null;
    }
  | {
      kind: "connection";
      connectionId: string;
      /** The connection's provider; present iff resolved, absent means the
       * target never matches. */
      provider?: string;
      tools: string[];
    }
  // A secret target gates its resolved host pattern(s): a specific secret → its
  // one host, a level scope → the union. Empty = unresolved, never matches.
  | { kind: "secret"; hostPatterns: string[] };

/**
 * A `PolicyRuleV2` projected for the evaluator, with its identities and
 * targets. Empty identities mean "any", but a non-default rule with empty
 * targets matches nothing. `isDefault` marks the posture rule — the only
 * target-less match-all.
 */
export interface NewRule {
  scope: "organization" | "project";
  priority: number;
  isDefault: boolean;
  source: RuleSource;
  name: string;
  identities: NewIdentity[];
  targets: NewTarget[];
  action: "allow" | "block";
  requireApproval: boolean;
  rateLimit: number | null;
  rateLimitWindow: RateWindow | null;
  conditions: OldCondition[] | null;
}
