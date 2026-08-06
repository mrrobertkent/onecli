import { asciiLower, pathMatches } from "../../lib/path-match";
import type { OldCondition, PolicyRequest } from "./types";

// The request-level matcher shared by the oracle and the new evaluator, so the
// golden corpus tests the translation rather than the matcher (whose fidelity to
// the gateway is proven in path-match.test.ts). Host matching is the caller's
// job (hostMatches); this covers path, method, conditions and git discovery.

/**
 * Port of `apps/gateway/src/ee/condition_match.rs::matches`. Absent/empty
 * conditions match; each condition is AND-ed; only `(body, contains)` is
 * meaningful (case-insensitive substring, empty/absent body → false); any other
 * target/operator matches.
 *
 * Caller contract: malformed raw `conditions` must be coerced to `null` (→
 * match) as a whole, never cleaned up element by element, or it diverges from
 * the gateway's all-or-nothing `parse_conditions`. Absent body maps to
 * `undefined`, empty body to `""`.
 */
export const conditionsMatch = (
  conditions: OldCondition[] | null | undefined,
  body: string | undefined,
): boolean => {
  if (!conditions || conditions.length === 0) return true;
  return conditions.every((c) => conditionMatches(c, body));
};

const conditionMatches = (
  c: OldCondition,
  body: string | undefined,
): boolean => {
  if (c.target === "body" && c.operator === "contains") {
    if (body === undefined) return false;
    // ASCII fold to match Rust's to_ascii_lowercase (a non-ASCII condition value
    // must not fold under JS's Unicode toLowerCase).
    return asciiLower(body).includes(asciiLower(c.value));
  }
  return true;
};

// Port of `policy.rs::is_git_push_discovery` — `/info/refs?service=git-receive-pack`.
const isGitPushDiscovery = (path: string): boolean => {
  const qIdx = path.indexOf("?");
  const base = qIdx === -1 ? path : path.slice(0, qIdx);
  const query = qIdx === -1 ? "" : path.slice(qIdx + 1);
  return (
    base.endsWith("/info/refs") &&
    query.split("&").some((p) => p === "service=git-receive-pack")
  );
};

export interface EndpointPattern {
  pathPattern: string;
  method: string | null;
  conditions: OldCondition[] | null;
}

/**
 * Port of `policy.rs::matches_request` (host excluded — matched by the caller).
 * A rule blocking `POST …/git-receive-pack` also matches the preceding
 * `GET …/info/refs?service=git-receive-pack` push-discovery request.
 */
export const endpointMatches = (
  request: PolicyRequest,
  pattern: EndpointPattern,
): boolean => {
  const direct =
    pathMatches(request.path, pattern.pathPattern) &&
    (pattern.method === null ||
      asciiLower(pattern.method) === asciiLower(request.method)) &&
    conditionsMatch(pattern.conditions, request.body);
  if (direct) return true;

  if (
    pattern.pathPattern.endsWith("/git-receive-pack") &&
    asciiLower(request.method) === "get" &&
    isGitPushDiscovery(request.path)
  ) {
    return conditionsMatch(pattern.conditions, request.body);
  }
  return false;
};
