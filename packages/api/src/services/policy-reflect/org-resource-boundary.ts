import type { SimRuleRow } from "../policy-simulate/load-rules";
import type { PrincipalSet } from "../policy-simulate/principal-set";
import {
  isSessionPolicy,
  type SessionPolicyInput,
} from "../../validations/policy";
import { injectionIdentityMatches } from "./injection";
import { intersectPolicies } from "../../lib/resource-axis";

/**
 * The decision engine's identity law, not the injection engine's: a rule naming
 * no identity bounds every agent. Granting a credential by omission would be a
 * leak, but restricting by omission can only tighten access.
 */
const boundaryIdentityMatches = (
  identities: SimRuleRow["identities"],
  agentId: string,
  principals: PrincipalSet,
): boolean =>
  identities.length === 0 ||
  identities.some((i) => {
    if (i.agentId != null) return i.agentId === agentId;
    if (i.userId != null) return principals.userIds.includes(i.userId);
    if (i.groupId != null) return principals.groupIds.includes(i.groupId);
    return false;
  });

/**
 * Fold one scope's published injection rules into the session policy they leave
 * on a connection. Last match wins within the scope; a non-object result means
 * no resource restriction.
 */
const foldSessionPolicy = (
  rows: SimRuleRow[],
  connectionId: string,
  identityMatches: (identities: SimRuleRow["identities"]) => boolean,
): SessionPolicyInput | null => {
  let policy: unknown = null;
  for (const row of rows) {
    if (row.isDefault || row.action !== "allow") continue;
    if (!identityMatches(row.identities)) continue;
    if (
      !row.targets.some(
        (t) => t.kind === "connection" && t.appConnectionId === connectionId,
      )
    ) {
      continue;
    }
    policy = row.conditions;
  }
  return isSessionPolicy(policy) ? policy : null;
};

/**
 * How far the org allows one (agent, connection)'s injected credential to
 * reach. Unlike a scope's own selection this is not last-match-wins: only rules
 * that actually restrict count, and several constraining rules compose by
 * intersection. Mirrors `collect_boundaries` in the gateway.
 */
export const orgResourceBoundary = (
  orgInjectionRows: SimRuleRow[],
  agentId: string,
  principals: PrincipalSet,
  connectionId: string,
): SessionPolicyInput | null => {
  let boundary: SessionPolicyInput | null = null;
  for (const row of orgInjectionRows) {
    if (row.isDefault || row.action !== "allow") continue;
    if (!boundaryIdentityMatches(row.identities, agentId, principals)) continue;
    if (!isSessionPolicy(row.conditions)) continue;
    if (
      !row.targets.some(
        (t) => t.kind === "connection" && t.appConnectionId === connectionId,
      )
    ) {
      continue;
    }
    boundary =
      boundary === null
        ? row.conditions
        : intersectPolicies(boundary, row.conditions);
  }
  return boundary;
};

/**
 * The project's own selection for one (agent, connection) — the grant stack's
 * session policy, under the injection engine's explicit-identity law.
 */
export const projectResourceSelection = (
  projectInjectionRows: SimRuleRow[],
  agentId: string,
  principals: PrincipalSet,
  connectionId: string,
): SessionPolicyInput | null =>
  foldSessionPolicy(projectInjectionRows, connectionId, (identities) =>
    injectionIdentityMatches(identities, agentId, principals),
  );
