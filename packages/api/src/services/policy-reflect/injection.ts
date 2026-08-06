import type { SimRuleRow } from "../policy-simulate/load-rules";
import type { PrincipalSet } from "../policy-simulate/principal-set";
import type { SecretHostSet } from "../policy-simulate/secret-hosts";
import { hostMatches } from "../../lib/path-match";
import { providerHostMatches } from "../policy-translation/translate/app-catalog";

// Mirror of the gateway's connect-time credential selection (`inject_select.rs`
// + `connect.rs`), so the reflections' "credential attached" and
// "hasInjections" signals agree with what the gateway would inject.

/**
 * Whether a rule's identities cover this agent for injection purposes.
 *
 * Unlike the block/allow engine, empty identities never match here — a
 * credential must not inject to every agent, and a deleted agent leaves rules
 * with cascaded-empty identities behind.
 */
export const injectionIdentityMatches = (
  identities: SimRuleRow["identities"],
  agentId: string,
  principals: PrincipalSet,
): boolean =>
  identities.length > 0 &&
  identities.some((i) => {
    if (i.agentId != null) return i.agentId === agentId;
    if (i.userId != null) return principals.userIds.includes(i.userId);
    if (i.groupId != null) return principals.groupIds.includes(i.groupId);
    // No principal — unreachable given the one_principal CHECK, and never
    // widened to "any".
    return false;
  });

/**
 * Which secrets a selective agent's published rules grant it: specific ids, plus
 * any whole-level grants. The id-level counterpart of `buildInjectionProbe`, for
 * callers needing the secrets themselves rather than a host predicate.
 *
 * Pure — the caller supplies already-fenced rules.
 */
export const grantedSecretSelection = (
  rules: SimRuleRow[],
  agentId: string,
  principals: PrincipalSet,
): { ids: string[]; levels: Set<"project" | "organization"> } => {
  const ids = new Set<string>();
  const levels = new Set<"project" | "organization">();
  for (const row of rules) {
    if (row.isDefault || row.action !== "allow") continue;
    if (!injectionIdentityMatches(row.identities, agentId, principals))
      continue;
    for (const t of row.targets) {
      if (t.kind !== "secret") continue;
      if (t.secretId) ids.add(t.secretId);
      else if (t.secretScope === "project") levels.add("project");
      else if (t.secretScope === "organization") levels.add("organization");
    }
  }
  return { ids: [...ids], levels };
};

/**
 * Build the host predicate for whether a credential would inject for an agent +
 * host (the deny-default carve's `hasInjections` input). The injectable set is
 * the pool credentials, plus — for an agent — the targets of its published
 * allow rules whose identity matches: a `secret` target's host, a `connection`
 * target's provider, and an `app` target's provider when it carries a
 * `connectionScope` (without one it is block/allow only, never injection).
 *
 * Resolved through the already-fenced `secretHosts` / `connectionProviders`
 * maps, so a foreign or deleted id contributes nothing.
 */
export const buildInjectionProbe = (params: {
  agent: { id: string } | null;
  poolSecretHostPatterns: string[];
  poolProviders: string[];
  rules: SimRuleRow[];
  principals: PrincipalSet;
  secretHosts: SecretHostSet;
  connectionProviders: Map<string, string>;
}): ((host: string) => boolean) => {
  const secretPatterns = [...params.poolSecretHostPatterns];
  const providers = new Set(params.poolProviders);

  if (params.agent) {
    const agentId = params.agent.id;
    for (const row of params.rules) {
      if (row.isDefault || row.action !== "allow") continue;
      if (!injectionIdentityMatches(row.identities, agentId, params.principals))
        continue;
      for (const t of row.targets) {
        if (t.kind === "secret") {
          if (t.secretId) {
            const host = params.secretHosts.byId.get(t.secretId);
            if (host !== undefined) secretPatterns.push(host);
          } else if (t.secretScope === "project") {
            secretPatterns.push(...params.secretHosts.projectHosts);
          } else if (t.secretScope === "organization") {
            secretPatterns.push(...params.secretHosts.orgHosts);
          }
        } else if (t.kind === "connection") {
          if (t.appConnectionId) {
            const provider = params.connectionProviders.get(t.appConnectionId);
            if (provider !== undefined) providers.add(provider);
          }
        } else if (t.kind === "app") {
          if (
            t.appProvider &&
            (t.appConnectionScope === "project" ||
              t.appConnectionScope === "organization")
          ) {
            // Folded without checking a live connection exists, so a scope
            // grant with no connections can over-report `hasInjections`. Errs
            // more restrictive, which is safe for a read-only reflection.
            providers.add(t.appProvider);
          }
        }
      }
    }
  }

  const providerList = [...providers];
  return (host: string) =>
    secretPatterns.some((p) => hostMatches(host, p)) ||
    providerList.some((p) => providerHostMatches(host, p));
};
