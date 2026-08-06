"use client";

import { useQuery } from "@tanstack/react-query";
import { apiGet, queryKeys } from "@/lib/api";
import type { GrantResources } from "@/lib/api";

// Effective-access reflections read by the agent page and the
// connection/credential dialogs. Query keys spread the shared namespaces
// (`queryKeys.agents.all()` etc.) so broad invalidations still cover them.

export type EffectiveToolVerdict =
  | "allow"
  | "approval"
  | "block"
  | "mixed"
  | "unmanaged";

/** The deciding rule, trimmed for display — never the full targets/identities. */
export interface ProvenanceRuleRef {
  logicalId: string;
  name: string;
  source: string;
  action: "allow" | "block";
  requireApproval: boolean;
  rateLimit: number | null;
  rateLimitWindow: string | null;
}

export type EffectiveProvenance =
  | { kind: "rule"; scope: "organization"; redacted: true }
  | { kind: "rule"; scope: "organization" | "project"; rule: ProvenanceRuleRef }
  | { kind: "default"; scope: "organization" | "project" };

/** The ceiling a project can tighten under but never loosen past. Null = the
 * org is silent. */
export type OrgCeilingVerdict = "allow" | "approval" | "block";

export interface EffectiveToolResult {
  toolId: string;
  verdict: EffectiveToolVerdict;
  rateLimit: number | null;
  rateLimitWindow: string | null;
  decidedBy: EffectiveProvenance | null;
  orgCeiling: OrgCeilingVerdict | null;
}

export interface EffectiveToolGroupResult {
  category: "read" | "write";
  verdict: EffectiveToolVerdict;
  tools: EffectiveToolResult[];
}

export interface EffectiveAppPermissionsResult {
  provider: string;
  basis: {
    agentId: string | null;
    credentialAttached: boolean;
    scope: "organization" | "project";
  };
  /** Identity-scoped provider-relevant rules the agent-less baseline can't
   * show (viewer-scoped). */
  variesByIdentity: number;
  /** How far the org allows the credential to reach. Null = the org is silent
   * or no explicit (agent, connection) basis was given. */
  orgResources: GrantResources | null;
  /** The org boundary composed with the project's selection. An empty list =
   * the two don't overlap, so every request is refused. */
  effectiveResources: GrantResources | null;
  groups: EffectiveToolGroupResult[];
}

/**
 * Per-tool effective verdicts from the published rules. Omitting `agentId`
 * gives the agent-less baseline. Org-rule provenance arrives redacted for
 * non-org-admins. Project scope only.
 */
export const effectiveAppPermissions = (
  provider: string,
  opts: { agentId?: string; connectionId?: string } = {},
) => {
  const params = new URLSearchParams({ provider });
  if (opts.agentId) params.set("agentId", opts.agentId);
  // Reflects one account as the winning injected connection.
  if (opts.connectionId) params.set("connectionId", opts.connectionId);
  return apiGet<EffectiveAppPermissionsResult>(
    `/v1/policy/effective-app-permissions?${params}`,
  );
};

/** Per-tool effective verdicts. `agentId` null = the agent-less baseline. */
export const useEffectiveAppPermissions = (
  provider: string,
  agentId: string | null,
  enabled = true,
  /** Reflect one specific account; null = the provider view. */
  connectionId: string | null = null,
) =>
  useQuery({
    queryKey: [
      ...queryKeys.policy.all(),
      "effective-app-permissions",
      provider,
      agentId ?? "baseline",
      connectionId ?? "provider-level",
    ],
    queryFn: () =>
      effectiveAppPermissions(provider, {
        agentId: agentId ?? undefined,
        connectionId: connectionId ?? undefined,
      }),
    enabled: enabled && provider.length > 0,
  });

export type CredentialProvenance =
  | { kind: "rule"; scope: "organization"; redacted: true }
  | {
      kind: "rule";
      scope: "organization" | "project";
      rule: { logicalId: string; name: string };
    };

/** What a credential can actually do under the rules. */
export type CredentialAccessStatus =
  | "usable"
  | "limited"
  | "blocked"
  | "unknown";

export type EffectiveCredentialEntry =
  | {
      kind: "secret";
      id: string;
      name: string;
      host: string;
      status: CredentialAccessStatus;
      provenance: CredentialProvenance[];
    }
  | {
      kind: "connection";
      id: string;
      label: string | null;
      provider: string;
      status: CredentialAccessStatus;
      /** The org blocks every tool of this connection for this agent; a project
       * admin cannot lift it. */
      orgBlocked: boolean;
      provenance: CredentialProvenance[];
    };

export interface EffectiveCredentialsResult {
  agentId: string;
  /** Demoted to a footnote in the UI — never the headline. */
  mode: "all" | "selective";
  secrets: EffectiveCredentialEntry[];
  connections: EffectiveCredentialEntry[];
}

/** Which credentials can inject for this agent, under its published rule
 * grants. Org-rule provenance arrives redacted for non-org-admins. */
export const effectiveCredentials = (agentId: string) =>
  apiGet<EffectiveCredentialsResult>(
    `/v1/agents/${agentId}/effective-credentials`,
  );

/** Which credentials can inject for this agent. */
export const useEffectiveCredentials = (agentId: string, enabled = true) =>
  useQuery({
    queryKey: [...queryKeys.agents.all(), agentId, "effective-credentials"],
    queryFn: () => effectiveCredentials(agentId),
    enabled: enabled && agentId.length > 0,
  });

export type AgentCredentialStatus =
  | { status: "full" }
  | { status: "viaRule"; provenance: CredentialProvenance[] }
  | { status: "none" };

/** The effective-access headline for an agent on a connection. */
export type AgentAccessStatus =
  | "usable"
  | "limited"
  | "blocked"
  | "none"
  | "unknown";

export interface EffectiveAgentEntry {
  agentId: string;
  name: string;
  access: AgentAccessStatus;
  credential: AgentCredentialStatus;
  decisions: {
    allowedTools: number;
    totalTools: number;
    anyApproval: boolean;
    anyRateLimit: boolean;
  } | null;
}

export interface EffectiveAgentsResult {
  connectionId: string;
  provider: string;
  /** false = no permission catalog — the decisions axis is honestly absent. */
  catalog: boolean;
  agents: EffectiveAgentEntry[];
}

/** Per-agent credential status plus the per-tool decisions rollup, from the
 * published rules. Org-rule provenance arrives redacted for non-org-admins. */
export const effectiveAgents = (connectionId: string) =>
  apiGet<EffectiveAgentsResult>(
    `/v1/connections/${connectionId}/effective-agents`,
  );

/** Per-agent credential status plus the decisions rollup. */
export const useConnectionEffectiveAgents = (
  connectionId: string,
  enabled = true,
) =>
  useQuery({
    queryKey: [
      ...queryKeys.connections.all(),
      connectionId,
      "effective-agents",
    ],
    queryFn: () => effectiveAgents(connectionId),
    enabled: enabled && connectionId.length > 0,
  });
