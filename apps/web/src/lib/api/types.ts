export interface Agent {
  id: string;
  name: string;
  identifier: string;
  accessToken: string;
  isDefault: boolean;
  /** The all-vs-selective injection switch the gateway reads per request. Read
   * only from the console — policy rules decide access. */
  secretMode: string;
  createdAt: string;
  /** Newest gateway request inside the list's bounded lookback window; null =
   * none in-window. `agentLastSeen` distinguishes never-used from quiet. */
  lastSeenAt: string | null;
}

export interface CreatedAgent {
  id: string;
  name: string;
  identifier: string;
  createdAt: string;
}

export interface AgentDetail {
  id: string;
  name: string;
  identifier: string;
  isDefault: boolean;
  createdAt: string;
  /** Newest gateway request inside the server's bounded lookback window — the
   * Install page's verify signal. Null when the agent has none in-window. */
  recentRequestAt: string | null;
}

export interface DropboxFolder {
  id: string;
  name: string;
  pathLower: string;
  pathDisplay: string;
}

export interface Secret {
  id: string;
  name: string;
  type: string;
  typeLabel: string;
  valueSource: string;
  opRef: string | null;
  hostPattern: string;
  pathPattern: string | null;
  injectionConfig: unknown;
  metadata: Record<string, unknown> | null;
  scope: string | null;
  createdAt: string;
}

export interface CreatedSecret {
  id: string;
  name: string;
  type: string;
  hostPattern: string;
  pathPattern: string | null;
  createdAt: string;
  preview: string;
}

export interface Connection {
  id: string;
  provider: string;
  label: string | null;
  status: string;
  scopes: string[];
  scope: string | null;
  metadata: unknown;
  connectedAt: string;
}

// A project row as returned by the project CRUD routes (rename / create).
export interface Project {
  id: string;
  name: string | null;
  slug: string | null;
  createdAt: string;
}

// Project access bindings. `role` is the management role: "owner" may manage
// the project, "member" is a plain use grant. `isOwner` flags the creator — a
// display hint, distinct from the transferable management role.
export interface ProjectAccessUserRow {
  id: string;
  userId: string;
  name: string | null;
  email: string;
  role: "owner" | "member";
  isOwner: boolean;
  createdAt: string;
}

export interface ProjectAccessGroupRow {
  id: string;
  groupId: string;
  name: string;
  memberCount: number;
  createdAt: string;
}

export interface ProjectAccessBindings {
  users: ProjectAccessUserRow[];
  groups: ProjectAccessGroupRow[];
}

// The shares to keep. Groups carry no role.
export interface SetProjectAccessInput {
  users: { userId: string; role: "owner" | "member" }[];
  groupIds: string[];
}

export type SsoConnectionStatus = "pending" | "active" | "disabled";

// An org's SSO/IdP connection — the redacted API shape (the OIDC client
// secret never leaves the server).
export interface OrgSsoConnection {
  id: string;
  type: "saml" | "oidc";
  status: SsoConnectionStatus;
  displayName: string;
  cognitoProviderName: string;
  config: {
    metadataUrl?: string;
    metadataXml?: string;
    issuer?: string;
    clientId?: string;
    certExpiresAt?: string | null;
  };
  createdAt: string;
  updatedAt: string;
}

export interface SsoTestCheck {
  name: string;
  ok: boolean;
  detail?: string;
}

export interface SsoTestResult {
  ok: boolean;
  checks: SsoTestCheck[];
}

export interface CreateSsoConnectionInput {
  type: "saml" | "oidc";
  displayName: string;
  metadataUrl?: string;
  metadataXml?: string;
  issuer?: string;
  clientId?: string;
  clientSecret?: string;
}

export interface UpdateSsoConnectionInput {
  displayName?: string;
  enabled?: boolean;
  metadataUrl?: string;
  metadataXml?: string;
  issuer?: string;
  clientId?: string;
  clientSecret?: string;
}

// An org's claimed email domain. `verifiedAt` null = pending the DNS TXT
// check; the token is published in DNS, so it's safe to expose here.
export interface OrgDomain {
  id: string;
  domain: string;
  verificationToken: string;
  verifiedAt: string | null;
  createdAt: string;
}

// A bearer token for the org's /scim/v2 provisioning endpoint. Reads only
// ever carry metadata — the plaintext exists solely in the create response.
export interface ScimToken {
  id: string;
  label: string;
  lastUsedAt: string | null;
  createdAt: string;
}

// POST /v1/org/scim/tokens — `token` is shown once and never retrievable.
export interface CreatedScimToken extends ScimToken {
  token: string;
}

// Require-SSO enforcement state (GET/PATCH /v1/org/sso/enforcement).
export interface OrgSsoEnforcement {
  ssoRequired: boolean;
  hasActiveConnection: boolean;
  hasVerifiedDomain: boolean;
  canRequire: boolean;
  exemptMemberCount: number;
}

// PATCH /v1/org/members/:userId — exactly one change per request. `owner` is
// not assignable: it is the one role the directory cannot confer, and the one
// that may edit the group→role mappings.
export type UpdateOrgMemberInput =
  | { status: "active" | "suspended" }
  | { ssoExempt: boolean }
  | { role: "admin" | "member" };

export interface OrgMemberRow {
  userId: string;
  role: string;
  status: string;
  ssoExempt: boolean;
  /** Sessions ended by this change — non-zero only on a suspension. */
  sessionsRevoked: number;
}

export interface ResourceCounts {
  agents: number;
  apps: number;
  llms: number;
  secrets: number;
}

export interface CreateAgentInput {
  name: string;
  identifier: string;
}

export interface CreateSecretInput {
  name: string;
  type: string;
  value?: string;
  valueSource?: "inline" | "onepassword";
  opRef?: string;
  opDisplay?: { vault: string; item: string; field: string };
  hostPattern: string;
  pathPattern?: string;
  injectionConfig?: unknown;
}

// ── Org directory (groups, members) ──

/** Cursor envelope shared by every directory-scale list. */
export interface DirectoryPage<T> {
  data: T[];
  nextCursor: string | null;
}

export interface DirectoryListParams {
  limit?: number;
  cursor?: string;
  q?: string;
}

export interface GroupRow {
  id: string;
  name: string;
  /** "scim" groups are IdP-managed — manual writes 409. */
  source: "manual" | "scim";
  externalId: string | null;
  /** "all-users" resolves to every current and future member of the org. */
  membershipMode: "explicit" | "all-users";
  /** "all-projects" reaches every current and future project in the org. */
  projectAccessMode: "selected" | "all-projects";
  memberCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface UpdateGroupInput {
  name?: string;
  membershipMode?: "explicit" | "all-users";
  projectAccessMode?: "selected" | "all-projects";
}

export interface GroupMemberRow {
  userId: string;
  email: string;
  name: string | null;
  addedAt: string;
}

// Maps an IdP group to an org role, priority-ordered.
export interface RoleMappingRow {
  id: string;
  groupId: string;
  groupName: string;
  role: "admin" | "member";
  priority: number;
  memberCount: number;
  createdAt: string;
  updatedAt: string;
}

export interface CreateRoleMappingInput {
  groupId: string;
  role: "admin" | "member";
  priority?: number;
}

export interface UpdateRoleMappingInput {
  role: "admin" | "member";
  priority?: number;
}

export interface RoleMappingImpact {
  affectedCount: number;
}

export interface OrgMemberListRow {
  userId: string;
  email: string;
  name: string | null;
  role: string;
  status: string;
  ssoExempt: boolean;
  joinedAt: string;
}

// ── Shared policy identity/condition shapes ──────────────────────────────────
// Project rules target a specific agent or "any" (empty); org rules target
// directory identities. Conditions are body-contains.

export type ProjectionIdentity =
  | { type: "agent"; id: string }
  | { type: "user"; id: string }
  | { type: "group"; id: string };

export interface ProjectionCondition {
  target: string;
  operator: string;
  value: string;
}

// ── Editable policy rules (policy_rules_v2) ──────────────────────────────────
// GET /rules → PolicyRuleDto. Rows carry an `id` for PATCH/DELETE and are
// single-scope.
export type PolicyRuleTarget =
  | {
      kind: "app";
      provider: string;
      // Named tools → the exact tool fan-out; empty → the whole app.
      tools: string[];
      // Injection-only, never affects matching; null = no injection.
      connectionScope: "organization" | "project" | null;
    }
  // Injects the connection and matches its provider's app, narrowed to `tools`
  // when set.
  | { kind: "connection"; connectionId: string; tools: string[] }
  | {
      kind: "secret";
      // Exactly one of these is set.
      secretId: string | null;
      secretScope: "organization" | "project" | null;
    }
  | {
      kind: "network";
      hostPattern: string;
      pathPattern: string | null;
      method: string | null;
    };

export type PolicyRuleSource =
  | "custom"
  | "app_permission"
  | "blocklist"
  | "default"
  // Injection-only rules materialized from the equipment model; the editor
  // hides them, since they are managed via the agent access UI.
  | "equipment"
  // Compiled by the grants API; rendered as labeled, revocable derived rows.
  | "grant";

export interface PolicyRuleV2 {
  id: string;
  scope: "organization" | "project";
  status: "draft" | "published";
  generation: number;
  priority: number;
  enabled: boolean;
  isDefault: boolean;
  /** Generation-stable identity — the key for diffing draft vs published
   * (the row `id` regenerates on every publish). Empty on a virtual default. */
  logicalId: string;
  source: PolicyRuleSource;
  name: string;
  description: string | null;
  action: "allow" | "block";
  rateLimit: number | null;
  rateLimitWindow: "minute" | "hour" | "day" | null;
  requireApproval: boolean;
  conditions: ProjectionCondition[] | null;
  identities: ProjectionIdentity[];
  targets: PolicyRuleTarget[];
  createdAt: string;
}

export interface PublishResult {
  generation: number;
  ruleCount: number;
}

/** The scope's most recent publish. `appliedBy` null = a system publish (the
 * boot seeder); a null response = never published. */
export interface LastPublish {
  generation: number;
  ruleCount: number;
  appliedAt: string;
  appliedBy: { name: string | null; email: string } | null;
}

// ── Attach-model grants ──────────────────────────────────────────────────────
// Hand-mirrored from packages/api/src/services/grants-service.ts and
// grants-summary-service.ts.

/** A grant's session policy: which repositories/folders the connection's
 * injected credential may reach. One axis per provider. */
export type GrantResources = { repositories: string[] } | { folders: string[] };

export interface AgentGrantConnection {
  connectionId: string;
  provider: string;
  label: string | null;
  scope: "project" | "organization";
  access: "full" | "custom";
  allow: string[];
  ask: string[];
  /** Null = unrestricted. */
  resources: GrantResources | null;
}

export interface AgentGrantSecret {
  secretId: string;
  name: string;
  type: string;
  scope: "project" | "organization";
}

export interface AgentGrants {
  agentId: string;
  /** "all" = the agent injects the whole fenced pool. */
  mode: "all" | "grants";
  connections: AgentGrantConnection[];
  secrets: AgentGrantSecret[];
}

export interface ConnectionGrants {
  connectionId: string;
  agents: {
    agentId: string;
    access: "full" | "custom";
    allow: string[];
    ask: string[];
  }[];
}

/** `resources` is tri-state: absent = preserve what the stack carries, null =
 * clear, object = set. */
export type ConnectionGrantInput =
  | { access: "full"; resources?: GrantResources | null }
  | {
      access: "custom";
      allow: string[];
      ask: string[];
      resources?: GrantResources | null;
    };

export type GrantsSummaryEntry =
  | {
      kind: "app";
      provider: string;
      connectionId: string;
      label: string | null;
    }
  | { kind: "secret" | "llm"; id: string; name: string };

export interface AgentGrantsSummary {
  mode: "all" | "grants";
  entries: GrantsSummaryEntry[];
  total: number;
}

export interface AgentWithGrantsSummary extends Agent {
  grantsSummary: AgentGrantsSummary;
}
