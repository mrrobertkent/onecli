import type { CryptoService } from "../lib/crypto-types";
import type { AppDefinition } from "../apps/types";
import type { ResolvedAppCredentials } from "../apps/resolve-credentials";

export type OrgRole = "owner" | "admin" | "member";

export const ROLE_HIERARCHY: Record<OrgRole, number> = {
  owner: 3,
  admin: 2,
  member: 1,
};

/**
 * How the caller authenticated. A `project` key is bound to a single project and
 * is confined to it on project-management routes; `organization` keys and user
 * `session`s carry the user's full org-wide authority. Set by the auth middleware.
 */
export type AuthScope = "project" | "organization" | "session";

export interface AuthContext {
  userId: string;
  userEmail: string;
  projectId?: string;
  organizationId: string;
  role?: OrgRole;
  scope?: AuthScope;
}

export interface SessionUser {
  id: string;
  email: string;
  name?: string;
  /**
   * Whether the auth provider proved ownership of `email` (e.g. a verified
   * email claim). Optional — providers that don't know leave it unset.
   */
  emailVerified?: boolean;
  /**
   * Federated IdP name for this session (e.g. "Google"); null/unset for
   * native sign-ins or providers that don't distinguish.
   */
  federatedProvider?: string | null;
  /**
   * Every federated IdP name attached to this session's identity, in token
   * order; `federatedProvider` only sees the first. Consumers deciding on
   * identity trust should scan this array. Empty/unset for native sign-ins.
   */
  identityProviders?: string[];
}

export interface SessionProvider {
  getSession(request: Request): Promise<SessionUser | null>;
}

export interface RoleResolver {
  getUserRole(userId: string, organizationId: string): Promise<OrgRole | null>;
}

/** An explicit session rejection: the message shown to the user + a stable code. */
export interface SessionDenial {
  error: string;
  code: string;
}

/**
 * Edition policy applied to every authenticated session at resolution time
 * (e.g. enterprise "require SSO"). Runs after the user upsert and JIT
 * membership; returning a denial rejects the session with a 401.
 */
export type SessionEnforcer = (
  session: SessionUser,
  user: { id: string; email: string },
) => Promise<SessionDenial | null>;

export interface OAuthOrgHandlers {
  tryHandleOrgAuthorize: (
    auth: AuthContext,
    c: import("hono").Context,
    provider: string,
  ) => Promise<Response | null>;
  tryHandleOrgCallback: (
    request: Request,
    provider: string,
  ) => Promise<Response | null>;
  tryHandleOrgConnect: (
    auth: AuthContext,
    request: Request,
    provider: string,
    credentials: Record<string, unknown>,
    options?: {
      scopes?: string[];
      metadata?: Record<string, unknown>;
      label?: string;
    },
    connectionId?: string,
    fields?: Record<string, string>,
  ) => Promise<Response | null>;
}

/**
 * Org-level app-config reads backing the project → org → env credential
 * fallback. EE-only: OSS registers no provider, so the org tier is skipped.
 */
export interface OrgAppConfigProvider {
  /** Org-row-or-env credential resolution (mirrors the project resolver). */
  resolveCredentials(
    organizationId: string,
    app: AppDefinition,
  ): Promise<ResolvedAppCredentials | null>;
  /** The org's enabled config for one provider, if any. */
  getEnabledConfig(
    organizationId: string,
    provider: string,
  ): Promise<{ hasCredentials: boolean } | null>;
  /** All enabled org configs, keyed by provider. */
  listEnabledConfigs(
    organizationId: string,
  ): Promise<Record<string, { hasCredentials: boolean }>>;
}

/**
 * App-availability reads backing the connect-picker filter, mirroring the
 * gateway's runtime availability check. EE-only: OSS registers no provider, so
 * every app is available.
 */
export interface AppAvailabilityProvider {
  /**
   * The app-provider ids available to a project, or `null` when availability is
   * unrestricted (the org is in "open" mode) — the caller then treats every app
   * as available. Scoped to the acting org; never leaks other orgs' grants.
   */
  getAvailableProviders(
    projectId: string,
    organizationId: string,
  ): Promise<string[] | null>;
}

export type { CryptoService, AppDefinition };
