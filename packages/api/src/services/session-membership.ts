import { db } from "@onecli/db";
import { logger } from "../lib/logger";
import { OIDC_GROUPS_CLAIM_PATH } from "../lib/env";
import {
  AUDIT_ACTIONS,
  AUDIT_SERVICES,
  AUDIT_SOURCE,
  recordAuditEvent,
} from "./audit-service";
import {
  activeMembershipWhere,
  ensureSharedOrgMembership,
  SHARED_ORG_SLUG,
} from "./organization-service";
import { readClaimPath, resolveRoleFromGroups } from "./role-resolution";
import type { SessionDenial, SessionUser } from "../providers/types";

/**
 * The login-time role writer (design D-3), registered on the sanctioned
 * `ensureSessionMembership` hook.
 *
 * D-3 forbids a group-aware `RoleResolver`: authorization reads a PERSISTED
 * role, and the IdP's groups are consulted here instead, once per session sync.
 * That is also what upstream's enterprise edition does — resolve at SSO login
 * and materialise the result (`AUDIT_SOURCE.SSO_LOGIN`).
 *
 * WHERE THE CLAIM COMES FROM: not the session cookie. Better Auth persists the
 * OIDC `id_token` on `auth_accounts` at login, so the groups are read from our
 * own database rather than carried in a cookie that cannot be refreshed
 * (NFR-3). The token is not re-verified here — Better Auth verified it against
 * the provider's JWKS before storing it, and re-verifying a row we wrote
 * ourselves would only add a network call to the login path.
 *
 * CONTRACT: this hook must be idempotent and MUST NOT THROW. Membership is
 * best-effort; session resolution is not. Denying an unmapped identity is the
 * `SessionEnforcer`'s job, not this one's — a throw here would surface as a 500
 * rather than a denial.
 */
export const ossSessionMembership = async (
  _session: SessionUser,
  user: { id: string; email: string; name: string | null },
): Promise<void> => {
  try {
    const org = await db.organization.findUnique({
      where: { slug: SHARED_ORG_SLUG },
      select: { id: true },
    });
    // No shared org yet means this is the first login, and the caller's
    // bootstrap runs after us. Nothing to re-grade.
    if (!org) return;

    const groups = await readIdpGroups(user.id);
    if (groups.length === 0) return;

    const role = await resolveRoleFromGroups(org.id, groups);
    // Null means no group mapped. Deliberately NOT treated as "member": under
    // US-4 an unmapped identity is not admitted at all, and that decision
    // belongs to the enforcer. Silently downgrading here would admit them.
    if (!role) return;

    const member = await db.organizationMember.findFirst({
      where: { organizationId: org.id, userId: user.id },
      select: { role: true },
    });

    // First login for a mapped identity: CREATE the membership here, at the
    // resolved role. Returning early instead would let the caller's
    // `joinSharedOrganization` create it at its floor role, and the IdP's
    // groups would not take effect until the second sync. Creating it here is
    // also what lets the enforcer below treat "no membership" as "not
    // authorised" without denying every legitimate first login.
    if (!member) {
      await ensureSharedOrgMembership(user.id, user.email, role);
      await recordAuditEvent({
        organizationId: org.id,
        userId: user.id,
        userEmail: user.email,
        action: AUDIT_ACTIONS.CREATE,
        service: AUDIT_SERVICES.MEMBER,
        source: AUDIT_SOURCE.SSO_LOGIN,
        metadata: { to: role, groups },
      });
      return;
    }

    if (member.role === "owner" || member.role === role) return;

    await db.organizationMember.update({
      where: {
        organizationId_userId: { organizationId: org.id, userId: user.id },
      },
      data: { role },
    });

    // `recordAuditEvent`, not `withAudit`: the change is conditional (most
    // syncs are a no-op) and has already happened by here. It never throws,
    // which this hook's contract requires.
    await recordAuditEvent({
      organizationId: org.id,
      userId: user.id,
      userEmail: user.email,
      action: AUDIT_ACTIONS.UPDATE,
      service: AUDIT_SERVICES.MEMBER,
      source: AUDIT_SOURCE.SSO_LOGIN,
      metadata: { from: member.role, to: role, groups },
    });
  } catch (err) {
    // Never rethrow: see the contract above.
    logger.error({ err, userId: user.id }, "session role resolution failed");
  }
};

/**
 * Group names from the most recent OIDC `id_token` this user signed in with.
 *
 * Read by PATH, not by name (D-4): Authentik and Okta emit a flat `groups`,
 * Keycloak keeps roles at `realm_access.roles`, and a configuration storing a
 * claim NAME cannot express the second.
 */
const readIdpGroups = async (userId: string): Promise<string[]> => {
  const account = await db.authAccount.findFirst({
    where: { userId, idToken: { not: null } },
    select: { idToken: true },
    orderBy: { updatedAt: "desc" },
  });
  if (!account?.idToken) return [];

  const claims = decodeJwtPayload(account.idToken);
  if (!claims) return [];
  return readClaimPath(claims, OIDC_GROUPS_CLAIM_PATH);
};

/**
 * Decode a JWT payload WITHOUT verifying it. Safe only because the caller reads
 * a token Better Auth already verified against the provider's JWKS before
 * persisting it. Never use this on a token that arrived in a request.
 */
const decodeJwtPayload = (token: string): Record<string, unknown> | null => {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const json = Buffer.from(payload, "base64url").toString("utf8");
    const parsed: unknown = JSON.parse(json);
    if (typeof parsed !== "object" || parsed === null) return null;
    return parsed as Record<string, unknown>;
  } catch {
    return null;
  }
};

/**
 * The OSS `SessionEnforcer` — the server-side half of US-1's gate.
 *
 * Runs on EVERY authenticated session, after the role writer above and before
 * any project resolution, so it cannot be skipped by a client that goes
 * straight to a `/v1/*` route: no session resolves without passing here.
 *
 * The rule is simply "does this identity hold an active membership of the
 * shared organization". The writer above creates one for any identity whose
 * IdP groups map to a role, so the two together mean: authenticate at the IdP
 * AND map to a role, or you are not admitted (US-4). Authenticating alone is
 * not sufficient, which was the whole problem this spec started from.
 *
 * FAIL-CLOSED. A database error denies rather than admits — US-1's
 * "misconfiguration denies; it does not admit". That is also why this returns a
 * denial instead of throwing: a throw lands in the route's catch as a 500,
 * which some clients treat as retryable.
 */
export const ossSessionEnforcer = async (
  _session: SessionUser,
  user: { id: string; email: string },
): Promise<SessionDenial | null> => {
  try {
    const membership = await db.organizationMember.findFirst({
      where: { userId: user.id, ...activeMembershipWhere },
      select: { role: true },
    });
    if (membership) return null;

    logger.warn(
      { userId: user.id },
      "session denied: no active membership resolved",
    );
    return {
      error:
        "Your account is not authorised for this instance. Ask an administrator to grant you access.",
      code: "NOT_AUTHORISED",
    };
  } catch (err) {
    logger.error({ err, userId: user.id }, "membership check failed; denying");
    return {
      error:
        "Access could not be verified. Try again, or contact an administrator.",
      code: "AUTHORISATION_UNAVAILABLE",
    };
  }
};
