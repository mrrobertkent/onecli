import { db } from "@onecli/db";
import { logger } from "../lib/logger";
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
import {
  readIdpGroups,
  resolveRoleFromGroups,
  revokeResolvedRole,
  writeResolvedRole,
} from "./role-resolution";
import type { SessionDenial, SessionUser } from "../providers/types";

/**
 * Resolves the IdP's groups to a role and persists it, once per session sync.
 * Reads the id_token from `auth_accounts` rather than the session cookie, which
 * cannot be refreshed.
 *
 * Must be idempotent and must not throw — a throw here becomes a 500 instead of
 * a denial. Denying an unmapped identity is the `SessionEnforcer`'s job.
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
    // No shared org yet: the caller's bootstrap runs after us, so there is
    // nothing to re-grade.
    if (!org) return;

    // Only identities that actually sign in through the directory are governed
    // by it. A password account has no id_token, and treating that absence as
    // "no groups" would suspend the bootstrap admin on their next login.
    const groups = await readIdpGroups(user.id);
    if (groups === null) return;

    const role = await resolveRoleFromGroups(org.id, groups);

    // The directory no longer grants this identity anything — removed from
    // every group, or the mapping was deleted. Access has to follow, or the
    // grant survives every revocation after the first login.
    if (!role) {
      const revoked = await revokeResolvedRole(org.id, user.id);
      if (revoked.changed) {
        await recordAuditEvent({
          organizationId: org.id,
          userId: user.id,
          userEmail: user.email,
          action: AUDIT_ACTIONS.DELETE,
          service: AUDIT_SERVICES.MEMBER,
          source: AUDIT_SOURCE.SSO_LOGIN,
          metadata: { from: revoked.from, groups },
        });
      }
      return;
    }

    const member = await db.organizationMember.findFirst({
      where: { organizationId: org.id, userId: user.id },
      select: { role: true },
    });

    // First login for a mapped identity: create the membership at the resolved
    // role. Leaving it to the caller's `joinSharedOrganization` would create it
    // at the floor role, delaying the IdP's groups until the second sync.
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

    const written = await writeResolvedRole(org.id, user.id, role);
    if (!written.changed) return;

    // `recordAuditEvent` rather than `withAudit`: the write has already
    // happened, and this one never throws, as the hook's contract requires.
    await recordAuditEvent({
      organizationId: org.id,
      userId: user.id,
      userEmail: user.email,
      action: AUDIT_ACTIONS.UPDATE,
      service: AUDIT_SERVICES.MEMBER,
      source: AUDIT_SOURCE.SSO_LOGIN,
      metadata: { from: written.from, to: role, groups },
    });
  } catch (err) {
    // Never rethrow — see the contract above.
    logger.error({ err, userId: user.id }, "session role resolution failed");
  }
};

/**
 * The OSS `SessionEnforcer`: admits an identity only if it holds an active
 * membership of the shared org. Runs after the role writer above and before
 * project resolution, on every authenticated session.
 *
 * Fail-closed — a database error denies. Returns a denial rather than throwing,
 * since a throw becomes a 500 that some clients retry.
 */
export const ossSessionEnforcer = async (
  _session: SessionUser,
  user: { id: string; email: string },
): Promise<SessionDenial | null> => {
  try {
    // Scoped to the shared org, not to any membership anywhere: a leftover
    // membership of some other organization is not a grant on this instance.
    const membership = await db.organizationMember.findFirst({
      where: {
        userId: user.id,
        organization: { slug: SHARED_ORG_SLUG },
        ...activeMembershipWhere,
      },
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
