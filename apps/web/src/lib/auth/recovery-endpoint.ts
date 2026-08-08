import { createHash } from "node:crypto";
import { z } from "zod";
import { APIError, createAuthEndpoint } from "better-auth/api";
import { setSessionCookie } from "better-auth/cookies";
import type { BetterAuthPlugin } from "better-auth";
import { db } from "@onecli/db";
import {
  recordAuditEvent,
  AUDIT_ACTIONS,
  AUDIT_SERVICES,
  AUDIT_SOURCE,
  AUDIT_STATUS,
} from "@onecli/api/services/audit-service";
import { enterRecoveryMode } from "@/lib/auth/login-policy";

/**
 * Redeeming a host-minted recovery key: a session and a recovery window, and
 * nothing else written.
 *
 * An auth endpoint rather than a server action because `setSessionCookie` needs
 * the endpoint context. The key check stays inside it so this is not a "mint a
 * session for this user id" route.
 */

/** Matches what the gateway's `create-recovery-key` stored. */
const hashKey = (key: string): string =>
  createHash("sha256").update(key).digest("hex");

/**
 * One message for every failure. The operator holding a good key never sees
 * these, and telling anyone else which of "wrong", "expired" and "already
 * spent" applies only helps someone who should not be here.
 */
export const RECOVERY_REFUSED =
  "That recovery link is not valid. Mint a new one on the host.";

const refused = () =>
  new APIError("UNAUTHORIZED", {
    message: RECOVERY_REFUSED,
    code: "RECOVERY_KEY_INVALID",
  });

export const recoveryKeyPlugin = () =>
  ({
    id: "onecli-recovery",
    endpoints: {
      redeemRecoveryKey: createAuthEndpoint(
        "/recovery/redeem",
        { method: "POST", body: z.object({ key: z.string().min(1) }) },
        async (ctx) => {
          const token = await db.recoveryToken.findUnique({
            where: { tokenHash: hashKey(ctx.body.key) },
            select: {
              id: true,
              expiresAt: true,
              usedAt: true,
              user: { select: { id: true, email: true } },
            },
          });

          if (!token || token.usedAt || token.expiresAt <= new Date()) {
            if (!token) {
              // `AuditLog.userId` is a required foreign key, so a key matching
              // no row cannot be audited. Logged instead — someone probing keys
              // should not be the one event that leaves no trace anywhere.
              console.warn(
                "[onecli] recovery key presented that matches no record",
              );
            } else {
              await recordAuditEvent({
                userId: token.user.id,
                userEmail: token.user.email,
                action: AUDIT_ACTIONS.RECOVER,
                service: AUDIT_SERVICES.AUTH,
                source: AUDIT_SOURCE.RECOVERY,
                status: AUDIT_STATUS.FAILURE,
                metadata: { reason: token.usedAt ? "already-used" : "expired" },
              });
            }
            throw refused();
          }

          // Conditional update, not a read-then-write: two redemptions racing
          // must not both pass the check above.
          const claimed = await db.recoveryToken.updateMany({
            where: { id: token.id, usedAt: null },
            data: { usedAt: new Date() },
          });
          if (claimed.count === 0) throw refused();

          const actor = { userId: token.user.id, userEmail: token.user.email };
          // Before the session: a window that failed to open would otherwise
          // leave the operator signed in with password login still off.
          const expiresAt = await enterRecoveryMode(actor);

          const user = await ctx.context.internalAdapter.findUserById(
            token.user.id,
          );
          if (!user) throw refused();

          const session = await ctx.context.internalAdapter.createSession(
            user.id,
          );
          await setSessionCookie(ctx, { session, user });

          await recordAuditEvent({
            userId: actor.userId,
            userEmail: actor.userEmail,
            action: AUDIT_ACTIONS.RECOVER,
            service: AUDIT_SERVICES.AUTH,
            source: AUDIT_SOURCE.RECOVERY,
            status: AUDIT_STATUS.SUCCESS,
            metadata: { recoveryTokenId: token.id },
          });

          return ctx.json({ recoveryModeExpiresAt: expiresAt.toISOString() });
        },
      ),
    },
  }) satisfies BetterAuthPlugin;
