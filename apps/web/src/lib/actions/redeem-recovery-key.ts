"use server";

import "@/lib/init/server";
import { createHash } from "node:crypto";
import { headers } from "next/headers";
import { db } from "@onecli/db";
import {
  recordAuditEvent,
  AUDIT_ACTIONS,
  AUDIT_SERVICES,
  AUDIT_SOURCE,
  AUDIT_STATUS,
} from "@onecli/api/services/audit-service";
import { auth } from "@/lib/auth/better-auth-config";
import { hashPassword } from "@/lib/auth/password-hash";

export interface RedeemRecoveryResult {
  ok: boolean;
  error?: string;
}

/** Matches what the gateway's `create-recovery-key` stored. */
const hashKey = (key: string): string =>
  createHash("sha256").update(key).digest("hex");

/**
 * One message for every failure. The operator holding a good key never sees
 * these, and telling anyone else which of "wrong", "expired" and "already
 * spent" applies only helps someone who should not be here.
 */
const REFUSED = "That recovery link is not valid. Mint a new one on the host.";

/**
 * Redeem a host-minted recovery key: set a password, then sign in with it.
 *
 * The key authorises the rotation rather than minting a session directly, so
 * the session is created by the auth library's own sign-in path and the
 * operator leaves with a credential they can use again.
 */
export const redeemRecoveryKey = async (
  key: string,
  newPassword: string,
): Promise<RedeemRecoveryResult> => {
  if (newPassword.length < 12) {
    return { ok: false, error: "Use a password of at least 12 characters." };
  }

  const token = await db.recoveryToken.findUnique({
    where: { tokenHash: hashKey(key) },
    select: {
      id: true,
      expiresAt: true,
      usedAt: true,
      user: { select: { id: true, email: true } },
    },
  });

  if (!token || token.usedAt || token.expiresAt <= new Date()) {
    if (!token) {
      // `AuditLog.userId` is a required foreign key, so a key matching no row
      // cannot be audited. Logged instead — someone probing keys should not be
      // the one event that leaves no trace anywhere.
      console.warn("[onecli] recovery key presented that matches no record");
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
    return { ok: false, error: REFUSED };
  }

  // Conditional update, not a read-then-write: two redemptions racing must not
  // both pass the check above.
  const claimed = await db.recoveryToken.updateMany({
    where: { id: token.id, usedAt: null },
    data: { usedAt: new Date() },
  });
  if (claimed.count === 0) return { ok: false, error: REFUSED };

  const password = await hashPassword(newPassword);
  const account = await db.authAccount.findFirst({
    where: { userId: token.user.id, providerId: "credential" },
    select: { id: true },
  });

  await db.$transaction([
    account
      ? db.authAccount.update({ where: { id: account.id }, data: { password } })
      : // An SSO-only identity has no credential row yet; recovery is the one
        // path that may create one.
        db.authAccount.create({
          data: {
            accountId: token.user.id,
            providerId: "credential",
            userId: token.user.id,
            password,
          },
        }),
    // The recovery password is the one they just chose, so the flag that would
    // bounce them straight into rotation has already been satisfied.
    db.user.update({
      where: { id: token.user.id },
      data: { mustChangePassword: false },
    }),
  ]);

  // Whoever held the old credentials may be why recovery was needed.
  await db.authSession.deleteMany({ where: { userId: token.user.id } });

  await recordAuditEvent({
    userId: token.user.id,
    userEmail: token.user.email,
    action: AUDIT_ACTIONS.RECOVER,
    service: AUDIT_SERVICES.AUTH,
    source: AUDIT_SOURCE.RECOVERY,
    status: AUDIT_STATUS.SUCCESS,
    metadata: { recoveryTokenId: token.id },
  });

  await auth.api.signInEmail({
    body: { email: token.user.email, password: newPassword },
    headers: await headers(),
  });

  return { ok: true };
};
