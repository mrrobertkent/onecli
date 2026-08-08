"use server";

import "@/lib/init/server";
import { headers } from "next/headers";
import { db } from "@onecli/db";
import {
  recordAuditEvent,
  AUDIT_ACTIONS,
  AUDIT_SERVICES,
  AUDIT_SOURCE,
} from "@onecli/api/services/audit-service";
import { auth } from "@/lib/auth/better-auth-config";
import { getServerSession } from "@/lib/auth/server";
import { hashPassword, verifyPassword } from "@/lib/auth/password-hash";
import { readLoginPolicy } from "@/lib/auth/login-policy";

export interface ChangePasswordResult {
  ok: boolean;
  error?: string;
}

/**
 * Set the signed-in user's password. Written directly, not through the auth
 * library, so clearing `mustChangePassword` shares the transaction.
 *
 * Inside the user's own recovery window the current password is not asked for,
 * and a credential may be created for an SSO-only identity.
 */
export const changePassword = async (
  currentPassword: string,
  newPassword: string,
): Promise<ChangePasswordResult> => {
  const session = await getServerSession();
  if (!session) return { ok: false, error: "Not signed in." };

  if (newPassword.length < 12) {
    return { ok: false, error: "Use a password of at least 12 characters." };
  }

  const user = await db.user.findUnique({
    where: { externalAuthId: session.id },
    select: { id: true },
  });
  if (!user) return { ok: false, error: "Not signed in." };

  const policy = await readLoginPolicy();
  const recovering =
    policy.recovery.active && policy.recovery.userId === user.id;

  const account = await db.authAccount.findFirst({
    where: { userId: user.id, providerId: "credential" },
    select: { id: true, password: true },
  });

  if (!recovering) {
    if (newPassword === currentPassword) {
      return { ok: false, error: "Choose a password you have not used here." };
    }
    if (!account?.password) {
      return {
        ok: false,
        error: "This account signs in through your identity provider.",
      };
    }
    if (!(await verifyPassword(account.password, currentPassword))) {
      return { ok: false, error: "That is not your current password." };
    }
  }

  const next = await hashPassword(newPassword);

  await db.$transaction([
    account
      ? db.authAccount.update({
          where: { id: account.id },
          data: { password: next },
        })
      : db.authAccount.create({
          data: {
            accountId: user.id,
            providerId: "credential",
            userId: user.id,
            password: next,
          },
        }),
    db.user.update({
      where: { id: user.id },
      data: { mustChangePassword: false },
    }),
  ]);

  if (recovering) {
    await recordAuditEvent({
      userId: user.id,
      userEmail: session.email,
      action: AUDIT_ACTIONS.UPDATE,
      service: AUDIT_SERVICES.AUTH,
      source: AUDIT_SOURCE.RECOVERY,
      metadata: { event: account ? "password-changed" : "password-set" },
    });
  }

  // The old password may have been shared or logged, so every other session
  // holding it is revoked.
  await db.authSession.deleteMany({ where: { userId: user.id } });

  await auth.api.signInEmail({
    body: { email: session.email, password: newPassword },
    headers: await headers(),
  });

  return { ok: true };
};
