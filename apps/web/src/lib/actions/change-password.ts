"use server";

import "@/lib/init/server";
import { headers } from "next/headers";
import { db } from "@onecli/db";
import { auth } from "@/lib/auth/better-auth-config";
import { getServerSession } from "@/lib/auth/server";
import { hashPassword, verifyPassword } from "@/lib/auth/password-hash";

export interface ChangePasswordResult {
  ok: boolean;
  error?: string;
}

/**
 * Rotate the signed-in user's password.
 *
 * Written directly rather than through the auth library's own change-password
 * endpoint so clearing `mustChangePassword` is part of the same transaction —
 * a rotation that succeeded but left the flag set would trap the user in the
 * redirect it exists to drive.
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
  if (newPassword === currentPassword) {
    return { ok: false, error: "Choose a password you have not used here." };
  }

  const user = await db.user.findUnique({
    where: { externalAuthId: session.id },
    select: { id: true },
  });
  if (!user) return { ok: false, error: "Not signed in." };

  const account = await db.authAccount.findFirst({
    where: { userId: user.id, providerId: "credential" },
    select: { id: true, password: true },
  });
  if (!account?.password) {
    return {
      ok: false,
      error: "This account signs in through your identity provider.",
    };
  }

  if (!(await verifyPassword(account.password, currentPassword))) {
    return { ok: false, error: "That is not your current password." };
  }

  const next = await hashPassword(newPassword);

  await db.$transaction([
    db.authAccount.update({
      where: { id: account.id },
      data: { password: next },
    }),
    db.user.update({
      where: { id: user.id },
      data: { mustChangePassword: false },
    }),
  ]);

  // The old password may have been shared or logged, so every other session
  // holding it is revoked. Database-backed sessions make that a real
  // revocation rather than a cookie the client is asked to discard.
  await db.authSession.deleteMany({ where: { userId: user.id } });

  await auth.api.signInEmail({
    body: { email: session.email, password: newPassword },
    headers: await headers(),
  });

  return { ok: true };
};
