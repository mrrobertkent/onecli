"use server";

import "@/lib/init/server";
import { db } from "@onecli/db";
import { AUDIT_SOURCE } from "@onecli/api/services/audit-service";
import { getServerSession } from "@/lib/auth/server";
import { isOAuthConfigured } from "@/lib/auth/auth-mode";
import {
  readLoginPolicy,
  exitRecoveryMode,
  setPasswordLoginEnabled,
} from "@/lib/auth/login-policy";

export interface RecoveryBannerState {
  expiresAt: string;
  /** The stored setting: false while password login is only lent by recovery. */
  passwordLoginEnabled: boolean;
  /** Whether the account has a password to change, or none to set yet. */
  hasPassword: boolean;
  /** Only the operator who redeemed the key may act on the window. */
  canAct: boolean;
}

export interface RecoveryActionResult {
  ok: boolean;
  error?: string;
}

const NOT_IN_RECOVERY = "This instance is not in recovery mode.";
const NOT_THE_OPERATOR =
  "Only the person who redeemed the recovery key can do this.";

/**
 * The signed-in user, the current window, and whether they are the same person.
 * Everything below refuses on a closed window, so it is read fresh each time
 * rather than trusted from the client.
 */
const resolveRecoveryActor = async () => {
  const session = await getServerSession();
  if (!session) return null;

  const policy = await readLoginPolicy();
  if (!policy.recovery.active || !policy.recovery.expiresAt) return null;

  return {
    actor: { userId: session.id, userEmail: session.email },
    policy,
    canAct: policy.recovery.userId === session.id,
  };
};

/** What the banner renders, or null when there is no open window. */
export const getRecoveryBannerState =
  async (): Promise<RecoveryBannerState | null> => {
    const resolved = await resolveRecoveryActor();
    if (!resolved) return null;

    const credential = await db.authAccount.findFirst({
      where: { userId: resolved.actor.userId, providerId: "credential" },
      select: { id: true },
    });

    return {
      expiresAt: resolved.policy.recovery.expiresAt!.toISOString(),
      passwordLoginEnabled: resolved.policy.passwordLoginEnabled,
      hasPassword: credential !== null,
      canAct: resolved.canAct,
    };
  };

/** Keep password login on after the window closes. */
export const enablePasswordLoginPermanently =
  async (): Promise<RecoveryActionResult> => {
    const resolved = await resolveRecoveryActor();
    if (!resolved) return { ok: false, error: NOT_IN_RECOVERY };
    if (!resolved.canAct) return { ok: false, error: NOT_THE_OPERATOR };

    await setPasswordLoginEnabled({
      enabled: true,
      ssoAvailable: isOAuthConfigured(),
      actor: resolved.actor,
      source: AUDIT_SOURCE.RECOVERY,
    });
    return { ok: true };
  };

/**
 * Close the window now. Password login reverts to the stored setting, which is
 * the point: an operator whose identity provider came back leaves no trace.
 */
export const leaveRecoveryMode = async (): Promise<RecoveryActionResult> => {
  const resolved = await resolveRecoveryActor();
  if (!resolved) return { ok: false, error: NOT_IN_RECOVERY };
  if (!resolved.canAct) return { ok: false, error: NOT_THE_OPERATOR };

  await exitRecoveryMode(resolved.actor);
  return { ok: true };
};
