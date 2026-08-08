import { db, type Prisma } from "@onecli/db";
import { isOAuthConfigured } from "@/lib/auth/auth-mode";
import {
  recordAuditEvent,
  AUDIT_ACTIONS,
  AUDIT_SERVICES,
  AUDIT_SOURCE,
  AUDIT_STATUS,
  type AuditSource,
} from "@onecli/api/services/audit-service";

/**
 * Which login methods this instance offers, and the recovery window that lends
 * password login without writing the stored setting. SSO is not represented
 * here — it is environment-configured, and recovery never touches it.
 */

const INSTANCE_ID = "instance";

/** How long a redeemed recovery key keeps password login on. */
export const RECOVERY_WINDOW_MS = 60 * 60 * 1000;

export interface RecoveryMode {
  active: boolean;
  expiresAt: Date | null;
  /** Who redeemed the key, while the window is open. */
  userId: string | null;
}

export interface LoginPolicy {
  /** The stored answer. No recovery window ever writes it. */
  passwordLoginEnabled: boolean;
  /** What the sign-in path honours now — stored, or lent by recovery. */
  passwordLoginAvailable: boolean;
  recovery: RecoveryMode;
}

const NO_RECOVERY: RecoveryMode = {
  active: false,
  expiresAt: null,
  userId: null,
};

/** What an unreadable row resolves to: offer nothing, admit nobody. */
const DENIED: LoginPolicy = {
  passwordLoginEnabled: false,
  passwordLoginAvailable: false,
  recovery: NO_RECOVERY,
};

export interface RecoveryActor {
  userId: string;
  userEmail: string;
}

/** Raised when a change would leave the instance with no way in. */
export class LastLoginMethodError extends Error {
  constructor() {
    super(
      "Password login is the only way into this instance. Configure an " +
        "identity provider before turning it off.",
    );
    this.name = "LastLoginMethodError";
  }
}

const auditRecovery = async (
  actor: RecoveryActor,
  metadata: Prisma.InputJsonValue,
): Promise<void> =>
  recordAuditEvent({
    userId: actor.userId,
    userEmail: actor.userEmail,
    action: AUDIT_ACTIONS.RECOVER,
    service: AUDIT_SERVICES.AUTH,
    source: AUDIT_SOURCE.RECOVERY,
    status: AUDIT_STATUS.SUCCESS,
    metadata,
  });

/**
 * Close an expired window, auditing it once. Nothing sweeps the column, so the
 * first read clears it; the update is conditional so racing readers cannot both
 * claim the close.
 */
const closeExpiredWindow = async (
  expiresAt: Date,
  userId: string | null,
): Promise<void> => {
  const closed = await db.instanceSetting.updateMany({
    where: { id: INSTANCE_ID, recoveryModeExpiresAt: expiresAt },
    data: { recoveryModeExpiresAt: null, recoveryModeUserId: null },
  });
  if (closed.count === 0) return;

  const user = userId
    ? await db.user.findUnique({
        where: { id: userId },
        select: { email: true },
      })
    : null;
  if (!user) {
    // `AuditLog.userId` is a required foreign key, so a window whose user is
    // gone cannot be audited to a row.
    console.warn(
      "[onecli] recovery mode expired with no user to attribute it to",
    );
    return;
  }
  await auditRecovery(
    { userId: userId as string, userEmail: user.email },
    { event: "left", reason: "expired" },
  );
};

/**
 * The current policy. Reading it also retires an expired window.
 *
 * Password login is available whenever it is the only method configured, so
 * removing `OIDC_*` reopens it rather than sealing the instance.
 */
export const readLoginPolicy = async (): Promise<LoginPolicy> => {
  let row;
  try {
    row = await db.instanceSetting.findUnique({
      where: { id: INSTANCE_ID },
      select: {
        passwordLoginEnabled: true,
        recoveryModeExpiresAt: true,
        recoveryModeUserId: true,
      },
    });
  } catch (err) {
    console.error(
      "[onecli] login policy read failed; offering no password login",
      err,
    );
    return DENIED;
  }

  // No row is a fresh instance rather than a failure, so the column defaults
  // apply — a first install has no identity provider and must not be shut out
  // of the only method it has.
  const stored = row?.passwordLoginEnabled ?? true;
  const expiresAt = row?.recoveryModeExpiresAt ?? null;
  const onlyMethod = !isOAuthConfigured();

  if (expiresAt && expiresAt.getTime() <= Date.now()) {
    await closeExpiredWindow(expiresAt, row?.recoveryModeUserId ?? null);
    return {
      passwordLoginEnabled: stored,
      passwordLoginAvailable: stored || onlyMethod,
      recovery: NO_RECOVERY,
    };
  }

  return {
    passwordLoginEnabled: stored,
    passwordLoginAvailable: stored || expiresAt !== null || onlyMethod,
    recovery: expiresAt
      ? {
          active: true,
          expiresAt,
          userId: row?.recoveryModeUserId ?? null,
        }
      : NO_RECOVERY,
  };
};

/** Whether a password sign-in may be attempted at all. */
export const isPasswordLoginAvailable = async (): Promise<boolean> =>
  (await readLoginPolicy()).passwordLoginAvailable;

/**
 * Open a recovery window. Persisted, so a container restart mid-recovery does
 * not strip the banner while leaving password login on.
 */
export const enterRecoveryMode = async (
  actor: RecoveryActor,
): Promise<Date> => {
  const expiresAt = new Date(Date.now() + RECOVERY_WINDOW_MS);

  await db.instanceSetting.upsert({
    where: { id: INSTANCE_ID },
    create: {
      id: INSTANCE_ID,
      recoveryModeExpiresAt: expiresAt,
      recoveryModeUserId: actor.userId,
    },
    update: {
      recoveryModeExpiresAt: expiresAt,
      recoveryModeUserId: actor.userId,
    },
  });

  await auditRecovery(actor, { event: "entered", expiresAt });
  return expiresAt;
};

/** Close the window early. Returns false when there was nothing open. */
export const exitRecoveryMode = async (
  actor: RecoveryActor,
): Promise<boolean> => {
  const closed = await db.instanceSetting.updateMany({
    where: { id: INSTANCE_ID, recoveryModeExpiresAt: { not: null } },
    data: { recoveryModeExpiresAt: null, recoveryModeUserId: null },
  });
  if (closed.count === 0) return false;

  await auditRecovery(actor, { event: "left", reason: "exited" });
  return true;
};

/**
 * Change the stored setting. `ssoAvailable` is passed rather than read here
 * because it is environment-configured; turning off the last method is refused.
 */
export const setPasswordLoginEnabled = async ({
  enabled,
  ssoAvailable,
  actor,
  source = AUDIT_SOURCE.APP,
}: {
  enabled: boolean;
  ssoAvailable: boolean;
  actor: RecoveryActor;
  source?: AuditSource;
}): Promise<void> => {
  if (!enabled && !ssoAvailable) throw new LastLoginMethodError();

  await db.instanceSetting.upsert({
    where: { id: INSTANCE_ID },
    create: {
      id: INSTANCE_ID,
      passwordLoginEnabled: enabled,
      updatedByUserId: actor.userId,
    },
    update: {
      passwordLoginEnabled: enabled,
      updatedByUserId: actor.userId,
    },
  });

  await recordAuditEvent({
    userId: actor.userId,
    userEmail: actor.userEmail,
    action: AUDIT_ACTIONS.UPDATE,
    service: AUDIT_SERVICES.AUTH,
    source,
    status: AUDIT_STATUS.SUCCESS,
    metadata: { passwordLoginEnabled: enabled },
  });
};
