import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { db } from "@onecli/db";
import { findOrCreateSharedOrg } from "@onecli/api/services/organization-service";
import { ensureBootstrapOrgApiKey } from "@onecli/api/services/api-key-service";
import { hashPassword } from "@/lib/auth/password-hash";

/** Measured from process start, so a restart reopens the claim window. */
const CLAIM_WINDOW_MS = 15 * 60 * 1000;
const STARTED_AT = Date.now();

const INSTANCE_ID = "instance";

/** Read a setting from `NAME`, else from the file at `NAME_FILE`. */
const fromEnvOrFile = (name: string): string | undefined => {
  const direct = process.env[name]?.trim();
  if (direct) return direct;

  const file = process.env[`${name}_FILE`]?.trim();
  if (!file) return undefined;

  try {
    const contents = readFileSync(file, "utf8").trim();
    return contents || undefined;
  } catch (err) {
    throw new Error(
      `${name}_FILE could not be read (${file}): ${
        err instanceof Error ? err.message : String(err)
      }`,
    );
  }
};

export interface BootstrapAdminSeed {
  email: string;
  password?: string;
  passwordHash?: string;
  name?: string;
  /**
   * Whether first login must rotate the credential. Defaults to true for a
   * plaintext password, which is how an environment-configured one arrives —
   * readable in container configuration, so treated as compromised. `/setup`
   * passes false: the person chose it a moment ago, and there is nothing to
   * rotate away from.
   */
  mustChangePassword?: boolean;
}

/**
 * The environment-configured admin, or null when none is configured.
 *
 * A pre-hashed credential takes precedence; a plaintext password is treated as
 * compromised and forces a rotation at first login.
 */
export const readBootstrapAdminSeed = (): BootstrapAdminSeed | null => {
  const email = fromEnvOrFile("BOOTSTRAP_ADMIN_EMAIL");
  if (!email) return null;

  const passwordHash = fromEnvOrFile("BOOTSTRAP_ADMIN_PASSWORD_HASH");
  const password = fromEnvOrFile("BOOTSTRAP_ADMIN_PASSWORD");

  if (!passwordHash && !password) {
    throw new Error(
      "BOOTSTRAP_ADMIN_EMAIL is set without a credential — also set " +
        "BOOTSTRAP_ADMIN_PASSWORD_HASH (preferred) or BOOTSTRAP_ADMIN_PASSWORD.",
    );
  }

  return {
    email,
    passwordHash,
    password,
    name: fromEnvOrFile("BOOTSTRAP_ADMIN_NAME"),
  };
};

export type ClaimWindow =
  | { claimable: true; expiresAt: Date }
  | { claimable: false; reason: "already-claimed" | "window-expired" };

/** Ensure the singleton settings row exists, tolerating a concurrent create. */
const ensureInstanceRow = async (): Promise<void> => {
  try {
    await db.instanceSetting.upsert({
      where: { id: INSTANCE_ID },
      create: { id: INSTANCE_ID },
      update: {},
    });
  } catch {
    // Lost the create race; the row someone else wrote is equally good.
  }
};

/** An instance that already has an owner is set up, whatever the column says. */
const ownerCount = (client: Pick<typeof db, "organizationMember">) =>
  client.organizationMember.count({
    where: { role: "owner", status: "active" },
  });

/** Whether the first-admin claim is open right now, and until when. */
export const claimWindow = async (): Promise<ClaimWindow> => {
  const row = await db.instanceSetting.findUnique({
    where: { id: INSTANCE_ID },
    select: { bootstrapAdminUserId: true },
  });

  // The claim column is nullable and its foreign key clears it when the admin's
  // user row goes, which would otherwise reopen an unauthenticated claim on a
  // populated instance.
  if (row?.bootstrapAdminUserId || (await ownerCount(db)) > 0) {
    return { claimable: false, reason: "already-claimed" };
  }

  const expiresAt = new Date(STARTED_AT + CLAIM_WINDOW_MS);
  if (Date.now() >= expiresAt.getTime()) {
    return { claimable: false, reason: "window-expired" };
  }

  return { claimable: true, expiresAt };
};

/** Raised when another claim won; the caller's own transaction has rolled back. */
export class BootstrapAdminAlreadyExistsError extends Error {
  constructor() {
    super("This instance already has an administrator.");
    this.name = "BootstrapAdminAlreadyExistsError";
  }
}

export interface EstablishedAdmin {
  userId: string;
  email: string;
  organizationId: string;
  mustChangePassword: boolean;
}

/**
 * Create the bootstrap administrator, or fail because one already exists.
 *
 * The user, its credential, its `owner` membership and the claim are one
 * transaction, so a caller that loses the claim race leaves nothing behind.
 */
export const establishBootstrapAdmin = async ({
  email,
  password,
  passwordHash,
  name,
  mustChangePassword: rotate,
}: BootstrapAdminSeed): Promise<EstablishedAdmin> => {
  if (!password && !passwordHash) {
    throw new Error("A bootstrap admin needs a password or a password hash.");
  }

  await ensureInstanceRow();
  const org = await findOrCreateSharedOrg();

  const normalisedEmail = email.trim().toLowerCase();
  const storedHash = passwordHash ?? (await hashPassword(password as string));
  // Only a credential we were handed in plaintext is treated as compromised,
  // and only when the caller has not said who chose it.
  const mustChangePassword = rotate ?? !passwordHash;
  const userId = randomUUID();

  const admin = await db.$transaction(async (tx) => {
    if ((await ownerCount(tx)) > 0) {
      throw new BootstrapAdminAlreadyExistsError();
    }

    const user = await tx.user.create({
      data: {
        id: userId,
        email: normalisedEmail,
        name: name ?? "Administrator",
        externalAuthId: userId,
        // Configured out of band by the operator; there is no mailbox to verify.
        emailVerified: true,
        mustChangePassword,
      },
      select: { id: true, email: true },
    });

    await tx.authAccount.create({
      data: {
        userId: user.id,
        providerId: "credential",
        accountId: user.id,
        password: storedHash,
      },
    });

    await tx.organizationMember.create({
      data: {
        organizationId: org.id,
        userId: user.id,
        userEmail: user.email,
        role: "owner",
      },
    });

    const claimed = await tx.instanceSetting.updateMany({
      where: { id: INSTANCE_ID, bootstrapAdminUserId: null },
      data: { bootstrapAdminUserId: user.id },
    });
    if (claimed.count === 0) throw new BootstrapAdminAlreadyExistsError();

    return user;
  });

  // Outside the transaction: idempotent, and its failure should not undo an
  // administrator who now exists.
  await ensureBootstrapOrgApiKey({
    organizationId: org.id,
    userId: admin.id,
    userEmail: admin.email,
  });

  return {
    userId: admin.id,
    email: admin.email,
    organizationId: org.id,
    mustChangePassword,
  };
};

/**
 * Apply the environment-configured admin, if one is configured and the instance
 * has none. Returns null when there is nothing to do.
 *
 * Safe to call on every boot: a seed left in the environment is never
 * re-applied once an administrator exists.
 */
export const seedBootstrapAdminFromEnv =
  async (): Promise<EstablishedAdmin | null> => {
    const seed = readBootstrapAdminSeed();
    if (!seed) return null;

    await ensureInstanceRow();
    const existing = await db.instanceSetting.findUnique({
      where: { id: INSTANCE_ID },
      select: { bootstrapAdminUserId: true },
    });
    if (existing?.bootstrapAdminUserId) return null;

    try {
      return await establishBootstrapAdmin(seed);
    } catch (err) {
      if (err instanceof BootstrapAdminAlreadyExistsError) return null;
      throw err;
    }
  };
