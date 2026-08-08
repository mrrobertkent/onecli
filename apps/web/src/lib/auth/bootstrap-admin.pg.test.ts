import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { proofDatabaseUrl } from "@onecli/api/testing/pg-proof";

/**
 * The bootstrap administrator against real PostgreSQL. The central claim is
 * about row locking and transaction rollback, which a mocked database cannot
 * settle, so these race real transactions.
 *
 * Env-gated like the other proof suites; see pg-proof.ts.
 */

const PROOF_URL = proofDatabaseUrl();

type Db = typeof import("@onecli/db").db;
type Bootstrap = typeof import("./bootstrap-admin");
type Hash = typeof import("./password-hash");

let db: Db;
let bootstrap: Bootstrap;
let hash: Hash;

const P = "bsadmin-";
const EMAIL = `${P}admin@proof.test`;
const PASSWORD = "a-perfectly-fine-passphrase";

const reset = async () => {
  await db.apiKey.deleteMany({ where: { userEmail: { startsWith: P } } });
  // Clear only the field this suite owns. `instance_settings` is a singleton
  // shared with the sign-up gate's suite, so deleting the row would take that
  // suite's `signupMode` with it.
  await db.instanceSetting.updateMany({
    where: { id: "instance" },
    data: { bootstrapAdminUserId: null },
  });
  const users = await db.user.findMany({
    where: { email: { startsWith: P } },
    select: { id: true },
  });
  const ids = users.map((u) => u.id);
  await db.authAccount.deleteMany({ where: { userId: { in: ids } } });
  await db.authSession.deleteMany({ where: { userId: { in: ids } } });
  await db.organizationMember.deleteMany({ where: { userId: { in: ids } } });
  await db.user.deleteMany({ where: { id: { in: ids } } });
};

const clearSeedEnv = () => {
  for (const key of [
    "BOOTSTRAP_ADMIN_EMAIL",
    "BOOTSTRAP_ADMIN_PASSWORD",
    "BOOTSTRAP_ADMIN_PASSWORD_HASH",
    "BOOTSTRAP_ADMIN_NAME",
  ]) {
    delete process.env[key];
  }
};

beforeAll(async () => {
  if (!PROOF_URL) return;
  process.env.DATABASE_URL = PROOF_URL;
  process.env.AUTH_SECRET = "proof-secret-not-used-outside-this-suite";

  ({ db } = await import("@onecli/db"));
  bootstrap = await import("./bootstrap-admin");
  hash = await import("./password-hash");

  await reset();
});

afterAll(async () => {
  if (!PROOF_URL) return;
  await reset();
  clearSeedEnv();
});

beforeEach(async () => {
  if (!PROOF_URL) return;
  await reset();
  clearSeedEnv();
});

describe.skipIf(!PROOF_URL)("bootstrap admin on real PostgreSQL", () => {
  it("creates the admin, its credential, and its owner membership", async () => {
    const admin = await bootstrap.establishBootstrapAdmin({
      email: EMAIL,
      password: PASSWORD,
    });

    const user = await db.user.findUnique({
      where: { id: admin.userId },
      select: { email: true, externalAuthId: true, mustChangePassword: true },
    });
    expect(user?.email).toBe(EMAIL);
    expect(user?.externalAuthId).toBe(admin.userId);

    const account = await db.authAccount.findFirst({
      where: { userId: admin.userId, providerId: "credential" },
      select: { password: true, accountId: true },
    });
    expect(account?.accountId).toBe(admin.userId);
    // Stored as a verifiable hash, never the plaintext.
    expect(account?.password).not.toBe(PASSWORD);
    await expect(
      hash.verifyPassword(account?.password ?? "", PASSWORD),
    ).resolves.toBe(true);

    const membership = await db.organizationMember.findFirst({
      where: { userId: admin.userId },
      select: { role: true, organizationId: true },
    });
    expect(membership?.role).toBe("owner");
    expect(membership?.organizationId).toBe(admin.organizationId);
  });

  it("mints the operator org API key, owned by the admin", async () => {
    const admin = await bootstrap.establishBootstrapAdmin({
      email: EMAIL,
      password: PASSWORD,
    });

    const key = await db.apiKey.findFirst({
      where: { organizationId: admin.organizationId, scope: "organization" },
      select: { userId: true },
    });
    // The key pins its owner via ON DELETE RESTRICT, so it must belong to a
    // real loginable account rather than a synthetic row.
    expect(key?.userId).toBe(admin.userId);
  });

  it("concurrent claims yield exactly one admin and no orphan users", async () => {
    const attempts = Array.from({ length: 8 }, (_, i) =>
      bootstrap
        .establishBootstrapAdmin({
          email: `${P}race-${i}@proof.test`,
          password: PASSWORD,
        })
        .then(
          () => "won" as const,
          () => "lost" as const,
        ),
    );

    const results = await Promise.all(attempts);
    expect(results.filter((r) => r === "won")).toHaveLength(1);

    // Not "at most one" — zero admins is the other half of the failure, and
    // the losers must leave nothing behind.
    const owners = await db.organizationMember.count({
      where: { role: "owner", userEmail: { startsWith: P } },
    });
    expect(owners).toBe(1);

    const users = await db.user.count({ where: { email: { startsWith: P } } });
    expect(users).toBe(1);

    const accounts = await db.authAccount.count({
      where: { user: { email: { startsWith: P } } },
    });
    expect(accounts).toBe(1);

    const settings = await db.instanceSetting.findUnique({
      where: { id: "instance" },
      select: { bootstrapAdminUserId: true },
    });
    const survivor = await db.user.findFirst({
      where: { email: { startsWith: P } },
      select: { id: true },
    });
    expect(settings?.bootstrapAdminUserId).toBe(survivor?.id);
  });

  it("an instance that already has an owner refuses the claim, whatever the column says", async () => {
    await bootstrap.establishBootstrapAdmin({
      email: EMAIL,
      password: PASSWORD,
    });

    // The claim column's foreign key is ON DELETE SET NULL, so losing the
    // admin's user row clears it while the organization keeps its owner.
    await db.instanceSetting.updateMany({
      data: { bootstrapAdminUserId: null },
    });

    await expect(bootstrap.claimWindow()).resolves.toMatchObject({
      claimable: false,
      reason: "already-claimed",
    });
    await expect(
      bootstrap.establishBootstrapAdmin({
        email: `${P}squatter@proof.test`,
        password: PASSWORD,
      }),
    ).rejects.toBeInstanceOf(bootstrap.BootstrapAdminAlreadyExistsError);
    await expect(
      db.user.count({ where: { email: `${P}squatter@proof.test` } }),
    ).resolves.toBe(0);
  });

  it("a second claim is refused once one exists", async () => {
    await bootstrap.establishBootstrapAdmin({
      email: EMAIL,
      password: PASSWORD,
    });

    await expect(
      bootstrap.establishBootstrapAdmin({
        email: `${P}second@proof.test`,
        password: PASSWORD,
      }),
    ).rejects.toBeInstanceOf(bootstrap.BootstrapAdminAlreadyExistsError);

    await expect(
      db.user.count({ where: { email: `${P}second@proof.test` } }),
    ).resolves.toBe(0);
  });

  it("claiming closes the window", async () => {
    await expect(bootstrap.claimWindow()).resolves.toMatchObject({
      claimable: true,
    });

    await bootstrap.establishBootstrapAdmin({
      email: EMAIL,
      password: PASSWORD,
    });

    await expect(bootstrap.claimWindow()).resolves.toEqual({
      claimable: false,
      reason: "already-claimed",
    });
  });

  it("a plaintext env seed applies once and forces rotation", async () => {
    process.env.BOOTSTRAP_ADMIN_EMAIL = EMAIL;
    process.env.BOOTSTRAP_ADMIN_PASSWORD = PASSWORD;

    const seeded = await bootstrap.seedBootstrapAdminFromEnv();
    expect(seeded?.email).toBe(EMAIL);
    expect(seeded?.mustChangePassword).toBe(true);

    // Left in the environment across restarts, it must never re-apply — that
    // would resurrect a rotated password every boot.
    await expect(bootstrap.seedBootstrapAdminFromEnv()).resolves.toBeNull();
    await expect(
      db.user.count({ where: { email: { startsWith: P } } }),
    ).resolves.toBe(1);
  });

  it("an admin who chose their own password at /setup is not sent to rotate it", async () => {
    // The plaintext rule exists for a credential handed over in container
    // configuration. `/setup` is the other case: the person typed it a moment
    // ago, so forcing a rotation would ask them to replace it immediately, and
    // the rotation page would tell them it came from the environment.
    const admin = await bootstrap.establishBootstrapAdmin({
      email: EMAIL,
      password: PASSWORD,
      mustChangePassword: false,
    });

    expect(admin.mustChangePassword).toBe(false);
    const user = await db.user.findUnique({
      where: { id: admin.userId },
      select: { mustChangePassword: true },
    });
    expect(user?.mustChangePassword).toBe(false);
  });

  it("a pre-hashed env seed does not force rotation", async () => {
    process.env.BOOTSTRAP_ADMIN_EMAIL = EMAIL;
    process.env.BOOTSTRAP_ADMIN_PASSWORD_HASH =
      await hash.hashPassword(PASSWORD);

    const seeded = await bootstrap.seedBootstrapAdminFromEnv();
    expect(seeded?.mustChangePassword).toBe(false);

    const account = await db.authAccount.findFirst({
      where: { userId: seeded?.userId, providerId: "credential" },
      select: { password: true },
    });
    // Stored verbatim, and still the hash of the real password.
    await expect(
      hash.verifyPassword(account?.password ?? "", PASSWORD),
    ).resolves.toBe(true);
  });

  it("an email with no credential is a loud configuration error", async () => {
    process.env.BOOTSTRAP_ADMIN_EMAIL = EMAIL;

    await expect(bootstrap.seedBootstrapAdminFromEnv()).rejects.toThrow(
      /without a credential/,
    );
    await expect(
      db.user.count({ where: { email: { startsWith: P } } }),
    ).resolves.toBe(0);
  });

  it("no configured seed is not an error", async () => {
    await expect(bootstrap.seedBootstrapAdminFromEnv()).resolves.toBeNull();
  });
});
