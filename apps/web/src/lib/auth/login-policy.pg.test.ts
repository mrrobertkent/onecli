import {
  afterAll,
  beforeAll,
  beforeEach,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { proofDatabaseUrl } from "@onecli/api/testing/pg-proof";

/**
 * Login methods as stored state, against real PostgreSQL: the recovery window
 * is a row rather than a module constant, its expiry is a column comparison,
 * and the last-method invariant is a refused write. The end-to-end case drives
 * `auth.api.signInEmail`, because a setting the sign-in path does not consult
 * is not a setting.
 *
 * Env-gated like the other proof suites; see pg-proof.ts.
 */

const PROOF_URL = proofDatabaseUrl();

vi.hoisted(() => {
  process.env.NEXT_PUBLIC_EDITION = "oss";
});

vi.mock("next/headers", () => ({ headers: async () => new Headers() }));

type Db = typeof import("@onecli/db").db;
type Policy = typeof import("./login-policy");
type AuthModule = typeof import("./better-auth-config");

let db: Db;
let policy: Policy;
let auth: AuthModule["auth"];

const P = "lgnpol-";
const USER = `${P}user`;
const EMAIL = `${P}user@proof.test`;
const PASSWORD = "correct-horse-battery-staple-9";

const ACTOR = { userId: USER, userEmail: EMAIL };

const reset = async () => {
  await db.auditLog.deleteMany({ where: { userId: { startsWith: P } } });
  await db.authSession.deleteMany({ where: { userId: { startsWith: P } } });
  await db.authAccount.deleteMany({ where: { userId: { startsWith: P } } });
  await db.user.deleteMany({ where: { id: { startsWith: P } } });
  // Only the columns this suite drives; the row is shared with every other one.
  await db.instanceSetting.updateMany({
    data: {
      passwordLoginEnabled: true,
      recoveryModeExpiresAt: null,
      recoveryModeUserId: null,
    },
  });
};

const seedUser = async (withPassword = false) => {
  await db.user.create({
    data: { id: USER, email: EMAIL, name: USER, externalAuthId: USER },
  });
  if (withPassword) {
    const { hashPassword } = await import("./password-hash");
    await db.authAccount.create({
      data: {
        userId: USER,
        providerId: "credential",
        accountId: USER,
        password: await hashPassword(PASSWORD),
      },
    });
  }
};

const settings = () =>
  db.instanceSetting.findUnique({
    where: { id: "instance" },
    select: {
      passwordLoginEnabled: true,
      recoveryModeExpiresAt: true,
      recoveryModeUserId: true,
    },
  });

const openWindow = (expiresInMs: number) =>
  db.instanceSetting.upsert({
    where: { id: "instance" },
    create: {
      id: "instance",
      recoveryModeExpiresAt: new Date(Date.now() + expiresInMs),
      recoveryModeUserId: USER,
    },
    update: {
      recoveryModeExpiresAt: new Date(Date.now() + expiresInMs),
      recoveryModeUserId: USER,
    },
  });

/** `auth.api.*` throws `APIError` on non-2xx; normalise both into a status. */
const signInStatus = async (): Promise<number> => {
  try {
    await auth.api.signInEmail({
      body: { email: EMAIL, password: PASSWORD },
      headers: new Headers(),
    });
    return 200;
  } catch (err) {
    return (err as { statusCode?: number }).statusCode ?? 500;
  }
};

beforeAll(async () => {
  if (!PROOF_URL) return;
  process.env.DATABASE_URL = PROOF_URL;
  process.env.AUTH_SECRET = "proof-secret-not-used-outside-this-suite";
  process.env.APP_URL = "http://localhost:10254";

  ({ db } = await import("@onecli/db"));
  policy = await import("./login-policy");
  ({ auth } = await import("./better-auth-config"));

  await reset();
});

afterAll(async () => {
  if (!PROOF_URL) return;
  await reset();
});

beforeEach(async () => {
  if (!PROOF_URL) return;
  await reset();
});

describe.skipIf(!PROOF_URL)("login methods on real PostgreSQL", () => {
  it("offers password login by default — a first install has nothing else", async () => {
    const read = await policy.readLoginPolicy();
    expect(read.passwordLoginEnabled).toBe(true);
    expect(read.passwordLoginAvailable).toBe(true);
    expect(read.recovery.active).toBe(false);
  });

  it("refuses to turn off the last way in, and writes nothing", async () => {
    await seedUser();

    await expect(
      policy.setPasswordLoginEnabled({
        enabled: false,
        ssoAvailable: false,
        actor: ACTOR,
      }),
    ).rejects.toBeInstanceOf(policy.LastLoginMethodError);

    expect((await settings())?.passwordLoginEnabled).toBe(true);
    await expect(db.auditLog.count({ where: { userId: USER } })).resolves.toBe(
      0,
    );
  });

  it("turns password login off once an identity provider is configured", async () => {
    await seedUser();

    await policy.setPasswordLoginEnabled({
      enabled: false,
      ssoAvailable: true,
      actor: ACTOR,
    });

    const read = await policy.readLoginPolicy();
    expect(read.passwordLoginEnabled).toBe(false);
    expect(read.passwordLoginAvailable).toBe(false);
  });

  it("the sign-in path honours the setting, not the build", async () => {
    await seedUser(true);
    expect(await signInStatus()).toBe(200);

    await policy.setPasswordLoginEnabled({
      enabled: false,
      ssoAvailable: true,
      actor: ACTOR,
    });
    expect(await signInStatus()).toBe(403);
  });

  it("a recovery window lends password login without writing the setting", async () => {
    await seedUser(true);
    await policy.setPasswordLoginEnabled({
      enabled: false,
      ssoAvailable: true,
      actor: ACTOR,
    });

    await policy.enterRecoveryMode(ACTOR);

    const read = await policy.readLoginPolicy();
    expect(read.passwordLoginEnabled).toBe(false);
    expect(read.passwordLoginAvailable).toBe(true);
    expect(read.recovery.active).toBe(true);
    expect(await signInStatus()).toBe(200);
  });

  it("expiry reverts password login, and is audited exactly once", async () => {
    await seedUser(true);
    await policy.setPasswordLoginEnabled({
      enabled: false,
      ssoAvailable: true,
      actor: ACTOR,
    });
    await openWindow(-1_000);

    // Two readers race the close; one of them writes the audit row.
    const [a, b] = await Promise.all([
      policy.readLoginPolicy(),
      policy.readLoginPolicy(),
    ]);
    expect(a!.passwordLoginAvailable).toBe(false);
    expect(b!.recovery.active).toBe(false);
    expect(await signInStatus()).toBe(403);

    expect((await settings())?.recoveryModeExpiresAt).toBeNull();
    const left = await db.auditLog.findMany({
      where: { userId: USER, action: "recover" },
      select: { metadata: true },
    });
    expect(
      left.filter(
        (e) => (e.metadata as { reason?: string } | null)?.reason === "expired",
      ),
    ).toHaveLength(1);
  });

  it("exiting reverts password login, and is audited", async () => {
    await seedUser(true);
    await policy.setPasswordLoginEnabled({
      enabled: false,
      ssoAvailable: true,
      actor: ACTOR,
    });
    await policy.enterRecoveryMode(ACTOR);

    await expect(policy.exitRecoveryMode(ACTOR)).resolves.toBe(true);

    expect((await policy.readLoginPolicy()).passwordLoginAvailable).toBe(false);
    expect(await signInStatus()).toBe(403);
    const left = await db.auditLog.findMany({
      where: { userId: USER, action: "recover" },
      select: { metadata: true },
    });
    expect(
      left.filter(
        (e) => (e.metadata as { reason?: string } | null)?.reason === "exited",
      ),
    ).toHaveLength(1);
    // Nothing left to exit.
    await expect(policy.exitRecoveryMode(ACTOR)).resolves.toBe(false);
  });

  it("recovery mode outlives the process — it is a row, not a module global", async () => {
    await seedUser();
    await policy.setPasswordLoginEnabled({
      enabled: false,
      ssoAvailable: true,
      actor: ACTOR,
    });
    await policy.enterRecoveryMode(ACTOR);

    // As close to a container restart as a test gets: every module this file
    // holds is discarded and loaded again.
    vi.resetModules();
    const restarted: Policy = await import("./login-policy");

    const read = await restarted.readLoginPolicy();
    expect(read.recovery.active).toBe(true);
    expect(read.recovery.userId).toBe(USER);
    expect(read.passwordLoginAvailable).toBe(true);
  });
});
