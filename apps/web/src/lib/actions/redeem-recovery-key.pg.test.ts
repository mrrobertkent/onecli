import { createHash } from "node:crypto";
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
 * Recovery-key redemption against real PostgreSQL. Single use is a conditional
 * update, expiry is a column comparison, and "changes nothing else" is a claim
 * about rows that were not written — none of which a mock settles.
 *
 * Env-gated like the other proof suites; see pg-proof.ts.
 */

const PROOF_URL = proofDatabaseUrl();

vi.hoisted(() => {
  process.env.NEXT_PUBLIC_EDITION = "oss";
});

vi.mock("next/headers", () => ({ headers: async () => new Headers() }));

type Db = typeof import("@onecli/db").db;
type Redeem = typeof import("./redeem-recovery-key");

let db: Db;
let redeem: Redeem;

const P = "rcvr-";
const USER = `${P}user`;
const EMAIL = `${P}user@proof.test`;

/** A stored credential, verbatim, so a rewrite of it is visible byte for byte. */
const EXISTING_HASH =
  "$argon2id$v=19$m=19456,t=2,p=1$cmVjb3Zlcnlwcm9vZnNhbHQ$Zm9yLXByb29mLW9ubHktbm90LWEtcmVhbC1oYXNo";

const hashKey = (key: string) => createHash("sha256").update(key).digest("hex");

const reset = async () => {
  await db.auditLog.deleteMany({ where: { userId: { startsWith: P } } });
  await db.recoveryToken.deleteMany({ where: { userId: { startsWith: P } } });
  await db.authSession.deleteMany({ where: { userId: { startsWith: P } } });
  await db.authAccount.deleteMany({ where: { userId: { startsWith: P } } });
  await db.user.deleteMany({ where: { id: { startsWith: P } } });
  // Only the columns this suite drives; the row is shared with every other one.
  await db.instanceSetting.updateMany({
    data: {
      recoveryModeExpiresAt: null,
      recoveryModeUserId: null,
      passwordLoginEnabled: true,
    },
  });
};

const seedUser = async ({
  password,
  mustChangePassword = false,
}: {
  password?: string;
  mustChangePassword?: boolean;
} = {}) => {
  await db.user.create({
    data: {
      id: USER,
      email: EMAIL,
      name: USER,
      externalAuthId: USER,
      mustChangePassword,
    },
  });
  if (password) {
    await db.authAccount.create({
      data: {
        userId: USER,
        providerId: "credential",
        accountId: USER,
        password,
      },
    });
  }
};

/** Mint as the gateway does: store only the hash. */
const mintKey = async (key: string, expiresInMs: number) => {
  await db.recoveryToken.create({
    data: {
      tokenHash: hashKey(key),
      userId: USER,
      expiresAt: new Date(Date.now() + expiresInMs),
    },
  });
  return key;
};

const storedPassword = async () => {
  const account = await db.authAccount.findFirst({
    where: { userId: USER, providerId: "credential" },
    select: { password: true },
  });
  return account?.password ?? null;
};

beforeAll(async () => {
  if (!PROOF_URL) return;
  process.env.DATABASE_URL = PROOF_URL;
  process.env.AUTH_SECRET = "proof-secret-not-used-outside-this-suite";
  process.env.APP_URL = "http://localhost:10254";

  ({ db } = await import("@onecli/db"));
  redeem = await import("./redeem-recovery-key");

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

describe.skipIf(!PROOF_URL)(
  "recovery key redemption on real PostgreSQL",
  () => {
    it("the mint stores only a hash — the key itself is never in the table", async () => {
      await seedUser();
      const key = await mintKey("key-secrecy", 60_000);

      const rows = await db.recoveryToken.findMany({
        where: { userId: USER },
        select: { tokenHash: true },
      });
      expect(rows).toHaveLength(1);
      expect(rows[0]!.tokenHash).not.toContain(key);
      expect(rows[0]!.tokenHash).toBe(hashKey(key));
    });

    it("pins the hash the gateway writes — SHA-256 hex of the key", () => {
      // Known answer, asserted identically in `recovery.rs`. If the two drift,
      // every minted key silently fails to redeem.
      expect(hashKey("onecli-recovery-known-answer")).toBe(
        "f1bb0f5f4e8fa2cadabd895af06faec86b6ef2e60d7d680a67c05c72c46def41",
      );
    });

    it("a valid key grants a session and marks itself used", async () => {
      await seedUser({ password: EXISTING_HASH });
      const key = await mintKey("key-happy", 60_000);

      await expect(redeem.redeemRecoveryKey(key)).resolves.toMatchObject({
        ok: true,
      });

      const token = await db.recoveryToken.findUnique({
        where: { tokenHash: hashKey(key) },
        select: { usedAt: true },
      });
      expect(token?.usedAt).not.toBeNull();

      await expect(
        db.authSession.count({ where: { userId: USER } }),
      ).resolves.toBe(1);
    });

    it("leaves the existing password byte for byte as it found it", async () => {
      await seedUser({ password: EXISTING_HASH });
      const key = await mintKey("key-no-rewrite", 60_000);

      await expect(redeem.redeemRecoveryKey(key)).resolves.toMatchObject({
        ok: true,
      });

      await expect(storedPassword()).resolves.toBe(EXISTING_HASH);
    });

    it("creates no credential for an identity that only ever used SSO", async () => {
      await seedUser();
      const key = await mintKey("key-sso-only", 60_000);

      await expect(redeem.redeemRecoveryKey(key)).resolves.toMatchObject({
        ok: true,
      });

      await expect(
        db.authAccount.count({
          where: { userId: USER, providerId: "credential" },
        }),
      ).resolves.toBe(0);
    });

    it("leaves mustChangePassword as it found it", async () => {
      await seedUser({ password: EXISTING_HASH, mustChangePassword: true });
      const key = await mintKey("key-rotation-flag", 60_000);

      await redeem.redeemRecoveryKey(key);

      const user = await db.user.findUnique({
        where: { id: USER },
        select: { mustChangePassword: true },
      });
      expect(user?.mustChangePassword).toBe(true);
    });

    it("leaves other sessions alone — recovery revokes nothing", async () => {
      await seedUser({ password: EXISTING_HASH });
      await db.authSession.create({
        data: {
          id: `${P}live`,
          userId: USER,
          token: `${P}live-token`,
          expiresAt: new Date(Date.now() + 3_600_000),
        },
      });
      const key = await mintKey("key-keeps-sessions", 60_000);

      await redeem.redeemRecoveryKey(key);

      await expect(
        db.authSession.count({ where: { id: `${P}live` } }),
      ).resolves.toBe(1);
    });

    it("opens a recovery window on the settings row, not in the process", async () => {
      await seedUser({ password: EXISTING_HASH });
      const key = await mintKey("key-window", 60_000);

      await redeem.redeemRecoveryKey(key);

      const settings = await db.instanceSetting.findUnique({
        where: { id: "instance" },
        select: {
          recoveryModeExpiresAt: true,
          recoveryModeUserId: true,
          passwordLoginEnabled: true,
        },
      });
      expect(settings?.recoveryModeUserId).toBe(USER);
      expect(settings?.recoveryModeExpiresAt?.getTime()).toBeGreaterThan(
        Date.now(),
      );
      // The window lends password login; it does not write the setting.
      expect(settings?.passwordLoginEnabled).toBe(true);
    });

    it("a second use of the same key is refused", async () => {
      await seedUser({ password: EXISTING_HASH });
      const key = await mintKey("key-once", 60_000);

      await expect(redeem.redeemRecoveryKey(key)).resolves.toMatchObject({
        ok: true,
      });

      await expect(redeem.redeemRecoveryKey(key)).resolves.toMatchObject({
        ok: false,
      });
    });

    it("an expired key is refused, and does not become used", async () => {
      await seedUser({ password: EXISTING_HASH });
      const key = await mintKey("key-expired", -1_000);

      await expect(redeem.redeemRecoveryKey(key)).resolves.toMatchObject({
        ok: false,
      });

      const token = await db.recoveryToken.findUnique({
        where: { tokenHash: hashKey(key) },
        select: { usedAt: true },
      });
      expect(token?.usedAt).toBeNull();
    });

    it("an unknown key is refused, and opens no window", async () => {
      await seedUser();

      await expect(
        redeem.redeemRecoveryKey("never-minted"),
      ).resolves.toMatchObject({ ok: false });

      const settings = await db.instanceSetting.findUnique({
        where: { id: "instance" },
        select: { recoveryModeExpiresAt: true },
      });
      expect(settings?.recoveryModeExpiresAt ?? null).toBeNull();
      await expect(
        db.authAccount.count({ where: { userId: USER } }),
      ).resolves.toBe(0);
    });

    it("concurrent redemptions of one key admit exactly one", async () => {
      await seedUser({ password: EXISTING_HASH });
      const key = await mintKey("key-race", 60_000);

      const results = await Promise.all(
        Array.from({ length: 8 }, () => redeem.redeemRecoveryKey(key)),
      );

      expect(results.filter((r) => r.ok)).toHaveLength(1);
    });

    it("audits the redemption, entering recovery, and a spent key", async () => {
      await seedUser({ password: EXISTING_HASH });
      const key = await mintKey("key-audited", 60_000);

      await redeem.redeemRecoveryKey(key);
      await redeem.redeemRecoveryKey(key);

      const events = await db.auditLog.findMany({
        where: { userId: USER, action: "recover" },
        select: { status: true, source: true, metadata: true },
      });
      expect(events.every((e) => e.source === "recovery")).toBe(true);
      expect(events.filter((e) => e.status === "failure")).toHaveLength(1);
      expect(
        events.filter(
          (e) => (e.metadata as { event?: string } | null)?.event === "entered",
        ),
      ).toHaveLength(1);
      expect(
        events.filter(
          (e) =>
            (e.metadata as { recoveryTokenId?: string } | null)
              ?.recoveryTokenId !== undefined,
        ),
      ).toHaveLength(1);
    });
  },
);
