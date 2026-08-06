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
 * Recovery-key redemption against real PostgreSQL. Single-use is a conditional
 * update and expiry is a column comparison, so neither is settled by a mock.
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
const PASSWORD = "a-perfectly-fine-passphrase";

const hashKey = (key: string) => createHash("sha256").update(key).digest("hex");

const reset = async () => {
  await db.auditLog.deleteMany({ where: { userId: { startsWith: P } } });
  await db.recoveryToken.deleteMany({ where: { userId: { startsWith: P } } });
  await db.authSession.deleteMany({ where: { userId: { startsWith: P } } });
  await db.authAccount.deleteMany({ where: { userId: { startsWith: P } } });
  await db.user.deleteMany({ where: { id: { startsWith: P } } });
};

const seedUser = (mustChangePassword = false) =>
  db.user.create({
    data: {
      id: USER,
      email: EMAIL,
      name: USER,
      externalAuthId: USER,
      mustChangePassword,
    },
  });

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

    it("a valid key sets the password and marks itself used", async () => {
      await seedUser();
      const key = await mintKey("key-happy", 60_000);

      await expect(
        redeem.redeemRecoveryKey(key, PASSWORD),
      ).resolves.toMatchObject({ ok: true });

      const token = await db.recoveryToken.findUnique({
        where: { tokenHash: hashKey(key) },
        select: { usedAt: true },
      });
      expect(token?.usedAt).not.toBeNull();

      const account = await db.authAccount.findFirst({
        where: { userId: USER, providerId: "credential" },
        select: { password: true },
      });
      expect(account?.password).toBeTruthy();
      // Stored as a PHC hash, never the password itself.
      expect(account?.password).toMatch(/^\$argon2id\$/);
    });

    it("a second use of the same key is refused", async () => {
      await seedUser();
      const key = await mintKey("key-once", 60_000);

      await expect(
        redeem.redeemRecoveryKey(key, PASSWORD),
      ).resolves.toMatchObject({ ok: true });

      await expect(
        redeem.redeemRecoveryKey(key, "a-different-passphrase"),
      ).resolves.toMatchObject({ ok: false });
    });

    it("an expired key is refused, and does not become used", async () => {
      await seedUser();
      const key = await mintKey("key-expired", -1_000);

      await expect(
        redeem.redeemRecoveryKey(key, PASSWORD),
      ).resolves.toMatchObject({ ok: false });

      const token = await db.recoveryToken.findUnique({
        where: { tokenHash: hashKey(key) },
        select: { usedAt: true },
      });
      expect(token?.usedAt).toBeNull();
    });

    it("an unknown key is refused and writes no credential", async () => {
      await seedUser();

      await expect(
        redeem.redeemRecoveryKey("never-minted", PASSWORD),
      ).resolves.toMatchObject({ ok: false });

      await expect(
        db.authAccount.count({ where: { userId: USER } }),
      ).resolves.toBe(0);
    });

    it("concurrent redemptions of one key admit exactly one", async () => {
      await seedUser();
      const key = await mintKey("key-race", 60_000);

      const results = await Promise.all(
        Array.from({ length: 8 }, (_, i) =>
          redeem.redeemRecoveryKey(key, `${PASSWORD}-${i}`),
        ),
      );

      expect(results.filter((r) => r.ok)).toHaveLength(1);
    });

    it("clears mustChangePassword, so recovery does not land in a rotation loop", async () => {
      await seedUser(true);
      const key = await mintKey("key-rotate", 60_000);

      await expect(
        redeem.redeemRecoveryKey(key, PASSWORD),
      ).resolves.toMatchObject({ ok: true });

      const user = await db.user.findUnique({
        where: { id: USER },
        select: { mustChangePassword: true },
      });
      expect(user?.mustChangePassword).toBe(false);
    });

    it("audits the redemption, and audits a spent key too", async () => {
      await seedUser();
      const key = await mintKey("key-audited", 60_000);

      await redeem.redeemRecoveryKey(key, PASSWORD);
      await redeem.redeemRecoveryKey(key, PASSWORD);

      const events = await db.auditLog.findMany({
        where: { userId: USER, action: "recover" },
        select: { status: true, source: true },
      });
      expect(events.map((e) => e.status).sort()).toEqual([
        "failure",
        "success",
      ]);
      expect(events.every((e) => e.source === "recovery")).toBe(true);
    });

    it("revokes existing sessions, since the old credential may be why recovery was needed", async () => {
      await seedUser();
      await db.authSession.create({
        data: {
          id: `${P}stale`,
          userId: USER,
          token: `${P}stale-token`,
          expiresAt: new Date(Date.now() + 3_600_000),
        },
      });
      const key = await mintKey("key-revoke", 60_000);

      await redeem.redeemRecoveryKey(key, PASSWORD);

      await expect(
        db.authSession.count({ where: { id: `${P}stale` } }),
      ).resolves.toBe(0);
    });
  },
);
