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
import type { OrgRole } from "@onecli/api/providers";

/**
 * The administrator switch for password login, against real PostgreSQL.
 *
 * Two things have to hold at once and neither is settled by the other: a member
 * cannot change an instance setting, and nobody at any role can turn off the
 * last way in. The second is what makes the first safe to have at all.
 *
 * Env-gated like the other proof suites; see pg-proof.ts.
 */

const PROOF_URL = proofDatabaseUrl();

const ctx = vi.hoisted(() => {
  process.env.NEXT_PUBLIC_EDITION = "oss";
  return {
    headers: new Headers(),
    session: null as { id: string; email: string } | null,
  };
});

vi.mock("next/headers", () => ({ headers: async () => ctx.headers }));
vi.mock("@/lib/auth/server", () => ({
  getServerSession: async () => ctx.session,
}));

type Db = typeof import("@onecli/db").db;
type Actions = typeof import("./login-methods");
type OrgService = typeof import("@onecli/api/services/organization-service");

let db: Db;
let actions: Actions;
let orgService: OrgService;
let orgId: string;

const P = "lgnmeth-";
const ADMIN = `${P}admin`;
const MEMBER = `${P}member`;

const reset = async () => {
  await db.auditLog.deleteMany({ where: { userId: { startsWith: P } } });
  await db.projectAccess.deleteMany({ where: { userId: { startsWith: P } } });
  await db.project.deleteMany({ where: { id: { startsWith: P } } });
  await db.organizationMember.deleteMany({
    where: { userId: { startsWith: P } },
  });
  await db.user.deleteMany({ where: { id: { startsWith: P } } });
  // Only the column this suite drives; the row is shared with every other one.
  await db.instanceSetting.updateMany({ data: { passwordLoginEnabled: true } });
};

const seed = async (id: string, role: OrgRole) => {
  await db.user.create({
    data: { id, email: `${id}@proof.test`, name: id, externalAuthId: id },
  });
  await orgService.ensureSharedOrgMembership(id, `${id}@proof.test`, role);
  await db.project.create({
    data: {
      id: `${id}-proj`,
      name: id,
      slug: `${id}-proj`,
      organizationId: orgId,
      createdByUserId: id,
      createdByUserEmail: `${id}@proof.test`,
      accessBindings: { create: { userId: id, role: "owner" } },
    },
  });
};

const as = (userId: string) => {
  ctx.session = { id: userId, email: `${userId}@proof.test` };
};

const storedSetting = async () =>
  (
    await db.instanceSetting.findUnique({
      where: { id: "instance" },
      select: { passwordLoginEnabled: true },
    })
  )?.passwordLoginEnabled;

beforeAll(async () => {
  if (!PROOF_URL) return;
  process.env.DATABASE_URL = PROOF_URL;
  // An instance that has somewhere else to send people. Without this, refusing
  // to turn password login off is the only possible answer and the role check
  // would never be the thing under test.
  process.env.OIDC_ISSUER = "http://127.0.0.1:9/idp";
  process.env.OIDC_CLIENT_ID = "proof-client";
  process.env.OIDC_CLIENT_SECRET = "proof-client-secret";

  ({ db } = await import("@onecli/db"));
  actions = await import("./login-methods");
  orgService = await import("@onecli/api/services/organization-service");

  ({ id: orgId } = await orgService.findOrCreateSharedOrg());
  await reset();
});

afterAll(async () => {
  if (!PROOF_URL) return;
  await reset();
});

beforeEach(async () => {
  if (!PROOF_URL) return;
  await reset();
  ctx.session = null;
  await seed(ADMIN, "admin");
  await seed(MEMBER, "member");
});

describe.skipIf(!PROOF_URL)(
  "the login-methods switch on real PostgreSQL",
  () => {
    it("a member cannot turn password login off, and nothing moves", async () => {
      as(MEMBER);

      await expect(actions.setPasswordLogin(false)).resolves.toMatchObject({
        ok: false,
      });
      await expect(storedSetting()).resolves.toBe(true);
      await expect(
        db.auditLog.count({ where: { userId: MEMBER } }),
      ).resolves.toBe(0);
    });

    it("a member cannot even read the setting", async () => {
      as(MEMBER);
      await expect(actions.getLoginMethods()).rejects.toThrow(
        /requires the admin role/,
      );
    });

    it("an admin turns it off, and the write is audited to them", async () => {
      as(ADMIN);

      await expect(actions.setPasswordLogin(false)).resolves.toMatchObject({
        ok: true,
      });
      await expect(storedSetting()).resolves.toBe(false);

      const events = await db.auditLog.findMany({
        where: { userId: ADMIN, action: "update", service: "auth" },
        select: { source: true, metadata: true },
      });
      expect(events).toHaveLength(1);
      expect(events[0]!.source).toBe("app");
      expect(events[0]!.metadata).toMatchObject({
        passwordLoginEnabled: false,
      });
    });

    it("an admin sees the stored answer, not the one recovery is lending", async () => {
      as(ADMIN);
      await actions.setPasswordLogin(false);
      await db.instanceSetting.updateMany({
        data: {
          recoveryModeExpiresAt: new Date(Date.now() + 60_000),
          recoveryModeUserId: ADMIN,
        },
      });

      try {
        await expect(actions.getLoginMethods()).resolves.toMatchObject({
          passwordLoginEnabled: false,
          lentByRecovery: true,
        });
      } finally {
        await db.instanceSetting.updateMany({
          data: { recoveryModeExpiresAt: null, recoveryModeUserId: null },
        });
      }
    });

    it("nobody turns off the last way in", async () => {
      as(ADMIN);
      delete process.env.OIDC_ISSUER;
      delete process.env.OIDC_CLIENT_ID;
      delete process.env.OIDC_CLIENT_SECRET;
      vi.resetModules();

      try {
        const solo: Actions = await import("./login-methods");
        await expect(solo.setPasswordLogin(false)).resolves.toMatchObject({
          ok: false,
          error: expect.stringContaining("only way into this instance"),
        });
        await expect(storedSetting()).resolves.toBe(true);
      } finally {
        process.env.OIDC_ISSUER = "http://127.0.0.1:9/idp";
        process.env.OIDC_CLIENT_ID = "proof-client";
        process.env.OIDC_CLIENT_SECRET = "proof-client-secret";
        vi.resetModules();
      }
    });
  },
);
