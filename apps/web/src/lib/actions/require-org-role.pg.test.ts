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
 * `requireOrgRole` against real PostgreSQL. Server actions never reach the
 * `/v1/*` middleware, so this is the only gate standing between a signed-in
 * member and an admin-only setting — and the path Phase 2c's password-login
 * switch is built on.
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
type RequireOrgRole = typeof import("./require-org-role");
type OrgService = typeof import("@onecli/api/services/organization-service");

let db: Db;
let guard: RequireOrgRole;
let orgService: OrgService;
let orgId: string;

const P = "reqrole-";
const OWNER = `${P}owner`;
const ADMIN = `${P}admin`;
const MEMBER = `${P}member`;

const reset = async () => {
  await db.projectAccess.deleteMany({ where: { userId: { startsWith: P } } });
  await db.project.deleteMany({ where: { id: { startsWith: P } } });
  await db.organizationMember.deleteMany({
    where: { userId: { startsWith: P } },
  });
  await db.user.deleteMany({ where: { id: { startsWith: P } } });
};

/** A user with a membership at `role` and a project, as provisioning writes it. */
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

/** Sign in as this user for the next call. */
const as = (userId: string) => {
  ctx.session = { id: userId, email: `${userId}@proof.test` };
};

beforeAll(async () => {
  if (!PROOF_URL) return;
  process.env.DATABASE_URL = PROOF_URL;

  ({ db } = await import("@onecli/db"));
  guard = await import("./require-org-role");
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

  await seed(OWNER, "owner");
  await seed(ADMIN, "admin");
  await seed(MEMBER, "member");
});

describe.skipIf(!PROOF_URL)("requireOrgRole on real PostgreSQL", () => {
  it("refuses a member asking for admin", async () => {
    as(MEMBER);
    await expect(guard.requireOrgRole("admin")).rejects.toThrow(
      /requires the admin role/,
    );
  });

  it("refuses an admin asking for owner — D-16 holds on this path too", async () => {
    as(ADMIN);
    await expect(guard.requireOrgRole("owner")).rejects.toThrow(
      /requires the owner role/,
    );
  });

  it("admits an admin and hands back the resolved role", async () => {
    as(ADMIN);
    await expect(guard.requireOrgRole("admin")).resolves.toMatchObject({
      userId: ADMIN,
      organizationId: orgId,
      role: "admin",
    });
  });

  it("admits an owner asking for admin, at their real role", async () => {
    as(OWNER);
    await expect(guard.requireOrgRole("admin")).resolves.toMatchObject({
      role: "owner",
    });
  });

  it("refuses a suspended admin", async () => {
    await db.organizationMember.update({
      where: {
        organizationId_userId: { organizationId: orgId, userId: ADMIN },
      },
      data: { status: "suspended" },
    });
    as(ADMIN);

    // The session enforcer refuses before the role is ever read; either way the
    // action must not run.
    await expect(guard.requireOrgRole("admin")).rejects.toThrow();
  });

  it("refuses when nobody is signed in", async () => {
    ctx.session = null;
    await expect(guard.requireOrgRole("admin")).rejects.toThrow(
      /Not authenticated/,
    );
  });
});
