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
 * `resolveProjectContext` against real PostgreSQL. Server actions never reach
 * the `/v1/*` middleware, so the header they trust — `x-project-id` — is a
 * second, independent way into a project and needs its own proof.
 *
 * Env-gated like the other proof suites; see pg-proof.ts.
 */

const PROOF_URL = proofDatabaseUrl();

const ctx = vi.hoisted(() => {
  // Read at module load by `@onecli/api/lib/env`, which decides tenancy; CI
  // defaults to `cloud`, where the shared-org fence does not apply.
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
type ResolveUser = typeof import("./resolve-user");
type OrgService = typeof import("@onecli/api/services/organization-service");

let db: Db;
let resolveUser: ResolveUser;
let orgService: OrgService;
let orgId: string;

const P = "srvact-";
const ALICE = `${P}alice`;
const BOB = `${P}bob`;
const ADMIN = `${P}admin`;
const ALICE_PROJECT = `${P}alice-proj`;
const BOB_PROJECT = `${P}bob-proj`;

const NOT_AUTHORISED = /not authorised for this instance/;

const reset = async () => {
  await db.projectAccess.deleteMany({ where: { userId: { startsWith: P } } });
  await db.project.deleteMany({ where: { id: { startsWith: P } } });
  await db.organizationMember.deleteMany({
    where: { userId: { startsWith: P } },
  });
  await db.user.deleteMany({ where: { id: { startsWith: P } } });
};

const seedUser = (id: string) =>
  db.user.create({
    data: { id, email: `${id}@proof.test`, name: id, externalAuthId: id },
  });

const seedMember = (userId: string, role: string, status = "active") =>
  db.organizationMember.create({
    data: {
      organizationId: orgId,
      userId,
      userEmail: `${userId}@proof.test`,
      role,
      status,
    },
  });

/** A project plus its creator's owner binding, as provisioning writes it. */
const seedProject = (id: string, ownerId: string) =>
  db.project.create({
    data: {
      id,
      name: id,
      slug: id,
      organizationId: orgId,
      createdByUserId: ownerId,
      createdByUserEmail: `${ownerId}@proof.test`,
      accessBindings: { create: { userId: ownerId, role: "owner" } },
    },
  });

/** Sign in as `userId` and target `projectId` the way the browser would. */
const asUser = (userId: string, projectId?: string) => {
  ctx.session = { id: userId, email: `${userId}@proof.test` };
  ctx.headers = projectId
    ? new Headers({ "x-project-id": projectId })
    : new Headers();
};

beforeAll(async () => {
  if (!PROOF_URL) return;
  process.env.DATABASE_URL = PROOF_URL;

  ({ db } = await import("@onecli/db"));
  orgService = await import("@onecli/api/services/organization-service");
  // Imports `@/lib/init/server`, which is what registers the role resolver and
  // the session enforcer. A stand-in for either would decide these cases.
  resolveUser = await import("./resolve-user");

  // The enforcer admits members of the shared org only, so the fixture has to
  // be that org — not a private one seeded under the test prefix.
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

  await seedUser(ALICE);
  await seedUser(BOB);
  await seedUser(ADMIN);
  await seedProject(ALICE_PROJECT, ALICE);
  await seedProject(BOB_PROJECT, BOB);
});

describe.skipIf(!PROOF_URL)("resolveProjectContext on real PostgreSQL", () => {
  it("a member reaches their own project", async () => {
    await seedMember(ALICE, "member");
    asUser(ALICE, ALICE_PROJECT);

    await expect(resolveUser.resolveProjectContext()).resolves.toEqual({
      userId: ALICE,
      userEmail: `${ALICE}@proof.test`,
      organizationId: orgId,
      projectId: ALICE_PROJECT,
    });
  });

  it("a member does NOT reach another member's project via x-project-id", async () => {
    await seedMember(ALICE, "member");
    await seedMember(BOB, "member");
    asUser(BOB, ALICE_PROJECT);

    // Both share the one organization, so "a project in my org" admits Bob
    // to everything. The binding check is the only thing that refuses.
    await expect(resolveUser.resolveProjectContext()).rejects.toThrow(
      "No project found",
    );
  });

  it("an admin reaches any project in the org", async () => {
    await seedMember(ADMIN, "admin");
    asUser(ADMIN, ALICE_PROJECT);

    await expect(resolveUser.resolveProjectContext()).resolves.toMatchObject({
      userId: ADMIN,
      projectId: ALICE_PROJECT,
    });
  });

  it("a suspended member is refused, including for their own project", async () => {
    await seedMember(ALICE, "member", "suspended");
    asUser(ALICE, ALICE_PROJECT);

    await expect(resolveUser.resolveProjectContext()).rejects.toThrow(
      NOT_AUTHORISED,
    );
  });

  it("an identity with no membership is refused", async () => {
    asUser(ALICE, ALICE_PROJECT);

    await expect(resolveUser.resolveProjectContext()).rejects.toThrow(
      NOT_AUTHORISED,
    );
  });
});
