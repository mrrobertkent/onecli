import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { proofDatabaseUrl } from "../../testing/pg-proof.js";

/**
 * `resolveProjectId` against real PostgreSQL. Under shared tenancy every user is
 * in one organization, so org membership alone admits everybody to everything;
 * the fence is the ProjectAccess binding check inside `canAccessProjectAsUser`,
 * which only applies when a role resolver is registered.
 */

const PROOF_URL = proofDatabaseUrl();

type Db = typeof import("@onecli/db").db;
type Providers = typeof import("../../providers");
type Resolve = typeof import("./resolve");
type RoleResolution = typeof import("../../services/role-resolution");

let db: Db;
let providers: Providers;
let resolve: Resolve;
let roleResolution: RoleResolution;

const P = "rslv-";
const ORG = `${P}org`;
const ALICE = `${P}alice`;
const BOB = `${P}bob`;
const ADMIN = `${P}admin`;
const ALICE_PROJECT = `${P}alice-proj`;
const BOB_PROJECT = `${P}bob-proj`;

const scope = (projectId: string) => new Headers({ "x-project-id": projectId });

const reset = async () => {
  await db.projectAccess.deleteMany({ where: { userId: { startsWith: P } } });
  await db.project.deleteMany({ where: { id: { startsWith: P } } });
  await db.organizationMember.deleteMany({
    where: { userId: { startsWith: P } },
  });
  await db.user.deleteMany({ where: { id: { startsWith: P } } });
  await db.organization.deleteMany({ where: { id: { startsWith: P } } });
};

const seedUser = (id: string) =>
  db.user.create({
    data: { id, email: `${id}@proof.test`, name: id, externalAuthId: id },
  });

const seedMember = (userId: string, role: string, status = "active") =>
  db.organizationMember.create({
    data: {
      organizationId: ORG,
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
      organizationId: ORG,
      createdByUserId: ownerId,
      createdByUserEmail: `${ownerId}@proof.test`,
      accessBindings: { create: { userId: ownerId, role: "owner" } },
    },
  });

beforeAll(async () => {
  if (!PROOF_URL) return;
  process.env.DATABASE_URL = PROOF_URL;

  ({ db } = await import("@onecli/db"));
  providers = await import("../../providers");
  resolve = await import("./resolve");
  roleResolution = await import("../../services/role-resolution");

  providers.initRoleResolver(roleResolution.ossRoleResolver);
  await reset();
});

afterAll(async () => {
  if (!PROOF_URL) return;
  await reset();
});

beforeEach(async () => {
  if (!PROOF_URL) return;
  await reset();

  await db.organization.create({
    data: { id: ORG, name: ORG, slug: ORG },
  });
  await seedUser(ALICE);
  await seedUser(BOB);
  await seedUser(ADMIN);
  await seedProject(ALICE_PROJECT, ALICE);
  await seedProject(BOB_PROJECT, BOB);
});

describe.skipIf(!PROOF_URL)("resolveProjectId on real PostgreSQL", () => {
  it("a member reaches their own project", async () => {
    await seedMember(ALICE, "member");

    await expect(
      resolve.resolveProjectId(scope(ALICE_PROJECT), ALICE),
    ).resolves.toBe(ALICE_PROJECT);
  });

  it("a member does NOT reach another member's project in the same org", async () => {
    await seedMember(ALICE, "member");
    await seedMember(BOB, "member");

    // Alice belongs to the org Bob's project lives in, so org membership
    // alone would admit her. The binding check is what refuses.
    await expect(
      resolve.resolveProjectId(scope(BOB_PROJECT), ALICE),
    ).resolves.toBeNull();
  });

  it("an admin reaches any project in the org", async () => {
    await seedMember(ADMIN, "admin");

    await expect(
      resolve.resolveProjectId(scope(BOB_PROJECT), ADMIN),
    ).resolves.toBe(BOB_PROJECT);
  });

  it("a suspended member reaches nothing, including their own project", async () => {
    await seedMember(ALICE, "member", "suspended");

    await expect(
      resolve.resolveProjectId(scope(ALICE_PROJECT), ALICE),
    ).resolves.toBeNull();
  });

  it("a suspended admin reaches nothing", async () => {
    await seedMember(ADMIN, "admin", "suspended");

    await expect(
      resolve.resolveProjectId(scope(BOB_PROJECT), ADMIN),
    ).resolves.toBeNull();
  });

  it("a non-member reaches nothing", async () => {
    await expect(
      resolve.resolveProjectId(scope(ALICE_PROJECT), ALICE),
    ).resolves.toBeNull();
  });

  it("with no header, a member falls back to their own default project", async () => {
    await seedMember(ALICE, "member");

    await expect(resolve.resolveProjectId(new Headers(), ALICE)).resolves.toBe(
      ALICE_PROJECT,
    );
  });
});
