import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { proofDatabaseUrl } from "../../testing/pg-proof.js";

/**
 * The two dynamic group modes against real PostgreSQL.
 *
 * The property under test is that neither mode is backed by rows: an all-users
 * group admits a member who is in no group, and an all-projects group admits
 * them to a project created after the group existed. A materialised
 * implementation passes the first case and fails the last.
 *
 * Env-gated like the other proof suites; see pg-proof.ts.
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

const P = "gmode-";
const ORG = `${P}org`;
const OTHER_ORG = `${P}other-org`;
const ALICE = `${P}alice`;
const BOB = `${P}bob`;
const BOB_PROJECT = `${P}bob-proj`;

const scope = (projectId: string) => new Headers({ "x-project-id": projectId });

const reset = async () => {
  await db.projectAccess.deleteMany({
    where: { project: { id: { startsWith: P } } },
  });
  await db.groupMember.deleteMany({ where: { userId: { startsWith: P } } });
  await db.group.deleteMany({ where: { id: { startsWith: P } } });
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

const seedMember = (userId: string, role = "member") =>
  db.organizationMember.create({
    data: {
      organizationId: ORG,
      userId,
      userEmail: `${userId}@proof.test`,
      role,
    },
  });

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

const seedGroup = (
  id: string,
  modes: {
    membershipMode?: string;
    projectAccessMode?: string;
    organizationId?: string;
  } = {},
) =>
  db.group.create({
    data: {
      id,
      organizationId: modes.organizationId ?? ORG,
      name: id,
      membershipMode: modes.membershipMode ?? "explicit",
      projectAccessMode: modes.projectAccessMode ?? "selected",
    },
  });

const bindGroupToProject = (groupId: string, projectId: string) =>
  db.projectAccess.create({ data: { projectId, groupId } });

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

  await db.organization.create({ data: { id: ORG, name: ORG, slug: ORG } });
  await db.organization.create({
    data: { id: OTHER_ORG, name: OTHER_ORG, slug: OTHER_ORG },
  });
  await seedUser(ALICE);
  await seedUser(BOB);
  await seedMember(ALICE);
  await seedMember(BOB);
  await seedProject(BOB_PROJECT, BOB);
});

describe.skipIf(!PROOF_URL)("group modes on real PostgreSQL", () => {
  it("an explicit group with no member does not admit", async () => {
    const group = await seedGroup(`${P}g-explicit`);
    await bindGroupToProject(group.id, BOB_PROJECT);

    await expect(
      resolve.resolveProjectId(scope(BOB_PROJECT), ALICE),
    ).resolves.toBeNull();
  });

  it("an all-users group admits a member who is in no group", async () => {
    const group = await seedGroup(`${P}g-everyone`, {
      membershipMode: "all-users",
    });
    await bindGroupToProject(group.id, BOB_PROJECT);

    await expect(
      resolve.resolveProjectId(scope(BOB_PROJECT), ALICE),
    ).resolves.toBe(BOB_PROJECT);

    // The admission came from the mode, not from a row written on Alice's behalf.
    await expect(
      db.groupMember.count({ where: { groupId: group.id } }),
    ).resolves.toBe(0);
  });

  it("an all-users group does not admit a suspended member", async () => {
    const group = await seedGroup(`${P}g-everyone`, {
      membershipMode: "all-users",
    });
    await bindGroupToProject(group.id, BOB_PROJECT);
    await db.organizationMember.update({
      where: { organizationId_userId: { organizationId: ORG, userId: ALICE } },
      data: { status: "suspended" },
    });

    await expect(
      resolve.resolveProjectId(scope(BOB_PROJECT), ALICE),
    ).resolves.toBeNull();
  });

  it("an all-projects group admits its member to a project it is not bound to", async () => {
    const group = await seedGroup(`${P}g-unrestricted`, {
      projectAccessMode: "all-projects",
    });
    await db.groupMember.create({ data: { groupId: group.id, userId: ALICE } });

    await expect(
      resolve.resolveProjectId(scope(BOB_PROJECT), ALICE),
    ).resolves.toBe(BOB_PROJECT);

    // "All projects" cannot be expressed as rows, so there must be none.
    await expect(
      db.projectAccess.count({ where: { groupId: group.id } }),
    ).resolves.toBe(0);
  });

  it("an all-projects group reaches a project created after it", async () => {
    const group = await seedGroup(`${P}g-unrestricted`, {
      projectAccessMode: "all-projects",
    });
    await db.groupMember.create({ data: { groupId: group.id, userId: ALICE } });

    const later = await seedProject(`${P}later-proj`, BOB);

    // This is the case a backfill cannot cover: the project did not exist when
    // the group was granted access.
    await expect(
      resolve.resolveProjectId(scope(later.id), ALICE),
    ).resolves.toBe(later.id);
  });

  it("all-users and all-projects together admit every member everywhere", async () => {
    await seedGroup(`${P}g-open`, {
      membershipMode: "all-users",
      projectAccessMode: "all-projects",
    });

    await expect(
      resolve.resolveProjectId(scope(BOB_PROJECT), ALICE),
    ).resolves.toBe(BOB_PROJECT);
  });

  it("a group in another organization admits nobody here", async () => {
    const group = await seedGroup(`${P}g-foreign`, {
      organizationId: OTHER_ORG,
      membershipMode: "all-users",
      projectAccessMode: "all-projects",
    });
    await db.groupMember.create({ data: { groupId: group.id, userId: ALICE } });

    await expect(
      resolve.resolveProjectId(scope(BOB_PROJECT), ALICE),
    ).resolves.toBeNull();
  });
});
