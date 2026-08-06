import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { proofDatabaseUrl } from "../testing/pg-proof.js";

/**
 * Login-time role resolution against real PostgreSQL.
 *
 * The property under test is what happens on the *second* login, once the
 * directory has changed: a grant that is never re-evaluated is a grant that can
 * never be revoked. The mocked suite asserts the first login only.
 *
 * Env-gated like the other proof suites; see pg-proof.ts.
 */

const PROOF_URL = proofDatabaseUrl();

type Db = typeof import("@onecli/db").db;
type Membership = typeof import("./session-membership");
type OrgService = typeof import("./organization-service");

let db: Db;
let membership: Membership;
let orgService: OrgService;

const P = "smem-";
const SSO_USER = `${P}sso`;
const PASSWORD_USER = `${P}pw`;
const OWNER_USER = `${P}owner`;
const GROUP = `${P}engineers`;

let orgId: string;

/** An unsigned JWT — only the payload is ever read, and only from our own row. */
const idToken = (claims: Record<string, unknown>) =>
  [
    Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url"),
    Buffer.from(JSON.stringify(claims)).toString("base64url"),
    "",
  ].join(".");

const reset = async () => {
  await db.auditLog.deleteMany({ where: { userId: { startsWith: P } } });
  await db.groupRoleMapping.deleteMany({ where: { organizationId: orgId } });
  await db.groupMember.deleteMany({ where: { userId: { startsWith: P } } });
  await db.group.deleteMany({ where: { name: { startsWith: P } } });
  await db.organizationMember.deleteMany({
    where: { userId: { startsWith: P } },
  });
  await db.authAccount.deleteMany({ where: { userId: { startsWith: P } } });
  await db.user.deleteMany({ where: { id: { startsWith: P } } });
};

const seedUser = (id: string) =>
  db.user.create({
    data: { id, email: `${id}@proof.test`, name: id, externalAuthId: id },
  });

/** Give the user a directory identity carrying these group names. */
const seedSsoAccount = (userId: string, groups: string[]) =>
  db.authAccount.create({
    data: {
      userId,
      providerId: "oidc",
      accountId: userId,
      idToken: idToken({ sub: userId, groups }),
    },
  });

const seedPasswordAccount = (userId: string) =>
  db.authAccount.create({
    data: {
      userId,
      providerId: "credential",
      accountId: userId,
      password: "argon2-hash-placeholder",
    },
  });

/** Map a directory group name to a role in the shared org. */
const seedMapping = async (name: string, role: string) => {
  const group = await db.group.create({
    data: { id: `${P}g-${role}`, organizationId: orgId, name },
  });
  await db.groupRoleMapping.create({
    data: { organizationId: orgId, groupId: group.id, role, priority: 10 },
  });
};

const sync = (id: string) =>
  membership.ossSessionMembership(
    { id, email: `${id}@proof.test` },
    { id, email: `${id}@proof.test`, name: id },
  );

const memberRow = (userId: string) =>
  db.organizationMember.findFirst({
    where: { userId },
    select: { role: true, status: true },
  });

beforeAll(async () => {
  if (!PROOF_URL) return;
  process.env.DATABASE_URL = PROOF_URL;

  ({ db } = await import("@onecli/db"));
  membership = await import("./session-membership");
  orgService = await import("./organization-service");

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
});

describe.skipIf(!PROOF_URL)("login-time role resolution", () => {
  it("admits a mapped identity at its resolved role", async () => {
    await seedUser(SSO_USER);
    await seedSsoAccount(SSO_USER, [GROUP]);
    await seedMapping(GROUP, "admin");

    await sync(SSO_USER);

    expect(await memberRow(SSO_USER)).toMatchObject({
      role: "admin",
      status: "active",
    });
  });

  it("revokes access when the user leaves every mapped group", async () => {
    await seedUser(SSO_USER);
    const account = await seedSsoAccount(SSO_USER, [GROUP]);
    await seedMapping(GROUP, "admin");
    await sync(SSO_USER);
    expect(await memberRow(SSO_USER)).toMatchObject({ status: "active" });

    // The next login carries a token with no groups.
    await db.authAccount.update({
      where: { id: account.id },
      data: { idToken: idToken({ sub: SSO_USER, groups: [] }) },
    });
    await sync(SSO_USER);

    // Without this the grant survives every revocation after the first login.
    expect(await memberRow(SSO_USER)).toMatchObject({ status: "suspended" });
  });

  it("revokes access when the mapping itself is deleted", async () => {
    await seedUser(SSO_USER);
    await seedSsoAccount(SSO_USER, [GROUP]);
    await seedMapping(GROUP, "member");
    await sync(SSO_USER);

    await db.groupRoleMapping.deleteMany({ where: { organizationId: orgId } });
    await sync(SSO_USER);

    expect(await memberRow(SSO_USER)).toMatchObject({ status: "suspended" });
  });

  it("reinstates access when the directory grants it again", async () => {
    await seedUser(SSO_USER);
    const account = await seedSsoAccount(SSO_USER, []);
    await seedMapping(GROUP, "member");
    await orgService.ensureSharedOrgMembership(
      SSO_USER,
      `${SSO_USER}@proof.test`,
      "member",
    );

    await sync(SSO_USER);
    expect(await memberRow(SSO_USER)).toMatchObject({ status: "suspended" });

    await db.authAccount.update({
      where: { id: account.id },
      data: { idToken: idToken({ sub: SSO_USER, groups: [GROUP] }) },
    });
    await sync(SSO_USER);

    expect(await memberRow(SSO_USER)).toMatchObject({
      role: "member",
      status: "active",
    });
  });

  it("never suspends an owner, whatever the directory says", async () => {
    await seedUser(OWNER_USER);
    await seedSsoAccount(OWNER_USER, []);
    await orgService.ensureSharedOrgMembership(
      OWNER_USER,
      `${OWNER_USER}@proof.test`,
      "owner",
    );

    await sync(OWNER_USER);

    // Otherwise anyone who can edit the directory can lock the operator out of
    // their own instance.
    expect(await memberRow(OWNER_USER)).toMatchObject({
      role: "owner",
      status: "active",
    });
  });

  it("leaves a password-only account alone", async () => {
    await seedUser(PASSWORD_USER);
    await seedPasswordAccount(PASSWORD_USER);
    await orgService.ensureSharedOrgMembership(
      PASSWORD_USER,
      `${PASSWORD_USER}@proof.test`,
      "admin",
    );

    await sync(PASSWORD_USER);

    // It has no id_token, so the directory has no opinion about it. Reading
    // that absence as "no groups" would suspend the bootstrap admin on their
    // next login and leave nobody able to administer the instance.
    expect(await memberRow(PASSWORD_USER)).toMatchObject({
      role: "admin",
      status: "active",
    });
  });

  it("audits a revocation", async () => {
    await seedUser(SSO_USER);
    const account = await seedSsoAccount(SSO_USER, [GROUP]);
    await seedMapping(GROUP, "admin");
    await sync(SSO_USER);

    await db.authAccount.update({
      where: { id: account.id },
      data: { idToken: idToken({ sub: SSO_USER, groups: [] }) },
    });
    await sync(SSO_USER);

    const entry = await db.auditLog.findFirst({
      where: { userId: SSO_USER, service: "member", action: "delete" },
      select: { source: true, metadata: true },
    });
    expect(entry?.source).toBe("sso-login");
    expect(entry?.metadata).toMatchObject({ from: "admin" });
  });

  it("is idempotent — an unchanged directory writes nothing new", async () => {
    await seedUser(SSO_USER);
    await seedSsoAccount(SSO_USER, [GROUP]);
    await seedMapping(GROUP, "admin");

    await sync(SSO_USER);
    await sync(SSO_USER);
    await sync(SSO_USER);

    const audits = await db.auditLog.count({ where: { userId: SSO_USER } });
    expect(audits).toBe(1);
  });
});

describe.skipIf(!PROOF_URL)("the session enforcer", () => {
  it("denies a membership held in a different organization", async () => {
    await seedUser(SSO_USER);
    const other = await db.organization.create({
      data: { id: `${P}other-org`, name: `${P}other`, slug: `${P}other` },
    });
    await db.organizationMember.create({
      data: {
        organizationId: other.id,
        userId: SSO_USER,
        userEmail: `${SSO_USER}@proof.test`,
        role: "admin",
      },
    });

    const denial = await membership.ossSessionEnforcer(
      { id: SSO_USER, email: `${SSO_USER}@proof.test` },
      { id: SSO_USER, email: `${SSO_USER}@proof.test` },
    );

    // A membership of some other org is not a grant on this instance.
    expect(denial?.code).toBe("NOT_AUTHORISED");

    await db.organizationMember.deleteMany({ where: { userId: SSO_USER } });
    await db.organization.delete({ where: { id: other.id } });
  });

  it("denies a suspended member of the shared org", async () => {
    await seedUser(SSO_USER);
    await orgService.ensureSharedOrgMembership(
      SSO_USER,
      `${SSO_USER}@proof.test`,
      "admin",
    );
    await db.organizationMember.updateMany({
      where: { userId: SSO_USER },
      data: { status: "suspended" },
    });

    const denial = await membership.ossSessionEnforcer(
      { id: SSO_USER, email: `${SSO_USER}@proof.test` },
      { id: SSO_USER, email: `${SSO_USER}@proof.test` },
    );

    expect(denial?.code).toBe("NOT_AUTHORISED");
  });

  it("admits an active member of the shared org", async () => {
    await seedUser(SSO_USER);
    await orgService.ensureSharedOrgMembership(
      SSO_USER,
      `${SSO_USER}@proof.test`,
      "member",
    );

    await expect(
      membership.ossSessionEnforcer(
        { id: SSO_USER, email: `${SSO_USER}@proof.test` },
        { id: SSO_USER, email: `${SSO_USER}@proof.test` },
      ),
    ).resolves.toBeNull();
  });
});
