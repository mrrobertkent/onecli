import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { proofDatabaseUrl } from "../testing/pg-proof.js";
import { errorHandler } from "../middleware/error-handler";
import type { ApiEnv } from "../types";

/**
 * The `/v1/org/*` admin surface against real PostgreSQL, driven through the
 * routers so the auth middleware is part of what is proven.
 *
 * Two properties carry the weight: an `admin` cannot write a role mapping —
 * otherwise any admin grants themselves admin through a directory group — and
 * a revocation ends the member's sessions, which are database-backed and so
 * would otherwise outlive the grant they depend on.
 *
 * Env-gated like the other proof suites; see pg-proof.ts.
 */

const PROOF_URL = proofDatabaseUrl();

type Db = typeof import("@onecli/db").db;
type Providers = typeof import("../providers");
type SessionUser = import("../providers/types").SessionUser;

let db: Db;
let providers: Providers;
/** The three routers mounted as `createApiApp` mounts them, error handler and all. */
let app: Hono<ApiEnv>;

const GROUPS = "/v1/org/groups";
const MEMBERS = "/v1/org/members";
const MAPPINGS = "/v1/org/role-mappings";

const P = "oadm-";
const ORG = `${P}org`;
const OWNER = `${P}owner`;
const ADMIN = `${P}admin`;
const MEMBER = `${P}member`;

let currentSession: SessionUser | null = null;

const reset = async () => {
  await db.auditLog.deleteMany({ where: { organizationId: ORG } });
  await db.groupRoleMapping.deleteMany({ where: { organizationId: ORG } });
  await db.groupMember.deleteMany({ where: { userId: { startsWith: P } } });
  await db.group.deleteMany({ where: { organizationId: ORG } });
  await db.authSession.deleteMany({ where: { userId: { startsWith: P } } });
  await db.authAccount.deleteMany({ where: { userId: { startsWith: P } } });
  await db.organizationMember.deleteMany({
    where: { userId: { startsWith: P } },
  });
  await db.user.deleteMany({ where: { id: { startsWith: P } } });
  await db.organization.deleteMany({ where: { id: ORG } });
};

const seedUser = (id: string) =>
  db.user.create({
    data: { id, email: `${id}@proof.test`, name: id, externalAuthId: id },
  });

const seedMember = (userId: string, role: string) =>
  db.organizationMember.create({
    data: {
      organizationId: ORG,
      userId,
      userEmail: `${userId}@proof.test`,
      role,
    },
  });

/** Sign in as this user for the next request. */
const as = (userId: string) => {
  currentSession = { id: userId, email: `${userId}@proof.test` };
};

const headers = {
  "x-organization-id": ORG,
  "content-type": "application/json",
};

const call = async (method: string, path: string, body?: unknown) => {
  const res = await app.request(path, {
    method,
    headers,
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await res.text();
  return {
    status: res.status,
    body: text ? (JSON.parse(text) as Record<string, unknown>) : {},
  };
};

const seedGroup = (name: string) =>
  db.group.create({ data: { organizationId: ORG, name } });

/** An unsigned JWT — only the payload is read, and only from our own row. */
const idToken = (claims: Record<string, unknown>) =>
  [
    Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url"),
    Buffer.from(JSON.stringify(claims)).toString("base64url"),
    "",
  ].join(".");

/** Give a user a directory identity carrying these group names. */
const seedSsoAccount = (userId: string, groups: string[]) =>
  db.authAccount.create({
    data: {
      userId,
      providerId: "oidc",
      accountId: userId,
      idToken: idToken({ sub: userId, groups }),
    },
  });

beforeAll(async () => {
  if (!PROOF_URL) return;
  process.env.DATABASE_URL = PROOF_URL;

  ({ db } = await import("@onecli/db"));
  providers = await import("../providers");
  const roleResolution = await import("../services/role-resolution");
  const { orgGroupRoutes } = await import("./org-groups");
  const { orgMemberRoutes } = await import("./org-members");
  const { orgRoleMappingRoutes } = await import("./org-role-mappings");

  app = new Hono<ApiEnv>().basePath("/v1");
  app.onError(errorHandler);
  app.route("/org/members", orgMemberRoutes());
  app.route("/org/groups", orgGroupRoutes());
  app.route("/org/role-mappings", orgRoleMappingRoutes());

  providers.initSession({ getSession: async () => currentSession });
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
  currentSession = null;

  await db.organization.create({ data: { id: ORG, name: ORG, slug: ORG } });
  await seedUser(OWNER);
  await seedUser(ADMIN);
  await seedUser(MEMBER);
  await seedMember(OWNER, "owner");
  await seedMember(ADMIN, "admin");
  await seedMember(MEMBER, "member");
});

describe.skipIf(!PROOF_URL)("/v1/org/role-mappings authority", () => {
  it("an admin may not create a role mapping", async () => {
    const group = await seedGroup(`${P}engineers`);
    as(ADMIN);

    const res = await call("POST", MAPPINGS, {
      groupId: group.id,
      role: "admin",
    });

    // Without this an admin grants admin to a directory group they can join.
    expect(res.status).toBe(403);
    await expect(
      db.groupRoleMapping.count({ where: { organizationId: ORG } }),
    ).resolves.toBe(0);
  });

  it("an admin may not edit, reorder or delete one either", async () => {
    const group = await seedGroup(`${P}engineers`);
    const mapping = await db.groupRoleMapping.create({
      data: {
        organizationId: ORG,
        groupId: group.id,
        role: "member",
        priority: 1,
      },
    });
    as(ADMIN);

    await expect(
      call("PATCH", `${MAPPINGS}/${mapping.id}`, { role: "admin" }),
    ).resolves.toMatchObject({ status: 403 });
    await expect(
      call("PUT", `${MAPPINGS}/order`, { orderedIds: [mapping.id] }),
    ).resolves.toMatchObject({ status: 403 });
    await expect(
      call("DELETE", `${MAPPINGS}/${mapping.id}`),
    ).resolves.toMatchObject({ status: 403 });

    await expect(
      db.groupRoleMapping.findUnique({ where: { id: mapping.id } }),
    ).resolves.toMatchObject({ role: "member", priority: 1 });
  });

  it("an owner may create one, and it is audited", async () => {
    const group = await seedGroup(`${P}engineers`);
    as(OWNER);

    const res = await call("POST", MAPPINGS, {
      groupId: group.id,
      role: "admin",
    });

    expect(res.status).toBe(201);
    expect(res.body).toMatchObject({ groupId: group.id, role: "admin" });
    await expect(
      db.auditLog.count({
        where: {
          organizationId: ORG,
          service: "role-mapping",
          action: "create",
        },
      }),
    ).resolves.toBe(1);
  });

  it("no mapping may confer owner", async () => {
    const group = await seedGroup(`${P}engineers`);
    as(OWNER);

    const res = await call("POST", MAPPINGS, {
      groupId: group.id,
      role: "owner",
    });

    expect(res.status).toBe(400);
    await expect(
      db.groupRoleMapping.count({ where: { organizationId: ORG } }),
    ).resolves.toBe(0);
  });

  it("a group maps to at most one role", async () => {
    const group = await seedGroup(`${P}engineers`);
    as(OWNER);
    await call("POST", MAPPINGS, { groupId: group.id, role: "member" });

    const res = await call("POST", MAPPINGS, {
      groupId: group.id,
      role: "admin",
    });

    expect(res.status).toBe(409);
  });

  it("a new mapping never outranks one that already exists", async () => {
    const first = await seedGroup(`${P}first`);
    const second = await seedGroup(`${P}second`);
    as(OWNER);

    await call("POST", MAPPINGS, { groupId: first.id, role: "admin" });
    await call("POST", MAPPINGS, {
      groupId: second.id,
      role: "member",
    });

    const list = await call("GET", MAPPINGS);
    const rows = list.body as unknown as { groupId: string }[];
    expect(rows.map((r) => r.groupId)).toEqual([first.id, second.id]);
  });

  it("reordering puts index 0 highest", async () => {
    const first = await seedGroup(`${P}first`);
    const second = await seedGroup(`${P}second`);
    as(OWNER);
    const a = await call("POST", MAPPINGS, {
      groupId: first.id,
      role: "admin",
    });
    const b = await call("POST", MAPPINGS, {
      groupId: second.id,
      role: "member",
    });

    const res = await call("PUT", `${MAPPINGS}/order`, {
      orderedIds: [b.body.id, a.body.id],
    });

    expect(res.status).toBe(200);
    const rows = res.body as unknown as { groupId: string }[];
    expect(rows.map((r) => r.groupId)).toEqual([second.id, first.id]);
  });
});

describe.skipIf(!PROOF_URL)("/v1/org/role-mappings preview", () => {
  it("counts nobody when no member signs in through the directory", async () => {
    const group = await seedGroup(`${P}engineers`);
    as(ADMIN);

    const res = await call("POST", `${MAPPINGS}/preview`, {
      groupId: group.id,
      role: "admin",
    });

    // A password account has no id_token; login would leave it exactly as it is.
    expect(res.body).toMatchObject({ affectedCount: 0 });
  });

  it("counts the members whose resolved role would change", async () => {
    const group = await seedGroup(`${P}engineers`);
    // The member is in the directory group and would become an admin; the
    // second identity is in no group and would stay as it is.
    await seedSsoAccount(MEMBER, [`${P}engineers`]);
    await seedSsoAccount(ADMIN, [`${P}engineers`]);
    as(ADMIN);

    const res = await call("POST", `${MAPPINGS}/preview`, {
      groupId: group.id,
      role: "admin",
    });

    expect(res.body).toMatchObject({ affectedCount: 1 });
  });

  it("counts an unmapped identity as losing its access", async () => {
    const group = await seedGroup(`${P}engineers`);
    await seedSsoAccount(MEMBER, [`${P}other-team`]);
    as(ADMIN);

    const res = await call("POST", `${MAPPINGS}/preview`, {
      groupId: group.id,
      role: "member",
    });

    // Nothing would map them, so their next login suspends them.
    expect(res.body).toMatchObject({ affectedCount: 1 });
  });
});

describe.skipIf(!PROOF_URL)("/v1/org/members", () => {
  it("revoking a member deletes their sessions", async () => {
    await db.authSession.createMany({
      data: [
        {
          userId: MEMBER,
          token: `${P}tok-1`,
          expiresAt: new Date(Date.now() + 86_400_000),
        },
        {
          userId: MEMBER,
          token: `${P}tok-2`,
          expiresAt: new Date(Date.now() + 86_400_000),
        },
      ],
    });
    as(ADMIN);

    const res = await call("PATCH", `${MEMBERS}/${MEMBER}`, {
      status: "suspended",
    });

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: "suspended", sessionsRevoked: 2 });
    // Sessions are database-backed, so leaving them is leaving the access.
    await expect(
      db.authSession.count({ where: { userId: MEMBER } }),
    ).resolves.toBe(0);
  });

  it("reinstating a member leaves other sessions alone", async () => {
    await db.authSession.create({
      data: {
        userId: ADMIN,
        token: `${P}tok-admin`,
        expiresAt: new Date(Date.now() + 86_400_000),
      },
    });
    as(ADMIN);

    await call("PATCH", `${MEMBERS}/${MEMBER}`, { status: "suspended" });
    const res = await call("PATCH", `${MEMBERS}/${MEMBER}`, {
      status: "active",
    });

    expect(res.body).toMatchObject({ status: "active", sessionsRevoked: 0 });
    await expect(
      db.authSession.count({ where: { userId: ADMIN } }),
    ).resolves.toBe(1);
  });

  it("an admin may change a member's role, and it is audited", async () => {
    as(ADMIN);

    const res = await call("PATCH", `${MEMBERS}/${MEMBER}`, {
      role: "admin",
    });

    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ role: "admin" });
    await expect(
      db.auditLog.count({
        where: { organizationId: ORG, service: "member", action: "update" },
      }),
    ).resolves.toBe(1);
  });

  it("an owner cannot be demoted or suspended here", async () => {
    as(ADMIN);

    await expect(
      call("PATCH", `${MEMBERS}/${OWNER}`, { role: "member" }),
    ).resolves.toMatchObject({ status: 409 });
    await expect(
      call("PATCH", `${MEMBERS}/${OWNER}`, { status: "suspended" }),
    ).resolves.toMatchObject({ status: 409 });

    await expect(
      db.organizationMember.findFirst({
        where: { organizationId: ORG, userId: OWNER },
        select: { role: true, status: true },
      }),
    ).resolves.toMatchObject({ role: "owner", status: "active" });
  });

  it("owner is not an assignable role", async () => {
    as(OWNER);

    await expect(
      call("PATCH", `${MEMBERS}/${MEMBER}`, { role: "owner" }),
    ).resolves.toMatchObject({ status: 400 });
  });

  it("a plain member reaches none of it", async () => {
    as(MEMBER);

    await expect(call("GET", MEMBERS)).resolves.toMatchObject({
      status: 403,
    });
    await expect(call("GET", GROUPS)).resolves.toMatchObject({
      status: 403,
    });
    await expect(call("GET", MAPPINGS)).resolves.toMatchObject({
      status: 403,
    });
  });

  it("lists members with their role and status", async () => {
    as(ADMIN);
    await call("PATCH", `${MEMBERS}/${MEMBER}`, { status: "suspended" });

    const res = await call("GET", MEMBERS);
    const rows = (res.body as unknown as { data: Record<string, unknown>[] })
      .data;

    expect(rows).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ userId: OWNER, role: "owner" }),
        expect.objectContaining({ userId: MEMBER, status: "suspended" }),
      ]),
    );
  });
});

describe.skipIf(!PROOF_URL)("/v1/org/groups", () => {
  it("an admin creates, renames and deletes a group, each audited", async () => {
    as(ADMIN);

    const created = await call("POST", GROUPS, {
      name: `${P}platform`,
    });
    expect(created.status).toBe(201);

    const renamed = await call("PATCH", `${GROUPS}/${created.body.id}`, {
      name: `${P}platform-team`,
    });
    expect(renamed.body).toMatchObject({ name: `${P}platform-team` });

    const removed = await call("DELETE", `${GROUPS}/${created.body.id}`);
    expect(removed.status).toBe(204);

    await expect(
      db.auditLog.count({ where: { organizationId: ORG, service: "group" } }),
    ).resolves.toBe(3);
  });

  it("group modes are settable and readable", async () => {
    as(ADMIN);

    const created = await call("POST", GROUPS, {
      name: `${P}everyone`,
      membershipMode: "all-users",
      projectAccessMode: "all-projects",
    });

    expect(created.body).toMatchObject({
      membershipMode: "all-users",
      projectAccessMode: "all-projects",
      // An all-users group counts the org's active members, not its rows.
      memberCount: 3,
    });
  });

  it("an all-users group lists every member without a row", async () => {
    const group = await db.group.create({
      data: {
        organizationId: ORG,
        name: `${P}everyone`,
        membershipMode: "all-users",
      },
    });
    as(ADMIN);

    const res = await call("GET", `${GROUPS}/${group.id}/members`);
    const rows = (res.body as unknown as { data: { userId: string }[] }).data;

    expect(rows.map((r) => r.userId).sort()).toEqual(
      [ADMIN, MEMBER, OWNER].sort(),
    );
    await expect(
      db.groupMember.count({ where: { groupId: group.id } }),
    ).resolves.toBe(0);
  });

  it("membership is a replace-set over org members only", async () => {
    const group = await seedGroup(`${P}platform`);
    as(ADMIN);

    const first = await call("PUT", `${GROUPS}/${group.id}/members`, {
      userIds: [MEMBER, ADMIN],
    });
    expect(first.body).toMatchObject({ added: 2, removed: 0 });

    const second = await call("PUT", `${GROUPS}/${group.id}/members`, {
      userIds: [MEMBER],
    });
    expect(second.body).toMatchObject({ added: 0, removed: 1 });

    const outsider = await call("PUT", `${GROUPS}/${group.id}/members`, {
      userIds: [`${P}nobody`],
    });
    expect(outsider.status).toBe(422);
  });

  it("two groups cannot share a name", async () => {
    await seedGroup(`${P}platform`);
    as(ADMIN);

    const res = await call("POST", GROUPS, { name: `${P}platform` });

    expect(res.status).toBe(409);
  });
});
