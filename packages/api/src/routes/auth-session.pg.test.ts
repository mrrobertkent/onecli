import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";

import { proofDatabaseUrl } from "../testing/pg-proof.js";

/**
 * `GET /v1/auth/session` against real PostgreSQL. Unlike `auth-session.test.ts`,
 * which mocks `@onecli/db`, every case starts from the state the auth library
 * produces: the user row committed, this endpoint seeing it for the first time.
 *
 * Env-gated like the other proof suites; see pg-proof.ts.
 */

const PROOF_URL = proofDatabaseUrl();

type Db = typeof import("@onecli/db").db;
type Providers = typeof import("../providers");
type Route = typeof import("./auth-session");
type OrgService = typeof import("../services/organization-service");
type SessionMembership = typeof import("../services/session-membership");

let db: Db;
let providers: Providers;
let route: Route;
let orgService: OrgService;
let sessionMembership: SessionMembership;

const P = "asess-";
const USER = `${P}user`;
const SECOND_USER = `${P}second`;

/** The session the auth library hands us; `id` is `users.id`. */
let currentSession: import("../providers/types").SessionUser | null = null;

const reset = async () => {
  await db.auditLog.deleteMany({ where: { userId: { startsWith: P } } });
  await db.apiKey.deleteMany({ where: { userId: { startsWith: P } } });
  await db.agent.deleteMany({
    where: { project: { createdByUserId: { startsWith: P } } },
  });
  await db.projectAccess.deleteMany({ where: { userId: { startsWith: P } } });
  await db.project.deleteMany({
    where: { createdByUserId: { startsWith: P } },
  });
  await db.organizationMember.deleteMany({
    where: { userId: { startsWith: P } },
  });
  await db.user.deleteMany({ where: { id: { startsWith: P } } });
};

/** Create the user row exactly as Better Auth's `create.before` hook does. */
const seedAuthLibraryUser = async (id: string) =>
  db.user.create({
    data: {
      id,
      email: `${id}@proof.test`,
      name: id,
      externalAuthId: id,
    },
    select: { id: true, email: true },
  });

const callSessionRoute = async () => {
  const app = route.authSessionRoutes();
  const res = await app.request("/", { headers: { host: "proof.test" } });
  return {
    status: res.status,
    body: (await res.json()) as Record<string, unknown>,
  };
};

beforeAll(async () => {
  if (!PROOF_URL) return;
  process.env.DATABASE_URL = PROOF_URL;

  ({ db } = await import("@onecli/db"));
  providers = await import("../providers");
  route = await import("./auth-session");
  orgService = await import("../services/organization-service");
  sessionMembership = await import("../services/session-membership");

  // The real OSS wiring, not a stand-in — the enforcer runs before project
  // resolution, so a stub would change the outcome.
  providers.initSession({
    getSession: async () => currentSession,
  });
  providers.initSessionEnforcer(sessionMembership.ossSessionEnforcer);
  route.initSessionHooks({
    ensureSessionMembership: sessionMembership.ossSessionMembership,
  });

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
});

describe.skipIf(!PROOF_URL)("GET /v1/auth/session on real PostgreSQL", () => {
  it("provisions a project for a user the auth library already created", async () => {
    const user = await seedAuthLibraryUser(USER);
    // The membership the login-time role writer creates for a mapped identity;
    // without it the enforcer denies before provisioning is reached.
    await orgService.ensureSharedOrgMembership(user.id, user.email, "member");
    currentSession = { id: user.id, email: user.email };

    const { status, body } = await callSessionRoute();

    expect(status).toBe(200);
    expect(body.projectId).toBeTruthy();

    const project = await db.project.findFirst({
      where: { createdByUserId: user.id },
      select: { id: true },
    });
    expect(project?.id).toBe(body.projectId);
  });

  it("gives the provisioned project its API key and default agent", async () => {
    const user = await seedAuthLibraryUser(USER);
    await orgService.ensureSharedOrgMembership(user.id, user.email, "member");
    currentSession = { id: user.id, email: user.email };

    const { body } = await callSessionRoute();

    const keys = await db.apiKey.count({
      where: { projectId: body.projectId as string },
    });
    const agents = await db.agent.count({
      where: { projectId: body.projectId as string },
    });
    expect(keys).toBeGreaterThan(0);
    expect(agents).toBeGreaterThan(0);
  });

  it("is idempotent — a second call returns the same project, not a second one", async () => {
    const user = await seedAuthLibraryUser(USER);
    await orgService.ensureSharedOrgMembership(user.id, user.email, "member");
    currentSession = { id: user.id, email: user.email };

    const first = await callSessionRoute();
    const second = await callSessionRoute();

    expect(second.body.projectId).toBe(first.body.projectId);
    // Assert the count: "same id" would also hold if a second row existed and
    // merely sorted later.
    await expect(
      db.project.count({ where: { createdByUserId: user.id } }),
    ).resolves.toBe(1);
  });

  it("lands a second joiner as 'member', never 'owner'", async () => {
    const first = await seedAuthLibraryUser(USER);
    await orgService.ensureSharedOrgMembership(first.id, first.email, "owner");
    currentSession = { id: first.id, email: first.email };
    await callSessionRoute();

    const second = await seedAuthLibraryUser(SECOND_USER);
    await orgService.ensureSharedOrgMembership(
      second.id,
      second.email,
      "member",
    );
    currentSession = { id: second.id, email: second.email };
    await callSessionRoute();

    // Asserted on the persisted role — a behavioural check would pass either
    // way, since the resolver reads this same column.
    const membership = await db.organizationMember.findFirst({
      where: { userId: second.id },
      select: { role: true },
    });
    expect(membership?.role).toBe("member");
  });

  it("tenant isolation: each user's session resolves to their OWN project", async () => {
    const first = await seedAuthLibraryUser(USER);
    await orgService.ensureSharedOrgMembership(first.id, first.email, "owner");
    currentSession = { id: first.id, email: first.email };
    const firstResult = await callSessionRoute();

    const second = await seedAuthLibraryUser(SECOND_USER);
    await orgService.ensureSharedOrgMembership(
      second.id,
      second.email,
      "member",
    );
    currentSession = { id: second.id, email: second.email };
    const secondResult = await callSessionRoute();

    expect(secondResult.body.projectId).toBeTruthy();
    // Both users share one organization, so "a project in my org" is not a
    // fence; the projects must still be distinct.
    expect(secondResult.body.projectId).not.toBe(firstResult.body.projectId);
    expect(secondResult.body.organizationId).toBe(
      firstResult.body.organizationId,
    );
  });

  it("denies an identity with no membership, and gives it no project", async () => {
    const user = await seedAuthLibraryUser(USER);
    // No membership: authenticated at the IdP but mapped to no role.
    currentSession = { id: user.id, email: user.email };

    const { status, body } = await callSessionRoute();

    expect(status).toBe(401);
    expect(body.code).toBe("NOT_AUTHORISED");
    // The gate must close on the side effects too, not just the response.
    await expect(
      db.project.count({ where: { createdByUserId: user.id } }),
    ).resolves.toBe(0);
    await expect(db.apiKey.count({ where: { userId: user.id } })).resolves.toBe(
      0,
    );
  });
});
