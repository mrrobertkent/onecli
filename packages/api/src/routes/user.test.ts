import { describe, expect, it, vi } from "vitest";

// GET /user must work without a project header — an org key carries no project
// of its own — while the api-key sub-routes stay project-scoped.
//
// No edition is pinned: under CI's cloud edition org-key auth re-checks the
// admin role, so a roleResolver is registered or the key would 401 at the role
// gate before reaching what these tests measure.

const ORG_KEY = "oc_org_test-key";

const services = vi.hoisted(() => ({
  getUser: vi.fn(async () => ({
    email: "admin@example.com",
    name: "Admin",
  })),
}));

vi.mock("@onecli/db", () => ({
  Prisma: {},
  db: {
    apiKey: {
      findUnique: async ({ where }: { where: { key: string } }) =>
        where.key === ORG_KEY
          ? { userId: "user-1", organizationId: "org-1", scope: "organization" }
          : null,
      findFirst: async () => null,
    },
    user: { findUnique: async () => ({ email: "admin@example.com" }) },
  },
}));

vi.mock("../services/user-service", () => ({
  getUser: services.getUser,
  updateProfile: vi.fn(),
}));

const { createApiApp } = await import("../app");

const app = createApiApp(
  { getSession: async () => null },
  // The key's user still holds an admin role — the cloud org-key gate.
  { roleResolver: { getUserRole: async () => "owner" } },
);

const AUTH = { Authorization: `Bearer ${ORG_KEY}` };

describe("GET /v1/user auth posture", () => {
  it("answers an org key WITHOUT a project header (the auth login path)", async () => {
    const res = await app.request("/v1/user", { headers: AUTH });
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ email: "admin@example.com" });
  });

  it("keeps the project-scoped api-key sub-route fenced for org keys", async () => {
    const res = await app.request("/v1/user/api-key", { headers: AUTH });
    expect(res.status).toBe(400);
    const body = (await res.json()) as { error: { message: string } };
    expect(body.error.message).toContain("X-Project-Id");
  });

  it("still rejects an unknown key outright", async () => {
    const res = await app.request("/v1/user", {
      headers: { Authorization: "Bearer oc_org_nope" },
    });
    expect(res.status).toBe(401);
  });
});
