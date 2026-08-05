import { beforeEach, describe, expect, it, vi } from "vitest";

// Minimal in-memory `@onecli/db` mock — just the operations
// `joinSharedOrganization` touches — so we can assert the single-org invariants
// (one shared org, per-user projects, idempotency) without a real database.

interface OrgRow {
  id: string;
  slug: string;
  name: string;
}
interface MemberRow {
  organizationId: string;
  userId: string;
  userEmail: string;
  role: string;
}
interface ProjectRow {
  id: string;
  name: string | null;
  slug: string | null;
  organizationId: string;
  createdByUserId: string | null;
  createdByUserEmail: string | null;
  seq: number;
}
interface ApiKeyRow {
  key: string;
  userId: string;
  userEmail: string;
  organizationId: string;
  scope: string;
}

const store = vi.hoisted(() => ({
  orgs: [] as OrgRow[],
  members: [] as MemberRow[],
  projects: [] as ProjectRow[],
  apiKeys: [] as ApiKeyRow[],
  seq: 0,
}));

vi.mock("@onecli/db", () => ({
  db: {
    organization: {
      findUnique: async ({ where: { slug } }: { where: { slug: string } }) =>
        store.orgs.find((o) => o.slug === slug) ?? null,
      findUniqueOrThrow: async ({
        where: { slug },
      }: {
        where: { slug: string };
      }) => {
        const org = store.orgs.find((o) => o.slug === slug);
        if (!org) throw new Error(`org ${slug} not found`);
        return org;
      },
      create: async ({ data }: { data: OrgRow }) => {
        if (store.orgs.some((o) => o.slug === data.slug)) {
          throw new Error("unique constraint: organization.slug");
        }
        const org: OrgRow = { id: data.id, slug: data.slug, name: data.name };
        store.orgs.push(org);
        return org;
      },
    },
    organizationMember: {
      upsert: async ({
        where: { organizationId_userId },
        create,
      }: {
        where: {
          organizationId_userId: { organizationId: string; userId: string };
        };
        create: MemberRow;
      }) => {
        const existing = store.members.find(
          (m) =>
            m.organizationId === organizationId_userId.organizationId &&
            m.userId === organizationId_userId.userId,
        );
        if (existing) return existing;
        store.members.push(create);
        return create;
      },
    },
    project: {
      findFirst: async ({
        where: { organizationId, createdByUserId },
      }: {
        where: { organizationId: string; createdByUserId: string };
      }) =>
        store.projects
          .filter(
            (p) =>
              p.organizationId === organizationId &&
              p.createdByUserId === createdByUserId,
          )
          .sort((a, b) => a.seq - b.seq)[0] ?? null,
      create: async ({ data }: { data: Omit<ProjectRow, "seq"> }) => {
        if (
          store.projects.some(
            (p) =>
              p.organizationId === data.organizationId && p.slug === data.slug,
          )
        ) {
          throw new Error("unique constraint: (organizationId, slug)");
        }
        const project: ProjectRow = { ...data, seq: store.seq++ };
        store.projects.push(project);
        return project;
      },
    },
    apiKey: {
      findFirst: async ({
        where: { organizationId, scope },
      }: {
        where: { organizationId: string; scope: string };
      }) =>
        store.apiKeys.find(
          (k) => k.organizationId === organizationId && k.scope === scope,
        ) ?? null,
      create: async ({ data }: { data: ApiKeyRow }) => {
        if (store.apiKeys.some((k) => k.key === data.key)) {
          throw new Error("unique constraint: api_key.key");
        }
        store.apiKeys.push(data);
        return data;
      },
    },
  },
}));

vi.mock("../lib/logger", () => ({
  logger: { warn: () => {}, info: () => {}, error: () => {} },
}));

import {
  ensureSharedOrgBootstrap,
  joinSharedOrganization,
  SHARED_ORG_SLUG,
} from "./organization-service";

beforeEach(() => {
  store.orgs = [];
  store.members = [];
  store.projects = [];
  store.apiKeys = [];
  store.seq = 0;
  delete process.env.ONECLI_ORG_API_KEY;
  delete process.env.ONECLI_ORG_API_KEY_FILE;
});

describe("joinSharedOrganization", () => {
  it("creates the one shared org and a project for the first user", async () => {
    const { organization, project } = await joinSharedOrganization(
      "user-aaaaaaaa",
      "a@example.com",
      "member",
    );

    expect(store.orgs).toHaveLength(1);
    expect(store.orgs[0]?.slug).toBe(SHARED_ORG_SLUG);
    expect(organization.id).toBe(store.orgs[0]?.id);
    expect(project.organizationId).toBe(organization.id);
    expect(store.members).toHaveLength(1);
    expect(store.projects).toHaveLength(1);
    // The creator's ProjectAccess binding is seeded owner (step 13c) with the project.
    expect(
      (store.projects[0] as { accessBindings?: unknown }).accessBindings,
    ).toEqual({ create: { userId: "user-aaaaaaaa", role: "owner" } });
  });

  it("puts a second user in the SAME org with a distinct project", async () => {
    const first = await joinSharedOrganization(
      "user-aaaaaaaa",
      "a@example.com",
      "member",
    );
    const second = await joinSharedOrganization(
      "user-bbbbbbbb",
      "b@example.com",
      "member",
    );

    expect(store.orgs).toHaveLength(1); // one shared org
    expect(second.organization.id).toBe(first.organization.id);
    expect(second.project.id).not.toBe(first.project.id); // distinct projects
    expect(store.members).toHaveLength(2);
    expect(store.projects).toHaveLength(2);
  });

  it("is idempotent when the same user joins again", async () => {
    const first = await joinSharedOrganization(
      "user-aaaaaaaa",
      "a@example.com",
      "member",
    );
    const again = await joinSharedOrganization(
      "user-aaaaaaaa",
      "a@example.com",
      "member",
    );

    expect(again.organization.id).toBe(first.organization.id);
    expect(again.project.id).toBe(first.project.id);
    expect(store.orgs).toHaveLength(1);
    expect(store.members).toHaveLength(1);
    expect(store.projects).toHaveLength(1);
  });

  // ── Design D-11 regression ────────────────────────────────────────────
  //
  // This path used to create EVERY shared-org membership with `role: "owner"`,
  // unconditionally. Under `single-org-shared` that made every user who logged
  // in an owner of the one organization, and a `RoleResolver` reading
  // `organization_members.role` then returned `owner` for all of them — the
  // resolver answering correctly from poisoned data.
  //
  // These assert on the PERSISTED role, not on behaviour, because a passing
  // authorization check is exactly what hid the bug.
  it("persists the role it was given, and never silently promotes to owner", async () => {
    await joinSharedOrganization("user-aaaaaaaa", "a@example.com", "member");

    expect(store.members).toHaveLength(1);
    expect(store.members[0]?.role).toBe("member");
  });

  it("does not make a second joiner an owner of the shared org", async () => {
    await joinSharedOrganization("user-aaaaaaaa", "a@example.com", "owner");
    await joinSharedOrganization("user-bbbbbbbb", "b@example.com", "member");

    const second = store.members.find((m) => m.userId === "user-bbbbbbbb");
    expect(second?.role).toBe("member");
    expect(store.members.filter((m) => m.role === "owner")).toHaveLength(1);
  });

  it("preserves an existing role when the same user joins again", async () => {
    // Re-entry must not re-grade anyone: role changes belong to the login-time
    // role writer (D-3) or an admin, never to a bootstrap helper.
    await joinSharedOrganization("user-aaaaaaaa", "a@example.com", "member");
    await joinSharedOrganization("user-aaaaaaaa", "a@example.com", "owner");

    expect(store.members).toHaveLength(1);
    expect(store.members[0]?.role).toBe("member");
  });

  it("does not seed the bootstrap org API key for an ordinary joiner", async () => {
    // Owning that key makes a user undeletable (`ApiKey.user` is ON DELETE
    // RESTRICT). It belongs to the bootstrap admin alone.
    await joinSharedOrganization("user-aaaaaaaa", "a@example.com", "member");

    expect(store.apiKeys).toHaveLength(0);
  });

  it("avoids project-slug collisions for ids sharing a prefix", async () => {
    // Distinct user ids whose first 8 chars match — the per-user project slug
    // must still be unique within the shared org (it uses the full user id).
    const first = await joinSharedOrganization(
      "dup12345-aaaa",
      "a@example.com",
      "member",
    );
    const second = await joinSharedOrganization(
      "dup12345-bbbb",
      "b@example.com",
      "member",
    );

    expect(second.organization.id).toBe(first.organization.id);
    expect(second.project.id).not.toBe(first.project.id);
    expect(store.projects).toHaveLength(2);
  });
});

describe("bootstrap org API key (via ensureSharedOrgBootstrap)", () => {
  it("generates one org-scoped key for the shared org, owned by the first user", async () => {
    await ensureSharedOrgBootstrap("user-aaaaaaaa", "a@example.com");

    expect(store.apiKeys).toHaveLength(1);
    const key = store.apiKeys[0]!;
    expect(key.scope).toBe("organization");
    expect(key.organizationId).toBe(store.orgs[0]?.id);
    expect(key.userId).toBe("user-aaaaaaaa");
    expect(key.key).toMatch(/^oc_org_[0-9a-f]{64}$/);
  });

  it("is idempotent — a second user's join adds no new org key", async () => {
    await ensureSharedOrgBootstrap("user-aaaaaaaa", "a@example.com");
    await ensureSharedOrgBootstrap("user-bbbbbbbb", "b@example.com");

    expect(store.apiKeys).toHaveLength(1);
  });

  it("uses ONECLI_ORG_API_KEY when set and valid", async () => {
    const supplied = "oc_org_" + "a".repeat(64);
    process.env.ONECLI_ORG_API_KEY = supplied;

    await ensureSharedOrgBootstrap("user-aaaaaaaa", "a@example.com");

    expect(store.apiKeys).toHaveLength(1);
    expect(store.apiKeys[0]?.key).toBe(supplied);
  });

  it("fails loudly on a malformed ONECLI_ORG_API_KEY", async () => {
    process.env.ONECLI_ORG_API_KEY = "not-a-valid-key";

    await expect(
      ensureSharedOrgBootstrap("user-aaaaaaaa", "a@example.com"),
    ).rejects.toThrow(/ONECLI_ORG_API_KEY/);
  });
});
