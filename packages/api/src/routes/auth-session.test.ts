import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { SessionUser } from "../providers/types";

// Route-level tests for the identity-conflict seam in GET /auth/session: a
// session whose email belongs to a user with a different externalAuthId is
// decided by the resolveIdentityConflict hook — the default links, a rejecting
// hook turns the sign-in into a 409.

// Pinned before any import evaluates so the suite is hermetic to the ambient
// edition (CI runs with NEXT_PUBLIC_EDITION=cloud).
vi.hoisted(() => {
  process.env.NEXT_PUBLIC_EDITION = "oss";
});

const state = vi.hoisted(() => ({
  session: null as SessionUser | null,
  dbUser: null as {
    id: string;
    email: string;
    externalAuthId: string;
  } | null,
  upserts: [] as Record<string, unknown>[],
  defaultProject: null as { id: string; organizationId: string } | null,
  bootstraps: 0,
  joinRoles: [] as string[],
}));

vi.mock("@onecli/db", () => ({
  Prisma: { JsonNull: null },
  db: {
    user: {
      findUnique: async () =>
        state.dbUser
          ? {
              id: state.dbUser.id,
              email: state.dbUser.email,
              externalAuthId: state.dbUser.externalAuthId,
            }
          : null,
      upsert: async (args: Record<string, unknown>) => {
        state.upserts.push(args);
        return { id: "user-1", email: "guy@acme.com", name: "Guy" };
      },
    },
  },
}));

// The org/project side is stateful: the default (proj-1) takes the
// established-user path (no bootstrap); onUserCreated-seam tests null it to
// drive the bootstrap decision.
vi.mock("../services/organization-service", () => ({
  findUserDefaultProject: async () => state.defaultProject,
  bootstrapOrganization: async () => {
    state.bootstraps += 1;
    return { project: { id: "boot-proj", organizationId: "boot-org" } };
  },
  // Under `single-org-shared` tenancy this is the branch the bootstrap
  // decision takes; it counts as a bootstrap for these tests, which care
  // whether the org side ran, not which shape it took.
  joinSharedOrganization: async (
    _userId: string,
    _userEmail: string,
    role: string,
  ) => {
    state.bootstraps += 1;
    // Recorded so the route's choice of role is pinned here; the service-level
    // test only sees calls the route actually makes.
    state.joinRoles.push(role);
    return { project: { id: "boot-proj", organizationId: "boot-org" } };
  },
  ensureProjectSeeds: async () => {},
}));

import { initSession, initSessionEnforcer } from "../providers";
import { authSessionRoutes, initSessionHooks } from "./auth-session";
import type { SessionHooks } from "./auth-session";

initSession({
  getSession: async () => state.session,
});

const app = authSessionRoutes();

beforeEach(() => {
  state.session = null;
  state.dbUser = null;
  state.upserts = [];
  state.defaultProject = { id: "proj-1", organizationId: "org-1" };
  state.bootstraps = 0;
  state.joinRoles = [];
});

afterEach(() => {
  // _hooks is module-global — restore the defaults so later suites in the
  // same worker never inherit a rejecting hook.
  initSessionHooks({});
  initSessionEnforcer(null);
});

describe("GET /auth/session identity-conflict seam", () => {
  it("links on conflict by default (historical behavior, pins OSS)", async () => {
    state.session = { id: "new-sub", email: "guy@acme.com", name: "Guy" };
    state.dbUser = {
      id: "user-1",
      email: "guy@acme.com",
      externalAuthId: "old-sub",
    };

    const res = await app.request("/");
    expect(res.status).toBe(200);
    expect(state.upserts).toHaveLength(1);
  });

  it("returns 409 and skips the upsert when the hook rejects", async () => {
    initSessionHooks({ resolveIdentityConflict: () => "reject" });
    state.session = { id: "evil-sub", email: "guy@acme.com" };
    state.dbUser = {
      id: "user-1",
      email: "guy@acme.com",
      externalAuthId: "old-sub",
    };

    const res = await app.request("/");
    expect(res.status).toBe(409);
    const body = (await res.json()) as { error: string };
    expect(body.error).toContain("different sign-in identity");
    expect(state.upserts).toHaveLength(0);
  });

  it("never consults the hook when the sub matches", async () => {
    let consulted = false;
    initSessionHooks({
      resolveIdentityConflict: () => {
        consulted = true;
        return "reject";
      },
    });
    state.session = { id: "same-sub", email: "guy@acme.com" };
    state.dbUser = {
      id: "user-1",
      email: "guy@acme.com",
      externalAuthId: "same-sub",
    };

    const res = await app.request("/");
    expect(res.status).toBe(200);
    expect(consulted).toBe(false);
  });

  it("never consults the hook for a brand-new email", async () => {
    let consulted = false;
    initSessionHooks({
      resolveIdentityConflict: () => {
        consulted = true;
        return "reject";
      },
    });
    state.session = { id: "new-sub", email: "new@acme.com" };
    state.dbUser = null;

    const res = await app.request("/");
    expect(res.status).toBe(200);
    expect(consulted).toBe(false);
  });
});

describe("GET /auth/session ensureSessionMembership seam", () => {
  it("calls the hook with the session and the upserted user, before project resolution", async () => {
    const calls: Array<{ sessionId: string; userId: string }> = [];
    initSessionHooks({
      ensureSessionMembership: async (session, user) => {
        calls.push({ sessionId: session.id, userId: user.id });
      },
    });
    state.session = { id: "sso-sub", email: "guy@acme.com", name: "Guy" };
    state.dbUser = null;

    const res = await app.request("/");
    expect(res.status).toBe(200);
    expect(calls).toEqual([{ sessionId: "sso-sub", userId: "user-1" }]);
  });

  it("default hook is a no-op (existing sessions unaffected)", async () => {
    state.session = { id: "same-sub", email: "guy@acme.com" };
    state.dbUser = {
      id: "user-1",
      email: "guy@acme.com",
      externalAuthId: "same-sub",
    };

    const res = await app.request("/");
    expect(res.status).toBe(200);
    const body = (await res.json()) as { projectId?: string };
    expect(body.projectId).toBe("proj-1");
  });
});

describe("GET /auth/session onUserCreated seam", () => {
  type CreatedCall = {
    email: string;
    bootstrappedOrg: boolean;
    hasRequest: boolean;
  };

  const recordCreated = (
    calls: CreatedCall[],
    extra: Partial<SessionHooks> = {},
  ) => {
    initSessionHooks({
      ...extra,
      onUserCreated: (user, _attrs, context) => {
        calls.push({
          email: user.email,
          bootstrappedOrg: context.bootstrappedOrg,
          hasRequest: context.request instanceof Request,
        });
      },
    });
  };

  it("fires with bootstrappedOrg=true on the organic path", async () => {
    const calls: CreatedCall[] = [];
    recordCreated(calls);
    state.session = { id: "new-sub", email: "new@acme.com" };
    state.dbUser = null;
    state.defaultProject = null;

    const res = await app.request("/");
    expect(res.status).toBe(200);
    // The upsert mock always returns guy@acme.com — the assertion pins that
    // the hook sees the upserted user, not the session.
    expect(calls).toEqual([
      { email: "guy@acme.com", bootstrappedOrg: true, hasRequest: true },
    ]);
    expect(state.bootstraps).toBe(1);
    // Never `owner` for an ordinary joiner.
    expect(state.joinRoles).toEqual(["member"]);
  });

  it("fires without bootstrap when shouldBootstrapOrg declines", async () => {
    const calls: CreatedCall[] = [];
    recordCreated(calls, { shouldBootstrapOrg: () => false });
    state.session = { id: "new-sub", email: "new@acme.com" };
    state.dbUser = null;
    state.defaultProject = null;

    const res = await app.request("/?fromInvitation=1");
    expect(res.status).toBe(200);
    expect(calls).toEqual([
      { email: "guy@acme.com", bootstrappedOrg: false, hasRequest: true },
    ]);
    expect(state.bootstraps).toBe(0);
  });

  it("fires with bootstrappedOrg=false when a project already exists (JIT-membership shape)", async () => {
    const calls: CreatedCall[] = [];
    recordCreated(calls);
    state.session = { id: "sso-sub", email: "new@acme.com" };
    state.dbUser = null;
    // defaultProject stays proj-1: created-without-bootstrap still notifies.

    const res = await app.request("/");
    expect(res.status).toBe(200);
    expect(calls).toEqual([
      { email: "guy@acme.com", bootstrappedOrg: false, hasRequest: true },
    ]);
    expect(state.bootstraps).toBe(0);
  });

  it("does not fire for an existing user", async () => {
    const calls: CreatedCall[] = [];
    recordCreated(calls);
    state.session = { id: "same-sub", email: "guy@acme.com" };
    state.dbUser = {
      id: "user-1",
      email: "guy@acme.com",
      externalAuthId: "same-sub",
    };

    const res = await app.request("/");
    expect(res.status).toBe(200);
    expect(calls).toEqual([]);
  });
});

describe("GET /auth/session sessionEnforcer seam", () => {
  it("returns 401 with the denial body when the enforcer rejects (after the upsert/JIT, never a 500)", async () => {
    initSessionEnforcer(async () => ({
      error: "Your organization requires single sign-on.",
      code: "sso_required",
    }));
    state.session = { id: "same-sub", email: "guy@acme.com" };
    state.dbUser = {
      id: "user-1",
      email: "guy@acme.com",
      externalAuthId: "same-sub",
    };

    const res = await app.request("/");
    expect(res.status).toBe(401);
    const body = (await res.json()) as { error: string; code: string };
    expect(body.code).toBe("sso_required");
    expect(body.error).toContain("single sign-on");
    // Placement proof: the upsert already ran — enforcement is post-identity,
    // pre-project.
    expect(state.upserts).toHaveLength(1);
  });

  it("an allowing enforcer leaves the session untouched", async () => {
    const seen: string[] = [];
    initSessionEnforcer(async (_session, user) => {
      seen.push(user.id);
      return null;
    });
    state.session = { id: "same-sub", email: "guy@acme.com" };
    state.dbUser = {
      id: "user-1",
      email: "guy@acme.com",
      externalAuthId: "same-sub",
    };

    const res = await app.request("/");
    expect(res.status).toBe(200);
    expect(seen).toEqual(["user-1"]);
  });
});
