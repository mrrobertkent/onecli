import { beforeEach, describe, expect, it, vi } from "vitest";

import type { OrgRole, RoleResolver } from "../providers";

/**
 * The minimum-org-role decision both edges share.
 *
 * The case that carries the most weight is the unregistered resolver. That
 * state is a misconfiguration, and a misconfiguration that admits is the exact
 * failure D-2 exists to prevent — so it is reproduced here properly, by making
 * `getRoleResolver` return null, rather than by a resolver that answers null.
 * `initRoleResolver` has no null reset, which is why the provider is mocked.
 */

const state = vi.hoisted(() => ({
  resolver: null as RoleResolver | null,
}));

vi.mock("../providers", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../providers")>()),
  getRoleResolver: () => state.resolver,
}));

import { resolveOrgRoleAtLeast } from "./org-authorization";

const USER = "u1";
const ORG = "org-1";

const withRole = (role: OrgRole | null) => {
  state.resolver = { getUserRole: async () => role };
};

beforeEach(() => {
  state.resolver = null;
});

describe("resolveOrgRoleAtLeast", () => {
  it("refuses when no resolver is registered — fail-closed, not fail-open", async () => {
    // Nothing installed: an edition that forgot to register one must deny.
    await expect(resolveOrgRoleAtLeast(USER, ORG, "member")).resolves.toEqual({
      ok: false,
      reason: "not-a-member",
    });
  });

  it("refuses when the resolver finds no membership", async () => {
    withRole(null);
    await expect(resolveOrgRoleAtLeast(USER, ORG, "member")).resolves.toEqual({
      ok: false,
      reason: "not-a-member",
    });
  });

  it("refuses a role below the minimum, and says which refusal it is", async () => {
    withRole("member");
    await expect(resolveOrgRoleAtLeast(USER, ORG, "admin")).resolves.toEqual({
      ok: false,
      reason: "insufficient",
    });
  });

  it("admits a role at the minimum", async () => {
    withRole("admin");
    await expect(resolveOrgRoleAtLeast(USER, ORG, "admin")).resolves.toEqual({
      ok: true,
      role: "admin",
    });
  });

  it("admits a role above the minimum and returns the real one", async () => {
    withRole("owner");
    // The caller records what the actor actually is, not what was demanded.
    await expect(resolveOrgRoleAtLeast(USER, ORG, "admin")).resolves.toEqual({
      ok: true,
      role: "owner",
    });
  });

  it("refuses an admin asking for owner — the D-16 boundary", async () => {
    withRole("admin");
    await expect(resolveOrgRoleAtLeast(USER, ORG, "owner")).resolves.toEqual({
      ok: false,
      reason: "insufficient",
    });
  });
});
