import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// `canAccessProjectAsUser` only enforces under RBAC, so pin the cloud edition.
vi.hoisted(() => {
  process.env.NEXT_PUBLIC_EDITION = "cloud";
});

const state = vi.hoisted(() => ({
  bindingRow: null as { id: string } | null,
  unrestrictedGroup: null as { id: string } | null,
}));

vi.mock("@onecli/db", () => ({
  db: {
    user: { findUnique: async () => null },
    project: { findFirst: async () => null, findUnique: async () => null },
    projectAccess: { findFirst: async () => state.bindingRow },
    // The all-projects arm: a group that reaches every project in the org
    // without a ProjectAccess row.
    group: { findFirst: async () => state.unrestrictedGroup },
  },
}));

import { canAccessProjectAsUser } from "./resolve";
import { initRoleResolver } from "../../providers";
import type { OrgRole } from "../../providers";

const PROJECT = {
  id: "proj-1",
  organizationId: "org-1",
};

let role: OrgRole | null = null;

beforeEach(() => {
  role = null;
  state.bindingRow = null;
  state.unrestrictedGroup = null;
  initRoleResolver({ getUserRole: async () => role });
});

afterEach(() => {
  initRoleResolver({ getUserRole: async () => null });
});

// An active member reaches a project when they are an org admin/owner or hold a
// ProjectAccess binding. The binding check lives inside the active-member gate,
// so a suspended user's binding is never consulted.
describe("canAccessProjectAsUser (cloud, bindings-only)", () => {
  it("admins access any project in their org", async () => {
    role = "admin";
    await expect(canAccessProjectAsUser("someone-else", PROJECT)).resolves.toBe(
      true,
    );
  });

  it("an active member shared in via a ProjectAccess binding gets access", async () => {
    role = "member";
    state.bindingRow = { id: "binding-1" };
    await expect(canAccessProjectAsUser("someone-else", PROJECT)).resolves.toBe(
      true,
    );
  });

  it("an active member with no binding is denied", async () => {
    role = "member";
    state.bindingRow = null;
    await expect(canAccessProjectAsUser("someone-else", PROJECT)).resolves.toBe(
      false,
    );
  });

  it("an active member in an all-projects group gets access with no binding", async () => {
    role = "member";
    state.bindingRow = null;
    state.unrestrictedGroup = { id: "group-1" };
    await expect(canAccessProjectAsUser("someone-else", PROJECT)).resolves.toBe(
      true,
    );
  });

  it("denies the creator once their binding is gone (13b: no creator arm)", async () => {
    // A creator is just a member; with no binding they do not get in.
    role = "member";
    state.bindingRow = null;
    await expect(canAccessProjectAsUser("creator-1", PROJECT)).resolves.toBe(
      false,
    );
  });

  it("a membership-less creator is denied (13b closes the creator door)", async () => {
    // A binding is only ever consulted for an active member.
    role = null;
    state.bindingRow = null;
    await expect(canAccessProjectAsUser("creator-1", PROJECT)).resolves.toBe(
      false,
    );
  });

  it("a binding does NOT rescue a suspended/non-member (no role)", async () => {
    // No role means non-member or suspended, so the stray binding is never
    // consulted.
    role = null;
    state.bindingRow = { id: "binding-1" };
    await expect(canAccessProjectAsUser("someone-else", PROJECT)).resolves.toBe(
      false,
    );
  });
});
