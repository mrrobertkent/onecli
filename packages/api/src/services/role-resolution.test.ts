import { beforeEach, describe, expect, it, vi } from "vitest";

const state = vi.hoisted(() => ({
  member: null as { role: string } | null,
  mappings: [] as { role: string; priority: number }[],
}));

vi.mock("@onecli/db", () => ({
  db: {
    organizationMember: {
      findFirst: async () => state.member,
    },
    groupRoleMapping: {
      findMany: async () =>
        [...state.mappings].sort((a, b) => b.priority - a.priority),
    },
  },
}));

vi.mock("../lib/logger", () => ({
  logger: { warn: () => {}, info: () => {}, error: () => {} },
}));

import {
  ossRoleResolver,
  readClaimPath,
  resolveRoleFromGroups,
} from "./role-resolution";

beforeEach(() => {
  state.member = null;
  state.mappings = [];
});

describe("readClaimPath (design D-4: a PATH, not a name)", () => {
  it("reads a flat claim — Authentik and Okta", () => {
    expect(readClaimPath({ groups: ["eng", "ops"] }, "groups")).toEqual([
      "eng",
      "ops",
    ]);
  });

  it("reads a NESTED claim — Keycloak keeps roles at realm_access.roles", () => {
    // This is the case a claim NAME cannot express, and the reason Better
    // Auth's own flat-key `mapping.extraFields` is not used for role
    // resolution.
    const claims = { realm_access: { roles: ["admin"] } };
    expect(readClaimPath(claims, "realm_access.roles")).toEqual(["admin"]);
  });

  it("wraps a single string claim as one group", () => {
    expect(readClaimPath({ groups: "eng" }, "groups")).toEqual(["eng"]);
  });

  it("returns empty for a missing path rather than throwing", () => {
    expect(readClaimPath({}, "realm_access.roles")).toEqual([]);
    expect(readClaimPath({ realm_access: null }, "realm_access.roles")).toEqual(
      [],
    );
  });

  it("drops non-string entries instead of coercing them", () => {
    expect(readClaimPath({ groups: ["eng", 42, null] }, "groups")).toEqual([
      "eng",
    ]);
  });
});

describe("resolveRoleFromGroups", () => {
  it("returns null when the user is in no groups", async () => {
    expect(await resolveRoleFromGroups("org-1", [])).toBeNull();
  });

  it("returns null when no group maps — NOT a default of member", async () => {
    // US-4: an identity whose membership maps to nothing is not admitted.
    // Substituting a default here would admit exactly the strangers the gate
    // exists to keep out.
    state.mappings = [];
    expect(await resolveRoleFromGroups("org-1", ["unmapped"])).toBeNull();
  });

  it("highest priority wins", async () => {
    state.mappings = [
      { role: "member", priority: 1 },
      { role: "admin", priority: 9 },
    ];
    expect(await resolveRoleFromGroups("org-1", ["a", "b"])).toBe("admin");
  });

  it("never confers owner from a directory group", async () => {
    // Otherwise anyone who can edit a group in the IdP can take the instance.
    state.mappings = [{ role: "owner", priority: 99 }];
    expect(await resolveRoleFromGroups("org-1", ["sneaky"])).toBeNull();
  });

  it("skips a non-assignable role and falls through to the next", async () => {
    state.mappings = [
      { role: "owner", priority: 99 },
      { role: "member", priority: 1 },
    ];
    expect(await resolveRoleFromGroups("org-1", ["a", "b"])).toBe("member");
  });
});

describe("ossRoleResolver", () => {
  it("returns the persisted role", async () => {
    state.member = { role: "admin" };
    expect(await ossRoleResolver.getUserRole("u1", "org-1")).toBe("admin");
  });

  it("returns null for a non-member", async () => {
    state.member = null;
    expect(await ossRoleResolver.getUserRole("u1", "org-1")).toBeNull();
  });

  it("returns null for an unrecognised stored role rather than trusting it", async () => {
    state.member = { role: "superuser" };
    expect(await ossRoleResolver.getUserRole("u1", "org-1")).toBeNull();
  });
});
