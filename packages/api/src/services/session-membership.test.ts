import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SessionUser } from "../providers/types";

// The enforcer is the access gate — authenticating is not enough to be
// provisioned, and it fails closed — so these tests lean on the denial paths.

const state = vi.hoisted(() => ({
  membership: null as { role: string } | null,
  throwOnMembership: false,
}));

vi.mock("@onecli/db", () => ({
  db: {
    organizationMember: {
      findFirst: async () => {
        if (state.throwOnMembership) throw new Error("connection refused");
        return state.membership;
      },
    },
    organization: { findUnique: async () => null },
    authAccount: { findFirst: async () => null },
  },
}));

// `child` is needed because audit-service builds a child logger at import time.
vi.mock("../lib/logger", () => {
  const noop = { warn: () => {}, info: () => {}, error: () => {} };
  return { logger: { ...noop, child: () => noop } };
});

import { ossSessionEnforcer, ossSessionMembership } from "./session-membership";

const SESSION: SessionUser = { id: "sub-1", email: "a@example.com" };
const USER = { id: "user-1", email: "a@example.com", name: null };

beforeEach(() => {
  state.membership = null;
  state.throwOnMembership = false;
});

describe("ossSessionEnforcer", () => {
  it("admits a session holding an active membership", async () => {
    state.membership = { role: "member" };
    expect(await ossSessionEnforcer(SESSION, USER)).toBeNull();
  });

  it("DENIES an authenticated identity with no membership", async () => {
    state.membership = null;
    const denial = await ossSessionEnforcer(SESSION, USER);
    expect(denial?.code).toBe("NOT_AUTHORISED");
  });

  it("DENIES when the membership check throws", async () => {
    // Fail-closed: a database problem must not become an open door.
    state.throwOnMembership = true;
    const denial = await ossSessionEnforcer(SESSION, USER);
    expect(denial?.code).toBe("AUTHORISATION_UNAVAILABLE");
  });

  it("returns a denial rather than throwing", async () => {
    // A throw lands in the route's catch as a 500, which carries no code for
    // the denial page.
    state.throwOnMembership = true;
    await expect(ossSessionEnforcer(SESSION, USER)).resolves.toBeTruthy();
  });

  it("carries a code the denial page can render, on every denial path", async () => {
    state.membership = null;
    const noMember = await ossSessionEnforcer(SESSION, USER);
    state.throwOnMembership = true;
    const dbDown = await ossSessionEnforcer(SESSION, USER);

    for (const denial of [noMember, dbDown]) {
      expect(denial?.code).toBeTruthy();
      expect(denial?.error).toBeTruthy();
    }
  });
});

describe("ossSessionMembership contract", () => {
  it("never throws, even when the database is unreachable", async () => {
    // Contract on the hook: membership is best-effort, session resolution is
    // not. A throw here surfaces as a 500 instead of a denial.
    state.throwOnMembership = true;
    await expect(ossSessionMembership(SESSION, USER)).resolves.toBeUndefined();
  });

  it("is a no-op before the shared org exists", async () => {
    await expect(ossSessionMembership(SESSION, USER)).resolves.toBeUndefined();
  });
});
