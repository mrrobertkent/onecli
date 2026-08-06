import { beforeEach, describe, expect, it, vi } from "vitest";

// The sign-up gate's whole value is that it fails closed: every path where the
// setting cannot be established must deny.

const state = vi.hoisted(() => ({
  row: null as { signupMode: string } | null,
  throwOnRead: false,
  upserts: [] as Record<string, unknown>[],
}));

vi.mock("@onecli/db", () => ({
  db: {
    instanceSetting: {
      findUnique: async () => {
        if (state.throwOnRead) throw new Error("connection refused");
        return state.row;
      },
      upsert: async (args: Record<string, unknown>) => {
        state.upserts.push(args);
        return args;
      },
    },
  },
}));

vi.mock("../lib/logger", () => ({
  logger: { warn: () => {}, info: () => {}, error: () => {} },
}));

import { getSignupMode, isSignupAllowed, setSignupMode } from "./signup-policy";

beforeEach(() => {
  state.row = null;
  state.throwOnRead = false;
  state.upserts = [];
});

describe("getSignupMode fail-closed paths", () => {
  it("denies when no settings row exists yet (fresh instance)", async () => {
    expect(await getSignupMode()).toBe("closed");
  });

  it("denies when the database read throws", async () => {
    state.throwOnRead = true;
    expect(await getSignupMode()).toBe("closed");
  });

  it("denies on a value this build does not recognise", async () => {
    // e.g. written by a newer version, or hand-edited. Admitting on an unknown
    // value would make a typo an instance-wide opening.
    state.row = { signupMode: "opne" };
    expect(await getSignupMode()).toBe("closed");
  });

  it("returns a recognised value unchanged", async () => {
    state.row = { signupMode: "sso-only" };
    expect(await getSignupMode()).toBe("sso-only");
  });
});

describe("isSignupAllowed", () => {
  it("closed denies both kinds", async () => {
    state.row = { signupMode: "closed" };
    expect(await isSignupAllowed("sso")).toBe(false);
    expect(await isSignupAllowed("password")).toBe(false);
  });

  it("sso-only admits SSO but NOT password self-registration", async () => {
    // The reason the setting is three-valued rather than a boolean: these are
    // different decisions and a boolean forces them together.
    state.row = { signupMode: "sso-only" };
    expect(await isSignupAllowed("sso")).toBe(true);
    expect(await isSignupAllowed("password")).toBe(false);
  });

  it("open admits both", async () => {
    state.row = { signupMode: "open" };
    expect(await isSignupAllowed("sso")).toBe(true);
    expect(await isSignupAllowed("password")).toBe(true);
  });

  it("denies both kinds when the read fails", async () => {
    state.throwOnRead = true;
    expect(await isSignupAllowed("sso")).toBe(false);
    expect(await isSignupAllowed("password")).toBe(false);
  });
});

describe("setSignupMode", () => {
  it("returns the previous value so the audit entry can record both sides", async () => {
    state.row = { signupMode: "closed" };
    const result = await setSignupMode("open", "user-1");
    expect(result).toEqual({ previous: "closed", next: "open" });
    expect(state.upserts).toHaveLength(1);
  });

  it("reports an unreadable previous value as closed rather than guessing", async () => {
    state.throwOnRead = true;
    const result = await setSignupMode("open", "user-1");
    expect(result.previous).toBe("closed");
  });
});
