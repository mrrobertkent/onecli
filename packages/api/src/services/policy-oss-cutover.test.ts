import { beforeEach, describe, expect, it, vi } from "vitest";

// The `db` mock is a landmine on purpose: the seeder must not read the database
// at all, so any query fails loudly.

const state = vi.hoisted(() => ({
  calls: [] as { scope: unknown; rules: Record<string, unknown>[] }[],
}));

vi.mock("./policy-service", () => ({
  backfillPublishScope: async (
    scope: unknown,
    rules: Record<string, unknown>[],
  ) => {
    state.calls.push({ scope, rules });
    return { skipped: false, generation: 1, ruleCount: rules.length };
  },
}));

vi.mock("@onecli/db", () => ({
  db: new Proxy(
    {},
    {
      get() {
        throw new Error(
          "the OSS project seeder must not query the database — its posture is pinned to allow",
        );
      },
    },
  ),
}));

const { ossNewProjectPolicySeeder } = await import("./policy-oss-cutover");

beforeEach(() => {
  state.calls = [];
});

describe("the OSS new-project seeded posture", () => {
  it("seeds exactly one project Default Rule with action ALLOW", async () => {
    await ossNewProjectPolicySeeder.seed("org-x", "proj-1");
    expect(state.calls).toHaveLength(1);
    expect(state.calls[0]?.scope).toEqual({ projectId: "proj-1" });
    expect(state.calls[0]?.rules).toHaveLength(1);
    expect(state.calls[0]?.rules[0]).toMatchObject({
      isDefault: true,
      source: "default",
      name: "Default Rule",
      action: "allow",
      priority: 0,
      requireApproval: false,
      identities: [],
      targets: [],
    });
  });

  it("stays ALLOW no matter what exists already — no instance-posture inheritance", async () => {
    await ossNewProjectPolicySeeder.seed("org-x", "proj-2");
    await ossNewProjectPolicySeeder.seed("org-x", "proj-3");
    expect(state.calls.map((c) => c.rules[0]?.action)).toEqual([
      "allow",
      "allow",
    ]);
  });

  it("no-ops for an org-only call — OSS has no org scope", async () => {
    await ossNewProjectPolicySeeder.seed("org-x");
    expect(state.calls).toHaveLength(0);
  });
});
