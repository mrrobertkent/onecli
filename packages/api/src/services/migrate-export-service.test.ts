import { beforeEach, describe, expect, it, vi } from "vitest";

// The self-hosted → cloud exporter carries secrets and agents only. The property
// under test is that the policy it cannot carry is reported, so a customer with
// rules never sees a clean success and lands on a destination enforcing nothing
// they authored.

const state = vi.hoisted(() => ({
  secrets: [] as unknown[],
  agents: [] as unknown[],
  policyCount: 0,
  ruleCountWhere: null as unknown,
  sent: null as Record<string, unknown> | null,
}));

vi.mock("@onecli/db", () => ({
  Prisma: {},
  db: {
    secret: { findMany: async () => state.secrets },
    agent: { findMany: async () => state.agents },
    policyRuleV2: {
      count: async (args: { where: unknown }) => {
        state.ruleCountWhere = args.where;
        return state.policyCount;
      },
    },
  },
}));

vi.mock("../providers", () => ({
  getCrypto: () => ({ decrypt: async (v: string) => `plain:${v}` }),
}));

const { exportToCloud } = await import("./migrate-export-service");

beforeEach(() => {
  state.secrets = [];
  state.agents = [];
  state.policyCount = 0;
  state.ruleCountWhere = null;
  state.sent = null;
  vi.stubGlobal(
    "fetch",
    vi.fn(async (_url: string, init: { body: string }) => {
      state.sent = JSON.parse(init.body) as Record<string, unknown>;
      return {
        ok: true,
        json: async () => ({
          imported: { secrets: 1, agents: 1, agentSecrets: 0, rules: 0 },
          skipped: [],
        }),
      };
    }),
  );
});

const secret = () => ({
  name: "key",
  type: "anthropic",
  valueSource: "inline",
  encryptedValue: "enc",
  hostPattern: "api.anthropic.com",
  pathPattern: null,
  injectionConfig: null,
  metadata: null,
});

describe("policy that cannot be migrated is reported, never dropped silently", () => {
  it("reports the project's rules in skipped[] with a count and a next step", async () => {
    state.secrets = [secret()];
    state.policyCount = 3;
    const result = await exportToCloud("proj-1", "key", "https://cloud");
    const policySkip = result.skipped.find((s) => s.type === "policy");
    expect(policySkip).toBeDefined();
    expect(policySkip?.name).toBe("3 policy rules");
    expect(policySkip?.reason).toMatch(/Policy console/);
  });

  it("singularises one rule (the message is user-facing)", async () => {
    state.secrets = [secret()];
    state.policyCount = 1;
    const result = await exportToCloud("proj-1", "key", "https://cloud");
    expect(result.skipped.find((s) => s.type === "policy")?.name).toBe(
      "1 policy rule",
    );
  });

  it("says nothing when the project has no policy of its own", async () => {
    state.secrets = [secret()];
    state.policyCount = 0;
    const result = await exportToCloud("proj-1", "key", "https://cloud");
    expect(result.skipped.some((s) => s.type === "policy")).toBe(false);
  });

  it("reports even when there is nothing else to export at all", async () => {
    // The early return for an empty project is the easiest place to lose the
    // warning: no secrets and no agents, but the user still had policy.
    state.policyCount = 2;
    const result = await exportToCloud("proj-1", "key", "https://cloud");
    expect(result.skipped.find((s) => s.type === "policy")?.name).toBe(
      "2 policy rules",
    );
  });

  it("counts the user's OWN rules — not the default, blocklist or grants", async () => {
    state.secrets = [secret()];
    await exportToCloud("proj-1", "key", "https://cloud");
    expect(state.ruleCountWhere).toMatchObject({
      scope: "project",
      projectId: "proj-1",
      status: "draft",
      isDefault: false,
      source: { notIn: ["blocklist", "equipment", "grant"] },
    });
  });
});

describe("the frozen tables never travel", () => {
  it("the payload carries secrets + agents only", async () => {
    state.secrets = [secret()];
    state.agents = [
      { name: "bot", identifier: "bot", isDefault: true, secretMode: "all" },
    ];
    await exportToCloud("proj-1", "key", "https://cloud");
    expect(Object.keys(state.sent ?? {}).sort()).toEqual([
      "agents",
      "secrets",
      "version",
    ]);
  });
});
