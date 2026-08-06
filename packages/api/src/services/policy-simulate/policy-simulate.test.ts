import { beforeEach, describe, expect, it, vi } from "vitest";

// The policy rule-load services' contracts: every read is org/project-fenced at
// the query level, the rule load mirrors the gateway's (enabled-only, defaults
// included, equipment dropped, max published generation), and the row→rule
// mapper decodes all three identity kinds and resolves secret hosts and
// connection providers fail-closed. The db is mocked at the boundary and the
// recorded `where`s are asserted.

const state = vi.hoisted(() => ({
  calls: [] as { model: string; op: string; args: unknown }[],
  results: new Map<string, unknown>(),
  aggregate: { _max: { generation: null as number | null } },
}));

const record = vi.hoisted(
  () =>
    (model: string) =>
    (op: string) =>
    async (args: unknown): Promise<unknown> => {
      state.calls.push({ model, op, args });
      if (op === "aggregate") return state.aggregate;
      return state.results.get(`${model}.${op}`) ?? [];
    },
);

vi.mock("@onecli/db", () => {
  const model = (name: string) => ({
    findMany: record(name)("findMany"),
    aggregate: record(name)("aggregate"),
  });
  return {
    Prisma: {},
    db: {
      projectAccess: model("projectAccess"),
      group: model("group"),
      groupMember: model("groupMember"),
      organizationMember: model("organizationMember"),
      secret: model("secret"),
      appConnection: model("appConnection"),
      policyRuleV2: model("policyRuleV2"),
    },
  };
});

const { resolvePrincipalSet } = await import("./principal-set");
const { loadSecretHosts } = await import("./secret-hosts");
const { loadConnectionProviders } = await import("./connection-providers");
const { loadRulesForSimulation } = await import("./load-rules");
const { toSimRule } = await import("./sim-rule");
import type { SimRuleRow } from "./load-rules";

const whereOf = (model: string, index = 0): Record<string, unknown> => {
  const call = state.calls.filter((c) => c.model === model)[index];
  return (call?.args as { where: Record<string, unknown> })?.where ?? {};
};

beforeEach(() => {
  state.calls = [];
  state.results = new Map();
  state.aggregate = { _max: { generation: null } };
});

describe("resolvePrincipalSet (find_principal_set mirror)", () => {
  it("org-fences every arm and filters suspended members", async () => {
    state.results.set("projectAccess.findMany", [
      { userId: "u1", groupId: null },
      { userId: null, groupId: "g1" },
    ]);
    state.results.set("group.findMany", [{ id: "g1" }]);
    // groupMember is read twice (group→members, then user→groups) — the shared
    // stub row carries both fields so each read maps its own column.
    state.results.set("groupMember.findMany", [
      { userId: "u2", groupId: "g1" },
    ]);
    state.results.set("organizationMember.findMany", [{ userId: "u1" }]);

    const set = await resolvePrincipalSet("p1", "org-1");

    // Granted groups are org-fenced.
    expect(whereOf("group")).toEqual({
      id: { in: ["g1"] },
      organizationId: "org-1",
    });
    // Only active members of this org survive (u2 was filtered out).
    expect(whereOf("organizationMember")).toEqual({
      userId: { in: ["u1", "u2"] },
      organizationId: "org-1",
      status: { not: "suspended" },
    });
    expect(set.userIds).toEqual(["u1"]);
    expect(set.groupIds).toEqual(["g1"]);
  });

  it("expands the surviving users' groups org-fenced", async () => {
    state.results.set("projectAccess.findMany", [
      { userId: "u1", groupId: null },
    ]);
    state.results.set("organizationMember.findMany", [{ userId: "u1" }]);
    state.results.set("groupMember.findMany", [{ groupId: "g9" }]);

    const set = await resolvePrincipalSet("p1", "org-1");

    // The user→groups expansion carries the org fence — a user can belong to
    // other orgs' groups.
    const expansion = state.calls.filter((c) => c.model === "groupMember");
    expect(
      (expansion.at(-1)?.args as { where: Record<string, unknown> }).where,
    ).toEqual({ userId: { in: ["u1"] }, group: { organizationId: "org-1" } });
    expect(set.groupIds).toEqual(["g9"]);
  });
});

describe("loadSecretHosts (find_secret_hosts mirror)", () => {
  it("fences to the acting org+project and splits levels", async () => {
    state.results.set("secret.findMany", [
      { id: "s1", hostPattern: "api.a.com", scope: "project" },
      { id: "s2", hostPattern: "api.b.com", scope: "organization" },
    ]);

    const set = await loadSecretHosts("org-1", "p1");

    expect(whereOf("secret")).toEqual({
      OR: [
        { projectId: "p1" },
        { organizationId: "org-1", scope: "organization" },
      ],
    });
    expect(set.projectHosts).toEqual(["api.a.com"]);
    expect(set.orgHosts).toEqual(["api.b.com"]);
    expect(set.byId.get("s2")).toBe("api.b.com");
  });
});

describe("loadConnectionProviders (find_connection_providers mirror)", () => {
  it("fences to the acting org+project — a foreign connection id can never resolve", async () => {
    state.results.set("appConnection.findMany", [
      { id: "c1", provider: "gmail" },
      { id: "c2", provider: "github" },
    ]);

    const map = await loadConnectionProviders("org-1", "p1");

    // The fence is the query: a rule naming another org's connection id
    // resolves to nothing.
    expect(whereOf("appConnection")).toEqual({
      OR: [
        { projectId: "p1" },
        { organizationId: "org-1", scope: "organization" },
      ],
    });
    expect(map.get("c1")).toBe("gmail");
    expect(map.get("c-foreign")).toBeUndefined();
  });
});

describe("loadRulesForSimulation (gateway-load mirror)", () => {
  it("loads enabled non-equipment rules, defaults INCLUDED", async () => {
    await loadRulesForSimulation(
      { scope: "project", projectId: "p1" },
      "draft",
    );

    const where = whereOf("policyRuleV2");
    expect(where).toEqual({
      scope: "project",
      projectId: "p1",
      status: "draft",
      enabled: true,
      source: { not: "equipment" },
    });
    // No isDefault filter, so the Default Rules load.
    expect("isDefault" in where).toBe(false);
  });

  it("pins published to the active max generation", async () => {
    state.aggregate = { _max: { generation: 4 } };
    await loadRulesForSimulation(
      { scope: "organization", organizationId: "org-1" },
      "published",
    );

    const find = state.calls.find(
      (c) => c.model === "policyRuleV2" && c.op === "findMany",
    );
    expect(
      (find?.args as { where: { generation: number } }).where.generation,
    ).toBe(4);
  });

  it("returns [] when nothing was ever published", async () => {
    expect(
      await loadRulesForSimulation(
        { scope: "organization", organizationId: "org-1" },
        "published",
      ),
    ).toEqual([]);
  });

  // `NewRule` carries no id, so the evaluator can't re-sort by it: the
  // equal-priority tie-break lives entirely in this loader's orderBy.
  it("orders by (priority, id) — the gateway-consistent tie-break", async () => {
    await loadRulesForSimulation(
      { scope: "project", projectId: "p1" },
      "draft",
    );
    const find = state.calls.find(
      (c) => c.model === "policyRuleV2" && c.op === "findMany",
    );
    expect((find?.args as { orderBy: unknown }).orderBy).toEqual([
      { priority: "asc" },
      { id: "asc" },
    ]);
  });
});

// ── toSimRule (pure) ────────────────────────────────────────────────────────

const simRow = (over: Partial<SimRuleRow>): SimRuleRow =>
  ({
    id: "r1",
    scope: "project",
    projectId: "p1",
    organizationId: null,
    status: "published",
    generation: 1,
    priority: 1,
    enabled: true,
    isDefault: false,
    logicalId: "l1",
    source: "custom",
    name: "Rule",
    description: null,
    action: "block",
    rateLimit: null,
    rateLimitWindow: null,
    requireApproval: false,
    conditions: null,
    createdByUserId: null,
    createdAt: new Date("2026-01-01"),
    updatedAt: new Date("2026-01-01"),
    identities: [],
    targets: [],
    ...over,
  }) as SimRuleRow;

const identityRow = (
  over: Partial<SimRuleRow["identities"][number]>,
): SimRuleRow["identities"][number] =>
  ({
    id: "i1",
    ruleId: "r1",
    agentId: null,
    userId: null,
    groupId: null,
    ...over,
  }) as SimRuleRow["identities"][number];

const targetRow = (
  over: { kind: string } & Partial<SimRuleRow["targets"][number]>,
): SimRuleRow["targets"][number] =>
  ({
    id: "t1",
    ruleId: "r1",
    appProvider: null,
    appTools: [],
    appConnectionScope: null,
    appConnectionId: null,
    secretId: null,
    secretScope: null,
    hostPattern: null,
    pathPattern: null,
    method: null,
    ...over,
  }) as SimRuleRow["targets"][number];

const emptyHosts = {
  byId: new Map<string, string>(),
  projectHosts: [],
  orgHosts: [],
};

const emptyProviders = new Map<string, string>();

describe("toSimRule (decode_row mirror, full fidelity)", () => {
  it("decodes all THREE identity kinds", () => {
    const { rule } = toSimRule(
      simRow({
        identities: [
          identityRow({ agentId: "a1" }),
          identityRow({ userId: "u1" }),
          identityRow({ groupId: "g1" }),
        ],
      }),
      emptyHosts,
      emptyProviders,
    );
    expect(rule.identities).toEqual([
      { type: "agent", id: "a1" },
      { type: "user", id: "u1" },
      { type: "group", id: "g1" },
    ]);
  });

  it("resolves a specific secret target to its fenced host, fail-closed", () => {
    const hosts = {
      byId: new Map([["s1", "api.a.com"]]),
      projectHosts: ["api.a.com"],
      orgHosts: ["api.o.com"],
    };
    const { rule } = toSimRule(
      simRow({
        targets: [
          targetRow({ kind: "secret", secretId: "s1" }),
          targetRow({ kind: "secret", secretId: "missing" }),
          targetRow({ kind: "secret", secretScope: "organization" }),
        ],
      }),
      hosts,
      emptyProviders,
    );
    expect(rule.targets).toEqual([
      { kind: "secret", hostPatterns: ["api.a.com"] },
      { kind: "secret", hostPatterns: [] },
      { kind: "secret", hostPatterns: ["api.o.com"] },
    ]);
  });

  it("maps unknown/provider-less targets to inert connection targets", () => {
    const { rule } = toSimRule(
      simRow({
        targets: [targetRow({ kind: "app" }), targetRow({ kind: "mystery" })],
      }),
      emptyHosts,
      emptyProviders,
    );
    expect(rule.targets.every((t) => t.kind === "connection")).toBe(true);
  });

  it("resolves a connection target keeping its id (per-connection decisions)", () => {
    // The id is kept, so the target binds to the connection that wins
    // injection (no tools = the whole app, host-only).
    const { rule } = toSimRule(
      simRow({
        targets: [targetRow({ kind: "connection", appConnectionId: "c1" })],
      }),
      emptyHosts,
      new Map([["c1", "gmail"]]),
    );
    expect(rule.targets).toEqual([
      { kind: "connection", connectionId: "c1", provider: "gmail", tools: [] },
    ]);
  });

  it("carries a tool-narrowed connection target's tools onto the resolved shape", () => {
    // A tools-narrowed target keeps both its tools (the tool fan-out, not the
    // whole app) and its id.
    const { rule } = toSimRule(
      simRow({
        targets: [
          targetRow({
            kind: "connection",
            appConnectionId: "c1",
            appTools: ["read_message", "search_messages"],
          }),
        ],
      }),
      emptyHosts,
      new Map([["c1", "gmail"]]),
    );
    expect(rule.targets).toEqual([
      {
        kind: "connection",
        connectionId: "c1",
        provider: "gmail",
        tools: ["read_message", "search_messages"],
      },
    ]);
  });

  it("leaves a connection target inert when its id is missing from the fenced map", () => {
    // Deleted in the cache window, or foreign/forged (the fence excluded it) —
    // the target stays an unresolved connection target (never matches).
    const { rule } = toSimRule(
      simRow({
        targets: [targetRow({ kind: "connection", appConnectionId: "c-gone" })],
      }),
      emptyHosts,
      emptyProviders,
    );
    expect(rule.targets).toEqual([
      { kind: "connection", connectionId: "c-gone", tools: [] },
    ]);
  });

  it("keeps a degenerate identity row as a never-matching entry (gateway mirror)", () => {
    // A no-principal row is impossible per the DB CHECK, but the mirror must
    // not INVERT it: dropping the entry would flip `identities: []` = "any
    // agent" (the gateway keeps `Identity::Unresolved` — never matches).
    const { rule } = toSimRule(
      simRow({ identities: [identityRow({})] }),
      emptyHosts,
      emptyProviders,
    );
    expect(rule.identities).toEqual([{ type: "agent", id: "" }]);
  });

  it("coerces malformed conditions to null, all-or-nothing", () => {
    const good = toSimRule(
      simRow({
        conditions: [{ target: "body", operator: "contains", value: "x" }],
      }),
      emptyHosts,
      emptyProviders,
    );
    const bad = toSimRule(
      simRow({
        conditions: [
          { target: "body", operator: "contains", value: "x" },
          { broken: true },
        ],
      }),
      emptyHosts,
      emptyProviders,
    );
    expect(good.rule.conditions).toEqual([
      { target: "body", operator: "contains", value: "x" },
    ]);
    expect(bad.rule.conditions).toBeNull();
  });

  it("carries the naming metadata beside the engine rule", () => {
    const sim = toSimRule(
      simRow({
        id: "row-9",
        logicalId: "l-9",
        name: "Named",
        scope: "organization",
      }),
      emptyHosts,
      emptyProviders,
    );
    expect(sim.meta).toEqual({
      id: "row-9",
      logicalId: "l-9",
      name: "Named",
      scope: "organization",
      source: "custom",
    });
  });
});
