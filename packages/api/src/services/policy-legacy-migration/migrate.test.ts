import { beforeEach, describe, expect, it, vi } from "vitest";

// The boot pass walks every project on every boot, so a converted project must
// cost one count and no read of the deprecated tables. This asserts on query
// shape; the pg suite proves the conversion itself is correct.

const calls = vi.hoisted(() => ({ log: [] as string[] }));
const state = vi.hoisted(() => ({
  publishedCount: 0,
  legacyCount: 0,
  activeDefaultDescription: null as string | null,
}));

const record = vi.hoisted(
  () => (model: string) => (op: string) => async (): Promise<unknown> => {
    calls.log.push(`${model}.${op}`);
    if (model === "policyRuleV2" && op === "count") return state.publishedCount;
    if (model === "policyRule" && op === "count") return state.legacyCount;
    if (model === "policyRuleV2" && op === "findFirst")
      return state.activeDefaultDescription === null
        ? null
        : { description: state.activeDefaultDescription };
    if (op === "count") return 0;
    if (op === "create") return { id: "r", logicalId: "l" };
    if (op === "deleteMany") return { count: 0 };
    if (op === "findFirst" || op === "findUnique") return null;
    return [];
  },
);

vi.mock("@onecli/db", () => {
  const model = (name: string) => ({
    count: record(name)("count"),
    findMany: record(name)("findMany"),
    findFirst: record(name)("findFirst"),
    findUnique: record(name)("findUnique"),
  });
  return {
    Prisma: {},
    db: {
      policyRule: model("policyRule"),
      policyRuleV2: model("policyRuleV2"),
      agent: model("agent"),
      organization: model("organization"),
      // `backfillPublishScope` takes a scope advisory lock inside the tx.
      $transaction: async (fn: (tx: unknown) => unknown) =>
        fn({
          $executeRaw: async () => 0,
          policyRuleV2: {
            count: record("policyRuleV2")("count"),
            create: record("policyRuleV2")("create"),
            deleteMany: record("policyRuleV2")("deleteMany"),
          },
        }),
    },
  };
});

const { cutoverOssProject } = await import("./migrate");
const { OSS_MIGRATED_DEFAULT_DESCRIPTION } = await import("./translate");

beforeEach(() => {
  calls.log = [];
  state.publishedCount = 0;
  state.legacyCount = 0;
  state.activeDefaultDescription = null;
});

describe("the steady state costs one count and touches no deprecated table", () => {
  it("a converted project with no legacy rows reads nothing else", async () => {
    state.publishedCount = 1;
    state.legacyCount = 0;
    const result = await cutoverOssProject("p1", "allow");
    expect(result).toEqual({ status: "skipped", ruleCount: 0 });
    // The only deprecated-table access is the legacy count.
    expect(calls.log).toEqual(["policyRuleV2.count", "policyRule.count"]);
  });

  it("never reads the legacy rules or the per-agent grants once converted", async () => {
    state.publishedCount = 1;
    state.legacyCount = 3;
    state.activeDefaultDescription = OSS_MIGRATED_DEFAULT_DESCRIPTION;
    await cutoverOssProject("p1", "allow");
    expect(calls.log).not.toContain("policyRule.findMany");
    expect(calls.log).not.toContain("agent.findMany");
  });

  it("still catches a user publish that pre-empted the conversion", async () => {
    // A published generation that isn't the migration's own means the legacy
    // rules were never carried over.
    state.publishedCount = 1;
    state.legacyCount = 3;
    state.activeDefaultDescription = "a user's own default";
    const result = await cutoverOssProject("p1", "allow");
    expect(result.preempted).toBe(true);
  });

  it("an UNCONVERTED project still does the full read", async () => {
    // The complement — proving the fast path is a fast path and not a skip.
    state.publishedCount = 0;
    await cutoverOssProject("p1", "allow");
    expect(calls.log).toContain("policyRule.findMany");
    expect(calls.log).toContain("agent.findMany");
  });
});
