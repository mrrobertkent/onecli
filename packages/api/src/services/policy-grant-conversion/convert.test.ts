import { describe, expect, it } from "vitest";
import { groupsToGrantInput } from "./convert";

// A `mixed` verdict is unreachable once network/behavioral rules are excluded
// from the fold, so hitting one means an unmodeled rule shape and must abort
// rather than bake a guess into a grant stack. The pg proofs cannot reach this.

const group = (tools: { toolId: string; verdict: string }[]) => [{ tools }];

describe("groupsToGrantInput", () => {
  it("all allow/unmanaged folds to the uncustomized whole-app attach", () => {
    expect(
      groupsToGrantInput(
        group([
          { toolId: "a", verdict: "allow" },
          { toolId: "b", verdict: "unmanaged" },
        ]),
        "agent-1",
      ),
    ).toEqual({ access: "full" });
  });

  it("any approval or block customizes with the exact A/K split", () => {
    expect(
      groupsToGrantInput(
        group([
          { toolId: "a", verdict: "allow" },
          { toolId: "k", verdict: "approval" },
          { toolId: "b", verdict: "block" },
        ]),
        "agent-1",
      ),
    ).toEqual({ access: "custom", allow: ["a"], ask: ["k"] });
  });

  it("a mixed verdict aborts loudly instead of guessing", () => {
    expect(() =>
      groupsToGrantInput(group([{ toolId: "t", verdict: "mixed" }]), "agent-1"),
    ).toThrow(/unconvertible/);
  });
});
