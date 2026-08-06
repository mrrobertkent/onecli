import { describe, expect, it } from "vitest";
import { getAppPermissionDefinitions } from ".";
import {
  toAppPermissionDefinitionSummary,
  wildcardCoversGroup,
  type AppTool,
} from "./types";

const methodsOf = (tool: AppTool): string[] =>
  tool.methods ?? (tool.method ? [tool.method] : []);

// The tools picker offers a group's `wildcard` as "all of them" only when the
// server stamps the group `wildcardComplete`. Read wildcards are allowed to be
// incomplete and some genuinely are, so this file pins which, and a catalog edit
// that changes a wildcard's coverage turns the suite red.

// Every group across the catalog that ships a wildcard, paired with the
// server-computed summary flag for the same group.
const wildcardGroups = getAppPermissionDefinitions().flatMap((def) => {
  const summary = toAppPermissionDefinitionSummary(def);
  return def.groups.flatMap((group, index) =>
    group.wildcard
      ? [
          {
            provider: def.provider,
            category: group.category,
            wildcard: group.wildcard,
            tools: group.tools,
            summaryComplete: summary.groups[index]?.wildcardComplete,
          },
        ]
      : [],
  );
});

describe("wildcardComplete on the real catalog", () => {
  it("has at least one wildcard group to check", () => {
    expect(wildcardGroups.length).toBeGreaterThan(0);
  });

  it.each(wildcardGroups)(
    "$provider · $category wildcard is a prefix glob (path ends with /*)",
    ({ wildcard }) => {
      // A "/*"-terminated pattern leaves `wildcardCoversGroup` a prefix ending
      // in "/", so a tool is only covered at a segment boundary.
      expect(wildcard.pathPattern.endsWith("/*")).toBe(true);
    },
  );

  it.each(wildcardGroups)(
    "$provider · $category wildcard + every tool declares a method",
    ({ wildcard, tools }) => {
      // A tool declaring neither method nor methods yields an empty list, which
      // `wildcardCoversGroup`'s `.every` satisfies vacuously — marking it
      // covered whatever the wildcard's methods are.
      expect(methodsOf(wildcard).length).toBeGreaterThan(0);
      for (const tool of tools) {
        expect(methodsOf(tool).length).toBeGreaterThan(0);
      }
    },
  );

  it.each(wildcardGroups)(
    "$provider · $category summary flag equals the coverage function",
    ({ wildcard, tools, summaryComplete }) => {
      expect(summaryComplete).toBe(wildcardCoversGroup(wildcard, tools));
    },
  );

  it.each(wildcardGroups.filter((g) => g.category === "write"))(
    "$provider · write wildcard is complete (a gate must cover every write)",
    ({ summaryComplete }) => {
      expect(summaryComplete).toBe(true);
    },
  );
});

// Pin the known read-wildcard cases so the picker's behavior can't flip.
const readComplete = (provider: string): boolean | undefined => {
  const summary = toAppPermissionDefinitionSummary(
    getAppPermissionDefinitions().find((d) => d.provider === provider)!,
  );
  return summary.groups.find((g) => g.category === "read")?.wildcardComplete;
};

describe("known read-wildcard coverage", () => {
  it("gmail 'All read operations' is complete (/gmail/v1/* GET covers every read)", () => {
    expect(readComplete("gmail")).toBe(true);
  });

  it("jira 'All read operations' is INCOMPLETE (read_all is GET-only, JQL search is POST)", () => {
    expect(readComplete("jira")).toBe(false);
  });

  it("confluence 'All read operations' is INCOMPLETE (search lives on /wiki/rest/api, not the /wiki/api/v2/* umbrella)", () => {
    expect(readComplete("confluence")).toBe(false);
  });
});
