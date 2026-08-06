import { describe, expect, it } from "vitest";
import { getAppPermissionDefinitions } from ".";
import type { AppTool } from "./types";

// A write group's `wildcard` is the "gate all write operations" toggle, so its
// promise only holds if the wildcard is a genuine superset of every tool in the
// group: same host, a path prefix containing each tool's path, and a method set
// containing each tool's methods. Coverage is re-derived from the catalog here,
// so a new write endpoint that escapes its wildcard turns the suite red.

const methodsOf = (tool: AppTool): string[] =>
  tool.methods ?? (tool.method ? [tool.method] : []);

// Every glob a tool is reachable at: its primary path plus any host-path
// aliases.
const patternsOf = (tool: AppTool): string[] => [
  tool.pathPattern,
  ...(tool.aliasPatterns ?? []),
];

// Tool patterns reuse the wildcard's leading "*" segments verbatim, so a
// `startsWith` on the text before the trailing "*" mirrors the gateway's prefix
// match and fails closed.
const prefixOf = (pattern: string): string =>
  pattern.endsWith("*") ? pattern.slice(0, -1) : pattern;

// Every write group across the whole catalog that ships a gate-all wildcard.
const writeWildcardGroups = getAppPermissionDefinitions().flatMap((def) =>
  def.groups
    .filter((group) => group.category === "write" && group.wildcard)
    .map((group) => ({
      provider: def.provider,
      wildcard: group.wildcard!,
      tools: group.tools,
    })),
);

describe.each(writeWildcardGroups)(
  "$provider · write wildcard is a true superset of its tools",
  ({ wildcard, tools }) => {
    it("is a prefix glob (path ends with /*)", () => {
      expect(wildcard.pathPattern.endsWith("/*")).toBe(true);
    });

    const prefixes = [
      wildcard.pathPattern,
      ...(wildcard.aliasPatterns ?? []),
    ].map(prefixOf);
    const wildcardMethods = methodsOf(wildcard);

    it.each(tools)("covers $id", (tool) => {
      // A wildcard can only gate calls to its own host.
      expect(tool.hostPattern).toBe(wildcard.hostPattern);

      for (const pattern of patternsOf(tool)) {
        expect(prefixes.some((prefix) => pattern.startsWith(prefix))).toBe(
          true,
        );
      }

      for (const method of methodsOf(tool)) {
        expect(wildcardMethods).toContain(method);
      }
    });
  },
);

// Pin Gmail's destructive endpoints so they can't drop out of the write group.
const gmailExpectedWrites = [
  {
    id: "batch_modify_messages",
    method: "POST",
    path: "/gmail/v1/users/*/messages/batchModify",
  },
  {
    id: "batch_delete_messages",
    method: "POST",
    path: "/gmail/v1/users/*/messages/batchDelete",
  },
  {
    id: "delete_message",
    method: "DELETE",
    path: "/gmail/v1/users/*/messages/*",
  },
  {
    id: "untrash_message",
    method: "POST",
    path: "/gmail/v1/users/*/messages/*/untrash",
  },
  { id: "insert_message", method: "POST", path: "/gmail/v1/users/*/messages" },
  {
    id: "import_message",
    method: "POST",
    path: "/gmail/v1/users/*/messages/import",
  },
  {
    id: "trash_thread",
    method: "POST",
    path: "/gmail/v1/users/*/threads/*/trash",
  },
  {
    id: "untrash_thread",
    method: "POST",
    path: "/gmail/v1/users/*/threads/*/untrash",
  },
  {
    id: "modify_thread",
    method: "POST",
    path: "/gmail/v1/users/*/threads/*/modify",
  },
  {
    id: "delete_thread",
    method: "DELETE",
    path: "/gmail/v1/users/*/threads/*",
  },
  { id: "update_draft", method: "PUT", path: "/gmail/v1/users/*/drafts/*" },
];

describe("gmail write catalog locks the reported destructive endpoints", () => {
  const gmail = getAppPermissionDefinitions().find(
    (d) => d.provider === "gmail",
  );
  const writeGroup = gmail?.groups.find((group) => group.category === "write");
  const byId = new Map(
    (writeGroup?.tools ?? []).map((tool) => [tool.id, tool]),
  );

  it.each(gmailExpectedWrites)(
    "enumerates $id ($method $path)",
    ({ id, method, path }) => {
      const tool = byId.get(id);
      expect(tool).toBeDefined();
      expect(methodsOf(tool!)).toContain(method);
      expect(tool!.pathPattern).toBe(path);
    },
  );

  it("gates the batchModify inbox-delete path via the write wildcard", () => {
    const wildcard = writeGroup?.wildcard;
    expect(wildcard).toBeDefined();
    expect(wildcard!.pathPattern).toBe("/gmail/v1/*");
    expect(methodsOf(wildcard!)).toContain("POST");
    expect(
      "/gmail/v1/users/*/messages/batchModify".startsWith(
        prefixOf(wildcard!.pathPattern),
      ),
    ).toBe(true);
  });

  it("also covers upload-shaped writes through the wildcard alias", () => {
    const wildcard = writeGroup?.wildcard;
    expect(wildcard?.aliasPatterns).toContain("/upload/gmail/v1/*");
  });
});
