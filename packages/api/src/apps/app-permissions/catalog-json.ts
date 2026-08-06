import { allGroupTools, type AppPermissionDefinition } from "./types";

// The gateway-facing projection of the catalog: per provider, per tool id, the
// host + path(×alias) + method(s) that tool fans into. The TypeScript catalog is
// authored; this JSON is derived from it and drift-checked in CI, so the API and
// the gateway cannot disagree.
//
// Server-only: the endpoint mapping must never reach a client bundle.

/** One tool's endpoint fan-out. Empty `methods` means any method. */
export interface CatalogTool {
  hostPattern: string;
  paths: string[];
  methods: string[];
}

/** provider → tool id → endpoints. */
export type CatalogJson = Record<string, Record<string, CatalogTool>>;

/** Derive the gateway catalog projection from catalog definitions. Includes the
 * wildcard tool of each group (via `allGroupTools`), keyed by tool id. */
export const buildCatalogJson = (
  defs: AppPermissionDefinition[],
): CatalogJson => {
  const out: CatalogJson = {};
  for (const def of defs) {
    const tools: Record<string, CatalogTool> = {};
    for (const group of def.groups) {
      for (const tool of allGroupTools(group)) {
        tools[tool.id] = {
          hostPattern: tool.hostPattern,
          paths: [tool.pathPattern, ...(tool.aliasPatterns ?? [])],
          // Empty `methods` means "any method", so never author an explicit
          // `methods: []` to mean "no method": TS would match nothing while the
          // gateway matches everything. Omit `method`/`methods` instead.
          methods: tool.methods ?? (tool.method ? [tool.method] : []),
        };
      }
    }
    // Sort tool keys for a stable, diff-friendly serialization.
    out[def.provider] = Object.fromEntries(
      Object.entries(tools).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
    );
  }
  return Object.fromEntries(
    Object.entries(out).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
  );
};

/** Canonical serialization — the exact bytes committed and drift-checked. */
export const serializeCatalogJson = (catalog: CatalogJson): string =>
  `${JSON.stringify(catalog, null, 2)}\n`;
