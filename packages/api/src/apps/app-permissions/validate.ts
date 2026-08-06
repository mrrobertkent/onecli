import { ServiceError } from "../../services/errors";
import { getAppPermissionDefinition } from "./index";

/**
 * Validate that every tool id names a concrete catalog tool of `provider`.
 *
 * An unknown id would compile into a rule that matches nothing, so reject it
 * loudly rather than silently no-op. Group wildcard ids count as unknown here:
 * the grant compiler needs the concrete set to derive the blocked complement.
 * A provider with no catalog has no per-tool axis at all, so any tool list for
 * it is unprocessable.
 */
export const assertToolIdsValid = (
  provider: string,
  toolIds: string[],
): void => {
  if (toolIds.length === 0) return;
  const def = getAppPermissionDefinition(provider);
  if (!def) {
    throw new ServiceError(
      "UNPROCESSABLE",
      `Per-tool permissions need a permission catalog; "${provider}" has none.`,
    );
  }
  const known = new Set(def.groups.flatMap((g) => g.tools.map((t) => t.id)));
  const unknown = [...new Set(toolIds)].filter((id) => !known.has(id));
  if (unknown.length > 0) {
    throw new ServiceError(
      "UNPROCESSABLE",
      `Unknown tool id(s) for "${provider}": ${unknown.join(", ")}`,
    );
  }
};

/** The provider's full concrete tool-id set, which the grant compiler derives
 * the blocked complement from. Empty for a catalog-less provider. */
export const catalogToolIds = (provider: string): string[] => {
  const def = getAppPermissionDefinition(provider);
  if (!def) return [];
  return def.groups.flatMap((g) => g.tools.map((t) => t.id));
};
