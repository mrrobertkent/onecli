// `PUT /policy/rules/order` takes the full ordered id list, while the editor
// only lets the user rearrange the custom rules. This rebuilds the full
// permutation from a new custom relative order.

/** The minimal row shape the rebuild needs (satisfied by PolicyRuleDto). */
export interface ReorderableRule {
  id: string;
  source: string;
}

/**
 * Fill each custom rule's position from `newCustomOrder` in sequence, leaving
 * non-custom rows where they are. Throws when `newCustomOrder` is not exactly
 * the draft's custom id set: both arguments must come from the same snapshot.
 */
export const buildReorderIds = (
  fullDraftRules: readonly ReorderableRule[],
  newCustomOrder: readonly string[],
): string[] => {
  const customIds = new Set(
    fullDraftRules.filter((r) => r.source === "custom").map((r) => r.id),
  );
  const namesEveryCustomOnce =
    newCustomOrder.length === customIds.size &&
    new Set(newCustomOrder).size === newCustomOrder.length &&
    newCustomOrder.every((id) => customIds.has(id));
  if (!namesEveryCustomOnce) {
    throw new Error(
      "newCustomOrder must name each custom draft rule exactly once",
    );
  }
  const queue = [...newCustomOrder];
  return fullDraftRules.map((r) =>
    r.source === "custom" ? (queue.shift() ?? r.id) : r.id,
  );
};
