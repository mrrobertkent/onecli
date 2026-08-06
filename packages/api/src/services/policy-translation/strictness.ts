import type { NewRule } from "./types";

/**
 * Strictness rank, block (0) to allow (3), reproducing the gateway's
 * Block > ManualApproval > RateLimit > Allow. Shared by the translator's
 * priority assignment and the evaluator's first-match ordering: the two have to
 * agree, so the rank lives in one place.
 */
export const strictnessRank = (rule: NewRule): number => {
  if (rule.action === "block") return 0;
  if (rule.requireApproval) return 1;
  if (rule.rateLimit !== null) return 2;
  return 3;
};
