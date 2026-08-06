import { policy } from "@/lib/api";
import type { PageScope } from "@/lib/api";

/**
 * The OSS publish-mode seam: immediate apply. Chained inside the mutation, so
 * the button's pending state covers write plus publish and the invalidation
 * that follows sees the published truth.
 *
 * A failed publish leaves the write staged in the draft; the next successful
 * write publishes the whole draft, so the state self-heals.
 */
export const afterPolicyWrite = async (scope: PageScope): Promise<void> => {
  await policy.publish(scope);
};

/** The rule drawer's subtitle — OSS applies writes immediately (no draft). */
export const ruleSheetDescription: (scope: PageScope) => string = () =>
  "Who this applies to, what it targets, and what happens. Changes apply immediately.";
