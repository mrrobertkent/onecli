/** The OSS new-project policy seeder, wired via the OSS init seam. */
import { backfillPublishScope, type BackfillRuleInput } from "./policy-service";

/** The seeded per-project Default Rule. Priority is assigned by the caller. */
const ossProjectDefaultRule = (): BackfillRuleInput => ({
  priority: 0,
  isDefault: true,
  source: "default",
  name: "Default Rule",
  action: "allow",
  rateLimit: null,
  rateLimitWindow: null,
  requireApproval: false,
  conditions: null,
  identities: [],
  targets: [],
});

/**
 * Seed a fresh project's published Default Rule as allow — the published
 * generation is the gateway's per-project enforce signal, so the project
 * enforces v2 from birth. Org-only calls no-op: OSS has no org scope.
 */
export const ossNewProjectPolicySeeder = {
  seed: async (_organizationId: string, projectId?: string): Promise<void> => {
    if (!projectId) return;
    await backfillPublishScope({ projectId }, [ossProjectDefaultRule()]);
  },
};
