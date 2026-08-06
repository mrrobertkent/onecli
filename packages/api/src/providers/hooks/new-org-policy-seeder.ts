// ── New-org policy seed seam ────────────────────────────────────────────────
// Seeds a new organization's published `policy_rules_v2` so the engine has a
// posture from birth. The default is a no-op; editions with an org scope inject
// a real seeder via `createApiApp`.

export interface NewOrgPolicySeeder {
  /** Seed the new org's initial published policy. Idempotent: a no-op once the
   * scope already has a published generation. `projectId` is the org's
   * freshly-created default project, used by seeders that have no org scope. */
  seed(organizationId: string, projectId?: string): Promise<void>;
}

const defaultNewOrgPolicySeeder: NewOrgPolicySeeder = {
  seed: async () => {},
};

let _newOrgPolicySeeder: NewOrgPolicySeeder = defaultNewOrgPolicySeeder;

export const initNewOrgPolicySeeder = (s: NewOrgPolicySeeder) => {
  _newOrgPolicySeeder = s;
};

export const getNewOrgPolicySeeder = (): NewOrgPolicySeeder =>
  _newOrgPolicySeeder;
