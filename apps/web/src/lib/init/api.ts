import type { CreateApiAppOptions } from "@onecli/api";
import { ossNewProjectPolicySeeder } from "@onecli/api/services/policy-oss-cutover";
import { ossPolicyValidator } from "@onecli/api/services/policy-oss-locks";
import { ossRoleResolver } from "@onecli/api/services/role-resolution";
import {
  ossSessionEnforcer,
  ossSessionMembership,
} from "@onecli/api/services/session-membership";

/**
 * The OSS edition's API wiring. Every EE edition aliases this file away, so
 * everything here is OSS-only by construction.
 *
 * The two auth registrations are load-bearing for tenant isolation, not
 * optional wiring: without `roleResolver`, `canAccessProjectAsUser` returns
 * false for everyone and every org API key is rejected. Without
 * `ensureSessionMembership`, every joiner falls through to the floor role and
 * the IdP's groups are never consulted.
 */
export const eeOverrides: CreateApiAppOptions | undefined = {
  newOrgPolicySeeder: ossNewProjectPolicySeeder,
  policyValidator: ossPolicyValidator,
  roleResolver: ossRoleResolver,
  sessionHooks: { ensureSessionMembership: ossSessionMembership },
  // The access gate: authenticating is not sufficient to be provisioned. Runs
  // on every authenticated session, so a direct `/v1/*` call cannot bypass it.
  // Fail-closed — nobody is admitted until a bootstrap admin exists and group
  // mappings are configured.
  sessionEnforcer: ossSessionEnforcer,
};
