import type { CreateApiAppOptions } from "@onecli/api";
import { ossNewProjectPolicySeeder } from "@onecli/api/services/policy-oss-cutover";
import { ossPolicyValidator } from "@onecli/api/services/policy-oss-locks";
import { ossRoleResolver } from "@onecli/api/services/role-resolution";
import {
  ossSessionEnforcer,
  ossSessionMembership,
} from "@onecli/api/services/session-membership";

/**
 * The OSS edition's API wiring. Every EE edition ALIASES THIS FILE AWAY
 * (`next.config.js` → `@/ee/init/api` or `@/ee/onprem/init/api`), so anything
 * here is OSS-only by construction:
 *
 * - the new-project seeder gives fresh projects their published Default Rule —
 *   the per-project enforce signal — pinned to ALLOW since step 6;
 * - the policy validator LOCKS granular resource scoping (a OneCLI Cloud
 *   capability the OSS gateway does not enforce) with a loud 422.
 *
 * The two auth registrations are load-bearing for tenant isolation, not
 * optional wiring:
 *
 * - `roleResolver` — with `CAPS.rbac` now true, `canAccessProjectAsUser`
 *   returns false for EVERYONE if no resolver is registered
 *   (`resolve.ts:86`), and every org API key is rejected
 *   (`api-key.ts:52-59`). Removing this line does not loosen the system, it
 *   bricks it.
 * - `sessionHooks.ensureSessionMembership` — the login-time role writer. It is
 *   what makes the resolver's answer meaningful; without it every joiner falls
 *   through to the floor role and the IdP's groups are never consulted.
 */
export const eeOverrides: CreateApiAppOptions | undefined = {
  newOrgPolicySeeder: ossNewProjectPolicySeeder,
  policyValidator: ossPolicyValidator,
  roleResolver: ossRoleResolver,
  sessionHooks: { ensureSessionMembership: ossSessionMembership },
  // The access gate: authenticating is not sufficient to be provisioned. Runs
  // on every authenticated session, so going straight to a `/v1/*` route does
  // not bypass it.
  //
  // Deliberate consequence: until a bootstrap admin exists and group mappings
  // are configured, NOBODY is admitted. That is the fail-closed posture, and
  // why the bootstrap admin has to ship alongside this.
  sessionEnforcer: ossSessionEnforcer,
};
